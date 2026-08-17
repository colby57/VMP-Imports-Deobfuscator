use std::{
    collections::{BTreeMap, HashSet},
    error::Error,
    fmt,
};

use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, Instruction, OpKind};

use crate::{pe::Section, process::Architecture};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferOpcode {
    Call,
    Jump,
}

impl fmt::Display for TransferOpcode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Call => formatter.write_str("call"),
            Self::Jump => formatter.write_str("jmp"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmTransfer {
    pub opcode: TransferOpcode,
    pub instruction_rva: u32,
    pub instruction_size: u8,
    pub stub_rva: u32,
    pub return_rva: Option<u32>,
}

#[derive(Debug)]
pub enum TransferError {
    SectionOrdinalOutOfRange(usize),
    SectionRangeOverflow(String),
    SectionOutsideSnapshot(String),
    AddressOverflow,
    RvaOutsideRange(u64),
    InstructionSizeOutsideRange(usize),
}

impl fmt::Display for TransferError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SectionOrdinalOutOfRange(ordinal) => {
                write!(formatter, "section number {} does not exist", ordinal + 1)
            }
            Self::SectionRangeOverflow(name) => {
                write!(formatter, "section `{name}` address range overflowed")
            }
            Self::SectionOutsideSnapshot(name) => {
                write!(formatter, "section `{name}` exceeds the module snapshot")
            }
            Self::AddressOverflow => formatter.write_str("instruction address overflowed"),
            Self::RvaOutsideRange(address) => {
                write!(formatter, "address 0x{address:x} does not fit a PE RVA")
            }
            Self::InstructionSizeOutsideRange(size) => {
                write!(
                    formatter,
                    "decoded instruction size {size} does not fit in u8"
                )
            }
        }
    }
}

impl Error for TransferError {}

pub fn find(
    architecture: Architecture,
    module_base: u64,
    module_snapshot: &[u8],
    sections: &[Section],
    vm_section_ordinals: &[usize],
    code_root_rvas: &[u32],
) -> Result<Vec<VmTransfer>, TransferError> {
    let vm_ranges = vm_ranges(module_base, sections, vm_section_ordinals)?;
    let mut vm_transfers = Vec::new();
    let mut executable_regions = Vec::new();

    for (ordinal, section) in sections.iter().enumerate() {
        if !section.is_executable() || vm_section_ordinals.contains(&ordinal) {
            continue;
        }

        let section_bytes = section_bytes(module_snapshot, section)?;
        let address_begin = module_base
            .checked_add(u64::from(section.virtual_address))
            .ok_or(TransferError::AddressOverflow)?;
        let address_end = address_begin
            .checked_add(section_bytes.len() as u64)
            .ok_or(TransferError::AddressOverflow)?;
        executable_regions.push(ExecutableRegion {
            address_begin,
            address_end,
            bytes: section_bytes,
        });
    }

    let mut pending_addresses = code_root_rvas
        .iter()
        .map(|rva| {
            module_base
                .checked_add(u64::from(*rva))
                .ok_or(TransferError::AddressOverflow)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut visited_addresses = HashSet::new();
    let mut decoded_ranges = BTreeMap::new();

    while let Some(instruction_address) = pending_addresses.pop() {
        if !visited_addresses.insert(instruction_address) {
            continue;
        }
        let Some(instruction_bytes) = executable_regions
            .iter()
            .find_map(|region| region.bytes_at(instruction_address))
        else {
            continue;
        };
        let mut decoder = Decoder::with_ip(
            architecture_bitness(architecture),
            instruction_bytes,
            instruction_address,
            DecoderOptions::NONE,
        );
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            continue;
        }
        let instruction_end = instruction.next_ip();
        if range_overlaps_decoded_instruction(&decoded_ranges, instruction_address, instruction_end)
        {
            continue;
        }
        decoded_ranges.insert(instruction_address, instruction_end);

        if let Some(opcode) = transfer_opcode(architecture, &instruction) {
            let stub_address = instruction.near_branch_target();
            if vm_ranges
                .iter()
                .any(|vm_range| vm_range.contains(stub_address))
            {
                let instruction_rva = address_to_rva(module_base, instruction.ip())?;
                let stub_rva = address_to_rva(module_base, stub_address)?;
                let return_rva = match opcode {
                    TransferOpcode::Call => {
                        Some(address_to_rva(module_base, instruction.next_ip())?)
                    }
                    TransferOpcode::Jump => None,
                };
                let instruction_size = u8::try_from(instruction.len())
                    .map_err(|_| TransferError::InstructionSizeOutsideRange(instruction.len()))?;

                vm_transfers.push(VmTransfer {
                    opcode,
                    instruction_rva,
                    instruction_size,
                    stub_rva,
                    return_rva,
                });
            }
        }
        append_control_flow_addresses(&mut pending_addresses, &instruction);
    }

    vm_transfers.sort_unstable_by_key(|transfer| transfer.instruction_rva);
    Ok(vm_transfers)
}

struct ExecutableRegion<'a> {
    address_begin: u64,
    address_end: u64,
    bytes: &'a [u8],
}

impl<'a> ExecutableRegion<'a> {
    fn bytes_at(&self, address: u64) -> Option<&'a [u8]> {
        if !(self.address_begin..self.address_end).contains(&address) {
            return None;
        }
        let offset = usize::try_from(address - self.address_begin).ok()?;
        self.bytes.get(offset..)
    }
}

#[derive(Clone, Copy)]
struct VmRange {
    begin: u64,
    end: u64,
}

impl VmRange {
    fn contains(self, address: u64) -> bool {
        (self.begin..self.end).contains(&address)
    }
}

fn vm_ranges(
    module_base: u64,
    sections: &[Section],
    vm_section_ordinals: &[usize],
) -> Result<Vec<VmRange>, TransferError> {
    vm_section_ordinals
        .iter()
        .map(|ordinal| {
            let section = sections
                .get(*ordinal)
                .ok_or(TransferError::SectionOrdinalOutOfRange(*ordinal))?;
            let begin = module_base
                .checked_add(u64::from(section.virtual_address))
                .ok_or_else(|| TransferError::SectionRangeOverflow(section.name.clone()))?;
            let end = begin
                .checked_add(u64::from(section.mapped_size()))
                .ok_or_else(|| TransferError::SectionRangeOverflow(section.name.clone()))?;

            Ok(VmRange { begin, end })
        })
        .collect()
}

fn section_bytes<'a>(
    module_snapshot: &'a [u8],
    section: &Section,
) -> Result<&'a [u8], TransferError> {
    let begin = section.virtual_address as usize;
    let end = begin
        .checked_add(section.mapped_size() as usize)
        .ok_or_else(|| TransferError::SectionRangeOverflow(section.name.clone()))?;

    module_snapshot
        .get(begin..end)
        .ok_or_else(|| TransferError::SectionOutsideSnapshot(section.name.clone()))
}

fn transfer_opcode(
    architecture: Architecture,
    instruction: &Instruction,
) -> Option<TransferOpcode> {
    match (architecture, instruction.code()) {
        (Architecture::X86, Code::Call_rel32_32) | (Architecture::X64, Code::Call_rel32_64) => {
            Some(TransferOpcode::Call)
        }
        (Architecture::X86, Code::Jmp_rel32_32) | (Architecture::X64, Code::Jmp_rel32_64) => {
            Some(TransferOpcode::Jump)
        }
        _ => None,
    }
}

fn append_control_flow_addresses(pending_addresses: &mut Vec<u64>, instruction: &Instruction) {
    let next_address = instruction.next_ip();
    match instruction.flow_control() {
        FlowControl::Next | FlowControl::IndirectCall => pending_addresses.push(next_address),
        FlowControl::Call | FlowControl::ConditionalBranch | FlowControl::XbeginXabortXend => {
            if is_near_branch(instruction.op0_kind()) {
                pending_addresses.push(instruction.near_branch_target());
            }
            pending_addresses.push(next_address);
        }
        FlowControl::UnconditionalBranch => {
            if is_near_branch(instruction.op0_kind()) {
                pending_addresses.push(instruction.near_branch_target());
            }
        }
        FlowControl::IndirectBranch
        | FlowControl::Return
        | FlowControl::Interrupt
        | FlowControl::Exception => {}
    }
}

fn range_overlaps_decoded_instruction(
    decoded_ranges: &BTreeMap<u64, u64>,
    begin: u64,
    end: u64,
) -> bool {
    decoded_ranges
        .range(..=begin)
        .next_back()
        .is_some_and(|(_, decoded_end)| *decoded_end > begin)
        || decoded_ranges.range(begin..end).next().is_some()
}

const fn is_near_branch(operand: OpKind) -> bool {
    matches!(
        operand,
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
}

const fn architecture_bitness(architecture: Architecture) -> u32 {
    match architecture {
        Architecture::X86 => 32,
        Architecture::X64 => 64,
    }
}

fn address_to_rva(module_base: u64, address: u64) -> Result<u32, TransferError> {
    let rva = address
        .checked_sub(module_base)
        .ok_or(TransferError::RvaOutsideRange(address))?;
    u32::try_from(rva).map_err(|_| TransferError::RvaOutsideRange(address))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODULE_BASE_X86: u64 = 0x40_0000;
    const MODULE_BASE_X64: u64 = 0x0000_7ff6_0000_0000;
    const TEXT_RVA: u32 = 0x1000;
    const VM_RVA: u32 = 0x2000;

    #[test]
    fn finds_x86_call_into_vm_section() {
        let mut module_snapshot = vec![0_u8; 0x3000];
        module_snapshot[TEXT_RVA as usize..TEXT_RVA as usize + 5]
            .copy_from_slice(&[0xe8, 0xfb, 0x0f, 0x00, 0x00]);
        let sections = sample_sections();

        let vm_transfers = find(
            Architecture::X86,
            MODULE_BASE_X86,
            &module_snapshot,
            &sections,
            &[1],
            &[TEXT_RVA],
        )
        .expect("valid x86 scan");

        assert_eq!(
            vm_transfers,
            [VmTransfer {
                opcode: TransferOpcode::Call,
                instruction_rva: TEXT_RVA,
                instruction_size: 5,
                stub_rva: VM_RVA,
                return_rva: Some(TEXT_RVA + 5),
            }]
        );
    }

    #[test]
    fn finds_x64_jump_without_return_address() {
        let mut module_snapshot = vec![0_u8; 0x3000];
        module_snapshot[TEXT_RVA as usize..TEXT_RVA as usize + 5]
            .copy_from_slice(&[0xe9, 0xfb, 0x0f, 0x00, 0x00]);
        let sections = sample_sections();

        let vm_transfers = find(
            Architecture::X64,
            MODULE_BASE_X64,
            &module_snapshot,
            &sections,
            &[1],
            &[TEXT_RVA],
        )
        .expect("valid x64 scan");

        assert_eq!(
            vm_transfers,
            [VmTransfer {
                opcode: TransferOpcode::Jump,
                instruction_rva: TEXT_RVA,
                instruction_size: 5,
                stub_rva: VM_RVA,
                return_rva: None,
            }]
        );
    }

    #[test]
    fn ignores_transfer_bytes_outside_reachable_code() {
        const FUNCTION_RVA: u32 = TEXT_RVA + 0x10;
        let mut module_snapshot = vec![0_u8; 0x3000];
        module_snapshot[TEXT_RVA as usize..TEXT_RVA as usize + 5]
            .copy_from_slice(&[0xe8, 0xfb, 0x0f, 0x00, 0x00]);
        module_snapshot[FUNCTION_RVA as usize..FUNCTION_RVA as usize + 5]
            .copy_from_slice(&[0xe8, 0xeb, 0x0f, 0x00, 0x00]);

        let vm_transfers = find(
            Architecture::X86,
            MODULE_BASE_X86,
            &module_snapshot,
            &sample_sections(),
            &[1],
            &[FUNCTION_RVA],
        )
        .expect("valid rooted VM-transfer scan");

        assert_eq!(vm_transfers.len(), 1);
        assert_eq!(vm_transfers[0].instruction_rva, FUNCTION_RVA);
    }

    fn sample_sections() -> Vec<Section> {
        vec![
            Section {
                name: ".text".to_owned(),
                virtual_address: TEXT_RVA,
                virtual_size: 0x1000,
                raw_size: 0x1000,
                characteristics: 0x6000_0020,
            },
            Section {
                name: ".vmp0".to_owned(),
                virtual_address: VM_RVA,
                virtual_size: 0x1000,
                raw_size: 0x1000,
                characteristics: 0x6000_0020,
            },
        ]
    }
}
