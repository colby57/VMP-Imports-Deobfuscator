use std::{
    collections::{BTreeMap, HashMap, HashSet},
    error::Error,
    fmt,
    mem::size_of,
};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};

use crate::{exports::ExportIndex, pe::Section, process::Architecture};

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ImportSymbol {
    Name(String),
    Ordinal(u16),
}

impl fmt::Display for ImportSymbol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => name.fmt(formatter),
            Self::Ordinal(ordinal) => write!(formatter, "#{ordinal}"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredImport {
    pub module_name: String,
    pub symbol: ImportSymbol,
    pub destination_address: u64,
}

impl fmt::Display for RecoveredImport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}!{}", self.module_name, self.symbol)
    }
}

#[derive(Debug)]
pub enum ImportRecoveryError {
    OrdinalOutsideRange { module_name: String, ordinal: u32 },
}

impl fmt::Display for ImportRecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OrdinalOutsideRange {
                module_name,
                ordinal,
            } => write!(
                formatter,
                "export ordinal {ordinal} from `{module_name}` does not fit in a PE import ordinal"
            ),
        }
    }
}

impl Error for ImportRecoveryError {}

pub fn recover_import(
    destination_address: u64,
    export_symbols: &[crate::exports::ExportSymbol],
) -> Result<Option<RecoveredImport>, ImportRecoveryError> {
    // @note: an address can have export aliases, so choose one stable representation;
    // the caller logs every candidate because the original import name is unknowable here.
    let Some(export_symbol) = export_symbols.iter().min_by_key(|export_symbol| {
        (
            export_symbol.name.is_none(),
            is_api_set_contract(&export_symbol.module_name),
            !export_symbol.forwarded,
            export_symbol.module_name.to_ascii_lowercase(),
            export_symbol.name.as_deref().unwrap_or(""),
            export_symbol.ordinal,
        )
    }) else {
        return Ok(None);
    };

    let symbol = match &export_symbol.name {
        Some(name) => ImportSymbol::Name(name.clone()),
        None => ImportSymbol::Ordinal(u16::try_from(export_symbol.ordinal).map_err(|_| {
            ImportRecoveryError::OrdinalOutsideRange {
                module_name: export_symbol.module_name.clone(),
                ordinal: export_symbol.ordinal,
            }
        })?),
    };

    Ok(Some(RecoveredImport {
        module_name: export_symbol.module_name.clone(),
        symbol,
        destination_address,
    }))
}

fn is_api_set_contract(module_name: &str) -> bool {
    let module_name = module_name.to_ascii_lowercase();
    module_name.starts_with("api-ms-") || module_name.starts_with("ext-ms-")
}

pub fn normalize_recovered_imports(
    recovered_imports: impl IntoIterator<Item = RecoveredImport>,
) -> Vec<RecoveredImport> {
    let mut imports_by_identity = BTreeMap::new();
    for recovered_import in recovered_imports {
        let identity = (
            recovered_import.module_name.to_ascii_lowercase(),
            recovered_import.symbol.clone(),
        );
        if imports_by_identity
            .get(&identity)
            .is_none_or(|existing_import: &RecoveredImport| {
                recovered_import.destination_address < existing_import.destination_address
            })
        {
            imports_by_identity.insert(identity, recovered_import);
        }
    }

    imports_by_identity.into_values().collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedImportPointer {
    pub pointer_rva: u32,
    pub destination_address: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PointerOperand {
    Memory,
    Immediate,
}

impl fmt::Display for PointerOperand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memory => formatter.write_str("memory"),
            Self::Immediate => formatter.write_str("immediate"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportPointerReference {
    pub instruction_rva: u32,
    pub instruction_size: u8,
    pub mnemonic: Mnemonic,
    pub operand_index: u8,
    pub operand: PointerOperand,
    pub pointer_rva: u32,
    pub destination_address: u64,
}

#[derive(Debug)]
pub enum ImportScanError {
    SectionRangeOverflow(String),
    SectionOutsideSnapshot(String),
    RvaOutsideRange(usize),
    AddressOverflow,
    InstructionRvaOutsideRange(u64),
    InstructionSizeOutsideRange(usize),
}

impl fmt::Display for ImportScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SectionRangeOverflow(name) => {
                write!(formatter, "section `{name}` address range overflowed")
            }
            Self::SectionOutsideSnapshot(name) => {
                write!(formatter, "section `{name}` exceeds the module snapshot")
            }
            Self::RvaOutsideRange(rva) => {
                write!(formatter, "RVA 0x{rva:x} does not fit in a PE RVA")
            }
            Self::AddressOverflow => formatter.write_str("import-pointer address overflowed"),
            Self::InstructionRvaOutsideRange(address) => {
                write!(
                    formatter,
                    "instruction address 0x{address:x} does not fit in a PE RVA"
                )
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

impl Error for ImportScanError {}

pub fn find_resolved_pointers(
    architecture: Architecture,
    module_snapshot: &[u8],
    sections: &[Section],
    export_index: &ExportIndex,
) -> Result<Vec<ResolvedImportPointer>, ImportScanError> {
    let pointer_size = match architecture {
        Architecture::X86 => size_of::<u32>(),
        Architecture::X64 => size_of::<u64>(),
    };
    let mut resolved_pointers = Vec::new();

    for section in sections {
        if !section.is_readable() || section.is_executable() {
            continue;
        }

        let section_begin = section.virtual_address as usize;
        let section_end = section_begin
            .checked_add(section.mapped_size() as usize)
            .ok_or_else(|| ImportScanError::SectionRangeOverflow(section.name.clone()))?;
        let section_bytes = module_snapshot
            .get(section_begin..section_end)
            .ok_or_else(|| ImportScanError::SectionOutsideSnapshot(section.name.clone()))?;

        for (pointer_ordinal, pointer_bytes) in section_bytes.chunks_exact(pointer_size).enumerate()
        {
            let pointer_offset = pointer_ordinal * pointer_size;
            let destination_address = match architecture {
                Architecture::X86 => u64::from(u32::from_le_bytes(
                    pointer_bytes
                        .try_into()
                        .expect("an x86 pointer has four bytes"),
                )),
                Architecture::X64 => u64::from_le_bytes(
                    pointer_bytes
                        .try_into()
                        .expect("an x64 pointer has eight bytes"),
                ),
            };
            if export_index.at(destination_address).is_empty() {
                continue;
            }

            let pointer_rva = section_begin
                .checked_add(pointer_offset)
                .ok_or_else(|| ImportScanError::SectionRangeOverflow(section.name.clone()))?;
            resolved_pointers.push(ResolvedImportPointer {
                pointer_rva: u32::try_from(pointer_rva)
                    .map_err(|_| ImportScanError::RvaOutsideRange(pointer_rva))?,
                destination_address,
            });
        }
    }

    Ok(resolved_pointers)
}

pub fn find_pointer_references(
    architecture: Architecture,
    module_base: u64,
    module_snapshot: &[u8],
    sections: &[Section],
    vm_section_ordinals: &[usize],
    resolved_pointers: &[ResolvedImportPointer],
    code_root_rvas: &[u32],
) -> Result<Vec<ImportPointerReference>, ImportScanError> {
    let mut pointers_by_address = HashMap::with_capacity(resolved_pointers.len());
    for resolved_pointer in resolved_pointers {
        let pointer_address = module_base
            .checked_add(u64::from(resolved_pointer.pointer_rva))
            .ok_or(ImportScanError::AddressOverflow)?;
        pointers_by_address.insert(pointer_address, *resolved_pointer);
    }

    let mut executable_regions = Vec::new();
    for (section_ordinal, section) in sections.iter().enumerate() {
        if !section.is_executable() || vm_section_ordinals.contains(&section_ordinal) {
            continue;
        }

        let section_begin = section.virtual_address as usize;
        let section_end = section_begin
            .checked_add(section.mapped_size() as usize)
            .ok_or_else(|| ImportScanError::SectionRangeOverflow(section.name.clone()))?;
        let section_bytes = module_snapshot
            .get(section_begin..section_end)
            .ok_or_else(|| ImportScanError::SectionOutsideSnapshot(section.name.clone()))?;
        let address_begin = module_base
            .checked_add(u64::from(section.virtual_address))
            .ok_or(ImportScanError::AddressOverflow)?;
        let address_end = address_begin
            .checked_add(section_bytes.len() as u64)
            .ok_or(ImportScanError::AddressOverflow)?;
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
                .ok_or(ImportScanError::AddressOverflow)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut visited_addresses = HashSet::new();
    let mut decoded_ranges = BTreeMap::new();
    let mut pointer_references = Vec::new();

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

        append_pointer_references(
            &mut pointer_references,
            &instruction,
            module_base,
            &pointers_by_address,
        )?;
        append_control_flow_addresses(&mut pending_addresses, &instruction);
    }

    pointer_references.sort_by_key(|pointer_reference| {
        (
            pointer_reference.instruction_rva,
            pointer_reference.operand_index,
        )
    });
    Ok(pointer_references)
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

fn append_pointer_references(
    pointer_references: &mut Vec<ImportPointerReference>,
    instruction: &Instruction,
    module_base: u64,
    pointers_by_address: &HashMap<u64, ResolvedImportPointer>,
) -> Result<(), ImportScanError> {
    for operand_index in 0..instruction.op_count() {
        let Some((operand, pointer_address)) = static_pointer_operand(instruction, operand_index)
        else {
            continue;
        };
        let Some(resolved_pointer) = pointers_by_address.get(&pointer_address) else {
            continue;
        };

        let instruction_rva = instruction
            .ip()
            .checked_sub(module_base)
            .and_then(|rva| u32::try_from(rva).ok())
            .ok_or(ImportScanError::InstructionRvaOutsideRange(
                instruction.ip(),
            ))?;
        pointer_references.push(ImportPointerReference {
            instruction_rva,
            instruction_size: u8::try_from(instruction.len())
                .map_err(|_| ImportScanError::InstructionSizeOutsideRange(instruction.len()))?,
            mnemonic: instruction.mnemonic(),
            operand_index: operand_index as u8,
            operand,
            pointer_rva: resolved_pointer.pointer_rva,
            destination_address: resolved_pointer.destination_address,
        });
    }

    Ok(())
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

fn static_pointer_operand(
    instruction: &Instruction,
    operand_index: u32,
) -> Option<(PointerOperand, u64)> {
    match instruction.op_kind(operand_index) {
        OpKind::Memory
            if instruction.is_ip_rel_memory_operand()
                || (instruction.memory_base() == Register::None
                    && instruction.memory_index() == Register::None) =>
        {
            Some((PointerOperand::Memory, instruction.memory_displacement64()))
        }
        OpKind::Immediate32 | OpKind::Immediate64 | OpKind::Immediate32to64 => Some((
            PointerOperand::Immediate,
            instruction.immediate(operand_index),
        )),
        _ => None,
    }
}

const fn architecture_bitness(architecture: Architecture) -> u32 {
    match architecture {
        Architecture::X86 => 32,
        Architecture::X64 => 64,
    }
}

const fn is_near_branch(operand: OpKind) -> bool {
    matches!(
        operand,
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
}

#[cfg(test)]
mod tests {
    use crate::exports::ExportSymbol;

    use super::*;

    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
    const MODULE_BASE_X86: u64 = 0x40_0000;
    const MODULE_BASE_X64: u64 = 0x0000_7ff6_0000_0000;

    #[test]
    fn finds_x86_export_pointer_in_readable_data_section() {
        const DESTINATION_ADDRESS: u32 = 0x7654_3210;
        let mut module_snapshot = vec![0_u8; 0x3000];
        module_snapshot[0x1004..0x1008].copy_from_slice(&DESTINATION_ADDRESS.to_le_bytes());
        module_snapshot[0x2004..0x2008].copy_from_slice(&DESTINATION_ADDRESS.to_le_bytes());
        let sections = [
            section(".text", 0x1000, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE),
            section(".rdata", 0x2000, IMAGE_SCN_MEM_READ),
        ];
        let export_index = export_index(u64::from(DESTINATION_ADDRESS));

        assert_eq!(
            find_resolved_pointers(
                Architecture::X86,
                &module_snapshot,
                &sections,
                &export_index,
            )
            .expect("valid import-pointer scan"),
            [ResolvedImportPointer {
                pointer_rva: 0x2004,
                destination_address: u64::from(DESTINATION_ADDRESS),
            }]
        );
    }

    #[test]
    fn reads_x64_pointer_width() {
        const DESTINATION_ADDRESS: u64 = 0x0000_7ffa_1234_5678;
        let mut module_snapshot = vec![0_u8; 0x3000];
        module_snapshot[0x2008..0x2010].copy_from_slice(&DESTINATION_ADDRESS.to_le_bytes());
        let sections = [section(".rdata", 0x2000, IMAGE_SCN_MEM_READ)];
        let export_index = export_index(DESTINATION_ADDRESS);

        assert_eq!(
            find_resolved_pointers(
                Architecture::X64,
                &module_snapshot,
                &sections,
                &export_index,
            )
            .expect("valid import-pointer scan"),
            [ResolvedImportPointer {
                pointer_rva: 0x2008,
                destination_address: DESTINATION_ADDRESS,
            }]
        );
    }

    #[test]
    fn matches_x86_absolute_memory_and_immediate_operands() {
        const POINTER_RVA: u32 = 0x2004;
        const DESTINATION_ADDRESS: u64 = 0x7654_3210;
        let pointer_address = (MODULE_BASE_X86 + u64::from(POINTER_RVA)) as u32;
        let mut module_snapshot = vec![0_u8; 0x3000];
        module_snapshot[0x1000..0x1002].copy_from_slice(&[0xff, 0x15]);
        module_snapshot[0x1002..0x1006].copy_from_slice(&pointer_address.to_le_bytes());
        module_snapshot[0x1006] = 0xb8;
        module_snapshot[0x1007..0x100b].copy_from_slice(&pointer_address.to_le_bytes());
        let sections = [
            section(".text", 0x1000, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE),
            section(".rdata", 0x2000, IMAGE_SCN_MEM_READ),
        ];
        let resolved_pointers = [ResolvedImportPointer {
            pointer_rva: POINTER_RVA,
            destination_address: DESTINATION_ADDRESS,
        }];

        assert_eq!(
            find_pointer_references(
                Architecture::X86,
                MODULE_BASE_X86,
                &module_snapshot,
                &sections,
                &[],
                &resolved_pointers,
                &[0x1000],
            )
            .expect("valid x86 reference scan"),
            [
                ImportPointerReference {
                    instruction_rva: 0x1000,
                    instruction_size: 6,
                    mnemonic: Mnemonic::Call,
                    operand_index: 0,
                    operand: PointerOperand::Memory,
                    pointer_rva: POINTER_RVA,
                    destination_address: DESTINATION_ADDRESS,
                },
                ImportPointerReference {
                    instruction_rva: 0x1006,
                    instruction_size: 5,
                    mnemonic: Mnemonic::Mov,
                    operand_index: 1,
                    operand: PointerOperand::Immediate,
                    pointer_rva: POINTER_RVA,
                    destination_address: DESTINATION_ADDRESS,
                },
            ]
        );
    }

    #[test]
    fn matches_x64_rip_relative_memory_and_immediate_operands() {
        const POINTER_RVA: u32 = 0x2008;
        const DESTINATION_ADDRESS: u64 = 0x0000_7ffa_1234_5678;
        let pointer_address = MODULE_BASE_X64 + u64::from(POINTER_RVA);
        let mut module_snapshot = vec![0_u8; 0x3000];
        module_snapshot[0x1000..0x1003].copy_from_slice(&[0x48, 0x8b, 0x05]);
        let displacement = i32::try_from(pointer_address - (MODULE_BASE_X64 + 0x1007))
            .expect("sample RIP displacement fits in i32");
        module_snapshot[0x1003..0x1007].copy_from_slice(&displacement.to_le_bytes());
        module_snapshot[0x1007..0x1009].copy_from_slice(&[0x48, 0xb8]);
        module_snapshot[0x1009..0x1011].copy_from_slice(&pointer_address.to_le_bytes());
        let sections = [
            section(".text", 0x1000, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE),
            section(".rdata", 0x2000, IMAGE_SCN_MEM_READ),
        ];
        let resolved_pointers = [ResolvedImportPointer {
            pointer_rva: POINTER_RVA,
            destination_address: DESTINATION_ADDRESS,
        }];

        assert_eq!(
            find_pointer_references(
                Architecture::X64,
                MODULE_BASE_X64,
                &module_snapshot,
                &sections,
                &[],
                &resolved_pointers,
                &[0x1000],
            )
            .expect("valid x64 reference scan"),
            [
                ImportPointerReference {
                    instruction_rva: 0x1000,
                    instruction_size: 7,
                    mnemonic: Mnemonic::Mov,
                    operand_index: 1,
                    operand: PointerOperand::Memory,
                    pointer_rva: POINTER_RVA,
                    destination_address: DESTINATION_ADDRESS,
                },
                ImportPointerReference {
                    instruction_rva: 0x1007,
                    instruction_size: 10,
                    mnemonic: Mnemonic::Mov,
                    operand_index: 1,
                    operand: PointerOperand::Immediate,
                    pointer_rva: POINTER_RVA,
                    destination_address: DESTINATION_ADDRESS,
                },
            ]
        );
    }

    #[test]
    fn starts_reference_scan_from_pe_code_roots() {
        const POINTER_RVA: u32 = 0x2004;
        const FUNCTION_RVA: u32 = 0x1010;
        const DESTINATION_ADDRESS: u64 = 0x7654_3210;
        let pointer_address = (MODULE_BASE_X86 + u64::from(POINTER_RVA)) as u32;
        let mut module_snapshot = vec![0_u8; 0x3000];
        module_snapshot[0x1000] = 0xc3;
        module_snapshot[FUNCTION_RVA as usize..FUNCTION_RVA as usize + 2]
            .copy_from_slice(&[0xff, 0x15]);
        module_snapshot[FUNCTION_RVA as usize + 2..FUNCTION_RVA as usize + 6]
            .copy_from_slice(&pointer_address.to_le_bytes());
        let sections = [
            section(".text", 0x1000, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE),
            section(".rdata", 0x2000, IMAGE_SCN_MEM_READ),
        ];
        let resolved_pointers = [ResolvedImportPointer {
            pointer_rva: POINTER_RVA,
            destination_address: DESTINATION_ADDRESS,
        }];

        let references = find_pointer_references(
            Architecture::X86,
            MODULE_BASE_X86,
            &module_snapshot,
            &sections,
            &[],
            &resolved_pointers,
            &[0x1000, FUNCTION_RVA],
        )
        .expect("valid rooted reference scan");

        assert_eq!(references.len(), 1);
        assert_eq!(references[0].instruction_rva, FUNCTION_RVA);
    }

    #[test]
    fn chooses_named_export_alias_deterministically() {
        let export_symbols = [
            ExportSymbol {
                module_name: "KERNEL32.dll".to_owned(),
                name: Some("FatalExit".to_owned()),
                ordinal: 450,
                forwarded: false,
            },
            ExportSymbol {
                module_name: "KERNEL32.dll".to_owned(),
                name: Some("ExitProcess".to_owned()),
                ordinal: 449,
                forwarded: false,
            },
        ];

        assert_eq!(
            recover_import(0x7ffa_1234_5678, &export_symbols)
                .expect("valid export aliases")
                .expect("resolved export address"),
            RecoveredImport {
                module_name: "KERNEL32.dll".to_owned(),
                symbol: ImportSymbol::Name("ExitProcess".to_owned()),
                destination_address: 0x7ffa_1234_5678,
            }
        );
    }

    #[test]
    fn prefers_public_forwarder_over_implementation_and_api_set_aliases() {
        let export_symbols = [
            ExportSymbol {
                module_name: "KERNELBASE.dll".to_owned(),
                name: Some("GetTickCount".to_owned()),
                ordinal: 1,
                forwarded: false,
            },
            ExportSymbol {
                module_name: "api-ms-win-core-sysinfo-l1-1-0.dll".to_owned(),
                name: Some("GetTickCount".to_owned()),
                ordinal: 2,
                forwarded: true,
            },
            ExportSymbol {
                module_name: "KERNEL32.dll".to_owned(),
                name: Some("GetTickCount".to_owned()),
                ordinal: 3,
                forwarded: true,
            },
        ];

        let recovered = recover_import(0x7ffa_1234_5678, &export_symbols)
            .expect("valid export aliases")
            .expect("resolved export address");

        assert_eq!(recovered.module_name, "KERNEL32.dll");
        assert_eq!(
            recovered.symbol,
            ImportSymbol::Name("GetTickCount".to_owned())
        );
    }

    #[test]
    fn normalizes_duplicate_imports_and_module_name_case() {
        let recovered_imports = [
            RecoveredImport {
                module_name: "KERNEL32.dll".to_owned(),
                symbol: ImportSymbol::Name("Sleep".to_owned()),
                destination_address: 0x7ffa_2222_0000,
            },
            RecoveredImport {
                module_name: "kernel32.DLL".to_owned(),
                symbol: ImportSymbol::Name("Sleep".to_owned()),
                destination_address: 0x7ffa_1111_0000,
            },
        ];

        let normalized_imports = normalize_recovered_imports(recovered_imports);
        assert_eq!(normalized_imports.len(), 1);
        assert_eq!(normalized_imports[0].destination_address, 0x7ffa_1111_0000);
    }

    fn section(name: &str, virtual_address: u32, characteristics: u32) -> Section {
        Section {
            name: name.to_owned(),
            virtual_address,
            virtual_size: 0x20,
            raw_size: 0x20,
            characteristics,
        }
    }

    fn export_index(destination_address: u64) -> ExportIndex {
        let mut export_index = ExportIndex::default();
        export_index.insert(
            destination_address,
            ExportSymbol {
                module_name: "kernel32.dll".to_owned(),
                name: Some("ImportedFunction".to_owned()),
                ordinal: 1,
                forwarded: false,
            },
        );
        export_index
    }
}
