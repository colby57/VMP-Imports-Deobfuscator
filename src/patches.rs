use std::{collections::BTreeSet, error::Error, fmt};

use iced_x86::{
    Code, Decoder, DecoderOptions, Encoder, IcedError, Instruction, MemoryOperand, Mnemonic,
    OpKind, Register,
};

use crate::{
    emulator::GeneralRegister,
    import_layout::ImportSectionLayout,
    imports::{ImportPointerReference, PointerOperand},
    process::Architecture,
    transfers::{TransferOpcode, VmTransfer},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmImportSemantics {
    ExternalTransfer {
        destination_address: u64,
        stack_pointer_delta: i64,
        resume_rva: Option<u32>,
    },
    RegisterLoad {
        register: GeneralRegister,
        destination_address: u64,
        continuation_rva: u32,
    },
}

impl VmImportSemantics {
    fn destination_address(self) -> u64 {
        match self {
            Self::ExternalTransfer {
                destination_address,
                ..
            }
            | Self::RegisterLoad {
                destination_address,
                ..
            } => destination_address,
        }
    }
}

impl fmt::Display for VmImportSemantics {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExternalTransfer { .. } => formatter.write_str("external transfer"),
            Self::RegisterLoad { register, .. } => write!(formatter, "load {register}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmImportRewrite {
    pub transfer: VmTransfer,
    pub semantics: VmImportSemantics,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppliedPointerPatch {
    pub instruction_rva: u32,
    pub instruction_size: u8,
    pub patch_rva: u32,
    pub patch_byte_count: u8,
    pub pointer_rva: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppliedVmPatch {
    pub instruction_rva: u32,
    pub patch_rva: u32,
    pub patch_byte_count: usize,
    pub pointer_rva: u32,
    pub discarded_stack_byte_count: usize,
    pub resume_rva: Option<u32>,
    pub semantics: VmImportSemantics,
}

struct DirectVmPatch {
    patch_rva: u32,
    bytes: Vec<u8>,
    base_relocation_rvas: Vec<u32>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum PatchError {
    MissingRebuiltPointer(u64),
    InstructionOutsideSnapshot(u32),
    InvalidInstruction(u32),
    InstructionChanged {
        instruction_rva: u32,
        expected_size: u8,
        actual_size: usize,
    },
    MissingEncodedConstant(u32),
    UnsupportedEncodedConstant {
        instruction_rva: u32,
        byte_count: usize,
    },
    AddressOutsideEncodedRange {
        instruction_rva: u32,
        address: u64,
        byte_count: usize,
    },
    RelativeAddressOutsideRange {
        source_rva: u32,
        destination_rva: u32,
    },
    VmOpcodeChanged(u32),
    InvalidExternalStackDelta {
        instruction_rva: u32,
        stack_pointer_delta: i64,
    },
    InstructionEncoding(String),
    RegisterArchitectureMismatch {
        architecture: Architecture,
        register: GeneralRegister,
    },
    PatchRangesOverlap {
        first_rva: u32,
        second_rva: u32,
    },
    PatchRangeOutsideInstruction {
        instruction_rva: u32,
        patch_rva: u32,
    },
    GeneratedImportTargetMismatch {
        instruction_rva: u32,
        expected_address: u64,
        actual_address: Option<u64>,
    },
    GeneratedInstructionMismatch {
        instruction_rva: u32,
        expected: &'static str,
    },
    GeneratedRelocationsMismatch {
        expected: Vec<u32>,
        actual: Vec<u32>,
    },
    ArithmeticOverflow,
}

impl fmt::Display for PatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRebuiltPointer(address) => write!(
                formatter,
                "no rebuilt import pointer corresponds to address 0x{address:x}"
            ),
            Self::InstructionOutsideSnapshot(rva) => {
                write!(
                    formatter,
                    "instruction at RVA 0x{rva:08x} exceeds the snapshot"
                )
            }
            Self::InvalidInstruction(rva) => {
                write!(
                    formatter,
                    "instruction at RVA 0x{rva:08x} no longer decodes"
                )
            }
            Self::InstructionChanged {
                instruction_rva,
                expected_size,
                actual_size,
            } => write!(
                formatter,
                "instruction at RVA 0x{instruction_rva:08x} changed size from {expected_size} to {actual_size}"
            ),
            Self::MissingEncodedConstant(rva) => write!(
                formatter,
                "instruction at RVA 0x{rva:08x} has no encoded pointer constant"
            ),
            Self::UnsupportedEncodedConstant {
                instruction_rva,
                byte_count,
            } => write!(
                formatter,
                "instruction at RVA 0x{instruction_rva:08x} uses an unsupported {byte_count}-byte pointer constant"
            ),
            Self::AddressOutsideEncodedRange {
                instruction_rva,
                address,
                byte_count,
            } => write!(
                formatter,
                "address 0x{address:x} does not fit the {byte_count}-byte constant at RVA 0x{instruction_rva:08x}"
            ),
            Self::RelativeAddressOutsideRange {
                source_rva,
                destination_rva,
            } => write!(
                formatter,
                "relative transfer from RVA 0x{source_rva:08x} to 0x{destination_rva:08x} exceeds rel32"
            ),
            Self::VmOpcodeChanged(rva) => write!(
                formatter,
                "VM transfer opcode at RVA 0x{rva:08x} changed after discovery"
            ),
            Self::InvalidExternalStackDelta {
                instruction_rva,
                stack_pointer_delta,
            } => write!(
                formatter,
                "VM transfer at RVA 0x{instruction_rva:08x} produced unsupported stack delta {stack_pointer_delta:+}"
            ),
            Self::InstructionEncoding(message) => {
                write!(formatter, "cannot encode an import rewrite: {message}")
            }
            Self::RegisterArchitectureMismatch {
                architecture,
                register,
            } => write!(
                formatter,
                "cannot generate an {architecture} import load for {register}"
            ),
            Self::PatchRangesOverlap {
                first_rva,
                second_rva,
            } => write!(
                formatter,
                "generated patches at RVA 0x{first_rva:08x} and 0x{second_rva:08x} overlap"
            ),
            Self::PatchRangeOutsideInstruction {
                instruction_rva,
                patch_rva,
            } => write!(
                formatter,
                "patch at RVA 0x{patch_rva:08x} exceeds instruction 0x{instruction_rva:08x}"
            ),
            Self::GeneratedImportTargetMismatch {
                instruction_rva,
                expected_address,
                actual_address,
            } => match actual_address {
                Some(actual_address) => write!(
                    formatter,
                    "generated instruction at RVA 0x{instruction_rva:08x} references 0x{actual_address:x}, expected rebuilt IAT pointer 0x{expected_address:x}"
                ),
                None => write!(
                    formatter,
                    "generated instruction at RVA 0x{instruction_rva:08x} does not reference expected rebuilt IAT pointer 0x{expected_address:x}"
                ),
            },
            Self::GeneratedInstructionMismatch {
                instruction_rva,
                expected,
            } => write!(
                formatter,
                "generated instruction at RVA 0x{instruction_rva:08x} does not implement {expected}"
            ),
            Self::GeneratedRelocationsMismatch { expected, actual } => write!(
                formatter,
                "generated base relocations do not match absolute operands (expected {expected:x?}, found {actual:x?})"
            ),
            Self::ArithmeticOverflow => {
                formatter.write_str("instruction patch arithmetic overflowed")
            }
        }
    }
}

impl Error for PatchError {}

pub fn rewrite_pointer_operands(
    architecture: Architecture,
    module_base: u64,
    module_snapshot: &mut [u8],
    pointer_references: &[ImportPointerReference],
    import_layout: &ImportSectionLayout,
) -> Result<Vec<AppliedPointerPatch>, PatchError> {
    let mut applied_patches = Vec::with_capacity(pointer_references.len());

    for pointer_reference in pointer_references {
        let pointer_rva =
            rebuilt_pointer_rva(import_layout, pointer_reference.destination_address)?;
        let instruction_offset = pointer_reference.instruction_rva as usize;
        let instruction_bytes = module_snapshot.get(instruction_offset..).ok_or(
            PatchError::InstructionOutsideSnapshot(pointer_reference.instruction_rva),
        )?;
        let instruction_address = module_base
            .checked_add(u64::from(pointer_reference.instruction_rva))
            .ok_or(PatchError::ArithmeticOverflow)?;
        let mut decoder = Decoder::with_ip(
            architecture_bitness(architecture),
            instruction_bytes,
            instruction_address,
            DecoderOptions::NONE,
        );
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return Err(PatchError::InvalidInstruction(
                pointer_reference.instruction_rva,
            ));
        }
        if instruction.len() != usize::from(pointer_reference.instruction_size) {
            return Err(PatchError::InstructionChanged {
                instruction_rva: pointer_reference.instruction_rva,
                expected_size: pointer_reference.instruction_size,
                actual_size: instruction.len(),
            });
        }

        let constant_offsets = decoder.get_constant_offsets(&instruction);
        let (constant_offset, byte_count, pointer_bits) = match pointer_reference.operand {
            PointerOperand::Memory if instruction.is_ip_rel_memory_operand() => {
                let pointer_address = module_base
                    .checked_add(u64::from(pointer_rva))
                    .ok_or(PatchError::ArithmeticOverflow)?;
                let displacement = i64::try_from(pointer_address)
                    .ok()
                    .and_then(|pointer_address| {
                        i64::try_from(instruction.next_ip())
                            .ok()
                            .and_then(|next_ip| pointer_address.checked_sub(next_ip))
                    })
                    .and_then(|displacement| i32::try_from(displacement).ok())
                    .ok_or(PatchError::RelativeAddressOutsideRange {
                        source_rva: pointer_reference.instruction_rva,
                        destination_rva: pointer_rva,
                    })?;
                (
                    constant_offsets.displacement_offset(),
                    constant_offsets.displacement_size(),
                    u64::from(displacement as u32),
                )
            }
            PointerOperand::Memory => (
                constant_offsets.displacement_offset(),
                constant_offsets.displacement_size(),
                module_base
                    .checked_add(u64::from(pointer_rva))
                    .ok_or(PatchError::ArithmeticOverflow)?,
            ),
            PointerOperand::Immediate => (
                constant_offsets.immediate_offset(),
                constant_offsets.immediate_size(),
                module_base
                    .checked_add(u64::from(pointer_rva))
                    .ok_or(PatchError::ArithmeticOverflow)?,
            ),
        };
        if byte_count == 0 {
            return Err(PatchError::MissingEncodedConstant(
                pointer_reference.instruction_rva,
            ));
        }

        let patch_offset = instruction_offset
            .checked_add(constant_offset)
            .ok_or(PatchError::ArithmeticOverflow)?;
        let patch_rva = pointer_reference
            .instruction_rva
            .checked_add(
                u32::try_from(constant_offset).map_err(|_| PatchError::ArithmeticOverflow)?,
            )
            .ok_or(PatchError::ArithmeticOverflow)?;
        write_unsigned_constant(
            module_snapshot,
            patch_offset,
            byte_count,
            pointer_bits,
            pointer_reference.instruction_rva,
        )?;
        applied_patches.push(AppliedPointerPatch {
            instruction_rva: pointer_reference.instruction_rva,
            instruction_size: pointer_reference.instruction_size,
            patch_rva,
            patch_byte_count: u8::try_from(byte_count)
                .map_err(|_| PatchError::ArithmeticOverflow)?,
            pointer_rva,
        });
    }

    Ok(applied_patches)
}

pub fn rewrite_vm_transfers(
    architecture: Architecture,
    module_base: u64,
    module_snapshot: &mut [u8],
    import_layout: &mut ImportSectionLayout,
    vm_rewrites: &[VmImportRewrite],
) -> Result<Vec<AppliedVmPatch>, PatchError> {
    let normalized_rewrites = vm_rewrites
        .iter()
        .copied()
        .map(|vm_rewrite| normalize_vm_rewrite(architecture, module_snapshot, vm_rewrite))
        .collect::<Vec<_>>();
    let mut direct_rewrites = Vec::with_capacity(normalized_rewrites.len());
    for vm_rewrite in normalized_rewrites {
        let pointer_rva =
            rebuilt_pointer_rva(import_layout, vm_rewrite.semantics.destination_address())?;
        if let Some(direct_patch) = prepare_direct_vm_patch(
            architecture,
            module_base,
            module_snapshot,
            pointer_rva,
            vm_rewrite,
        )? {
            direct_rewrites.push((vm_rewrite, direct_patch));
        }
    }
    let mut applied_patches = Vec::with_capacity(direct_rewrites.len());

    for (vm_rewrite, direct_patch) in &direct_rewrites {
        let pointer_rva =
            rebuilt_pointer_rva(import_layout, vm_rewrite.semantics.destination_address())?;
        let (discarded_stack_byte_count, resume_rva) = match vm_rewrite.semantics {
            VmImportSemantics::ExternalTransfer {
                stack_pointer_delta,
                resume_rva,
                ..
            } => (
                vm_stack_discard_size(
                    architecture,
                    vm_rewrite.transfer,
                    stack_pointer_delta,
                    resume_rva,
                )?,
                resume_rva,
            ),
            VmImportSemantics::RegisterLoad {
                continuation_rva, ..
            } => (0, Some(continuation_rva)),
        };
        let patch_offset = direct_patch.patch_rva as usize;
        let patch_end = patch_offset
            .checked_add(direct_patch.bytes.len())
            .ok_or(PatchError::ArithmeticOverflow)?;
        let destination = module_snapshot.get_mut(patch_offset..patch_end).ok_or(
            PatchError::InstructionOutsideSnapshot(direct_patch.patch_rva),
        )?;
        destination.copy_from_slice(&direct_patch.bytes);
        import_layout
            .base_relocation_rvas
            .extend_from_slice(&direct_patch.base_relocation_rvas);
        applied_patches.push(AppliedVmPatch {
            instruction_rva: vm_rewrite.transfer.instruction_rva,
            patch_rva: direct_patch.patch_rva,
            patch_byte_count: direct_patch.bytes.len(),
            pointer_rva,
            discarded_stack_byte_count,
            resume_rva,
            semantics: vm_rewrite.semantics,
        });
    }

    Ok(applied_patches)
}

pub fn pointer_references_outside_vm_patches(
    pointer_references: &[ImportPointerReference],
    vm_patches: &[AppliedVmPatch],
) -> Vec<ImportPointerReference> {
    pointer_references
        .iter()
        .copied()
        .filter(|pointer_reference| {
            let instruction_begin = u128::from(pointer_reference.instruction_rva);
            let instruction_end =
                instruction_begin + u128::from(pointer_reference.instruction_size);
            !vm_patches.iter().any(|vm_patch| {
                let patch_begin = u128::from(vm_patch.patch_rva);
                let patch_end = patch_begin + vm_patch.patch_byte_count as u128;
                instruction_begin < patch_end && patch_begin < instruction_end
            })
        })
        .collect()
}

pub fn verify_applied_patches(
    architecture: Architecture,
    module_base: u64,
    module_snapshot: &[u8],
    pointer_patches: &[AppliedPointerPatch],
    vm_patches: &[AppliedVmPatch],
    import_layout: &ImportSectionLayout,
) -> Result<(), PatchError> {
    let mut written_ranges = Vec::with_capacity(pointer_patches.len() + vm_patches.len());
    let valid_iat_addresses = import_layout
        .rebuilt_pointers
        .iter()
        .map(|rebuilt_pointer| {
            module_base
                .checked_add(u64::from(rebuilt_pointer.pointer_rva))
                .ok_or(PatchError::ArithmeticOverflow)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;

    for patch in pointer_patches {
        let patch_end = add_rva(patch.patch_rva, usize::from(patch.patch_byte_count))?;
        let instruction = decode_instruction_at(
            architecture,
            module_base,
            module_snapshot,
            patch.instruction_rva,
        )?;
        if instruction.len() != usize::from(patch.instruction_size) {
            return Err(PatchError::InstructionChanged {
                instruction_rva: patch.instruction_rva,
                expected_size: patch.instruction_size,
                actual_size: instruction.len(),
            });
        }
        let instruction_end = add_rva(patch.instruction_rva, instruction.len())?;
        if patch.patch_rva < patch.instruction_rva || patch_end > instruction_end {
            return Err(PatchError::PatchRangeOutsideInstruction {
                instruction_rva: patch.instruction_rva,
                patch_rva: patch.patch_rva,
            });
        }
        let expected_address = module_base
            .checked_add(u64::from(patch.pointer_rva))
            .ok_or(PatchError::ArithmeticOverflow)?;
        let static_addresses = instruction_static_addresses(&instruction);
        if !valid_iat_addresses.contains(&expected_address)
            || !static_addresses.contains(&expected_address)
        {
            return Err(PatchError::GeneratedImportTargetMismatch {
                instruction_rva: patch.instruction_rva,
                expected_address,
                actual_address: static_addresses.into_iter().next(),
            });
        }
        written_ranges.push((patch.patch_rva, patch_end));
    }

    let mut expected_relocations = BTreeSet::new();
    for patch in vm_patches {
        let patch_end = add_rva(patch.patch_rva, patch.patch_byte_count)?;
        let patch_bytes = module_snapshot
            .get(patch.patch_rva as usize..patch_end as usize)
            .ok_or(PatchError::InstructionOutsideSnapshot(patch.patch_rva))?;
        let patch_address = module_base
            .checked_add(u64::from(patch.patch_rva))
            .ok_or(PatchError::ArithmeticOverflow)?;
        let mut decoder = Decoder::with_ip(
            architecture_bitness(architecture),
            patch_bytes,
            patch_address,
            DecoderOptions::NONE,
        );
        let mut decoded_instructions = Vec::new();
        while decoder.can_decode() {
            let instruction = decoder.decode();
            let instruction_rva = u32::try_from(
                instruction
                    .ip()
                    .checked_sub(module_base)
                    .ok_or(PatchError::ArithmeticOverflow)?,
            )
            .map_err(|_| PatchError::ArithmeticOverflow)?;
            if instruction.is_invalid() {
                return Err(PatchError::InvalidInstruction(instruction_rva));
            }

            let has_memory_operand = (0..instruction.op_count())
                .any(|operand| instruction.op_kind(operand) == OpKind::Memory);
            if architecture == Architecture::X86
                && has_memory_operand
                && instruction.memory_base() == Register::None
                && instruction.memory_index() == Register::None
            {
                let target_address = instruction.memory_displacement64();
                if !valid_iat_addresses.contains(&target_address) {
                    let expected_address = module_base
                        .checked_add(u64::from(patch.pointer_rva))
                        .ok_or(PatchError::ArithmeticOverflow)?;
                    return Err(PatchError::GeneratedImportTargetMismatch {
                        instruction_rva,
                        expected_address,
                        actual_address: Some(target_address),
                    });
                }
                let constant_offsets = decoder.get_constant_offsets(&instruction);
                let byte_count = constant_offsets.displacement_size();
                if byte_count != 4 {
                    return Err(PatchError::UnsupportedEncodedConstant {
                        instruction_rva,
                        byte_count,
                    });
                }
                expected_relocations.insert(add_rva(
                    instruction_rva,
                    constant_offsets.displacement_offset(),
                )?);
            }
            decoded_instructions.push(instruction);
        }
        verify_vm_instructions(architecture, module_base, patch, &decoded_instructions)?;
        written_ranges.push((patch.patch_rva, patch_end));
    }

    written_ranges.sort_unstable();
    for ranges in written_ranges.windows(2) {
        let [(first_rva, first_end), (second_rva, _)] = ranges else {
            unreachable!("a two-element window has two ranges");
        };
        if second_rva < first_end {
            return Err(PatchError::PatchRangesOverlap {
                first_rva: *first_rva,
                second_rva: *second_rva,
            });
        }
    }

    let mut actual_relocations = import_layout.base_relocation_rvas.clone();
    actual_relocations.sort_unstable();
    let expected_relocations = expected_relocations.into_iter().collect::<Vec<_>>();
    if actual_relocations != expected_relocations {
        return Err(PatchError::GeneratedRelocationsMismatch {
            expected: expected_relocations,
            actual: actual_relocations,
        });
    }

    Ok(())
}

fn verify_vm_instructions(
    architecture: Architecture,
    module_base: u64,
    patch: &AppliedVmPatch,
    instructions: &[Instruction],
) -> Result<(), PatchError> {
    let Some(first_instruction) = instructions.first() else {
        return Err(PatchError::GeneratedInstructionMismatch {
            instruction_rva: patch.patch_rva,
            expected: "a direct IAT instruction",
        });
    };
    let expected_address = module_base
        .checked_add(u64::from(patch.pointer_rva))
        .ok_or(PatchError::ArithmeticOverflow)?;
    let actual_address = instruction_static_memory_address(first_instruction);
    if actual_address != Some(expected_address) {
        return Err(PatchError::GeneratedImportTargetMismatch {
            instruction_rva: patch.patch_rva,
            expected_address,
            actual_address,
        });
    }

    match patch.semantics {
        VmImportSemantics::ExternalTransfer {
            resume_rva: Some(resume_rva),
            ..
        } => {
            let resume_address = module_base
                .checked_add(u64::from(resume_rva))
                .ok_or(PatchError::ArithmeticOverflow)?;
            let continuation_is_direct = instructions.len() == 1
                && first_instruction.mnemonic() == Mnemonic::Call
                && first_instruction.next_ip() == resume_address;
            let continuation_uses_jump = instructions.len() == 2
                && first_instruction.mnemonic() == Mnemonic::Call
                && first_instruction.next_ip() == instructions[1].ip()
                && instructions[1].mnemonic() == Mnemonic::Jmp
                && is_near_branch(instructions[1].op0_kind())
                && instructions[1].near_branch_target() == resume_address;
            if !continuation_is_direct && !continuation_uses_jump {
                return Err(PatchError::GeneratedInstructionMismatch {
                    instruction_rva: patch.patch_rva,
                    expected: "call [IAT] followed by the proven continuation",
                });
            }
        }
        VmImportSemantics::ExternalTransfer {
            resume_rva: None, ..
        } => {
            if instructions.len() != 1 || first_instruction.mnemonic() != Mnemonic::Jmp {
                return Err(PatchError::GeneratedInstructionMismatch {
                    instruction_rva: patch.patch_rva,
                    expected: "jmp [IAT]",
                });
            }
        }
        VmImportSemantics::RegisterLoad {
            register,
            continuation_rva,
            ..
        } => {
            let expected_register = iced_register(architecture, register).ok_or(
                PatchError::RegisterArchitectureMismatch {
                    architecture,
                    register,
                },
            )?;
            let continuation_address = module_base
                .checked_add(u64::from(continuation_rva))
                .ok_or(PatchError::ArithmeticOverflow)?;
            if instructions.len() != 1
                || first_instruction.mnemonic() != Mnemonic::Mov
                || first_instruction.op0_kind() != OpKind::Register
                || first_instruction.op0_register() != expected_register
                || first_instruction.next_ip() != continuation_address
            {
                return Err(PatchError::GeneratedInstructionMismatch {
                    instruction_rva: patch.patch_rva,
                    expected: "mov reg, [IAT] ending at the proven continuation",
                });
            }
        }
    }
    Ok(())
}

fn instruction_static_addresses(instruction: &Instruction) -> Vec<u64> {
    let mut addresses = Vec::new();
    if let Some(address) = instruction_static_memory_address(instruction) {
        addresses.push(address);
    }
    for operand_index in 0..instruction.op_count() {
        if matches!(
            instruction.op_kind(operand_index),
            OpKind::Immediate32 | OpKind::Immediate64 | OpKind::Immediate32to64
        ) {
            addresses.push(instruction.immediate(operand_index));
        }
    }
    addresses
}

fn instruction_static_memory_address(instruction: &Instruction) -> Option<u64> {
    let has_memory_operand = (0..instruction.op_count())
        .any(|operand_index| instruction.op_kind(operand_index) == OpKind::Memory);
    if !has_memory_operand {
        return None;
    }
    if instruction.is_ip_rel_memory_operand() {
        return Some(instruction.ip_rel_memory_address());
    }
    (instruction.memory_base() == Register::None && instruction.memory_index() == Register::None)
        .then(|| instruction.memory_displacement64())
}

const fn is_near_branch(operand: OpKind) -> bool {
    matches!(
        operand,
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
}

fn decode_instruction_at(
    architecture: Architecture,
    module_base: u64,
    module_snapshot: &[u8],
    instruction_rva: u32,
) -> Result<Instruction, PatchError> {
    let instruction_bytes = module_snapshot
        .get(instruction_rva as usize..)
        .ok_or(PatchError::InstructionOutsideSnapshot(instruction_rva))?;
    let instruction_address = module_base
        .checked_add(u64::from(instruction_rva))
        .ok_or(PatchError::ArithmeticOverflow)?;
    let mut decoder = Decoder::with_ip(
        architecture_bitness(architecture),
        instruction_bytes,
        instruction_address,
        DecoderOptions::NONE,
    );
    let instruction = decoder.decode();
    if instruction.is_invalid() {
        return Err(PatchError::InvalidInstruction(instruction_rva));
    }
    Ok(instruction)
}

fn normalize_vm_rewrite(
    architecture: Architecture,
    module_snapshot: &[u8],
    vm_rewrite: VmImportRewrite,
) -> VmImportRewrite {
    let VmImportSemantics::ExternalTransfer {
        destination_address,
        stack_pointer_delta,
        resume_rva: Some(resume_rva),
    } = vm_rewrite.semantics
    else {
        return vm_rewrite;
    };
    let pointer_size = match architecture {
        Architecture::X86 => 4_i64,
        Architecture::X64 => 8_i64,
    };
    if stack_pointer_delta != -pointer_size {
        return vm_rewrite;
    }
    let Some((continuation_rva, register)) =
        indirect_register_call_before_rva(architecture, module_snapshot, resume_rva)
    else {
        return vm_rewrite;
    };
    if preceding_register_pop_rva(
        architecture,
        module_snapshot,
        vm_rewrite.transfer.instruction_rva,
        register,
    )
    .is_none()
    {
        return vm_rewrite;
    }

    // @note: some VMProtect variants enter the import before emulation can observe
    // the loaded register. A matching POP before E8 and CALL reg ending at the reported
    // return address proves that the original operation was MOV reg, [IAT].
    VmImportRewrite {
        transfer: vm_rewrite.transfer,
        semantics: VmImportSemantics::RegisterLoad {
            register,
            destination_address,
            continuation_rva,
        },
    }
}

fn prepare_direct_vm_patch(
    architecture: Architecture,
    module_base: u64,
    module_snapshot: &[u8],
    pointer_rva: u32,
    vm_rewrite: VmImportRewrite,
) -> Result<Option<DirectVmPatch>, PatchError> {
    if let VmImportSemantics::RegisterLoad {
        register,
        continuation_rva,
        ..
    } = vm_rewrite.semantics
    {
        return prepare_direct_register_load(
            architecture,
            module_base,
            module_snapshot,
            pointer_rva,
            vm_rewrite.transfer,
            register,
            continuation_rva,
        );
    }
    let VmImportSemantics::ExternalTransfer {
        stack_pointer_delta,
        resume_rva,
        ..
    } = vm_rewrite.semantics
    else {
        return Ok(None);
    };
    validate_vm_transfer(
        architecture,
        module_base,
        module_snapshot,
        vm_rewrite.transfer,
    )?;

    let discarded_stack_byte_count = match vm_stack_discard_size(
        architecture,
        vm_rewrite.transfer,
        stack_pointer_delta,
        resume_rva,
    ) {
        Ok(byte_count) => byte_count,
        Err(PatchError::InvalidExternalStackDelta { .. }) => return Ok(None),
        Err(failure) => return Err(failure),
    };
    let pointer_size = match architecture {
        Architecture::X86 => 4,
        Architecture::X64 => 8,
    };
    let patch_rva = if discarded_stack_byte_count == 0 {
        vm_rewrite.transfer.instruction_rva
    } else if discarded_stack_byte_count == pointer_size {
        let Some(push_rva) = preceding_register_push_rva(
            architecture,
            module_snapshot,
            vm_rewrite.transfer.instruction_rva,
        ) else {
            return Ok(None);
        };
        push_rva
    } else {
        return Ok(None);
    };
    let replacement_opcode = if resume_rva.is_some() {
        TransferOpcode::Call
    } else {
        TransferOpcode::Jump
    };
    let (mut bytes, base_relocation_rvas) = encode_direct_import_transfer(
        architecture,
        module_base,
        patch_rva,
        pointer_rva,
        replacement_opcode,
    )?;
    let transfer_end_rva = vm_rewrite
        .transfer
        .instruction_rva
        .checked_add(u32::from(vm_rewrite.transfer.instruction_size))
        .ok_or(PatchError::ArithmeticOverflow)?;
    let patch_end_rva = if let Some(resume_rva) = resume_rva {
        resume_rva
    } else if patch_rva < vm_rewrite.transfer.instruction_rva {
        transfer_end_rva
    } else {
        patch_rva
            .checked_add(u32::try_from(bytes.len()).map_err(|_| PatchError::ArithmeticOverflow)?)
            .ok_or(PatchError::ArithmeticOverflow)?
    };
    let patch_byte_count = patch_end_rva
        .checked_sub(patch_rva)
        .and_then(|byte_count| usize::try_from(byte_count).ok())
        .ok_or(PatchError::ArithmeticOverflow)?;

    if resume_rva.is_some() {
        if bytes.len() > patch_byte_count {
            return Ok(None);
        }
        if bytes.len() < patch_byte_count {
            let remaining_byte_count = patch_byte_count - bytes.len();
            if remaining_byte_count < 2 {
                return Ok(None);
            }
            let jump_rva = add_rva(patch_rva, bytes.len())?;
            let jump = encode_continuation_jump(
                architecture,
                jump_rva,
                patch_end_rva,
                remaining_byte_count,
            )?;
            bytes.extend_from_slice(&jump);
        }
    } else if bytes.len() != patch_byte_count {
        return Ok(None);
    }

    let patch_offset = patch_rva as usize;
    let patch_end = patch_offset
        .checked_add(bytes.len())
        .ok_or(PatchError::ArithmeticOverflow)?;
    if module_snapshot.get(patch_offset..patch_end).is_none() {
        return Ok(None);
    }

    Ok(Some(DirectVmPatch {
        patch_rva,
        bytes,
        base_relocation_rvas,
    }))
}

fn prepare_direct_register_load(
    architecture: Architecture,
    module_base: u64,
    module_snapshot: &[u8],
    pointer_rva: u32,
    transfer: VmTransfer,
    register: GeneralRegister,
    continuation_rva: u32,
) -> Result<Option<DirectVmPatch>, PatchError> {
    if transfer.opcode != TransferOpcode::Call {
        return Ok(None);
    }
    validate_vm_transfer(architecture, module_base, module_snapshot, transfer)?;
    let patch_rva = if architecture == Architecture::X86 && register == GeneralRegister::Eax {
        transfer.instruction_rva
    } else {
        // @note: a VMProtect transform can preserve the original MOV width with a matching POP
        // immediately before E8; replace that complete transformation, not the call alone.
        let Some(stack_setup_rva) = preceding_register_setup_rva(
            architecture,
            module_snapshot,
            transfer.instruction_rva,
            register,
        ) else {
            return Ok(None);
        };
        stack_setup_rva
    };
    let instruction = match architecture {
        Architecture::X86 if register == GeneralRegister::Eax => {
            let pointer_address = x86_virtual_address(module_base, pointer_rva, patch_rva)?;
            Instruction::with2(
                Code::Mov_EAX_moffs32,
                Register::EAX,
                MemoryOperand::with_displ(u64::from(pointer_address), 4),
            )
            .map_err(instruction_encoding_error)?
        }
        Architecture::X86 => {
            let target_register = iced_register(architecture, register).ok_or(
                PatchError::RegisterArchitectureMismatch {
                    architecture,
                    register,
                },
            )?;
            let pointer_address = x86_virtual_address(module_base, pointer_rva, patch_rva)?;
            Instruction::with2(
                Code::Mov_r32_rm32,
                target_register,
                MemoryOperand::with_displ(u64::from(pointer_address), 4),
            )
            .map_err(instruction_encoding_error)?
        }
        Architecture::X64 => {
            let target_register = iced_register(architecture, register).ok_or(
                PatchError::RegisterArchitectureMismatch {
                    architecture,
                    register,
                },
            )?;
            Instruction::with2(
                Code::Mov_r64_rm64,
                target_register,
                MemoryOperand::with_base_displ(Register::RIP, i64::from(pointer_rva)),
            )
            .map_err(instruction_encoding_error)?
        }
    };
    let mut bytes = Vec::new();
    let mut base_relocation_rvas = Vec::new();
    if architecture == Architecture::X86 {
        append_x86_instruction(
            &mut bytes,
            &mut base_relocation_rvas,
            patch_rva,
            &instruction,
        )?;
    } else {
        let mut encoder = Encoder::new(64);
        encoder
            .encode(&instruction, u64::from(patch_rva))
            .map_err(instruction_encoding_error)?;
        bytes = encoder.take_buffer();
    }
    let patch_byte_count = continuation_rva
        .checked_sub(patch_rva)
        .and_then(|byte_count| usize::try_from(byte_count).ok())
        .ok_or(PatchError::ArithmeticOverflow)?;
    if bytes.len() != patch_byte_count {
        return Ok(None);
    }

    Ok(Some(DirectVmPatch {
        patch_rva,
        bytes,
        base_relocation_rvas,
    }))
}

fn encode_direct_import_transfer(
    architecture: Architecture,
    module_base: u64,
    instruction_rva: u32,
    pointer_rva: u32,
    opcode: TransferOpcode,
) -> Result<(Vec<u8>, Vec<u32>), PatchError> {
    let code = match (architecture, opcode) {
        (Architecture::X86, TransferOpcode::Call) => Code::Call_rm32,
        (Architecture::X86, TransferOpcode::Jump) => Code::Jmp_rm32,
        (Architecture::X64, TransferOpcode::Call) => Code::Call_rm64,
        (Architecture::X64, TransferOpcode::Jump) => Code::Jmp_rm64,
    };
    let memory = match architecture {
        Architecture::X86 => MemoryOperand::with_displ(
            u64::from(x86_virtual_address(
                module_base,
                pointer_rva,
                instruction_rva,
            )?),
            4,
        ),
        Architecture::X64 => MemoryOperand::with_base_displ(Register::RIP, i64::from(pointer_rva)),
    };
    let instruction = Instruction::with1(code, memory).map_err(instruction_encoding_error)?;
    let mut bytes = Vec::new();
    let mut base_relocation_rvas = Vec::new();
    if architecture == Architecture::X86 {
        append_x86_instruction(
            &mut bytes,
            &mut base_relocation_rvas,
            instruction_rva,
            &instruction,
        )?;
    } else {
        let mut encoder = Encoder::new(64);
        encoder
            .encode(&instruction, u64::from(instruction_rva))
            .map_err(instruction_encoding_error)?;
        bytes = encoder.take_buffer();
    }
    Ok((bytes, base_relocation_rvas))
}

fn encode_continuation_jump(
    architecture: Architecture,
    instruction_rva: u32,
    destination_rva: u32,
    available_byte_count: usize,
) -> Result<Vec<u8>, PatchError> {
    let short_next_rva = instruction_rva
        .checked_add(2)
        .ok_or(PatchError::ArithmeticOverflow)?;
    let short_displacement = i64::from(destination_rva) - i64::from(short_next_rva);
    let code = if i8::try_from(short_displacement).is_ok() {
        match architecture {
            Architecture::X86 => Code::Jmp_rel8_32,
            Architecture::X64 => Code::Jmp_rel8_64,
        }
    } else if available_byte_count >= 5 {
        match architecture {
            Architecture::X86 => Code::Jmp_rel32_32,
            Architecture::X64 => Code::Jmp_rel32_64,
        }
    } else {
        return Err(PatchError::RelativeAddressOutsideRange {
            source_rva: instruction_rva,
            destination_rva,
        });
    };
    let instruction = Instruction::with_branch(code, u64::from(destination_rva))
        .map_err(instruction_encoding_error)?;
    let mut encoder = Encoder::new(architecture_bitness(architecture));
    encoder
        .encode(&instruction, u64::from(instruction_rva))
        .map_err(instruction_encoding_error)?;
    let bytes = encoder.take_buffer();
    if bytes.len() > available_byte_count {
        return Err(PatchError::RelativeAddressOutsideRange {
            source_rva: instruction_rva,
            destination_rva,
        });
    }
    Ok(bytes)
}

fn preceding_register_push_rva(
    architecture: Architecture,
    module_snapshot: &[u8],
    instruction_rva: u32,
) -> Option<u32> {
    let push_code = match architecture {
        Architecture::X86 => Code::Push_r32,
        Architecture::X64 => Code::Push_r64,
    };
    preceding_register_instruction(architecture, module_snapshot, instruction_rva, &[push_code])
        .map(|(push_rva, _, _)| push_rva)
}

fn preceding_register_pop_rva(
    architecture: Architecture,
    module_snapshot: &[u8],
    instruction_rva: u32,
    register: GeneralRegister,
) -> Option<u32> {
    let pop_code = match architecture {
        Architecture::X86 => Code::Pop_r32,
        Architecture::X64 => Code::Pop_r64,
    };
    let (pop_rva, _, actual_register) = preceding_register_instruction(
        architecture,
        module_snapshot,
        instruction_rva,
        &[pop_code],
    )?;
    let expected_register = iced_register(architecture, register)?;
    (actual_register == expected_register).then_some(pop_rva)
}

fn preceding_register_setup_rva(
    architecture: Architecture,
    module_snapshot: &[u8],
    instruction_rva: u32,
    destination_register: GeneralRegister,
) -> Option<u32> {
    let (push_code, pop_code) = match architecture {
        Architecture::X86 => (Code::Push_r32, Code::Pop_r32),
        Architecture::X64 => (Code::Push_r64, Code::Pop_r64),
    };
    let (setup_rva, code, actual_register) = preceding_register_instruction(
        architecture,
        module_snapshot,
        instruction_rva,
        &[push_code, pop_code],
    )?;
    let destination_register = iced_register(architecture, destination_register)?;

    // @note: a VMProtect stub can save a scratch register immediately before E8 while the
    // protected stub consumes that save. A same-register PUSH belongs to the original
    // function's preservation contract and must remain intact.
    match code {
        code if code == pop_code && actual_register == destination_register => Some(setup_rva),
        code if code == push_code && actual_register != destination_register => Some(setup_rva),
        _ => None,
    }
}

fn indirect_register_call_before_rva(
    architecture: Architecture,
    module_snapshot: &[u8],
    resume_rva: u32,
) -> Option<(u32, GeneralRegister)> {
    let call_code = match architecture {
        Architecture::X86 => Code::Call_rm32,
        Architecture::X64 => Code::Call_rm64,
    };
    let (call_rva, _, register) =
        preceding_register_instruction(architecture, module_snapshot, resume_rva, &[call_code])?;

    general_register(register).map(|register| (call_rva, register))
}

fn preceding_register_instruction(
    architecture: Architecture,
    module_snapshot: &[u8],
    end_rva: u32,
    codes: &[Code],
) -> Option<(u32, Code, Register)> {
    let end_offset = end_rva as usize;
    let mut matched_instruction = None;

    for &code in codes {
        for &register in architecture_registers(architecture) {
            let instruction = Instruction::with1(code, register).ok()?;
            let mut encoder = Encoder::new(architecture_bitness(architecture));
            encoder.encode(&instruction, 0).ok()?;
            let instruction_bytes = encoder.take_buffer();
            let instruction_offset = end_offset.checked_sub(instruction_bytes.len())?;
            if module_snapshot.get(instruction_offset..end_offset) != Some(&instruction_bytes) {
                continue;
            }

            let instruction_rva =
                end_rva.checked_sub(u32::try_from(instruction_bytes.len()).ok()?)?;
            let candidate = (instruction_rva, code, register, instruction_bytes.len());
            match matched_instruction {
                None => matched_instruction = Some(candidate),
                Some((_, _, _, matched_byte_count))
                    if instruction_bytes.len() > matched_byte_count =>
                {
                    matched_instruction = Some(candidate);
                }
                Some((_, matched_code, matched_register, matched_byte_count))
                    if instruction_bytes.len() == matched_byte_count
                        && (code != matched_code || register != matched_register) =>
                {
                    return None;
                }
                _ => {}
            }
        }
    }

    matched_instruction.map(|(rva, code, register, _)| (rva, code, register))
}

const fn architecture_registers(architecture: Architecture) -> &'static [Register] {
    match architecture {
        Architecture::X86 => &[
            Register::EAX,
            Register::ECX,
            Register::EDX,
            Register::EBX,
            Register::ESP,
            Register::EBP,
            Register::ESI,
            Register::EDI,
        ],
        Architecture::X64 => &[
            Register::RAX,
            Register::RCX,
            Register::RDX,
            Register::RBX,
            Register::RSP,
            Register::RBP,
            Register::RSI,
            Register::RDI,
            Register::R8,
            Register::R9,
            Register::R10,
            Register::R11,
            Register::R12,
            Register::R13,
            Register::R14,
            Register::R15,
        ],
    }
}

fn rebuilt_pointer_rva(
    import_layout: &ImportSectionLayout,
    destination_address: u64,
) -> Result<u32, PatchError> {
    import_layout
        .rebuilt_pointers
        .iter()
        .find(|rebuilt_pointer| {
            rebuilt_pointer.recovered_import.destination_address == destination_address
        })
        .map(|rebuilt_pointer| rebuilt_pointer.pointer_rva)
        .ok_or(PatchError::MissingRebuiltPointer(destination_address))
}

fn validate_vm_transfer(
    architecture: Architecture,
    module_base: u64,
    module_snapshot: &[u8],
    transfer: VmTransfer,
) -> Result<(), PatchError> {
    let instruction_offset = transfer.instruction_rva as usize;
    let instruction_size = usize::from(transfer.instruction_size);
    let instruction_end = instruction_offset
        .checked_add(instruction_size)
        .ok_or(PatchError::ArithmeticOverflow)?;
    let instruction_bytes = module_snapshot
        .get(instruction_offset..instruction_end)
        .ok_or(PatchError::InstructionOutsideSnapshot(
            transfer.instruction_rva,
        ))?;
    let instruction_address = module_base
        .checked_add(u64::from(transfer.instruction_rva))
        .ok_or(PatchError::ArithmeticOverflow)?;
    let mut decoder = Decoder::with_ip(
        architecture_bitness(architecture),
        instruction_bytes,
        instruction_address,
        DecoderOptions::NONE,
    );
    let instruction = decoder.decode();
    let expected_code = match (architecture, transfer.opcode) {
        (Architecture::X86, TransferOpcode::Call) => Code::Call_rel32_32,
        (Architecture::X86, TransferOpcode::Jump) => Code::Jmp_rel32_32,
        (Architecture::X64, TransferOpcode::Call) => Code::Call_rel32_64,
        (Architecture::X64, TransferOpcode::Jump) => Code::Jmp_rel32_64,
    };
    let return_address_matches = match transfer.return_rva {
        Some(return_rva) => module_base
            .checked_add(u64::from(return_rva))
            .is_some_and(|return_address| return_address == instruction.next_ip()),
        None => transfer.opcode == TransferOpcode::Jump,
    };
    if instruction.is_invalid()
        || instruction.len() != instruction_size
        || instruction.code() != expected_code
        || !return_address_matches
    {
        return Err(PatchError::VmOpcodeChanged(transfer.instruction_rva));
    }
    Ok(())
}

fn vm_stack_discard_size(
    architecture: Architecture,
    transfer: VmTransfer,
    stack_pointer_delta: i64,
    resume_rva: Option<u32>,
) -> Result<usize, PatchError> {
    let stack_pointer_delta = usize::try_from(stack_pointer_delta).map_err(|_| {
        PatchError::InvalidExternalStackDelta {
            instruction_rva: transfer.instruction_rva,
            stack_pointer_delta,
        }
    })?;
    let pointer_size = match architecture {
        Architecture::X86 => 4,
        Architecture::X64 => 8,
    };
    let discarded_stack_byte_count = match (resume_rva, transfer.opcode) {
        (Some(_), _) | (None, TransferOpcode::Jump) => stack_pointer_delta,
        (None, TransferOpcode::Call) => stack_pointer_delta.checked_sub(pointer_size).ok_or(
            PatchError::InvalidExternalStackDelta {
                instruction_rva: transfer.instruction_rva,
                stack_pointer_delta: stack_pointer_delta as i64,
            },
        )?,
    };
    if !discarded_stack_byte_count.is_multiple_of(pointer_size)
        || i32::try_from(discarded_stack_byte_count).is_err()
    {
        return Err(PatchError::InvalidExternalStackDelta {
            instruction_rva: transfer.instruction_rva,
            stack_pointer_delta: stack_pointer_delta as i64,
        });
    }
    Ok(discarded_stack_byte_count)
}

fn append_x86_instruction(
    bytes: &mut Vec<u8>,
    base_relocation_rvas: &mut Vec<u32>,
    code_rva: u32,
    instruction: &Instruction,
) -> Result<(), PatchError> {
    let instruction_rva = add_rva(code_rva, bytes.len())?;
    let mut encoder = Encoder::new(32);
    encoder
        .encode(instruction, u64::from(instruction_rva))
        .map_err(instruction_encoding_error)?;
    let constant_offsets = encoder.get_constant_offsets();
    let offset = constant_offsets.displacement_offset();
    let byte_count = constant_offsets.displacement_size();
    if byte_count != 4 {
        return Err(PatchError::UnsupportedEncodedConstant {
            instruction_rva,
            byte_count,
        });
    }
    base_relocation_rvas.push(add_rva(instruction_rva, offset)?);
    bytes.extend_from_slice(&encoder.take_buffer());
    Ok(())
}

fn x86_virtual_address(
    module_base: u64,
    rva: u32,
    instruction_rva: u32,
) -> Result<u32, PatchError> {
    let address = module_base
        .checked_add(u64::from(rva))
        .ok_or(PatchError::ArithmeticOverflow)?;
    u32::try_from(address).map_err(|_| PatchError::AddressOutsideEncodedRange {
        instruction_rva,
        address,
        byte_count: 4,
    })
}

fn add_rva(rva: u32, byte_count: usize) -> Result<u32, PatchError> {
    rva.checked_add(u32::try_from(byte_count).map_err(|_| PatchError::ArithmeticOverflow)?)
        .ok_or(PatchError::ArithmeticOverflow)
}

fn write_unsigned_constant(
    bytes: &mut [u8],
    offset: usize,
    byte_count: usize,
    bits: u64,
    instruction_rva: u32,
) -> Result<(), PatchError> {
    let encoded = bits.to_le_bytes();
    if !matches!(byte_count, 1 | 2 | 4 | 8) {
        return Err(PatchError::UnsupportedEncodedConstant {
            instruction_rva,
            byte_count,
        });
    }
    if byte_count < 8 && bits >= 1_u64 << (byte_count * 8) {
        return Err(PatchError::AddressOutsideEncodedRange {
            instruction_rva,
            address: bits,
            byte_count,
        });
    }
    let destination = bytes
        .get_mut(offset..offset + byte_count)
        .ok_or(PatchError::InstructionOutsideSnapshot(instruction_rva))?;
    destination.copy_from_slice(&encoded[..byte_count]);
    Ok(())
}

const fn architecture_bitness(architecture: Architecture) -> u32 {
    match architecture {
        Architecture::X86 => 32,
        Architecture::X64 => 64,
    }
}

fn instruction_encoding_error(source: IcedError) -> PatchError {
    PatchError::InstructionEncoding(source.to_string())
}

fn iced_register(architecture: Architecture, register: GeneralRegister) -> Option<Register> {
    let register = match register {
        GeneralRegister::Eax => Register::EAX,
        GeneralRegister::Ecx => Register::ECX,
        GeneralRegister::Edx => Register::EDX,
        GeneralRegister::Ebx => Register::EBX,
        GeneralRegister::Ebp => Register::EBP,
        GeneralRegister::Esi => Register::ESI,
        GeneralRegister::Edi => Register::EDI,
        GeneralRegister::Rax => Register::RAX,
        GeneralRegister::Rcx => Register::RCX,
        GeneralRegister::Rdx => Register::RDX,
        GeneralRegister::Rbx => Register::RBX,
        GeneralRegister::Rbp => Register::RBP,
        GeneralRegister::Rsi => Register::RSI,
        GeneralRegister::Rdi => Register::RDI,
        GeneralRegister::R8 => Register::R8,
        GeneralRegister::R9 => Register::R9,
        GeneralRegister::R10 => Register::R10,
        GeneralRegister::R11 => Register::R11,
        GeneralRegister::R12 => Register::R12,
        GeneralRegister::R13 => Register::R13,
        GeneralRegister::R14 => Register::R14,
        GeneralRegister::R15 => Register::R15,
    };
    match architecture {
        Architecture::X86 if register.is_gpr32() => Some(register),
        Architecture::X64 if register.is_gpr64() => Some(register),
        _ => None,
    }
}

const fn general_register(register: Register) -> Option<GeneralRegister> {
    match register {
        Register::EAX => Some(GeneralRegister::Eax),
        Register::ECX => Some(GeneralRegister::Ecx),
        Register::EDX => Some(GeneralRegister::Edx),
        Register::EBX => Some(GeneralRegister::Ebx),
        Register::EBP => Some(GeneralRegister::Ebp),
        Register::ESI => Some(GeneralRegister::Esi),
        Register::EDI => Some(GeneralRegister::Edi),
        Register::RAX => Some(GeneralRegister::Rax),
        Register::RCX => Some(GeneralRegister::Rcx),
        Register::RDX => Some(GeneralRegister::Rdx),
        Register::RBX => Some(GeneralRegister::Rbx),
        Register::RBP => Some(GeneralRegister::Rbp),
        Register::RSI => Some(GeneralRegister::Rsi),
        Register::RDI => Some(GeneralRegister::Rdi),
        Register::R8 => Some(GeneralRegister::R8),
        Register::R9 => Some(GeneralRegister::R9),
        Register::R10 => Some(GeneralRegister::R10),
        Register::R11 => Some(GeneralRegister::R11),
        Register::R12 => Some(GeneralRegister::R12),
        Register::R13 => Some(GeneralRegister::R13),
        Register::R14 => Some(GeneralRegister::R14),
        Register::R15 => Some(GeneralRegister::R15),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use iced_x86::Mnemonic;

    use crate::{
        import_layout::RebuiltImportPointer,
        imports::{ImportSymbol, RecoveredImport},
    };

    use super::*;

    #[test]
    fn rewrites_x86_absolute_import_pointer() {
        const MODULE_BASE: u64 = 0x400000;
        let mut module_snapshot = vec![0_u8; 0x2000];
        module_snapshot[0x1000..0x1006].copy_from_slice(&[0xff, 0x15, 0x00, 0x20, 0x40, 0x00]);
        let pointer_references = [ImportPointerReference {
            instruction_rva: 0x1000,
            instruction_size: 6,
            mnemonic: Mnemonic::Call,
            operand_index: 0,
            operand: PointerOperand::Memory,
            pointer_rva: 0x2000,
            destination_address: 0x7654_3210,
        }];
        let import_layout = sample_layout(0x3000, 0x7654_3210);

        let applied_patches = rewrite_pointer_operands(
            Architecture::X86,
            MODULE_BASE,
            &mut module_snapshot,
            &pointer_references,
            &import_layout,
        )
        .expect("valid x86 pointer rewrite");

        assert_eq!(&module_snapshot[0x1002..0x1006], &[0x00, 0x30, 0x40, 0x00]);
        verify_applied_patches(
            Architecture::X86,
            MODULE_BASE,
            &module_snapshot,
            &applied_patches,
            &[],
            &import_layout,
        )
        .expect("the rewritten x86 operand targets the rebuilt IAT");
    }

    #[test]
    fn rewrites_x64_rip_relative_import_pointer() {
        const MODULE_BASE: u64 = 0x0000_7ff6_0000_0000;
        let mut module_snapshot = vec![0_u8; 0x3000];
        module_snapshot[0x1000..0x1007]
            .copy_from_slice(&[0x48, 0x8b, 0x05, 0xf9, 0x0f, 0x00, 0x00]);
        let pointer_references = [ImportPointerReference {
            instruction_rva: 0x1000,
            instruction_size: 7,
            mnemonic: Mnemonic::Mov,
            operand_index: 1,
            operand: PointerOperand::Memory,
            pointer_rva: 0x2000,
            destination_address: 0x0000_7ffa_1234_5678,
        }];
        let import_layout = sample_layout(0x2800, 0x0000_7ffa_1234_5678);

        let applied_patches = rewrite_pointer_operands(
            Architecture::X64,
            MODULE_BASE,
            &mut module_snapshot,
            &pointer_references,
            &import_layout,
        )
        .expect("valid x64 pointer rewrite");

        assert_eq!(&module_snapshot[0x1003..0x1007], &[0xf9, 0x17, 0x00, 0x00]);
        verify_applied_patches(
            Architecture::X64,
            MODULE_BASE,
            &module_snapshot,
            &applied_patches,
            &[],
            &import_layout,
        )
        .expect("the rewritten x64 operand targets the rebuilt IAT");
    }

    #[test]
    fn leaves_x64_transfer_unchanged_when_direct_call_does_not_fit() {
        const MODULE_BASE: u64 = 0x0000_7ff6_0000_0000;
        let mut module_snapshot = vec![0_u8; 0x2000];
        module_snapshot[0x1000..0x1005].copy_from_slice(&[0xe8, 0, 0, 0, 0]);
        let mut import_layout = sample_layout(0x3000, 0x7ffa_1234_5678);
        let original_module_snapshot = module_snapshot.clone();
        let original_layout_bytes = import_layout.bytes.clone();
        let vm_rewrites = [VmImportRewrite {
            transfer: VmTransfer {
                opcode: TransferOpcode::Call,
                instruction_rva: 0x1000,
                instruction_size: 5,
                stub_rva: 0x2000,
                return_rva: Some(0x1005),
            },
            semantics: VmImportSemantics::ExternalTransfer {
                destination_address: 0x7ffa_1234_5678,
                stack_pointer_delta: 0,
                resume_rva: Some(0x1005),
            },
        }];

        let applied_patches = rewrite_vm_transfers(
            Architecture::X64,
            MODULE_BASE,
            &mut module_snapshot,
            &mut import_layout,
            &vm_rewrites,
        )
        .expect("an unavailable direct rewrite must be skipped");

        assert!(applied_patches.is_empty());
        assert_eq!(module_snapshot, original_module_snapshot);
        assert_eq!(import_layout.bytes, original_layout_bytes);
        assert!(import_layout.base_relocation_rvas.is_empty());
    }

    #[test]
    fn rewrites_available_transfers_when_one_direct_rewrite_does_not_fit() {
        const MODULE_BASE: u64 = 0x0000_7ff6_0000_0000;
        let mut module_snapshot = vec![0_u8; 0x2000];
        module_snapshot[0x1000..0x1006].copy_from_slice(&[0xe8, 0, 0, 0, 0, 0xfa]);
        module_snapshot[0x1100..0x1105].copy_from_slice(&[0xe8, 0, 0, 0, 0]);
        let unavailable_transfer_bytes = module_snapshot[0x1100..0x1105].to_vec();
        let mut import_layout = sample_layout(0x3000, 0x7ffa_1234_5678);
        let vm_rewrites = [
            VmImportRewrite {
                transfer: VmTransfer {
                    opcode: TransferOpcode::Call,
                    instruction_rva: 0x1000,
                    instruction_size: 5,
                    stub_rva: 0x2000,
                    return_rva: Some(0x1005),
                },
                semantics: VmImportSemantics::ExternalTransfer {
                    destination_address: 0x7ffa_1234_5678,
                    stack_pointer_delta: 0,
                    resume_rva: Some(0x1006),
                },
            },
            VmImportRewrite {
                transfer: VmTransfer {
                    opcode: TransferOpcode::Call,
                    instruction_rva: 0x1100,
                    instruction_size: 5,
                    stub_rva: 0x2100,
                    return_rva: Some(0x1105),
                },
                semantics: VmImportSemantics::ExternalTransfer {
                    destination_address: 0x7ffa_1234_5678,
                    stack_pointer_delta: 0,
                    resume_rva: Some(0x1105),
                },
            },
        ];

        let applied_patches = rewrite_vm_transfers(
            Architecture::X64,
            MODULE_BASE,
            &mut module_snapshot,
            &mut import_layout,
            &vm_rewrites,
        )
        .expect("the first rewrite must not be cancelled by the second one");

        assert_eq!(applied_patches.len(), 1);
        assert_eq!(applied_patches[0].instruction_rva, 0x1000);
        assert_eq!(&module_snapshot[0x1100..0x1105], unavailable_transfer_bytes);
        assert!(import_layout.base_relocation_rvas.is_empty());
    }

    #[test]
    fn replaces_x64_call_and_protected_byte_directly() {
        const MODULE_BASE: u64 = 0x0000_7ff6_0000_0000;
        let mut module_snapshot = vec![0_u8; 0x2000];
        module_snapshot[0x1000..0x1006].copy_from_slice(&[0xe8, 0, 0, 0, 0, 0xfa]);
        let mut import_layout = sample_layout(0x3000, 0x7ffa_1234_5678);
        let vm_rewrites = [VmImportRewrite {
            transfer: VmTransfer {
                opcode: TransferOpcode::Call,
                instruction_rva: 0x1000,
                instruction_size: 5,
                stub_rva: 0x2000,
                return_rva: Some(0x1005),
            },
            semantics: VmImportSemantics::ExternalTransfer {
                destination_address: 0x7ffa_1234_5678,
                stack_pointer_delta: 0,
                resume_rva: Some(0x1006),
            },
        }];

        let applied_patches = rewrite_vm_transfers(
            Architecture::X64,
            MODULE_BASE,
            &mut module_snapshot,
            &mut import_layout,
            &vm_rewrites,
        )
        .expect("valid direct x64 VM rewrite");

        assert_eq!(applied_patches[0].patch_rva, 0x1000);
        let instructions = decode_instructions(64, &module_snapshot[0x1000..0x1006], 0x1000);
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].mnemonic(), Mnemonic::Call);
        assert_eq!(instructions[0].ip_rel_memory_address(), 0x3000);
        assert_eq!(import_layout.bytes.len(), 0x40);
        assert!(import_layout.base_relocation_rvas.is_empty());
        verify_applied_patches(
            Architecture::X64,
            MODULE_BASE,
            &module_snapshot,
            &[],
            &applied_patches,
            &import_layout,
        )
        .expect("the generated x64 call targets the rebuilt IAT");
    }

    #[test]
    fn replaces_prefixed_x64_call_directly() {
        const MODULE_BASE: u64 = 0x0000_7ff6_0000_0000;
        let mut module_snapshot = vec![0_u8; 0x3000];
        module_snapshot[0x1000..0x1006].copy_from_slice(&[0x2e, 0xe8, 0xfa, 0x0f, 0x00, 0x00]);
        let mut import_layout = sample_layout(0x3000, 0x7ffa_1234_5678);
        let vm_rewrites = [VmImportRewrite {
            transfer: VmTransfer {
                opcode: TransferOpcode::Call,
                instruction_rva: 0x1000,
                instruction_size: 6,
                stub_rva: 0x2000,
                return_rva: Some(0x1006),
            },
            semantics: VmImportSemantics::ExternalTransfer {
                destination_address: 0x7ffa_1234_5678,
                stack_pointer_delta: 0,
                resume_rva: Some(0x1006),
            },
        }];

        let applied_patches = rewrite_vm_transfers(
            Architecture::X64,
            MODULE_BASE,
            &mut module_snapshot,
            &mut import_layout,
            &vm_rewrites,
        )
        .expect("a six-byte prefixed call has room for a direct x64 IAT call");

        assert_eq!(applied_patches.len(), 1);
        assert_eq!(
            &module_snapshot[0x1000..0x1006],
            &[0xff, 0x15, 0xfa, 0x1f, 0x00, 0x00]
        );
        verify_applied_patches(
            Architecture::X64,
            MODULE_BASE,
            &module_snapshot,
            &[],
            &applied_patches,
            &import_layout,
        )
        .expect("the generated x64 call targets the rebuilt IAT");
    }

    #[test]
    fn verifier_rejects_wrong_x64_iat_target() {
        const MODULE_BASE: u64 = 0x0000_7ff6_0000_0000;
        let mut module_snapshot = vec![0_u8; 0x2000];
        module_snapshot[0x1000..0x1006].copy_from_slice(&[0xe8, 0, 0, 0, 0, 0xfa]);
        let mut import_layout = sample_layout(0x3000, 0x7ffa_1234_5678);
        let rewrites = [VmImportRewrite {
            transfer: VmTransfer {
                opcode: TransferOpcode::Call,
                instruction_rva: 0x1000,
                instruction_size: 5,
                stub_rva: 0x2000,
                return_rva: Some(0x1005),
            },
            semantics: VmImportSemantics::ExternalTransfer {
                destination_address: 0x7ffa_1234_5678,
                stack_pointer_delta: 0,
                resume_rva: Some(0x1006),
            },
        }];
        let applied_patches = rewrite_vm_transfers(
            Architecture::X64,
            MODULE_BASE,
            &mut module_snapshot,
            &mut import_layout,
            &rewrites,
        )
        .expect("valid x64 rewrite");
        module_snapshot[0x1002] = module_snapshot[0x1002].wrapping_add(1);

        let error = verify_applied_patches(
            Architecture::X64,
            MODULE_BASE,
            &module_snapshot,
            &[],
            &applied_patches,
            &import_layout,
        )
        .expect_err("a wrong RIP-relative IAT target must be rejected");

        assert!(matches!(
            error,
            PatchError::GeneratedImportTargetMismatch { .. }
        ));
    }

    #[test]
    fn bypasses_x64_vm_prefix_and_skipped_bytes() {
        const MODULE_BASE: u64 = 0x0000_7ff6_0000_0000;
        let mut module_snapshot = vec![0_u8; 0x2000];
        module_snapshot[0x0fff] = 0x50;
        module_snapshot[0x1000..0x1008].copy_from_slice(&[0xe8, 0, 0, 0, 0, 0x74, 0x01, 0xfa]);
        let mut import_layout = sample_layout(0x3000, 0x7ffa_1234_5678);
        let vm_rewrites = [VmImportRewrite {
            transfer: VmTransfer {
                opcode: TransferOpcode::Call,
                instruction_rva: 0x1000,
                instruction_size: 5,
                stub_rva: 0x2000,
                return_rva: Some(0x1005),
            },
            semantics: VmImportSemantics::ExternalTransfer {
                destination_address: 0x7ffa_1234_5678,
                stack_pointer_delta: 8,
                resume_rva: Some(0x1008),
            },
        }];

        let applied_patches = rewrite_vm_transfers(
            Architecture::X64,
            MODULE_BASE,
            &mut module_snapshot,
            &mut import_layout,
            &vm_rewrites,
        )
        .expect("valid x64 VM rewrite with prefix and skipped bytes");

        assert_eq!(applied_patches[0].discarded_stack_byte_count, 8);
        assert_eq!(applied_patches[0].patch_rva, 0x0fff);
        let instructions = decode_instructions(64, &module_snapshot[0x0fff..0x1007], 0x0fff);
        assert_eq!(
            instructions
                .iter()
                .map(Instruction::mnemonic)
                .collect::<Vec<_>>(),
            [Mnemonic::Call, Mnemonic::Jmp]
        );
        assert_eq!(instructions[0].ip_rel_memory_address(), 0x3000);
        assert_eq!(instructions[1].near_branch_target(), 0x1008);
        assert_eq!(module_snapshot[0x1007], 0xfa);
        assert_eq!(import_layout.bytes.len(), 0x40);
        assert!(import_layout.base_relocation_rvas.is_empty());
    }

    #[test]
    fn uses_rel32_continuation_without_overwriting_protected_residue() {
        const MODULE_BASE: u64 = 0x0000_7ff6_0000_0000;
        let mut module_snapshot = vec![0_u8; 0x4000];
        module_snapshot[0x1000..0x1200].fill(0xfa);
        module_snapshot[0x1000..0x1005].copy_from_slice(&[0xe8, 0, 0, 0, 0]);
        let mut import_layout = sample_layout(0x3000, 0x7ffa_1234_5678);
        let vm_rewrites = [VmImportRewrite {
            transfer: VmTransfer {
                opcode: TransferOpcode::Call,
                instruction_rva: 0x1000,
                instruction_size: 5,
                stub_rva: 0x2000,
                return_rva: Some(0x1005),
            },
            semantics: VmImportSemantics::ExternalTransfer {
                destination_address: 0x7ffa_1234_5678,
                stack_pointer_delta: 0,
                resume_rva: Some(0x1200),
            },
        }];

        rewrite_vm_transfers(
            Architecture::X64,
            MODULE_BASE,
            &mut module_snapshot,
            &mut import_layout,
            &vm_rewrites,
        )
        .expect("valid rewrite with a distant continuation");

        let instructions = decode_instructions(64, &module_snapshot[0x1000..0x100b], 0x1000);
        assert_eq!(
            instructions
                .iter()
                .map(Instruction::mnemonic)
                .collect::<Vec<_>>(),
            [Mnemonic::Call, Mnemonic::Jmp]
        );
        assert_eq!(instructions[1].near_branch_target(), 0x1200);
        assert_eq!(module_snapshot[0x100b], 0xfa);
        assert_eq!(module_snapshot[0x11ff], 0xfa);
    }

    #[test]
    fn bypasses_x64_prefix_before_tail_transfer() {
        let mut module_snapshot = vec![0_u8; 0x2000];
        module_snapshot[0x0ffe] = 0x73;
        module_snapshot[0x0fff] = 0x56;
        module_snapshot[0x1000..0x1005].copy_from_slice(&[0xe8, 0, 0, 0, 0]);
        let mut import_layout = sample_layout(0x3000, 0x7ffa_1234_5678);
        let vm_rewrites = [VmImportRewrite {
            transfer: VmTransfer {
                opcode: TransferOpcode::Call,
                instruction_rva: 0x1000,
                instruction_size: 5,
                stub_rva: 0x2000,
                return_rva: Some(0x1005),
            },
            semantics: VmImportSemantics::ExternalTransfer {
                destination_address: 0x7ffa_1234_5678,
                stack_pointer_delta: 16,
                resume_rva: None,
            },
        }];

        let applied_patches = rewrite_vm_transfers(
            Architecture::X64,
            0,
            &mut module_snapshot,
            &mut import_layout,
            &vm_rewrites,
        )
        .expect("valid x64 tail VM rewrite with prefix");

        assert_eq!(applied_patches[0].discarded_stack_byte_count, 8);
        assert_eq!(module_snapshot[0x0ffe], 0x73);
        assert_eq!(applied_patches[0].patch_rva, 0x0fff);
        let instructions = decode_instructions(64, &module_snapshot[0x0fff..0x1005], 0x0fff);
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].mnemonic(), Mnemonic::Jmp);
        assert_eq!(instructions[0].ip_rel_memory_address(), 0x3000);
        assert_eq!(import_layout.bytes.len(), 0x40);
    }

    #[test]
    fn bypasses_x86_vm_prefix_and_skipped_bytes() {
        const MODULE_BASE: u64 = 0x0040_0000;
        let mut module_snapshot = vec![0_u8; 0x2000];
        module_snapshot[0x0fff] = 0x50;
        module_snapshot[0x1000..0x1008].copy_from_slice(&[0xe8, 0, 0, 0, 0, 0x73, 0x56, 0xfa]);
        let mut import_layout = sample_layout(0x3000, 0x7654_3210);
        let vm_rewrites = [VmImportRewrite {
            transfer: VmTransfer {
                opcode: TransferOpcode::Call,
                instruction_rva: 0x1000,
                instruction_size: 5,
                stub_rva: 0x2000,
                return_rva: Some(0x1005),
            },
            semantics: VmImportSemantics::ExternalTransfer {
                destination_address: 0x7654_3210,
                stack_pointer_delta: 4,
                resume_rva: Some(0x1008),
            },
        }];

        let applied_patches = rewrite_vm_transfers(
            Architecture::X86,
            MODULE_BASE,
            &mut module_snapshot,
            &mut import_layout,
            &vm_rewrites,
        )
        .expect("valid x86 VM rewrite with prefix and skipped bytes");

        assert_eq!(applied_patches[0].discarded_stack_byte_count, 4);
        assert_eq!(applied_patches[0].patch_rva, 0x0fff);
        let instructions = decode_instructions(32, &module_snapshot[0x0fff..0x1007], 0x0fff);
        assert_eq!(
            instructions
                .iter()
                .map(Instruction::mnemonic)
                .collect::<Vec<_>>(),
            [Mnemonic::Call, Mnemonic::Jmp]
        );
        assert_eq!(instructions[0].memory_displacement32(), 0x0040_3000);
        assert_eq!(instructions[1].near_branch_target(), 0x1008);
        assert_eq!(module_snapshot[0x1007], 0xfa);
        assert_eq!(import_layout.bytes.len(), 0x40);
        assert_eq!(import_layout.base_relocation_rvas, [0x1001]);
        verify_applied_patches(
            Architecture::X86,
            MODULE_BASE,
            &module_snapshot,
            &[],
            &applied_patches,
            &import_layout,
        )
        .expect("the generated x86 instructions and relocation agree");
    }

    #[test]
    fn verifier_rejects_overlapping_patch_ranges() {
        const MODULE_BASE: u64 = 0x0040_0000;
        let mut module_snapshot = vec![0_u8; 0x2000];
        module_snapshot[0x1000] = 0xb8;
        module_snapshot[0x1001..0x1005]
            .copy_from_slice(&(MODULE_BASE as u32 + 0x3000).to_le_bytes());
        let import_layout = sample_layout(0x3000, 0x7654_3210);
        let patch = AppliedPointerPatch {
            instruction_rva: 0x1000,
            instruction_size: 5,
            patch_rva: 0x1001,
            patch_byte_count: 4,
            pointer_rva: 0x3000,
        };

        let error = verify_applied_patches(
            Architecture::X86,
            MODULE_BASE,
            &module_snapshot,
            &[patch, patch],
            &[],
            &import_layout,
        )
        .expect_err("overlapping patches must be rejected");

        assert_eq!(
            error,
            PatchError::PatchRangesOverlap {
                first_rva: 0x1001,
                second_rva: 0x1001,
            }
        );
    }

    #[test]
    fn excludes_conventional_reference_overlapped_by_vm_patch() {
        let references = [
            ImportPointerReference {
                instruction_rva: 0x1000,
                instruction_size: 8,
                mnemonic: Mnemonic::Mov,
                operand_index: 1,
                operand: PointerOperand::Memory,
                pointer_rva: 0x3000,
                destination_address: 0x7654_3210,
            },
            ImportPointerReference {
                instruction_rva: 0x1100,
                instruction_size: 7,
                mnemonic: Mnemonic::Call,
                operand_index: 0,
                operand: PointerOperand::Memory,
                pointer_rva: 0x3004,
                destination_address: 0x7654_3220,
            },
        ];
        let vm_patches = [AppliedVmPatch {
            instruction_rva: 0x1004,
            patch_rva: 0x1004,
            patch_byte_count: 6,
            pointer_rva: 0x3010,
            discarded_stack_byte_count: 0,
            resume_rva: Some(0x100a),
            semantics: VmImportSemantics::ExternalTransfer {
                destination_address: 0x7654_3230,
                stack_pointer_delta: 0,
                resume_rva: Some(0x100a),
            },
        }];

        let filtered = pointer_references_outside_vm_patches(&references, &vm_patches);

        assert_eq!(filtered, [references[1]]);
    }

    #[test]
    fn replaces_x86_eax_load_directly() {
        const MODULE_BASE: u64 = 0x0040_0000;
        let mut module_snapshot = vec![0_u8; 0x2000];
        module_snapshot[0x1000..0x1005].copy_from_slice(&[0xe8, 0, 0, 0, 0]);
        let mut import_layout = sample_layout(0x3000, 0x7654_3210);
        let vm_rewrites = [VmImportRewrite {
            transfer: VmTransfer {
                opcode: TransferOpcode::Call,
                instruction_rva: 0x1000,
                instruction_size: 5,
                stub_rva: 0x2000,
                return_rva: Some(0x1005),
            },
            semantics: VmImportSemantics::RegisterLoad {
                register: GeneralRegister::Eax,
                destination_address: 0x7654_3210,
                continuation_rva: 0x1005,
            },
        }];

        rewrite_vm_transfers(
            Architecture::X86,
            MODULE_BASE,
            &mut module_snapshot,
            &mut import_layout,
            &vm_rewrites,
        )
        .expect("valid x86 VM load rewrite");

        let instructions = decode_instructions(32, &module_snapshot[0x1000..0x1005], 0x1000);
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].mnemonic(), Mnemonic::Mov);
        assert_eq!(instructions[0].memory_displacement32(), 0x0040_3000);
        assert_eq!(import_layout.bytes.len(), 0x40);
        assert_eq!(import_layout.base_relocation_rvas, [0x1001]);
    }

    #[test]
    fn replaces_x86_matching_pop_and_register_load_directly() {
        const MODULE_BASE: u64 = 0x0040_0000;
        let mut module_snapshot = vec![0_u8; 0x2000];
        module_snapshot[0x0fff] = 0x5a;
        module_snapshot[0x1000..0x1005].copy_from_slice(&[0xe8, 0, 0, 0, 0]);
        let mut import_layout = sample_layout(0x3000, 0x7654_3210);
        let vm_rewrites = [VmImportRewrite {
            transfer: VmTransfer {
                opcode: TransferOpcode::Call,
                instruction_rva: 0x1000,
                instruction_size: 5,
                stub_rva: 0x2000,
                return_rva: Some(0x1005),
            },
            semantics: VmImportSemantics::RegisterLoad {
                register: GeneralRegister::Edx,
                destination_address: 0x7654_3210,
                continuation_rva: 0x1005,
            },
        }];

        let applied_patches = rewrite_vm_transfers(
            Architecture::X86,
            MODULE_BASE,
            &mut module_snapshot,
            &mut import_layout,
            &vm_rewrites,
        )
        .expect("valid x86 matching-pop rewrite");

        assert_eq!(applied_patches[0].patch_rva, 0x0fff);
        let instructions = decode_instructions(32, &module_snapshot[0x0fff..0x1005], 0x0fff);
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].mnemonic(), Mnemonic::Mov);
        assert_eq!(instructions[0].op0_register(), Register::EDX);
        assert_eq!(instructions[0].memory_displacement32(), 0x0040_3000);
    }

    #[test]
    fn replaces_x86_scratch_push_and_register_load_directly() {
        const MODULE_BASE: u64 = 0x0040_0000;
        let mut module_snapshot = vec![0_u8; 0x2000];
        module_snapshot[0x0ffe..0x1000].copy_from_slice(&[0x57, 0x55]);
        module_snapshot[0x1000..0x1005].copy_from_slice(&[0xe8, 0, 0, 0, 0]);
        let mut import_layout = sample_layout(0x3000, 0x7654_3210);
        let vm_rewrites = [VmImportRewrite {
            transfer: VmTransfer {
                opcode: TransferOpcode::Call,
                instruction_rva: 0x1000,
                instruction_size: 5,
                stub_rva: 0x2000,
                return_rva: Some(0x1005),
            },
            semantics: VmImportSemantics::RegisterLoad {
                register: GeneralRegister::Edi,
                destination_address: 0x7654_3210,
                continuation_rva: 0x1005,
            },
        }];

        let applied_patches = rewrite_vm_transfers(
            Architecture::X86,
            MODULE_BASE,
            &mut module_snapshot,
            &mut import_layout,
            &vm_rewrites,
        )
        .expect("valid x86 scratch-save rewrite");

        assert_eq!(module_snapshot[0x0ffe], 0x57);
        assert_eq!(applied_patches[0].patch_rva, 0x0fff);
        let instructions = decode_instructions(32, &module_snapshot[0x0fff..0x1005], 0x0fff);
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].mnemonic(), Mnemonic::Mov);
        assert_eq!(instructions[0].op0_register(), Register::EDI);
        assert_eq!(instructions[0].memory_displacement32(), 0x0040_3000);
        assert_eq!(import_layout.base_relocation_rvas, [0x1001]);
    }

    #[test]
    fn preserves_x86_same_register_push_when_load_does_not_fit() {
        const MODULE_BASE: u64 = 0x0040_0000;
        let mut module_snapshot = vec![0_u8; 0x2000];
        module_snapshot[0x0fff] = 0x57;
        module_snapshot[0x1000..0x1005].copy_from_slice(&[0xe8, 0, 0, 0, 0]);
        let original_module_snapshot = module_snapshot.clone();
        let mut import_layout = sample_layout(0x3000, 0x7654_3210);
        let vm_rewrites = [VmImportRewrite {
            transfer: VmTransfer {
                opcode: TransferOpcode::Call,
                instruction_rva: 0x1000,
                instruction_size: 5,
                stub_rva: 0x2000,
                return_rva: Some(0x1005),
            },
            semantics: VmImportSemantics::RegisterLoad {
                register: GeneralRegister::Edi,
                destination_address: 0x7654_3210,
                continuation_rva: 0x1005,
            },
        }];

        let applied_patches = rewrite_vm_transfers(
            Architecture::X86,
            MODULE_BASE,
            &mut module_snapshot,
            &mut import_layout,
            &vm_rewrites,
        )
        .expect("an unavailable direct rewrite must be skipped");

        assert!(applied_patches.is_empty());
        assert_eq!(module_snapshot, original_module_snapshot);
        assert!(import_layout.base_relocation_rvas.is_empty());
    }

    #[test]
    fn leaves_unrepresentable_external_stack_deltas_unchanged() {
        for stack_pointer_delta in [3, -32] {
            let mut module_snapshot = vec![0_u8; 0x2000];
            module_snapshot[0x1000..0x1005].copy_from_slice(&[0xe8, 0, 0, 0, 0]);
            let original_module_snapshot = module_snapshot.clone();
            let mut import_layout = sample_layout(0x3000, 0x7654_3210);
            let vm_rewrites = [VmImportRewrite {
                transfer: VmTransfer {
                    opcode: TransferOpcode::Call,
                    instruction_rva: 0x1000,
                    instruction_size: 5,
                    stub_rva: 0x2000,
                    return_rva: Some(0x1005),
                },
                semantics: VmImportSemantics::ExternalTransfer {
                    destination_address: 0x7654_3210,
                    stack_pointer_delta,
                    resume_rva: Some(0x1005),
                },
            }];

            let applied_patches = rewrite_vm_transfers(
                Architecture::X86,
                0x0040_0000,
                &mut module_snapshot,
                &mut import_layout,
                &vm_rewrites,
            )
            .expect("an unrepresentable stack effect must leave the transfer unchanged");

            assert!(applied_patches.is_empty());
            assert_eq!(module_snapshot, original_module_snapshot);
        }
    }

    #[test]
    fn replaces_x64_extended_register_load_directly() {
        const MODULE_BASE: u64 = 0x0000_7ff6_0000_0000;
        let mut module_snapshot = vec![0_u8; 0x2000];
        module_snapshot[0x0ffe..0x1000].copy_from_slice(&[0x41, 0x58]);
        module_snapshot[0x1000..0x1005].copy_from_slice(&[0xe8, 0, 0, 0, 0]);
        let mut import_layout = sample_layout(0x3000, 0x7ffa_1234_5678);
        let vm_rewrites = [VmImportRewrite {
            transfer: VmTransfer {
                opcode: TransferOpcode::Call,
                instruction_rva: 0x1000,
                instruction_size: 5,
                stub_rva: 0x2000,
                return_rva: Some(0x1005),
            },
            semantics: VmImportSemantics::RegisterLoad {
                register: GeneralRegister::R8,
                destination_address: 0x7ffa_1234_5678,
                continuation_rva: 0x1005,
            },
        }];

        let applied_patches = rewrite_vm_transfers(
            Architecture::X64,
            MODULE_BASE,
            &mut module_snapshot,
            &mut import_layout,
            &vm_rewrites,
        )
        .expect("valid direct x64 register-load rewrite");

        assert_eq!(applied_patches[0].patch_rva, 0x0ffe);
        let instructions = decode_instructions(64, &module_snapshot[0x0ffe..0x1005], 0x0ffe);
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].mnemonic(), Mnemonic::Mov);
        assert_eq!(instructions[0].op0_register(), Register::R8);
        assert_eq!(instructions[0].ip_rel_memory_address(), 0x3000);
        assert_eq!(import_layout.bytes.len(), 0x40);
        assert!(import_layout.base_relocation_rvas.is_empty());
    }

    #[test]
    fn replaces_x64_extended_scratch_push_and_legacy_register_load() {
        const MODULE_BASE: u64 = 0x0000_7ff6_0000_0000;
        let mut module_snapshot = vec![0_u8; 0x2000];
        module_snapshot[0x0ffe..0x1000].copy_from_slice(&[0x41, 0x50]);
        module_snapshot[0x1000..0x1005].copy_from_slice(&[0xe8, 0, 0, 0, 0]);
        let mut import_layout = sample_layout(0x3000, 0x7ffa_1234_5678);
        let vm_rewrites = [VmImportRewrite {
            transfer: VmTransfer {
                opcode: TransferOpcode::Call,
                instruction_rva: 0x1000,
                instruction_size: 5,
                stub_rva: 0x2000,
                return_rva: Some(0x1005),
            },
            semantics: VmImportSemantics::RegisterLoad {
                register: GeneralRegister::Rcx,
                destination_address: 0x7ffa_1234_5678,
                continuation_rva: 0x1005,
            },
        }];

        let applied_patches = rewrite_vm_transfers(
            Architecture::X64,
            MODULE_BASE,
            &mut module_snapshot,
            &mut import_layout,
            &vm_rewrites,
        )
        .expect("valid x64 scratch-save rewrite");

        assert_eq!(applied_patches[0].patch_rva, 0x0ffe);
        let instructions = decode_instructions(64, &module_snapshot[0x0ffe..0x1005], 0x0ffe);
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].mnemonic(), Mnemonic::Mov);
        assert_eq!(instructions[0].op0_register(), Register::RCX);
        assert_eq!(instructions[0].ip_rel_memory_address(), 0x3000);
    }

    #[test]
    fn recovers_x64_register_load_reported_as_negative_stack_transfer() {
        const MODULE_BASE: u64 = 0x0000_7ff6_0000_0000;
        let mut module_snapshot = vec![0_u8; 0x2000];
        module_snapshot[0x0fff] = 0x5a;
        module_snapshot[0x1000..0x1008].copy_from_slice(&[0xe8, 0, 0, 0, 0, 0x0e, 0xff, 0xd2]);
        let mut import_layout = sample_layout(0x3000, 0x7ffa_1234_5678);
        let vm_rewrites = [VmImportRewrite {
            transfer: VmTransfer {
                opcode: TransferOpcode::Call,
                instruction_rva: 0x1000,
                instruction_size: 5,
                stub_rva: 0x2000,
                return_rva: Some(0x1005),
            },
            semantics: VmImportSemantics::ExternalTransfer {
                destination_address: 0x7ffa_1234_5678,
                stack_pointer_delta: -8,
                resume_rva: Some(0x1008),
            },
        }];

        let applied_patches = rewrite_vm_transfers(
            Architecture::X64,
            MODULE_BASE,
            &mut module_snapshot,
            &mut import_layout,
            &vm_rewrites,
        )
        .expect("negative stack transfer has a proven register-load shape");

        assert_eq!(applied_patches[0].patch_rva, 0x0fff);
        assert_eq!(applied_patches[0].resume_rva, Some(0x1006));
        assert_eq!(
            applied_patches[0].semantics,
            VmImportSemantics::RegisterLoad {
                register: GeneralRegister::Rdx,
                destination_address: 0x7ffa_1234_5678,
                continuation_rva: 0x1006,
            }
        );
        let instructions = decode_instructions(64, &module_snapshot[0x0fff..0x1006], 0x0fff);
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].mnemonic(), Mnemonic::Mov);
        assert_eq!(instructions[0].op0_register(), Register::RDX);
        assert_eq!(instructions[0].ip_rel_memory_address(), 0x3000);
        assert_eq!(&module_snapshot[0x1006..0x1008], &[0xff, 0xd2]);
    }

    #[test]
    fn preserves_x64_same_register_push_when_load_does_not_fit() {
        const MODULE_BASE: u64 = 0x0000_7ff6_0000_0000;
        let mut module_snapshot = vec![0_u8; 0x2000];
        module_snapshot[0x0ffe..0x1000].copy_from_slice(&[0x41, 0x50]);
        module_snapshot[0x1000..0x1005].copy_from_slice(&[0xe8, 0, 0, 0, 0]);
        let original_module_snapshot = module_snapshot.clone();
        let mut import_layout = sample_layout(0x3000, 0x7ffa_1234_5678);
        let vm_rewrites = [VmImportRewrite {
            transfer: VmTransfer {
                opcode: TransferOpcode::Call,
                instruction_rva: 0x1000,
                instruction_size: 5,
                stub_rva: 0x2000,
                return_rva: Some(0x1005),
            },
            semantics: VmImportSemantics::RegisterLoad {
                register: GeneralRegister::R8,
                destination_address: 0x7ffa_1234_5678,
                continuation_rva: 0x1005,
            },
        }];

        let applied_patches = rewrite_vm_transfers(
            Architecture::X64,
            MODULE_BASE,
            &mut module_snapshot,
            &mut import_layout,
            &vm_rewrites,
        )
        .expect("an unavailable direct rewrite must be skipped");

        assert!(applied_patches.is_empty());
        assert_eq!(module_snapshot, original_module_snapshot);
        assert!(import_layout.base_relocation_rvas.is_empty());
    }

    fn decode_instructions(bitness: u32, bytes: &[u8], instruction_rva: u64) -> Vec<Instruction> {
        let mut decoder = Decoder::with_ip(bitness, bytes, instruction_rva, DecoderOptions::NONE);
        let mut instructions = Vec::new();
        while decoder.can_decode() {
            let instruction = decoder.decode();
            let finishes_rewrite = matches!(instruction.mnemonic(), Mnemonic::Jmp | Mnemonic::Ret);
            instructions.push(instruction);
            if finishes_rewrite {
                break;
            }
        }
        instructions
    }

    fn sample_layout(pointer_rva: u32, destination_address: u64) -> ImportSectionLayout {
        ImportSectionLayout {
            bytes: vec![0_u8; 0x40],
            import_directory_rva: 0x3000,
            import_directory_size: 40,
            import_address_table_rva: pointer_rva,
            import_address_table_size: 8,
            rebuilt_pointers: vec![RebuiltImportPointer {
                recovered_import: RecoveredImport {
                    module_name: "KERNEL32.dll".to_owned(),
                    symbol: ImportSymbol::Name("ImportedFunction".to_owned()),
                    destination_address,
                },
                pointer_rva,
            }],
            base_relocation_rvas: Vec::new(),
        }
    }
}
