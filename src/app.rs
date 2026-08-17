use std::{
    collections::HashSet,
    error::Error,
    fmt, fs,
    num::{NonZeroU32, NonZeroUsize},
    ops::Range,
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
};

use crate::{
    emulator::{EmulationStop, StubEmulator},
    exports::ExportIndex,
    import_layout,
    imports::{self, RecoveredImport},
    patches,
    pe::{self, Section},
    process::{Architecture, Module, Process},
    transfers,
};
use clap::{CommandFactory, Parser, error::ErrorKind};

const MAX_SECTION_NAME_BYTES: usize = 8;
const STUB_INSTRUCTION_LIMIT: usize = 100_000;
const VM_ENTROPY_THRESHOLD: f64 = 7.0;

#[derive(Clone, Debug, Eq, PartialEq)]
enum SectionSelector {
    Ordinal(NonZeroUsize),
    Name(String),
}

impl fmt::Display for SectionSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ordinal(ordinal) => ordinal.fmt(formatter),
            Self::Name(name) => name.fmt(formatter),
        }
    }
}

impl FromStr for SectionSelector {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        if raw.bytes().all(|byte| byte.is_ascii_digit()) {
            return raw
                .parse::<NonZeroUsize>()
                .map(Self::Ordinal)
                .map_err(|_| "section numbers start at 1".to_owned());
        }

        validate_section_name(raw)?;
        Ok(Self::Name(raw.to_owned()))
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "vid",
    version,
    about = "Reconstruct protected PE imports from a live Windows process"
)]
struct Options {
    #[arg(long, value_name = "PID")]
    pid: NonZeroU32,

    #[arg(long, value_name = "NAME", value_parser = validate_module_name)]
    module: Option<String>,

    #[arg(
        long,
        value_name = "SECTION",
        num_args = 1..=3,
        help = "Select one to three VM sections by 1-based number or name"
    )]
    vm_sections: Vec<SectionSelector>,

    #[arg(
        long,
        conflicts_with_all = ["vm_sections", "section_name", "output", "new_entry_rva"],
        help = "List PE sections and exit"
    )]
    list_sections: bool,

    #[arg(
        long,
        value_name = "NAME",
        default_value = ".vid",
        value_parser = validate_section_name,
        help = "Name of the section that will contain the rebuilt imports"
    )]
    section_name: String,

    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,

    #[arg(
        long,
        value_name = "RVA",
        value_parser = parse_rva,
        help = "Override AddressOfEntryPoint in the rebuilt PE (decimal or 0x-prefixed hex)"
    )]
    new_entry_rva: Option<u32>,
}

impl Options {
    fn from_env() -> Self {
        let options = <Self as Parser>::parse();

        if let Err(message) = options.validate() {
            Self::command()
                .error(ErrorKind::ValueValidation, message)
                .exit();
        }

        options
    }

    fn validate(&self) -> Result<(), String> {
        if self.vm_sections.len() > 3 {
            return Err("--vm-sections accepts at most three sections".to_owned());
        }

        let uses_ordinals = self
            .vm_sections
            .iter()
            .any(|selector| matches!(selector, SectionSelector::Ordinal(_)));
        let uses_names = self
            .vm_sections
            .iter()
            .any(|selector| matches!(selector, SectionSelector::Name(_)));

        if uses_ordinals && uses_names {
            return Err("--vm-sections must contain either numbers or names, not both".to_owned());
        }
        if self
            .output
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err("--output cannot be empty".to_owned());
        }

        Ok(())
    }
}

fn validate_module_name(raw: &str) -> Result<String, String> {
    if raw.trim().is_empty() || raw.contains('\0') {
        return Err("a module name cannot be empty".to_owned());
    }
    Ok(raw.to_owned())
}

fn validate_section_name(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("a PE section name cannot be empty".to_owned());
    }

    if !raw.is_ascii() || raw.bytes().any(|byte| byte.is_ascii_control()) {
        return Err("a PE section name must contain only printable ASCII characters".to_owned());
    }

    if raw.len() > MAX_SECTION_NAME_BYTES {
        return Err(format!(
            "a PE section name cannot exceed {MAX_SECTION_NAME_BYTES} bytes"
        ));
    }

    Ok(raw.to_owned())
}

fn parse_rva(raw: &str) -> Result<u32, String> {
    let parsed_rva =
        if let Some(hex_digits) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
            u32::from_str_radix(hex_digits, 16)
        } else {
            raw.parse()
        };
    parsed_rva.map_err(|_| format!("`{raw}` is not a 32-bit RVA"))
}

pub fn run() -> ExitCode {
    let options = Options::from_env();
    match inspect(&options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            spdlog::error!("{failure}");
            ExitCode::FAILURE
        }
    }
}

fn inspect(options: &Options) -> Result<(), Box<dyn Error>> {
    let process = Process::open(options.pid)?;
    spdlog::info!(
        "Process {} opened | {}",
        options.pid,
        process.architecture()
    );

    let module = process.find_module(options.module.as_deref())?;
    spdlog::info!(
        "Module {} | base 0x{:x} | size 0x{:x}",
        module.name,
        module.base_address,
        module.image_size
    );
    spdlog::debug!("Module path: {}", module.image_path);
    if let Some(entry_rva) = options.new_entry_rva {
        spdlog::info!(
            "Output entry point override | RVA 0x{entry_rva:08x} | live analysis unchanged"
        );
    }

    let sections = pe::read_sections(&process, &module)?;
    let entropies = calculate_entropies(&process, &module, &sections);

    if options.list_sections {
        log_sections(&sections, &entropies);
        return Ok(());
    }

    let selected_ordinals = select_vm_sections(options, &sections, &entropies)?;
    for &ordinal in &selected_ordinals {
        let section = &sections[ordinal];
        let entropy = entropies[ordinal]
            .map(|entropy| format!("{entropy:.4}"))
            .unwrap_or_else(|| "unavailable".to_owned());
        spdlog::info!(
            "VM section #{} {} | RVA 0x{:08x} | entropy {}",
            ordinal + 1,
            section.name,
            section.virtual_address,
            entropy
        );
    }

    let mut module_snapshot = read_module_snapshot(&process, &module, &sections)?;
    let pe_file_metadata = pe::PeFileMetadata::parse(process.architecture(), &module_snapshot)?;
    let code_root_rvas = pe_file_metadata.code_roots(&module_snapshot, module.base_address)?;
    spdlog::info!("Code roots from PE metadata: {}", code_root_rvas.len());
    let vm_transfers = transfers::find(
        process.architecture(),
        module.base_address,
        &module_snapshot,
        &sections,
        &selected_ordinals,
        &code_root_rvas,
    )?;
    spdlog::info!(
        "Discovered {} transfer(s) into the selected VM sections",
        vm_transfers.len()
    );

    let loaded_modules = process.modules()?;
    let export_index = ExportIndex::read(&process, &loaded_modules)?;
    spdlog::info!(
        "Indexed exports from {} loaded module(s)",
        loaded_modules.len()
    );
    let resolved_import_pointers = imports::find_resolved_pointers(
        process.architecture(),
        &module_snapshot,
        &sections,
        &export_index,
    )?;
    spdlog::info!(
        "Export-backed pointers in the module: {}",
        resolved_import_pointers.len()
    );
    for resolved_pointer in &resolved_import_pointers {
        let formatted_symbols = export_index
            .at(resolved_pointer.destination_address)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        spdlog::debug!(
            "  pointer 0x{:08x} -> {} @ 0x{:x}",
            resolved_pointer.pointer_rva,
            formatted_symbols,
            resolved_pointer.destination_address
        );
    }
    let pointer_references = imports::find_pointer_references(
        process.architecture(),
        module.base_address,
        &module_snapshot,
        &sections,
        &selected_ordinals,
        &resolved_import_pointers,
        &code_root_rvas,
    )?;
    let memory_reference_count = pointer_references
        .iter()
        .filter(|pointer_reference| pointer_reference.operand == imports::PointerOperand::Memory)
        .count();
    let immediate_reference_count = pointer_references.len() - memory_reference_count;
    let referenced_pointer_count = pointer_references
        .iter()
        .map(|pointer_reference| pointer_reference.pointer_rva)
        .collect::<HashSet<_>>()
        .len();
    let unreferenced_pointer_count = resolved_import_pointers.len() - referenced_pointer_count;
    spdlog::info!(
        "Conventional references: {} | pointers {} | memory {} | immediate {}",
        pointer_references.len(),
        referenced_pointer_count,
        memory_reference_count,
        immediate_reference_count
    );
    if unreferenced_pointer_count != 0 {
        spdlog::info!(
            "{} resolved pointer(s) are unused by reachable non-VM code",
            unreferenced_pointer_count
        );
    }
    for pointer_reference in &pointer_references {
        let formatted_symbols = export_index
            .at(pointer_reference.destination_address)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let formatted_mnemonic = format!("{:?}", pointer_reference.mnemonic).to_ascii_lowercase();
        spdlog::debug!(
            "  RVA 0x{:08x} | {:<7} {:>2} B | op{} {:<9} -> pointer 0x{:08x} -> {} @ 0x{:x}",
            pointer_reference.instruction_rva,
            formatted_mnemonic,
            pointer_reference.instruction_size,
            pointer_reference.operand_index,
            pointer_reference.operand,
            pointer_reference.pointer_rva,
            formatted_symbols,
            pointer_reference.destination_address
        );
    }

    let mut recovered_imports = pointer_references
        .iter()
        .map(|pointer_reference| pointer_reference.destination_address)
        .collect::<HashSet<_>>()
        .into_iter()
        .filter_map(|destination_address| {
            imports::recover_import(destination_address, export_index.at(destination_address))
                .transpose()
        })
        .collect::<Result<Vec<_>, _>>()?;

    let emulator = StubEmulator::new(
        process.architecture(),
        module.base_address,
        module_snapshot.clone(),
    )?;
    let instruction_limit =
        NonZeroUsize::new(STUB_INSTRUCTION_LIMIT).expect("the instruction limit is non-zero");
    let mut vm_rewrites = Vec::new();
    let mut unresolved_vm_transfers = Vec::new();

    for vm_transfer in &vm_transfers {
        let stub_address = absolute_address(module.base_address, vm_transfer.stub_rva)?;
        let return_address = vm_transfer
            .return_rva
            .map(|return_rva| absolute_address(module.base_address, return_rva))
            .transpose()?;

        spdlog::debug!(
            "VM transfer 0x{:08x} | {} {} B | stub 0x{:08x}",
            vm_transfer.instruction_rva,
            vm_transfer.opcode,
            vm_transfer.instruction_size,
            vm_transfer.stub_rva
        );

        match emulator.emulate_stub(stub_address, return_address, instruction_limit) {
            Ok(stop_reason) => {
                if let VmRecoveryOutcome::Unresolved {
                    destination_address,
                } = record_emulated_imports(
                    process.architecture(),
                    *vm_transfer,
                    stop_reason,
                    &export_index,
                    &module,
                    &mut recovered_imports,
                    &mut vm_rewrites,
                )? {
                    unresolved_vm_transfers
                        .push((vm_transfer.instruction_rva, destination_address));
                }
            }
            Err(failure) => {
                spdlog::warn!(
                    "Cannot emulate VM transfer 0x{:08x} | {}",
                    vm_transfer.instruction_rva,
                    failure
                );
                unresolved_vm_transfers.push((vm_transfer.instruction_rva, None));
            }
        }
    }

    if !unresolved_vm_transfers.is_empty() {
        let unique_destination_count = unresolved_vm_transfers
            .iter()
            .filter_map(|(_, destination_address)| *destination_address)
            .collect::<HashSet<_>>()
            .len();
        spdlog::warn!(
            "Partial VM recovery | rewritten {} of {} | left unchanged {} | unresolved destinations {}",
            vm_rewrites.len(),
            vm_transfers.len(),
            unresolved_vm_transfers.len(),
            unique_destination_count
        );
    }

    let recovered_imports = imports::normalize_recovered_imports(recovered_imports);
    validate_rebuild_readiness(recovered_imports.len(), unresolved_vm_transfers.len())?;
    let recovered_module_count = recovered_imports
        .iter()
        .map(|recovered_import| recovered_import.module_name.to_ascii_lowercase())
        .collect::<HashSet<_>>()
        .len();
    spdlog::info!(
        "Recovered {} import(s) from {} module(s)",
        recovered_imports.len(),
        recovered_module_count
    );
    for recovered_import in &recovered_imports {
        let export_aliases = export_index.at(recovered_import.destination_address);
        if export_aliases.len() > 1 {
            let formatted_aliases = export_aliases
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            spdlog::warn!(
                "Import 0x{:x} has aliases [{}] | selected {}",
                recovered_import.destination_address,
                formatted_aliases,
                recovered_import
            );
        } else {
            spdlog::info!(
                "  {} @ 0x{:x}",
                recovered_import,
                recovered_import.destination_address
            );
        }
    }

    let mut import_layout = import_layout::build(
        process.architecture(),
        pe_file_metadata.new_section_rva(),
        &recovered_imports,
    )?;
    spdlog::info!(
        "Preparing {} conventional reference(s) and {} proven protected transfer(s)",
        pointer_references.len(),
        vm_rewrites.len()
    );
    let vm_patches = patches::rewrite_vm_transfers(
        process.architecture(),
        module.base_address,
        &mut module_snapshot,
        &mut import_layout,
        &vm_rewrites,
    )?;
    let unchanged_direct_rewrite_count = vm_rewrites.len() - vm_patches.len();
    if unchanged_direct_rewrite_count != 0 {
        spdlog::warn!(
            "Direct VM rewrites | applied {} of {} | left unchanged {}",
            vm_patches.len(),
            vm_rewrites.len(),
            unchanged_direct_rewrite_count
        );
    }
    let pointer_references_to_rewrite =
        patches::pointer_references_outside_vm_patches(&pointer_references, &vm_patches);
    let covered_reference_count = pointer_references.len() - pointer_references_to_rewrite.len();
    let pointer_patches = patches::rewrite_pointer_operands(
        process.architecture(),
        module.base_address,
        &mut module_snapshot,
        &pointer_references_to_rewrite,
        &import_layout,
    )?;
    if covered_reference_count != 0 {
        spdlog::warn!(
            "Conventional rewrites | applied {} of {} | covered by protected rewrites {}",
            pointer_patches.len(),
            pointer_references.len(),
            covered_reference_count
        );
    }
    for applied_patch in &pointer_patches {
        spdlog::debug!(
            "  reference 0x{:08x} -> IAT 0x{:08x}",
            applied_patch.instruction_rva,
            applied_patch.pointer_rva
        );
    }
    for applied_patch in &vm_patches {
        let direct_instruction = match applied_patch.semantics {
            patches::VmImportSemantics::ExternalTransfer {
                resume_rva: Some(_),
                ..
            } => "call [IAT]".to_owned(),
            patches::VmImportSemantics::ExternalTransfer {
                resume_rva: None, ..
            } => "jmp [IAT]".to_owned(),
            patches::VmImportSemantics::RegisterLoad { register, .. } => {
                format!("mov {register}, [IAT]")
            }
        };
        let mut details = vec![
            format!("IAT 0x{:08x}", applied_patch.pointer_rva),
            format!("write 0x{:08x}", applied_patch.patch_rva),
        ];
        if applied_patch.discarded_stack_byte_count != 0 {
            details.push(format!(
                "discard {} stack byte(s)",
                applied_patch.discarded_stack_byte_count
            ));
        }
        if let Some(resume_rva) = applied_patch.resume_rva {
            let encoded_return_rva = applied_patch
                .instruction_rva
                .checked_add(5)
                .ok_or_else(|| SelectionError("VM transfer RVA overflowed".to_owned()))?;
            if resume_rva > encoded_return_rva {
                details.push(format!(
                    "skip {} protected byte(s) -> 0x{resume_rva:08x}",
                    resume_rva - encoded_return_rva
                ));
            } else if resume_rva != encoded_return_rva {
                details.push(format!("continue at 0x{resume_rva:08x}"));
            }
        }
        spdlog::info!(
            "  RVA 0x{:08x} | {:<15} | {}",
            applied_patch.instruction_rva,
            direct_instruction,
            details.join(" | ")
        );
    }
    patches::verify_applied_patches(
        process.architecture(),
        module.base_address,
        &module_snapshot,
        &pointer_patches,
        &vm_patches,
        &import_layout,
    )?;
    spdlog::debug!("Verified generated instructions, patch ranges, and relocations");
    let base_relocation_directory =
        pe_file_metadata.append_base_relocations(&module_snapshot, &mut import_layout)?;
    if let Some(directory) = base_relocation_directory {
        spdlog::info!(
            "Base relocations | RVA 0x{:08x} | size 0x{:x} | {} generated fixup(s)",
            directory.rva,
            directory.size,
            import_layout.base_relocation_rvas.len()
        );
    }
    spdlog::info!(
        "Section {} | RVA 0x{:08x} | {} byte(s)",
        options.section_name,
        pe_file_metadata.new_section_rva(),
        import_layout.bytes.len()
    );
    spdlog::info!(
        "Import directory | RVA 0x{:08x} | size 0x{:x} | IAT 0x{:08x} | size 0x{:x}",
        import_layout.import_directory_rva,
        import_layout.import_directory_size,
        import_layout.import_address_table_rva,
        import_layout.import_address_table_size
    );
    for rebuilt_pointer in &import_layout.rebuilt_pointers {
        spdlog::debug!(
            "  IAT 0x{:08x} <- {}",
            rebuilt_pointer.pointer_rva,
            rebuilt_pointer.recovered_import
        );
    }

    let output_path = output_path(options, &module);
    ensure_output_does_not_overwrite_module(&output_path, &module)?;
    let output_bytes = pe_file_metadata.build_file(
        &module_snapshot,
        module.base_address,
        &options.section_name,
        options.new_entry_rva,
        &import_layout,
        base_relocation_directory,
    )?;
    if let Some(parent) = output_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output_path, &output_bytes)?;
    spdlog::info!(
        "Output {} | {} byte(s) | section {}",
        output_path.display(),
        output_bytes.len(),
        options.section_name
    );
    spdlog::info!(
        "Done | {} conventional reference(s) | {} protected transfer(s)",
        pointer_patches.len(),
        vm_patches.len()
    );
    Ok(())
}

fn read_module_snapshot(
    process: &Process,
    module: &Module,
    sections: &[Section],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut module_snapshot = vec![0_u8; module.image_size as usize];
    for range in module_snapshot_ranges(module.image_size, sections)? {
        let range_rva = u32::try_from(range.start)
            .map_err(|_| SelectionError("module snapshot RVA exceeds 32 bits".to_owned()))?;
        let address = absolute_address(module.base_address, range_rva)?;
        process.read_exact(address, &mut module_snapshot[range])?;
    }
    Ok(module_snapshot)
}

fn module_snapshot_ranges(
    image_size: u32,
    sections: &[Section],
) -> Result<Vec<Range<usize>>, SelectionError> {
    let first_section_rva = sections
        .iter()
        .map(|section| section.virtual_address)
        .min()
        .ok_or_else(|| SelectionError("the selected module has no sections".to_owned()))?;
    let mut ranges = Vec::with_capacity(sections.len() + 1);
    ranges.push(0..first_section_rva as usize);

    for section in sections {
        let begin = section.virtual_address as usize;
        let end = begin
            .checked_add(section.mapped_size() as usize)
            .filter(|end| *end <= image_size as usize)
            .ok_or_else(|| {
                SelectionError(format!(
                    "section `{}` exceeds the module image",
                    section.name
                ))
            })?;
        if begin != end {
            ranges.push(begin..end);
        }
    }

    ranges.sort_unstable_by_key(|range| range.start);
    let mut merged_ranges: Vec<Range<usize>> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if let Some(previous) = merged_ranges.last_mut()
            && range.start <= previous.end
        {
            previous.end = previous.end.max(range.end);
        } else if !range.is_empty() {
            merged_ranges.push(range);
        }
    }
    Ok(merged_ranges)
}

fn absolute_address(module_base: u64, rva: u32) -> Result<u64, SelectionError> {
    module_base
        .checked_add(u64::from(rva))
        .ok_or_else(|| SelectionError(format!("RVA 0x{rva:08x} overflows the module address")))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VmRecoveryOutcome {
    Rewritten,
    Unresolved { destination_address: Option<u64> },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExternalContinuation {
    Resume(u32),
    TailTransfer,
    Unproven,
}

fn record_emulated_imports(
    architecture: Architecture,
    vm_transfer: transfers::VmTransfer,
    stop_reason: EmulationStop,
    export_index: &ExportIndex,
    module: &Module,
    recovered_imports: &mut Vec<RecoveredImport>,
    vm_rewrites: &mut Vec<patches::VmImportRewrite>,
) -> Result<VmRecoveryOutcome, imports::ImportRecoveryError> {
    let instruction_rva = vm_transfer.instruction_rva;
    match stop_reason {
        EmulationStop::ExternalTransfer {
            destination_address,
            stack_pointer_delta,
            external_return_address,
        } => {
            let export_symbols = export_index.at(destination_address);
            if export_symbols.is_empty() {
                spdlog::debug!(
                    "VM 0x{:08x} reached unresolved address 0x{:x}",
                    instruction_rva,
                    destination_address
                );
                return Ok(VmRecoveryOutcome::Unresolved {
                    destination_address: Some(destination_address),
                });
            }

            let formatted_symbols = export_symbols
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            spdlog::info!(
                "  VM 0x{:08x} -> {} @ 0x{:x} | stack {:+} | return {}",
                instruction_rva,
                formatted_symbols,
                destination_address,
                stack_pointer_delta,
                format!("0x{external_return_address:x}")
            );
            let resume_rva = match classify_external_continuation(
                architecture,
                vm_transfer,
                stack_pointer_delta,
                external_return_address,
                module.base_address,
                module.image_size,
            ) {
                ExternalContinuation::Resume(resume_rva) => Some(resume_rva),
                ExternalContinuation::TailTransfer => None,
                ExternalContinuation::Unproven => {
                    spdlog::warn!(
                        "VM 0x{:08x} has no proven continuation after reaching 0x{:x}",
                        instruction_rva,
                        destination_address
                    );
                    return Ok(VmRecoveryOutcome::Unresolved {
                        destination_address: Some(destination_address),
                    });
                }
            };
            if let Some(recovered_import) =
                imports::recover_import(destination_address, export_symbols)?
            {
                recovered_imports.push(recovered_import);
                vm_rewrites.push(patches::VmImportRewrite {
                    transfer: vm_transfer,
                    semantics: patches::VmImportSemantics::ExternalTransfer {
                        destination_address,
                        stack_pointer_delta,
                        resume_rva,
                    },
                });
                Ok(VmRecoveryOutcome::Rewritten)
            } else {
                Ok(VmRecoveryOutcome::Unresolved {
                    destination_address: Some(destination_address),
                })
            }
        }
        EmulationStop::UnmappedMemory {
            access,
            address,
            byte_count,
        } => {
            spdlog::warn!(
                "VM 0x{:08x} stopped on unmapped {:?} at 0x{:x} | {} byte(s)",
                instruction_rva,
                access,
                address,
                byte_count
            );
            Ok(VmRecoveryOutcome::Unresolved {
                destination_address: None,
            })
        }
        EmulationStop::ReturnedToCaller {
            return_address,
            register_readings,
        } => {
            let mut resolved_registers = Vec::new();
            for register_reading in register_readings {
                let export_symbols = export_index.at(register_reading.bits);
                if export_symbols.is_empty() {
                    continue;
                }

                let formatted_symbols = export_symbols
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                spdlog::info!(
                    "  VM 0x{:08x} -> {} = {} @ 0x{:x}",
                    instruction_rva,
                    register_reading.register,
                    formatted_symbols,
                    register_reading.bits
                );
                if let Some(recovered_import) =
                    imports::recover_import(register_reading.bits, export_symbols)?
                {
                    resolved_registers.push((register_reading, recovered_import));
                }
            }

            if resolved_registers.is_empty() {
                spdlog::warn!(
                    "VM 0x{:08x} returned to 0x{:x} without an import in a general-purpose register",
                    instruction_rva,
                    return_address
                );
                Ok(VmRecoveryOutcome::Unresolved {
                    destination_address: None,
                })
            } else if resolved_registers.len() == 1 {
                let (register_reading, recovered_import) = resolved_registers
                    .pop()
                    .expect("one resolved register was verified");
                let Some(continuation_rva) = vm_transfer.return_rva else {
                    spdlog::warn!(
                        "VM 0x{:08x} returned an import without a call continuation",
                        instruction_rva
                    );
                    return Ok(VmRecoveryOutcome::Unresolved {
                        destination_address: Some(register_reading.bits),
                    });
                };
                recovered_imports.push(recovered_import);
                vm_rewrites.push(patches::VmImportRewrite {
                    transfer: vm_transfer,
                    semantics: patches::VmImportSemantics::RegisterLoad {
                        register: register_reading.register,
                        destination_address: register_reading.bits,
                        continuation_rva,
                    },
                });
                Ok(VmRecoveryOutcome::Rewritten)
            } else {
                spdlog::warn!(
                    "VM 0x{:08x} returned {} resolved registers | rewrite is ambiguous",
                    instruction_rva,
                    resolved_registers.len()
                );
                Ok(VmRecoveryOutcome::Unresolved {
                    destination_address: None,
                })
            }
        }
        EmulationStop::InstructionLimit {
            instruction_address,
        } => {
            spdlog::warn!(
                "VM 0x{:08x} reached the instruction limit at 0x{:x}",
                instruction_rva,
                instruction_address
            );
            Ok(VmRecoveryOutcome::Unresolved {
                destination_address: None,
            })
        }
    }
}

fn classify_external_continuation(
    architecture: Architecture,
    vm_transfer: transfers::VmTransfer,
    stack_pointer_delta: i64,
    external_return_address: u64,
    module_base: u64,
    module_size: u32,
) -> ExternalContinuation {
    if let Some(resume_rva) = external_return_address
        .checked_sub(module_base)
        .and_then(|rva| u32::try_from(rva).ok())
        .filter(|rva| *rva < module_size)
    {
        return ExternalContinuation::Resume(resume_rva);
    }

    if vm_transfer.opcode == transfers::TransferOpcode::Call && vm_transfer.return_rva.is_none() {
        return ExternalContinuation::Unproven;
    }
    let pointer_size = match architecture {
        Architecture::X86 => 4,
        Architecture::X64 => 8,
    };
    let Ok(stack_pointer_delta) = usize::try_from(stack_pointer_delta) else {
        return ExternalContinuation::Unproven;
    };
    if !stack_pointer_delta.is_multiple_of(pointer_size) {
        return ExternalContinuation::Unproven;
    }

    match vm_transfer.opcode {
        transfers::TransferOpcode::Call if stack_pointer_delta >= pointer_size => {
            ExternalContinuation::TailTransfer
        }
        transfers::TransferOpcode::Jump => ExternalContinuation::TailTransfer,
        transfers::TransferOpcode::Call => ExternalContinuation::Unproven,
    }
}

fn validate_rebuild_readiness(
    recovered_import_count: usize,
    unresolved_transfer_count: usize,
) -> Result<(), SelectionError> {
    if recovered_import_count != 0 {
        return Ok(());
    }
    Err(SelectionError(format!(
        "no recovered imports are available | unresolved VM transfers {unresolved_transfer_count} | no output was written"
    )))
}

fn calculate_entropies(
    process: &Process,
    module: &Module,
    sections: &[Section],
) -> Vec<Option<f64>> {
    sections
        .iter()
        .map(
            |section| match pe::section_entropy(process, module, section) {
                Ok(entropy) => Some(entropy),
                Err(failure) => {
                    spdlog::warn!(
                        "Cannot calculate entropy for section {} | {}",
                        section.name,
                        failure
                    );
                    None
                }
            },
        )
        .collect()
}

fn log_sections(sections: &[Section], entropies: &[Option<f64>]) {
    spdlog::info!(" idx  name      RVA        size       flags       entropy");
    for (ordinal, (section, entropy)) in sections.iter().zip(entropies).enumerate() {
        let entropy = entropy
            .map(|entropy| format!("{entropy:.4}"))
            .unwrap_or_else(|| "n/a".to_owned());
        spdlog::info!(
            " {:>3}  {:<8}  {:08x}  {:08x}  {} {:08x}  {}",
            ordinal + 1,
            section.name,
            section.virtual_address,
            section.mapped_size(),
            section_permissions(section),
            section.characteristics,
            entropy
        );
    }
}

fn section_permissions(section: &Section) -> String {
    [
        if section.is_readable() { 'R' } else { '-' },
        if section.is_writable() { 'W' } else { '-' },
        if section.is_executable() { 'X' } else { '-' },
    ]
    .into_iter()
    .collect()
}

fn select_vm_sections(
    options: &Options,
    sections: &[Section],
    entropies: &[Option<f64>],
) -> Result<Vec<usize>, SelectionError> {
    if options.vm_sections.is_empty() {
        let candidates = sections
            .iter()
            .zip(entropies)
            .enumerate()
            .filter_map(|(ordinal, (section, entropy))| {
                (section.is_executable()
                    && entropy
                        .is_some_and(|section_entropy| section_entropy > VM_ENTROPY_THRESHOLD))
                .then_some(ordinal)
            })
            .collect::<Vec<_>>();

        return match candidates.len() {
            0 => Err(SelectionError(format!(
                "no executable section has entropy above {VM_ENTROPY_THRESHOLD:.1}; use --list-sections and --vm-sections"
            ))),
            1..=3 => Ok(candidates),
            _ => Err(SelectionError(format!(
                "found {} executable sections above entropy {VM_ENTROPY_THRESHOLD:.1}; choose one to three with --vm-sections",
                candidates.len()
            ))),
        };
    }

    let mut selected_ordinals = Vec::with_capacity(options.vm_sections.len());
    for selector in &options.vm_sections {
        let ordinal = match selector {
            SectionSelector::Ordinal(ordinal) => ordinal
                .get()
                .checked_sub(1)
                .filter(|ordinal| *ordinal < sections.len()),
            SectionSelector::Name(name) => sections
                .iter()
                .position(|section| section.name.eq_ignore_ascii_case(name)),
        }
        .ok_or_else(|| SelectionError(format!("section `{selector}` does not exist")))?;

        if selected_ordinals.contains(&ordinal) {
            return Err(SelectionError(format!(
                "section `{selector}` was selected more than once"
            )));
        }
        if !sections[ordinal].is_executable() {
            return Err(SelectionError(format!(
                "section `{selector}` is not executable and cannot contain VM code"
            )));
        }
        selected_ordinals.push(ordinal);
    }

    Ok(selected_ordinals)
}

fn output_path(options: &Options, module: &Module) -> PathBuf {
    if let Some(path) = &options.output {
        return path.clone();
    }

    let module_path = Path::new(&module.name);
    let stem = module_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or(&module.name);
    match module_path
        .extension()
        .and_then(|extension| extension.to_str())
    {
        Some(extension) => PathBuf::from(format!("{stem}.vid.{extension}")),
        None => PathBuf::from(format!("{stem}.vid")),
    }
}

fn ensure_output_does_not_overwrite_module(
    output_path: &Path,
    module: &Module,
) -> Result<(), SelectionError> {
    let Ok(output_path) = fs::canonicalize(output_path) else {
        return Ok(());
    };
    let Ok(module_path) = fs::canonicalize(&module.image_path) else {
        return Ok(());
    };
    if output_path == module_path {
        return Err(SelectionError(format!(
            "output path `{}` would overwrite the inspected module",
            output_path.display()
        )));
    }
    Ok(())
}

#[derive(Debug)]
struct SelectionError(String);

impl fmt::Display for SelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Error for SelectionError {}

#[cfg(test)]
mod tests {
    use crate::{
        emulator::{GeneralRegister, RegisterReading},
        exports::ExportSymbol,
        transfers::{TransferOpcode, VmTransfer},
    };

    use super::*;

    #[test]
    fn requires_non_zero_pid() {
        let missing = Options::try_parse_from(["vid"]).expect_err("PID is required");
        let zero = Options::try_parse_from(["vid", "--pid", "0"]).expect_err("PID zero is invalid");
        let maximum = Options::try_parse_from(["vid", "--pid", "4294967295"])
            .expect("the largest PID representation fits u32");

        assert_eq!(missing.kind(), ErrorKind::MissingRequiredArgument);
        assert_eq!(zero.kind(), ErrorKind::ValueValidation);
        assert_eq!(maximum.pid, NonZeroU32::new(u32::MAX).expect("non-zero"));
    }

    #[test]
    fn validates_module_name() {
        let options = Options::try_parse_from([
            "vid",
            "--pid",
            "1234",
            "--module",
            r"C:\Windows\System32\KERNEL32.DLL",
        ])
        .expect("a module path is valid");

        assert_eq!(
            options.module.as_deref(),
            Some(r"C:\Windows\System32\KERNEL32.DLL")
        );
        for invalid_name in ["", "   ", "bad\0name.dll"] {
            assert!(
                Options::try_parse_from(["vid", "--pid", "1234", "--module", invalid_name])
                    .is_err(),
                "module name {invalid_name:?} must be rejected"
            );
        }
    }

    #[test]
    fn accepts_all_reconstruction_parameters_together() {
        let options = Options::try_parse_from([
            "vid",
            "--output",
            r"out\rebuilt.exe",
            "--new-entry-rva",
            "4096",
            "--module",
            "sample.exe",
            "--section-name",
            ".imports",
            "--vm-sections",
            "2",
            "3",
            "--pid",
            "1234",
        ])
        .expect("all reconstruction parameters are compatible");

        assert!(options.validate().is_ok());
        assert_eq!(options.pid.get(), 1234);
        assert_eq!(options.module.as_deref(), Some("sample.exe"));
        assert_eq!(options.vm_sections.len(), 2);
        assert_eq!(options.section_name, ".imports");
        assert_eq!(options.output, Some(PathBuf::from(r"out\rebuilt.exe")));
        assert_eq!(options.new_entry_rva, Some(4096));
    }

    #[test]
    fn list_sections_accepts_module_but_rejects_rebuild_parameters() {
        let options = Options::try_parse_from([
            "vid",
            "--pid",
            "1234",
            "--module",
            "kernel32",
            "--list-sections",
        ])
        .expect("module selection is meaningful while listing sections");
        assert!(options.list_sections);

        for conflicting_arguments in [
            vec!["--vm-sections", ".vmp"],
            vec!["--section-name", ".new"],
            vec!["--output", "rebuilt.exe"],
            vec!["--new-entry-rva", "4096"],
        ] {
            let mut arguments = vec!["vid", "--pid", "1234", "--list-sections"];
            arguments.extend(conflicting_arguments);
            let error = Options::try_parse_from(arguments)
                .expect_err("listing must not silently ignore rebuild parameters");
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
        }
    }

    #[test]
    fn accepts_section_ordinals() {
        let options = Options::try_parse_from(["vid", "--pid", "1234", "--vm-sections", "2", "3"])
            .expect("valid CLI options");

        assert_eq!(
            options.vm_sections,
            [
                SectionSelector::Ordinal(NonZeroUsize::new(2).expect("non-zero")),
                SectionSelector::Ordinal(NonZeroUsize::new(3).expect("non-zero")),
            ]
        );
        assert!(options.validate().is_ok());
    }

    #[test]
    fn accepts_section_names() {
        let options =
            Options::try_parse_from(["vid", "--pid", "1234", "--vm-sections", ".vmp0", ".vmp1"])
                .expect("valid CLI options");

        assert_eq!(
            options.vm_sections,
            [
                SectionSelector::Name(".vmp0".to_owned()),
                SectionSelector::Name(".vmp1".to_owned()),
            ]
        );
        assert!(options.validate().is_ok());
    }

    #[test]
    fn accepts_one_to_three_section_selectors() {
        for selectors in [vec!["1"], vec!["1", "2"], vec!["1", "2", "3"]] {
            let mut arguments = vec!["vid", "--pid", "1234", "--vm-sections"];
            arguments.extend(selectors.iter().copied());
            let options = Options::try_parse_from(arguments).expect("valid selector count");
            assert_eq!(options.vm_sections.len(), selectors.len());
            assert!(options.validate().is_ok());
        }

        assert!(
            Options::try_parse_from(["vid", "--pid", "1234", "--vm-sections", "1", "2", "3", "4",])
                .is_err()
        );
        assert!(Options::try_parse_from(["vid", "--pid", "1234", "--vm-sections", "0"]).is_err());
    }

    #[test]
    fn rejects_more_than_three_selectors_across_repeated_flags() {
        let parsed = Options::try_parse_from([
            "vid",
            "--pid",
            "1234",
            "--vm-sections",
            "1",
            "2",
            "--vm-sections",
            "3",
            "4",
        ]);

        if let Ok(options) = parsed {
            assert!(options.validate().is_err());
        }
    }

    #[test]
    fn rejects_mixed_section_selectors() {
        let options =
            Options::try_parse_from(["vid", "--pid", "1234", "--vm-sections", "2", ".vmp1"])
                .expect("individually valid section selectors");

        assert!(options.validate().is_err());
    }

    #[test]
    fn rejects_long_section_name() {
        let error =
            Options::try_parse_from(["vid", "--pid", "1234", "--section-name", ".imports2"])
                .expect_err("section name is longer than eight bytes");

        assert_eq!(error.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn validates_output_section_name_boundaries() {
        let valid = Options::try_parse_from(["vid", "--pid", "1234", "--section-name", ".vid1234"])
            .expect("an eight-byte printable name is valid");
        assert_eq!(valid.section_name, ".vid1234");

        for invalid_name in ["", ".импорт", ".bad\n"] {
            assert!(
                Options::try_parse_from(["vid", "--pid", "1234", "--section-name", invalid_name,])
                    .is_err(),
                "section name {invalid_name:?} must be rejected"
            );
        }
    }

    #[test]
    fn accepts_hexadecimal_new_entry_rva() {
        let options =
            Options::try_parse_from(["vid", "--pid", "1234", "--new-entry-rva", "0x1000"])
                .expect("valid hexadecimal entry RVA");

        assert_eq!(options.new_entry_rva, Some(0x1000));
        assert!(
            Options::try_parse_from(["vid", "--pid", "1234", "--entry-rva", "0x1000"]).is_err()
        );
    }

    #[test]
    fn validates_every_new_entry_rva_form() {
        for (raw, expected) in [
            ("4096", 0x1000),
            ("0X1000", 0x1000),
            ("4294967295", u32::MAX),
        ] {
            let options = Options::try_parse_from(["vid", "--pid", "1234", "--new-entry-rva", raw])
                .expect("valid entry RVA representation");
            assert_eq!(options.new_entry_rva, Some(expected));
        }

        for invalid in ["-1", "0x", "0x100000000", "not-an-rva"] {
            assert!(
                Options::try_parse_from(["vid", "--pid", "1234", "--new-entry-rva", invalid,])
                    .is_err(),
                "entry RVA {invalid:?} must be rejected"
            );
        }
    }

    #[test]
    fn validates_output_path_and_default_names() {
        let explicit =
            Options::try_parse_from(["vid", "--pid", "1234", "--output", r"nested\rebuilt.exe"])
                .expect("valid output path");
        assert!(explicit.validate().is_ok());
        assert_eq!(
            output_path(&explicit, &sample_module("sample.exe")),
            PathBuf::from(r"nested\rebuilt.exe")
        );

        assert!(Options::try_parse_from(["vid", "--pid", "1234", "--output", ""]).is_err());

        let defaults =
            Options::try_parse_from(["vid", "--pid", "1234"]).expect("valid default options");
        assert_eq!(
            output_path(&defaults, &sample_module("sample.exe")),
            PathBuf::from("sample.vid.exe")
        );
        assert_eq!(
            output_path(&defaults, &sample_module("plugin.dll")),
            PathBuf::from("plugin.vid.dll")
        );
        assert_eq!(
            output_path(&defaults, &sample_module("image")),
            PathBuf::from("image.vid")
        );
    }

    #[test]
    fn rejects_output_that_overwrites_inspected_module() {
        let current_executable = std::env::current_exe().expect("current executable path");
        let module = Module {
            name: current_executable
                .file_name()
                .expect("executable file name")
                .to_string_lossy()
                .into_owned(),
            image_path: current_executable.to_string_lossy().into_owned(),
            base_address: 0,
            image_size: 0,
        };

        assert!(ensure_output_does_not_overwrite_module(&current_executable, &module).is_err());
    }

    #[test]
    fn rejects_non_executable_vm_section() {
        let options = Options::try_parse_from(["vid", "--pid", "1234", "--vm-sections", ".data"])
            .expect("valid command line");
        let sections = [Section {
            name: ".data".to_owned(),
            virtual_address: 0x2000,
            virtual_size: 0x1000,
            raw_size: 0x1000,
            characteristics: 0x4000_0040,
        }];

        let error = select_vm_sections(&options, &sections, &[Some(7.5)])
            .expect_err("a VM section must be executable");

        assert!(error.to_string().contains("is not executable"));
    }

    #[test]
    fn validates_manual_and_automatic_section_combinations() {
        let sections = [
            sample_section(".text", true),
            sample_section(".vmp0", true),
            sample_section(".vmp1", true),
            sample_section(".vmp2", true),
            sample_section(".data", false),
        ];
        let entropies = [Some(5.0), Some(7.1), Some(7.2), Some(7.3), Some(8.0)];
        let automatic =
            Options::try_parse_from(["vid", "--pid", "1234"]).expect("valid automatic selection");
        assert_eq!(
            select_vm_sections(&automatic, &sections, &entropies)
                .expect("three executable high-entropy candidates"),
            [1, 2, 3]
        );

        for selectors in [
            vec![".vmp0"],
            vec![".vmp0", ".vmp1"],
            vec![".vmp0", ".vmp1", ".vmp2"],
        ] {
            let mut arguments = vec!["vid", "--pid", "1234", "--vm-sections"];
            arguments.extend(selectors.iter().copied());
            let options = Options::try_parse_from(arguments).expect("valid named selection");
            assert_eq!(
                select_vm_sections(&options, &sections, &entropies)
                    .expect("selected sections exist")
                    .len(),
                selectors.len()
            );
        }

        let duplicate =
            Options::try_parse_from(["vid", "--pid", "1234", "--vm-sections", ".VMP0", ".vmp0"])
                .expect("individually valid selectors");
        assert!(select_vm_sections(&duplicate, &sections, &entropies).is_err());

        let missing =
            Options::try_parse_from(["vid", "--pid", "1234", "--vm-sections", ".missing"])
                .expect("individually valid selector");
        assert!(select_vm_sections(&missing, &sections, &entropies).is_err());

        let four_candidates = [
            sample_section(".vmp0", true),
            sample_section(".vmp1", true),
            sample_section(".vmp2", true),
            sample_section(".vmp3", true),
        ];
        assert!(select_vm_sections(&automatic, &four_candidates, &[Some(7.1); 4]).is_err());
        assert!(select_vm_sections(&automatic, &sections[..1], &[Some(5.0)]).is_err());
    }

    #[test]
    fn allows_partial_vm_recovery_when_imports_were_recovered() {
        assert!(validate_rebuild_readiness(2233, 99).is_ok());
    }

    #[test]
    fn rejects_rebuild_without_any_recovered_import() {
        let error =
            validate_rebuild_readiness(0, 99).expect_err("a rebuild without any import must fail");

        assert!(error.to_string().contains("no recovered imports"));
    }

    #[test]
    fn rejects_register_result_without_call_continuation() {
        const IMPORT_ADDRESS: u64 = 0x7654_3210;
        let export_index = sample_export_index(IMPORT_ADDRESS);
        let module = Module {
            name: "sample.exe".to_owned(),
            image_path: "sample.exe".to_owned(),
            base_address: 0x0040_0000,
            image_size: 0x3000,
        };
        let mut recovered_imports = Vec::new();
        let mut rewrites = Vec::new();

        let outcome = record_emulated_imports(
            Architecture::X86,
            VmTransfer {
                opcode: TransferOpcode::Jump,
                instruction_rva: 0x1000,
                instruction_size: 5,
                stub_rva: 0x2000,
                return_rva: None,
            },
            EmulationStop::ReturnedToCaller {
                return_address: 0x0040_1005,
                register_readings: vec![RegisterReading {
                    register: GeneralRegister::Eax,
                    bits: IMPORT_ADDRESS,
                }],
            },
            &export_index,
            &module,
            &mut recovered_imports,
            &mut rewrites,
        )
        .expect("valid import lookup");

        assert_eq!(
            outcome,
            VmRecoveryOutcome::Unresolved {
                destination_address: Some(IMPORT_ADDRESS)
            }
        );
        assert!(recovered_imports.is_empty());
        assert!(rewrites.is_empty());
    }

    #[test]
    fn requires_stack_proof_for_external_tail_transfer() {
        let transfer = VmTransfer {
            opcode: TransferOpcode::Call,
            instruction_rva: 0x1000,
            instruction_size: 5,
            stub_rva: 0x2000,
            return_rva: Some(0x1005),
        };

        assert_eq!(
            classify_external_continuation(
                Architecture::X64,
                transfer,
                0,
                0,
                0x0000_7ff6_0000_0000,
                0x3000,
            ),
            ExternalContinuation::Unproven
        );
        assert_eq!(
            classify_external_continuation(
                Architecture::X64,
                transfer,
                8,
                0,
                0x0000_7ff6_0000_0000,
                0x3000,
            ),
            ExternalContinuation::TailTransfer
        );
    }

    #[test]
    fn snapshot_ranges_skip_unmapped_image_gaps() {
        let sections = [
            Section {
                name: ".text".to_owned(),
                virtual_address: 0x1000,
                virtual_size: 0x1000,
                raw_size: 0x1000,
                characteristics: 0x6000_0020,
            },
            Section {
                name: ".data".to_owned(),
                virtual_address: 0x3000,
                virtual_size: 0x1000,
                raw_size: 0x1000,
                characteristics: 0xc000_0040,
            },
        ];

        assert_eq!(
            module_snapshot_ranges(0x4000, &sections).expect("valid image ranges"),
            [0..0x2000, 0x3000..0x4000]
        );
    }

    fn sample_export_index(address: u64) -> ExportIndex {
        let mut export_index = ExportIndex::default();
        export_index.insert(
            address,
            ExportSymbol {
                module_name: "KERNEL32.dll".to_owned(),
                name: Some("GetVersion".to_owned()),
                ordinal: 1,
                forwarded: false,
            },
        );
        export_index
    }

    fn sample_module(name: &str) -> Module {
        Module {
            name: name.to_owned(),
            image_path: name.to_owned(),
            base_address: 0x0040_0000,
            image_size: 0x5000,
        }
    }

    fn sample_section(name: &str, executable: bool) -> Section {
        Section {
            name: name.to_owned(),
            virtual_address: 0x1000,
            virtual_size: 0x1000,
            raw_size: 0x1000,
            characteristics: if executable { 0x6000_0020 } else { 0x4000_0040 },
        }
    }
}
