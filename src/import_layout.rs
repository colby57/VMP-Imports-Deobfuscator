use std::{collections::BTreeMap, error::Error, fmt};

use crate::{
    imports::{ImportSymbol, RecoveredImport, normalize_recovered_imports},
    process::Architecture,
};

const IMPORT_DESCRIPTOR_SIZE: usize = 20;
const ORDINAL_FLAG_32: u64 = 0x8000_0000;
const ORDINAL_FLAG_64: u64 = 0x8000_0000_0000_0000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RebuiltImportPointer {
    pub recovered_import: RecoveredImport,
    pub pointer_rva: u32,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ImportSectionLayout {
    pub bytes: Vec<u8>,
    pub import_directory_rva: u32,
    pub import_directory_size: u32,
    pub import_address_table_rva: u32,
    pub import_address_table_size: u32,
    pub rebuilt_pointers: Vec<RebuiltImportPointer>,
    pub base_relocation_rvas: Vec<u32>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ImportLayoutError {
    EmptyImports,
    InvalidModuleName(String),
    InvalidImportName {
        module_name: String,
        import_name: String,
    },
    ArithmeticOverflow,
}

impl fmt::Display for ImportLayoutError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyImports => formatter.write_str("no recovered imports are available"),
            Self::InvalidModuleName(module_name) => write!(
                formatter,
                "module name `{module_name}` cannot be encoded in a PE import directory"
            ),
            Self::InvalidImportName {
                module_name,
                import_name,
            } => write!(
                formatter,
                "import name `{module_name}!{import_name}` cannot be encoded in a PE import directory"
            ),
            Self::ArithmeticOverflow => {
                formatter.write_str("rebuilt import-section offsets overflowed")
            }
        }
    }
}

impl Error for ImportLayoutError {}

pub fn build(
    architecture: Architecture,
    section_rva: u32,
    recovered_imports: &[RecoveredImport],
) -> Result<ImportSectionLayout, ImportLayoutError> {
    let recovered_imports = normalize_recovered_imports(recovered_imports.iter().cloned());
    if recovered_imports.is_empty() {
        return Err(ImportLayoutError::EmptyImports);
    }
    validate_names(&recovered_imports)?;

    let mut imports_by_module = BTreeMap::<String, Vec<RecoveredImport>>::new();
    for recovered_import in recovered_imports {
        imports_by_module
            .entry(recovered_import.module_name.to_ascii_lowercase())
            .or_default()
            .push(recovered_import);
    }

    let pointer_size = match architecture {
        Architecture::X86 => 4,
        Architecture::X64 => 8,
    };
    let descriptor_count = imports_by_module
        .len()
        .checked_add(1)
        .ok_or(ImportLayoutError::ArithmeticOverflow)?;
    let import_directory_size = descriptor_count
        .checked_mul(IMPORT_DESCRIPTOR_SIZE)
        .ok_or(ImportLayoutError::ArithmeticOverflow)?;
    let mut next_offset = align_up(import_directory_size, pointer_size)?;
    let mut planned_modules = Vec::with_capacity(imports_by_module.len());

    for recovered_imports in imports_by_module.into_values() {
        let pointer_count = recovered_imports
            .len()
            .checked_add(1)
            .ok_or(ImportLayoutError::ArithmeticOverflow)?;
        let table_size = pointer_count
            .checked_mul(pointer_size)
            .ok_or(ImportLayoutError::ArithmeticOverflow)?;
        let lookup_table_offset = next_offset;
        next_offset = next_offset
            .checked_add(table_size)
            .ok_or(ImportLayoutError::ArithmeticOverflow)?;
        planned_modules.push(PlannedModule {
            module_name: recovered_imports[0].module_name.clone(),
            recovered_imports,
            lookup_table_offset,
            import_address_table_offset: 0,
            module_name_offset: 0,
            import_name_offsets: Vec::new(),
        });
    }

    // @note: keep every IAT array adjacent so the PE IAT data directory covers one exact
    // range and every later instruction patch can target a stable pointer RVA.
    let import_address_table_offset = next_offset;
    for planned_module in &mut planned_modules {
        let pointer_count = planned_module
            .recovered_imports
            .len()
            .checked_add(1)
            .ok_or(ImportLayoutError::ArithmeticOverflow)?;
        let table_size = pointer_count
            .checked_mul(pointer_size)
            .ok_or(ImportLayoutError::ArithmeticOverflow)?;
        planned_module.import_address_table_offset = next_offset;
        next_offset = next_offset
            .checked_add(table_size)
            .ok_or(ImportLayoutError::ArithmeticOverflow)?;
    }
    let import_address_table_size = next_offset
        .checked_sub(import_address_table_offset)
        .ok_or(ImportLayoutError::ArithmeticOverflow)?;

    for planned_module in &mut planned_modules {
        planned_module.module_name_offset = next_offset;
        next_offset = next_offset
            .checked_add(planned_module.module_name.len())
            .and_then(|offset| offset.checked_add(1))
            .ok_or(ImportLayoutError::ArithmeticOverflow)?;
    }

    next_offset = align_up(next_offset, 2)?;
    for planned_module in &mut planned_modules {
        planned_module.import_name_offsets =
            Vec::with_capacity(planned_module.recovered_imports.len());
        for recovered_import in &planned_module.recovered_imports {
            match &recovered_import.symbol {
                ImportSymbol::Name(import_name) => {
                    planned_module.import_name_offsets.push(Some(next_offset));
                    next_offset = next_offset
                        .checked_add(2)
                        .and_then(|offset| offset.checked_add(import_name.len()))
                        .and_then(|offset| offset.checked_add(1))
                        .ok_or(ImportLayoutError::ArithmeticOverflow)?;
                    next_offset = align_up(next_offset, 2)?;
                }
                ImportSymbol::Ordinal(_) => planned_module.import_name_offsets.push(None),
            }
        }
    }

    let section_size =
        u32::try_from(next_offset).map_err(|_| ImportLayoutError::ArithmeticOverflow)?;
    section_rva
        .checked_add(section_size)
        .ok_or(ImportLayoutError::ArithmeticOverflow)?;
    let mut bytes = vec![0_u8; next_offset];
    let mut rebuilt_pointers = Vec::new();

    for (module_ordinal, planned_module) in planned_modules.iter().enumerate() {
        let descriptor_offset = module_ordinal
            .checked_mul(IMPORT_DESCRIPTOR_SIZE)
            .ok_or(ImportLayoutError::ArithmeticOverflow)?;
        let lookup_table_rva = rva_at(section_rva, planned_module.lookup_table_offset)?;
        let module_name_rva = rva_at(section_rva, planned_module.module_name_offset)?;
        let import_address_table_rva =
            rva_at(section_rva, planned_module.import_address_table_offset)?;
        write_u32(&mut bytes, descriptor_offset, lookup_table_rva);
        write_u32(&mut bytes, descriptor_offset + 12, module_name_rva);
        write_u32(&mut bytes, descriptor_offset + 16, import_address_table_rva);
        write_ascii(
            &mut bytes,
            planned_module.module_name_offset,
            &planned_module.module_name,
        );

        for (import_ordinal, recovered_import) in
            planned_module.recovered_imports.iter().enumerate()
        {
            let pointer_offset = import_ordinal
                .checked_mul(pointer_size)
                .ok_or(ImportLayoutError::ArithmeticOverflow)?;
            let lookup_pointer_offset = planned_module
                .lookup_table_offset
                .checked_add(pointer_offset)
                .ok_or(ImportLayoutError::ArithmeticOverflow)?;
            let import_pointer_offset = planned_module
                .import_address_table_offset
                .checked_add(pointer_offset)
                .ok_or(ImportLayoutError::ArithmeticOverflow)?;
            let thunk_bits = match (
                &recovered_import.symbol,
                planned_module.import_name_offsets[import_ordinal],
            ) {
                (ImportSymbol::Name(import_name), Some(import_name_offset)) => {
                    write_u16(&mut bytes, import_name_offset, 0);
                    write_ascii(&mut bytes, import_name_offset + 2, import_name);
                    u64::from(rva_at(section_rva, import_name_offset)?)
                }
                (ImportSymbol::Ordinal(ordinal), None) => {
                    ordinal_flag(architecture) | u64::from(*ordinal)
                }
                _ => unreachable!("planned import names match their symbols"),
            };
            write_pointer(&mut bytes, lookup_pointer_offset, architecture, thunk_bits);
            write_pointer(&mut bytes, import_pointer_offset, architecture, thunk_bits);
            rebuilt_pointers.push(RebuiltImportPointer {
                recovered_import: recovered_import.clone(),
                pointer_rva: rva_at(section_rva, import_pointer_offset)?,
            });
        }
    }

    Ok(ImportSectionLayout {
        bytes,
        import_directory_rva: section_rva,
        import_directory_size: u32::try_from(import_directory_size)
            .map_err(|_| ImportLayoutError::ArithmeticOverflow)?,
        import_address_table_rva: rva_at(section_rva, import_address_table_offset)?,
        import_address_table_size: u32::try_from(import_address_table_size)
            .map_err(|_| ImportLayoutError::ArithmeticOverflow)?,
        rebuilt_pointers,
        base_relocation_rvas: Vec::new(),
    })
}

struct PlannedModule {
    module_name: String,
    recovered_imports: Vec<RecoveredImport>,
    lookup_table_offset: usize,
    import_address_table_offset: usize,
    module_name_offset: usize,
    import_name_offsets: Vec<Option<usize>>,
}

fn validate_names(recovered_imports: &[RecoveredImport]) -> Result<(), ImportLayoutError> {
    for recovered_import in recovered_imports {
        if recovered_import.module_name.is_empty()
            || !recovered_import.module_name.is_ascii()
            || recovered_import.module_name.contains('\0')
        {
            return Err(ImportLayoutError::InvalidModuleName(
                recovered_import.module_name.clone(),
            ));
        }
        if let ImportSymbol::Name(import_name) = &recovered_import.symbol
            && (import_name.is_empty() || !import_name.is_ascii() || import_name.contains('\0'))
        {
            return Err(ImportLayoutError::InvalidImportName {
                module_name: recovered_import.module_name.clone(),
                import_name: import_name.clone(),
            });
        }
    }

    Ok(())
}

fn align_up(offset: usize, alignment: usize) -> Result<usize, ImportLayoutError> {
    let remainder = offset % alignment;
    if remainder == 0 {
        return Ok(offset);
    }

    offset
        .checked_add(alignment - remainder)
        .ok_or(ImportLayoutError::ArithmeticOverflow)
}

fn rva_at(section_rva: u32, offset: usize) -> Result<u32, ImportLayoutError> {
    let offset = u32::try_from(offset).map_err(|_| ImportLayoutError::ArithmeticOverflow)?;
    section_rva
        .checked_add(offset)
        .ok_or(ImportLayoutError::ArithmeticOverflow)
}

fn ordinal_flag(architecture: Architecture) -> u64 {
    match architecture {
        Architecture::X86 => ORDINAL_FLAG_32,
        Architecture::X64 => ORDINAL_FLAG_64,
    }
}

fn write_ascii(bytes: &mut [u8], offset: usize, text: &str) {
    bytes[offset..offset + text.len()].copy_from_slice(text.as_bytes());
}

fn write_u16(bytes: &mut [u8], offset: usize, bits: u16) {
    bytes[offset..offset + 2].copy_from_slice(&bits.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, bits: u32) {
    bytes[offset..offset + 4].copy_from_slice(&bits.to_le_bytes());
}

fn write_pointer(bytes: &mut [u8], offset: usize, architecture: Architecture, bits: u64) {
    match architecture {
        Architecture::X86 => write_u32(
            bytes,
            offset,
            u32::try_from(bits).expect("an x86 thunk fits in four bytes"),
        ),
        Architecture::X64 => bytes[offset..offset + 8].copy_from_slice(&bits.to_le_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_pe32_named_and_ordinal_imports() {
        let recovered_imports = [
            recovered_name("KERNEL32.dll", "Sleep", 0x7654_1000),
            RecoveredImport {
                module_name: "KERNEL32.dll".to_owned(),
                symbol: ImportSymbol::Ordinal(5),
                destination_address: 0x7654_2000,
            },
        ];

        let layout =
            build(Architecture::X86, 0x5000, &recovered_imports).expect("valid PE32 import layout");

        assert_eq!(layout.import_directory_rva, 0x5000);
        assert_eq!(layout.import_directory_size, 40);
        assert_eq!(layout.import_address_table_rva, 0x5034);
        assert_eq!(layout.import_address_table_size, 12);
        assert_eq!(read_u32(&layout.bytes, 0), 0x5028);
        assert_eq!(read_u32(&layout.bytes, 12), 0x5040);
        assert_eq!(read_u32(&layout.bytes, 16), 0x5034);
        assert_eq!(read_u32(&layout.bytes, 40), 0x504e);
        assert_eq!(read_u32(&layout.bytes, 44), 0x8000_0005);
        assert_eq!(read_u32(&layout.bytes, 52), 0x504e);
        assert_eq!(read_u32(&layout.bytes, 56), 0x8000_0005);
        assert_eq!(layout.rebuilt_pointers[0].pointer_rva, 0x5034);
        assert_eq!(layout.rebuilt_pointers[1].pointer_rva, 0x5038);
        assert_eq!(&layout.bytes[64..77], b"KERNEL32.dll\0");
        assert_eq!(&layout.bytes[80..86], b"Sleep\0");
    }

    #[test]
    fn builds_pe32_plus_wide_thunks() {
        let recovered_imports = [recovered_name(
            "USER32.dll",
            "MessageBoxA",
            0x0000_7ffa_1234_5000,
        )];

        let layout = build(Architecture::X64, 0x7000, &recovered_imports)
            .expect("valid PE32+ import layout");

        assert_eq!(layout.import_address_table_rva, 0x7038);
        assert_eq!(layout.import_address_table_size, 16);
        assert_eq!(read_u32(&layout.bytes, 0), 0x7028);
        assert_eq!(read_u32(&layout.bytes, 12), 0x7048);
        assert_eq!(read_u32(&layout.bytes, 16), 0x7038);
        assert_eq!(read_u64(&layout.bytes, 40), 0x7054);
        assert_eq!(read_u64(&layout.bytes, 56), 0x7054);
        assert_eq!(layout.rebuilt_pointers[0].pointer_rva, 0x7038);
        assert_eq!(&layout.bytes[72..83], b"USER32.dll\0");
        assert_eq!(&layout.bytes[86..98], b"MessageBoxA\0");
    }

    fn recovered_name(
        module_name: &str,
        import_name: &str,
        destination_address: u64,
    ) -> RecoveredImport {
        RecoveredImport {
            module_name: module_name.to_owned(),
            symbol: ImportSymbol::Name(import_name.to_owned()),
            destination_address,
        }
    }

    fn read_u32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("four bytes"))
    }

    fn read_u64(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("eight bytes"))
    }
}
