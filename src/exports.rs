use std::{collections::HashMap, error::Error, fmt, mem::size_of};

use crate::process::{Module, Process, ProcessError};

const DOS_HEADER_SIZE: usize = 64;
const NT_PREFIX_SIZE: usize = 24;
const EXPORT_DIRECTORY_SIZE: usize = 40;
const MAX_NT_HEADER_OFFSET: u64 = 1024 * 1024;
const MAX_OPTIONAL_HEADER_SIZE: u16 = 4096;
const MAX_EXPORT_COUNT: u32 = 1_000_000;
const MAX_EXPORT_NAME_BYTES: usize = 4096;
const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x010b;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020b;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportSymbol {
    pub module_name: String,
    pub name: Option<String>,
    pub ordinal: u32,
    pub forwarded: bool,
}

impl fmt::Display for ExportSymbol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.name {
            Some(name) => write!(formatter, "{}!{name}", self.module_name),
            None => write!(formatter, "{}!#{}", self.module_name, self.ordinal),
        }
    }
}

#[derive(Default)]
pub struct ExportIndex {
    symbols_by_address: HashMap<u64, Vec<ExportSymbol>>,
}

impl ExportIndex {
    pub fn read(process: &Process, modules: &[Module]) -> Result<Self, ExportError> {
        let mut definitions = Vec::new();
        for module in modules {
            match read_module(process, module) {
                Ok(module_definitions) => definitions.extend(module_definitions),
                Err(error) if error.is_invalid_pe_image() => {
                    spdlog::warn!("skipping {error}");
                }
                Err(error) => return Err(error),
            }
        }
        Ok(Self::from_definitions(definitions))
    }

    pub fn at(&self, address: u64) -> &[ExportSymbol] {
        self.symbols_by_address
            .get(&address)
            .map_or(&[], Vec::as_slice)
    }

    fn from_definitions(definitions: Vec<ExportDefinition>) -> Self {
        let mut index = Self::default();
        let mut addresses_by_key = HashMap::new();
        let mut pending_forwarders = Vec::new();

        for definition in definitions {
            match definition.target {
                ExportTarget::Direct(address) => {
                    index.insert_definition(&mut addresses_by_key, address, definition.symbol);
                }
                ExportTarget::Forwarder(_) => pending_forwarders.push(definition),
            }
        }

        loop {
            let mut progress = false;
            let mut unresolved = Vec::new();
            for mut definition in pending_forwarders {
                let ExportTarget::Forwarder(target) = &definition.target else {
                    unreachable!("only forwarders remain unresolved");
                };
                let Some(address) = addresses_by_key.get(target).copied() else {
                    unresolved.push(definition);
                    continue;
                };

                definition.symbol.forwarded = true;
                index.insert_definition(&mut addresses_by_key, address, definition.symbol);
                progress = true;
            }
            if !progress {
                break;
            }
            pending_forwarders = unresolved;
        }

        index
    }

    fn insert_definition(
        &mut self,
        addresses_by_key: &mut HashMap<ExportKey, u64>,
        address: u64,
        symbol: ExportSymbol,
    ) {
        for key in export_keys(&symbol) {
            addresses_by_key.entry(key).or_insert(address);
        }
        self.insert(address, symbol);
    }

    pub(crate) fn insert(&mut self, address: u64, symbol: ExportSymbol) {
        self.symbols_by_address
            .entry(address)
            .or_default()
            .push(symbol);
    }
}

#[derive(Clone, Debug)]
struct ExportDefinition {
    symbol: ExportSymbol,
    target: ExportTarget,
}

#[derive(Clone, Debug)]
enum ExportTarget {
    Direct(u64),
    Forwarder(ExportKey),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ExportKey {
    module_name: String,
    symbol: ExportKeySymbol,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum ExportKeySymbol {
    Name(String),
    Ordinal(u32),
}

fn read_module(process: &Process, module: &Module) -> Result<Vec<ExportDefinition>, ExportError> {
    let Some(directory) = read_directory(process, module)? else {
        return Ok(Vec::new());
    };

    let function_rvas = read_u32_array(
        process,
        module,
        directory.functions_rva,
        directory.function_count,
    )?;
    let name_rvas = read_u32_array(process, module, directory.names_rva, directory.name_count)?;
    let name_ordinals = read_u16_array(
        process,
        module,
        directory.ordinals_rva,
        directory.name_count,
    )?;
    let mut named_functions = vec![false; function_rvas.len()];
    let mut definitions = Vec::with_capacity(function_rvas.len());

    for (name_rva, name_ordinal) in name_rvas.into_iter().zip(name_ordinals) {
        let function_index = usize::from(name_ordinal);
        let Some(function_rva) = function_rvas.get(function_index).copied() else {
            return Err(ExportError::NameOrdinalOutsideFunctions {
                module_name: module.name.clone(),
                name_ordinal,
                function_count: directory.function_count,
            });
        };
        named_functions[function_index] = true;
        let Some(target) = export_target(process, module, directory, function_rva)? else {
            continue;
        };
        let name = read_name(process, module, name_rva)?;
        let ordinal = directory
            .ordinal_base
            .checked_add(function_index as u32)
            .ok_or_else(|| ExportError::OrdinalOverflow(module.name.clone()))?;
        definitions.push(ExportDefinition {
            symbol: ExportSymbol {
                module_name: module.name.clone(),
                name: Some(name),
                ordinal,
                forwarded: false,
            },
            target,
        });
    }

    for (function_index, function_rva) in function_rvas.into_iter().enumerate() {
        if named_functions[function_index] {
            continue;
        }
        let Some(target) = export_target(process, module, directory, function_rva)? else {
            continue;
        };
        let ordinal = directory
            .ordinal_base
            .checked_add(function_index as u32)
            .ok_or_else(|| ExportError::OrdinalOverflow(module.name.clone()))?;
        definitions.push(ExportDefinition {
            symbol: ExportSymbol {
                module_name: module.name.clone(),
                name: None,
                ordinal,
                forwarded: false,
            },
            target,
        });
    }

    Ok(definitions)
}

fn export_keys(symbol: &ExportSymbol) -> Vec<ExportKey> {
    let module_name = normalize_module_name(&symbol.module_name);
    let mut keys = vec![ExportKey {
        module_name: module_name.clone(),
        symbol: ExportKeySymbol::Ordinal(symbol.ordinal),
    }];
    if let Some(name) = &symbol.name {
        keys.push(ExportKey {
            module_name,
            symbol: ExportKeySymbol::Name(name.clone()),
        });
    }
    keys
}

fn parse_forwarder(module: &Module, rva: u32, raw: &str) -> Result<ExportKey, ExportError> {
    let Some((module_name, symbol)) = raw.rsplit_once('.') else {
        return Err(ExportError::InvalidForwarder {
            module_name: module.name.clone(),
            rva,
            value: raw.to_owned(),
        });
    };
    if module_name.is_empty() || symbol.is_empty() {
        return Err(ExportError::InvalidForwarder {
            module_name: module.name.clone(),
            rva,
            value: raw.to_owned(),
        });
    }
    let symbol = if let Some(ordinal) = symbol.strip_prefix('#') {
        ExportKeySymbol::Ordinal(ordinal.parse().map_err(|_| ExportError::InvalidForwarder {
            module_name: module.name.clone(),
            rva,
            value: raw.to_owned(),
        })?)
    } else {
        ExportKeySymbol::Name(symbol.to_owned())
    };

    Ok(ExportKey {
        module_name: normalize_module_name(module_name),
        symbol,
    })
}

fn normalize_module_name(module_name: &str) -> String {
    let mut normalized = module_name.to_ascii_lowercase();
    if !normalized.ends_with(".dll") && !normalized.ends_with(".exe") {
        normalized.push_str(".dll");
    }
    normalized
}

#[derive(Clone, Copy)]
struct ExportDirectory {
    rva: u32,
    size: u32,
    ordinal_base: u32,
    function_count: u32,
    name_count: u32,
    functions_rva: u32,
    names_rva: u32,
    ordinals_rva: u32,
}

#[derive(Debug)]
pub enum ExportError {
    ProcessMemory {
        module_name: String,
        source: ProcessError,
    },
    InvalidImage {
        module_name: String,
        reason: &'static str,
    },
    InvalidOptionalHeader {
        module_name: String,
        size: u16,
    },
    UnsupportedOptionalHeader {
        module_name: String,
        magic: u16,
    },
    ExportCountTooLarge {
        module_name: String,
        function_count: u32,
        name_count: u32,
    },
    RangeOutsideImage {
        module_name: String,
        rva: u32,
        size: usize,
    },
    NameOrdinalOutsideFunctions {
        module_name: String,
        name_ordinal: u16,
        function_count: u32,
    },
    UnterminatedName {
        module_name: String,
        rva: u32,
    },
    InvalidName {
        module_name: String,
        rva: u32,
    },
    InvalidForwarder {
        module_name: String,
        rva: u32,
        value: String,
    },
    OrdinalOverflow(String),
    AddressOverflow(String),
}

impl fmt::Display for ExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProcessMemory {
                module_name,
                source,
            } => write!(
                formatter,
                "cannot read exports from `{module_name}`: {source}"
            ),
            Self::InvalidImage {
                module_name,
                reason,
            } => write!(formatter, "invalid PE image `{module_name}`: {reason}"),
            Self::InvalidOptionalHeader { module_name, size } => write!(
                formatter,
                "invalid optional-header size {size} in `{module_name}`"
            ),
            Self::UnsupportedOptionalHeader { module_name, magic } => write!(
                formatter,
                "unsupported optional-header magic 0x{magic:04x} in `{module_name}`"
            ),
            Self::ExportCountTooLarge {
                module_name,
                function_count,
                name_count,
            } => write!(
                formatter,
                "suspicious export counts in `{module_name}` (functions {function_count}, names {name_count})"
            ),
            Self::RangeOutsideImage {
                module_name,
                rva,
                size,
            } => write!(
                formatter,
                "export range at RVA 0x{rva:08x} with size 0x{size:x} exceeds `{module_name}`"
            ),
            Self::NameOrdinalOutsideFunctions {
                module_name,
                name_ordinal,
                function_count,
            } => write!(
                formatter,
                "export name ordinal {name_ordinal} exceeds {function_count} functions in `{module_name}`"
            ),
            Self::UnterminatedName { module_name, rva } => write!(
                formatter,
                "export name at RVA 0x{rva:08x} in `{module_name}` has no terminator"
            ),
            Self::InvalidName { module_name, rva } => write!(
                formatter,
                "export name at RVA 0x{rva:08x} in `{module_name}` is not ASCII"
            ),
            Self::InvalidForwarder {
                module_name,
                rva,
                value,
            } => write!(
                formatter,
                "export forwarder `{value}` at RVA 0x{rva:08x} in `{module_name}` is invalid"
            ),
            Self::OrdinalOverflow(module_name) => {
                write!(formatter, "export ordinal overflow in `{module_name}`")
            }
            Self::AddressOverflow(module_name) => {
                write!(formatter, "export address overflow in `{module_name}`")
            }
        }
    }
}

impl ExportError {
    fn is_invalid_pe_image(&self) -> bool {
        matches!(
            self,
            Self::InvalidImage { .. }
                | Self::InvalidOptionalHeader { .. }
                | Self::UnsupportedOptionalHeader { .. }
        )
    }
}

impl Error for ExportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ProcessMemory { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn read_directory(
    process: &Process,
    module: &Module,
) -> Result<Option<ExportDirectory>, ExportError> {
    if module.image_size < DOS_HEADER_SIZE as u32 {
        return Err(invalid_image(
            module,
            "image is smaller than the DOS header",
        ));
    }

    let mut dos_header = [0_u8; DOS_HEADER_SIZE];
    read_image(process, module, 0, &mut dos_header)?;
    if dos_header[..2] != *b"MZ" {
        return Err(invalid_image(module, "missing MZ signature"));
    }

    let nt_offset = i32::from_le_bytes(
        dos_header[0x3c..0x40]
            .try_into()
            .expect("the DOS header offset has four bytes"),
    );
    if nt_offset < DOS_HEADER_SIZE as i32 || nt_offset as u64 > MAX_NT_HEADER_OFFSET {
        return Err(invalid_image(module, "invalid PE header offset"));
    }
    let nt_offset = nt_offset as u64;

    let mut nt_prefix = [0_u8; NT_PREFIX_SIZE];
    read_image(process, module, nt_offset, &mut nt_prefix)?;
    if nt_prefix[..4] != *b"PE\0\0" {
        return Err(invalid_image(module, "missing PE signature"));
    }

    let optional_header_size = read_u16(&nt_prefix, 20);
    if optional_header_size < size_of::<u16>() as u16
        || optional_header_size > MAX_OPTIONAL_HEADER_SIZE
    {
        return Err(ExportError::InvalidOptionalHeader {
            module_name: module.name.clone(),
            size: optional_header_size,
        });
    }
    let optional_header_offset = nt_offset
        .checked_add(NT_PREFIX_SIZE as u64)
        .ok_or_else(|| ExportError::AddressOverflow(module.name.clone()))?;
    let mut optional_header = vec![0_u8; usize::from(optional_header_size)];
    read_image(
        process,
        module,
        optional_header_offset,
        &mut optional_header,
    )?;

    let optional_magic = read_u16(&optional_header, 0);
    let (directory_count_offset, export_directory_offset) = match optional_magic {
        IMAGE_NT_OPTIONAL_HDR32_MAGIC => (92, 96),
        IMAGE_NT_OPTIONAL_HDR64_MAGIC => (108, 112),
        _ => {
            return Err(ExportError::UnsupportedOptionalHeader {
                module_name: module.name.clone(),
                magic: optional_magic,
            });
        }
    };
    if optional_header.len() < export_directory_offset + 8 {
        return Err(invalid_image(
            module,
            "optional header does not contain the export directory",
        ));
    }
    if read_u32(&optional_header, directory_count_offset) == 0 {
        return Ok(None);
    }

    let directory_rva = read_u32(&optional_header, export_directory_offset);
    let directory_size = read_u32(&optional_header, export_directory_offset + 4);
    if directory_rva == 0 || directory_size == 0 {
        return Ok(None);
    }
    validate_range(
        module,
        directory_rva,
        EXPORT_DIRECTORY_SIZE.max(directory_size as usize),
    )?;

    let mut directory_bytes = [0_u8; EXPORT_DIRECTORY_SIZE];
    read_image(
        process,
        module,
        u64::from(directory_rva),
        &mut directory_bytes,
    )?;
    let function_count = read_u32(&directory_bytes, 20);
    let name_count = read_u32(&directory_bytes, 24);
    if function_count > MAX_EXPORT_COUNT || name_count > MAX_EXPORT_COUNT {
        return Err(ExportError::ExportCountTooLarge {
            module_name: module.name.clone(),
            function_count,
            name_count,
        });
    }

    Ok(Some(ExportDirectory {
        rva: directory_rva,
        size: directory_size,
        ordinal_base: read_u32(&directory_bytes, 16),
        function_count,
        name_count,
        functions_rva: read_u32(&directory_bytes, 28),
        names_rva: read_u32(&directory_bytes, 32),
        ordinals_rva: read_u32(&directory_bytes, 36),
    }))
}

fn read_u32_array(
    process: &Process,
    module: &Module,
    rva: u32,
    count: u32,
) -> Result<Vec<u32>, ExportError> {
    let byte_count = usize::try_from(count)
        .ok()
        .and_then(|count| count.checked_mul(size_of::<u32>()))
        .ok_or_else(|| ExportError::RangeOutsideImage {
            module_name: module.name.clone(),
            rva,
            size: usize::MAX,
        })?;
    validate_range(module, rva, byte_count)?;

    let mut bytes = vec![0_u8; byte_count];
    read_image(process, module, u64::from(rva), &mut bytes)?;
    Ok(bytes
        .chunks_exact(size_of::<u32>())
        .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("four-byte export RVA")))
        .collect())
}

fn read_u16_array(
    process: &Process,
    module: &Module,
    rva: u32,
    count: u32,
) -> Result<Vec<u16>, ExportError> {
    let byte_count = usize::try_from(count)
        .ok()
        .and_then(|count| count.checked_mul(size_of::<u16>()))
        .ok_or_else(|| ExportError::RangeOutsideImage {
            module_name: module.name.clone(),
            rva,
            size: usize::MAX,
        })?;
    validate_range(module, rva, byte_count)?;

    let mut bytes = vec![0_u8; byte_count];
    read_image(process, module, u64::from(rva), &mut bytes)?;
    Ok(bytes
        .chunks_exact(size_of::<u16>())
        .map(|bytes| u16::from_le_bytes(bytes.try_into().expect("two-byte export ordinal")))
        .collect())
}

fn read_name(process: &Process, module: &Module, rva: u32) -> Result<String, ExportError> {
    validate_range(module, rva, 1)?;
    let available = usize::try_from(module.image_size - rva).unwrap_or(usize::MAX);
    let byte_count = available.min(MAX_EXPORT_NAME_BYTES);
    validate_range(module, rva, byte_count)?;

    let mut bytes = vec![0_u8; byte_count];
    read_image(process, module, u64::from(rva), &mut bytes)?;
    let Some(name_size) = bytes.iter().position(|byte| *byte == 0) else {
        return Err(ExportError::UnterminatedName {
            module_name: module.name.clone(),
            rva,
        });
    };
    if !bytes[..name_size].is_ascii() {
        return Err(ExportError::InvalidName {
            module_name: module.name.clone(),
            rva,
        });
    }

    Ok(
        String::from_utf8(bytes[..name_size].to_vec())
            .expect("an ASCII export name is valid UTF-8"),
    )
}

fn export_target(
    process: &Process,
    module: &Module,
    directory: ExportDirectory,
    function_rva: u32,
) -> Result<Option<ExportTarget>, ExportError> {
    if function_rva == 0 {
        return Ok(None);
    }

    let directory_end = directory
        .rva
        .checked_add(directory.size)
        .ok_or_else(|| ExportError::AddressOverflow(module.name.clone()))?;
    if (directory.rva..directory_end).contains(&function_rva) {
        let forwarder = read_name(process, module, function_rva)?;
        return parse_forwarder(module, function_rva, &forwarder)
            .map(ExportTarget::Forwarder)
            .map(Some);
    }
    validate_range(module, function_rva, 1)?;

    module
        .base_address
        .checked_add(u64::from(function_rva))
        .map(ExportTarget::Direct)
        .map(Some)
        .ok_or_else(|| ExportError::AddressOverflow(module.name.clone()))
}

fn read_image(
    process: &Process,
    module: &Module,
    offset: u64,
    buffer: &mut [u8],
) -> Result<(), ExportError> {
    let rva = u32::try_from(offset).map_err(|_| ExportError::RangeOutsideImage {
        module_name: module.name.clone(),
        rva: u32::MAX,
        size: buffer.len(),
    })?;
    validate_range(module, rva, buffer.len())?;
    let address = module
        .base_address
        .checked_add(offset)
        .ok_or_else(|| ExportError::AddressOverflow(module.name.clone()))?;

    process
        .read_exact(address, buffer)
        .map_err(|source| ExportError::ProcessMemory {
            module_name: module.name.clone(),
            source,
        })
}

fn validate_range(module: &Module, rva: u32, size: usize) -> Result<(), ExportError> {
    let range_end =
        u64::from(rva)
            .checked_add(size as u64)
            .ok_or_else(|| ExportError::RangeOutsideImage {
                module_name: module.name.clone(),
                rva,
                size,
            })?;
    if range_end > u64::from(module.image_size) {
        return Err(ExportError::RangeOutsideImage {
            module_name: module.name.clone(),
            rva,
            size,
        });
    }

    Ok(())
}

fn invalid_image(module: &Module, reason: &'static str) -> ExportError {
    ExportError::InvalidImage {
        module_name: module.name.clone(),
        reason,
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("validated two-byte field"),
    )
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("validated four-byte field"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_index_preserves_export_aliases() {
        let mut index = ExportIndex::default();
        index.insert(
            0x1800_1000,
            ExportSymbol {
                module_name: "kernelbase.dll".to_owned(),
                name: Some("GetTickCount".to_owned()),
                ordinal: 725,
                forwarded: false,
            },
        );
        index.insert(
            0x1800_1000,
            ExportSymbol {
                module_name: "kernelbase.dll".to_owned(),
                name: Some("GetTickCountStub".to_owned()),
                ordinal: 726,
                forwarded: false,
            },
        );

        assert_eq!(index.at(0x1800_1000).len(), 2);
        assert!(index.at(0x1800_2000).is_empty());
    }

    #[test]
    fn resolves_forwarder_chains_to_direct_export_address() {
        let definitions = vec![
            ExportDefinition {
                symbol: ExportSymbol {
                    module_name: "legacy.dll".to_owned(),
                    name: Some("GetTickCount".to_owned()),
                    ordinal: 1,
                    forwarded: false,
                },
                target: ExportTarget::Forwarder(ExportKey {
                    module_name: "kernel32.dll".to_owned(),
                    symbol: ExportKeySymbol::Name("GetTickCount".to_owned()),
                }),
            },
            ExportDefinition {
                symbol: ExportSymbol {
                    module_name: "KERNEL32.DLL".to_owned(),
                    name: Some("GetTickCount".to_owned()),
                    ordinal: 2,
                    forwarded: false,
                },
                target: ExportTarget::Forwarder(ExportKey {
                    module_name: "kernelbase.dll".to_owned(),
                    symbol: ExportKeySymbol::Name("GetTickCount".to_owned()),
                }),
            },
            ExportDefinition {
                symbol: ExportSymbol {
                    module_name: "KERNELBASE.dll".to_owned(),
                    name: Some("GetTickCount".to_owned()),
                    ordinal: 3,
                    forwarded: false,
                },
                target: ExportTarget::Direct(0x1800_1000),
            },
        ];

        let index = ExportIndex::from_definitions(definitions);
        let aliases = index.at(0x1800_1000);

        assert_eq!(aliases.len(), 3);
        assert_eq!(aliases.iter().filter(|symbol| symbol.forwarded).count(), 2);
        assert!(
            aliases
                .iter()
                .any(|symbol| symbol.module_name == "legacy.dll")
        );
        assert!(
            aliases
                .iter()
                .any(|symbol| symbol.module_name.eq_ignore_ascii_case("kernel32.dll"))
        );
    }

    #[test]
    fn parses_named_and_ordinal_forwarders() {
        let module = Module {
            name: "source.dll".to_owned(),
            image_path: String::new(),
            base_address: 0x1800_0000,
            image_size: 0x2000,
        };

        assert_eq!(
            parse_forwarder(&module, 0x1000, "KERNELBASE.GetTickCount")
                .expect("valid named forwarder"),
            ExportKey {
                module_name: "kernelbase.dll".to_owned(),
                symbol: ExportKeySymbol::Name("GetTickCount".to_owned()),
            }
        );
        assert_eq!(
            parse_forwarder(&module, 0x1000, "NTDLL.#42").expect("valid ordinal forwarder"),
            ExportKey {
                module_name: "ntdll.dll".to_owned(),
                symbol: ExportKeySymbol::Ordinal(42),
            }
        );
    }

    #[test]
    fn rejects_range_beyond_module_image() {
        let module = Module {
            name: "sample.dll".to_owned(),
            image_path: String::new(),
            base_address: 0x1800_0000,
            image_size: 0x2000,
        };

        assert!(matches!(
            validate_range(&module, 0x1ff0, 0x20),
            Err(ExportError::RangeOutsideImage { .. })
        ));
    }
}
