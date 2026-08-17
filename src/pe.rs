use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    mem::size_of,
};

use crate::{
    import_layout::ImportSectionLayout,
    process::{Architecture, Module, Process, ProcessError},
};

const DOS_HEADER_SIZE: usize = 64;
const NT_PREFIX_SIZE: usize = 24;
const SECTION_HEADER_SIZE: usize = 40;
const MAX_NT_HEADER_OFFSET: u64 = 1024 * 1024;
const MAX_OPTIONAL_HEADER_SIZE: u16 = 4096;
const MAX_SECTION_COUNT: u16 = 96;
const ENTROPY_CHUNK_SIZE: usize = 64 * 1024;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x010b;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020b;
const IMPORT_DIRECTORY_ORDINAL: usize = 1;
const EXPORT_DIRECTORY_ORDINAL: usize = 0;
const EXCEPTION_DIRECTORY_ORDINAL: usize = 3;
const SECURITY_DIRECTORY_ORDINAL: usize = 4;
const BASE_RELOCATION_DIRECTORY_ORDINAL: usize = 5;
const BOUND_IMPORT_DIRECTORY_ORDINAL: usize = 11;
const IAT_DIRECTORY_ORDINAL: usize = 12;
const TLS_DIRECTORY_ORDINAL: usize = 9;
const REQUIRED_DIRECTORY_COUNT: u32 = 13;
#[cfg(test)]
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
const IMAGE_REL_BASED_DIR64: u16 = 10;
const BASE_RELOCATION_BLOCK_HEADER_SIZE: usize = 8;
const BASE_RELOCATION_PAGE_MASK: u32 = !0xfff;
const EXPORT_DIRECTORY_SIZE: usize = 40;
const RUNTIME_FUNCTION_SIZE: usize = 12;
const MAX_CODE_ROOT_COUNT: usize = 1_000_000;

#[derive(Clone, Debug)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

impl Section {
    pub fn mapped_size(&self) -> u32 {
        self.virtual_size.max(self.raw_size)
    }

    pub fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }

    pub fn is_readable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_READ != 0
    }

    pub fn is_writable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }
}

#[derive(Clone, Copy, Debug)]
struct FileSection {
    virtual_address: u32,
    mapped_size: u32,
    raw_offset: u32,
    raw_size: u32,
    characteristics: u32,
}

#[derive(Debug)]
pub struct PeFileMetadata {
    architecture: Architecture,
    nt_offset: usize,
    optional_header_offset: usize,
    section_count: u16,
    section_alignment: u32,
    file_alignment: u32,
    size_of_headers: u32,
    data_directory_offset: usize,
    entry_rva: u32,
    new_section_rva: u32,
    new_section_header_offset: usize,
    new_section_raw_offset: u32,
    file_sections: Vec<FileSection>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BaseRelocationDirectory {
    pub rva: u32,
    pub size: u32,
}

impl PeFileMetadata {
    pub fn parse(
        architecture: Architecture,
        module_snapshot: &[u8],
    ) -> Result<Self, PeOutputError> {
        require_snapshot_range(module_snapshot, 0, DOS_HEADER_SIZE)?;
        if module_snapshot[..2] != *b"MZ" {
            return Err(PeOutputError::InvalidHeaders("missing MZ signature"));
        }

        let nt_offset = i32::from_le_bytes(
            module_snapshot[0x3c..0x40]
                .try_into()
                .expect("the DOS header offset has four bytes"),
        );
        if nt_offset < DOS_HEADER_SIZE as i32 || nt_offset as u64 > MAX_NT_HEADER_OFFSET {
            return Err(PeOutputError::InvalidHeaders("invalid PE header offset"));
        }
        let nt_offset = nt_offset as usize;
        require_snapshot_range(module_snapshot, nt_offset, NT_PREFIX_SIZE)?;
        if module_snapshot[nt_offset..nt_offset + 4] != *b"PE\0\0" {
            return Err(PeOutputError::InvalidHeaders("missing PE signature"));
        }

        let machine = read_u16(module_snapshot, nt_offset + 4);
        let section_count = read_u16(module_snapshot, nt_offset + 6);
        if section_count == 0 || section_count > MAX_SECTION_COUNT {
            return Err(PeOutputError::InvalidSectionCount(section_count));
        }
        let optional_header_size = read_u16(module_snapshot, nt_offset + 20);
        if optional_header_size < size_of::<u16>() as u16
            || optional_header_size > MAX_OPTIONAL_HEADER_SIZE
        {
            return Err(PeOutputError::InvalidOptionalHeaderSize(
                optional_header_size,
            ));
        }
        let optional_header_offset = nt_offset
            .checked_add(NT_PREFIX_SIZE)
            .ok_or(PeOutputError::ArithmeticOverflow)?;
        require_snapshot_range(
            module_snapshot,
            optional_header_offset,
            usize::from(optional_header_size),
        )?;
        let optional_magic = read_u16(module_snapshot, optional_header_offset);
        let (directory_count_offset, data_directory_offset): (usize, usize) =
            match (architecture, machine, optional_magic) {
                (Architecture::X86, IMAGE_FILE_MACHINE_I386, IMAGE_NT_OPTIONAL_HDR32_MAGIC) => {
                    (92, 96)
                }
                (Architecture::X64, IMAGE_FILE_MACHINE_AMD64, IMAGE_NT_OPTIONAL_HDR64_MAGIC) => {
                    (108, 112)
                }
                _ => {
                    return Err(PeOutputError::ArchitectureMismatch {
                        architecture,
                        machine,
                        optional_magic,
                    });
                }
            };
        let minimum_optional_size = data_directory_offset
            .checked_add(REQUIRED_DIRECTORY_COUNT as usize * 8)
            .ok_or(PeOutputError::ArithmeticOverflow)?;
        if usize::from(optional_header_size) < minimum_optional_size {
            return Err(PeOutputError::MissingDataDirectories);
        }
        let data_directory_count = read_u32(
            module_snapshot,
            optional_header_offset + directory_count_offset,
        );
        if data_directory_count < REQUIRED_DIRECTORY_COUNT {
            return Err(PeOutputError::MissingDataDirectories);
        }

        let section_alignment = read_u32(module_snapshot, optional_header_offset + 32);
        let file_alignment = read_u32(module_snapshot, optional_header_offset + 36);
        if !section_alignment.is_power_of_two() || !file_alignment.is_power_of_two() {
            return Err(PeOutputError::InvalidAlignment {
                section_alignment,
                file_alignment,
            });
        }
        let size_of_image = read_u32(module_snapshot, optional_header_offset + 56);
        let size_of_headers = read_u32(module_snapshot, optional_header_offset + 60);
        if size_of_headers == 0 {
            return Err(PeOutputError::InvalidHeaders("SizeOfHeaders is zero"));
        }
        require_snapshot_range(module_snapshot, 0, size_of_headers as usize)?;

        let section_table_offset = optional_header_offset
            .checked_add(usize::from(optional_header_size))
            .ok_or(PeOutputError::ArithmeticOverflow)?;
        let existing_section_headers_size = usize::from(section_count)
            .checked_mul(SECTION_HEADER_SIZE)
            .ok_or(PeOutputError::ArithmeticOverflow)?;
        require_snapshot_range(
            module_snapshot,
            section_table_offset,
            existing_section_headers_size,
        )?;
        let new_section_header_offset = section_table_offset
            .checked_add(existing_section_headers_size)
            .ok_or(PeOutputError::ArithmeticOverflow)?;
        let new_section_header_end = new_section_header_offset
            .checked_add(SECTION_HEADER_SIZE)
            .ok_or(PeOutputError::ArithmeticOverflow)?;

        let mut first_raw_offset = size_of_headers;
        let mut greatest_raw_end = size_of_headers;
        let mut greatest_virtual_end = size_of_image;
        let mut file_sections = Vec::with_capacity(usize::from(section_count));
        for section_ordinal in 0..usize::from(section_count) {
            let section_header_offset = section_table_offset
                .checked_add(
                    section_ordinal
                        .checked_mul(SECTION_HEADER_SIZE)
                        .ok_or(PeOutputError::ArithmeticOverflow)?,
                )
                .ok_or(PeOutputError::ArithmeticOverflow)?;
            let virtual_size = read_u32(module_snapshot, section_header_offset + 8);
            let virtual_address = read_u32(module_snapshot, section_header_offset + 12);
            let raw_size = read_u32(module_snapshot, section_header_offset + 16);
            let raw_offset = read_u32(module_snapshot, section_header_offset + 20);
            let characteristics = read_u32(module_snapshot, section_header_offset + 36);
            let mapped_size = virtual_size.max(raw_size);
            let virtual_end = virtual_address
                .checked_add(mapped_size)
                .ok_or(PeOutputError::ArithmeticOverflow)?;
            greatest_virtual_end = greatest_virtual_end.max(virtual_end);
            if raw_size != 0 {
                if raw_offset == 0 {
                    return Err(PeOutputError::InvalidHeaders(
                        "a section with raw bytes has a zero file offset",
                    ));
                }
                first_raw_offset = first_raw_offset.min(raw_offset);
                let raw_end = raw_offset
                    .checked_add(raw_size)
                    .ok_or(PeOutputError::ArithmeticOverflow)?;
                greatest_raw_end = greatest_raw_end.max(raw_end);
            }
            file_sections.push(FileSection {
                virtual_address,
                mapped_size,
                raw_offset,
                raw_size,
                characteristics,
            });
        }
        let header_limit = size_of_headers.min(first_raw_offset) as usize;
        if new_section_header_end > header_limit {
            return Err(PeOutputError::NoSectionHeaderSpace {
                required_end: new_section_header_end,
                available_end: header_limit,
            });
        }

        let new_section_rva = align_up_u32(greatest_virtual_end, section_alignment)?;
        let new_section_raw_offset = align_up_u32(greatest_raw_end, file_alignment)?;

        Ok(Self {
            architecture,
            nt_offset,
            optional_header_offset,
            section_count,
            section_alignment,
            file_alignment,
            size_of_headers,
            data_directory_offset: optional_header_offset + data_directory_offset,
            entry_rva: read_u32(module_snapshot, optional_header_offset + 16),
            new_section_rva,
            new_section_header_offset,
            new_section_raw_offset,
            file_sections,
        })
    }

    pub fn new_section_rva(&self) -> u32 {
        self.new_section_rva
    }

    pub fn code_roots(
        &self,
        module_snapshot: &[u8],
        module_base: u64,
    ) -> Result<Vec<u32>, PeOutputError> {
        let mut roots = BTreeSet::new();
        if self.entry_rva != 0 {
            insert_code_root(module_snapshot, &mut roots, u64::from(self.entry_rva))?;
        }
        append_export_roots(module_snapshot, self.data_directory_offset, &mut roots)?;
        if self.architecture == Architecture::X64 {
            append_runtime_function_roots(module_snapshot, self.data_directory_offset, &mut roots)?;
        }
        append_tls_roots(
            self.architecture,
            module_snapshot,
            module_base,
            self.data_directory_offset,
            &mut roots,
        )?;
        if roots.is_empty() {
            return Err(PeOutputError::InvalidHeaders(
                "no executable entry roots are present",
            ));
        }
        Ok(roots.into_iter().collect())
    }

    pub fn append_base_relocations(
        &self,
        module_snapshot: &[u8],
        import_layout: &mut ImportSectionLayout,
    ) -> Result<Option<BaseRelocationDirectory>, PeOutputError> {
        if import_layout.base_relocation_rvas.is_empty() {
            return Ok(None);
        }
        let generated_relocation_type = match self.architecture {
            Architecture::X86 => IMAGE_REL_BASED_HIGHLOW,
            Architecture::X64 => IMAGE_REL_BASED_DIR64,
        };

        let mut blocks = read_base_relocation_blocks(module_snapshot, self.data_directory_offset)?;
        for &relocation_rva in &import_layout.base_relocation_rvas {
            let page_rva = relocation_rva & BASE_RELOCATION_PAGE_MASK;
            let page_offset = u16::try_from(relocation_rva - page_rva)
                .map_err(|_| PeOutputError::ArithmeticOverflow)?;
            blocks
                .entry(page_rva)
                .or_default()
                .insert((generated_relocation_type << 12) | page_offset);
        }

        let relocation_bytes = encode_base_relocation_blocks(&blocks)?;
        let relocation_offset = align_up_u32(
            u32::try_from(import_layout.bytes.len())
                .map_err(|_| PeOutputError::ArithmeticOverflow)?,
            4,
        )?;
        import_layout.bytes.resize(relocation_offset as usize, 0);
        let directory = BaseRelocationDirectory {
            rva: self
                .new_section_rva
                .checked_add(relocation_offset)
                .ok_or(PeOutputError::ArithmeticOverflow)?,
            size: u32::try_from(relocation_bytes.len())
                .map_err(|_| PeOutputError::ArithmeticOverflow)?,
        };
        import_layout.bytes.extend_from_slice(&relocation_bytes);
        Ok(Some(directory))
    }

    pub fn build_file(
        &self,
        module_snapshot: &[u8],
        module_base: u64,
        section_name: &str,
        entry_rva: Option<u32>,
        import_layout: &ImportSectionLayout,
        base_relocation_directory: Option<BaseRelocationDirectory>,
    ) -> Result<Vec<u8>, PeOutputError> {
        if import_layout.import_directory_rva != self.new_section_rva {
            return Err(PeOutputError::ImportLayoutRvaMismatch {
                expected: self.new_section_rva,
                actual: import_layout.import_directory_rva,
            });
        }
        if section_name.is_empty() || !section_name.is_ascii() || section_name.len() > 8 {
            return Err(PeOutputError::InvalidSectionName(section_name.to_owned()));
        }

        let virtual_size = u32::try_from(import_layout.bytes.len())
            .map_err(|_| PeOutputError::ArithmeticOverflow)?;
        validate_directory_inside_section(
            "import",
            import_layout.import_directory_rva,
            import_layout.import_directory_size,
            self.new_section_rva,
            virtual_size,
        )?;
        validate_directory_inside_section(
            "IAT",
            import_layout.import_address_table_rva,
            import_layout.import_address_table_size,
            self.new_section_rva,
            virtual_size,
        )?;
        if let Some(directory) = base_relocation_directory {
            validate_directory_inside_section(
                "base relocation",
                directory.rva,
                directory.size,
                self.new_section_rva,
                virtual_size,
            )?;
        }
        let raw_size = align_up_u32(virtual_size, self.file_alignment)?;
        let file_size = self
            .new_section_raw_offset
            .checked_add(raw_size)
            .ok_or(PeOutputError::ArithmeticOverflow)? as usize;
        let mut file_bytes = vec![0_u8; file_size];
        let header_size = self.size_of_headers as usize;
        require_snapshot_range(module_snapshot, 0, header_size)?;
        file_bytes[..header_size].copy_from_slice(&module_snapshot[..header_size]);

        // @note: a live image is RVA-mapped, while a PE file is raw-offset mapped; copying
        // sections by their headers prevents a memory dump from masquerading as a valid file.
        for file_section in &self.file_sections {
            if file_section.raw_size == 0 {
                continue;
            }
            let source_offset = file_section.virtual_address as usize;
            let byte_count = file_section.raw_size as usize;
            require_snapshot_range(module_snapshot, source_offset, byte_count)?;
            let destination_offset = file_section.raw_offset as usize;
            let destination_end = destination_offset
                .checked_add(byte_count)
                .ok_or(PeOutputError::ArithmeticOverflow)?;
            let destination = file_bytes
                .get_mut(destination_offset..destination_end)
                .ok_or(PeOutputError::RawRangeOutsideFile {
                    offset: file_section.raw_offset,
                    size: file_section.raw_size,
                })?;
            destination
                .copy_from_slice(&module_snapshot[source_offset..source_offset + byte_count]);
        }

        let new_section_offset = self.new_section_raw_offset as usize;
        file_bytes[new_section_offset..new_section_offset + import_layout.bytes.len()]
            .copy_from_slice(&import_layout.bytes);

        let updated_section_count = self
            .section_count
            .checked_add(1)
            .ok_or(PeOutputError::ArithmeticOverflow)?;
        write_u16(&mut file_bytes, self.nt_offset + 6, updated_section_count);
        match self.architecture {
            Architecture::X86 => write_u32(
                &mut file_bytes,
                self.optional_header_offset + 28,
                u32::try_from(module_base)
                    .map_err(|_| PeOutputError::X86ImageBaseOutsideRange(module_base))?,
            ),
            Architecture::X64 => write_u64(
                &mut file_bytes,
                self.optional_header_offset + 24,
                module_base,
            ),
        }
        let size_of_image = align_up_u32(
            self.new_section_rva
                .checked_add(virtual_size)
                .ok_or(PeOutputError::ArithmeticOverflow)?,
            self.section_alignment,
        )?;
        if let Some(entry_rva) = entry_rva {
            if entry_rva >= size_of_image {
                return Err(PeOutputError::EntryRvaOutsideImage {
                    entry_rva,
                    size_of_image,
                });
            }
            if !self.file_sections.iter().any(|section| {
                section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
                    && entry_rva
                        .checked_sub(section.virtual_address)
                        .is_some_and(|offset| offset < section.mapped_size)
            }) {
                return Err(PeOutputError::EntryRvaNotExecutable(entry_rva));
            }
            write_u32(&mut file_bytes, self.optional_header_offset + 16, entry_rva);
        }
        write_u32(
            &mut file_bytes,
            self.optional_header_offset + 56,
            size_of_image,
        );
        write_u32(&mut file_bytes, self.optional_header_offset + 64, 0);
        write_directory(
            &mut file_bytes,
            self.data_directory_offset,
            IMPORT_DIRECTORY_ORDINAL,
            import_layout.import_directory_rva,
            import_layout.import_directory_size,
        );
        write_directory(
            &mut file_bytes,
            self.data_directory_offset,
            SECURITY_DIRECTORY_ORDINAL,
            0,
            0,
        );
        write_directory(
            &mut file_bytes,
            self.data_directory_offset,
            BOUND_IMPORT_DIRECTORY_ORDINAL,
            0,
            0,
        );
        write_directory(
            &mut file_bytes,
            self.data_directory_offset,
            IAT_DIRECTORY_ORDINAL,
            import_layout.import_address_table_rva,
            import_layout.import_address_table_size,
        );
        if let Some(directory) = base_relocation_directory {
            let characteristics = read_u16(&file_bytes, self.nt_offset + 22);
            write_u16(
                &mut file_bytes,
                self.nt_offset + 22,
                characteristics & !IMAGE_FILE_RELOCS_STRIPPED,
            );
            write_directory(
                &mut file_bytes,
                self.data_directory_offset,
                BASE_RELOCATION_DIRECTORY_ORDINAL,
                directory.rva,
                directory.size,
            );
        }

        let section_header = file_bytes
            .get_mut(
                self.new_section_header_offset
                    ..self.new_section_header_offset + SECTION_HEADER_SIZE,
            )
            .expect("the new section header was validated inside SizeOfHeaders");
        section_header.fill(0);
        section_header[..section_name.len()].copy_from_slice(section_name.as_bytes());
        write_u32(section_header, 8, virtual_size);
        write_u32(section_header, 12, self.new_section_rva);
        write_u32(section_header, 16, raw_size);
        write_u32(section_header, 20, self.new_section_raw_offset);
        write_u32(
            section_header,
            36,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        );

        Ok(file_bytes)
    }
}

#[derive(Debug)]
pub enum PeOutputError {
    SnapshotRangeOutsideImage {
        offset: usize,
        size: usize,
    },
    InvalidHeaders(&'static str),
    InvalidOptionalHeaderSize(u16),
    InvalidSectionCount(u16),
    ArchitectureMismatch {
        architecture: Architecture,
        machine: u16,
        optional_magic: u16,
    },
    MissingDataDirectories,
    InvalidAlignment {
        section_alignment: u32,
        file_alignment: u32,
    },
    NoSectionHeaderSpace {
        required_end: usize,
        available_end: usize,
    },
    ImportLayoutRvaMismatch {
        expected: u32,
        actual: u32,
    },
    InvalidSectionName(String),
    EntryRvaOutsideImage {
        entry_rva: u32,
        size_of_image: u32,
    },
    EntryRvaNotExecutable(u32),
    DirectoryOutsideNewSection {
        name: &'static str,
        rva: u32,
        size: u32,
        section_rva: u32,
        section_size: u32,
    },
    X86ImageBaseOutsideRange(u64),
    RawRangeOutsideFile {
        offset: u32,
        size: u32,
    },
    ArithmeticOverflow,
}

impl fmt::Display for PeOutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SnapshotRangeOutsideImage { offset, size } => write!(
                formatter,
                "snapshot range at 0x{offset:x} with size 0x{size:x} exceeds the live image"
            ),
            Self::InvalidHeaders(reason) => write!(formatter, "invalid PE headers: {reason}"),
            Self::InvalidOptionalHeaderSize(size) => {
                write!(formatter, "invalid optional-header size {size}")
            }
            Self::InvalidSectionCount(count) => write!(formatter, "invalid section count {count}"),
            Self::ArchitectureMismatch {
                architecture,
                machine,
                optional_magic,
            } => write!(
                formatter,
                "expected {architecture} PE headers, found machine 0x{machine:04x} and optional magic 0x{optional_magic:04x}"
            ),
            Self::MissingDataDirectories => formatter
                .write_str("the optional header does not contain import and IAT data directories"),
            Self::InvalidAlignment {
                section_alignment,
                file_alignment,
            } => write!(
                formatter,
                "invalid PE alignments (section 0x{section_alignment:x}, file 0x{file_alignment:x})"
            ),
            Self::NoSectionHeaderSpace {
                required_end,
                available_end,
            } => write!(
                formatter,
                "no room for another section header (needs end 0x{required_end:x}, available through 0x{available_end:x})"
            ),
            Self::ImportLayoutRvaMismatch { expected, actual } => write!(
                formatter,
                "import layout starts at RVA 0x{actual:08x}, expected new section RVA 0x{expected:08x}"
            ),
            Self::InvalidSectionName(name) => {
                write!(formatter, "`{name}` is not a valid PE section name")
            }
            Self::EntryRvaOutsideImage {
                entry_rva,
                size_of_image,
            } => write!(
                formatter,
                "entry RVA 0x{entry_rva:08x} exceeds image size 0x{size_of_image:x}"
            ),
            Self::EntryRvaNotExecutable(entry_rva) => write!(
                formatter,
                "entry RVA 0x{entry_rva:08x} is not inside an executable section"
            ),
            Self::DirectoryOutsideNewSection {
                name,
                rva,
                size,
                section_rva,
                section_size,
            } => write!(
                formatter,
                "{name} directory at RVA 0x{rva:08x} with size 0x{size:x} exceeds the new section at RVA 0x{section_rva:08x} with size 0x{section_size:x}"
            ),
            Self::X86ImageBaseOutsideRange(address) => {
                write!(formatter, "x86 image base 0x{address:x} exceeds 32 bits")
            }
            Self::RawRangeOutsideFile { offset, size } => write!(
                formatter,
                "raw section range at 0x{offset:x} with size 0x{size:x} exceeds the output file"
            ),
            Self::ArithmeticOverflow => formatter.write_str("PE output arithmetic overflowed"),
        }
    }
}

impl Error for PeOutputError {}

#[derive(Debug)]
pub enum PeError {
    ProcessMemory(ProcessError),
    ImageTooSmall,
    InvalidDosSignature,
    InvalidNtOffset(i32),
    InvalidNtSignature,
    InvalidOptionalHeaderSize(u16),
    UnsupportedHeaders {
        machine: u16,
        optional_magic: u16,
    },
    ArchitectureMismatch {
        process: Architecture,
        image: Architecture,
    },
    InvalidSectionCount(u16),
    HeaderArithmeticOverflow,
    RangeOutsideImage {
        offset: u64,
        size: usize,
        image_size: u32,
    },
}

impl fmt::Display for PeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProcessMemory(source) => source.fmt(formatter),
            Self::ImageTooSmall => {
                formatter.write_str("the selected module is too small for a PE image")
            }
            Self::InvalidDosSignature => {
                formatter.write_str("the selected module has no MZ signature")
            }
            Self::InvalidNtOffset(offset) => {
                write!(formatter, "invalid PE header offset {offset}")
            }
            Self::InvalidNtSignature => {
                formatter.write_str("the selected module has no PE signature")
            }
            Self::InvalidOptionalHeaderSize(size) => {
                write!(formatter, "invalid PE optional-header size {size}")
            }
            Self::UnsupportedHeaders {
                machine,
                optional_magic,
            } => write!(
                formatter,
                "unsupported PE headers (machine 0x{machine:04x}, optional magic 0x{optional_magic:04x})"
            ),
            Self::ArchitectureMismatch { process, image } => write!(
                formatter,
                "process architecture is {process}, but the selected module is {image}"
            ),
            Self::InvalidSectionCount(count) => {
                write!(formatter, "invalid PE section count {count}")
            }
            Self::HeaderArithmeticOverflow => {
                formatter.write_str("PE header offsets overflow the address space")
            }
            Self::RangeOutsideImage {
                offset,
                size,
                image_size,
            } => write!(
                formatter,
                "PE range at RVA 0x{offset:x} with size 0x{size:x} exceeds module size 0x{image_size:x}"
            ),
        }
    }
}

impl Error for PeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ProcessMemory(source) => Some(source),
            _ => None,
        }
    }
}

impl From<ProcessError> for PeError {
    fn from(source: ProcessError) -> Self {
        Self::ProcessMemory(source)
    }
}

pub fn read_sections(process: &Process, module: &Module) -> Result<Vec<Section>, PeError> {
    if module.image_size < DOS_HEADER_SIZE as u32 {
        return Err(PeError::ImageTooSmall);
    }

    let mut dos_header = [0_u8; DOS_HEADER_SIZE];
    read_image(process, module, 0, &mut dos_header)?;
    if dos_header[..2] != *b"MZ" {
        return Err(PeError::InvalidDosSignature);
    }

    let nt_offset = i32::from_le_bytes(
        dos_header[0x3c..0x40]
            .try_into()
            .expect("the DOS header offset has four bytes"),
    );
    if nt_offset < DOS_HEADER_SIZE as i32 || nt_offset as u64 > MAX_NT_HEADER_OFFSET {
        return Err(PeError::InvalidNtOffset(nt_offset));
    }
    let nt_offset = nt_offset as u64;

    let mut nt_prefix = [0_u8; NT_PREFIX_SIZE];
    read_image(process, module, nt_offset, &mut nt_prefix)?;
    if nt_prefix[..4] != *b"PE\0\0" {
        return Err(PeError::InvalidNtSignature);
    }

    let machine = read_u16(&nt_prefix, 4);
    let section_count = read_u16(&nt_prefix, 6);
    let optional_header_size = read_u16(&nt_prefix, 20);
    if optional_header_size < size_of::<u16>() as u16
        || optional_header_size > MAX_OPTIONAL_HEADER_SIZE
    {
        return Err(PeError::InvalidOptionalHeaderSize(optional_header_size));
    }
    if section_count == 0 || section_count > MAX_SECTION_COUNT {
        return Err(PeError::InvalidSectionCount(section_count));
    }

    let optional_header_offset = nt_offset
        .checked_add(NT_PREFIX_SIZE as u64)
        .ok_or(PeError::HeaderArithmeticOverflow)?;
    let mut optional_magic = [0_u8; 2];
    read_image(process, module, optional_header_offset, &mut optional_magic)?;
    let optional_magic = u16::from_le_bytes(optional_magic);
    let image_architecture = match (machine, optional_magic) {
        (IMAGE_FILE_MACHINE_I386, IMAGE_NT_OPTIONAL_HDR32_MAGIC) => Architecture::X86,
        (IMAGE_FILE_MACHINE_AMD64, IMAGE_NT_OPTIONAL_HDR64_MAGIC) => Architecture::X64,
        _ => {
            return Err(PeError::UnsupportedHeaders {
                machine,
                optional_magic,
            });
        }
    };
    if image_architecture != process.architecture() {
        return Err(PeError::ArchitectureMismatch {
            process: process.architecture(),
            image: image_architecture,
        });
    }

    let section_table_offset = optional_header_offset
        .checked_add(u64::from(optional_header_size))
        .ok_or(PeError::HeaderArithmeticOverflow)?;
    let section_table_size = usize::from(section_count)
        .checked_mul(SECTION_HEADER_SIZE)
        .ok_or(PeError::HeaderArithmeticOverflow)?;
    let mut section_table = vec![0_u8; section_table_size];
    read_image(process, module, section_table_offset, &mut section_table)?;

    let mut sections = Vec::with_capacity(usize::from(section_count));
    for section_header in section_table.chunks_exact(SECTION_HEADER_SIZE) {
        let name_length = section_header[..8]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(8);
        let section = Section {
            name: String::from_utf8_lossy(&section_header[..name_length]).into_owned(),
            virtual_size: read_u32(section_header, 8),
            virtual_address: read_u32(section_header, 12),
            raw_size: read_u32(section_header, 16),
            characteristics: read_u32(section_header, 36),
        };
        validate_section_range(module, &section)?;
        sections.push(section);
    }

    Ok(sections)
}

pub fn section_entropy(
    process: &Process,
    module: &Module,
    section: &Section,
) -> Result<f64, PeError> {
    let section_size = section.mapped_size() as usize;
    if section_size == 0 {
        return Ok(0.0);
    }

    validate_section_range(module, section)?;
    let mut frequencies = [0_u64; 256];
    let mut processed = 0_usize;
    let mut chunk = vec![0_u8; ENTROPY_CHUNK_SIZE.min(section_size)];

    while processed < section_size {
        let chunk_size = chunk.len().min(section_size - processed);
        let chunk_offset = u64::from(section.virtual_address)
            .checked_add(processed as u64)
            .ok_or(PeError::HeaderArithmeticOverflow)?;
        read_image(process, module, chunk_offset, &mut chunk[..chunk_size])?;

        for byte in &chunk[..chunk_size] {
            frequencies[usize::from(*byte)] += 1;
        }
        processed += chunk_size;
    }

    Ok(entropy_from_frequencies(&frequencies, section_size as u64))
}

fn validate_section_range(module: &Module, section: &Section) -> Result<(), PeError> {
    let offset = u64::from(section.virtual_address);
    let size = section.mapped_size() as usize;
    validate_image_range(module, offset, size)
}

fn read_image(
    process: &Process,
    module: &Module,
    offset: u64,
    buffer: &mut [u8],
) -> Result<(), PeError> {
    validate_image_range(module, offset, buffer.len())?;
    let address = module
        .base_address
        .checked_add(offset)
        .ok_or(PeError::HeaderArithmeticOverflow)?;
    process.read_exact(address, buffer)?;
    Ok(())
}

fn validate_image_range(module: &Module, offset: u64, size: usize) -> Result<(), PeError> {
    let range_end = offset
        .checked_add(size as u64)
        .ok_or(PeError::HeaderArithmeticOverflow)?;
    if range_end > u64::from(module.image_size) {
        return Err(PeError::RangeOutsideImage {
            offset,
            size,
            image_size: module.image_size,
        });
    }
    Ok(())
}

fn require_snapshot_range(
    module_snapshot: &[u8],
    offset: usize,
    size: usize,
) -> Result<(), PeOutputError> {
    let range_end = offset
        .checked_add(size)
        .ok_or(PeOutputError::ArithmeticOverflow)?;
    if range_end > module_snapshot.len() {
        return Err(PeOutputError::SnapshotRangeOutsideImage { offset, size });
    }
    Ok(())
}

fn append_export_roots(
    module_snapshot: &[u8],
    data_directory_offset: usize,
    roots: &mut BTreeSet<u32>,
) -> Result<(), PeOutputError> {
    let Some((directory_rva, directory_size)) = data_directory(
        module_snapshot,
        data_directory_offset,
        EXPORT_DIRECTORY_ORDINAL,
    )?
    else {
        return Ok(());
    };
    if (directory_size as usize) < EXPORT_DIRECTORY_SIZE {
        return Err(PeOutputError::InvalidHeaders(
            "the export directory is truncated",
        ));
    }
    require_snapshot_range(
        module_snapshot,
        directory_rva as usize,
        EXPORT_DIRECTORY_SIZE,
    )?;
    let directory_offset = directory_rva as usize;
    let function_count = read_u32(module_snapshot, directory_offset + 20) as usize;
    if function_count > MAX_CODE_ROOT_COUNT {
        return Err(PeOutputError::InvalidHeaders(
            "the export function count is too large",
        ));
    }
    let functions_rva = read_u32(module_snapshot, directory_offset + 28);
    let function_bytes = function_count
        .checked_mul(size_of::<u32>())
        .ok_or(PeOutputError::ArithmeticOverflow)?;
    require_snapshot_range(module_snapshot, functions_rva as usize, function_bytes)?;
    let directory_end = directory_rva
        .checked_add(directory_size)
        .ok_or(PeOutputError::ArithmeticOverflow)?;

    for function_index in 0..function_count {
        let function_offset = (functions_rva as usize)
            .checked_add(
                function_index
                    .checked_mul(size_of::<u32>())
                    .ok_or(PeOutputError::ArithmeticOverflow)?,
            )
            .ok_or(PeOutputError::ArithmeticOverflow)?;
        let function_rva = read_u32(module_snapshot, function_offset);
        if function_rva != 0 && !(directory_rva..directory_end).contains(&function_rva) {
            insert_code_root(module_snapshot, roots, u64::from(function_rva))?;
        }
    }
    Ok(())
}

fn append_runtime_function_roots(
    module_snapshot: &[u8],
    data_directory_offset: usize,
    roots: &mut BTreeSet<u32>,
) -> Result<(), PeOutputError> {
    let Some((directory_rva, directory_size)) = data_directory(
        module_snapshot,
        data_directory_offset,
        EXCEPTION_DIRECTORY_ORDINAL,
    )?
    else {
        return Ok(());
    };
    if !(directory_size as usize).is_multiple_of(RUNTIME_FUNCTION_SIZE) {
        return Err(PeOutputError::InvalidHeaders(
            "the exception directory has a partial runtime-function record",
        ));
    }
    let function_count = directory_size as usize / RUNTIME_FUNCTION_SIZE;
    if function_count > MAX_CODE_ROOT_COUNT {
        return Err(PeOutputError::InvalidHeaders(
            "the runtime-function count is too large",
        ));
    }
    require_snapshot_range(
        module_snapshot,
        directory_rva as usize,
        directory_size as usize,
    )?;
    for function_index in 0..function_count {
        let function_offset = (directory_rva as usize)
            .checked_add(
                function_index
                    .checked_mul(RUNTIME_FUNCTION_SIZE)
                    .ok_or(PeOutputError::ArithmeticOverflow)?,
            )
            .ok_or(PeOutputError::ArithmeticOverflow)?;
        let function_rva = read_u32(module_snapshot, function_offset);
        if function_rva != 0 {
            insert_code_root(module_snapshot, roots, u64::from(function_rva))?;
        }
    }
    Ok(())
}

fn append_tls_roots(
    architecture: Architecture,
    module_snapshot: &[u8],
    module_base: u64,
    data_directory_offset: usize,
    roots: &mut BTreeSet<u32>,
) -> Result<(), PeOutputError> {
    let Some((directory_rva, directory_size)) = data_directory(
        module_snapshot,
        data_directory_offset,
        TLS_DIRECTORY_ORDINAL,
    )?
    else {
        return Ok(());
    };
    let (directory_byte_count, callback_field_offset, pointer_size) = match architecture {
        Architecture::X86 => (24, 12, size_of::<u32>()),
        Architecture::X64 => (40, 24, size_of::<u64>()),
    };
    if (directory_size as usize) < directory_byte_count {
        return Err(PeOutputError::InvalidHeaders(
            "the TLS directory is truncated",
        ));
    }
    require_snapshot_range(
        module_snapshot,
        directory_rva as usize,
        directory_byte_count,
    )?;
    let callback_field = (directory_rva as usize)
        .checked_add(callback_field_offset)
        .ok_or(PeOutputError::ArithmeticOverflow)?;
    let callback_table_address = match architecture {
        Architecture::X86 => u64::from(read_u32(module_snapshot, callback_field)),
        Architecture::X64 => read_u64(module_snapshot, callback_field),
    };
    if callback_table_address == 0 {
        return Ok(());
    }
    let callback_table_rva = callback_table_address
        .checked_sub(module_base)
        .and_then(|rva| usize::try_from(rva).ok())
        .filter(|rva| *rva < module_snapshot.len())
        .ok_or(PeOutputError::InvalidHeaders(
            "the TLS callback table is outside the image",
        ))?;

    for callback_index in 0..MAX_CODE_ROOT_COUNT {
        let callback_offset = callback_table_rva
            .checked_add(
                callback_index
                    .checked_mul(pointer_size)
                    .ok_or(PeOutputError::ArithmeticOverflow)?,
            )
            .ok_or(PeOutputError::ArithmeticOverflow)?;
        require_snapshot_range(module_snapshot, callback_offset, pointer_size)?;
        let callback_address = match architecture {
            Architecture::X86 => u64::from(read_u32(module_snapshot, callback_offset)),
            Architecture::X64 => read_u64(module_snapshot, callback_offset),
        };
        if callback_address == 0 {
            return Ok(());
        }
        let callback_rva =
            callback_address
                .checked_sub(module_base)
                .ok_or(PeOutputError::InvalidHeaders(
                    "a TLS callback is outside the image",
                ))?;
        insert_code_root(module_snapshot, roots, callback_rva)?;
    }
    Err(PeOutputError::InvalidHeaders(
        "the TLS callback table is not terminated",
    ))
}

fn data_directory(
    module_snapshot: &[u8],
    data_directory_offset: usize,
    directory_ordinal: usize,
) -> Result<Option<(u32, u32)>, PeOutputError> {
    let directory_offset = data_directory_offset
        .checked_add(
            directory_ordinal
                .checked_mul(8)
                .ok_or(PeOutputError::ArithmeticOverflow)?,
        )
        .ok_or(PeOutputError::ArithmeticOverflow)?;
    require_snapshot_range(module_snapshot, directory_offset, 8)?;
    let rva = read_u32(module_snapshot, directory_offset);
    let size = read_u32(module_snapshot, directory_offset + 4);
    match (rva, size) {
        (0, 0) => Ok(None),
        (0, _) | (_, 0) => Err(PeOutputError::InvalidHeaders(
            "a PE data directory is incomplete",
        )),
        _ => Ok(Some((rva, size))),
    }
}

fn insert_code_root(
    module_snapshot: &[u8],
    roots: &mut BTreeSet<u32>,
    rva: u64,
) -> Result<(), PeOutputError> {
    let rva = u32::try_from(rva).map_err(|_| {
        PeOutputError::InvalidHeaders("an executable entry root exceeds the PE RVA range")
    })?;
    if rva as usize >= module_snapshot.len() {
        return Err(PeOutputError::InvalidHeaders(
            "an executable entry root is outside the image",
        ));
    }
    roots.insert(rva);
    Ok(())
}

fn read_base_relocation_blocks(
    module_snapshot: &[u8],
    data_directory_offset: usize,
) -> Result<BTreeMap<u32, BTreeSet<u16>>, PeOutputError> {
    let directory_offset = data_directory_offset + BASE_RELOCATION_DIRECTORY_ORDINAL * 8;
    let directory_rva = read_u32(module_snapshot, directory_offset);
    let directory_size = read_u32(module_snapshot, directory_offset + 4);
    if directory_rva == 0 && directory_size == 0 {
        return Ok(BTreeMap::new());
    }
    if directory_rva == 0 || directory_size == 0 {
        return Err(PeOutputError::InvalidHeaders(
            "incomplete base-relocation directory",
        ));
    }
    let directory_offset = directory_rva as usize;
    let directory_size = directory_size as usize;
    require_snapshot_range(module_snapshot, directory_offset, directory_size)?;
    let directory = &module_snapshot[directory_offset..directory_offset + directory_size];
    let mut blocks = BTreeMap::<u32, BTreeSet<u16>>::new();
    let mut offset = 0;

    while offset < directory.len() {
        let remaining = &directory[offset..];
        if remaining.iter().all(|byte| *byte == 0) {
            break;
        }
        if remaining.len() < BASE_RELOCATION_BLOCK_HEADER_SIZE {
            return Err(PeOutputError::InvalidHeaders(
                "truncated base-relocation block header",
            ));
        }
        let page_rva = read_u32(directory, offset);
        let block_size = read_u32(directory, offset + 4) as usize;
        if page_rva & !BASE_RELOCATION_PAGE_MASK != 0
            || block_size < BASE_RELOCATION_BLOCK_HEADER_SIZE
            || !block_size.is_multiple_of(2)
            || block_size > remaining.len()
        {
            return Err(PeOutputError::InvalidHeaders(
                "invalid base-relocation block",
            ));
        }
        let entries_begin = offset + BASE_RELOCATION_BLOCK_HEADER_SIZE;
        let entries_end = offset + block_size;
        for entry_offset in (entries_begin..entries_end).step_by(2) {
            let entry = read_u16(directory, entry_offset);
            if entry >> 12 != 0 {
                blocks.entry(page_rva).or_default().insert(entry);
            }
        }
        offset = entries_end;
    }

    Ok(blocks)
}

fn encode_base_relocation_blocks(
    blocks: &BTreeMap<u32, BTreeSet<u16>>,
) -> Result<Vec<u8>, PeOutputError> {
    let mut bytes = Vec::new();
    for (&page_rva, entries) in blocks {
        if entries.is_empty() {
            continue;
        }
        let block_offset = bytes.len();
        bytes.resize(
            block_offset
                .checked_add(BASE_RELOCATION_BLOCK_HEADER_SIZE)
                .ok_or(PeOutputError::ArithmeticOverflow)?,
            0,
        );
        for &entry in entries {
            bytes.extend_from_slice(&entry.to_le_bytes());
        }
        if !(bytes.len() - block_offset).is_multiple_of(4) {
            bytes.extend_from_slice(&0_u16.to_le_bytes());
        }
        let block_size = u32::try_from(bytes.len() - block_offset)
            .map_err(|_| PeOutputError::ArithmeticOverflow)?;
        write_u32(&mut bytes, block_offset, page_rva);
        write_u32(&mut bytes, block_offset + 4, block_size);
    }
    Ok(bytes)
}

fn align_up_u32(bits: u32, alignment: u32) -> Result<u32, PeOutputError> {
    let remainder = bits % alignment;
    if remainder == 0 {
        return Ok(bits);
    }

    bits.checked_add(alignment - remainder)
        .ok_or(PeOutputError::ArithmeticOverflow)
}

fn write_directory(
    bytes: &mut [u8],
    directory_offset: usize,
    directory_ordinal: usize,
    rva: u32,
    size: u32,
) {
    let offset = directory_offset + directory_ordinal * 8;
    write_u32(bytes, offset, rva);
    write_u32(bytes, offset + 4, size);
}

fn validate_directory_inside_section(
    name: &'static str,
    directory_rva: u32,
    directory_size: u32,
    section_rva: u32,
    section_size: u32,
) -> Result<(), PeOutputError> {
    let directory_end = directory_rva.checked_add(directory_size);
    let section_end = section_rva.checked_add(section_size);
    let is_inside = directory_size != 0
        && directory_rva >= section_rva
        && directory_end
            .zip(section_end)
            .is_some_and(|(directory_end, section_end)| directory_end <= section_end);
    if !is_inside {
        return Err(PeOutputError::DirectoryOutsideNewSection {
            name,
            rva: directory_rva,
            size: directory_size,
            section_rva,
            section_size,
        });
    }

    Ok(())
}

fn write_u16(bytes: &mut [u8], offset: usize, bits: u16) {
    bytes[offset..offset + 2].copy_from_slice(&bits.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, bits: u32) {
    bytes[offset..offset + 4].copy_from_slice(&bits.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, bits: u64) {
    bytes[offset..offset + 8].copy_from_slice(&bits.to_le_bytes());
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("validated PE field width"),
    )
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("validated PE field width"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("validated eight-byte field"),
    )
}

fn entropy_from_frequencies(frequencies: &[u64; 256], byte_count: u64) -> f64 {
    if byte_count == 0 {
        return 0.0;
    }

    let byte_count = byte_count as f64;
    frequencies
        .iter()
        .filter(|frequency| **frequency != 0)
        .map(|frequency| {
            let probability = *frequency as f64 / byte_count;
            -probability * probability.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use crate::import_layout::ImportSectionLayout;

    use super::*;

    #[test]
    fn constant_bytes_have_zero_entropy() {
        let mut frequencies = [0_u64; 256];
        frequencies[42] = 1024;

        assert_eq!(entropy_from_frequencies(&frequencies, 1024), 0.0);
    }

    #[test]
    fn uniform_bytes_have_maximum_entropy() {
        let frequencies = [1_u64; 256];

        assert_eq!(entropy_from_frequencies(&frequencies, 256), 8.0);
    }

    #[test]
    fn rebuilds_pe32_file_from_rva_mapped_snapshot() {
        verify_rebuilt_file(Architecture::X86, 0x0040_0000);
    }

    #[test]
    fn rebuilds_pe32_plus_file_from_rva_mapped_snapshot() {
        verify_rebuilt_file(Architecture::X64, 0x0000_7ff6_1234_0000);
    }

    #[test]
    fn collects_entry_export_runtime_and_tls_code_roots() {
        const MODULE_BASE: u64 = 0x0000_7ff6_1234_0000;
        let mut module_snapshot = sample_snapshot(Architecture::X64);
        let optional_header_offset = 0x98;
        let data_directory_offset = optional_header_offset + 112;
        write_u32(&mut module_snapshot, optional_header_offset + 16, 0x1010);

        write_directory(
            &mut module_snapshot,
            data_directory_offset,
            EXPORT_DIRECTORY_ORDINAL,
            0x1100,
            0x80,
        );
        write_u32(&mut module_snapshot, 0x1100 + 20, 1);
        write_u32(&mut module_snapshot, 0x1100 + 28, 0x1200);
        write_u32(&mut module_snapshot, 0x1200, 0x1020);

        write_directory(
            &mut module_snapshot,
            data_directory_offset,
            EXCEPTION_DIRECTORY_ORDINAL,
            0x1210,
            RUNTIME_FUNCTION_SIZE as u32,
        );
        write_u32(&mut module_snapshot, 0x1210, 0x1030);

        write_directory(
            &mut module_snapshot,
            data_directory_offset,
            TLS_DIRECTORY_ORDINAL,
            0x1230,
            40,
        );
        write_u64(&mut module_snapshot, 0x1230 + 24, MODULE_BASE + 0x1280);
        write_u64(&mut module_snapshot, 0x1280, MODULE_BASE + 0x1040);

        let metadata = PeFileMetadata::parse(Architecture::X64, &module_snapshot)
            .expect("valid PE file metadata");

        assert_eq!(
            metadata
                .code_roots(&module_snapshot, MODULE_BASE)
                .expect("valid PE code roots"),
            [0x1010, 0x1020, 0x1030, 0x1040]
        );
    }

    #[test]
    fn rejects_truncated_export_directory_when_collecting_code_roots() {
        let mut module_snapshot = sample_snapshot(Architecture::X64);
        let data_directory_offset = 0x98 + 112;
        write_directory(
            &mut module_snapshot,
            data_directory_offset,
            EXPORT_DIRECTORY_ORDINAL,
            0x1100,
            (EXPORT_DIRECTORY_SIZE - 1) as u32,
        );
        let metadata = PeFileMetadata::parse(Architecture::X64, &module_snapshot)
            .expect("valid PE file metadata");

        let error = metadata
            .code_roots(&module_snapshot, 0x0000_7ff6_1234_0000)
            .expect_err("a partial export directory must be rejected");

        assert!(matches!(
            error,
            PeOutputError::InvalidHeaders("the export directory is truncated")
        ));
    }

    #[test]
    fn rejects_entry_point_outside_executable_sections() {
        let module_snapshot = sample_snapshot(Architecture::X64);
        let metadata = PeFileMetadata::parse(Architecture::X64, &module_snapshot)
            .expect("valid PE file metadata");
        let import_layout = sample_import_layout();

        let error = metadata
            .build_file(
                &module_snapshot,
                0x0000_7ff6_1234_0000,
                ".vid",
                Some(0x2000),
                &import_layout,
                None,
            )
            .expect_err("the new data section is not executable");

        assert!(matches!(
            error,
            PeOutputError::EntryRvaNotExecutable(0x2000)
        ));
    }

    #[test]
    fn rejects_entry_point_outside_image() {
        let module_snapshot = sample_snapshot(Architecture::X64);
        let metadata = PeFileMetadata::parse(Architecture::X64, &module_snapshot)
            .expect("valid PE file metadata");
        let import_layout = sample_import_layout();

        let error = metadata
            .build_file(
                &module_snapshot,
                0x0000_7ff6_1234_0000,
                ".vid",
                Some(u32::MAX),
                &import_layout,
                None,
            )
            .expect_err("entry RVA exceeds SizeOfImage");

        assert!(matches!(error, PeOutputError::EntryRvaOutsideImage { .. }));
    }

    #[test]
    fn rejects_iat_outside_new_section() {
        let module_snapshot = sample_snapshot(Architecture::X64);
        let metadata = PeFileMetadata::parse(Architecture::X64, &module_snapshot)
            .expect("valid PE file metadata");
        let mut import_layout = sample_import_layout();
        import_layout.import_address_table_rva = 0x3000;

        let error = metadata
            .build_file(
                &module_snapshot,
                0x0000_7ff6_1234_0000,
                ".vid",
                None,
                &import_layout,
                None,
            )
            .expect_err("the IAT exceeds the new section");

        assert!(matches!(
            error,
            PeOutputError::DirectoryOutsideNewSection { name: "IAT", .. }
        ));
    }

    #[test]
    fn rebuilds_x86_base_relocations_for_generated_code() {
        let mut module_snapshot = sample_snapshot(Architecture::X86);
        write_u16(&mut module_snapshot, 0x80 + 22, IMAGE_FILE_RELOCS_STRIPPED);
        let data_directory_offset = 0x98 + 96;
        write_directory(
            &mut module_snapshot,
            data_directory_offset,
            BASE_RELOCATION_DIRECTORY_ORDINAL,
            0x1100,
            12,
        );
        write_u32(&mut module_snapshot, 0x1100, 0x1000);
        write_u32(&mut module_snapshot, 0x1104, 12);
        write_u16(&mut module_snapshot, 0x1108, 0x3010);

        let metadata = PeFileMetadata::parse(Architecture::X86, &module_snapshot)
            .expect("valid PE file metadata");
        let mut import_layout = ImportSectionLayout {
            bytes: vec![0xa5; 0x30],
            import_directory_rva: 0x2000,
            import_directory_size: 40,
            import_address_table_rva: 0x2020,
            import_address_table_size: 8,
            rebuilt_pointers: Vec::new(),
            base_relocation_rvas: vec![0x2042, 0x2048],
        };

        let directory = metadata
            .append_base_relocations(&module_snapshot, &mut import_layout)
            .expect("valid rebuilt base relocations")
            .expect("generated x86 operands require relocations");

        assert_eq!(directory.rva, 0x2030);
        assert_eq!(directory.size, 24);
        assert_eq!(read_u32(&import_layout.bytes, 0x30), 0x1000);
        assert_eq!(read_u32(&import_layout.bytes, 0x34), 12);
        assert_eq!(read_u16(&import_layout.bytes, 0x38), 0x3010);
        assert_eq!(read_u32(&import_layout.bytes, 0x3c), 0x2000);
        assert_eq!(read_u32(&import_layout.bytes, 0x40), 12);
        assert_eq!(read_u16(&import_layout.bytes, 0x44), 0x3042);
        assert_eq!(read_u16(&import_layout.bytes, 0x46), 0x3048);

        let file_bytes = metadata
            .build_file(
                &module_snapshot,
                0x0040_0000,
                ".vid",
                None,
                &import_layout,
                Some(directory),
            )
            .expect("valid rebuilt PE file");
        assert_eq!(read_u32(&file_bytes, data_directory_offset + 40), 0x2030);
        assert_eq!(read_u32(&file_bytes, data_directory_offset + 44), 24);
        assert_eq!(read_u32(&file_bytes, 0x430), 0x1000);
        assert_eq!(
            read_u16(&file_bytes, 0x80 + 22) & IMAGE_FILE_RELOCS_STRIPPED,
            0
        );
    }

    #[test]
    fn rebuilds_x64_base_relocations_for_generated_code() {
        let mut module_snapshot = sample_snapshot(Architecture::X64);
        let data_directory_offset = 0x98 + 112;
        write_directory(
            &mut module_snapshot,
            data_directory_offset,
            BASE_RELOCATION_DIRECTORY_ORDINAL,
            0x1100,
            12,
        );
        write_u32(&mut module_snapshot, 0x1100, 0x1000);
        write_u32(&mut module_snapshot, 0x1104, 12);
        write_u16(&mut module_snapshot, 0x1108, 0xa010);

        let metadata = PeFileMetadata::parse(Architecture::X64, &module_snapshot)
            .expect("valid PE file metadata");
        let mut import_layout = ImportSectionLayout {
            bytes: vec![0xa5; 0x30],
            import_directory_rva: 0x2000,
            import_directory_size: 40,
            import_address_table_rva: 0x2020,
            import_address_table_size: 8,
            rebuilt_pointers: Vec::new(),
            base_relocation_rvas: vec![0x2040],
        };

        let directory = metadata
            .append_base_relocations(&module_snapshot, &mut import_layout)
            .expect("valid rebuilt base relocations")
            .expect("generated x64 pointers require relocations");

        assert_eq!(directory.rva, 0x2030);
        assert_eq!(directory.size, 24);
        assert_eq!(read_u16(&import_layout.bytes, 0x38), 0xa010);
        assert_eq!(read_u32(&import_layout.bytes, 0x3c), 0x2000);
        assert_eq!(read_u32(&import_layout.bytes, 0x40), 12);
        assert_eq!(read_u16(&import_layout.bytes, 0x44), 0xa040);

        let file_bytes = metadata
            .build_file(
                &module_snapshot,
                0x0000_7ff6_1234_0000,
                ".vid",
                None,
                &import_layout,
                Some(directory),
            )
            .expect("valid rebuilt PE file");
        assert_eq!(read_u32(&file_bytes, data_directory_offset + 40), 0x2030);
        assert_eq!(read_u32(&file_bytes, data_directory_offset + 44), 24);
    }

    fn verify_rebuilt_file(architecture: Architecture, module_base: u64) {
        let module_snapshot = sample_snapshot(architecture);
        let metadata =
            PeFileMetadata::parse(architecture, &module_snapshot).expect("valid PE file metadata");
        assert_eq!(metadata.new_section_rva(), 0x2000);
        let import_layout = sample_import_layout();

        let file_bytes = metadata
            .build_file(
                &module_snapshot,
                module_base,
                ".vid",
                Some(0x1010),
                &import_layout,
                None,
            )
            .expect("valid rebuilt PE file");

        let optional_header_offset = 0x98;
        let data_directory_offset = optional_header_offset
            + match architecture {
                Architecture::X86 => 96,
                Architecture::X64 => 112,
            };
        assert_eq!(file_bytes.len(), 0x600);
        assert_eq!(read_u16(&file_bytes, 0x86), 2);
        assert_eq!(read_u32(&file_bytes, optional_header_offset + 56), 0x3000);
        assert_eq!(read_u32(&file_bytes, optional_header_offset + 16), 0x1010);
        match architecture {
            Architecture::X86 => {
                assert_eq!(
                    read_u32(&file_bytes, optional_header_offset + 28),
                    module_base as u32
                )
            }
            Architecture::X64 => assert_eq!(
                u64::from_le_bytes(
                    file_bytes[optional_header_offset + 24..optional_header_offset + 32]
                        .try_into()
                        .expect("eight-byte image base"),
                ),
                module_base
            ),
        }
        assert_eq!(read_u32(&file_bytes, data_directory_offset + 8), 0x2000);
        assert_eq!(read_u32(&file_bytes, data_directory_offset + 12), 40);
        assert_eq!(
            read_u32(
                &file_bytes,
                data_directory_offset + IAT_DIRECTORY_ORDINAL * 8
            ),
            0x2020
        );
        assert_eq!(file_bytes[0x200], 0xcc);
        assert_eq!(&file_bytes[0x400..0x430], &[0xa5; 0x30]);
        let new_section_header = metadata.new_section_header_offset;
        assert_eq!(
            &file_bytes[new_section_header..new_section_header + 8],
            b".vid\0\0\0\0"
        );
        assert_eq!(read_u32(&file_bytes, new_section_header + 8), 0x30);
        assert_eq!(read_u32(&file_bytes, new_section_header + 12), 0x2000);
        assert_eq!(read_u32(&file_bytes, new_section_header + 16), 0x200);
        assert_eq!(read_u32(&file_bytes, new_section_header + 20), 0x400);
        assert_eq!(
            read_u32(&file_bytes, new_section_header + 36),
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
        );
    }

    fn sample_import_layout() -> ImportSectionLayout {
        ImportSectionLayout {
            bytes: vec![0xa5; 0x30],
            import_directory_rva: 0x2000,
            import_directory_size: 40,
            import_address_table_rva: 0x2020,
            import_address_table_size: 8,
            rebuilt_pointers: Vec::new(),
            base_relocation_rvas: Vec::new(),
        }
    }

    fn sample_snapshot(architecture: Architecture) -> Vec<u8> {
        const NT_OFFSET: usize = 0x80;
        const OPTIONAL_HEADER_OFFSET: usize = NT_OFFSET + NT_PREFIX_SIZE;
        let optional_header_size: u16 = match architecture {
            Architecture::X86 => 0xe0,
            Architecture::X64 => 0xf0,
        };
        let (machine, optional_magic, directory_count_offset) = match architecture {
            Architecture::X86 => (IMAGE_FILE_MACHINE_I386, IMAGE_NT_OPTIONAL_HDR32_MAGIC, 92),
            Architecture::X64 => (IMAGE_FILE_MACHINE_AMD64, IMAGE_NT_OPTIONAL_HDR64_MAGIC, 108),
        };
        let mut module_snapshot = vec![0_u8; 0x2000];
        module_snapshot[..2].copy_from_slice(b"MZ");
        write_u32(&mut module_snapshot, 0x3c, NT_OFFSET as u32);
        module_snapshot[NT_OFFSET..NT_OFFSET + 4].copy_from_slice(b"PE\0\0");
        write_u16(&mut module_snapshot, NT_OFFSET + 4, machine);
        write_u16(&mut module_snapshot, NT_OFFSET + 6, 1);
        write_u16(&mut module_snapshot, NT_OFFSET + 20, optional_header_size);
        write_u16(&mut module_snapshot, OPTIONAL_HEADER_OFFSET, optional_magic);
        write_u32(&mut module_snapshot, OPTIONAL_HEADER_OFFSET + 32, 0x1000);
        write_u32(&mut module_snapshot, OPTIONAL_HEADER_OFFSET + 36, 0x200);
        write_u32(&mut module_snapshot, OPTIONAL_HEADER_OFFSET + 56, 0x2000);
        write_u32(&mut module_snapshot, OPTIONAL_HEADER_OFFSET + 60, 0x200);
        write_u32(
            &mut module_snapshot,
            OPTIONAL_HEADER_OFFSET + directory_count_offset,
            16,
        );
        let section_header_offset = OPTIONAL_HEADER_OFFSET + usize::from(optional_header_size);
        module_snapshot[section_header_offset..section_header_offset + 5].copy_from_slice(b".text");
        write_u32(&mut module_snapshot, section_header_offset + 8, 0x1000);
        write_u32(&mut module_snapshot, section_header_offset + 12, 0x1000);
        write_u32(&mut module_snapshot, section_header_offset + 16, 0x200);
        write_u32(&mut module_snapshot, section_header_offset + 20, 0x200);
        write_u32(
            &mut module_snapshot,
            section_header_offset + 36,
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        );
        module_snapshot[0x1000] = 0xcc;
        module_snapshot
    }
}
