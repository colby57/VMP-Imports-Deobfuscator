use std::{error::Error, ffi::c_void, fmt, mem::size_of, num::NonZeroU32, path::Path};

use windows::{
    Win32::{
        Foundation::{CloseHandle, ERROR_BAD_LENGTH, ERROR_NO_MORE_FILES, HANDLE},
        System::{
            Diagnostics::{
                Debug::ReadProcessMemory,
                ToolHelp::{
                    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW,
                    TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
                },
            },
            SystemInformation::{
                IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_UNKNOWN,
            },
            Threading::{IsWow64Process2, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
        },
    },
    core::{Error as WindowsError, HRESULT},
};

const MAX_SNAPSHOT_ATTEMPTS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Architecture {
    X86,
    X64,
}

impl fmt::Display for Architecture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86 => formatter.write_str("x86"),
            Self::X64 => formatter.write_str("x64"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Module {
    pub name: String,
    pub image_path: String,
    pub base_address: u64,
    pub image_size: u32,
}

#[derive(Debug)]
pub enum ProcessError {
    Windows {
        operation: &'static str,
        source: WindowsError,
    },
    UnsupportedArchitecture {
        process_machine: u16,
        native_machine: u16,
    },
    NoModules,
    ModuleNotFound(String),
    AddressOutsideHost(u64),
    ShortRead {
        address: u64,
        expected: usize,
        actual: usize,
    },
}

impl ProcessError {
    fn windows(operation: &'static str, source: WindowsError) -> Self {
        Self::Windows { operation, source }
    }
}

impl fmt::Display for ProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Windows { operation, source } => write!(formatter, "{operation}: {source}"),
            Self::UnsupportedArchitecture {
                process_machine,
                native_machine,
            } => write!(
                formatter,
                "unsupported process architecture (process machine 0x{process_machine:04x}, native machine 0x{native_machine:04x})"
            ),
            Self::NoModules => formatter.write_str("the target process has no visible modules"),
            Self::ModuleNotFound(name) => {
                write!(
                    formatter,
                    "module `{name}` was not found in the target process"
                )
            }
            Self::AddressOutsideHost(address) => {
                write!(
                    formatter,
                    "address 0x{address:x} does not fit the host address space"
                )
            }
            Self::ShortRead {
                address,
                expected,
                actual,
            } => write!(
                formatter,
                "short process-memory read at 0x{address:x}: expected {expected} bytes, read {actual}"
            ),
        }
    }
}

impl Error for ProcessError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Windows { source, .. } => Some(source),
            _ => None,
        }
    }
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this type is the sole owner of the valid handle returned by Win32.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

pub struct Process {
    handle: OwnedHandle,
    pid: NonZeroU32,
    architecture: Architecture,
}

impl Process {
    pub fn open(pid: NonZeroU32) -> Result<Self, ProcessError> {
        // SAFETY: the PID is supplied by the user and no borrowed pointers are passed.
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                false,
                pid.get(),
            )
        }
        .map(OwnedHandle)
        .map_err(|source| ProcessError::windows("cannot open the target process", source))?;

        let architecture = detect_architecture(handle.raw())?;

        Ok(Self {
            handle,
            pid,
            architecture,
        })
    }

    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    pub fn find_module(&self, requested_name: Option<&str>) -> Result<Module, ProcessError> {
        let modules = self.modules()?;

        let Some(requested_name) = requested_name else {
            return modules.into_iter().next().ok_or(ProcessError::NoModules);
        };

        modules
            .into_iter()
            .find(|module| module_matches(module, requested_name))
            .ok_or_else(|| ProcessError::ModuleNotFound(requested_name.to_owned()))
    }

    pub fn modules(&self) -> Result<Vec<Module>, ProcessError> {
        self.enumerate_modules()
    }

    pub fn read_exact(&self, address: u64, buffer: &mut [u8]) -> Result<(), ProcessError> {
        if buffer.is_empty() {
            return Ok(());
        }

        let host_address = usize::try_from(address)
            .map_err(|_| ProcessError::AddressOutsideHost(address))?
            as *const c_void;
        let mut bytes_read = 0;

        // SAFETY: the destination points to `buffer`, and Win32 receives its exact byte length.
        unsafe {
            ReadProcessMemory(
                self.handle.raw(),
                host_address,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                Some(&mut bytes_read),
            )
        }
        .map_err(|source| ProcessError::windows("cannot read target process memory", source))?;

        if bytes_read != buffer.len() {
            return Err(ProcessError::ShortRead {
                address,
                expected: buffer.len(),
                actual: bytes_read,
            });
        }

        Ok(())
    }

    fn enumerate_modules(&self) -> Result<Vec<Module>, ProcessError> {
        let snapshot_flags = match self.architecture {
            Architecture::X86 => TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            Architecture::X64 => TH32CS_SNAPMODULE,
        };
        let snapshot = create_module_snapshot(snapshot_flags, self.pid.get())?;
        let mut module_record = MODULEENTRY32W {
            dwSize: size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };

        // SAFETY: `module_record` has the required size and remains valid for the call.
        if let Err(source) = unsafe { Module32FirstW(snapshot.raw(), &mut module_record) } {
            if source.code() == HRESULT::from_win32(ERROR_NO_MORE_FILES.0) {
                return Err(ProcessError::NoModules);
            }
            return Err(ProcessError::windows(
                "cannot enumerate target process modules",
                source,
            ));
        }

        let mut modules = Vec::new();
        loop {
            modules.push(Module {
                name: decode_wide_string(&module_record.szModule),
                image_path: decode_wide_string(&module_record.szExePath),
                base_address: module_record.modBaseAddr as usize as u64,
                image_size: module_record.modBaseSize,
            });

            // SAFETY: `module_record` remains initialized with the required structure size.
            match unsafe { Module32NextW(snapshot.raw(), &mut module_record) } {
                Ok(()) => {}
                Err(source) if source.code() == HRESULT::from_win32(ERROR_NO_MORE_FILES.0) => {
                    break;
                }
                Err(source) => {
                    return Err(ProcessError::windows(
                        "cannot continue target process module enumeration",
                        source,
                    ));
                }
            }
        }

        Ok(modules)
    }
}

fn detect_architecture(handle: HANDLE) -> Result<Architecture, ProcessError> {
    let mut process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    let mut native_machine = IMAGE_FILE_MACHINE_UNKNOWN;

    // SAFETY: both output pointers are valid for the duration of the call.
    unsafe { IsWow64Process2(handle, &mut process_machine, Some(&mut native_machine)) }
        .map_err(|source| ProcessError::windows("cannot determine process architecture", source))?;

    let effective_machine = if process_machine == IMAGE_FILE_MACHINE_UNKNOWN {
        native_machine
    } else {
        process_machine
    };

    match effective_machine {
        IMAGE_FILE_MACHINE_I386 => Ok(Architecture::X86),
        IMAGE_FILE_MACHINE_AMD64 => Ok(Architecture::X64),
        _ => Err(ProcessError::UnsupportedArchitecture {
            process_machine: process_machine.0,
            native_machine: native_machine.0,
        }),
    }
}

fn create_module_snapshot(
    snapshot_flags: windows::Win32::System::Diagnostics::ToolHelp::CREATE_TOOLHELP_SNAPSHOT_FLAGS,
    pid: u32,
) -> Result<OwnedHandle, ProcessError> {
    for attempt in 0..MAX_SNAPSHOT_ATTEMPTS {
        // SAFETY: the flags and PID are plain Win32 values with no pointer arguments.
        match unsafe { CreateToolhelp32Snapshot(snapshot_flags, pid) } {
            Ok(handle) => return Ok(OwnedHandle(handle)),
            Err(source)
                if source.code() == HRESULT::from_win32(ERROR_BAD_LENGTH.0)
                    && attempt + 1 < MAX_SNAPSHOT_ATTEMPTS => {}
            Err(source) => {
                return Err(ProcessError::windows(
                    "cannot create a target process module snapshot",
                    source,
                ));
            }
        }
    }

    unreachable!("the final snapshot attempt always returns")
}

fn module_matches(module: &Module, requested_name: &str) -> bool {
    let requested_file_name = Path::new(requested_name)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(requested_name);

    if module.name.eq_ignore_ascii_case(requested_file_name) {
        return true;
    }

    Path::new(requested_file_name).extension().is_none()
        && Path::new(&module.name)
            .file_stem()
            .and_then(|name| name.to_str())
            .is_some_and(|stem| stem.eq_ignore_ascii_case(requested_file_name))
}

fn decode_wide_string(buffer: &[u16]) -> String {
    let length = buffer
        .iter()
        .position(|character| *character == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..length])
}
