//! Console set-up for decorated output.
//!
//! On Windows the console output code page is switched to UTF-8 and ANSI
//! sequences are enabled on stdout and stderr; the previous settings come
//! back when the guard is dropped. Elsewhere the guard does nothing.

/// Restores the console settings changed at start-up when dropped.
pub struct ConsoleGuard {
    #[cfg(windows)]
    saved: imp::Saved,
}

impl ConsoleGuard {
    /// Prepares the console for decorated output; `None` when not decorating.
    pub fn prepare(decorate: bool) -> Option<ConsoleGuard> {
        if !decorate {
            return None;
        }
        Some(ConsoleGuard {
            #[cfg(windows)]
            saved: imp::prepare(),
        })
    }
}

#[cfg(windows)]
impl Drop for ConsoleGuard {
    fn drop(&mut self) {
        imp::restore(&self.saved);
    }
}

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Console::{
        CONSOLE_MODE, ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, GetConsoleOutputCP,
        GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE, SetConsoleMode, SetConsoleOutputCP,
    };

    const CP_UTF8: u32 = 65001;

    pub struct Saved {
        code_page: u32,
        modes: Vec<(HANDLE, CONSOLE_MODE)>,
    }

    pub fn prepare() -> Saved {
        // SAFETY: plain Win32 calls on the process's own standard handles;
        // failures are reported through return values and leave state as is.
        unsafe {
            let code_page = GetConsoleOutputCP();
            if code_page != 0 && code_page != CP_UTF8 {
                SetConsoleOutputCP(CP_UTF8);
            }
            let mut modes = Vec::new();
            for which in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
                let handle = GetStdHandle(which);
                if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                    continue;
                }
                let mut mode: CONSOLE_MODE = 0;
                if GetConsoleMode(handle, &mut mode) == 0 {
                    continue;
                }
                if mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING == 0
                    && SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
                {
                    modes.push((handle, mode));
                }
            }
            Saved { code_page, modes }
        }
    }

    pub fn restore(saved: &Saved) {
        // SAFETY: restores values read in `prepare` on the same handles.
        unsafe {
            for (handle, mode) in &saved.modes {
                SetConsoleMode(*handle, *mode);
            }
            if saved.code_page != 0 && saved.code_page != CP_UTF8 {
                SetConsoleOutputCP(saved.code_page);
            }
        }
    }
}
