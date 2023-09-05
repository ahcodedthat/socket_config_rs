use cfg_if::cfg_if;
use crate::errors::OpenSocketError;
use socket2::Socket;
use std::io;

cfg_if! {
	if #[cfg(windows)] {
		use std::os::windows::io::{
			AsRawSocket,
			RawSocket,
		};
	}
	else if #[cfg(unix)] {
		use std::os::fd::{
			AsRawFd,
			RawFd as RawSocket,
		};
	}
}

#[allow(unused)]
pub(crate) fn unsupported<T>(name: &'static str) -> Result<T, OpenSocketError> {
	Err(OpenSocketError::UnsupportedUserOption { name })
}

#[allow(unused)]
pub(crate) fn check_unsupported<T>(option: Option<T>, name: &'static str) -> Result<(), OpenSocketError> {
	if option.is_some() {
		unsupported(name)
	}
	else {
		Ok(())
	}
}

pub(crate) fn inapplicable<T>(name: &'static str) -> Result<T, OpenSocketError> {
	Err(OpenSocketError::InapplicableUserOption { name })
}

pub(crate) fn check_inapplicable<T>(option: Option<T>, name: &'static str) -> Result<(), OpenSocketError> {
	if option.is_some() {
		inapplicable(name)
	}
	else {
		Ok(())
	}
}

pub(crate) fn check_inapplicable_bool(option: bool, name: &'static str) -> Result<(), OpenSocketError> {
	if option {
		inapplicable(name)
	}
	else {
		Ok(())
	}
}

/// Mark a socket as inheritable, so that a child process will inherit it.
///
/// If this function is successful, the return value is the file descriptor or handle to pass to the child process.
///
///
/// # Availability
///
/// Unix-like platforms and Windows only.
///
///
/// # Details
///
/// By convention, Rust socket libraries, including [the standard library][std], create non-inheritable sockets. When spawning a subprocess from a Rust program (such as an integration test) that is to inherit a socket from the parent process, the socket must be made inheritable first.
///
/// On Windows, handles (including but not limited to sockets) [can be inherited](https://learn.microsoft.com/en-us/windows/win32/sysinfo/handle-inheritance), but two conditions must be met: the handle's `bInheritHandle` attribute must be set to true, and when the child process is created, the [`CreateProcess`](https://learn.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createprocessa) parameter `bInheritHandles` must be set to true. This function fulfills the former requirement using the [`SetHandleInformation`](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-sethandleinformation) function. The latter requirement is already fulfilled by [`std::process::Command`], whose subprocess-spawning methods always set the `CreateProcess` parameter `bInheritHandles` to true.
///
/// On Unix-like platforms, file descriptors (including but not limited to sockets) can be inherited, but only if the `CLOEXEC` flag is not set. Rust socket libraries always create sockets with the `CLOEXEC` flag set, so this function clears it using the `fcntl` system call.
#[cfg(any(unix, windows))]
pub fn make_socket_inheritable(socket: &Socket) -> io::Result<RawSocket> {
	cfg_if! {
		if #[cfg(windows)] {
			compile_error!("need implementation here")
			// TODO: use SetHandleInformation to make handle inheritable
		}
		else {
			socket.set_cloexec(false)?;
			Ok(socket.as_raw_fd())
		}
	}
}
