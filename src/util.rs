use crate::{
	errors::OpenSocketError,
	sys,
};
use socket2::Socket;
use std::{
	io,
	path::Path,
};

#[cfg(test)]
use {
	assert_matches::assert_matches,
	once_cell::sync::Lazy,
	std::{
		fs,
		path::PathBuf,
	},
};

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

/// Mark a socket as inheritable (or not), so that a child process will (or will not) inherit it.
///
/// If the `inheritable` parameter is true, the socket is made inheritable; otherwise, it is made non-inheritable.
///
/// If this function is successful, the return value is the file descriptor or handle to pass to the child process.
///
///
/// # Background
///
/// Rust socket libraries, including [the standard library][std], typically create non-inheritable sockets. When spawning a subprocess from a Rust program (such as an integration test) that is to inherit a socket from the parent process, the socket must be made inheritable first.
///
/// On Windows, handles (including but not limited to sockets) [can be inherited](https://learn.microsoft.com/en-us/windows/win32/sysinfo/handle-inheritance), but two conditions must be met: the handle's `bInheritHandle` attribute must be set to true, and when the child process is created, the [`CreateProcess`](https://learn.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createprocessa) parameter `bInheritHandles` must be set to true. This function fulfills the former requirement using the [`SetHandleInformation`](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-sethandleinformation) function. The latter requirement is already fulfilled by [`std::process::Command`], whose subprocess-spawning methods always set the `CreateProcess` parameter `bInheritHandles` to true.
///
/// On Unix-like platforms, file descriptors (including but not limited to sockets) can be inherited, but only if the `CLOEXEC` flag is not set. Rust socket libraries always create sockets with the `CLOEXEC` flag set. This function sets or clears it using the `fcntl` system call.
pub fn make_socket_inheritable(
	socket: &Socket,
	inheritable: bool,
) -> io::Result<sys::RawSocket> {
	sys::make_socket_inheritable(socket, inheritable)
}

/// Checks whether the file at the given `path` is a Unix-domain socket.
///
/// Unix-like platforms and Windows have very different ways of checking if a file is a Unix-domain socket. This utility function abstracts over those differences.
///
///
/// # Errors
///
/// Any I/O error raised by the operating system call used to get the file's status (). If the error's [`std::io::Error::kind`] is [`std::io::ErrorKind::NotFound`], then there is no
pub fn is_unix_socket(path: &Path) -> io::Result<bool> {
	sys::is_unix_socket(path)
}

#[test]
fn test_is_unix_socket() {
	let socket_path: PathBuf = TEST_SCRATCH.join("test1.socket");

	// First try creating a folder at that path. `is_unix_socket` should return `Ok(false)` for that.
	let _ = fs::remove_file(&socket_path);

	fs::create_dir(&socket_path).unwrap();

	assert_matches!(
		is_unix_socket(&socket_path),
		Ok(false)
	);

	// Try removing the folder. `is_unix_socket` should now return an error with `io::ErrorKind::NotFound`.
	fs::remove_dir(&socket_path).unwrap();

	assert_matches!(
		is_unix_socket(&socket_path),
		Err(error)
		if error.kind() == io::ErrorKind::NotFound
	);

	// Try creating an actual socket. `is_unix_socket` should now return `Ok(true)`.
	let socket = socket2::Socket::new(
		socket2::Domain::UNIX,
		socket2::Type::STREAM,
		None,
	).unwrap();

	socket.bind(&socket2::SockAddr::unix(&socket_path).unwrap()).unwrap();

	assert_matches!(
		is_unix_socket(&socket_path),
		Ok(true)
	);

	// Make sure the socket isn't closed before `is_unix_socket` is called. I'm not sure if Windows deletes Unix-domain sockets once they're closed, and that isn't part of the test anyway.
	drop(socket);
}

#[cfg(test)]
pub(crate) static TEST_SCRATCH: Lazy<PathBuf> = Lazy::new(|| {
	let path: PathBuf = ["target", "lib-test-scratch"].into_iter().collect();

	// Try to remove the scratch folder, but ignore errors in doing so.
	let _ = fs::remove_dir_all(&path);

	fs::create_dir(&path)
	.expect("couldn't create test scratch folder");

	path
});
