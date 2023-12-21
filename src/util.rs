use crate::{
	errors::OpenSocketError,
	SocketAppOptions,
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
/// # Warning: Not Thread Safe
///
/// When a socket is marked as inheritable, it is inherited by *any and all* child processes spawned afterward, until the socket is closed or marked non-inheritable. In a multithreaded program that spawns child processes from more than one thread at the same time, this can result in a socket intended for one child process being also inherited by another child process.
///
/// It is possible to avoid this problem on Unix-like platforms, by making the socket inheritable after `fork` but before `exec`. (See [`std::os::unix::process::CommandExt::pre_exec`](https://doc.rust-lang.org/stable/std/os/unix/process/trait.CommandExt.html#tymethod.pre_exec) for how to do so with [`std::process::Command`].) A convenient API for doing that may be added to a future version of this library.
///
/// On Windows, however, it appears to be impossible to solve this problem. There is a way to control which sockets (or other handles) are inherited by a child process (the `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` attribute for the Windows API function [`UpdateProcThreadAttribute`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)), but all such handles must be marked as inheritable first, and unfortunately, child processes inherit all inheritable handles by default. In other words, `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` can only filter out inheritable handles when creating a child process; it cannot make a handle inheritable only by that specific child process.
///
///
/// # Availability
///
/// All platforms.
///
/// Socket inheritance on Windows only works if there are no [Layered Service Providers](https://en.wikipedia.org/wiki/Layered_Service_Provider) (LSPs) installed. In the past, LSPs were commonly used by Windows security software to inspect network traffic. LSPs were replaced by the [Windows Filtering Platform](https://en.wikipedia.org/wiki/Windows_Filtering_Platform) in Windows Vista and have been deprecated since Windows Server 2012, though as of 2022 they are still supported for backward compatibility reasons. Therefore, inherited sockets are likely but not guaranteed to work on modern Windows systems, and unlikely to work on legacy Windows systems.
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
	// TODO: Consider adding something that uses `CommandExt::pre_exec`, as described above, to make a socket inheritable after `fork` but before `exec`.
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

/// Gets a raw socket handle or file descriptor from the given socket-like object.
///
/// This is a simple portable abstraction over either `std::os::fd::AsRawFd::as_raw_fd` or `std::os::windows::io::AsRawSocket::as_raw_socket`, depending on the platform.
pub fn as_raw_socket(socket: &impl sys::AsRawSocket) -> sys::RawSocket {
	sys::as_raw_socket(socket)
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

#[cfg(not(windows))]
pub(crate) fn is_socket_probably_tcp(
	socket: &Socket,
	local_addr: &socket2::SockAddr,
	app_options: &SocketAppOptions,
) -> bool {
	if let Some(protocol) = app_options.protocol {
		return protocol == socket2::Protocol::TCP;
	}

	#[cfg(any(
		target_os = "android",
		target_os = "freebsd",
		target_os = "fuchsia",
		target_os = "linux",
	))]
	if let Ok(Some(protocol)) = socket.protocol() {
		return protocol == socket2::Protocol::TCP;
	}

	app_options.r#type == socket2::Type::STREAM && (local_addr.is_ipv4() || local_addr.is_ipv6())
}
