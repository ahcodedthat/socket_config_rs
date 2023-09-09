use cfg_if::cfg_if;
use crate::errors::OpenSocketError;
use socket2::Socket;

#[cfg(any(unix, windows))]
use std::{
	fs,
	io,
	path::Path,
};

cfg_if! {
	if #[cfg(windows)] {
		use std::{
			mem,
			net::{Ipv4Addr, UdpSocket},
			os::windows::{
				fs::OpenOptionsExt,
				io::{AsRawHandle, AsRawSocket},
			},
			sync::Once,
		};
		use windows_sys::Win32::{
			Foundation::{
				HANDLE_FLAG_INHERIT,
				SetHandleInformation,
			},
			Storage::FileSystem::{
				FILE_ATTRIBUTE_REPARSE_POINT,
				FILE_FLAG_BACKUP_SEMANTICS,
				FILE_FLAG_OPEN_REPARSE_POINT,
				FILE_ATTRIBUTE_TAG_INFO,
				FileAttributeTagInfo,
				GetFileInformationByHandleEx,
			},
			System::SystemServices::IO_REPARSE_TAG_AF_UNIX,
		};
	}
	else if #[cfg(unix)] {
		use std::os::{
			fd::AsRawFd,
			unix::fs::FileTypeExt,
		};
	}
}

#[cfg(all(test, any(unix, windows)))]
use {
	assert_matches::assert_matches,
	once_cell::sync::Lazy,
	std::path::PathBuf,
};

cfg_if! {
	if #[cfg(windows)] {
		pub(crate) use std::os::windows::io::RawSocket;
	}
	else {
		pub(crate) use std::os::fd::RawFd as RawSocket;
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

/// Mark a socket as inheritable (or not), so that a child process will (or will not) inherit it.
/// 
/// If the `inheritable` parameter is true, the socket is made inheritable; otherwise, it is made non-inheritable.
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
/// Rust socket libraries, including [the standard library][std], typically create non-inheritable sockets. When spawning a subprocess from a Rust program (such as an integration test) that is to inherit a socket from the parent process, the socket must be made inheritable first.
///
/// On Windows, handles (including but not limited to sockets) [can be inherited](https://learn.microsoft.com/en-us/windows/win32/sysinfo/handle-inheritance), but two conditions must be met: the handle's `bInheritHandle` attribute must be set to true, and when the child process is created, the [`CreateProcess`](https://learn.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createprocessa) parameter `bInheritHandles` must be set to true. This function fulfills the former requirement using the [`SetHandleInformation`](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-sethandleinformation) function. The latter requirement is already fulfilled by [`std::process::Command`], whose subprocess-spawning methods always set the `CreateProcess` parameter `bInheritHandles` to true.
///
/// On Unix-like platforms, file descriptors (including but not limited to sockets) can be inherited, but only if the `CLOEXEC` flag is not set. Rust socket libraries always create sockets with the `CLOEXEC` flag set. This function sets or clears it using the `fcntl` system call.
#[cfg(any(unix, windows))]
pub fn make_socket_inheritable(
	socket: &Socket,
	inheritable: bool,
) -> io::Result<RawSocket> {
	cfg_if! {
		if #[cfg(windows)] {
			let handle = socket.as_raw_socket();

			let success = unsafe {
				// Safety: `handle` is a valid handle. `HANDLE_FLAG_INHERIT` is a valid handle flag. 0 and `HANDLE_FLAG_INHERIT` are both valid values for the third parameter.
				SetHandleInformation(
					handle as _,
					HANDLE_FLAG_INHERIT,
					match inheritable {
						true => HANDLE_FLAG_INHERIT,
						false => 0,
					},
				)
			};

			if success == 0 {
				Err(io::Error::last_os_error())
			}
			else {
				Ok(handle)
			}
		}
		else {
			socket.set_cloexec(!inheritable)?;
			Ok(socket.as_raw_fd())
		}
	}
}

/// Checks whether the file at the given `path` is a Unix-domain socket.
/// 
/// Unix-like platforms and Windows have very different ways of checking if a file is a Unix-domain socket. This utility function abstracts over those differences.
/// 
/// 
/// # Errors
/// 
/// Any I/O error raised by the operating system call used to get the file's status (). If the error's [`std::io::Error::kind`] is [`std::io::ErrorKind::NotFound`], then there is no 
/// 
/// 
/// # Availability
/// 
/// Unix-like platforms and Windows only.
#[cfg(any(unix, windows))]
pub fn is_unix_socket(path: &Path) -> io::Result<bool> {
	cfg_if! {
		if #[cfg(windows)] {
			// On Windows, Unix-domain sockets appear in the file system as a kind of reparse point. The Rust standard library has code to figure out what kind of reparse point the file is, but it doesn't actually expose that information, so we're going to have to do it ourselves.

			// First of all, we need to open the socket as a file. If we request zero desired access, then opening should succeed, even if the file is exclusively locked. There are some special system files like `hiberfil.sys` where this will still fail, but none of them are Unix-domain sockets, so that's not an issue here.
			let file: fs::File =
				fs::OpenOptions::new()
				.access_mode(0)
				.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
				.open(path)?;

			// Here's where the file attributes (including reparse tag) will be stored.
			let mut file_attrs: FILE_ATTRIBUTE_TAG_INFO = unsafe {
				// Safety: All zeroes is a valid instance of this type.
				mem::zeroed()
			};

			let file_attrs_len = mem::size_of_val(&file_attrs).try_into().unwrap();

			// Get the file attributes.
			let get_result = unsafe {
				// Safety:
				//
				// * `file.as_raw_handle()` is a valid file handle.
				// * `FileAttributeTagInfo` is a valid `FILE_INFO_BY_HANDLE_CLASS`.
				// * `file_attrs` is a valid `FILE_ATTRIBUTE_TAG_INFO`, which is what `GetFileInformationByHandleEx` expects the pointer to point to when getting `FileAttributeTagInfo`, and `file_attrs_len` is its length.
				GetFileInformationByHandleEx(
					file.as_raw_handle() as _,
					FileAttributeTagInfo,
					&mut file_attrs as *mut FILE_ATTRIBUTE_TAG_INFO as *mut _,
					file_attrs_len,
				)
			};

			// Bail on error.
			if get_result == 0 {
				return Err(io::Error::last_os_error());
			}

			// Now then, we want to know whether this file is a reparse point, and if so, whether it is a Unix-domain socket.
			let is_unix_socket: bool =
				(file_attrs.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 &&
				file_attrs.ReparseTag == IO_REPARSE_TAG_AF_UNIX;

			// And that's it.
			Ok(is_unix_socket)
		}
		else {
			// On Unix-like systems, the Rust standard library already exposes the information we need, so just use that.
			fs::symlink_metadata(path)
			.map(|metadata| metadata.file_type().is_socket())
		}
	}
}

#[cfg(any(unix, windows))]
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

#[cfg(all(test, any(unix, windows)))]
pub(crate) static TEST_SCRATCH: Lazy<PathBuf> = Lazy::new(|| {
	let path: PathBuf = ["target", "lib-test-scratch"].into_iter().collect();

	// Try to remove the scratch folder, but ignore errors in doing so.
	let _ = fs::remove_dir_all(&path);

	fs::create_dir(&path)
	.expect("couldn't create test scratch folder");

	path
});

/// Utility function that triggers initialization the system socket API.
/// 
/// 
/// # Availability
/// 
/// All platforms, but this function does nothing except on Windows.
/// 
/// On Windows, the socket API must be initialized before use, with the `WSAStartup` function. This utility function indirectly triggers a call to that function.
#[cfg_attr(not(windows), inline(always))]
pub(crate) fn startup_socket_api() {
	#[cfg(windows)] {
		static ONCE: Once = Once::new();

		ONCE.call_once(|| {
			let _ = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16));
		});
	}
}
