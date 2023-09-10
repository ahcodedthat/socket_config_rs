use crate::convert::SocketState;
use socket2::Socket;
use std::{
	ffi::c_int,
	fs,
	mem,
	net::{Ipv4Addr, UdpSocket},
	io,
	os::windows::{
		fs::OpenOptionsExt,
		io::{AsRawHandle, AsRawSocket},
	},
	path::Path,
	sync::Once,
};
use windows_sys::Win32::{
	Foundation::{
		HANDLE_FLAG_INHERIT,
		INVALID_HANDLE_VALUE,
		SetHandleInformation,
	},
	Networking::WinSock::{
		getsockopt,
		SO_ACCEPTCONN,
		SO_PROTOCOL_INFOW,
		SOL_SOCKET,
		WSAPROTOCOL_INFOW,
	},
	Storage::FileSystem::{
		FILE_ATTRIBUTE_REPARSE_POINT,
		FILE_FLAG_BACKUP_SEMANTICS,
		FILE_FLAG_OPEN_REPARSE_POINT,
		FILE_ATTRIBUTE_TAG_INFO,
		FileAttributeTagInfo,
		GetFileInformationByHandleEx,
	},
	System::Console::{GetStdHandle, STD_INPUT_HANDLE},
	System::SystemServices::IO_REPARSE_TAG_AF_UNIX,
};

pub use std::os::windows::io::{
	BorrowedSocket,
	OwnedSocket,
	RawSocket,
};

pub fn make_socket_inheritable(
	socket: &Socket,
	inheritable: bool,
) -> io::Result<RawSocket> {
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

pub fn is_unix_socket(path: &Path) -> io::Result<bool> {
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

pub fn startup_socket_api() {
	static ONCE: Once = Once::new();

	ONCE.call_once(|| {
		let _ = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16));
	});
}

pub fn get_stdin_as_socket() -> io::Result<RawSocket> {
	let maybe_socket = unsafe {
		// Safety: `STD_INPUT_HANDLE` is a valid standard device identifier.
		GetStdHandle(STD_INPUT_HANDLE)
	};

	if maybe_socket == INVALID_HANDLE_VALUE {
		return Err(io::Error::last_os_error());
	}

	Ok(maybe_socket as RawSocket)
}

pub(crate) fn get_socket_state(socket: &Socket) -> io::Result<SocketState> {
	let mut protocol_info: WSAPROTOCOL_INFOW = unsafe {
		// Safety: all zeroes is a valid instance of the `WSAPROTOCOL_INFOW` type.
		mem::zeroed()
	};

	let mut protocol_info_len: c_int = mem::size_of_val(&protocol_info).try_into().unwrap();

	let getsockopt_result = unsafe {
		// Safety:
		//
		// * `socket.as_raw_socket()` is a valid socket handle.
		// * `SOL_SOCKET` AND `SO_PROTOCOL_INFOW` are a valid socket option level and socket option in that level, respectively.
		// * `protocol_info` is a valid `WSAPROTOCOL_INFOW`, which is the data type that `SO_PROTOCOL_INFOW` expects a pointer to, and `protocol_info_len` is its length.
		getsockopt(
			socket.as_raw_socket() as _,
			SOL_SOCKET,
			SO_PROTOCOL_INFOW,
			&mut protocol_info as *mut WSAPROTOCOL_INFOW as *mut _,
			&mut protocol_info_len,
		)
	};

	if getsockopt_result != 0 {
		return Err(io::Error::last_os_error());
	}

	let r#type = socket2::Type::from(protocol_info.iSocketType);
	let protocol = Some(socket2::Protocol::from(protocol_info.iProtocol));

	let mut is_listening_dword: u32 = 0;
	let mut is_listening_dword_len: c_int = mem::size_of_val(&is_listening_dword).try_into().unwrap();

	let getsockopt_result = unsafe {
		// Safety:
		//
		// * `socket.as_raw_socket()` is a valid socket handle.
		// * `SOL_SOCKET` AND `SO_ACCEPTCONN` are a valid socket option level and socket option in that level, respectively.
		// * `is_listening_dword` is a valid `DWORD`, which is the data type that `SO_ACCEPTCONN` expects a pointer to, and `is_listening_dword_len` is its length.
		getsockopt(
			socket.as_raw_socket() as _,
			SOL_SOCKET,
			SO_ACCEPTCONN,
			&mut is_listening_dword as *mut u32 as *mut _,
			&mut is_listening_dword_len,
		)
	};

	if getsockopt_result != 0 {
		return Err(io::Error::last_os_error());
	}

	let is_listening = Some(is_listening_dword != 0);

	Ok(SocketState { r#type, protocol, is_listening })
}
