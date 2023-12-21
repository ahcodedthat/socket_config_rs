use cfg_if::cfg_if;
use crate::convert::SocketState;
use once_cell::sync::Lazy;
use socket2::Socket;
use std::{
	convert::Infallible,
	env,
	fs,
	io,
	os::unix::fs::FileTypeExt,
	path::Path,
	process,
};

pub use std::os::fd::{
	AsRawFd as AsRawSocket,
	BorrowedFd as BorrowedSocket,
	OwnedFd as OwnedSocket,
	RawFd as RawSocket,
};

type Pid = u32;

pub const SD_LISTEN_FDS_START: RawSocket = 3;

pub static SD_LISTEN_FDS_END: Lazy<Option<RawSocket>> = Lazy::new(|| {
	let expected_pid: Pid =
		env::var("LISTEN_PID")
		.ok()?
		.parse()
		.ok()?;

	let actual_pid: Pid = process::id();

	if actual_pid != expected_pid {
		return None;
	}

	let total_listen_fds =
		env::var("LISTEN_FDS")
		.ok()?
		.parse()
		.ok()
		.filter(|count| *count >= 1)?;

	let listen_fds_end = SD_LISTEN_FDS_START.saturating_add(total_listen_fds);

	Some(listen_fds_end)
});

pub fn make_socket_inheritable(
	socket: &Socket,
	inheritable: bool,
) -> io::Result<RawSocket> {
	socket.set_cloexec(!inheritable)?;
	Ok(socket.as_raw_fd())
}

pub fn is_unix_socket(path: &Path) -> io::Result<bool> {
	fs::symlink_metadata(path)
	.map(|metadata| metadata.file_type().is_socket())
}

pub fn startup_socket_api() {}

pub fn get_stdin_as_socket() -> Result<RawSocket, Infallible> {
	Ok(0)
}

pub(crate) fn get_socket_state(socket: &Socket) -> io::Result<SocketState> {
	let r#type = socket.r#type()?;

	cfg_if! {
		if #[cfg(any(
			target_os = "android",
			target_os = "freebsd",
			target_os = "fuchsia",
			target_os = "linux",
		))] {
			let protocol = socket.protocol()?;
		}
		else {
			let protocol = None;
		}
	}

	cfg_if! {
		if #[cfg(any(
			target_os = "aix",
			target_os = "android",
			target_os = "freebsd",
			target_os = "fuchsia",
			target_os = "linux",
		))] {
			let is_listening = Some(socket.is_listener()?);
		}
		else {
			let is_listening = None;
		}
	}

	Ok(SocketState { r#type, protocol, is_listening })
}

pub fn as_raw_socket(socket: &impl AsRawSocket) -> RawSocket {
	socket.as_raw_fd()
}
