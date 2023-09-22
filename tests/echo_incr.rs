use escargot::CargoBuild;
use socket2::Socket;
use std::{
	io::{Read, Write},
	mem::MaybeUninit,
	net::{Ipv4Addr, Shutdown},
	process::Child,
	thread,
};

#[cfg(unix)]
use std::{
	fs,
	os::unix::fs::MetadataExt,
};

const TEST_MSG_LEN: usize = 13;
const TEST_MSG: &[u8; TEST_MSG_LEN] = b"Hello, world!";
const TEST_MSG_MODIFIED: &[u8; TEST_MSG_LEN] = b"Ifmmp-!xpsme\"";

#[test]
fn inherit() {
	let socket_addr: socket2::SockAddr =
		std::net::SocketAddrV4::new(
			Ipv4Addr::LOCALHOST,
			0,
		)
		.into();

	let socket = Socket::new(socket_addr.domain(), socket2::Type::STREAM, None).unwrap();
	socket.bind(&socket_addr).unwrap();
	socket.listen(128).unwrap();

	let socket_addr: socket2::SockAddr = socket.local_addr().unwrap();
	let socket_handle = socket_config::make_socket_inheritable(&socket, true).unwrap();

	let child_process = KillOnDrop(
		CargoBuild::new()
		.example("echo_incr")
		.features("clap tokio")
		.run()
		.unwrap()
		.command()
		.arg(format!("fd:{socket_handle}"))
		.spawn()
		.unwrap()
	);

	drop(socket);

	let socket = Socket::new(socket_addr.domain(), socket2::Type::STREAM, None).unwrap();
	socket.connect(&socket_addr).unwrap();
	echo_incr_client(socket);

	drop(child_process);
}

#[test]
fn unix() {
	// Do this twice, in order to verify that deleting and replacing the Unix socket works.
	for _ in 0..=1 {
		let app_options = socket_config::SocketAppOptions::new(socket2::Type::STREAM);

		#[cfg_attr(not(unix), allow(unused_mut))]
		let mut user_options = socket_config::SocketUserOptions::default();

		#[cfg(unix)] {
			user_options.unix_socket_permissions = Some(nix::sys::stat::Mode::from_bits(0o660).unwrap());
		}

		let (server_addr, server_thread) = echo_incr_server(
			&"./target/test.socket".parse().unwrap(),
			&app_options,
			&user_options
		);

		#[cfg(unix)] {
			let perms = fs::metadata("./target/test.socket").unwrap().mode() & 0o7777;
			assert_eq!(perms, 0o660);
		}

		let socket = Socket::new(server_addr.domain(), app_options.r#type, app_options.protocol).unwrap();
		socket.connect(&server_addr).unwrap();
		echo_incr_client(socket);

		server_thread.join().unwrap();
	}
}

#[test]
fn udp() {
	let mut app_options = socket_config::SocketAppOptions::new(socket2::Type::DGRAM);
	app_options.protocol = Some(socket2::Protocol::UDP);
	app_options.default_port = Some(0);

	let user_options = socket_config::SocketUserOptions::default();

	let (server_addr, server_thread) = echo_incr_server(
		&"127.0.0.1".parse().unwrap(),
		&app_options,
		&user_options
	);

	let socket = Socket::new(server_addr.domain(), app_options.r#type, app_options.protocol).unwrap();
	socket.connect(&server_addr).unwrap();
	echo_incr_client(socket);

	server_thread.join().unwrap();
}

/// Connects to the [`echo_incr_server`] and checks if it echoes correctly. Also works with the `echo_incr` example program running in a child process. Expects `socket` to already be connected.
fn echo_incr_client(mut socket: Socket) {
	let mut actual_input = [0u8; TEST_MSG_LEN];

	socket.write_all(TEST_MSG).unwrap();
	socket.flush().unwrap();
	socket.shutdown(Shutdown::Write).unwrap();

	socket.read_exact(&mut actual_input).unwrap();

	assert_eq!(&actual_input, TEST_MSG_MODIFIED);
}

/// Runs a server much like the `echo_incr` example program, on a separate thread. Also works for datagram sockets.
///
/// It only accepts one connection (if a connection-oriented socket is used) and only receives and echoes one message [`TEST_MSG_LEN`] bytes long before terminating.
///
/// This function does not return until after the server socket has been opened, so it should be safe to connect to it immediately thereafter.
fn echo_incr_server(
	address: &socket_config::SocketAddr,
	app_options: &socket_config::SocketAppOptions,
	user_options: &socket_config::SocketUserOptions,
) -> (socket2::SockAddr, thread::JoinHandle<()>) {
	let mut socket: Socket = socket_config::open(
		address,
		app_options,
		user_options,
	).unwrap();

	let need_accept: bool = app_options.listen && app_options.r#type == socket2::Type::STREAM;

	let address = socket.local_addr().unwrap();

	let thread = thread::spawn(move || {
		if need_accept {
			(socket, _) = socket.accept().unwrap();
		}

		let mut buf = [MaybeUninit::<u8>::uninit(); TEST_MSG_LEN];

		let (bytes_read, client_addr) = socket.recv_from(&mut buf).unwrap();

		assert_eq!(bytes_read, TEST_MSG_LEN);
		let buf: &mut [u8; TEST_MSG_LEN] = unsafe {
			&mut *(
				&mut buf
				as *mut [MaybeUninit<u8>; TEST_MSG_LEN]
				as *mut [u8; TEST_MSG_LEN]
			)
		};

		for byte in &mut *buf {
			*byte = byte.wrapping_add(1);
		}

		socket.send_to(buf, &client_addr).unwrap();
	});

	(address, thread)
}

#[derive(derive_more::Deref)]
struct KillOnDrop(Child);
impl Drop for KillOnDrop {
	fn drop(&mut self) {
		let _ = self.0.kill();
		let _ = self.0.wait();
	}
}
