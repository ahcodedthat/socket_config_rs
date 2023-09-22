use anyhow::Context as _;
use socket_config::{
	convert::{
		AnyTokioListener,
		AnyTokioStream,
	},
	SocketAddr,
	SocketAppOptions,
	SocketUserOptions,
};
use socket2::Socket;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A simple echo server that listens on a stream socket and echoes back all bytes to clients, incremented by one.
#[derive(clap::Parser)]
struct CommandLine {
	#[command(flatten)]
	options: SocketUserOptions,

	socket: SocketAddr,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
	// Parse the command line options.
	let command_line = <CommandLine as clap::Parser>::parse();

	// Set up the `SocketAppOptions`. In this example, we'll use the defaults, except for an explicit default port of 27910.
	let mut socket_app_options = SocketAppOptions::new(socket2::Type::STREAM);
	socket_app_options.default_port = Some(27910);

	// Open the socket.
	let socket: Socket = socket_config::open(
		&command_line.socket,
		&socket_app_options,
		&command_line.options,
	).context("couldn't open socket")?;

	// Set up the socket for use with Tokio.
	let socket: AnyTokioListener =
		socket.try_into()
		.context("couldn't configure socket for Tokio")?;

	// Start accepting connections.
	loop {
		let (connection, _): (AnyTokioStream, socket2::SockAddr) =
			socket.accept().await
			.context("couldn't accept a connection")?;

		tokio::task::spawn(echo(connection));
	}
}

async fn echo(mut connection: AnyTokioStream) {
	let mut buf = [0u8; 1024];

	loop {
		// Read some bytes from the client.
		let bytes_read = match connection.read(&mut buf).await {
			Ok(0) => break,
			Ok(n) => n,
			Err(error) => {
				eprintln!("Error reading from client: {error}!");
				break
			}
		};

		// Take a slice of the buffer, containing just the bytes that were read.
		let buf = &mut buf[..bytes_read];

		// Increment each byte by one.
		for byte in &mut *buf {
			*byte = byte.wrapping_add(1);
		}

		// Echo the bytes back.
		if let Err(error) = connection.write_all(buf).await {
			eprintln!("Error writing to client: {error}!");
			break;
		}
	}
}
