use anyhow::Context as _;
use socket_config::{
	SocketAddr,
	SocketAppOptions,
	SocketUserOptions,
};
use socket2::Socket;
use std::io::Write;

/// A simple chargen server that listens on a stream socket, accepts one connection, and endlessly sends characters to the client, like the classic CHARGEN service.
#[derive(clap::Parser)]
struct CommandLine {
	#[command(flatten)]
	options: SocketUserOptions,

	socket: SocketAddr,
}

fn main() -> anyhow::Result<()> {
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

	// Wait for and accept a connection.
	let (mut connection, _): (Socket, _) =
		socket.accept()
		.context("couldn't accept a connection")?;

	// Close the listening socket once a connection is established.
	drop(socket);

	// Generate the characters we're going to send to the client: everything in the ASCII range.
	let chars: Vec<u8> = (b' '..b'~').into_iter().collect();

	// Send characters repeatedly until the client disconnects.
	loop {
		match connection.write_all(&chars) {
			Ok(()) => {}

			Err(error) if error.kind() == std::io::ErrorKind::WriteZero => {
				// Client disconnected.
				break;
			}

			Err(error) => {
				return Err(anyhow::format_err!(error).context("couldn't send characters to client"));
			}
		}
	}

	Ok(())
}
