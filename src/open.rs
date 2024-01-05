use crate::{
	cleanup_unix_path_socket,
	errors::OpenSocketError,
	SocketAppOptions,
	SocketAddr,
	SocketUserOptions,
	sys,
	util::*,
};
use socket2::Socket;
use std::{
	fs,
	path::Path,
};

#[cfg(doc)]
use crate::convert::AnyStdSocket;

#[cfg(all(doc, feature = "tokio"))]
use crate::convert::AnyTokioListener;

/// `socket_config` entry point. Opens a socket (or claims an inherited one), according to the given address and options.
///
/// Three parameters are needed:
///
/// 1. A [`SocketAddr`], indicating which address to bind the socket to, or which inherited socket to use. This is taken from the user, typically from a command-line parameter or configuration file.
/// 2. [`SocketAppOptions`], which sets things like [socket type][SocketAppOptions::type] (such as stream or datagram) and [default port number][SocketAppOptions::default_port]. These are hard-coded into your application.
/// 3. [`SocketUserOptions`], which sets things like [Unix socket permissions][SocketUserOptions::unix_socket_permissions] and [whether to allow IPv4 connections to an IPv6 socket][SocketUserOptions::ip_socket_v6_only]. These are also taken from the user, same as the `SocketAddr`.
///
/// The return value is a [`socket2::Socket`]. This can be used several ways:
///
/// * Directly, for blocking I/O. (When doing this, be sure to retry operations that fail with [`std::io::ErrorKind::Interrupted`]; unlike the Rust standard library, the methods of `socket2::Socket` do not automatically retry.)
#[cfg_attr(feature = "tokio", doc = r#"
* Converted to [`AnyTokioListener`]. This accepts connections on a TCP or Unix-domain listening socket using [`tokio`] non-blocking I/O."#)]
/// * Converted to a standard library socket type like [`std::net::TcpListener`]. To do that, first convert it to [`AnyStdSocket`] using its `TryFrom<socket2::Socket>` implementation, and then extract the intended standard library socket type from it.
///
///
/// # Inherited sockets
///
/// This function duplicates inherited sockets (`dup` on Unix-like platforms; `WSADuplicateSocket` on Windows), rather than directly wrapping them in `Socket`. The original inherited socket is not closed, even when the returned `Socket` is dropped.
///
/// That way, it is possible to open, close, and reopen the same `SocketAddr`, regardless of whether it is inherited. The original inherited socket is left open, and will simply be duplicated again.
///
///
/// # Example
///
/// ```no_run
/// use socket2::Socket;
/// use std::io::Write;
///
/// # fn example_fn() -> std::io::Result<()> {
/// // The socket address and user options are specified by the user of your
/// // application. Usually they come from command-line options or a
/// // configuration file, but it's up to you to decide how to obtain them.
/// let socket_addr: socket_config::SocketAddr;
/// let user_options: socket_config::SocketUserOptions;
/// # socket_addr = unimplemented!();
/// # user_options = unimplemented!();
///
/// // The application options are hard-coded into your application. In this
/// // example, we'll set a default port number.
/// let mut app_options = socket_config::SocketAppOptions::new(socket2::Type::STREAM);
/// app_options.default_port = Some(27910);
///
/// // Open the listening socket.
/// let listen_socket: Socket = socket_config::open(
/// 	&socket_addr,
/// 	&app_options,
/// 	&user_options,
/// )?;
///
/// // Accept a connection.
/// let (mut connected_socket, client_addr): (Socket, socket2::SockAddr) = loop {
/// 	let result = listen_socket.accept();
///
/// 	// On some platforms, `accept` can fail due to the system call being
/// 	// interrupted. When it does, just try again.
/// 	if matches!(result, Err(e) if e.kind() == std::io::ErrorKind::Interrupted) {
/// 		continue;
/// 	}
///
/// 	break result
/// }?;
///
/// // Say hello.
/// connected_socket.write_all(b"Hello, world!\n")?;
/// #
/// # Ok(())
/// # }
/// ```
pub fn open(
	address: &SocketAddr,
	app_options: &SocketAppOptions,
	user_options: &SocketUserOptions,
) -> Result<Socket, OpenSocketError> {
	let orig_address = address;

	let open_new = |address: socket2::SockAddr| -> Result<Socket, OpenSocketError> {
		// Is this a path-based Unix-domain socket? (We can't use `socket2::SockAddr::as_pathname` here, because it isn't available on Windows.)
		let unix_socket_path: Option<&Path> = match orig_address {
			SocketAddr::Unix { path } => Some(path),
			_ => None,
		};

		// Prepare any Unix security attributes, if relevant.
		#[cfg(unix)]
		crate::unix_security::prepare(user_options, unix_socket_path)?;

		// Check if we need to `listen` on this socket, and if so, what the backlog should be.
		let listen_backlog: Option<_> = {
			if app_options.listen && app_options.r#type == socket2::Type::STREAM {
				Some(
					user_options.listen_socket_backlog
					.unwrap_or(SocketUserOptions::DEFAULT_LISTEN_SOCKET_BACKLOG)
				)
			}
			else {
				check_inapplicable(user_options.listen_socket_backlog, "listen_socket_backlog")?;
				None
			}
		};

		// Create the new socket.
		let mut socket: socket2::Socket =
			Socket::new(address.domain(), app_options.r#type, app_options.protocol)
			.map_err(|error| OpenSocketError::CreateSocket { error })?;

		if let Some(socket_path) = unix_socket_path {
			// Clean up the previous socket, if desired and applicable.
			if !user_options.unix_socket_no_unlink {
				cleanup_unix_path_socket(socket_path)?;
			}

			// Create any needed parent folders.
			if let Some(socket_parent_path) = socket_path.parent() {
				fs::create_dir_all(socket_parent_path)
				.map_err(|error| OpenSocketError::MkdirParents { error })?;
			}
		}

		// Set socket options.

		// `SO_REUSEADDR` is only set for TCP listening sockets on non-Windows platforms, same as the Rust standard library. See explanation: https://github.com/rust-lang/rust/blob/1b225414f325593f974c6b41e671a0a0dc5d7d5e/library/std/src/sys_common/net.rs#L395
		#[cfg(not(windows))]
		if listen_backlog.is_some() && is_socket_probably_tcp(&socket, &address, app_options) {
			socket.set_reuse_address(true)
			.map_err(|error| OpenSocketError::SetSockOpt {
				option: "SO_REUSEADDR",
				error,
			})?;
		}

		#[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
		if user_options.ip_socket_reuse_port {
			socket.set_reuse_port(true)
			.map_err(|error| OpenSocketError::SetSockOpt {
				option: "SO_REUSEPORT",
				error,
			})?;
		}

		if user_options.ip_socket_v6_only {
			socket.set_only_v6(true)
			.map_err(|error| OpenSocketError::SetSockOpt {
				option: "IPV6_V6ONLY",
				error,
			})?;
		}

		// Bind the socket to its address.
		if let Some(before_bind) = &app_options.before_bind {
			before_bind(&mut socket)
			.map_err(OpenSocketError::BeforeBind)?;
		}

		socket.bind(&address)
		.map_err(|error| OpenSocketError::Bind { error })?;

		// Set security attributes on the socket, if applicable and configured.
		#[cfg(unix)]
		crate::unix_security::apply(user_options, &socket, unix_socket_path)?;

		// Set the socket to listening, if applicable and configured.
		if let Some(listen_backlog) = listen_backlog {
			socket.listen(listen_backlog)
			.map_err(|error| OpenSocketError::Listen { error })?;
		}

		Ok(socket)
	};

	let inherit = |socket: sys::RawSocket| -> Result<Socket, OpenSocketError> {
		sys::startup_socket_api();

		#[cfg(unix)] {
			check_inapplicable(user_options.unix_socket_permissions.as_ref(), "unix_socket_permissions")?;
			check_inapplicable(user_options.unix_socket_owner.as_ref(), "unix_socket_owner")?;
			check_inapplicable(user_options.unix_socket_group.as_ref(), "unix_socket_group")?;
		}

		#[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
		check_inapplicable_bool(user_options.ip_socket_reuse_port, "ip_socket_reuse_port")?;

		check_inapplicable_bool(user_options.ip_socket_v6_only, "ip_socket_v6_only")?;
		check_inapplicable(user_options.listen_socket_backlog, "listen_socket_backlog")?;

		// Safety: Inherited socket file descriptors/handles are supplied by the user or by an operating system API. Either way, we assume they're valid.
		let socket: sys::BorrowedSocket<'_> = unsafe {
			sys::BorrowedSocket::borrow_raw(socket)
		};

		let socket: sys::OwnedSocket =
			socket.try_clone_to_owned()
			.map_err(|error| OpenSocketError::DupInherited { error })?;

		let socket: Socket = Socket::from(socket);

		let actual_type: socket2::Type =
			socket.r#type()
			.map_err(|error| OpenSocketError::CheckInheritedSocket { error })?;

		if actual_type != app_options.r#type {
			return Err(OpenSocketError::InheritWrongType {
				expected: app_options.r#type,
				actual: actual_type,
			});
		}

		// Check whether the socket is in a listening state, if the platform supports that. Ignore errors from the socket API; the only likely error is that the operating system is an old version that doesn't support this check.
		#[cfg(any(
			target_os = "aix",
			target_os = "android",
			target_os = "freebsd",
			target_os = "fuchsia",
			target_os = "linux",
		))]
		if actual_type == socket2::Type::STREAM {
		if let Ok(actual_listen) = socket.is_listener() {
		if app_options.listen != actual_listen {
			return Err(match app_options.listen {
				true => OpenSocketError::InheritedIsNotListening,
				false => OpenSocketError::InheritedIsListening,
			});
		}}}

		Ok(socket)
	};

	let socket: Socket = match address {
		SocketAddr::Ip { addr, port } => {
			let port: u16 =
				(*port)
				.or(app_options.default_port)
				.ok_or(OpenSocketError::PortRequired)?;

			let addr = std::net::SocketAddr::new(*addr, port);

			open_new(addr.into())?
		}

		SocketAddr::Unix { path } => {
			let address =
				socket2::SockAddr::unix(path)
				.map_err(|error| OpenSocketError::InvalidUnixPath { error })?;

			open_new(address)?
		},

		SocketAddr::Inherit { socket } => inherit(*socket)?,

		SocketAddr::InheritStdin {} => {
			let socket: sys::RawSocket = sys::get_stdin_as_socket().map_err(|error| -> OpenSocketError {
				match error {
					// This can only fail on Windows.
					#[cfg(windows)]
					error @ std::io::Error { .. } => OpenSocketError::WindowsGetStdin { error },
				}
			})?;

			inherit(socket)?
		},

		#[cfg(not(windows))]
		SocketAddr::SystemdNumeric { socket } => {
			if
				*socket >= sys::SD_LISTEN_FDS_START ||
				sys::SD_LISTEN_FDS_END.is_some_and(|sd_listen_fds_end| *socket <= sd_listen_fds_end)
			{
				inherit(*socket)?
			}
			else {
				return Err(OpenSocketError::InvalidSystemdFd)
			}
		},
	};

	Ok(socket)
}
