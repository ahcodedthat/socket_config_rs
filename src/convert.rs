//! Conversion to socket types besides [`socket2::Socket`], such as [`std::net::TcpListener`].

use cfg_if::cfg_if;
use socket2::Socket;
use std::io;

cfg_if! {
	if #[cfg(feature = "tokio")] {
		mod tokio;
		pub use self::tokio::*;
	}
}

/// A wrapper around all of the [standard library][std] socket types. On Unix-like platforms, that includes Unix-domain socket types.
///
/// There is also an `Other` variant, for sockets that don't fit any of the available standard library socket types.
///
///
/// # Example
///
/// The main way to use this is to open a [`socket2::Socket`] and then convert it into an `AnyStdSocket`, like this:
///
/// ```no_run
/// # use socket_config::convert::AnyStdSocket;
/// # use std::io;
/// # fn example_fn() -> io::Result<()> {
/// # let address: socket_config::SocketAddr = unimplemented!();
/// # let app_options: socket_config::SocketAppOptions<'static> = unimplemented!();
/// # let user_options: socket_config::SocketUserOptions = unimplemented!();
/// let socket: AnyStdSocket = socket_config::open(
/// 	&address,
/// 	&app_options,
/// 	&user_options,
/// )?.try_into()?;
/// # Ok(())
/// # }
/// ```
///
/// This opens a socket using [`open`][crate::open()] and then converts it into an `AnyStdSocket`.
///
///
/// # Stream socket handling
///
/// When converting a [stream-type][socket2::Type::STREAM] socket to this type, it is checked whether the socket is listening and whether it is connected.
///
/// Listening sockets are mapped to the `TcpListener` or `UnixListener` variant, and connected sockets are mapped to the `TcpStream` or `UnixStream` variant. Sockets that are neither listening nor connected are mapped to the `Other` variant.
///
/// **Warning:** On platforms other than AIX, Android, FreeBSD, Fuchsia, Linux, and Windows, it is not possible to check whether a socket is listening. It is therefore **assumed** on such platforms that a non-connected socket is a listening socket. Sockets that are neither listening nor connected will not be properly detected on such platforms.
///
///
/// # Transport protocol checking
///
/// When converting a socket to this type, if the socket's domain is [IPv4][socket2::Domain::IPV4] or [IPv6][socket2::Domain::IPV6], and if the platform is Android, FreeBSD, Fuchsia, Linux, or Windows, then the conversion checks the transport protocol of Internet-domain sockets, and maps the socket to the appropriate variant. If the transport protocol is neither TCP nor UDP, then the socket is mapped to the `Other` variant.
///
/// **Warning:** On platforms other than Android, FreeBSD, Fuchsia, Linux, and Windows, it is not possible to check the transport protocol of a socket. It is therefore **assumed** on such platforms that IPv4/IPv6-domain [stream][socket2::Type::STREAM] and [datagram][socket2::Type::DGRAM] sockets are TCP and UDP, respectively. This assumption is usually but not always correct; for example, an IPv4 stream-type socket is probably TCP, but it might be SCTP.
///
///
/// # Availability
///
/// All platforms, but the variants starting with `Unix` are only available on Unix-like platforms.
///
/// Unix-domain sockets on Windows are currently mapped to the `Other` variant, because the Rust standard library does not yet support them (see [Rust issue #56533](https://github.com/rust-lang/rust/issues/56533)). If and when such support is added, this library will need to be updated.
#[derive(Debug, derive_more::From)]
#[non_exhaustive]
pub enum AnyStdSocket {
	/// A TCP listening socket.
	///
	/// # Availability
	///
	/// All platforms.
	TcpListener(std::net::TcpListener),

	/// A connected TCP socket.
	///
	/// # Availability
	///
	/// All platforms.
	TcpStream(std::net::TcpStream),

	/// A UDP socket.
	///
	/// # Availability
	///
	/// All platforms.
	UdpSocket(std::net::UdpSocket),

	// ***FUTURE NOTE***: If Unix-domain sockets ever become available in the standard library on Windows, the special error message for `IntoTokioError::Inappropriate` must be removed! It currently checks for `AnyStdSocket::Other` and `socket2::Domain::UNIX`, and assumes that this combination is the result of Unix-domain sockets not being supported on Windows.

	/// A Unix-domain datagram socket.
	///
	/// # Availability
	///
	/// Unix-like platforms only. The standard library currently does not support Unix-domain sockets on Windows.
	#[cfg(unix)] UnixDatagram(std::os::unix::net::UnixDatagram),

	/// A Unix-domain [stream-type][socket2::Type::STREAM] listening socket.
	///
	/// # Availability
	///
	/// Unix-like platforms only. The standard library currently does not support Unix-domain sockets on Windows.
	#[cfg(unix)] UnixListener(std::os::unix::net::UnixListener),

	/// A connected Unix-domain [stream-type][socket2::Type::STREAM] socket.
	///
	/// # Availability
	///
	/// Unix-like platforms only. The standard library currently does not support Unix-domain sockets on Windows.
	#[cfg(unix)] UnixStream(std::os::unix::net::UnixStream),

	/// An unrecognized kind of socket.
	///
	/// When converting from [`socket2::Socket`] to `AnyStdSocket`, this variant is produced if there is no standard library mapping for the socket.
	///
	/// # Availability
	///
	/// All platforms.
	#[from(ignore)]
	Other(Socket),
}

impl TryFrom<Socket> for AnyStdSocket {
	type Error = io::Error;

	#[allow(clippy::needless_late_init)] // False positive. Clippy doesn't seem to see the `cfg_if!`.
	fn try_from(socket: Socket) -> Result<Self, Self::Error> {
		let address: socket2::SockAddr = socket.local_addr()?;
		let domain: socket2::Domain = address.domain();

		let r#type: socket2::Type;
		let protocol: Option<socket2::Protocol>;
		let is_listening: Option<bool>;
		let is_connected: bool;

		cfg_if! {
			if #[cfg(windows)] {
				compile_error!("implement this using Win32 `SO_PROTOCOL_INFO` and `SO_ACCEPTCONN`");
			}
			else {
				r#type = socket.r#type()?;

				cfg_if! {
					if #[cfg(any(
						target_os = "android",
						target_os = "freebsd",
						target_os = "fuchsia",
						target_os = "linux",
					))] {
						protocol = socket.protocol()?;
					}
					else {
						protocol = None;
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
						is_listening = Some(socket.is_listener()?);
					}
					else {
						is_listening = None;
					}
				}
			}
		}

		is_connected = {
			if
				r#type != socket2::Type::STREAM ||
				is_listening == Some(true)
			{
				false
			}
			else { match socket.peer_addr() {
				Ok(_) => true,

				Err(error) if error.kind() == io::ErrorKind::NotConnected => false,

				Err(error) => return Err(error),
			}}
		};

		Ok(match (domain, r#type, protocol, is_listening, is_connected) {
			// This is where pattern matching really shines.

			(
				socket2::Domain::IPV4 | socket2::Domain::IPV6,
				socket2::Type::STREAM,
				None,
				None | Some(true),
				false,
			) | (
				_,
				_,
				Some(socket2::Protocol::TCP),
				None | Some(true),
				false,
			) => Self::TcpListener(socket.into()),

			(
				socket2::Domain::IPV4 | socket2::Domain::IPV6,
				socket2::Type::STREAM,
				None,
				Some(false),
				true,
			) | (
				_,
				_,
				Some(socket2::Protocol::TCP),
				Some(false),
				true,
			) => Self::TcpStream(socket.into()),

			(
				socket2::Domain::IPV4 | socket2::Domain::IPV6,
				socket2::Type::DGRAM,
				None,
				_,
				_,
			) | (
				_,
				_,
				Some(socket2::Protocol::UDP),
				_,
				_,
			) => Self::UdpSocket(socket.into()),

			#[cfg(unix)]
			(
				socket2::Domain::UNIX,
				socket2::Type::STREAM,
				_,
				None | Some(true),
				false,
			) => Self::UnixListener(socket.into()),

			#[cfg(unix)]
			(
				socket2::Domain::UNIX,
				socket2::Type::STREAM,
				_,
				Some(false),
				true,
			) => Self::UnixStream(socket.into()),

			#[cfg(unix)]
			(
				socket2::Domain::UNIX,
				socket2::Type::DGRAM,
				_,
				_,
				_,
			) => Self::UnixDatagram(socket.into()),

			_ => Self::Other(socket),
		})
	}
}

impl From<AnyStdSocket> for Socket {
	fn from(socket: AnyStdSocket) -> Self {
		match socket {
			AnyStdSocket::TcpListener(s) => s.into(),
			AnyStdSocket::TcpStream(s) => s.into(),
			AnyStdSocket::UdpSocket(s) => s.into(),
			#[cfg(unix)] AnyStdSocket::UnixDatagram(s) => s.into(),
			#[cfg(unix)] AnyStdSocket::UnixListener(s) => s.into(),
			#[cfg(unix)] AnyStdSocket::UnixStream(s) => s.into(),
			AnyStdSocket::Other(s) => s,
		}
	}
}
