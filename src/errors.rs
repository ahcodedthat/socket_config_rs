//! Various errors that can be raised by this library.

use std::{
	io,
	net,
	num::ParseIntError,
};

#[cfg(doc)]
use {
	crate::{
		convert,
		open,
		SocketAddr,
		SocketAppOptions,
		SocketUserOptions,
	},
	std::str::FromStr,
};

#[cfg(all(doc, feature = "tokio"))]
use crate::convert::{AnyTokioListener, AnyTokioStream};

#[cfg(feature = "tokio")]
use crate::convert::AnyStdSocket;

/// An error parsing a [`SocketAddr`] [from a string][FromStr].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InvalidSocketAddrError {
	/// The socket address did not fit one of the acceptable patterns.
	#[error("invalid socket address: must be a valid IP address and port, a Unix-domain socket path, `stdin`, `fd:n`, `socket:n`, or `systemd:n`")]
	#[non_exhaustive]
	Unrecognized {
		/// The error that occurred when attempting to parse the socket address as an IP address and port.
		#[source]
		ip_error: net::AddrParseError,
	},

	/// The socket address is in the form <code>fd:<var>n</var></code>, <code>socket:<var>n</var></code>, or <code>systemd:<var>n</var></code>, but <code><var>n</var></code> could not be parsed as a socket file descriptor or handle.
	#[error("invalid socket address: it is of the form `fd:n`, `socket:n`, or `systemd:n`, but `n` is not a valid integer: {error}")]
	#[non_exhaustive]
	InvalidSocketNum {
		#[source]
		error: ParseIntError,
	},
}

/// An error that occurred in [opening][open()] a socket.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OpenSocketError {
	/// The [`SocketAddr`] specifies a Unix-domain socket with a path, but that path is invalid.
	///
	/// This error results from a call to [`socket2::SockAddr::unix`], and most likely indicates that the socket path is too long.
	#[error("invalid Unix-domain socket path: {error}")]
	#[non_exhaustive]
	InvalidUnixPath {
		/// The error that this one arose from.
		#[source]
		error: io::Error,
	},

	/// The [`SocketAddr`] specifies a socket inherited from systemd socket activation, but no such socket was inherited.
	///
	/// # Availability
	///
	/// Non-Windows platforms only.
	#[cfg(not(windows))]
	#[error("no such inherited socket (according to the `LISTEN_PID` and `LISTEN_FDS` environment variables)")]
	#[non_exhaustive]
	InvalidSystemdFd,

	/// There was an error getting the standard input handle.
	///
	/// # Availability
	///
	/// Windows only. On all other platforms, getting the standard input handle never fails.
	#[cfg(windows)]
	#[error("couldn't get standard input handle: {error}")]
	#[non_exhaustive]
	WindowsGetStdin {
		/// The error that this one arose from.
		#[source]
		error: io::Error,
	},

	/// The [`SocketAddr`] specifies a socket inherited from the parent process (including systemd socket activation), but there was an error in getting the inherited socket.
	///
	/// Specifically, the error was in trying to duplicate the socket (`dup` on Unix-like platforms; `WSADuplicateSocket` on Windows). (This library duplicates inherited sockets so that they can be [opened][crate::open()] more than once.)
	///
	/// If this error occurs, it probably means that the process didn't actually inherit any socket with that file descriptor or handle.
	#[error("couldn't inherit socket: {error}")]
	#[non_exhaustive]
	DupInherited {
		/// The error that this one arose from.
		#[source]
		error: io::Error,
	},

	/// The [`SocketAddr`] specifies a socket inherited from the parent process (including systemd socket activation), but while the socket does exist, it has the wrong type.
	#[error("inherited socket has wrong type (expected `{expected:?}`; got `{actual:?}`)")]
	#[non_exhaustive]
	InheritWrongType {
		/// The type that the socket was expected to have.
		expected: socket2::Type,

		/// The type that the socket actually has.
		actual: socket2::Type,
	},

	/// A user option was used that is not applicable to this kind of socket.
	#[error("the `{name}` option is not applicable to this kind of socket")]
	#[non_exhaustive]
	InapplicableUserOption {
		/// The name of the option that is not applicable, as it appears in the API documentation, such as `ip_socket_reuse_port`.
		name: &'static str,
	},

	/// [`socket2::Socket::new`] failed.
	#[error("couldn't create socket: {error}")]
	#[non_exhaustive]
	CreateSocket {
		/// The error that this one arose from.
		#[source]
		error: io::Error,
	},

	/// The socket is a path-based Unix-domain socket, but there was an error creating any needed parent folders.
	#[error("couldn't create parent folders: {error}")]
	#[non_exhaustive]
	MkdirParents {
		/// The error that this one arose from.
		#[source]
		error: io::Error,
	},

	/// [`SocketAddr::cleanup`] failed.
	#[error("{0}")]
	Cleanup(#[from] CleanupSocketError),

	/// Setting a socket option failed.
	#[error("couldn't set socket option `{option}`: {error}")]
	#[non_exhaustive]
	SetSockOpt {
		/// The name of the socket option, like `SO_REUSEPORT`.
		option: &'static str,

		/// The error that this one arose from.
		#[source]
		error: io::Error,
	},

	/// [`SocketAppOptions::before_bind`] was used, and it returned an error.
	#[error("{0}")]
	BeforeBind(io::Error),

	/// [`socket2::Socket::bind`] failed.
	#[error("couldn't bind socket to address: {error}")]
	#[non_exhaustive]
	Bind {
		/// The error that this one arose from.
		#[source]
		error: io::Error,
	},

	/// There was an error setting the owner of the socket.
	///
	/// # Availability
	///
	/// Unix-like platforms only.
	#[cfg(unix)]
	#[error("`unix_socket_owner` and/or `unix_socket_group` was used, but there was an error setting the socket's owner: {error}")]
	#[non_exhaustive]
	SetOwner {
		/// The error that this one arose from.
		#[source]
		error: io::Error,
	},

	/// There was an error setting permissions on the socket.
	///
	/// # Availability
	///
	/// Unix-like platforms only.
	#[cfg(unix)]
	#[error("`unix_socket_permissions` was used, but there was an error setting the socket's permissions: {error}")]
	#[non_exhaustive]
	SetPermissions {
		/// The error that this one arose from.
		#[source]
		error: io::Error,
	},

	/// [`socket2::Socket::listen`] failed.
	#[error("couldn't make the socket listen: {error}")]
	#[non_exhaustive]
	Listen {
		/// The error that this one arose from.
		#[source]
		error: io::Error,
	},

	/// [`socket2::Socket::type`] failed.
	///
	/// This will, in particular, happen if the file descriptor or handle exists but is not a socket.
	#[error("couldn't check type of inherited socket: {error}")]
	#[non_exhaustive]
	CheckInheritedSocket {
		/// The error that this one arose from.
		#[source]
		error: io::Error,
	},

	/// The inherited [stream-type][socket2::Type::STREAM] socket is not in a listening state, but [`SocketAppOptions::listen`] is true.
	#[error("the inherited socket was expected to be in a listening state, but it is not")]
	#[non_exhaustive]
	InheritedIsNotListening,

	/// The inherited [stream-type][socket2::Type::STREAM] socket is in a listening state, but [`SocketAppOptions::listen`] is false.
	#[error("the inherited socket was expected to not be in a listening state, but it is")]
	#[non_exhaustive]
	InheritedIsListening,

	/// The [`SocketAddr`] is a [`SocketAddr::Ip`] with no port number, but [`SocketAppOptions::default_port`] is `None`.
	#[error("a port number is required")]
	#[non_exhaustive]
	PortRequired,
}

impl From<OpenSocketError> for io::Error {
	fn from(error: OpenSocketError) -> Self {
		use io::ErrorKind as EK;

		let kind = match &error {
			OpenSocketError::InheritWrongType { .. }       => EK::InvalidData ,
			OpenSocketError::InapplicableUserOption { .. } => EK::InvalidInput,
			OpenSocketError::InheritedIsListening          => EK::InvalidData ,
			OpenSocketError::InheritedIsNotListening       => EK::InvalidData ,
			OpenSocketError::PortRequired                  => EK::InvalidData ,

			| OpenSocketError::InvalidUnixPath { error }
			| OpenSocketError::DupInherited { error }
			| OpenSocketError::CreateSocket { error }
			| OpenSocketError::MkdirParents { error }
			| OpenSocketError::BeforeBind(error)
			| OpenSocketError::Bind { error }
			| OpenSocketError::Listen { error }
			| OpenSocketError::CheckInheritedSocket { error }
			| OpenSocketError::Cleanup(
				| CleanupSocketError::Stat { error }
				| CleanupSocketError::Unlink { error }
			)
			| OpenSocketError::SetSockOpt { error, .. }
			=> error.kind(),

			#[cfg(not(windows))]
			OpenSocketError::InvalidSystemdFd => EK::NotFound,

			#[cfg(windows)]
			OpenSocketError::WindowsGetStdin { error } => error.kind(),

			#[cfg(unix)]
			| OpenSocketError::SetOwner { error }
			| OpenSocketError::SetPermissions { error }
			=> error.kind(),
		};

		io::Error::new(kind, error)
	}
}

/// Error raised by [`SocketAddr::cleanup`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CleanupSocketError {
	/// The socket is a path-based Unix-domain socket, but [`std::fs::symlink_metadata`] (or the Windows equivalent) reported an error checking for a stale socket.
	#[error("couldn't check for a stale Unix-domain socket: {error}")]
	#[non_exhaustive]
	Stat {
		#[source]
		error: io::Error,
	},

	/// The socket is a path-based Unix-domain socket, and there is a stale socket at the designated path, but [`std::fs::remove_file`] reported an error removing it.
	#[error("couldn't remove the stale Unix-domain socket: {error}")]
	#[non_exhaustive]
	Unlink {
		#[source]
		error: io::Error,
	},
}

impl From<CleanupSocketError> for io::Error {
	fn from(error: CleanupSocketError) -> Self {
		let kind = match &error {
			| CleanupSocketError::Stat { error }
			| CleanupSocketError::Unlink { error }
			=> error.kind(),
		};

		io::Error::new(kind, error)
	}
}

/// The errors that can occur in setting up a socket for use with Tokio.
///
/// This error type can be raised when converting a socket to [`AnyTokioListener`] or [`AnyTokioStream`].
///
/// # Availability
///
/// Requires the `tokio` feature.
#[cfg(feature = "tokio")]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IntoTokioError {
	/// The socket is the wrong type or protocol. This can happen when trying to convert a UDP socket into an [`AnyTokioListener`], for example.
	///
	/// Note that this error can be caused by attempting to use a Unix-domain socket on Windows, which is not currently supported. A special error message is used if this happens.
	#[error("{}", match socket {
		#[cfg(all(windows, not(unix)))]
		AnyStdSocket::Other(socket)
		if {
			let local_addr = socket.local_addr().ok();
			let domain = local_addr.map(|a| a.domain());
			domain == Some(socket2::Domain::UNIX)
		}
		=> "Unix-domain sockets are not currently supported on Windows",

		_ => "inappropriate or unrecognized socket domain, type, or transport protocol",
	})]
	#[non_exhaustive]
	Inappropriate {
		/// The socket that was inappropriate.
		socket: AnyStdSocket,
	},

	/// There was an error checking details about the socket, such as its [type][socket2::Type] and [protocol][socket2::Protocol].
	#[error("couldn't get socket details: {error}")]
	#[non_exhaustive]
	Check {
		#[source]
		error: io::Error,
	},

	/// There was an error setting non-blocking mode on the socket.
	#[error("couldn't set non-blocking mode on socket: {error}")]
	#[non_exhaustive]
	SetNonBlocking {
		#[source]
		error: io::Error,
	},

	/// An error was raised by one of the Tokio socket type conversion methods, like [`tokio::net::TcpListener::from_std`].
	#[error("error passing the socket to Tokio: {error}")]
	#[non_exhaustive]
	Wrap {
		#[source]
		error: io::Error,
	},
}

#[cfg(feature = "tokio")]
impl From<IntoTokioError> for io::Error {
	fn from(error: IntoTokioError) -> Self {
		let kind = match &error {
			IntoTokioError::Inappropriate { .. } => io::ErrorKind::InvalidInput,

			| IntoTokioError::Check { error }
			| IntoTokioError::SetNonBlocking { error }
			| IntoTokioError::Wrap { error }
			=> error.kind(),
		};

		io::Error::new(kind, error)
	}
}
