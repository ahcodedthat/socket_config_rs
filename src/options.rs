use socket2::Socket;
use std::{
	ffi::c_int,
	io,
};

#[cfg(unix)]
use nix::{
	sys::stat::Mode,
	unistd::{Gid, Uid},
};

#[cfg(doc)]
use crate::SocketAddr;

/// Options for opening a socket, supplied by the user of your application. This is one of the three parameters to [`open`][crate::open()].
#[cfg_attr(feature = "serde", doc = r#"

This structure is suitable for deserializing with [`serde`], with one caveat: it is marked with the attribute `#[serde(deny_unknown_fields)]`, and therefore must not be referenced in a field marked `#[serde(flatten)]`.
"#)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
#[cfg_attr(feature = "serde", derive(serde::Deserialize), serde(default, deny_unknown_fields))]
#[non_exhaustive]
pub struct SocketUserOptions {
	/// Prevents the deletion of the existing socket, if any.
	///
	/// This option applies to non-inherited Unix-domain sockets only, and has no effect on other kinds of sockets.
	///
	/// # Availability
	///
	/// All platforms.
	#[cfg_attr(feature = "clap", arg(long))]
	pub unix_socket_no_unlink: bool,

	/// Permissions for created, path-based Unix-domain sockets. The default is to use the process umask (permission mask).
	///
	/// This option applies only to non-inherited path-based Unix-domain sockets. Using it on any other kind of socket, such as a TCP socket or an inherited Unix-domain socket, is an error.
	///
	/// # Command line syntax
	///
	/// This can be either a numeric Unix mode (as in the `chmod` command) or any combination of the letters `u`, `g`, and `o`, standing for the owning user, owning group, and all other users, respectively.
	///
	/// # Configuration file syntax
	///
	/// This can be either a numeric Unix mode, a string containing a numeric Unix mode in octal form, or a string containing any combination of the letters `u`, `g`, and `o`, standing for the owning user, owning group, and all other users, respectively.
	///
	/// # Availability
	///
	/// Unix-like platforms. Using this option on other platforms is an error.
	#[cfg(unix)]
	#[cfg_attr(feature = "clap", arg(long, value_parser = crate::unix_security::parse_mode))]
	#[cfg_attr(feature = "serde", serde(with = "serde_with::As::<Option<crate::unix_security::DeserMode>>"))]
	pub unix_socket_permissions: Option<Mode>,

	/// Owner for created, path-based Unix-domain sockets.
	///
	/// This option is applicable only to path-based Unix-domain sockets that are being created. Using it on any other kind of socket, such as a TCP socket or an inherited Unix-domain socket, is an error.
	///
	/// In order to change the owner of a file, including a Unix-domain socket, most operating systems require special privileges, such as the capability `CAP_CHOWN` on Linux.
	///
	/// # Command line syntax
	///
	/// Either a numeric user ID or a user name.
	///
	/// # Configuration file syntax
	///
	/// Either a user ID as a number, or a user name as a string.
	///
	/// # Availability
	///
	/// Unix-like platforms. Using this option on other platforms is an error.
	#[cfg(unix)]
	#[cfg_attr(feature = "clap", arg(long, value_parser = crate::unix_security::parse_uid))]
	#[cfg_attr(feature = "serde", serde(with = "serde_with::As::<Option<crate::unix_security::DeserUid>>"))]
	pub unix_socket_owner: Option<Uid>,

	/// Group for created, path-based Unix-domain sockets.
	///
	/// This option is applicable only to path-based Unix-domain sockets that are being created. Using it on any other kind of socket, such as a TCP socket or an inherited Unix-domain socket, is an error.
	///
	/// In order to change the group of a file, including a Unix-domain socket, most operating systems require the process to either be a member of that group or have special privileges, such as the capability `CAP_CHOWN` on Linux.
	///
	/// # Command line syntax
	///
	/// Either a numeric group ID or a group name.
	///
	/// # Configuration file syntax
	///
	/// Either a group ID as a number, or a group name as a string.
	///
	/// # Availability
	///
	/// Unix-like platforms. Using this option on other platforms is an error.
	#[cfg(unix)]
	#[cfg_attr(feature = "clap", arg(long, value_parser = crate::unix_security::parse_gid))]
	#[cfg_attr(feature = "serde", serde(with = "serde_with::As::<Option<crate::unix_security::DeserGid>>"))]
	pub unix_socket_group: Option<Gid>,

	/// Set the socket option `SO_REUSEPORT`, which allows multiple processes to receive connections or packets on the same port.
	///
	/// Using this option with an inherited socket is an error.
	///
	/// # Availability
	///
	/// Unix-like platforms except Solaris and illumos (that is, `cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))`). Using this option on other platforms is an error.
	#[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
	#[cfg_attr(feature = "clap", arg(long))]
	pub ip_socket_reuse_port: bool,

	/// Only communicate over IPv6, not IPv4.
	///
	/// Using this option with an inherited socket is an error.
	///
	/// # Availability
	///
	/// All platforms.
	#[cfg_attr(feature = "clap", arg(long))]
	pub ip_socket_v6_only: bool,

	/// Maximum pending connections, for listening sockets. Default is 128.
	///
	/// This option only has an effect on non-inherited [stream-type][socket2::Type::STREAM] listening sockets, and is ignored for all others.
	///
	/// # Availability
	///
	/// All platforms.
	#[cfg_attr(feature = "clap", arg(long))]
	pub listen_socket_backlog: Option<c_int>,
}

impl SocketUserOptions {
	/// The default value used when [`SocketUserOptions::listen_socket_backlog`] is `None`.
	pub const DEFAULT_LISTEN_SOCKET_BACKLOG: c_int = 128;
}

/// Options for opening a socket, supplied by your application itself. This is one of the three parameters to [`open`][crate::open()].
///
/// Note that the socket [domain][socket2::Domain] is not part of this structure. Instead, the domain is part of the socket address.
#[non_exhaustive]
pub struct SocketAppOptions<'a> {
	/// Socket type, such as stream or datagram.
	///
	/// For inherited sockets, it is an error if the inherited socket's type does not match this option.
	pub r#type: socket2::Type,

	/// Socket transport protocol, such as TCP or UDP.
	///
	/// Most combinations of socket domain and type (for example, IPv4 and stream) imply a transport protocol (in the aforementioned example, TCP), but this field can be used to specify a transport protocol explicitly.
	///
	/// For inherited sockets, this option is ignored.
	pub protocol: Option<socket2::Protocol>,

	/// Whether to call `listen` on newly opened sockets. Ignored if `type` is not [`socket2::Type::STREAM`]. Default is true.
	///
	/// For inherited stream-type sockets, it is instead checked whether the socket is in a listening state, and an error is raised if its state does not match this option. That is, if this option is true, then it is an error if the inherited socket is *not* listening, and if this option is false, then it is an error if the inherited socket *is* listening.
	///
	///
	/// # Availability
	///
	/// All platforms, but the aforementioned check of inherited sockets' listening state only occurs on sufficiently recent versions of AIX, Android, FreeBSD, Fuchsia, and Linux. Other platforms do not support checking the listening state of an existing socket. On those platforms, this option is ignored for inherited sockets.
	pub listen: bool,

	/// Default port number for TCP or UDP sockets. Default is zero.
	///
	/// If this is *not* zero, then when a [`SocketAddr::Ip`] with a port number of zero is [opened][crate::open()], this `default_port` will be used instead. This allows, for example, a web server to default to port 80 if the user doesn't supply an explicit port number.
	pub default_port: u16,

	/// A function that is called just before binding the newly created socket to its address. It is not called if the socket is inherited (such sockets are assumed to already be bound).
	#[allow(clippy::type_complexity)] // In my opinion, the complexity of this field's type is preferable to polluting the API documentation with a type alias.
	pub before_bind: Option<&'a dyn Fn(&mut Socket) -> io::Result<()>>,
}

impl<'a> SocketAppOptions<'a> {
	/// Initializes a new `SocketAppOptions` with the given [`type`][Self::type]. All other fields have their default values.
	pub fn new(r#type: socket2::Type) -> Self {
		Self {
			r#type,
			protocol: None,
			listen: true,
			default_port: 0,
			before_bind: None,
		}
	}
}
