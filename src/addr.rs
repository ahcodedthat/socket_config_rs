use crate::{
	errors::{
		CleanupSocketError,
		InvalidSocketAddrError,
	},
	is_unix_socket,
	sys,
};
use std::{
	fmt::{self, Display, Formatter},
	fs,
	io,
	net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
	path::{Path, PathBuf},
	str::FromStr,
};

#[cfg(doc)]
use crate::{
	convert::AnyStdSocket,
	SocketAppOptions,
};

/// The address to bind a socket to, or a description of an inherited socket to use. This is one of the three parameters to [`open`][crate::open()].
///
/// This is somewhat like [`std::net::SocketAddr`], but has many more variants.
///
/// This type is designed to be parsed or converted from other types, namely:
///
/// * From a string, using [`str::parse`] or [`FromStr::from_str`]. The documentation for each variant has a “Syntax” section explaining the expected syntax.
/// * [`From`] various standard library socket address types. The implementation of <code>From&lt;[PathBuf]&gt;</code> produces [`SocketAddr::Unix`].
#[cfg_attr(feature = "serde", doc = r#"
* From a serialization format supported by [`serde`]. The serialized representation is expected to be a string, also using the syntax described in the aforementioned “Syntax” sections.
"#)]
///
///
/// # Availability
///
/// All platforms. Deserializing with `serde` requires the `serde` feature.
#[derive(Clone, Debug, Eq, derive_more::From, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde_with::DeserializeFromStr))]
#[non_exhaustive]
pub enum SocketAddr {
	/// An Internet (IPv4 or IPv6) socket address.
	///
	/// # Availability
	///
	/// All platforms.
	///
	/// # Syntax
	///
	/// * `1.2.3.4`, an IPv4 address without port number
	/// * `1.2.3.4:5`, an IPv4 address with port number
	/// * `1::2`, a non-bracketed IPv6 address without port number
	/// * `[1::2]:3`, a bracketed IPv6 address with port number
	///
	/// If no port number is given, it defaults to 0.
	#[non_exhaustive]
	Ip {
		/// The IP address and port.
		addr: std::net::SocketAddr,
	},

	/// A Unix-domain socket at the given path.
	///
	/// # Availability
	///
	/// All platforms.
	///
	/// Despite the name, Unix-domain sockets are available on Windows. Only certain versions of Windows support it, however, namely build 17063 and later.
	///
	/// Although this library supports Unix-domain sockets on Windows, note that the Rust standard library and Tokio currently do not. Converting a Unix-domain socket to [`AnyStdSocket`] on Windows will result in the [`AnyStdSocket::Other`] variant, not any of the `AnyStdSocket` variants for Unix-domain sockets.
	///
	/// Some platforms, namely Linux and Windows, support Unix-domain sockets whose name is in an “abstract namespace” instead of the file system. That is not currently supported by this library.
	///
	/// Unix-domain socket names and paths are severely limited in length. The maximum length is platform-defined.
	///
	/// # Syntax
	///
	/// * A path starting with `\`, `/`, `.\`, or `./`
	/// * A path starting with <code><var>X</var>:&Backslash;</code> (where <code><var>X</var></code> is a single ASCII letter, `A` through `Z`, case insensitive)
	///
	/// Note that all of these patterns are recognized on all platforms as indicating a Unix-domain socket. That includes the <code><var>X</var>:&Backslash;</code> pattern, which is somewhat surprisingly interpreted as a *relative* path on non-Windows platforms.
	#[non_exhaustive]
	Unix {
		/// The path to the socket.
		path: PathBuf,
	},

	/// An existing socket inherited from the parent process.
	///
	/// Only sockets that have been made inheritable can be inherited. When spawning a child process from a Rust program (such as an integration test) that is to inherit a socket from the parent process, use the [`make_socket_inheritable`][crate::make_socket_inheritable()] function to make it inheritable.
	///
	/// # Availability
	///
	/// All platforms.
	///
	/// Socket inheritance on Windows only works if there are no [Layered Service Providers](https://en.wikipedia.org/wiki/Layered_Service_Provider) (LSPs) installed. In the past, LSPs were commonly used by Windows security software to inspect network traffic. LSPs were replaced by the [Windows Filtering Platform](https://en.wikipedia.org/wiki/Windows_Filtering_Platform) in Windows Vista and have been deprecated since Windows Server 2012, though as of 2022 they are still supported for backward compatibility reasons. Therefore, inherited sockets are likely but not guaranteed to work on modern Windows systems, and unlikely to work on legacy Windows systems.
	///
	/// # Syntax
	///
	/// <code>fd:<var>n</var></code> or <code>socket:<var>n</var></code> where <code><var>n</var></code> is a file descriptor number or Windows `SOCKET` handle.
	///
	/// Note that the `fd:` and `socket:` prefixes are synonymous. Either one is accepted on any platform. When a `SocketAddr` is [`Display`]ed, the `socket:` prefix is used on Windows, and `fd:` is used on all other platforms.
	#[from(ignore)]
	#[non_exhaustive]
	Inherit {
		/// The socket's file descriptor number or Windows `SOCKET` handle.
		socket: sys::RawSocket,
	},

	/// An existing socket inherited from the parent process, as the standard input.
	///
	/// This can be used with inetd sockets in `wait` mode, but is not compatible with `nowait` mode.
	///
	/// This is like the `Inherit` variant above, except the socket file descriptor number or Windows `SOCKET` handle is determined as follows:
	///
	/// * On Windows, <code>[GetStdHandle](https://learn.microsoft.com/en-us/windows/console/getstdhandle)(STD_INPUT_HANDLE)</code> is called to obtain the `SOCKET` handle.
	/// * On all other platforms, file descriptor number 0 is used.
	///
	/// # Availability
	///
	/// All platforms.
	///
	/// Availability notes for the `Inherit` variant also apply to this variant.
	///
	/// # Syntax
	///
	/// The exact string `stdin`.
	#[from(ignore)]
	#[non_exhaustive]
	InheritStdin,

	/// An existing socket inherited from systemd socket activation.
	///
	/// This is similar to the `Inherit` variant, but different in the systemd environment variables `LISTEN_FDS` and `LISTEN_PID` are checked before using the socket. See [the systemd documentation](https://www.freedesktop.org/software/systemd/man/sd_listen_fds.html) for details about these.
	///
	/// Systemd socket units used with this must be in `Accept=no` mode.
	///
	/// # Availability
	///
	/// Unix-like platforms only.
	///
	/// Note that, although systemd is Linux-specific, the systemd socket activation protocol is not, and other implementations for other platforms may exist. The socket activation protocol can be implemented on any platform with Unix-like inheritable file descriptors and environment variables.
	///
	/// The socket activation protocol is *not* possible to implement on Windows, because the protocol requires that the first socket is numbered 3, the second socket is numbered 4, and so on. Windows `SOCKET` handles' numeric values cannot be controlled like this. This socket address mode is therefore unavailable on Windows, and attempting to use it always results in an error.
	///
	/// # Syntax
	///
	/// <code>systemd:<var>n</var></code> where <code><var>n</var></code> is a file descriptor number for a socket inherited from systemd, starting at 3.
	#[cfg(not(windows))]
	#[from(ignore)]
	#[non_exhaustive]
	SystemdNumeric {
		/// The socket's file descriptor number.
		socket: sys::RawSocket,
	},
}

impl SocketAddr {
	/// Returns true if and only if this `SocketAddr` is one of the inherited variants, like `Inherit` or `SystemdNumeric`.
	pub fn is_inherited(&self) -> bool {
		match self {
			| Self::Inherit { .. }
			| Self::InheritStdin
			=> true,

			#[cfg(not(windows))]
			Self::SystemdNumeric { .. } => true,

			_ => false,
		}
	}

	/// Deletes the indicated path-based Unix-domain socket, if applicable.
	///
	/// This method does nothing if `self` is not [`SocketAddr::Unix`], or if there is not a Unix-domain socket at `self.path`.
	///
	/// This method attempts to check if the file at `self.path` really is a Unix-domain socket before deleting it. This check is imperfect, however; it is possible for a Unix-domain socket to be replaced with some other kind of file after the check but before the deletion (a [TOCTTOU] issue).
	///
	/// [TOCTTOU]: https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use
	pub fn cleanup(&self) -> Result<(), CleanupSocketError> {
		if let Self::Unix { path, .. } = self {
			cleanup_unix_path_socket(path)?;
		}

		Ok(())
	}

	fn from_std_ip(addr: IpAddr) -> Self {
		Self::from_std_ip_port(std::net::SocketAddr::new(addr, 0))
	}

	fn from_std_ip_port(addr: std::net::SocketAddr) -> Self {
		Self::Ip { addr }
	}
}

impl FromStr for SocketAddr {
	type Err = InvalidSocketAddrError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		// See if it's `stdin`.
		if s == "stdin" {
			return Ok(Self::InheritStdin {});
		}

		// See if it's `fd:n`, `socket:n`, or `systemd:n`.
		{
			enum InheritKind { RawFd, #[cfg(not(windows))] Systemd }
			const RAW_FD_PREFIX: &str = "fd:";
			const RAW_SOCKET_PREFIX: &str = "socket:";
			#[cfg(not(windows))] const SYSTEMD_PREFIX: &str = "systemd:";

			let inherit_kind: Option<InheritKind>;
			let inherit_prefix: &str;

			'found: {
				if s.starts_with(RAW_FD_PREFIX) {
					inherit_kind = Some(InheritKind::RawFd);
					inherit_prefix = RAW_FD_PREFIX;
					break 'found;
				}

				if s.starts_with(RAW_SOCKET_PREFIX) {
					inherit_kind = Some(InheritKind::RawFd);
					inherit_prefix = RAW_SOCKET_PREFIX;
					break 'found;
				}

				#[cfg(not(windows))]
				if s.starts_with(SYSTEMD_PREFIX) {
					inherit_kind = Some(InheritKind::Systemd);
					inherit_prefix = SYSTEMD_PREFIX;
					break 'found;
				}

				inherit_kind = None;
				inherit_prefix = "";
			}

			// If it is, then parse it.
			if let Some(inherit_kind) = inherit_kind {
				let socket: &str =
					s.get(inherit_prefix.len()..)
					.unwrap_or_default();

				let socket: sys::RawSocket =
					socket.parse()
					.map_err(|error| InvalidSocketAddrError::InvalidSocketNum { error })?;

				return Ok(match inherit_kind {
					InheritKind::RawFd => Self::Inherit {
						socket,
					},

					#[cfg(not(windows))]
					InheritKind::Systemd => Self::SystemdNumeric {
						socket,
					},
				});
			}
		}

		// See if it's a Unix-domain socket with a path.
		if
			s.starts_with('\\') ||
			s.starts_with('/') ||
			s.starts_with(r".\") ||
			s.starts_with("./") ||
			(
				// Check if it's a Windows drive-letter path.
				//
				// Extract the first three bytes of the path.
				s.as_bytes().get(0..=2)
				// Convert the slice reference to an array reference. (Rust has a method for doing this without making a subslice first, but it's not stable yet.)
				.and_then(|slice| <&[u8; 3]>::try_from(slice).ok())
				// Now, check if those first three bytes fit the `X:\` pattern.
				.is_some_and(|[letter, colon, backslash]| {
					letter.is_ascii_alphabetic() &&
					*colon == b':' &&
					*backslash == b'\\'
				})
			)
		{
			return Ok(Self::Unix {
				path: s.into(),
			})
		}

		// Assume anything else must be an IP address with optional port number. Try to parse it as that. If that fails, signal that the address is unrecognized.
		Ok(Self::Ip {
			addr: {
				IpAddr::from_str(s)
				.map(|ip_addr| std::net::SocketAddr::new(ip_addr, 0))
				.or_else(|_| std::net::SocketAddr::from_str(s))
				.map_err(|ip_error| InvalidSocketAddrError::Unrecognized {
					ip_error,
				})?
			},
		})
	}
}

impl Display for SocketAddr {
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		match self {
			Self::Ip { addr } => write!(f, "{addr}"),
			Self::Unix { path } => write!(f, "{}", path.display()),
			#[cfg(windows)] Self::Inherit { socket } => write!(f, "socket:{socket}"),
			#[cfg(not(windows))] Self::Inherit { socket } => write!(f, "fd:{socket}"),
			Self::InheritStdin {} => write!(f, "stdin"),
			#[cfg(not(windows))] Self::SystemdNumeric { socket } => write!(f, "systemd:{socket}"),
		}
	}
}

impl From<IpAddr> for SocketAddr {
	fn from(addr: IpAddr) -> Self {
		Self::from_std_ip(addr)
	}
}

impl From<Ipv4Addr> for SocketAddr {
	fn from(addr: Ipv4Addr) -> Self {
		Self::from_std_ip(IpAddr::from(addr))
	}
}

impl From<Ipv6Addr> for SocketAddr {
	fn from(addr: Ipv6Addr) -> Self {
		Self::from_std_ip(IpAddr::from(addr))
	}
}

impl From<SocketAddrV4> for SocketAddr {
	fn from(addr: SocketAddrV4) -> Self {
		Self::from_std_ip_port(std::net::SocketAddr::from(addr))
	}
}

impl From<SocketAddrV6> for SocketAddr {
	fn from(addr: SocketAddrV6) -> Self {
		Self::from_std_ip_port(std::net::SocketAddr::from(addr))
	}
}

pub(crate) fn cleanup_unix_path_socket(path: &Path) -> Result<(), CleanupSocketError> {
	let is_unix_socket: bool =
		is_unix_socket(path)
		.or_else(|error| {
			// Treat a “not found” error as equivalent to `Ok(false)`.
			if error.kind() == io::ErrorKind::NotFound {
				Ok(false)
			}
			else {
				Err(error)
			}
		})
		.map_err(|error| CleanupSocketError::Stat { error })?;

	if is_unix_socket {
		if let Err(error) = fs::remove_file(path) {
		if error.kind() != io::ErrorKind::NotFound {
			return Err(CleanupSocketError::Unlink { error });
		}}
	}

	Ok(())
}
