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
	make_socket_inheritable,
	SocketAppOptions,
	SocketUserOptions,
};

#[cfg(all(feature = "serde", test))]
use assert_matches::assert_matches;

/// The address to bind a socket to, or a description of an inherited socket to use. This is one of the three parameters to [`open`][crate::open()].
///
/// This is somewhat like [`std::net::SocketAddr`], but has many more variants.
///
/// This type is designed to be parsed or converted from other types, namely:
///
/// * From a string, using [`str::parse`] or [`FromStr::from_str`]. The documentation for each variant has a “Syntax” section explaining the expected syntax.
/// * [`From`] various standard library socket address types.
/// * `From` [`PathBuf`], which produces [`SocketAddr::Unix`].
/// * [`TryFrom`] `std::os::unix::net::SocketAddr` (Unix-like platforms only), which produces [`SocketAddr::Unix`] if the input address has a pathname, or fails if the input address is unnamed or (Linux only) has an abstract name.
#[cfg_attr(feature = "serde", doc = r#"
* From a serialization format supported by [`serde`]. The serialized representation is expected to be a string, also using the syntax described in the aforementioned “Syntax” sections.
"#)]
///
/// The [`Default`] for this type is the IPv4 address 127.0.0.1, with no port specified.
///
///
/// # Availability
///
/// All platforms. Deserializing with `serde` requires the `serde` feature.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde_with::DeserializeFromStr, serde_with::SerializeDisplay))]
#[non_exhaustive]
pub enum SocketAddr {
	/// An Internet (IPv4 or IPv6) socket address.
	///
	/// # Syntax
	///
	/// * `1.2.3.4`, an IPv4 address without port number
	/// * `1.2.3.4:5`, an IPv4 address with port number
	/// * `1::2`, a non-bracketed IPv6 address without port number
	/// * `[1::2]:3`, a bracketed IPv6 address with port number
	///
	/// If no port number is given, then [`SocketAppOptions::default_port`] is used as the port number instead. If that is also `None`, then [`open`][crate::open()] will raise an error.
	///
	/// # Availability
	///
	/// All platforms.
	#[non_exhaustive]
	Ip {
		/// The IP address.
		addr: std::net::IpAddr,

		/// The port, if any.
		port: Option<u16>,
	},

	/// A Unix-domain socket at the given path.
	///
	/// # Syntax
	///
	/// * A path starting with `\`, `/`, `.\`, or `./`
	/// * A path starting with <code><var>X</var>:&Backslash;</code> (where <code><var>X</var></code> is a single ASCII letter, `A` through `Z`, case insensitive)
	///
	/// Note that all of these patterns are recognized on all platforms as indicating a Unix-domain socket. That includes the <code><var>X</var>:&Backslash;</code> pattern, which is somewhat surprisingly interpreted as a *relative* path on non-Windows platforms.
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
	#[non_exhaustive]
	Unix {
		/// The path to the socket.
		path: PathBuf,
	},

	/// An existing socket inherited from the parent process.
	///
	/// Only sockets that have been made inheritable can be inherited. When spawning a child process from a Rust program (such as an integration test) that is to inherit a socket from the parent process, use the [`make_socket_inheritable`][crate::make_socket_inheritable()] function to make it inheritable.
	///
	/// # Syntax
	///
	/// <code>fd:<var>n</var></code> or <code>socket:<var>n</var></code> where <code><var>n</var></code> is a file descriptor number or Windows `SOCKET` handle.
	///
	/// Note that the `fd:` and `socket:` prefixes are synonymous. Either one is accepted on any platform. When a `SocketAddr` is [`Display`]ed, the `socket:` prefix is used on Windows, and `fd:` is used on all other platforms.
	///
	/// # Availability
	///
	/// All platforms.
	///
	/// Socket inheritance on Windows only works if there are no [Layered Service Providers](https://en.wikipedia.org/wiki/Layered_Service_Provider) (LSPs) installed. In the past, LSPs were commonly used by Windows security software to inspect network traffic. LSPs were replaced by the [Windows Filtering Platform](https://en.wikipedia.org/wiki/Windows_Filtering_Platform) in Windows Vista and have been deprecated since Windows Server 2012, though as of 2022 they are still supported for backward compatibility reasons. Therefore, inherited sockets are likely but not guaranteed to work on modern Windows systems, and unlikely to work on legacy Windows systems.
	#[non_exhaustive]
	Inherit {
		/// The socket's file descriptor number or Windows `SOCKET` handle.
		socket: sys::RawSocket,

		// Note: We use `RawSocket` here, rather than `BorrowedSocket<'static>` or `OwnedSocket`, for a few reasons:
		//
		// 1. `OwnedSocket` closes the socket when dropped. Developers using this library may assume that it is valid to parse a `SocketAddr`, drop it, then parse it again later, but that won't work correctly (and will cause undefined behavior) if `OwnedSocket` closes the inherited socket.
		//
		// 2. `BorrowedSocket` and `OwnedSocket` guarantee that the socket is valid. That is not known at the time of parsing. It is verified by `open`, which duplicates the alleged socket (which fails if no such socket exists) and then checks various things about the alleged socket (which fails if it's not a socket). That's still only mostly safe, but storing a `BorrowedSocket` or `OwnedSocket` here makes the representation that it's definitely a valid socket, which is definitely not safe.
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
	/// # Syntax
	///
	/// The exact string `stdin`.
	///
	/// # Availability
	///
	/// All platforms.
	///
	/// Availability notes for the `Inherit` variant also apply to this variant.
	#[non_exhaustive]
	InheritStdin,

	/// An existing socket inherited from systemd socket activation.
	///
	/// This is similar to the `Inherit` variant, but different in the systemd environment variables `LISTEN_FDS` and `LISTEN_PID` are checked before using the socket. See [the systemd documentation](https://www.freedesktop.org/software/systemd/man/sd_listen_fds.html) for details about these.
	///
	/// Systemd socket units used with this must be in `Accept=no` mode.
	///
	/// # Syntax
	///
	/// <code>systemd:<var>n</var></code> where <code><var>n</var></code> is a file descriptor number for a socket inherited from systemd, starting at 3.
	///
	/// # Availability
	///
	/// Unix-like platforms only.
	///
	/// Note that, although systemd is Linux-specific, the systemd socket activation protocol is not, and other implementations for other platforms may exist. The socket activation protocol can be implemented on any platform with Unix-like inheritable file descriptors and environment variables.
	///
	/// The socket activation protocol is *not* possible to implement on Windows, because the protocol requires that the first socket is numbered 3, the second socket is numbered 4, and so on. Windows `SOCKET` handles' numeric values cannot be controlled like this. This socket address mode is therefore unavailable on Windows, and attempting to use it always results in an error.
	#[cfg(not(windows))]
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
	/// Specifically, this method does the following:
	///
	/// 1. Check if `self` is [`SocketAddr::Unix`].
	/// 2. If so, check if there is a Unix-domain socket at [`self.path`][SocketAddr::Unix::path].
	/// 3. If so, delete the socket.
	///
	/// It is not normally necessary to call this method. Unless the user sets [`SocketUserOptions::unix_socket_no_unlink`] to true, stale sockets are automatically deleted when calling [`open`][crate::open()]. This is the conventional way to handle the deletion of stale Unix-domain sockets; see, for example, [BSD syslogd].
	///
	///
	/// # Caveats
	///
	/// The caveats for [`SocketUserOptions::unix_socket_no_unlink`] also apply to this method, namely:
	///
	/// The check performed in step 2 (see above) is imperfect; it is possible for a Unix-domain socket to be replaced with some other kind of file after the check but before the deletion (a [TOCTTOU] issue).
	///
	/// There will *not* be an attempt to check if the socket is still in use. If it is in use, then whichever process is using it will continue running, but it will be “detached” from the socket, and will not receive any new packets or connections over the socket. (Already-established connections are not affected.)
	///
	///
	/// # Errors
	///
	/// Returns an error if there is an I/O error checking for or deleting the socket.
	///
	/// It is not an error if the socket is not found, or if there is something other than a socket at `self.path` (such as a regular file). In that case, this method will return successfully without deleting anything.
	///
	///
	/// [BSD syslogd]: https://svnweb.freebsd.org/base/head/usr.sbin/syslogd/syslogd.c?revision=291328&view=markup#l565
	/// [TOCTTOU]: https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use
	pub fn cleanup(&self) -> Result<(), CleanupSocketError> {
		if let Self::Unix { path, .. } = self {
			cleanup_unix_path_socket(path)?;
		}

		Ok(())
	}

	/// Resolves relative file paths in this `SocketAddr`.
	///
	/// Specifically, if this is a [`SocketAddr::Unix`] and its `path` is relative, it is resolved against the provided `base_dir` using [`Path::join`].
	pub fn resolve_base_dir(&mut self, base_dir: &Path) {
		let do_resolve = |path_to_resolve: &mut PathBuf| {
			if !path_to_resolve.is_absolute() {
				*path_to_resolve = base_dir.join(&path_to_resolve);
			}
		};

		match self {
			Self::Unix { path } => do_resolve(path),
			_ => {}
		}
	}

	/// Creates a new [`SocketAddr::Inherit`] with the given socket.
	///
	/// This method exists because `SocketAddr::Inherit` is marked with the `non_exhaustive` attribute, and therefore cannot be instantiated directly. If a future version of this library adds additional fields to the `Inherit` variant, then this method will assign reasonable default values to them.
	///
	///
	/// # Example
	///
	/// When preparing a socket to be inherited by a child process, use this with [`make_socket_inheritable`] like so:
	///
	/// ```rust,no_run
	/// # use socket_config::{make_socket_inheritable, SocketAddr};
	/// # use std::process::Command;
	/// #
	/// # fn create_a_socket_somehow() -> std::io::Result<socket2::Socket> { unimplemented!() }
	/// #
	/// # fn run() -> std::io::Result<()> {
	/// // Create the socket that is to be inherited.
	/// let socket = create_a_socket_somehow()?;
	///
	/// // Make the socket inheritable, and prepare a `SocketAddr` for it.
	/// let addr = SocketAddr::new_inherit(
	/// 	make_socket_inheritable(&socket, true)?
	/// );
	///
	/// // Then pass it to the child process.
	/// Command::new("some_program")
	/// .arg(addr.to_string())
	/// .spawn()?;
	/// #
	/// # drop(addr);
	/// # Ok(())
	/// # }
	/// ```
	pub fn new_inherit(socket: sys::RawSocket) -> Self {
		Self::Inherit { socket }
	}

	/// Creates a new [`SocketAddr::InheritStdin`].
	///
	/// This method exists because `SocketAddr::InheritStdin` is marked with the `non_exhaustive` attribute, and therefore cannot be instantiated directly. If a future version of this library adds fields to the `InheritStdin` variant, then this method will assign reasonable default values to them.
	pub fn new_inherit_stdin() -> Self {
		Self::InheritStdin
	}

	/// Creates a new [`SocketAddr::SystemdNumeric`] with the given socket file descriptor number.
	///
	/// This method exists because `SocketAddr::SystemdNumeric` is marked with the `non_exhaustive` attribute, and therefore cannot be instantiated directly. If a future version of this library adds additional fields to the `SystemdNumeric` variant, then this method will assign reasonable default values to them.
	///
	///
	/// # Availability
	///
	/// Unix-like platforms only.
	#[cfg(not(windows))]
	pub fn new_systemd_numeric(socket: sys::RawSocket) -> Self {
		Self::SystemdNumeric { socket }
	}
}

fn str_is_unix_domain_socket_prefix(s: &str) -> bool {
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
}

impl Default for SocketAddr {
	fn default() -> Self {
		Self::Ip {
			addr: Ipv4Addr::LOCALHOST.into(),
			port: None,
		}
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
		if str_is_unix_domain_socket_prefix(s) {
			return Ok(Self::Unix {
				path: s.into(),
			})
		}

		// Assume anything else must be an IP address with optional port number. Try to parse it as that. If that fails, signal that the address is unrecognized.

		// See if it's an IP address without port number.
		if let Ok(addr) = IpAddr::from_str(s) {
			return Ok(addr.into());
		}

		// See if it's an IP address with port number.
		match std::net::SocketAddr::from_str(s) {
			Ok(addr) => Ok(addr.into()),

			// If not, then give up.
			Err(ip_error) => Err(InvalidSocketAddrError::Unrecognized {
				ip_error,
			}),
		}
	}
}

impl Display for SocketAddr {
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		match self {
			Self::Ip { addr, port: None } => write!(f, "{addr}"),

			Self::Ip { addr, port: Some(port) } => write!(f, "{}", std::net::SocketAddr::new(*addr, *port)),

			Self::Unix { path } => {
				let path = path.to_string_lossy();

				if !str_is_unix_domain_socket_prefix(&path) {
					write!(f, ".{}", std::path::MAIN_SEPARATOR)?;
				}

				write!(f, "{path}")
			},

			#[cfg(windows)] Self::Inherit { socket } => write!(f, "socket:{socket}"),
			#[cfg(not(windows))] Self::Inherit { socket } => write!(f, "fd:{socket}"),
			Self::InheritStdin {} => write!(f, "stdin"),
			#[cfg(not(windows))] Self::SystemdNumeric { socket } => write!(f, "systemd:{socket}"),
		}
	}
}

impl From<IpAddr> for SocketAddr {
	fn from(addr: IpAddr) -> Self {
		Self::Ip {
			addr,
			port: None,
		}
	}
}

impl From<Ipv4Addr> for SocketAddr {
	fn from(addr: Ipv4Addr) -> Self {
		Self::Ip {
			addr: addr.into(),
			port: None,
		}
	}
}

impl From<Ipv6Addr> for SocketAddr {
	fn from(addr: Ipv6Addr) -> Self {
		Self::Ip {
			addr: addr.into(),
			port: None,
		}
	}
}

impl From<SocketAddrV4> for SocketAddr {
	fn from(addr: SocketAddrV4) -> Self {
		Self::Ip {
			addr: (*addr.ip()).into(),
			port: Some(addr.port()),
		}
	}
}

impl From<SocketAddrV6> for SocketAddr {
	fn from(addr: SocketAddrV6) -> Self {
		Self::Ip {
			addr: (*addr.ip()).into(),
			port: Some(addr.port()),
		}
	}
}

impl From<std::net::SocketAddr> for SocketAddr {
	fn from(addr: std::net::SocketAddr) -> Self {
		Self::Ip {
			addr: addr.ip(),
			port: Some(addr.port()),
		}
	}
}

impl From<PathBuf> for SocketAddr {
	fn from(path: PathBuf) -> Self {
		Self::Unix { path }
	}
}

#[cfg(unix)]
impl<'a> TryFrom<&'a std::os::unix::net::SocketAddr> for SocketAddr {
	type Error = ();

	fn try_from(addr: &std::os::unix::net::SocketAddr) -> Result<Self, Self::Error> {
		if let Some(path) = addr.as_pathname() {
			Ok(Self::Unix {
				path: path.to_owned(),
			})
		}
		else {
			Err(())
		}
	}
}

#[cfg(unix)]
impl TryFrom<std::os::unix::net::SocketAddr> for SocketAddr {
	type Error = std::os::unix::net::SocketAddr;

	fn try_from(addr: std::os::unix::net::SocketAddr) -> Result<Self, Self::Error> {
		match SocketAddr::try_from(&addr) {
			Ok(ok) => Ok(ok),
			Err(()) => Err(addr),
		}
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

#[test]
fn test_serde() {
	let mut abs_unix_path = std::env::current_dir().unwrap();
	abs_unix_path.push("foo");

	let rel_unix_path = format!(".{}foo", std::path::MAIN_SEPARATOR);

	for (addr, expected_serialization, expected_roundtrip) in [
		(
			SocketAddr::Ip {
				addr: Ipv4Addr::LOCALHOST.into(),
				port: Some(27910),
			},
			"127.0.0.1:27910",
			None,
		),

		(
			SocketAddr::Ip {
				addr: Ipv4Addr::LOCALHOST.into(),
				port: None,
			},
			"127.0.0.1",
			None,
		),

		(
			SocketAddr::Ip {
				addr: Ipv4Addr::LOCALHOST.into(),
				port: Some(0),
			},
			"127.0.0.1:0",
			None,
		),

		(
			SocketAddr::Ip {
				addr: Ipv6Addr::from(0x2607_f8b0_400a_0804_0000_0000_0000_200e_u128).into(),
				port: Some(27910),
			},
			"[2607:f8b0:400a:804::200e]:27910",
			None,
		),

		(
			SocketAddr::Ip {
				addr: Ipv6Addr::from(0x2607_f8b0_400a_0804_0000_0000_0000_200e_u128).into(),
				port: Some(0),
			},
			"[2607:f8b0:400a:804::200e]:0",
			None,
		),

		(
			SocketAddr::Ip {
				addr: Ipv6Addr::from(0x2607_f8b0_400a_0804_0000_0000_0000_200e_u128).into(),
				port: None,
			},
			"2607:f8b0:400a:804::200e",
			None,
		),

		(
			// If `SocketAddr::Unix::path` is a plain relative path with no recognized prefix, a prefix will be added, and preserved upon round trip.
			SocketAddr::Unix {
				path: "foo".into(),
			},

			&rel_unix_path,

			Some(SocketAddr::Unix {
				path: rel_unix_path.clone().into(),
			}),
		),

		(
			SocketAddr::Unix {
				path: abs_unix_path.clone(),
			},
			abs_unix_path.to_str().unwrap(),
			None,
		),

		(
			SocketAddr::Inherit {
				socket: 31337,
			},

			#[cfg(windows)]
			"socket:31337",

			#[cfg(not(windows))]
			"fd:31337",

			None,
		),

		(
			SocketAddr::InheritStdin,
			"stdin",
			None,
		),

		#[cfg(not(windows))]
		(
			SocketAddr::SystemdNumeric {
				socket: 3,
			},
			"systemd:3",
			None,
		),
	] {
		let expected_roundtrip: &SocketAddr = expected_roundtrip.as_ref().unwrap_or(&addr);

		assert_eq!(addr.to_string(), expected_serialization);
		assert_eq!(&SocketAddr::from_str(expected_serialization).unwrap(), expected_roundtrip);

		#[cfg(feature = "serde")] {
			let serialized = serde_json::to_value(&addr).unwrap();
			assert_matches!(
				&serialized,
				serde_json::Value::String(string)
				if string == expected_serialization
			);

			assert_eq!(
				&serde_json::from_value::<SocketAddr>(serialized).unwrap(),
				expected_roundtrip,
			);
		}
	}
}
