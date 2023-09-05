//! Security attributes for Unix-like platforms.
//!
//! # Availability
//!
//! Unix-like platforms only.

use crate::{
	errors::{
		OpenSocketError,
		UnixSocketPermissionsParseError,
	},
	SocketUserOptions,
	util::check_inapplicable,
};
use libc::{gid_t, mode_t, uid_t};
use nix::{
	sys::stat::Mode,
	unistd::{chown, Gid, Group, Uid, User},
};
use std::{
	convert::Infallible,
	fmt::{self, Debug, Display, Formatter},
	fs,
	os::unix::fs::PermissionsExt,
	path::Path,
	str::FromStr,
};

/// Newtype wrapper around a Unix [`Mode`]. Parses as either a number or a string containing any combination of the letters `u`, `g`, and `o`.
#[derive(derive_more::AsRef, derive_more::AsMut, Clone, Copy, Debug, derive_more::Deref, Eq, derive_more::From, derive_more::Into, PartialEq)]
pub struct UnixSocketPermissions(pub Mode);

impl FromStr for UnixSocketPermissions {
	type Err = UnixSocketPermissionsParseError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if let Ok(i) = mode_t::from_str_radix(s, 8) {
			i.try_into()
		}
		else {
			let mut mode = Mode::empty();

			for byte in s.bytes() {
				mode |= match byte {
					b'-' => Mode::empty(),
					b'u' => Mode::S_IRUSR | Mode::S_IWUSR,
					b'g' => Mode::S_IRGRP | Mode::S_IWGRP,
					b'o' => Mode::S_IROTH | Mode::S_IWOTH,
					_ => return Err(UnixSocketPermissionsParseError),
				};
			}

			Ok(Self(mode))
		}
	}
}

impl TryFrom<mode_t> for UnixSocketPermissions {
	type Error = UnixSocketPermissionsParseError;

	fn try_from(value: mode_t) -> Result<Self, Self::Error> {
		Mode::from_bits(value)
		.ok_or(UnixSocketPermissionsParseError)
		.map(Self)
	}
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for UnixSocketPermissions {
	fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
		struct Visitor;

		impl Visitor {
			fn visit_int<'de, T, E>(self, v: T) -> Result<<Self as serde::de::Visitor<'de>>::Value, E>
			where
				T: Copy + std::fmt::Octal + TryInto<mode_t>,
				E: serde::de::Error,
			{
				(|| {
					let mode: mode_t =
						v.try_into()
						.map_err(|_| ())?;

					let mode: Mode =
						Mode::from_bits(mode)
						.ok_or(())?;

					Ok(UnixSocketPermissions(mode))
				})().map_err(|()| E::invalid_value(
					serde::de::Unexpected::Other(&format!("out-of-range numeric Unix mode {v:o}")),
					&self,
				))
			}
		}

		impl<'de> serde::de::Visitor<'de> for Visitor {
			type Value = UnixSocketPermissions;

			fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
				write!(f, "a numeric Unix mode or a string containing some combination of the letters `u`, `g`, and `o`")
			}

			fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
				UnixSocketPermissions::from_str(v)
				.map_err(|_| E::invalid_value(
					serde::de::Unexpected::Str(v),
					&self,
				))
			}

			fn visit_i128<E: serde::de::Error>(self, v: i128) -> Result<Self::Value, E> {
				self.visit_int(v)
			}

			fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
				self.visit_int(v)
			}

			fn visit_u128<E: serde::de::Error>(self, v: u128) -> Result<Self::Value, E> {
				self.visit_int(v)
			}

			fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
				self.visit_int(v)
			}
		}

		de.deserialize_any(Visitor)
	}
}

#[test]
fn test_unix_socket_permissions_parse() {
	assert_eq!(
		UnixSocketPermissions::from_str("644").unwrap(),
		UnixSocketPermissions(Mode::from_bits(0o644).unwrap()),
	);

	let _ = UnixSocketPermissions::from_str("77777").unwrap_err();

	#[cfg(feature = "serde")]
	assert_eq!(
		serde_json::from_str::<UnixSocketPermissions>("420").unwrap(),
		UnixSocketPermissions(Mode::from_bits(420).unwrap()),
	);

	for (string, bits) in [
		("", 0),
		("u", 0o600),
		("g", 0o060),
		("ug", 0o660),
		("o", 0o006),
		("uo", 0o606),
		("go", 0o066),
		("ugo", 0o666),
	] {
		assert_eq!(
			UnixSocketPermissions::from_str(string).unwrap().0.bits(),
			bits,
		);

		#[cfg(feature = "serde")]
		for json_repr in [
			format!("\"{string}\""),
			format!("{bits}"),
			format!("\"{bits:o}\""),
		] {
			assert_eq!(
				serde_json::from_str::<UnixSocketPermissions>(&json_repr).unwrap().0.bits(),
				bits,
			);
		}
	}
}

/// Identifies a Unix user or group (collectively a “principal”), by either name or numeric ID, for the purposes of Unix-domain socket ownership.
///
/// The parameter type `I` is the numeric identifier, typically `uid_t` or `gid_t`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize), serde(untagged))]
pub enum UnixPrincipal<I> {
	/// Identifies a Unix principal by numeric ID.
	Id(I),

	/// Identifies a Unix principal by name.
	Name(String),
}

impl<I> FromStr for UnixPrincipal<I>
where
	I: FromStr,
{
	type Err = Infallible;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if let Ok(id) = I::from_str(s) {
			Ok(Self::Id(id))
		}
		else {
			Ok(Self::Name(s.to_owned()))
		}
	}
}

impl<I> Display for UnixPrincipal<I>
where
	I: Display,
{
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		match self {
			Self::Id(id) => Display::fmt(id, f),
			Self::Name(name) => Display::fmt(name, f),
		}
	}
}

/// Identifies a Unix user, by either name or numeric ID, for the purposes of Unix-domain socket ownership.
pub type UnixUser = UnixPrincipal<uid_t>;

/// Identifies a Unix group, by either name or numeric ID, for the purposes of Unix-domain socket ownership.
pub type UnixGroup = UnixPrincipal<gid_t>;

pub(crate) struct PreparedUnixSecurityAttributes<'a> {
	socket_path: &'a Path,
	owner: Option<Uid>,
	group: Option<Gid>,
	mode: Option<Mode>,
}

impl<'a> PreparedUnixSecurityAttributes<'a> {
	pub(crate) fn new(
		socket_path: Option<&'a Path>,
		options: &SocketUserOptions,
	) -> Result<Option<Self>, OpenSocketError> {
		let Some(socket_path) = socket_path else {
			// If the socket in question is not path-based, then we can't apply security attributes to it, so just make sure none of the security-attribute-related options were used.

			check_inapplicable(options.unix_socket_owner.as_ref(), "unix_socket_owner")?;
			check_inapplicable(options.unix_socket_group.as_ref(), "unix_socket_group")?;
			check_inapplicable(options.unix_socket_permissions, "unix_socket_permissions")?;

			return Ok(None)
		};

		// Look up any user and/or group names that were given.
		let owner: Option<Uid> =
			options.unix_socket_owner.as_ref()
			.map(|owner| match owner {
				UnixUser::Id(id) => Ok(Uid::from_raw(*id)),
				UnixUser::Name(name) => match User::from_name(name) {
					Ok(Some(user)) => Ok(user.uid),
					Ok(None) => Err(OpenSocketError::OwnerNotFound),
					Err(error) => Err(OpenSocketError::LookupOwner {
						error: error.into(),
					}),
				},
			})
			.transpose()?;

		let group: Option<Gid> =
			options.unix_socket_group.as_ref()
			.map(|group| match group {
				UnixGroup::Id(id) => Ok(Gid::from_raw(*id)),
				UnixGroup::Name(name) => match Group::from_name(name) {
					Ok(Some(group)) => Ok(group.gid),
					Ok(None) => Err(OpenSocketError::UnixGroupNotFound),
					Err(error) => Err(OpenSocketError::LookupUnixGroup {
						error: error.into(),
					}),
				},
			})
			.transpose()?;

		let mode: Option<Mode> =
			options.unix_socket_permissions
			.map(|perms| perms.0);

		if owner.is_none() && group.is_none() && mode.is_none() {
			return Ok(None);
		}

		Ok(Some(Self {
			socket_path,
			owner,
			group,
			mode,
		}))
	}

	pub(crate) fn apply(self) -> Result<(), OpenSocketError> {
		if self.owner.is_some() || self.group.is_some() {
			chown(self.socket_path, self.owner, self.group)
			.map_err(|error| OpenSocketError::SetOwner {
				error: error.into(),
			})?;
		}

		if let Some(mode) = self.mode {
			let permissions = fs::Permissions::from_mode(mode.bits());

			fs::set_permissions(self.socket_path, permissions)
			.map_err(|error| OpenSocketError::SetPermissions { error })?;
		}

		Ok(())
	}
}
