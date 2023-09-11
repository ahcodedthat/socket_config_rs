use crate::{
	errors::OpenSocketError,
	SocketUserOptions,
	util::check_inapplicable,
};
use nix::unistd::chown;
use socket2::Socket;
use std::{
	fs,
	os::unix::fs::PermissionsExt,
	path::Path,
};

#[cfg(any(feature = "clap", feature = "serde"))]
mod parse_common {
	use libc::{gid_t, mode_t, uid_t};
	use nix::{
		sys::stat::Mode,
		unistd::{Gid, Group, Uid, User},
	};

	#[derive(Debug, thiserror::Error)]
	#[error("unrecognized character in `unix_socket_permissions` (only the letters `u`, `g`, and `o`, or an octal mode number, are recognized)")]
	pub struct UnixSocketPermissionsParseError;

	pub fn parse_mode(mode_str: &str) -> Result<Mode, UnixSocketPermissionsParseError> {
		if let Ok(i) = mode_t::from_str_radix(mode_str, 8) {
			Mode::from_bits(i)
			.ok_or(UnixSocketPermissionsParseError)
		}
		else {
			let mut mode = Mode::empty();

			for byte in mode_str.bytes() {
				mode |= match byte {
					b'-' => Mode::empty(),
					b'u' => Mode::S_IRUSR | Mode::S_IWUSR,
					b'g' => Mode::S_IRGRP | Mode::S_IWGRP,
					b'o' => Mode::S_IROTH | Mode::S_IWOTH,
					_ => return Err(UnixSocketPermissionsParseError),
				};
			}

			Ok(mode)
		}
	}

	#[test]
	fn test_parse_mode() {
		assert_eq!(
			parse_mode("644").unwrap(),
			Mode::from_bits(0o644).unwrap(),
		);

		let _ = parse_mode("77777").unwrap_err();

		#[cfg(feature = "serde")]
		#[derive(Debug, serde::Deserialize, Eq, PartialEq)]
		struct ModeDeser(
			#[serde(with = "serde_with::As::<super::DeserMode>")]
			Mode
		);

		#[cfg(feature = "serde")]
		assert_eq!(
			serde_json::from_str::<ModeDeser>("420").unwrap(),
			ModeDeser(Mode::from_bits(420).unwrap()),
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
				parse_mode(string).unwrap().bits(),
				bits,
			);

			#[cfg(feature = "serde")]
			for json_repr in [
				format!("\"{string}\""),
				format!("{bits}"),
				format!("\"{bits:o}\""),
			] {
				assert_eq!(
					serde_json::from_str::<ModeDeser>(&json_repr).unwrap().0.bits(),
					bits,
				);
			}
		}
	}

	#[cfg_attr(feature = "serde", derive(serde::Deserialize), serde(rename = "UnixPrincipal", untagged))]
	pub(super) enum DeserUnixPrincipal<'a, I> {
		Id(I),
		Name(&'a str),
	}

	impl<'a> DeserUnixPrincipal<'a, uid_t> {
		pub(super) fn to_uid(self) -> Result<Uid, UnixPrincipalLookupError> {
			match self {
				Self::Id(id) => Ok(Uid::from_raw(id)),
				Self::Name(name) => match User::from_name(name) {
					Ok(Some(user)) => Ok(user.uid),
					Ok(None) => Err(UnixPrincipalLookupError::NotFound {
						principal_kind: UnixPrincipalKind::User,
					}),
					Err(error) => Err(UnixPrincipalLookupError::Error {
						principal_kind: UnixPrincipalKind::User,
						error,
					}),
				},
			}
		}
	}

	impl<'a> DeserUnixPrincipal<'a, gid_t> {
		pub(super) fn to_gid(self) -> Result<Gid, UnixPrincipalLookupError> {
			match self {
				Self::Id(id) => Ok(Gid::from_raw(id)),
				Self::Name(name) => match Group::from_name(name) {
					Ok(Some(group)) => Ok(group.gid),
					Ok(None) => Err(UnixPrincipalLookupError::NotFound {
						principal_kind: UnixPrincipalKind::Group,
					}),
					Err(error) => Err(UnixPrincipalLookupError::Error {
						principal_kind: UnixPrincipalKind::Group,
						error,
					}),
				},
			}
		}
	}

	#[derive(Clone, Copy, Debug, derive_more::Display, Eq, PartialEq)]
	pub enum UnixPrincipalKind {
		#[display(fmt = "user")]
		User,

		#[display(fmt = "group")]
		Group,
	}

	#[derive(Debug, thiserror::Error)]
	pub enum UnixPrincipalLookupError {
		#[error("{principal_kind} not found")]
		NotFound {
			principal_kind: UnixPrincipalKind,
		},

		#[error("error looking up {principal_kind} ID: {error}")]
		Error {
			principal_kind: UnixPrincipalKind,

			#[source]
			error: nix::Error,
		},
	}

	#[test]
	fn test_principal_parse_lookup() {
		use super::*;

		let my_uid = Uid::current();
		let my_user = User::from_uid(my_uid).unwrap().unwrap().name;
		let my_gid = Gid::current();
		let my_group = Group::from_gid(my_gid).unwrap().unwrap().name;

		#[cfg(feature = "clap")] {
			use assert_matches::assert_matches;

			assert_eq!(
				parse_uid(&format!("{my_uid}")).unwrap(),
				my_uid,
			);

			assert_eq!(
				parse_uid(&my_user).unwrap(),
				my_uid,
			);

			assert_eq!(
				parse_gid(&format!("{my_gid}")).unwrap(),
				my_gid,
			);

			assert_eq!(
				parse_gid(&my_group).unwrap(),
				my_gid,
			);

			assert_matches!(
				parse_uid("<imaginary user, looking up for testing, please ignore>"),
				Err(UnixPrincipalLookupError::NotFound {
					principal_kind: UnixPrincipalKind::User,
				})
			);

			assert_matches!(
				parse_gid("<imaginary group, looking up for testing, please ignore>"),
				Err(UnixPrincipalLookupError::NotFound {
					principal_kind: UnixPrincipalKind::Group,
				})
			);
		}

		#[cfg(feature = "serde")] {
			#[derive(Debug, serde::Deserialize, Eq, PartialEq)]
			struct UserAndGroup {
				#[serde(with = "serde_with::As::<DeserUid>")]
				user: Uid,

				#[serde(with = "serde_with::As::<DeserGid>")]
				group: Gid,
			}

			assert_eq!(
				serde_json::from_str::<UserAndGroup>(&format!(r#"{{
					"user": {my_uid},
					"group": {my_gid}
				}}"#)).unwrap(),

				UserAndGroup {
					user: my_uid,
					group: my_gid,
				},
			);

			assert_eq!(
				serde_json::from_str::<UserAndGroup>(&format!(r#"{{
					"user": "{my_user}",
					"group": "{my_group}"
				}}"#)).unwrap(),

				UserAndGroup {
					user: my_uid,
					group: my_gid,
				},
			);
		}
	}
}

#[cfg(any(feature = "clap", feature = "serde"))]
pub use self::parse_common::*;

#[cfg(feature = "clap")]
mod from_str {
	use libc::{gid_t, uid_t};
	use nix::unistd::{Gid, Uid};
	use std::str::FromStr;
	use super::*;

	pub fn parse_uid(user: &str) -> Result<Uid, UnixPrincipalLookupError> {
		let principal = {
			if let Ok(id) = uid_t::from_str(user) {
				DeserUnixPrincipal::Id(id)
			}
			else {
				DeserUnixPrincipal::Name(user)
			}
		};

		principal.to_uid()
	}

	pub fn parse_gid(group: &str) -> Result<Gid, UnixPrincipalLookupError> {
		let principal = {
			if let Ok(id) = gid_t::from_str(group) {
				DeserUnixPrincipal::Id(id)
			}
			else {
				DeserUnixPrincipal::Name(group)
			}
		};

		principal.to_gid()
	}
}

#[cfg(feature = "clap")]
pub use self::from_str::*;

#[cfg(feature = "serde")]
mod from_serde {
	use libc::{gid_t, mode_t, uid_t};
	use nix::{
		sys::stat::Mode,
		unistd::{Gid, Uid},
	};
	use serde::{
		de::Error as _,
		Deserialize,
		Deserializer,
	};
	use serde_with::DeserializeAs;
	use std::fmt;
	use super::*;

	pub struct DeserMode;
	impl<'de> DeserializeAs<'de, Mode> for DeserMode {
		fn deserialize_as<D: Deserializer<'de>>(de: D) -> Result<Mode, D::Error> {
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

						Ok(mode)
					})().map_err(|()| E::invalid_value(
						serde::de::Unexpected::Other(&format!("out-of-range numeric Unix mode {v:o}")),
						&self,
					))
				}
			}

			impl<'de> serde::de::Visitor<'de> for Visitor {
				type Value = Mode;

				fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
					write!(f, "a numeric Unix mode or a string containing some combination of the letters `u`, `g`, and `o`")
				}

				fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
					parse_mode(v)
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

	pub struct DeserUid;
	impl<'de> DeserializeAs<'de, Uid> for DeserUid {
		fn deserialize_as<D: Deserializer<'de>>(de: D) -> Result<Uid, D::Error> {
			let principal = DeserUnixPrincipal::<uid_t>::deserialize(de)?;

			principal.to_uid().map_err(D::Error::custom)
		}
	}

	pub struct DeserGid;
	impl<'de> DeserializeAs<'de, Gid> for DeserGid {
		fn deserialize_as<D: Deserializer<'de>>(de: D) -> Result<Gid, D::Error> {
			let principal = DeserUnixPrincipal::<gid_t>::deserialize(de)?;

			principal.to_gid().map_err(D::Error::custom)
		}
	}
}

#[cfg(feature = "serde")]
pub use self::from_serde::*;

pub fn prepare(
	options: &SocketUserOptions,
	socket_path: Option<&Path>,
) -> Result<(), OpenSocketError> {
	if let None = socket_path {
		check_inapplicable(options.unix_socket_permissions, "unix_socket_permissions")?;
		check_inapplicable(options.unix_socket_owner, "unix_socket_owner")?;
		check_inapplicable(options.unix_socket_group, "unix_socket_group")?;
	}

	Ok(())
}

pub fn apply(
	options: &SocketUserOptions,
	_socket: &Socket,
	socket_path: Option<&Path>,
) -> Result<(), OpenSocketError> {
	if let Some(socket_path) = socket_path {
		if options.unix_socket_owner.is_some() || options.unix_socket_group.is_some() {
			chown(socket_path, options.unix_socket_owner, options.unix_socket_group)
			.map_err(|error| OpenSocketError::SetOwner {
				error: error.into(),
			})?;
		}

		if let Some(mode) = options.unix_socket_permissions {
			let permissions = fs::Permissions::from_mode(mode.bits());

			fs::set_permissions(socket_path, permissions)
			.map_err(|error| OpenSocketError::SetPermissions { error })?;
		}
	}

	Ok(())
}
