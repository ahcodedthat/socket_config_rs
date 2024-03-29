//! This library sets up sockets in a way that can be controlled by the user of your application, such as through a command-line option or configuration file.
//!
//! For example, your application might take a command-line option <code>&#x2d;&#x2d;listen=<var>SOCKET</var></code>, where <code><var>SOCKET</var></code> is a socket address that this library parses. Socket addresses can take forms like `127.0.0.1:12345` (IPv4), `[::1]:12345` (IPv6), `./my.socket` ([Unix-domain](https://en.wikipedia.org/wiki/Unix_domain_socket)), or `fd:3` (Unix file descriptor or Windows socket handle inherited from the parent process). See the [`SocketAddr`] documentation for complete syntax.
//!
//!
//! # Usage
//!
//! The entry point of this library is the [`open`][open()] function, which accepts a socket address and a set of options, and opens a socket accordingly.
//!
//! `open` returns a [`socket2::Socket`], which can be used for ordinary blocking I/O. This library also has the [`AnyStdSocket`][crate::convert::AnyStdSocket] type in the [`convert`] module, which can be used to convert a `socket2::Socket` into one of the [standard library][std]'s socket types.
#![cfg_attr(feature = "tokio", doc = r#" For non-blocking I/O with [`tokio`], the `convert` module includes [`AnyTokioListener`][crate::convert::AnyTokioListener] and [`AnyTokioStream`][crate::convert::AnyTokioStream]."#)]
//!
//!
//! # Feature flags and platform support
//!
//! This library is based on [`socket2`], and should work on any platform that `socket2` works on. A list of platforms supported by `socket2` can be found on [its crates.io page](https://crates.io/crates/socket2).
//!
//! Some items in this crate are limited in which platforms they're available on, or behave differently on different platforms, or are only available if a particular feature flag is enabled. Such differences are noted with an “Availability” section in those items' documentation.
#![cfg_attr(all(
	feature = "clap",
	feature = "futures",
	feature = "serde",
	feature = "tokio",
), doc = r#"

## Available feature flags

This library has the following feature flags:

* `clap`: Support parsing socket options from the command line using [`clap`]. Specifically, this adds an implementation of [`clap::Args`] for [`SocketUserOptions`].
* `futures`: Adds an implementation of [`futures::Stream`] for [`AnyTokioListener`][crate::convert::AnyTokioListener]. Only works if the `tokio` feature is also enabled; otherwise, this feature does nothing.
* `serde`: Support parsing socket options from configuration files or environment variables using [`serde`]. Specifically, this adds an implementation of [`serde::Deserialize`] to [`SocketAddr`] and [`SocketUserOptions`].
* `tokio`: Adds the utility types [`AnyTokioListener`][crate::convert::AnyTokioListener] and [`AnyTokioStream`][crate::convert::AnyTokioStream].
"#)]
#![cfg_attr(feature = "clap", doc = concat!(r#"

# Examples

## Blocking I/O example

This is a [CHARGEN](https://en.wikipedia.org/wiki/Character_Generator_Protocol) server that accepts a single connection. It uses blocking I/O.

<details>
<summary>Click to show example</summary>

```no_run
"#, include_str!("../examples/chargen_once.rs"), r#"
```

</details>
"#))]
#![cfg_attr(all(feature = "clap", feature = "tokio"), doc = concat!(r#"

## Non-blocking I/O example

This is an [Echo](https://en.wikipedia.org/wiki/Echo_Protocol) server that modifies received bytes before echoing them. It uses Tokio non-blocking I/O.

<details>
<summary>Click to show example</summary>

```no_run
"#, include_str!("../examples/echo_incr.rs"), r#"
```

</details>
"#))]
//!
//!
//! # Related libraries
//!
//! * [`socket2`]: Basis of this library.
//! * [`tokio_listener`](https://crates.io/crates/tokio-listener): Inspired this library. This library has largely the same purpose as `tokio_listener`, but uses a different approach.

#![allow(clippy::tabs_in_doc_comments)] // This project uses tabs for indentation throughout, including in documentation examples.

mod addr;
pub mod convert;
pub mod errors;
mod open;
mod options;
#[cfg(unix)] mod unix_security;
mod util;

pub use self::{
	addr::*,
	open::*,
	options::*,
	util::*,
};

cfg_if::cfg_if! {
	if #[cfg(windows)] {
		#[path = "sys/windows.rs"] mod sys;
	}
	else {
		#[path = "sys/other.rs"] mod sys;
	}
}
