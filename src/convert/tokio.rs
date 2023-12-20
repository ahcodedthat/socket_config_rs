use crate::{
	convert::AnyStdSocket,
	errors::IntoTokioError,
};
use pin_project::pin_project;
use socket2::{SockAddr, Socket};
use std::{
	io,
	pin::Pin,
	task,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(unix)]
use std::path::Path;

#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, AsSocket, BorrowedSocket, RawSocket};

#[cfg(not(windows))]
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};

#[cfg(unix)]
fn unix_sockaddr_into(addr: tokio::net::unix::SocketAddr) -> SockAddr {
	let pathname =
		addr.as_pathname()
		.unwrap_or(Path::new(""));

	SockAddr::unix(pathname)
	.expect("unexpected error constructing a Unix-domain socket address that's already known to be valid")
}

/// A [stream-type][socket2::Type::STREAM] listening socket, either TCP or Unix-domain, adapted for use with [`tokio`].
///
/// Much like [`tokio::net::TcpListener`], an `AnyTokioListener` is used to accept connections using the [`accept`][Self::accept] or [`poll_accept`][Self::poll_accept] method.
///
///
/// # Example
///
/// The main way to use this is to open a [`socket2::Socket`] and then convert it into an `AnyTokioListener`, like this:
///
/// ```no_run
/// # use socket_config::convert::{AnyTokioListener, AnyTokioStream};
/// # use std::io;
/// # async fn example_fn() -> io::Result<()> {
/// # let address: socket_config::SocketAddr = unimplemented!();
/// # let app_options: socket_config::SocketAppOptions<'static> = unimplemented!();
/// # let user_options: socket_config::SocketUserOptions = unimplemented!();
/// let socket: AnyTokioListener = socket_config::open(
/// 	&address,
/// 	&app_options,
/// 	&user_options,
/// )?.try_into()?;
///
/// loop {
/// 	let (connection, peer_addr): (AnyTokioStream, socket2::SockAddr) =
/// 		socket.accept().await?;
///
/// 	// …do something with the connection…
/// }
/// # Ok(())
/// # }
/// ```
///
/// This opens a socket using [`open`][crate::open()] and then converts it into an `AnyTokioListener`, then accepts connections as [`AnyTokioStream`]s.
///
/// The call to `try_into` will fail with an [`IntoTokioError`] if the socket is inappropriate, such as a UDP socket.
///
///
/// # Availability
///
/// All platforms, but the `Unix` variant is only available on Unix-like platforms. Converting a Unix-domain socket on Windows will result in an error.
///
/// Requires the `tokio` feature.
#[derive(Debug, derive_more::From)]
#[non_exhaustive]
pub enum AnyTokioListener {
	/// A TCP listening socket.
	///
	/// # Availability
	///
	/// All platforms.
	Tcp(tokio::net::TcpListener),

	/// A Unix-domain [stream-type][socket2::Type::STREAM] listening socket.
	///
	/// # Availability
	///
	/// Unix-like platforms only. Tokio currently does not support Unix-domain sockets on Windows.
	#[cfg(unix)] Unix(tokio::net::UnixListener),
}

impl AnyTokioListener {
	/// Accepts a new connection.
	///
	#[cfg_attr(unix, doc = r#"This method delegates to [`tokio::net::TcpListener::accept`] or [`tokio::net::UnixListener::accept`], as appropriate."#)]
	#[cfg_attr(not(unix), doc = r#"This method delegates to [`tokio::net::TcpListener::accept`]."#)]
	pub async fn accept(&self) -> io::Result<(AnyTokioStream, SockAddr)> {
		match self {
			Self::Tcp(l) => l.accept().await.map(Self::accept_tcp),
			#[cfg(unix)] Self::Unix(l) => l.accept().await.map(Self::accept_unix),
		}
	}

	/// Polls to accept a new connection.
	///
	#[cfg_attr(unix, doc = r#"This method delegates to [`tokio::net::TcpListener::poll_accept`] or [`tokio::net::UnixListener::poll_accept`], as appropriate."#)]
	#[cfg_attr(not(unix), doc = r#"This method delegates to [`tokio::net::TcpListener::poll_accept`]."#)]
	pub fn poll_accept(&self, cx: &mut task::Context<'_>) -> task::Poll<io::Result<(AnyTokioStream, SockAddr)>> {
		match self {
			Self::Tcp(l) => l.poll_accept(cx).map_ok(Self::accept_tcp),
			#[cfg(unix)] Self::Unix(l) => l.poll_accept(cx).map_ok(Self::accept_unix),
		}
	}

	fn accept_tcp(
		(socket, addr): (tokio::net::TcpStream, std::net::SocketAddr),
	) -> (AnyTokioStream, SockAddr) {
		(socket.into(), addr.into())
	}

	#[cfg(unix)]
	fn accept_unix(
		(socket, addr): (tokio::net::UnixStream, tokio::net::unix::SocketAddr),
	) -> (AnyTokioStream, SockAddr) {
		(socket.into(), unix_sockaddr_into(addr))
	}

	/// Returns the local address that this listener is bound to.
	///
	#[cfg_attr(unix, doc = r#"This method delegates to [`tokio::net::TcpListener::local_addr`] or [`tokio::net::UnixListener::local_addr`], as appropriate."#)]
	#[cfg_attr(not(unix), doc = r#"This method delegates to [`tokio::net::TcpListener::local_addr`]."#)]
	pub fn local_addr(&self) -> io::Result<SockAddr> {
		match self {
			Self::Tcp(l) => l.local_addr().map(SockAddr::from),
			#[cfg(unix)] Self::Unix(l) => l.local_addr().map(unix_sockaddr_into),
		}
	}
}

impl TryFrom<AnyStdSocket> for AnyTokioListener {
	type Error = IntoTokioError;

	fn try_from(socket: AnyStdSocket) -> Result<Self, Self::Error> {
		match socket {
			AnyStdSocket::TcpListener(l) => {
				l.set_nonblocking(true)
				.map_err(|error| IntoTokioError::SetNonBlocking { error })?;

				let l = l.try_into().map_err(|error| IntoTokioError::Wrap { error })?;

				Ok(Self::Tcp(l))
			}

			#[cfg(unix)]
			AnyStdSocket::UnixListener(l) => {
				l.set_nonblocking(true)
				.map_err(|error| IntoTokioError::SetNonBlocking { error })?;

				let l = l.try_into().map_err(|error| IntoTokioError::Wrap { error })?;

				Ok(Self::Unix(l))
			}

			_ => Err(IntoTokioError::Inappropriate {
				socket,
			}),
		}
	}
}

impl TryFrom<Socket> for AnyTokioListener {
	type Error = IntoTokioError;

	fn try_from(socket: Socket) -> Result<Self, Self::Error> {
		let socket: AnyStdSocket =
			socket.try_into()
			.map_err(|error| IntoTokioError::Check { error })?;

		socket.try_into()
	}
}

impl TryFrom<AnyTokioListener> for Socket {
	type Error = io::Error;

	fn try_from(l: AnyTokioListener) -> Result<Self, Self::Error> {
		match l {
			AnyTokioListener::Tcp(l) => l.into_std().map(Socket::from),
			#[cfg(unix)] AnyTokioListener::Unix(l) => l.into_std().map(Socket::from),
		}
	}
}

#[cfg(feature = "futures")]
impl futures::Stream for AnyTokioListener {
	type Item = io::Result<AnyTokioStream>;

	fn poll_next(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Option<Self::Item>> {
		self.poll_accept(cx)
		.map_ok(|(s, _)| s)
		.map(Some)
	}
}

#[cfg(feature = "tls-listener")]
impl tls_listener::AsyncAccept for AnyTokioListener {
	type Connection = AnyTokioStream;
	type Address = SockAddr;
	type Error = io::Error;

	fn poll_accept(
		self: Pin<&mut Self>,
		cx: &mut task::Context,
	) -> task::Poll<Result<(Self::Connection, Self::Address), Self::Error>> {
		(&*self).poll_accept(cx)
	}
}

#[cfg(not(windows))]
impl AsFd for AnyTokioListener {
	fn as_fd(&self) -> BorrowedFd {
		match self {
			Self::Tcp(l) => l.as_fd(),
			#[cfg(unix)] Self::Unix(l) => l.as_fd(),
		}
	}
}

#[cfg(not(windows))]
impl AsRawFd for AnyTokioListener {
	fn as_raw_fd(&self) -> RawFd {
		match self {
			Self::Tcp(l) => l.as_raw_fd(),
			#[cfg(unix)] Self::Unix(l) => l.as_raw_fd(),
		}
	}
}

#[cfg(windows)]
impl AsRawSocket for AnyTokioListener {
	fn as_raw_socket(&self) -> RawSocket {
		match self {
			Self::Tcp(l) => l.as_raw_socket(),
		}
	}
}

#[cfg(windows)]
impl AsSocket for AnyTokioListener {
	fn as_socket(&self) -> BorrowedSocket {
		match self {
			Self::Tcp(l) => l.as_socket(),
		}
	}
}

/// A connected [stream-type][socket2::Type::STREAM] socket, either TCP or Unix-domain, adapted for use with [`tokio`].
///
/// `AnyTokioStream`s are usually obtained from a call to [`AnyTokioListener::accept`]. This type implements [`AsyncRead`] and [`AsyncWrite`], and is used to communicate with the connected peer in much the same way as a [`tokio::net::TcpStream`].
///
///
/// # Availability
///
/// All platforms, but the `Unix` variant is only available on Unix-like platforms. Converting a Unix-domain socket on Windows will result in an error.
///
/// Requires the `tokio` feature.
#[derive(Debug, derive_more::From)]
#[pin_project(project = AnyTokioStreamProj)]
pub enum AnyTokioStream {
	/// A connected TCP socket.
	///
	/// # Availability
	///
	/// All platforms.
	Tcp(#[pin] tokio::net::TcpStream),

	/// A connected Unix-domain [stream-type][socket2::Type::STREAM] socket.
	///
	/// # Availability
	///
	/// Unix-like platforms only. Tokio currently does not support Unix-domain sockets on Windows.
	#[cfg(unix)] Unix(#[pin] tokio::net::UnixStream),
}

impl AnyTokioStream {
	/// Returns the local address that this socket is bound to.
	///
	#[cfg_attr(unix, doc = r#"This method delegates to [`tokio::net::TcpStream::local_addr`] or [`tokio::net::UnixStream::local_addr`], as appropriate."#)]
	#[cfg_attr(not(unix), doc = r#"This method delegates to [`tokio::net::TcpStream::local_addr`]."#)]
	pub fn local_addr(&self) -> io::Result<SockAddr> {
		match self {
			Self::Tcp(s) => s.local_addr().map(SockAddr::from),
			#[cfg(unix)] Self::Unix(s) => s.local_addr().map(unix_sockaddr_into),
		}
	}

	/// Returns the remote address that this socket is connected to.
	///
	#[cfg_attr(unix, doc = r#"This method delegates to [`tokio::net::TcpStream::peer_addr`] or [`tokio::net::UnixStream::peer_addr`], as appropriate."#)]
	#[cfg_attr(not(unix), doc = r#"This method delegates to [`tokio::net::TcpStream::peer_addr`]."#)]
	pub fn peer_addr(&self) -> io::Result<SockAddr> {
		match self {
			Self::Tcp(s) => s.peer_addr().map(SockAddr::from),
			#[cfg(unix)] Self::Unix(s) => s.peer_addr().map(unix_sockaddr_into),
		}
	}
}

impl AsyncRead for AnyTokioStream {
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut task::Context,
		buf: &mut ReadBuf,
	) -> task::Poll<io::Result<()>> {
		match self.project() {
			AnyTokioStreamProj::Tcp(s) => s.poll_read(cx, buf),
			#[cfg(unix)] AnyTokioStreamProj::Unix(s) => s.poll_read(cx, buf),
		}
	}
}

impl AsyncWrite for AnyTokioStream {
	fn poll_write(
		self: Pin<&mut Self>,
		cx: &mut task::Context,
		buf: &[u8],
	) -> task::Poll<Result<usize, io::Error>> {
		match self.project() {
			AnyTokioStreamProj::Tcp(s) => s.poll_write(cx, buf),
			#[cfg(unix)] AnyTokioStreamProj::Unix(s) => s.poll_write(cx, buf),
		}
	}

	fn poll_flush(
		self: Pin<&mut Self>,
		cx: &mut task::Context,
	) -> task::Poll<Result<(), io::Error>> {
		match self.project() {
			AnyTokioStreamProj::Tcp(s) => s.poll_flush(cx),
			#[cfg(unix)] AnyTokioStreamProj::Unix(s) => s.poll_flush(cx),
		}
	}

	fn poll_shutdown(
		self: Pin<&mut Self>,
		cx: &mut task::Context,
	) -> task::Poll<Result<(), io::Error>> {
		match self.project() {
			AnyTokioStreamProj::Tcp(s) => s.poll_shutdown(cx),
			#[cfg(unix)] AnyTokioStreamProj::Unix(s) => s.poll_shutdown(cx),
		}
	}

	fn poll_write_vectored(
		self: Pin<&mut Self>,
		cx: &mut task::Context,
		bufs: &[io::IoSlice],
	) -> task::Poll<Result<usize, io::Error>> {
		match self.project() {
			AnyTokioStreamProj::Tcp(s) => s.poll_write_vectored(cx, bufs),
			#[cfg(unix)] AnyTokioStreamProj::Unix(s) => s.poll_write_vectored(cx, bufs),
		}
	}

	fn is_write_vectored(&self) -> bool {
		match self {
			Self::Tcp(s) => s.is_write_vectored(),
			#[cfg(unix)] Self::Unix(s) => s.is_write_vectored(),
		}
	}
}

impl TryFrom<AnyStdSocket> for AnyTokioStream {
	type Error = IntoTokioError;

	fn try_from(socket: AnyStdSocket) -> Result<Self, Self::Error> {
		match socket {
			AnyStdSocket::TcpStream(s) => {
				s.set_nonblocking(true)
				.map_err(|error| IntoTokioError::SetNonBlocking { error })?;

				let s = s.try_into().map_err(|error| IntoTokioError::Wrap { error })?;

				Ok(Self::Tcp(s))
			}

			#[cfg(unix)]
			AnyStdSocket::UnixStream(s) => {
				s.set_nonblocking(true)
				.map_err(|error| IntoTokioError::SetNonBlocking { error })?;

				let s = s.try_into().map_err(|error| IntoTokioError::Wrap { error })?;

				Ok(Self::Unix(s))
			}

			_ => Err(IntoTokioError::Inappropriate {
				socket,
			}),
		}
	}
}

impl TryFrom<Socket> for AnyTokioStream {
	type Error = IntoTokioError;

	fn try_from(socket: Socket) -> Result<Self, Self::Error> {
		let socket: AnyStdSocket =
			socket.try_into()
			.map_err(|error| IntoTokioError::Check { error })?;

		socket.try_into()
	}
}

impl TryFrom<AnyTokioStream> for Socket {
	type Error = io::Error;

	fn try_from(socket: AnyTokioStream) -> Result<Self, Self::Error> {
		match socket {
			AnyTokioStream::Tcp(s) => s.into_std().map(Socket::from),
			#[cfg(unix)] AnyTokioStream::Unix(s) => s.into_std().map(Socket::from),
		}
	}
}

#[cfg(not(windows))]
impl AsFd for AnyTokioStream {
	fn as_fd(&self) -> BorrowedFd {
		match self {
			Self::Tcp(s) => s.as_fd(),
			#[cfg(unix)] Self::Unix(s) => s.as_fd(),
		}
	}
}

#[cfg(not(windows))]
impl AsRawFd for AnyTokioStream {
	fn as_raw_fd(&self) -> RawFd {
		match self {
			Self::Tcp(s) => s.as_raw_fd(),
			#[cfg(unix)] Self::Unix(s) => s.as_raw_fd(),
		}
	}
}

#[cfg(windows)]
impl AsRawSocket for AnyTokioStream {
	fn as_raw_socket(&self) -> RawSocket {
		match self {
			Self::Tcp(s) => s.as_raw_socket(),
		}
	}
}

#[cfg(windows)]
impl AsSocket for AnyTokioStream {
	fn as_socket(&self) -> BorrowedSocket {
		match self {
			Self::Tcp(s) => s.as_socket(),
		}
	}
}
