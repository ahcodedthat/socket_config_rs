# socket_config — Set up sockets according to command line option or configuration file

This library sets up sockets in a way that can be controlled by the user of your application, such as through a command-line option or configuration file.

For example, your application might take a command-line option <code>--listen=<var>SOCKET</var></code>, where <code><var>SOCKET</var></code> is a socket address that this library parses. Socket addresses can take forms like `127.0.0.1:12345` (IPv4), `[::1]:12345` (IPv6), `./my.socket` ([Unix-domain](https://en.wikipedia.org/wiki/Unix_domain_socket)), or `fd:3` (Unix file descriptor or Windows socket handle inherited from the parent process).

This library primarily opens `socket2::Socket`s. The `convert` module contains utilities to convert those sockets to standard library socket types (like `std::net::TcpListener`) or Tokio socket types (like `tokio::net::TcpListener`). This library also has a utility function for preparing a socket to be inherited by a child process.
