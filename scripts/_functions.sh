# This is mostly the same set of target platforms that the socket2 crate supports, but with the following changes:
#
# * x86_64-pc-solaris is currently excluded, because the nix crate does not yet work on that platform. See tracking issue <https://github.com/nix-rust/nix/issues/935>.
all_targets="aarch64-apple-ios aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-apple-darwin x86_64-pc-windows-msvc x86_64-unknown-freebsd x86_64-unknown-fuchsia x86_64-unknown-illumos x86_64-unknown-linux-gnu x86_64-unknown-linux-musl x86_64-unknown-netbsd x86_64-unknown-redox"
