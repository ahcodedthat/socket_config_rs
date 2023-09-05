use crate::RawSocket;
use once_cell::sync::Lazy;
use std::{env, process};

type Pid = u32;

pub(crate) const SD_LISTEN_FDS_START: RawSocket = 3;

pub(crate) static SD_LISTEN_FDS_END: Lazy<Option<RawSocket>> = Lazy::new(|| {
	let expected_pid: Pid =
		env::var("LISTEN_PID")
		.ok()?
		.parse()
		.ok()?;

	let actual_pid: Pid = process::id();

	if actual_pid != expected_pid {
		return None;
	}

	let total_listen_fds =
		env::var("LISTEN_FDS")
		.ok()?
		.parse()
		.ok()
		.filter(|count| *count >= 1)?;

	let listen_fds_end = SD_LISTEN_FDS_START.saturating_add(total_listen_fds);

	Some(listen_fds_end)
});
