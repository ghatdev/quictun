use std::path::Path;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use quictun_core::config::Config;

use crate::state;

/// Check whether a process is still alive via `kill(pid, 0)`.
fn process_alive(pid: u32) -> bool {
    // SAFETY: kill with signal 0 is a standard existence check.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// Send a signal to a process.
fn send_signal(pid: u32, sig: libc::c_int) -> bool {
    // SAFETY: standard POSIX signal delivery.
    unsafe { libc::kill(pid as libc::pid_t, sig) == 0 }
}

pub fn run(config_path: &str) -> Result<()> {
    let config = Config::load(Path::new(config_path)).context("failed to load config")?;
    let iface_name = config.interface_name(Path::new(config_path));

    let pid = match state::read_pid_file(&iface_name)? {
        Some(pid) => pid,
        None => {
            println!("no PID file for interface '{iface_name}' — nothing to do");
            return Ok(());
        }
    };

    if !process_alive(pid) {
        println!("process {pid} is not running — removing stale PID file");
        state::remove_pid_file(&iface_name);
        return Ok(());
    }

    println!("sending SIGTERM to process {pid} (interface '{iface_name}')");
    if !send_signal(pid, libc::SIGTERM) {
        // Process vanished between check and signal — clean up.
        state::remove_pid_file(&iface_name);
        println!("process already exited");
        return Ok(());
    }

    // Poll for exit up to 5 seconds.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if !process_alive(pid) {
            state::remove_pid_file(&iface_name);
            println!("process {pid} exited gracefully");
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    // Still alive — escalate to SIGKILL.
    println!("process {pid} did not exit in 5s, sending SIGKILL");
    send_signal(pid, libc::SIGKILL);
    thread::sleep(Duration::from_millis(200));

    state::remove_pid_file(&iface_name);
    println!("process {pid} killed");
    Ok(())
}
