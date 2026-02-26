use std::net::Ipv4Addr;
use std::process::Command;

use anyhow::{bail, Context, Result};

/// A veth pair for AF_XDP inner interface.
///
/// `app_iface` is the kernel-facing end (e.g., "quictun0") with an IP address.
/// `xdp_iface` is the DPDK-facing end (e.g., "quictun0_xdp") bound to AF_XDP PMD.
pub struct VethPair {
    /// Kernel-facing interface name (has IP, used by apps).
    pub app_iface: String,
    /// DPDK-facing interface name (bound to AF_XDP PMD).
    pub xdp_iface: String,
    /// MAC address of the app-facing interface.
    pub app_mac: [u8; 6],
}

impl VethPair {
    /// Create a veth pair and configure the app-facing end with an IP address.
    ///
    /// - `name`: base interface name (e.g., "quictun0")
    /// - `ip`: IPv4 address for the app-facing end
    /// - `prefix`: subnet prefix length (e.g., 24)
    /// - `mtu`: MTU for both ends
    pub fn create(name: &str, ip: Ipv4Addr, prefix: u8, mtu: u16) -> Result<Self> {
        let app_iface = name.to_string();
        let xdp_iface = format!("{name}_xdp");

        // Clean up any stale interfaces from a previous crash.
        let _ = Command::new("ip")
            .args(["link", "del", &app_iface])
            .output();

        // Create veth pair.
        run_cmd(
            "ip",
            &[
                "link", "add", &app_iface, "type", "veth", "peer", "name", &xdp_iface,
            ],
        )
        .context("failed to create veth pair")?;

        // Set MTU on both ends.
        let mtu_str = mtu.to_string();
        run_cmd("ip", &["link", "set", &app_iface, "mtu", &mtu_str])
            .context("failed to set app_iface MTU")?;
        run_cmd("ip", &["link", "set", &xdp_iface, "mtu", &mtu_str])
            .context("failed to set xdp_iface MTU")?;

        // Assign IP to the app-facing end.
        let addr = format!("{ip}/{prefix}");
        run_cmd("ip", &["addr", "add", &addr, "dev", &app_iface])
            .context("failed to assign IP to app_iface")?;

        // Bring both ends up.
        run_cmd("ip", &["link", "set", &app_iface, "up"])
            .context("failed to bring app_iface up")?;
        run_cmd("ip", &["link", "set", &xdp_iface, "up"])
            .context("failed to bring xdp_iface up")?;

        // Read MAC address of the app-facing interface.
        let app_mac = read_mac(&app_iface)
            .with_context(|| format!("failed to read MAC of {app_iface}"))?;

        tracing::info!(
            app_iface = %app_iface,
            xdp_iface = %xdp_iface,
            app_mac = %format_mac(&app_mac),
            ip = %ip,
            prefix,
            mtu,
            "veth pair created"
        );

        Ok(Self {
            app_iface,
            xdp_iface,
            app_mac,
        })
    }
}

impl Drop for VethPair {
    fn drop(&mut self) {
        // Deleting one end removes both.
        let _ = Command::new("ip")
            .args(["link", "del", &self.app_iface])
            .output();
        tracing::info!(iface = %self.app_iface, "veth pair deleted");
    }
}

/// Run a command and return an error if it fails.
fn run_cmd(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute: {program} {}", args.join(" ")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "{program} {} failed: {}",
            args.join(" "),
            stderr.trim()
        );
    }
    Ok(())
}

/// Read MAC address from sysfs.
fn read_mac(iface: &str) -> Result<[u8; 6]> {
    let path = format!("/sys/class/net/{iface}/address");
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read {path}"))?;
    parse_mac(content.trim())
}

fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        bail!("invalid MAC: {s}");
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .with_context(|| format!("invalid MAC octet: {part}"))?;
    }
    Ok(mac)
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}
