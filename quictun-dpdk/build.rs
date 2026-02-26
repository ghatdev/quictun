#[cfg(target_os = "linux")]
fn dpdk_build() {
    use std::env;
    use std::path::PathBuf;

    let dpdk = pkg_config::Config::new()
        .probe("libdpdk")
        .expect("pkg-config: libdpdk not found (install libdpdk-dev)");

    // Generate FFI bindings via bindgen.
    let mut builder = bindgen::Builder::default().header("csrc/shim.h");
    for path in &dpdk.include_paths {
        builder = builder.clang_arg(format!("-I{}", path.display()));
    }

    let bindings = builder
        // DPDK types
        .allowlist_type("rte_mbuf")
        .allowlist_type("rte_mempool")
        .allowlist_type("rte_eth_conf")
        .allowlist_type("rte_eth_rxconf")
        .allowlist_type("rte_eth_txconf")
        .allowlist_type("rte_eth_dev_info")
        .allowlist_type("rte_ether_addr")
        .allowlist_type("rte_eth_link")
        // DPDK functions (non-inline — callable directly)
        .allowlist_function("rte_eal_init")
        .allowlist_function("rte_eal_cleanup")
        .allowlist_function("rte_pktmbuf_pool_create")
        .allowlist_function("rte_eth_dev_configure")
        .allowlist_function("rte_eth_rx_queue_setup")
        .allowlist_function("rte_eth_tx_queue_setup")
        .allowlist_function("rte_eth_dev_start")
        .allowlist_function("rte_eth_dev_stop")
        .allowlist_function("rte_eth_dev_close")
        .allowlist_function("rte_eth_dev_info_get")
        .allowlist_function("rte_eth_macaddr_get")
        .allowlist_function("rte_eth_promiscuous_enable")
        .allowlist_function("rte_eth_link_get_nowait")
        .allowlist_function("rte_strerror")
        // Our C shim wrappers (for inline DPDK functions)
        .allowlist_function("shim_.*")
        .derive_default(true)
        .generate()
        .expect("bindgen: failed to generate DPDK bindings");

    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out.join("dpdk_bindings.rs"))
        .expect("failed to write DPDK bindings");

    // Compile C shim (wraps inline DPDK functions).
    // -march=native is required because DPDK headers (rte_memcpy.h) use
    // SSSE3/SSE4 intrinsics that need the corresponding target features.
    let mut cc_build = cc::Build::new();
    cc_build.file("csrc/shim.c");
    cc_build.flag("-march=native");
    for path in &dpdk.include_paths {
        cc_build.include(path);
    }
    cc_build.compile("dpdk_shim");
}

fn main() {
    #[cfg(target_os = "linux")]
    dpdk_build();
}
