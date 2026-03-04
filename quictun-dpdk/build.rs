#[cfg(target_os = "linux")]
fn dpdk_build() {
    use std::env;
    use std::path::PathBuf;

    // Rebuild when DPDK install path changes.
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");

    // Use .statik(true) for static DPDK builds (-Ddefault_library=static).
    // pkg-config will output --whole-archive flags to preserve PMD constructors.
    let dpdk = pkg_config::Config::new()
        .statik(true)
        .probe("libdpdk")
        .expect("pkg-config: libdpdk not found (set PKG_CONFIG_PATH for source builds)");

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
        .allowlist_type("rte_ring")
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
        // DPDK vdev functions (for AF_XDP PMD)
        .allowlist_function("rte_vdev_init")
        .allowlist_function("rte_vdev_uninit")
        .allowlist_function("rte_eth_dev_count_avail")
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
    // DPDK headers (rte_memcpy.h) use SIMD intrinsics that need target features.
    // Use -march=native for native builds, skip for cross-compilation so the
    // cross-compiler uses sane defaults for the target arch (NEON on aarch64, etc.).
    let target = env::var("TARGET").unwrap();
    let host = env::var("HOST").unwrap();
    let mut cc_build = cc::Build::new();
    cc_build.file("csrc/shim.c");
    if target == host {
        cc_build.flag("-march=native");
    }
    for path in &dpdk.include_paths {
        cc_build.include(path);
    }
    cc_build.compile("dpdk_shim");

    // DPDK PMDs register via __attribute__((constructor)). The pkg-config crate
    // emits --whole-archive flags but Cargo doesn't preserve their ordering relative
    // to library links. Explicitly link each PMD with +whole-archive to ensure
    // constructors survive static linking. (Demikernel does the same on Windows.)
    let pmd_libs = [
        ("rte_bus_pci", true),     // PCI bus (dep of net_virtio PCI driver)
        ("rte_bus_vdev", true),    // vdev bus (rte_vdev_init/uninit)
        ("rte_net_virtio", true),  // virtio-user PMD (--dpdk virtio)
        ("rte_net_tap", true),     // TAP PMD (--dpdk tap)
        ("rte_mempool_ring", true), // ring mempool (always needed)
    ];
    for (lib, required) in pmd_libs {
        if required || dpdk.libs.iter().any(|l| l.contains(lib)) {
            println!("cargo:rustc-link-lib=static:+whole-archive={lib}");
        }
    }
    // AF_XDP: only link if available (requires libxdp at DPDK build time).
    if dpdk.libs.iter().any(|l| l.contains("af_xdp")) {
        println!("cargo:rustc-link-lib=static:+whole-archive=rte_net_af_xdp");
    }

    // Track C source changes for incremental rebuilds (fixes cargo clean requirement).
    println!("cargo:rerun-if-changed=csrc/shim.h");
    println!("cargo:rerun-if-changed=csrc/shim.c");
}

fn main() {
    #[cfg(target_os = "linux")]
    dpdk_build();
}
