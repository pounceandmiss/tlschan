// Exposes the locked rustls version as RUSTLS_VERSION for tlsb_version().
fn main() {
    println!("cargo:rerun-if-changed=Cargo.lock");
    let lock = std::fs::read_to_string("Cargo.lock").unwrap_or_default();
    let ver = lock
        .split("[[package]]")
        .find(|p| p.contains("name = \"rustls\"\n"))
        .and_then(|p| p.lines().find_map(|l| l.strip_prefix("version = \"")))
        .map_or("0.23", |v| v.trim_end_matches('"'));
    println!("cargo:rustc-env=RUSTLS_VERSION={ver}");
}
