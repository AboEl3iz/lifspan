fn main() {
    println!("cargo:rustc-link-lib=bpf");
    println!("cargo:rustc-link-lib=elf");
    println!("cargo:rustc-link-lib=z");
}
