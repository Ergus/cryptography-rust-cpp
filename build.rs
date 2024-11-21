fn main() {
    cxx_build::bridge("src/lib.rs")
        .file("src/sha256.cpp")
        .flag_if_supported("-std=c++17")
        .compile("cxx-sha256");

    println!("cargo::rerun-if-changed=src/main.rs");
    println!("cargo::rerun-if-changed=src/sha256.cpp");
    println!("cargo::rerun-if-changed=include/sha256.h");

}
