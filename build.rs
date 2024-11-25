fn main() {
    // sha256
    cxx_build::bridge("src/bridge_sha256.rs")
        .file("cpp/sha256.cpp")
        .flag_if_supported("-std=c++20")
        .compile("cxx-sha256");

    println!("cargo::rerun-if-changed=src/bridge.rs");
    println!("cargo::rerun-if-changed=cpp/sha256.cpp");
    println!("cargo::rerun-if-changed=include/sha256.h");
}


