fn main() {

    // sha256
    cxx_build::bridge("src/bridge_sha256.rs")
        .file("cpp/sha256.cpp")
        .flag_if_supported("-std=c++20")
        .compile("cxx-sha256");

    println!("cargo::rerun-if-changed=src/bridge_sha256.rs");
    println!("cargo::rerun-if-changed=cpp/sha256.cpp");
    println!("cargo::rerun-if-changed=include/sha256.h");


    // key pairs code
    cxx_build::bridge("src/bridge_keys.rs")
        .file("cpp/keys.cpp")
        .flag_if_supported("-std=c++20")
        .compile("cxx-keys");

    println!("cargo::rerun-if-changed=src/bridge_keys.rs");
    println!("cargo::rerun-if-changed=cpp/keys.cpp");
    println!("cargo::rerun-if-changed=include/keys.h");

    println!("cargo:rustc-link-lib=dylib=gmp");
}


