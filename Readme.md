# Readme

This is a test project that implements the some cryptographic
primitives in C++ and Rust and compare results.  The main goal of this
is to learn (for me) about the cryptographic primitives and the use of
big number libraries in C++ and Rust.

Currently this includes only some code to

1. Generate `sha256` hash for strings and generic binary messages.
2. Generate `ECDSA` key pairs
3. Sign a message with the private key.
4. Validate the signatures given the public keys, the signature and
   the message.

This does not use any ssl or cryptographic library or rust crate. Only
the [gmp](https://gmplib.org/) library for bit integers in C++ and
[num\_bigint](https://docs.rs/num-bigint/latest/num_bigint/) for Rust.

TODO: Implement my own bigint library.
