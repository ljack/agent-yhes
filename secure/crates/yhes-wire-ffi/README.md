# Native public-key validator bridge

Statically linked C ABI for `yhes-wire::PublicKey::new`:

```c
uint8_t yhes_wire_public_key_is_valid(uint32_t algorithm,
                                     const uint8_t *bytes, size_t length);
```

Algorithm 1: Ed25519, exactly 32 bytes. Algorithm 2: P-256, exactly 65-byte
uncompressed SEC1. Returns only 1 (valid) or 0 (rejected); no error payload,
allocation transfer or secret data. Unknown algorithms/lengths and null pointers
are rejected before reads. Valid-length nonnull pointers must reference readable
memory; the native C shim receives a scoped Swift Data buffer. Panics are caught
at the ABI boundary; this is not protection from an invalid caller pointer.

The bridge uses the same `ed25519-dalek`/`p256` validation as `yhes-wire`, including
weak Ed25519-key rejection. No curve arithmetic is reimplemented. It performs no
signing, key creation, Keychain access, enrollment, network calls or environment
lookups. It does not validate a registry's authority or history.

Build through `native/YhesSigner/scripts/prepare-validator.sh`, which uses the
root workspace's locked dependency graph and writes its static archive only
under the native package's ignored `.build/rust` directory. The Swift package
links that exact archive into its executable; no external validator process is
launched when signing. `cargo test -p yhes-wire-ffi --locked` tests only public
known vectors and invalid input. Ownership was explicitly expanded by the parent
for this new crate; root workspace files remain parent-owned.
