# Chamber API

REST API server for the Chamber secrets manager.
Provides HTTP endpoints for vault operations, authentication,
and secret management with JWT-based security.

This crate is part of the [Chamber](https://github.com/koko1111/chamber) secrets manager ecosystem.

Install release `0.5.4` from the default branch.
The `v0.5.4` git tag predates this crate name.
`Cargo.lock` records third-party crates at
`registry+https://github.com/rust-lang/crates.io-index`.

```bash
cargo add --git https://github.com/koko1111/chamber.git chamber-api-fork
```

After `.github/workflows/publish-crates.yml` publishes to crates.io:

```bash
cargo add chamber-api-fork@0.5.4
```

The crate page will be [chamber-api-fork](https://crates.io/crates/chamber-api-fork).