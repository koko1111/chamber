# Chamber API

REST API server for the Chamber secrets manager.
Provides HTTP endpoints for vault operations, authentication,
and secret management with JWT-based security.

This crate is part of the [Chamber](https://github.com/koko1111/chamber) secrets manager ecosystem.

Install release `0.5.4` from the git tag.
`Cargo.lock` records third-party crates at
`registry+https://github.com/rust-lang/crates.io-index`.

```bash
cargo add --git https://github.com/koko1111/chamber.git --tag v0.5.4 chamber-api
```

After `.github/workflows/publish-crates.yml` publishes to crates.io:

```bash
cargo add chamber-api@0.5.4
```

The crate page is [chamber-api](https://crates.io/crates/chamber-api).