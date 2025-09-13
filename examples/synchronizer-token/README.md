# Synchronizer Token Example

Minimal Actix Web example demonstrating CSRF protection using the Synchronizer Token pattern (requires `actix-session`).

- GET `/form`: returns a simple HTML form with an editable `csrf_token` field (for tests only; usually hidden)
- POST `/form`: form submission; valid CSRF token required

Run:

```
cargo run --manifest-path examples/synchronizer-token/Cargo.toml
```