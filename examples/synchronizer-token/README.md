# Synchronizer Token Example

Minimal Actix Web example demonstrating CSRF protection using the Synchronizer Token pattern (requires `actix-session`).

- GET /form — returns current CSRF token in the response body (format: `token:<value>`)
- POST /submit — requires a valid CSRF token (header `X-CSRF-Token` or form/json field)

Run:

```
cargo run --manifest-path examples/synchronizer-token/Cargo.toml
```