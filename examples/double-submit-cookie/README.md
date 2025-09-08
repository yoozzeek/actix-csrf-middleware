# Double Submit Cookie Example

Minimal Actix Web example demonstrating CSRF protection using the Double Submit Cookie pattern.

- GET /form — returns current CSRF token in the response body (format: `token:<value>`)
- POST /submit — requires a valid CSRF token (header `X-CSRF-Token` or form/json field)

Run:

```
cargo run --manifest-path examples/double-submit-cookie/Cargo.toml
```