# Double Submit Cookie Example

Minimal Actix Web example demonstrating CSRF protection using the Double Submit Cookie pattern.

- GET `/form`: returns simple HTML form with editable `csrf_token` field (для тестов; обычно hidden)
- POST `/form`: form submission; valid CSRF token required

Run:

```
cargo run --manifest-path examples/double-submit-cookie/Cargo.toml
```