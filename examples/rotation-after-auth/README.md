# Rotation After Auth Example

Minimal Actix Web example demonstrating CSRF token rotation after successful authorization/mutation.

- POST /login — simulates login by issuing a session id cookie (`id`)
- GET /form — returns current CSRF token in the response body (format: `token:<value>`)
- POST /auth — protected endpoint; upon success rotates CSRF token using `CsrfRequestExt::rotate_csrf_token_in_response`

Run:

```
cargo run --manifest-path examples/rotation-after-auth/Cargo.toml
```