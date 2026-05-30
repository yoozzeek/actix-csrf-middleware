# Rotation After Auth Example

Minimal Actix Web example demonstrating CSRF token rotation after successful authorization/mutation.

- GET `/`: anonymous login form with the `csrf_token` field
- POST `/login`: issues a session id cookie (`id`) and upgrades the token to authorized via
  `CsrfRequestExt::rotate_csrf_after_login`
- GET `/page`: authorized page with a logout form
- POST `/logout`: tears down the session and CSRF state via
  `CsrfRequestExt::rotate_csrf_after_logout`

Run:

```
cargo run --manifest-path examples/rotation-after-auth/Cargo.toml
```