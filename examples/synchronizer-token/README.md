# Synchronizer Token Example

Minimal Actix Web example demonstrating CSRF protection using the Synchronizer Token pattern (requires `actix-session`).

- GET /form — возвращает простую HTML-форму с редактируемым полем `csrf_token` (для тестов; обычно hidden)
- POST /form — отправка формы; требуется валидный CSRF токен (из формы)

Run:

```
cargo run --manifest-path examples/synchronizer-token/Cargo.toml
```