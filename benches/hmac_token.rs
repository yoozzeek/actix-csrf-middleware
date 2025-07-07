use actix_csrf_middleware::{generate_hmac_token, generate_random_token, validate_hmac_token};
use criterion::{Criterion, criterion_group, criterion_main};

fn get_secret_key() -> Vec<u8> {
    b"super_secret_key".to_vec()
}

fn bench_hmac_token_gen(c: &mut Criterion) {
    c.bench_function("generate_hmac_token", |b| b.iter(generate_random_token));
}

fn bench_validate_hmac_tokens(c: &mut Criterion) {
    let sess1_id = generate_random_token();
    let sess2_id = generate_random_token();
    let token1 = generate_hmac_token(&sess1_id, &get_secret_key());
    let _token2 = generate_hmac_token(&sess2_id, &get_secret_key());
    c.bench_function("hmac_tokens_valid", |b| {
        b.iter(|| validate_hmac_token(&sess1_id, &token1, &get_secret_key()))
    });
    c.bench_function("hmac_tokens_invalid", |b| {
        b.iter(|| validate_hmac_token(&sess2_id, &token1, &get_secret_key()))
    });
}

criterion_group!(benches, bench_hmac_token_gen, bench_validate_hmac_tokens);
criterion_main!(benches);
