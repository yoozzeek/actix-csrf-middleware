use actix_csrf_middleware::{eq_tokens, generate_random_token};
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_csrf_token_gen(c: &mut Criterion) {
    c.bench_function("generate_csrf_token", |b| b.iter(generate_random_token));
}

fn bench_eq_csrf_tokens(c: &mut Criterion) {
    let token1 = generate_random_token();
    let token2 = generate_random_token();
    c.bench_function("eq_csrf_tokens_match", |b| {
        b.iter(|| eq_tokens(token1.as_bytes(), token1.as_bytes()))
    });
    c.bench_function("eq_csrf_tokens_nomatch", |b| {
        b.iter(|| eq_tokens(token1.as_bytes(), token2.as_bytes()))
    });
}

criterion_group!(benches, bench_csrf_token_gen, bench_eq_csrf_tokens);
criterion_main!(benches);
