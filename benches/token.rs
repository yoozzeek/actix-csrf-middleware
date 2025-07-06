use actix_csrf_middleware::{eq_csrf_tokens, generate_token};
use criterion::{Criterion, criterion_group, criterion_main};

fn bench_token_gen(c: &mut Criterion) {
    c.bench_function("generate_token", |b| b.iter(generate_token));
}

fn bench_eq_csrf_tokens(c: &mut Criterion) {
    let token1 = generate_token();
    let token2 = generate_token();
    c.bench_function("eq_csrf_tokens_match", |b| {
        b.iter(|| eq_csrf_tokens(&token1, &token1))
    });
    c.bench_function("eq_csrf_tokens_nomatch", |b| {
        b.iter(|| eq_csrf_tokens(&token1, &token2))
    });
}

criterion_group!(benches, bench_token_gen, bench_eq_csrf_tokens);
criterion_main!(benches);
