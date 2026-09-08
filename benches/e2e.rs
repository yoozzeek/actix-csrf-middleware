use actix_csrf_middleware::{
    CsrfDoubleSubmitCookie, CsrfMiddleware, CsrfMiddlewareConfig, DEFAULT_CSRF_TOKEN_HEADER,
    DEFAULT_SESSION_ID_KEY, TokenClass, generate_hmac_token_ctx,
};
use actix_http::Request;
use actix_http::body::{BoxBody, EitherBody};
use actix_web::cookie::SameSite;
use actix_web::dev::{Service, ServiceResponse};
use actix_web::http::header;
use actix_web::{App, HttpResponse, test, web};
use criterion::measurement::WallTime;
use criterion::{BatchSize, BenchmarkGroup, Criterion, criterion_group, criterion_main};
use futures_util::task::noop_waker;
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll};

type Scenario = (&'static str, Box<dyn Fn() -> Request>);

const MAX_POLLS: usize = 64;
const SECRET: &[u8] = b"bench-secret-bench-secret-bench-1234567890";
const SID: &str = "BENCH-SESSION-ID";
const SKIP_PREFIX: &str = "/healthz";

trait BenchService<B>:
    Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>
{
}

impl<S, B> BenchService<B> for S where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>
{
}

fn routes(cfg: &mut web::ServiceConfig) {
    cfg.route(
        "/form",
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    )
    .route(
        "/submit",
        web::post().to(|| async { HttpResponse::Ok().finish() }),
    )
    .route(
        SKIP_PREFIX,
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    );
}

fn double_submit_config() -> CsrfMiddlewareConfig {
    CsrfMiddlewareConfig::double_submit_cookie(SECRET)
        .with_token_cookie_config(CsrfDoubleSubmitCookie {
            http_only: false,
            same_site: SameSite::Lax,
        })
        .with_secure(false)
        .with_skip_for(vec![SKIP_PREFIX.to_owned()])
}

async fn plain_app() -> impl BenchService<BoxBody> {
    test::init_service(App::new().configure(routes)).await
}

async fn double_submit_app() -> impl BenchService<EitherBody<BoxBody>> {
    test::init_service(
        App::new()
            .wrap(CsrfMiddleware::new(double_submit_config()))
            .configure(routes),
    )
    .await
}

fn authorized_token() -> String {
    generate_hmac_token_ctx(TokenClass::Authorized, SID, SECRET)
}

fn get_cold() -> Request {
    test::TestRequest::get().uri("/form").to_request()
}

fn get_warm(token: &str) -> Request {
    test::TestRequest::get()
        .uri("/form")
        .insert_header((
            header::COOKIE,
            format!("{DEFAULT_SESSION_ID_KEY}={SID}; CSRF={token}"),
        ))
        .to_request()
}

fn post_header(token: &str) -> Request {
    test::TestRequest::post()
        .uri("/submit")
        .insert_header((header::COOKIE, format!("{DEFAULT_SESSION_ID_KEY}={SID}")))
        .insert_header((DEFAULT_CSRF_TOKEN_HEADER, token.to_owned()))
        .to_request()
}

fn post_json(token: &str, padding: usize) -> Request {
    let body = format!(
        r#"{{"csrf_token":"{token}","payload":"{}"}}"#,
        "x".repeat(padding)
    );

    test::TestRequest::post()
        .uri("/submit")
        .insert_header((header::COOKIE, format!("{DEFAULT_SESSION_ID_KEY}={SID}")))
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload(body)
        .to_request()
}

fn skipped() -> Request {
    test::TestRequest::get().uri(SKIP_PREFIX).to_request()
}

fn drive<F: Future>(fut: F) -> F::Output {
    let waker = noop_waker();

    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(&waker);

    for _ in 0..MAX_POLLS {
        if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
            return out;
        }
    }

    panic!("future did not settle in {MAX_POLLS} polls, real I/O in the bench path?");
}

fn bench_one<S: BenchService<B>, B>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    label: &str,
    srv: &S,
    make: &dyn Fn() -> Request,
) {
    group.bench_function(label, |b| {
        b.iter_batched(
            make,
            |req| {
                let resp = drive(srv.call(req)).expect("service call");
                assert!(resp.status().is_success(), "{}", resp.status());
                resp
            },
            BatchSize::SmallInput,
        )
    });
}

fn middleware_overhead(c: &mut Criterion) {
    let rt = actix_rt::Runtime::new().expect("bench runtime");
    let plain = rt.block_on(plain_app());
    let guarded = rt.block_on(double_submit_app());
    let token = authorized_token();

    let scenarios: Vec<Scenario> = vec![
        ("get_issue_tokens", Box::new(get_cold)),
        ("get_existing_tokens", {
            let t = token.clone();
            Box::new(move || get_warm(&t))
        }),
        ("skipped_prefix", Box::new(skipped)),
        ("post_token_in_header", {
            let t = token.clone();
            Box::new(move || post_header(&t))
        }),
        ("post_token_in_json_1k", {
            let t = token.clone();
            Box::new(move || post_json(&t, 1024))
        }),
        ("post_token_in_json_256k", {
            let t = token.clone();
            Box::new(move || post_json(&t, 256 * 1024))
        }),
    ];

    for (name, make) in &scenarios {
        let mut group = c.benchmark_group(*name);
        bench_one(&mut group, "baseline", &plain, make.as_ref());
        bench_one(&mut group, "double_submit", &guarded, make.as_ref());

        group.finish();
    }
}

criterion_group!(benches, middleware_overhead);
criterion_main!(benches);
