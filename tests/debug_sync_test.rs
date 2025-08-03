use actix_csrf_middleware::CsrfMiddlewareConfig;
use actix_web::test;

mod common;
use common::*;

#[actix_web::test]
async fn debug_synchronizer_token() {
    let mut config = CsrfMiddlewareConfig::synchronizer_token();
    config.secret_key = Some(b"test-secret-key".to_vec());
    let app = build_app(config).await;
    
    // First, let's see what happens when we get a token
    let req = test::TestRequest::get().uri("/form").to_request();
    let resp = test::call_service(&app, req).await;
    
    let status = resp.status();
    println!("GET /form response status: {}", status);
    
    // Check what cookies are set
    let cookies: Vec<_> = resp.response().cookies().map(|c| c.into_owned()).collect();
    println!("Cookies set: {:?}", cookies.iter().map(|c| c.name()).collect::<Vec<_>>());
    
    let body = test::read_body(resp).await;
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    println!("Response body: {}", body_str);
    
    if status.is_success() {
        let token = body_str.strip_prefix("token:").unwrap().to_string();
        println!("Extracted token: {}", token);
        
        // Now try to use the token
        if let Some(session_cookie) = cookies.first() {
            let req = test::TestRequest::post()
                .uri("/submit")
                .insert_header(("X-CSRF-Token", token.clone()))
                .cookie(session_cookie.clone())
                .to_request();
            
            let resp = test::call_service(&app, req).await;
            println!("POST /submit response status: {}", resp.status());
            
            if !resp.status().is_success() {
                let body = test::read_body(resp).await;
                let error_body = String::from_utf8(body.to_vec()).unwrap();
                println!("Error response body: {}", error_body);
            }
        }
    }
}
