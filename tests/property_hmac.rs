use actix_csrf_middleware::{generate_hmac_token_ctx, validate_hmac_token_ctx, TokenClass};
use proptest::prelude::*;
use proptest::sample::select;

// Strategy: reasonably small ascii for IDs to keep debug output readable, but include edge chars
fn id_strategy() -> impl Strategy<Value = String> {
    // Allow 1..64 chars, include some separators to ensure robustness
    // Exclude '.' because it's used as separator in token encoding; include '|' since we MAC using raw separators
    let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-|:/@#$%";
    let chars: Vec<char> = charset.chars().collect();
    proptest::collection::vec(select(chars), 1..64).prop_map(|v| v.into_iter().collect())
}

// Strategy for secrets: non-empty arbitrary bytes up to 64 bytes
fn secret_strategy() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 1..64)
}

proptest! {
    // Roundtrip should validate for Authorized tokens
    #[test]
    fn prop_auth_roundtrip(session_id in id_strategy(), secret in secret_strategy()) {
        let tok = generate_hmac_token_ctx(TokenClass::Authorized, &session_id, &secret);
        let ok = validate_hmac_token_ctx(TokenClass::Authorized, &session_id, tok.as_bytes(), &secret).unwrap();

        prop_assert!(ok);
    }

    // Roundtrip should validate for Anonymous tokens
    #[test]
    fn prop_anon_roundtrip(pre_sid in id_strategy(), secret in secret_strategy()) {
        let tok = generate_hmac_token_ctx(TokenClass::Anonymous, &pre_sid, &secret);
        let ok = validate_hmac_token_ctx(TokenClass::Anonymous, &pre_sid, tok.as_bytes(), &secret).unwrap();

        prop_assert!(ok);
    }

    // Cross-class validation must fail (anon token cannot validate as auth and vice versa)
    #[test]
    fn prop_cross_class_rejected(id in id_strategy(), secret in secret_strategy()) {
        let anon_tok = generate_hmac_token_ctx(TokenClass::Anonymous, &id, &secret);
        let auth_tok = generate_hmac_token_ctx(TokenClass::Authorized, &id, &secret);

        let anon_as_auth = validate_hmac_token_ctx(TokenClass::Authorized, &id, anon_tok.as_bytes(), &secret).unwrap_or(false);
        let auth_as_anon = validate_hmac_token_ctx(TokenClass::Anonymous, &id, auth_tok.as_bytes(), &secret).unwrap_or(false);

        prop_assert!(!anon_as_auth);
        prop_assert!(!auth_as_anon);
    }

    // Cross-session validation must fail
    #[test]
    fn prop_cross_session_rejected(id1 in id_strategy(), id2 in id_strategy(), secret in secret_strategy()) {
        prop_assume!(id1 != id2);

        let tok = generate_hmac_token_ctx(TokenClass::Authorized, &id1, &secret);
        let ok = validate_hmac_token_ctx(TokenClass::Authorized, &id2, tok.as_bytes(), &secret).unwrap_or(false);

        prop_assert!(!ok);
    }

    // Cross-secret validation must fail
    #[test]
    fn prop_cross_secret_rejected(id in id_strategy(), secret1 in secret_strategy(), secret2 in secret_strategy()) {
        prop_assume!(secret1 != secret2);

        let tok = generate_hmac_token_ctx(TokenClass::Authorized, &id, &secret1);
        let ok = validate_hmac_token_ctx(TokenClass::Authorized, &id, tok.as_bytes(), &secret2).unwrap_or(false);

        prop_assert!(!ok);
    }

    // Format invariants: hex HMAC (64 chars) + '.' + base64url token (43 chars), no padding
    #[test]
    fn prop_token_format(id in id_strategy(), secret in secret_strategy()) {
        let tok = generate_hmac_token_ctx(TokenClass::Authorized, &id, &secret);
        let parts: Vec<&str> = tok.split('.').collect();

        prop_assert_eq!(parts.len(), 2);

        let hmac_hex = parts[0];
        let nonce = parts[1];

        prop_assert_eq!(hmac_hex.len(), 64);
        prop_assert!(hmac_hex.chars().all(|c| c.is_ascii_hexdigit()));

        // base64url alphabet without padding, 32 bytes => 43 chars
        prop_assert_eq!(nonce.len(), 43);
        prop_assert!(nonce.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    // Malformed tokens should not validate (graceful false)
    #[test]
    fn prop_malformed_tokens_rejected(id in id_strategy(), secret in secret_strategy(), garbage in "[a-zA-Z0-9._-]{0,80}") {
        // Some random garbage strings are not necessarily invalid; enforce known malformed shapes
        let malformed = vec![
            String::from(""),
            String::from("no_dot_separator"),
            String::from("."),
            String::from("onlyhmac."),
            String::from(".onlynonce"),
            String::from("too.many.parts.here"),
        ];

        for t in malformed {
            let ok_auth = validate_hmac_token_ctx(TokenClass::Authorized, &id, t.as_bytes(), &secret).unwrap_or(false);
            let ok_anon = validate_hmac_token_ctx(TokenClass::Anonymous, &id, t.as_bytes(), &secret).unwrap_or(false);
            prop_assert!(!ok_auth && !ok_anon);
        }

        // Also try the random garbage
        let ok_auth = validate_hmac_token_ctx(TokenClass::Authorized, &id, garbage.as_bytes(), &secret).unwrap_or(false);
        let ok_anon = validate_hmac_token_ctx(TokenClass::Anonymous, &id, garbage.as_bytes(), &secret).unwrap_or(false);

        prop_assert!(!(ok_auth || ok_anon));
    }
}
