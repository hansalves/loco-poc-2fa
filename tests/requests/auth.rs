use insta::{assert_debug_snapshot, with_settings};
use loco_poc_2fa::views::auth::{LoginData, LoginResponse, RegisterTOTPResponse};
use loco_poc_2fa::{app::App, models::users};
use loco_rs::testing::prelude::*;
use rstest::rstest;
use serial_test::serial;
use totp_rs::{Algorithm, TOTP};

use super::prepare_data;

// TODO: see how to dedup / extract this to app-local test utils
// not to framework, because that would require a runtime dep on insta
macro_rules! configure_insta {
    ($($expr:expr),*) => {
        let mut settings = insta::Settings::clone_current();
        settings.set_prepend_module_to_snapshot(false);
        settings.set_snapshot_suffix("auth_request");
        let _guard = settings.bind_to_scope();
    };
}

#[tokio::test]
#[serial]
async fn can_register() {
    configure_insta!();

    request::<App, _, _>(|request, ctx| async move {
        let email = "test@loco.com";
        let payload = serde_json::json!({
            "name": "loco",
            "email": email,
            "password": "12341234"
        });

        let response = request.post("/api/auth/register").json(&payload).await;
        assert_eq!(
            response.status_code(),
            200,
            "Register request should succeed"
        );
        let saved_user = users::Model::find_by_email(&ctx.db, email).await;

        with_settings!({
            filters => cleanup_user_model()
        }, {
            assert_debug_snapshot!(saved_user);
        });

        let deliveries = ctx.mailer.unwrap().deliveries();
        assert_eq!(deliveries.count, 1, "Exactly one email should be sent");

        // with_settings!({
        //     filters => cleanup_email()
        // }, {
        //     assert_debug_snapshot!(ctx.mailer.unwrap().deliveries());
        // });
    })
    .await;
}

#[rstest]
#[case("login_with_valid_password", "12341234")]
#[case("login_with_invalid_password", "invalid-password")]
#[tokio::test]
#[serial]
async fn can_login_with_verify(#[case] test_name: &str, #[case] password: &str) {
    configure_insta!();

    request::<App, _, _>(|request, ctx| async move {
        let email = "test@loco.com";
        let register_payload = serde_json::json!({
            "name": "loco",
            "email": email,
            "password": "12341234"
        });

        //Creating a new user
        let register_response = request
            .post("/api/auth/register")
            .json(&register_payload)
            .await;

        assert_eq!(
            register_response.status_code(),
            200,
            "Register request should succeed"
        );

        let user = users::Model::find_by_email(&ctx.db, email).await.unwrap();
        let email_verification_token = user
            .email_verification_token
            .expect("Email verification token should be generated");
        request
            .get(&format!("/api/auth/verify/{email_verification_token}"))
            .await;

        //verify user request
        let response = request
            .post("/api/auth/login")
            .json(&serde_json::json!({
                "email": email,
                "password": password
            }))
            .await;

        // Make sure email_verified_at is set
        let user = users::Model::find_by_email(&ctx.db, email)
            .await
            .expect("Failed to find user by email");

        assert!(
            user.email_verified_at.is_some(),
            "Expected the email to be verified, but it was not. User: {:?}",
            user
        );

        with_settings!({
            filters => cleanup_user_model()
        }, {
            assert_debug_snapshot!(test_name, (response.status_code(), response.text()));
        });
    })
    .await;
}

#[tokio::test]
#[serial]
async fn login_with_un_existing_email() {
    configure_insta!();

    request::<App, _, _>(|request, _ctx| async move {

        let login_response = request
            .post("/api/auth/login")
            .json(&serde_json::json!({
                "email": "un_existing@loco.rs",
                "password":  "1234"
            }))
            .await;

        assert_eq!(login_response.status_code(), 401, "Login request should return 401");
        login_response.assert_json(&serde_json::json!({"error": "unauthorized", "description": "You do not have permission to access this resource"}));
    })
    .await;
}

#[tokio::test]
#[serial]
async fn can_login_without_verify() {
    configure_insta!();

    request::<App, _, _>(|request, _ctx| async move {
        let email = "test@loco.com";
        let password = "12341234";
        let register_payload = serde_json::json!({
            "name": "loco",
            "email": email,
            "password": password
        });

        //Creating a new user
        let register_response = request
            .post("/api/auth/register")
            .json(&register_payload)
            .await;

        assert_eq!(
            register_response.status_code(),
            200,
            "Register request should succeed"
        );

        //verify user request
        let login_response = request
            .post("/api/auth/login")
            .json(&serde_json::json!({
                "email": email,
                "password": password
            }))
            .await;

        assert_eq!(
            login_response.status_code(),
            200,
            "Login request should succeed"
        );

        with_settings!({
            filters => cleanup_user_model()
        }, {
            assert_debug_snapshot!(login_response.text());
        });
    })
    .await;
}

#[tokio::test]
#[serial]
async fn invalid_verification_token() {
    configure_insta!();

    request::<App, _, _>(|request, _ctx| async move {
        let response = request.get("/api/auth/verify/invalid-token").await;

        assert_eq!(response.status_code(), 401, "Verify request should reject");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn can_reset_password() {
    configure_insta!();

    request::<App, _, _>(|request, ctx| async move {
        let login_data = prepare_data::init_user_login(&request, &ctx).await;

        let forgot_payload = serde_json::json!({
            "email": login_data.user.email,
        });
        let forget_response = request.post("/api/auth/forgot").json(&forgot_payload).await;
        assert_eq!(
            forget_response.status_code(),
            200,
            "Forget request should succeed"
        );

        let user = users::Model::find_by_email(&ctx.db, &login_data.user.email)
            .await
            .expect("Failed to find user by email");

        assert!(
            user.reset_token.is_some(),
            "Expected reset_token to be set, but it was None. User: {user:?}"
        );
        assert!(
            user.reset_sent_at.is_some(),
            "Expected reset_sent_at to be set, but it was None. User: {user:?}"
        );

        let new_password = "new-password";
        let reset_payload = serde_json::json!({
            "token": user.reset_token,
            "password": new_password,
        });

        let reset_response = request.post("/api/auth/reset").json(&reset_payload).await;
        assert_eq!(
            reset_response.status_code(),
            200,
            "Reset password request should succeed"
        );

        let user = users::Model::find_by_email(&ctx.db, &user.email)
            .await
            .unwrap();

        assert!(user.reset_token.is_none());
        assert!(user.reset_sent_at.is_none());

        assert_debug_snapshot!(reset_response.text());

        let login_response = request
            .post("/api/auth/login")
            .json(&serde_json::json!({
                "email": user.email,
                "password": new_password
            }))
            .await;

        assert_eq!(
            login_response.status_code(),
            200,
            "Login request should succeed"
        );

        let deliveries = ctx.mailer.unwrap().deliveries();
        assert_eq!(deliveries.count, 2, "Exactly one email should be sent");
        // with_settings!({
        //     filters => cleanup_email()
        // }, {
        //     assert_debug_snapshot!(deliveries.messages);
        // });
    })
    .await;
}

#[tokio::test]
#[serial]
async fn can_get_current_user() {
    configure_insta!();

    request::<App, _, _>(|request, ctx| async move {
        let user = prepare_data::init_user_login(&request, &ctx).await;

        let (auth_key, auth_value) = prepare_data::auth_header(&user.token);
        let response = request
            .get("/api/auth/current")
            .add_header(auth_key, auth_value)
            .await;

        assert_eq!(
            response.status_code(),
            200,
            "Current request should succeed"
        );

        with_settings!({
            filters => cleanup_user_model()
        }, {
            assert_debug_snapshot!((response.status_code(), response.text()));
        });
    })
    .await;
}

#[tokio::test]
#[serial]
async fn can_auth_with_magic_link() {
    configure_insta!();
    request::<App, _, _>(|request, ctx| async move {
        seed::<App>(&ctx).await.unwrap();

        let payload = serde_json::json!({
            "email": "user1@example.com",
        });
        let response = request.post("/api/auth/magic-link").json(&payload).await;
        assert_eq!(
            response.status_code(),
            200,
            "Magic link request should succeed"
        );

        let deliveries = ctx.mailer.unwrap().deliveries();
        assert_eq!(deliveries.count, 1, "Exactly one email should be sent");

        // let redact_token = format!("[a-zA-Z0-9]{{{}}}", users::MAGIC_LINK_LENGTH);
        // with_settings!({
        //      filters => {
        //          let mut combined_filters = cleanup_email().clone();
        //         combined_filters.extend(vec![(r"(\\r\\n|=\\r\\n)", ""), (redact_token.as_str(), "[REDACT_TOKEN]") ]);
        //         combined_filters
        //     }
        // }, {
        //     assert_debug_snapshot!(deliveries.messages);
        // });

        let user = users::Model::find_by_email(&ctx.db, "user1@example.com")
            .await
            .expect("User should be found");

        let email = user.email;
        let magic_link_token = user
            .magic_link_token
            .expect("Magic link token should be generated");
        let payload = serde_json::json!({
            "email": email,
            "token": magic_link_token,
        });
        let magic_link_response = request
            .post(&format!("/api/auth/magic-link-verify"))
            .json(&payload)
            .await;
        assert_eq!(
            magic_link_response.status_code(),
            200,
            "Magic link authentication should succeed"
        );

        with_settings!({
            filters => cleanup_user_model()
        }, {
            assert_debug_snapshot!(magic_link_response.text());
        });
    })
    .await;
}

#[tokio::test]
#[serial]
async fn can_reject_invalid_email() {
    configure_insta!();
    request::<App, _, _>(|request, _ctx| async move {
        let invalid_email = "user1@temp-mail.com";
        let payload = serde_json::json!({
            "email": invalid_email,
        });
        let response = request.post("/api/auth/magic-link").json(&payload).await;
        assert_eq!(
            response.status_code(),
            400,
            "Expected request with invalid email '{invalid_email}' to be blocked, but it was allowed."
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn can_reject_invalid_magic_link_token() {
    configure_insta!();
    request::<App, _, _>(|request, ctx| async move {
        seed::<App>(&ctx).await.unwrap();

        let payload = serde_json::json!({
            "email": "user1@example.com",
            "token": "invalid-token",
        });
        let magic_link_response = request
            .post(&format!("/api/auth/magic-link-verify"))
            .json(&payload)
            .await;
        assert_eq!(
            magic_link_response.status_code(),
            401,
            "Magic link authentication should be rejected"
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn can_resend_verification_email() {
    configure_insta!();

    request::<App, _, _>(|request, ctx| async move {
        let email = "test@loco.com";
        let payload = serde_json::json!({
            "name": "loco",
            "email": email,
            "password": "12341234"
        });

        let response = request.post("/api/auth/register").json(&payload).await;
        assert_eq!(
            response.status_code(),
            200,
            "Register request should succeed"
        );

        let resend_payload = serde_json::json!({ "email": email });

        let resend_response = request
            .post("/api/auth/resend-verification-mail")
            .json(&resend_payload)
            .await;

        assert_eq!(
            resend_response.status_code(),
            200,
            "Resend verification email should succeed"
        );

        let deliveries = ctx.mailer.unwrap().deliveries();

        assert_eq!(
            deliveries.count, 2,
            "Two emails should have been sent: welcome and re-verification"
        );

        let user = users::Model::find_by_email(&ctx.db, email)
            .await
            .expect("User should exist");

        with_settings!({
            filters => cleanup_user_model()
        }, {
            assert_debug_snapshot!("resend_verification_user", user);
        });
    })
    .await;
}

#[tokio::test]
#[serial]
async fn cannot_resend_email_if_already_verified() {
    configure_insta!();

    request::<App, _, _>(|request, ctx| async move {
        let email = "verified@loco.com";
        let payload = serde_json::json!({
            "name": "verified",
            "email": email,
            "password": "12341234"
        });

        request.post("/api/auth/register").json(&payload).await;

        // Verify user
        let user = users::Model::find_by_email(&ctx.db, email).await.unwrap();
        if let Some(token) = user.email_verification_token.clone() {
            request.get(&format!("/api/auth/verify/{token}")).await;
        }

        // Try resending verification email
        let resend_payload = serde_json::json!({ "email": email });

        let resend_response = request
            .post("/api/auth/resend-verification-mail")
            .json(&resend_payload)
            .await;

        assert_eq!(
            resend_response.status_code(),
            200,
            "Should return 200 even if already verified"
        );

        let deliveries = ctx.mailer.unwrap().deliveries();
        assert_eq!(
            deliveries.count, 1,
            "Only the original welcome email should be sent"
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn can_login_with_totp() {
    configure_insta!();

    request::<App, _, _>(|request, ctx| async move {
        let login_data = prepare_data::init_user_login(&request, &ctx).await;

        // Register TOTP for the user (requires password and auth header)
        let (auth_key, auth_value) = prepare_data::auth_header(&login_data.token);
        let register_totp_response = request
            .post("/api/auth/register-totp")
            .add_header(auth_key.clone(), auth_value.clone())
            .json(&serde_json::json!({
                "password": "1234"
            }))
            .await;

        assert_eq!(register_totp_response.status_code(), 200);
        let totp_register: RegisterTOTPResponse =
            serde_json::from_str(&register_totp_response.text()).unwrap();

        // Extract the base32 secret from the otpauth URL
        let url = totp_register.url;
        let secret_b32 = url
            .split("secret=")
            .nth(1)
            .and_then(|s| s.split('&').next())
            .expect("secret should exist in otpauth url");
        let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret_b32)
            .expect("failed to decode base32 secret");

        // Create a TOTP instance compatible with server settings and generate a code
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
            Some("loco-poc-2fa".to_string()),
            login_data.user.email.clone(),
        )
        .expect("failed to create totp instance");
        let totp_code = totp.generate_current().expect("generate totp code");

        // Verify TOTP setup
        let verify_totp_response = request
            .post("/api/auth/verify-totp")
            .add_header(auth_key, auth_value)
            .json(&serde_json::json!({
                "totp": totp_code
            }))
            .await;
        assert_eq!(verify_totp_response.status_code(), 200);

        // Try password-only login: should now require TOTP (return a challenge)
        let login_response = request
            .post("/api/auth/login")
            .json(&serde_json::json!({
                "email": login_data.user.email,
                "password": "1234"
            }))
            .await;
        assert_eq!(login_response.status_code(), 200);

        let login_resp: LoginResponse = serde_json::from_str(&login_response.text()).unwrap();
        let totp_login_token = match login_resp {
            LoginResponse::TOTPChallenge(ch) => ch.totp_login_token,
            _ => panic!("expected TOTPChallenge after password login when TOTP is enabled"),
        };

        // Complete login by providing the TOTP code
        let totp_code_2 = totp.generate_current().expect("generate totp code");
        let final_login_response = request
            .post("/api/auth/login-totp")
            .json(&serde_json::json!({
                "email": login_data.user.email,
                "token": totp_login_token,
                "totp": totp_code_2
            }))
            .await;
        assert_eq!(final_login_response.status_code(), 200);
        let final_login: LoginResponse =
            serde_json::from_str(&final_login_response.text()).unwrap();
        match final_login {
            LoginResponse::Login(_) => {}
            _ => panic!("expected successful login after providing valid TOTP code"),
        }
    })
    .await;
}

#[tokio::test]
#[serial]
async fn can_login_with_totp_via_magic_link() {
    configure_insta!();

    request::<App, _, _>(|request, ctx| async move {
        // Register a new user with an allowed domain for magic link
        let email = "mltotp@example.com";
        let password = "1234";
        let register_payload = serde_json::json!({
            "name": "mltotp",
            "email": email,
            "password": password
        });

        let register_response = request
            .post("/api/auth/register")
            .json(&register_payload)
            .await;
        assert_eq!(register_response.status_code(), 200);

        // Login with password to obtain a JWT for TOTP registration
        let login_response = request
            .post("/api/auth/login")
            .json(&serde_json::json!({
                "email": email,
                "password": password
            }))
            .await;
        assert_eq!(login_response.status_code(), 200);
        let login_data: LoginData = serde_json::from_str(&login_response.text()).unwrap();

        // Register TOTP using the JWT and password
        let (auth_key, auth_value) = prepare_data::auth_header(&login_data.token);
        let register_totp_response = request
            .post("/api/auth/register-totp")
            .add_header(auth_key.clone(), auth_value.clone())
            .json(&serde_json::json!({
                "password": password
            }))
            .await;
        assert_eq!(register_totp_response.status_code(), 200);

        let totp_register: RegisterTOTPResponse =
            serde_json::from_str(&register_totp_response.text()).unwrap();

        // Extract base32 secret from otpauth URL and build TOTP generator
        let url = totp_register.url;
        let secret_b32 = url
            .split("secret=")
            .nth(1)
            .and_then(|s| s.split('&').next())
            .expect("secret should exist in otpauth url");
        let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret_b32)
            .expect("failed to decode base32 secret");

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
            Some("loco-poc-2fa".to_string()),
            email.to_string(),
        )
        .expect("failed to create totp instance");
        let totp_code = totp.generate_current().expect("generate totp code");

        // Verify TOTP setup
        let verify_totp_response = request
            .post("/api/auth/verify-totp")
            .add_header(auth_key, auth_value)
            .json(&serde_json::json!({
                "totp": totp_code
            }))
            .await;
        assert_eq!(verify_totp_response.status_code(), 200);

        // Start magic link flow
        let magic_link_request = request
            .post("/api/auth/magic-link")
            .json(&serde_json::json!({
                "email": email
            }))
            .await;
        assert_eq!(magic_link_request.status_code(), 200);

        // Fetch magic link token issued to the user
        let user = users::Model::find_by_email(&ctx.db, email)
            .await
            .expect("User should be found");
        let magic_link_token = user
            .magic_link_token
            .expect("Magic link token should be generated");

        // Verify magic link. Since TOTP is enabled, expect a TOTP challenge
        let magic_link_verify_response = request
            .post("/api/auth/magic-link-verify")
            .json(&serde_json::json!({
                "email": email,
                "token": magic_link_token
            }))
            .await;
        assert_eq!(magic_link_verify_response.status_code(), 200);
        let challenge: LoginResponse =
            serde_json::from_str(&magic_link_verify_response.text()).unwrap();
        let totp_login_token = match challenge {
            LoginResponse::TOTPChallenge(ch) => ch.totp_login_token,
            _ => panic!("expected TOTPChallenge after magic link verify when TOTP is enabled"),
        };

        // Complete login by providing the TOTP code to the dedicated endpoint
        let totp_code_2 = totp.generate_current().expect("generate totp code");
        let final_login_response = request
            .post("/api/auth/login-totp")
            .json(&serde_json::json!({
                "email": email,
                "token": totp_login_token,
                "totp": totp_code_2
            }))
            .await;
        assert_eq!(final_login_response.status_code(), 200);
        let final_login: LoginResponse =
            serde_json::from_str(&final_login_response.text()).unwrap();
        match final_login {
            LoginResponse::Login(_) => {}
            _ => panic!(
                "expected successful login after providing valid TOTP code via magic link flow"
            ),
        }
    })
    .await;
}
