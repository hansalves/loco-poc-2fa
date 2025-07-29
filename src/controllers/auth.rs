use crate::{
    mailers::auth::AuthMailer,
    models::{
        _entities::users,
        users::{LoginParams, RegisterParams},
    },
    views::auth::{CurrentResponse, LoginData, LoginResponse, RegisterTOTPResponse, TOTPChallenge},
};
use axum::debug_handler;
use loco_rs::{controller::ErrorDetail, prelude::*};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use totp_rs::{Algorithm, TOTP};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
    Key,
    Nonce, // Or `Aes128Gcm`
};
use zeroize::Zeroize;

pub static EMAIL_DOMAIN_RE: OnceLock<Regex> = OnceLock::new();

fn get_allow_email_domain_re() -> &'static Regex {
    EMAIL_DOMAIN_RE.get_or_init(|| {
        Regex::new(r"@example\.com$|@gmail\.com$").expect("Failed to compile regex")
    })
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForgotParams {
    pub email: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ResetParams {
    pub token: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MagicLinkParams {
    pub email: String,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct MagicLinkVerifyParams {
    pub email: String,
    pub token: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ResendVerificationParams {
    pub email: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RegisterTOTPParams {
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VerifyTOTPParams {
    pub totp: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginTOTPParams {
    pub email: String,
    pub token: String,
    pub totp: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ChangePasswordParams {
    pub old_password: String,
    pub new_password: String,
}

/// Register function creates a new user with the given parameters and sends a
/// welcome email to the user
#[debug_handler]
async fn register(
    State(ctx): State<AppContext>,
    Json(params): Json<RegisterParams>,
) -> Result<Response> {
    let res = users::Model::create_with_password(&ctx.db, &params).await;

    let user = match res {
        Ok(user) => user,
        Err(err) => {
            tracing::info!(
                message = err.to_string(),
                user_email = &params.email,
                "could not register user",
            );
            return format::json(());
        }
    };

    let user = user
        .into_active_model()
        .set_email_verification_sent(&ctx.db)
        .await?;

    AuthMailer::send_welcome(&ctx, &user).await?;

    format::json(())
}

/// Verify register user. if the user not verified his email, he can't login to
/// the system.
#[debug_handler]
async fn verify(State(ctx): State<AppContext>, Path(token): Path<String>) -> Result<Response> {
    let Ok(user) = users::Model::find_by_verification_token(&ctx.db, &token).await else {
        return unauthorized("invalid token");
    };

    if user.email_verified_at.is_some() {
        tracing::info!(pid = user.pid.to_string(), "user already verified");
    } else {
        let active_model = user.into_active_model();
        let user = active_model.verified(&ctx.db).await?;
        tracing::info!(pid = user.pid.to_string(), "user verified");
    }

    format::json(())
}

/// In case the user forgot his password  this endpoints generate a forgot token
/// and send email to the user. In case the email not found in our DB, we are
/// returning a valid request for for security reasons (not exposing users DB
/// list).
#[debug_handler]
async fn forgot(
    State(ctx): State<AppContext>,
    Json(params): Json<ForgotParams>,
) -> Result<Response> {
    let Ok(user) = users::Model::find_by_email(&ctx.db, &params.email).await else {
        // we don't want to expose our users email. if the email is invalid we still
        // returning success to the caller
        return format::json(());
    };

    let user = user
        .into_active_model()
        .set_forgot_password_sent(&ctx.db)
        .await?;

    AuthMailer::forgot_password(&ctx, &user).await?;

    format::json(())
}

/// reset user password by the given parameters
#[debug_handler]
async fn reset(State(ctx): State<AppContext>, Json(params): Json<ResetParams>) -> Result<Response> {
    let Ok(user) = users::Model::find_by_reset_token(&ctx.db, &params.token).await else {
        // we don't want to expose our users email. if the email is invalid we still
        // returning success to the caller
        tracing::info!("reset token not found");

        return format::json(());
    };
    user.into_active_model()
        .reset_password(&ctx.db, &params.password)
        .await?;

    format::json(())
}

/// Creates a user login and returns a token
#[debug_handler]
async fn login(State(ctx): State<AppContext>, Json(params): Json<LoginParams>) -> Result<Response> {
    let Ok(user) = users::Model::find_by_email(&ctx.db, &params.email).await else {
        tracing::debug!(
            email = params.email,
            "login attempt with non-existent email"
        );
        return unauthorized("Invalid credentials!");
    };

    let valid = user.verify_password(&params.password);

    if !valid {
        return unauthorized("unauthorized!");
    }

    if user.totp_verified_at.is_some() {
        let user = user
            .into_active_model()
            .create_totp_login_token(&ctx.db)
            .await?;
        return format::json(LoginResponse::TOTPChallenge(TOTPChallenge::new(&user)?));
    }

    let jwt_secret = ctx.config.get_jwt_config()?;

    let token = user
        .generate_jwt(&jwt_secret.secret, jwt_secret.expiration)
        .or_else(|_| unauthorized("unauthorized!"))?;

    format::json(LoginResponse::Login(LoginData::new(&user, &token)))
}

#[debug_handler]
async fn current(auth: auth::JWT, State(ctx): State<AppContext>) -> Result<Response> {
    let user = users::Model::find_by_pid(&ctx.db, &auth.claims.pid).await?;
    format::json(CurrentResponse::new(&user))
}

/// Magic link authentication provides a secure and passwordless way to log in to the application.
///
/// # Flow
/// 1. **Request a Magic Link**:
///    A registered user sends a POST request to `/magic-link` with their email.
///    If the email exists, a short-lived, one-time-use token is generated and sent to the user's email.
///    For security and to avoid exposing whether an email exists, the response always returns 200, even if the email is invalid.
///
/// 2. **Click the Magic Link**:
///    The user clicks the link (/magic-link/{token}), which validates the token and its expiration.
///    If valid, the server generates a JWT and responds with a [`LoginResponse`].
///    If invalid or expired, an unauthorized response is returned.
///
/// This flow enhances security by avoiding traditional passwords and providing a seamless login experience.
async fn magic_link(
    State(ctx): State<AppContext>,
    Json(params): Json<MagicLinkParams>,
) -> Result<Response> {
    let email_regex = get_allow_email_domain_re();
    if !email_regex.is_match(&params.email) {
        tracing::debug!(
            email = params.email,
            "The provided email is invalid or does not match the allowed domains"
        );
        return bad_request("invalid request");
    }

    let Ok(user) = users::Model::find_by_email(&ctx.db, &params.email).await else {
        // we don't want to expose our users email. if the email is invalid we still
        // returning success to the caller
        tracing::debug!(email = params.email, "user not found by email");
        return format::empty_json();
    };

    let user = user.into_active_model().create_magic_link(&ctx.db).await?;
    AuthMailer::send_magic_link(&ctx, &user).await?;

    format::empty_json()
}

/// Verifies a magic link token and authenticates the user.
async fn magic_link_verify(
    State(ctx): State<AppContext>,
    Json(params): Json<MagicLinkVerifyParams>,
) -> Result<Response> {
    // find by email instead of magic link token, because we have an index on the email column
    let Ok(user) = users::Model::find_by_email(&ctx.db, &params.email).await else {
        return unauthorized("unauthorized!");
    };
    if let Some(magic_link_token) = &user.magic_link_token {
        if magic_link_token != &params.token {
            return unauthorized("unauthorized!");
        }
    } else {
        return unauthorized("unauthorized!");
    }

    if let Some(expired_at) = user.magic_link_expiration {
        if expired_at <= chrono::Local::now() {
            tracing::debug!(
                user_pid = user.pid.to_string(),
                token_expiration = expired_at.to_string(),
                "magic token expired for the user."
            );
            return unauthorized("unauthorized!");
        }
    } else {
        tracing::error!(
            user_pid = user.pid.to_string(),
            "magic link expiration time not exists"
        );
        return unauthorized("unauthorized!");
    }

    let totp_login = user.totp_verified_at.is_some();

    let user = user
        .into_active_model()
        .clear_magic_link(&ctx.db, totp_login)
        .await?;

    if totp_login {
        return format::json(LoginResponse::TOTPChallenge(TOTPChallenge::new(&user)?));
    }

    let jwt_secret = ctx.config.get_jwt_config()?;

    let token = user
        .generate_jwt(&jwt_secret.secret, jwt_secret.expiration)
        .or_else(|_| unauthorized("unauthorized!"))?;

    format::json(LoginResponse::Login(LoginData::new(&user, &token)))
}

#[debug_handler]
async fn resend_verification_email(
    State(ctx): State<AppContext>,
    Json(params): Json<ResendVerificationParams>,
) -> Result<Response> {
    let Ok(user) = users::Model::find_by_email(&ctx.db, &params.email).await else {
        tracing::info!(
            email = params.email,
            "User not found for resend verification"
        );
        return format::json(());
    };

    if user.email_verified_at.is_some() {
        tracing::info!(
            pid = user.pid.to_string(),
            "User already verified, skipping resend"
        );
        return format::json(());
    }

    let user = user
        .into_active_model()
        .set_email_verification_sent(&ctx.db)
        .await?;

    AuthMailer::send_welcome(&ctx, &user).await?;
    tracing::info!(pid = user.pid.to_string(), "Verification email re-sent");

    format::json(())
}

fn decrypt_totp_secret(encrypted_secret: &str) -> Result<Vec<u8>, loco_rs::Error> {
    let mut totp_enc_key = base32::decode(
        base32::Alphabet::Rfc4648 { padding: false },
        &std::env::var("TOTP_ENC_KEY")
            .expect("totp encryption key not found, set TOTP_ENC_KEY env var"),
    )
    .expect("Failed to decode totp encryption key, should be base32 encoded");
    let key = Key::<Aes256Gcm>::from_slice(&totp_enc_key);
    let cipher = Aes256Gcm::new(&key);
    let parts: Vec<&str> = encrypted_secret.split('.').collect();
    if parts.len() != 2 {
        return Err(loco_rs::Error::InternalServerError);
    }
    let nonce = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, parts[1])
        .expect("Failed to decode nonce, should be base32 encoded");
    if nonce.len() != 12 {
        return Err(loco_rs::Error::InternalServerError);
    }
    let nonce = Nonce::from_slice(&nonce);
    let encrypted_secret = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, parts[0])
        .expect("Failed to decode encrypted secret, should be base32 encoded");

    let secret = cipher.decrypt(&nonce, encrypted_secret.as_ref());
    totp_enc_key.zeroize();
    secret.map_err(|_| loco_rs::Error::InternalServerError)
}

#[debug_handler]
async fn register_totp(
    auth: auth::JWT,
    State(ctx): State<AppContext>,
    Json(params): Json<RegisterTOTPParams>,
) -> Result<Response> {
    let user = users::Model::find_by_pid(&ctx.db, &auth.claims.pid).await?;

    let valid = user.verify_password(&params.password);
    if !valid {
        return unauthorized("unauthorized!");
    }

    let user = user.into_active_model().set_totp_secret(&ctx.db).await?;

    if let Some(encrypted_secret) = user.totp_secret {
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            decrypt_totp_secret(&encrypted_secret)?,
            Some("Check".to_string()),
            user.email.clone(),
        )
        .map_err(|_| loco_rs::Error::InternalServerError)?; // do this after zeroize so the decrypted secret will always be zeroized

        let url = totp.get_url();
        let qr_code = totp
            .get_qr_base64()
            .map_err(|_| loco_rs::Error::InternalServerError)?;
        format::json(RegisterTOTPResponse::new(url, qr_code))
    } else {
        Err(loco_rs::Error::InternalServerError)
    }
}

#[debug_handler]
async fn verify_totp(
    auth: auth::JWT,
    State(ctx): State<AppContext>,
    Json(params): Json<VerifyTOTPParams>,
) -> Result<Response> {
    let user = users::Model::find_by_pid(&ctx.db, &auth.claims.pid).await?;

    // Check if user has TOTP secret configured
    let Some(totp_secret) = &user.totp_secret else {
        return bad_request("TOTP not configured for this user");
    };

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        decrypt_totp_secret(&totp_secret)?,
        Some("Check".to_string()),
        user.email.clone(),
    )
    .map_err(|_| loco_rs::Error::InternalServerError)?;

    // Verify the user-supplied token
    let is_valid = totp
        .check_current(&params.totp)
        .map_err(|_| loco_rs::Error::InternalServerError)?;

    if !is_valid {
        return bad_request("Invalid TOTP token");
    }

    // Mark TOTP as verified for this user
    user.into_active_model()
        .set_totp_verified_at(&ctx.db)
        .await?;

    format::json(())
}

#[debug_handler]
async fn login_totp(
    State(ctx): State<AppContext>,
    Json(params): Json<LoginTOTPParams>,
) -> Result<Response> {
    let user = users::Model::find_by_email(&ctx.db, &params.email).await?;

    let Some(totp_secret) = &user.totp_secret else {
        return bad_request("TOTP not configured for this user");
    };
    let Some(totp_login_token) = &user.totp_login_token else {
        return bad_request("TOTP login flow not started");
    };

    if let Some(totp_login_token_expiration) = user.totp_login_token_expiration {
        if totp_login_token_expiration <= chrono::Local::now() {
            tracing::debug!(
                user_pid = user.pid.to_string(),
                token_expiration = totp_login_token_expiration.to_string(),
                "totp login token expired for the user."
            );
            return Ok((
                axum::http::StatusCode::UNAUTHORIZED,
                format::json(ErrorDetail::new("unauthorized", "Login token expired")),
            )
                .into_response());
        }
    } else {
        tracing::error!(
            user_pid = user.pid.to_string(),
            "totp login token expiration time not exists"
        );
        return unauthorized("invalid expiration time");
    }

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        decrypt_totp_secret(&totp_secret)?,
        Some("Check".to_string()),
        user.email.clone(),
    )
    .map_err(|_| loco_rs::Error::InternalServerError)?;

    let is_valid = totp
        .check_current(&params.totp)
        .map_err(|_| loco_rs::Error::InternalServerError)?;

    if !is_valid {
        return Ok((
            axum::http::StatusCode::UNAUTHORIZED,
            format::json(ErrorDetail::new("unauthorized", "Invalid 2FA Code")),
        )
            .into_response());
    }
    if &params.token != totp_login_token {
        return Ok((
            axum::http::StatusCode::UNAUTHORIZED,
            format::json(ErrorDetail::new(
                "unauthorized",
                "Invalid token, please go back and login again",
            )),
        )
            .into_response());
    }

    let user = user
        .into_active_model()
        .clear_totp_login_token(&ctx.db)
        .await?;

    let jwt_secret = ctx.config.get_jwt_config()?;

    let token = user
        .generate_jwt(&jwt_secret.secret, jwt_secret.expiration)
        .or_else(|_| unauthorized("unauthorized!"))?;

    format::json(LoginResponse::Login(LoginData::new(&user, &token)))
}

#[debug_handler]
async fn change_password(
    auth: auth::JWT,
    State(ctx): State<AppContext>,
    Json(params): Json<ChangePasswordParams>,
) -> Result<Response> {
    let user = users::Model::find_by_pid(&ctx.db, &auth.claims.pid).await?;

    let valid = user.verify_password(&params.old_password);
    if !valid {
        return unauthorized("unauthorized!");
    }

    user.into_active_model()
        .set_password(&ctx.db, &params.new_password)
        .await?;

    format::json(())
}

pub fn routes() -> Routes {
    Routes::new()
        .prefix("/api/auth")
        .add("/register", post(register))
        .add("/register-totp", post(register_totp))
        .add("/verify/{token}", get(verify))
        .add("/verify-totp", post(verify_totp))
        .add("/login", post(login))
        .add("/login-totp", post(login_totp))
        .add("/forgot", post(forgot))
        .add("/reset", post(reset))
        .add("/current", get(current))
        .add("/magic-link", post(magic_link))
        .add("/magic-link-verify", post(magic_link_verify))
        .add("/change-password", post(change_password))
        .add("/resend-verification-mail", post(resend_verification_email))
}
