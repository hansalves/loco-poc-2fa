use serde::{Deserialize, Serialize};

use crate::models::_entities::users;

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum LoginResponse {
    Login(LoginData),
    TOTPChallenge(TOTPChallenge),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TOTPChallenge {
    pub totp_login_token: String,
}

impl TOTPChallenge {
    #[must_use]
    pub fn new(user: &users::Model) -> Result<Self, loco_rs::Error> {
        let Some(token) = &user.totp_login_token else {
            return Err(loco_rs::Error::InternalServerError);
        };
        Ok(Self {
            totp_login_token: token.clone(),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginData {
    pub token: String,
    pub pid: String,
    pub name: String,
    pub email: String,
    pub is_verified: bool,
}

impl LoginData {
    #[must_use]
    pub fn new(user: &users::Model, token: &String) -> Self {
        Self {
            token: token.to_string(),
            pid: user.pid.to_string(),
            name: user.name.clone(),
            email: user.email.clone(),
            is_verified: user.email_verified_at.is_some(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CurrentResponse {
    pub pid: String,
    pub name: String,
    pub email: String,
    pub totp_setup: bool,
}

impl CurrentResponse {
    #[must_use]
    pub fn new(user: &users::Model) -> Self {
        Self {
            pid: user.pid.to_string(),
            name: user.name.clone(),
            email: user.email.clone(),
            totp_setup: user.totp_verified_at.is_some(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RegisterTOTPResponse {
    pub url: String,
    pub qr_code: String,
}

impl RegisterTOTPResponse {
    #[must_use]
    pub fn new(url: String, qr_code: String) -> Self {
        Self {
            url: url,
            qr_code: qr_code,
        }
    }
}
