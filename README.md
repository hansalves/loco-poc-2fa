# Welcome to Loco-poc-2fa :train:

[Loco](https://loco.rs) is a web and API framework running on Rust.

This is the **SaaS starter** which includes a `User` model and authentication based on JWT.
It also include configuration sections that help you pick either a frontend or a server-side template set up for your fullstack server.

In this project the user model has been modified to allow for two factor authentication using [totp-rs](https://crates.io/crates/totp-rs).

The frontend has been made using [🍦VanJS](https://vanjs.org/) and does not require a build step. 

To test the project 

- generate an encryption key for the totp secrets using for instance `head -c 32 /dev/urandom | base32`
- run `TOTP_ENC_KEY=....... cargo loco start` (replace ....... by the generated key)
- call the api to register a user `curl -i -d '{"name":"test","email":"test@example.com","password":"foobar"}' -H 'Content-Type: application/json' 'http://localhost:5150/api/auth/register'`.
- open http://localhost:5150/login in your browser
- login using un `test@example.com` and pw `foobar`
- after logging in, go to http://localhost:5150/account and use the `Setup 2FA` button to set register a TOTP secret
- logout
- when logging in again you'll be asked for a totp code

