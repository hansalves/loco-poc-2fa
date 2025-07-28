
start:
	cargo loco start

tailwind-update:
	cd ./frontend && npx @tailwindcss/cli -i ./src/input.css -o ./src/css/style.css

tailwind-watch:
	cd ./frontend && npx @tailwindcss/cli -i ./src/input.css -o ./src/css/style.css --watch

create-user:
	curl -i -d '{"name":"test","email":"test@example.com","password":"foobar"}' -H 'Content-Type: application/json' 'http://localhost:5150/api/auth/register'

reset-totp:
	sqlite3 loco-poc-2fa_development.sqlite 'update users set totp_secret = null, totp_verified_at = null, totp_login_token = null, totp_login_token_expiration = null'
