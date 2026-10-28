# BE-M-class

## Password reset configuration

Set these environment variables before using the password reset endpoints:

- `PASSWORD_RESET_SECRET`: private random secret with at least 32 characters, used to HMAC email identifiers, OTPs, and reset tokens.
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, and `SMTP_FROM`: SMTP connection and sender configuration.
- `SMTP_SECURE`: set to `true` when the SMTP server uses implicit TLS (commonly port 465). Otherwise, the service requires STARTTLS and fails delivery if the server does not support it.

The server creates the `password_reset_requests` table during schema initialization. Password reset uses a 6-digit OTP that expires after 10 minutes, allows up to 5 verification attempts, limits requests to 3 per email in 15 minutes, and issues a single-use reset token valid for 10 minutes. A successful reset revokes the user's existing sessions. Reset-email delivery is queued asynchronously so SMTP latency does not reveal whether the account exists; delivery failures are logged on the server.

## Password reset API

1. `POST /api/auth/forgot-password` with `{ "email": "user@example.com" }` returns `202` with a generic message, regardless of whether the account exists.
2. `POST /api/auth/verify-otp` with `{ "email": "user@example.com", "otp": "123456" }` returns a short-lived `resetToken` only when the OTP is valid.
3. `POST /api/auth/reset-password` with `{ "email": "user@example.com", "resetToken": "<token>", "newPassword": "<new password>" }` changes the password, consumes the token, and revokes existing sessions.

Validation errors return `400` with an `errors` object keyed by field. Configure the password-reset secret and SMTP credentials before enabling these routes in a deployed environment.