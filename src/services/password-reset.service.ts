import { createHmac, randomBytes, randomInt, timingSafeEqual } from "node:crypto";
import nodemailer from "nodemailer";
import type { PoolConnection, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import pool from "../config/db";
import { hashPassword } from "../utils/password";
import { ApiError } from "../utils/api-error";

const otpLifetimeMinutes = 10;
const resetTokenLifetimeMinutes = 10;
const maxOtpAttempts = 5;
const maxRequestsPerWindow = 3;
const requestWindowMinutes = 15;

interface PasswordResetRow extends RowDataPacket {
  user_id: string | null;
  otp_hash: string | null;
  otp_attempts: number;
  request_count: number;
  window_active: number;
  otp_valid: number;
  reset_token_hash: string | null;
  reset_token_valid: number;
}

function getResetSecret(): string {
  const secret = process.env.PASSWORD_RESET_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("PASSWORD_RESET_SECRET must be configured with at least 32 characters.");
  }
  return secret;
}

function digest(value: string, purpose: string): string {
  return createHmac("sha256", getResetSecret()).update(`${purpose}:${value}`).digest("hex");
}

function matchesDigest(value: string, expected: string | null, purpose: string): boolean {
  if (!expected || !/^[a-f0-9]{64}$/i.test(expected)) {
    return false;
  }
  const actualBytes = Buffer.from(digest(value, purpose), "hex");
  const expectedBytes = Buffer.from(expected, "hex");
  return timingSafeEqual(actualBytes, expectedBytes);
}

async function inTransaction<T>(callback: (connection: PoolConnection) => Promise<T>): Promise<T> {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const result = await callback(connection);
    await connection.commit();
    return result;
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
}

async function sendOtpEmail(email: string, otp: string): Promise<void> {
  const host = process.env.SMTP_HOST;
  const user = process.env.SMTP_USER;
  const password = process.env.SMTP_PASSWORD;
  const from = process.env.SMTP_FROM;
  const port = Number(process.env.SMTP_PORT);
  const secure = process.env.SMTP_SECURE === "true";
  if (!host || !user || !password || !from || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, and SMTP_FROM must be configured.");
  }

  const transporter = nodemailer.createTransport({
    host,
    port,
    secure,
    requireTLS: !secure,
    auth: { user, pass: password },
  });
  try {
    await transporter.sendMail({
      from,
      to: email,
      subject: "Kode reset password M-Class",
      text: `Kode OTP reset password Anda: ${otp}. Kode berlaku selama ${otpLifetimeMinutes} menit. Jika Anda tidak meminta reset, abaikan email ini.`,
    });
  } finally {
    transporter.close();
  }
}

export async function requestPasswordReset(email: string): Promise<void> {
  const emailHash = digest(email, "email");
  const otp = randomInt(0, 1_000_000).toString().padStart(6, "0");
  const otpHash = digest(otp, "otp");
  const [users] = await pool.execute<RowDataPacket[]>(
    "SELECT id FROM users WHERE email = ? AND is_active = TRUE LIMIT 1",
    [email],
  );
  const userId = users[0]?.id ?? null;

  const canSend = await inTransaction(async (connection) => {
    await connection.execute(
      "DELETE FROM password_reset_requests WHERE request_window_started_at < DATE_SUB(CURRENT_TIMESTAMP, INTERVAL 1 DAY)",
    );
    await connection.execute(
      `INSERT IGNORE INTO password_reset_requests
       (email_hash, otp_hash, otp_expires_at, request_count, request_window_started_at)
       VALUES (?, ?, CURRENT_TIMESTAMP, 0, CURRENT_TIMESTAMP)`,
      [emailHash, otpHash],
    );
    const [requests] = await connection.execute<PasswordResetRow[]>(
      `SELECT request_count, (request_window_started_at > DATE_SUB(CURRENT_TIMESTAMP, INTERVAL ? MINUTE)) AS window_active
       FROM password_reset_requests WHERE email_hash = ? FOR UPDATE`,
      [requestWindowMinutes, emailHash],
    );
    const request = requests[0];
    if (!request) {
      throw new Error("Password reset request row was not created.");
    }
    if (request.window_active && request.request_count >= maxRequestsPerWindow) {
      return false;
    }

    await connection.execute(
      `UPDATE password_reset_requests
       SET user_id = ?, otp_hash = ?, otp_expires_at = DATE_ADD(CURRENT_TIMESTAMP, INTERVAL ? MINUTE),
           otp_attempts = 0, reset_token_hash = NULL, reset_token_expires_at = NULL, verified_at = NULL,
           request_count = IF(request_window_started_at > DATE_SUB(CURRENT_TIMESTAMP, INTERVAL ? MINUTE), request_count + 1, 1),
           request_window_started_at = IF(request_window_started_at > DATE_SUB(CURRENT_TIMESTAMP, INTERVAL ? MINUTE), request_window_started_at, CURRENT_TIMESTAMP)
       WHERE email_hash = ?`,
      [userId, otpHash, otpLifetimeMinutes, requestWindowMinutes, requestWindowMinutes, emailHash],
    );
    return true;
  });

  if (canSend && userId !== null) {
    setImmediate(() => {
      void sendOtpEmail(email, otp).catch((error: unknown) => {
        console.error("Password reset email delivery failed:", error);
      });
    });
  }
}

export async function verifyPasswordResetOtp(email: string, otp: string): Promise<string> {
  const emailHash = digest(email, "email");
  const resetToken = randomBytes(32).toString("hex");
  const resetTokenHash = digest(resetToken, "reset-token");

  const verified = await inTransaction(async (connection) => {
    const [requests] = await connection.execute<PasswordResetRow[]>(
      `SELECT user_id, otp_hash, otp_attempts,
              (otp_expires_at > CURRENT_TIMESTAMP) AS otp_valid
       FROM password_reset_requests WHERE email_hash = ? FOR UPDATE`,
      [emailHash],
    );
    const request = requests[0];
    if (!request || !request.user_id || !request.otp_valid || !request.otp_hash || request.otp_attempts >= maxOtpAttempts) {
      return false;
    }
    if (!matchesDigest(otp, request.otp_hash, "otp")) {
      await connection.execute(
        "UPDATE password_reset_requests SET otp_attempts = otp_attempts + 1 WHERE email_hash = ?",
        [emailHash],
      );
      return false;
    }

    await connection.execute(
      `UPDATE password_reset_requests
       SET otp_hash = NULL, verified_at = CURRENT_TIMESTAMP, reset_token_hash = ?,
           reset_token_expires_at = DATE_ADD(CURRENT_TIMESTAMP, INTERVAL ? MINUTE)
       WHERE email_hash = ?`,
      [resetTokenHash, resetTokenLifetimeMinutes, emailHash],
    );
    return true;
  });

  if (!verified) {
    throw new ApiError(400, "Kode OTP tidak valid atau sudah kedaluwarsa.", { otp: "Kode OTP tidak valid atau sudah kedaluwarsa." });
  }
  return resetToken;
}

export async function resetPassword(email: string, resetToken: string, newPassword: string): Promise<void> {
  const emailHash = digest(email, "email");
  const passwordHash = await hashPassword(newPassword);

  const updated = await inTransaction(async (connection) => {
    const [requests] = await connection.execute<PasswordResetRow[]>(
      `SELECT user_id, reset_token_hash,
              (verified_at IS NOT NULL AND reset_token_expires_at > CURRENT_TIMESTAMP) AS reset_token_valid
       FROM password_reset_requests WHERE email_hash = ? FOR UPDATE`,
      [emailHash],
    );
    const request = requests[0];
    if (!request || !request.user_id || !request.reset_token_valid || !matchesDigest(resetToken, request.reset_token_hash, "reset-token")) {
      return false;
    }

    const [updateResult] = await connection.execute<ResultSetHeader>(
      "UPDATE users SET password_hash = ? WHERE id = ? AND is_active = TRUE",
      [passwordHash, request.user_id],
    );
    if (updateResult.affectedRows !== 1) {
      return false;
    }
    await connection.execute("DELETE FROM auth_sessions WHERE user_id = ?", [request.user_id]);
    await connection.execute("DELETE FROM password_reset_requests WHERE email_hash = ?", [emailHash]);
    return true;
  });

  if (!updated) {
    throw new ApiError(400, "Token reset tidak valid atau sudah kedaluwarsa.", { resetToken: "Token reset tidak valid atau sudah kedaluwarsa." });
  }
}
