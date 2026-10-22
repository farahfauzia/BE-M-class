import { createHash, randomBytes } from "node:crypto";
import type { Request, Response } from "express";
import type { ResultSetHeader, RowDataPacket } from "mysql2";
import pool from "../config/db";
import { getAuthenticatedUser, type AuthUser } from "../middlewares/auth";
import { hashPassword, verifyPassword } from "../utils/password";
import { ApiError } from "../utils/api-error";

interface UserRow extends RowDataPacket {
  id: string;
  name: string;
  nisn: string;
  email: string;
  password_hash: string;
  role: AuthUser["role"];
  is_active: number;
}

interface PublicUser {
  id: string;
  name: string;
  nisn: string;
  email: string;
  role: AuthUser["role"];
}

function getBody(req: Request): Record<string, unknown> {
  const body: unknown = req.body;
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new ApiError(400, "Body request harus berupa object JSON.");
  }
  return body as Record<string, unknown>;
}

function requiredString(body: Record<string, unknown>, field: string): string {
  const value = body[field];
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new ApiError(400, `${field} wajib diisi.`);
  }
  return value.trim();
}

function toPublicUser(user: Pick<UserRow, "id" | "name" | "nisn" | "email" | "role">): PublicUser {
  return {
    id: user.id,
    name: user.name,
    nisn: user.nisn,
    email: user.email,
    role: user.role,
  };
}

function isDuplicateEntry(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ER_DUP_ENTRY";
}

async function createSession(userId: string): Promise<string> {
  const token = randomBytes(32).toString("hex");
  const tokenHash = createHash("sha256").update(token).digest("hex");
  await pool.execute(
    "INSERT INTO auth_sessions (token_hash, user_id, expires_at) VALUES (?, ?, DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 7 DAY))",
    [tokenHash, userId],
  );
  return token;
}

export async function register(req: Request, res: Response): Promise<void> {
  const body = getBody(req);
  const name = requiredString(body, "name");
  const nisn = requiredString(body, "nisn");
  const email = requiredString(body, "email").toLowerCase();
  const password = body.password;

  if (name.length > 150 || nisn.length > 32 || email.length > 254) {
    throw new ApiError(400, "Nama, NISN, atau email melebihi batas panjang.");
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new ApiError(400, "Format email tidak valid.");
  }
  if (typeof password !== "string" || password.length < 8 || password.length > 128) {
    throw new ApiError(400, "Password harus terdiri dari 8 sampai 128 karakter.");
  }

  try {
    const passwordHash = await hashPassword(password);
    const [result] = await pool.execute<ResultSetHeader>(
      "INSERT INTO users (name, nisn, email, password_hash, role) VALUES (?, ?, ?, ?, 'student')",
      [name, nisn, email, passwordHash],
    );
    res.status(201).json({
      message: "Pendaftaran berhasil. Silakan login.",
      user: { id: String(result.insertId), name, nisn, email, role: "student" },
    });
  } catch (error) {
    if (isDuplicateEntry(error)) {
      throw new ApiError(409, "Email atau NISN sudah terdaftar.");
    }
    throw error;
  }
}

export async function login(expectedRoles: readonly AuthUser["role"][], req: Request, res: Response): Promise<void> {
  const body = getBody(req);
  const identity = requiredString(body, "identity").toLowerCase();
  const password = body.password;
  if (typeof password !== "string" || password.length === 0) {
    throw new ApiError(400, "password wajib diisi.");
  }

  const [rows] = await pool.execute<UserRow[]>(
    `SELECT id, name, nisn, email, password_hash, role, is_active
     FROM users
     WHERE email = ? OR nisn = ?
     LIMIT 1`,
    [identity, identity],
  );

  const user = rows[0];
  if (
    !user ||
    !user.is_active ||
    !(await verifyPassword(password, user.password_hash))
  ) {
    throw new ApiError(401, "Email/NISN atau password tidak valid.");
  }
  if (!expectedRoles.includes(user.role)) {
    throw new ApiError(403, "Akun ini tidak memiliki wewenang untuk login melalui endpoint tersebut.");
  }

  const token = await createSession(user.id);
  res.json({
    message: "Login berhasil.",
    token,
    tokenType: "Bearer",
    expiresIn: 604800,
    user: toPublicUser(user),
  });
}

export async function getMe(req: Request, res: Response): Promise<void> {
  res.json({ user: getAuthenticatedUser(req) });
}

export async function updateMe(req: Request, res: Response): Promise<void> {
  const body = getBody(req);
  const allowedFields = ["name", "nisn", "email"] as const;
  const updates: string[] = [];
  const values: string[] = [];

  for (const field of allowedFields) {
    if (body[field] !== undefined) {
      const value = requiredString(body, field);
      const maxLength = field === "name" ? 150 : field === "email" ? 254 : 32;
      if (value.length > maxLength) {
        throw new ApiError(400, `${field} melebihi batas panjang.`);
      }
      if (field === "email" && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
        throw new ApiError(400, "Format email tidak valid.");
      }
      updates.push(`${field} = ?`);
      values.push(field === "email" ? value.toLowerCase() : value);
    }
  }

  if (updates.length === 0) {
    throw new ApiError(400, "Isi setidaknya satu field: name, nisn, atau email.");
  }
  const user = getAuthenticatedUser(req);
  values.push(user.id);

  try {
    await pool.execute(`UPDATE users SET ${updates.join(", ")} WHERE id = ?`, values);
    const [rows] = await pool.execute<UserRow[]>(
      "SELECT id, name, nisn, email, password_hash, role, is_active FROM users WHERE id = ?",
      [user.id],
    );
    const updatedUser = rows[0];
    if (!updatedUser) {
      throw new ApiError(404, "Akun tidak ditemukan.");
    }
    res.json({ message: "Profil berhasil diperbarui.", user: toPublicUser(updatedUser) });
  } catch (error) {
    if (isDuplicateEntry(error)) {
      throw new ApiError(409, "Email atau NISN sudah digunakan akun lain.");
    }
    throw error;
  }
}

export async function deleteMe(req: Request, res: Response): Promise<void> {
  const user = getAuthenticatedUser(req);
  await pool.execute("DELETE FROM users WHERE id = ?", [user.id]);
  res.status(204).end();
}

export async function logout(req: Request, res: Response): Promise<void> {
  if (!req.authTokenHash) {
    throw new ApiError(401, "Sesi tidak valid.");
  }
  await pool.execute("DELETE FROM auth_sessions WHERE token_hash = ?", [req.authTokenHash]);
  res.json({ message: "Logout berhasil." });
}
