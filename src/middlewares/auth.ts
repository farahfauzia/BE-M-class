import { createHash } from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import type { RowDataPacket } from "mysql2";
import pool from "../config/db";
import { ApiError } from "../utils/api-error";

export interface AuthUser {
  id: string;
  name: string;
  nisn: string;
  email: string;
  role: "student" | "admin" | "teacher";
}

declare global {
  namespace Express {
    interface Request {
      authUser?: AuthUser;
      authTokenHash?: string;
    }
  }
}

interface AuthSessionRow extends RowDataPacket, AuthUser {}

export function getAuthenticatedUser(req: Request): AuthUser {
  if (!req.authUser) {
    throw new ApiError(401, "Autentikasi diperlukan.");
  }
  return req.authUser;
}

export function authorizeRoles(...allowedRoles: AuthUser["role"][]) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const user = req.authUser;
    if (!user) {
      next(new ApiError(401, "Autentikasi diperlukan."));
      return;
    }
    if (!allowedRoles.includes(user.role)) {
      next(new ApiError(403, "Anda tidak memiliki wewenang untuk mengakses resource ini."));
      return;
    }
    next();
  };
}

export async function authenticate(req: Request, _res: Response, next: NextFunction): Promise<void> {
  const authorization = req.header("authorization");
  const match = authorization?.match(/^Bearer ([\da-f]{64})$/i);
  if (!match) {
    throw new ApiError(401, "Token autentikasi tidak ada atau tidak valid.");
  }

  const tokenHash = createHash("sha256").update(match[1]).digest("hex");
  const [rows] = await pool.execute<AuthSessionRow[]>(
    `SELECT u.id, u.name, u.nisn, u.email, u.role
     FROM auth_sessions s
     INNER JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > CURRENT_TIMESTAMP AND u.is_active = TRUE`,
    [tokenHash],
  );

  const user = rows[0];
  if (!user) {
    throw new ApiError(401, "Sesi tidak valid atau sudah kedaluwarsa.");
  }

  req.authUser = user;
  req.authTokenHash = tokenHash;
  next();
}
