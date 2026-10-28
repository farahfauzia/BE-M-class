import type { RowDataPacket } from "mysql2";
import pool from "./db";

interface RoleColumnRow extends RowDataPacket {
  COLUMN_TYPE: string;
}

export async function initializeSchema(): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      name VARCHAR(150) NOT NULL,
      nisn VARCHAR(32) NOT NULL,
      email VARCHAR(254) NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      role ENUM('student', 'admin', 'teacher') NOT NULL DEFAULT 'student',
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY users_nisn_unique (nisn),
      UNIQUE KEY users_email_unique (email)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);

  const [roleColumns] = await pool.query<RoleColumnRow[]>(
    `SELECT COLUMN_TYPE
     FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'role'`,
  );
  const roleColumnType = roleColumns[0]?.COLUMN_TYPE;

  if (roleColumnType?.includes("'user'")) {
    await pool.query(
      "ALTER TABLE users MODIFY role ENUM('user', 'student', 'admin', 'teacher') NOT NULL DEFAULT 'student'",
    );
    await pool.query("UPDATE users SET role = 'student' WHERE role = 'user'");
    await pool.query(
      "ALTER TABLE users MODIFY role ENUM('student', 'admin', 'teacher') NOT NULL DEFAULT 'student'",
    );
  } else if (
    !roleColumnType?.includes("'student'") ||
    !roleColumnType.includes("'teacher'")
  ) {
    await pool.query(
      "ALTER TABLE users MODIFY role ENUM('student', 'admin', 'teacher') NOT NULL DEFAULT 'student'",
    );
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS auth_sessions (
      token_hash CHAR(64) NOT NULL,
      user_id BIGINT UNSIGNED NOT NULL,
      expires_at TIMESTAMP NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (token_hash),
      KEY auth_sessions_user_id_index (user_id),
      KEY auth_sessions_expires_at_index (expires_at),
      CONSTRAINT auth_sessions_user_id_foreign
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_reset_requests (
      email_hash CHAR(64) NOT NULL,
      user_id BIGINT UNSIGNED NULL,
      otp_hash CHAR(64) NULL,
      otp_expires_at DATETIME NULL,
      otp_attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
      request_count TINYINT UNSIGNED NOT NULL DEFAULT 0,
      request_window_started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      reset_token_hash CHAR(64) NULL,
      reset_token_expires_at DATETIME NULL,
      verified_at DATETIME NULL,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (email_hash),
      KEY password_reset_user_id_index (user_id),
      KEY password_reset_window_index (request_window_started_at),
      CONSTRAINT password_reset_user_id_foreign
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);
}
