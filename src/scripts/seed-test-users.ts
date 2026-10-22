import "dotenv/config";
import type { ResultSetHeader, RowDataPacket } from "mysql2";
import pool from "../config/db";
import { initializeSchema } from "../config/schema";
import { hashPassword } from "../utils/password";

interface ExistingUser extends RowDataPacket {
  id: string;
  name: string;
  nisn: string;
  email: string;
  role: "student" | "admin" | "teacher";
}

const testPassword = "MclassTest123!";
const testUsers = [
  {
    name: "Dummy Student",
    nisn: "TESTSTUDENT001",
    email: "student.test@mclass.local",
    role: "student",
  },
  {
    name: "Dummy Admin",
    nisn: "TESTADMIN001",
    email: "admin.test@mclass.local",
    role: "admin",
  },
  {
    name: "Dummy Teacher",
    nisn: "TESTTEACHER001",
    email: "teacher.test@mclass.local",
    role: "teacher",
  },
] as const;

async function seedTestUsers(): Promise<void> {
  if (process.env.NODE_ENV === "production") {
    throw new Error("Test users must not be seeded in production.");
  }

  await initializeSchema();

  for (const testUser of testUsers) {
    const [rows] = await pool.execute<ExistingUser[]>(
      "SELECT id, name, nisn, email, role FROM users WHERE email = ? OR nisn = ?",
      [testUser.email, testUser.nisn],
    );
    const existingUser = rows[0];
    const passwordHash = await hashPassword(testPassword);

    if (existingUser) {
      if (
        existingUser.email !== testUser.email ||
        existingUser.nisn !== testUser.nisn ||
        existingUser.role !== testUser.role
      ) {
        throw new Error(
          `Cannot seed ${testUser.email}: its email or NISN is already used by a different account.`,
        );
      }

      await pool.execute<ResultSetHeader>(
        "UPDATE users SET name = ?, password_hash = ?, is_active = TRUE WHERE id = ?",
        [testUser.name, passwordHash, existingUser.id],
      );
      console.log(`Updated ${testUser.role}: ${testUser.email}`);
      continue;
    }

    await pool.execute<ResultSetHeader>(
      "INSERT INTO users (name, nisn, email, password_hash, role) VALUES (?, ?, ?, ?, ?)",
      [testUser.name, testUser.nisn, testUser.email, passwordHash, testUser.role],
    );
    console.log(`Created ${testUser.role}: ${testUser.email}`);
  }

  console.log(`Test password for all seeded accounts: ${testPassword}`);
}

seedTestUsers()
  .catch((error: unknown) => {
    console.error("Failed to seed test users:", error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await pool.end();
  });
