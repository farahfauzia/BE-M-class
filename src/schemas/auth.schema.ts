import { z } from "zod";
import { ApiError } from "../utils/api-error";

export const registerSchema = z.object({
  name: z.string().trim().min(1, "name wajib diisi.").max(150, "name tidak boleh melebihi 150 karakter."),
  nisn: z.string().trim().min(1, "nisn wajib diisi.").max(32, "nisn tidak boleh melebihi 32 karakter."),
  email: z
    .string()
    .trim()
    .max(254, "email tidak boleh melebihi 254 karakter.")
    .email("Format email tidak valid.")
    .transform((email) => email.toLowerCase()),
  password: z.string().min(8, "Password harus terdiri dari 8 sampai 128 karakter.").max(128, "Password harus terdiri dari 8 sampai 128 karakter."),
});

export const loginSchema = z.object({
  identity: z.string().trim().min(1, "identity wajib diisi.").max(254, "identity tidak boleh melebihi 254 karakter.").transform((identity) => identity.toLowerCase()),
  password: z.string().min(1, "password wajib diisi.").max(128, "Password tidak boleh melebihi 128 karakter."),
});

export const updateProfileSchema = z
  .object({
    name: z.string().trim().min(1, "name wajib diisi.").max(150, "name tidak boleh melebihi 150 karakter.").optional(),
    nisn: z.string().trim().min(1, "nisn wajib diisi.").max(32, "nisn tidak boleh melebihi 32 karakter.").optional(),
    email: z
      .string()
      .trim()
      .max(254, "email tidak boleh melebihi 254 karakter.")
      .email("Format email tidak valid.")
      .transform((email) => email.toLowerCase())
      .optional(),
  })
  .refine((value) => Object.values(value).some((field) => field !== undefined), {
    message: "Isi setidaknya satu field: name, nisn, atau email.",
    path: ["body"],
  });

export const forgotPasswordSchema = z.object({
  email: z.string().trim().max(254, "email tidak boleh melebihi 254 karakter.").email("Format email tidak valid.").transform((email) => email.toLowerCase()),
});

export const verifyOtpSchema = z.object({
  email: z.string().trim().max(254, "email tidak boleh melebihi 254 karakter.").email("Format email tidak valid.").transform((email) => email.toLowerCase()),
  otp: z.string().regex(/^\d{6}$/, "OTP harus terdiri dari 6 angka."),
});

export const resetPasswordSchema = z.object({
  email: z.string().trim().max(254, "email tidak boleh melebihi 254 karakter.").email("Format email tidak valid.").transform((email) => email.toLowerCase()),
  resetToken: z.string().regex(/^[a-f0-9]{64}$/, "Token reset tidak valid."),
  newPassword: z.string().min(8, "Password harus terdiri dari 8 sampai 128 karakter.").max(128, "Password harus terdiri dari 8 sampai 128 karakter."),
});

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type UpdateProfileInput = z.infer<typeof updateProfileSchema>;
export type ForgotPasswordInput = z.infer<typeof forgotPasswordSchema>;
export type VerifyOtpInput = z.infer<typeof verifyOtpSchema>;
export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>;

export function parseAuthInput<T>(schema: z.ZodType<T>, body: unknown): T {
  const result = schema.safeParse(body);
  if (result.success) {
    return result.data;
  }

  const errors: Record<string, string> = {};
  for (const issue of result.error.issues) {
    const field = issue.path.length > 0 ? String(issue.path[0]) : "body";
    errors[field] ??= issue.message;
  }
  throw new ApiError(400, "Validasi gagal.", errors);
}
