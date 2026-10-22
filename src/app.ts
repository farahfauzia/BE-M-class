import cors from "cors";
import express from "express";
import authRoutes from "./routes/auth.routes";
import { ApiError } from "./utils/api-error";

const app = express();

app.use(cors());
app.use(express.json());
app.use("/api/auth", authRoutes);

app.get("/", (_req, res) => {
  res.json({ message: "BE_Mclass API is running" });
});

app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  if (error instanceof ApiError) {
    res.status(error.statusCode).json({ message: error.message });
    return;
  }
  console.error("Unhandled request error:", error);
  res.status(500).json({ message: "Terjadi kesalahan pada server." });
});

export default app;
