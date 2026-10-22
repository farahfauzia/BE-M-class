import "dotenv/config";
import app from "./app";
import { initializeSchema } from "./config/schema";

const port = Number(process.env.PORT ?? 3000);

async function startServer(): Promise<void> {
  await initializeSchema();
  app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
  });
}

startServer().catch((error: unknown) => {
  console.error("Failed to start server:", error);
  process.exitCode = 1;
});
