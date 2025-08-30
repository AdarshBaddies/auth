import app from "./src/app.js";
import connectToDatabase from "./src/config/db.js";
import { env } from "./src/config/env.js";

const start = async () => {
  try {
    await connectToDatabase(env.mongoUri);
    app.listen(env.port, () => {
      console.log(`Auth Service running on port ${env.port}`);
    });
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
};

start();
