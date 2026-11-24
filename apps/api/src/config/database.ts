import mongoose from "mongoose";

let connectionAttempted = false;

/**
 * Connect to the configured MongoDB database.
 * A missing URI is allowed for docs-only workflows, but data routes must not
 * report persistence until mongoose.connection.readyState is connected.
 */
export async function connectDatabase(): Promise<void> {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.warn("MONGODB_URI is not configured; database-backed features are unavailable.");
    return;
  }

  if (connectionAttempted && mongoose.connection.readyState === 1) return;
  connectionAttempted = true;

  await mongoose.connect(uri, {
    serverSelectionTimeoutMS: 5000,
    autoIndex: process.env.NODE_ENV !== "production"
  });

  console.info("ChainProof MongoDB connection established.");
}

export function isDatabaseConnected(): boolean {
  return mongoose.connection.readyState === 1;
}