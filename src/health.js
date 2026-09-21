import fs from "node:fs";
import { config } from "./config.js";

export function healthSnapshot() {
  let databaseWritable = false;

  try {
    fs.accessSync(config.dbPath, fs.constants.R_OK | fs.constants.W_OK);
    databaseWritable = true;
  } catch {
    databaseWritable = fs.existsSync(config.dbPath) === false;
  }

  return {
    status: databaseWritable ? "ok" : "degraded",
    service: "logonsystem",
    node: process.version,
    environment: config.nodeEnv,
    databaseWritable,
    uptimeSeconds: Math.floor(process.uptime())
  };
}
