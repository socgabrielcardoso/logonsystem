import { createApp } from "./app.js";
import { config } from "./config.js";
import { closeStore } from "./store.js";

const app = createApp();

const server = app.listen(config.port, () => {
  console.log("LogonSystem listening on http://localhost:" + config.port);
});

function shutdown(signal) {
  console.log(signal + " received. Closing server.");
  server.close(() => {
    closeStore();
    process.exit(0);
  });

  setTimeout(() => process.exit(1), 5000).unref();
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
