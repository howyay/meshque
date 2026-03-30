import { Hono } from "hono";
import { roomRoutes } from "./routes/rooms.js";
import { networkRoutes } from "./routes/networks.js";
import type { StorageAdapter } from "./storage/adapter.js";

export function createApp(storage: StorageAdapter): Hono {
  const app = new Hono();

  app.get("/health", (c) => c.json({ status: "ok" }));
  app.route("/api/rooms", roomRoutes(storage));
  app.route("/api/networks", networkRoutes(storage));

  return app;
}
