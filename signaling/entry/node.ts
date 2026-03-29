import { serve } from "@hono/node-server";
import { createApp } from "../src/app.js";
import { MemoryAdapter } from "../src/storage/memory.js";

const port = parseInt(process.env.PORT ?? "8787", 10);
const app = createApp(new MemoryAdapter());

serve({ fetch: app.fetch, port }, (info) => {
  console.log(`meshque signaling server listening on http://localhost:${info.port}`);
});
