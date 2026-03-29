/// <reference types="@cloudflare/workers-types" />
import { createApp } from "../src/app.js";
import { WorkersKVAdapter } from "../src/storage/workers-kv.js";

interface Env {
  ROOMS_KV: KVNamespace;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const app = createApp(new WorkersKVAdapter(env.ROOMS_KV));
    return app.fetch(request);
  },
};
