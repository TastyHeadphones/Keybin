import { createServer } from '@hono/node-server';
import app from './app';

const port = Number(process.env.PORT ?? '8080');

createServer({
  fetch: app.fetch,
  port
});

console.log(`Keybin running on http://localhost:${port}`);
