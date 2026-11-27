import { createApp } from './app.js';

const host = process.env.HOST || '127.0.0.1';
if (process.env.ALLOW_INSECURE_LOCALHOST === '1' && !['127.0.0.1', '::1', 'localhost'].includes(host)) throw new Error('Insecure development mode must bind to loopback');
const { app, close } = await createApp();
const server = app.listen(Number(process.env.PORT || 3000), host, () => console.log(`Listening on ${host}:${process.env.PORT || 3000}`));
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close(async () => { await close(); process.exit(0); }));
