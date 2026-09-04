import dotenv from 'dotenv';
import { app } from './app.js';

dotenv.config();

const port = Number(process.env.API_PORT ?? 4000);
app.listen(port, () => console.log(`[sentinelforge-api] listening on :${port}`));
