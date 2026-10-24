// CRITICAL NPROC / THREAD LIMIT CONSTRAINT:
// Restrict libuv thread pool size to strictly respect CloudLinux / cPanel / container 20-30 NPROC limits.
if (!process.env.UV_THREADPOOL_SIZE) {
  process.env.UV_THREADPOOL_SIZE = '2';
}

import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { apiRouter } from './server/routes.ts';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
  
  const distPath = path.resolve(__dirname, 'dist');
  const distExists = fs.existsSync(path.resolve(distPath, 'index.html'));
  
  // Safeguard: If pre-bundled dist/ exists, default to production static serving to prevent Vite from spawning file watchers & worker processes
  const isDev = process.env.NODE_ENV === 'development' && !distExists;
  const isProd = !isDev;

  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // SEC-05: Strict security guard forbidding direct access to server data, source code, and internal private files
  app.use((req, res, next) => {
    const p = req.path.toLowerCase();
    if (
      p.startsWith('/data') || 
      p.startsWith('/server') || 
      (isProd && p.startsWith('/node_modules')) ||
      p.includes('/.env') ||
      p.includes('/.git') ||
      (p.endsWith('.json') && p !== '/metadata.json') ||
      (isProd && (p.startsWith('/src') || p.endsWith('.ts') || p.endsWith('.tsx'))) ||
      p === '/package.json' ||
      p === '/tsconfig.json'
    ) {
      return res.status(403).json({ error: 'Access Denied: Protected System Resource' });
    }
    next();
  });

  // Register API Router
  app.use('/api', apiRouter);

  // DEP-06: 404 JSON handler for unknown /api endpoints
  app.use('/api/*', (_req, res) => {
    res.status(404).json({ error: 'API endpoint not found', code: 'NOT_FOUND' });
  });

  // Dedicated download handler for latest dist archive
  app.get(['/dist.zip', '/dist-latest.zip', '/download/dist', '/download/dist.zip', '/dtc-express-dist.zip'], (_req, res) => {
    const zipPath = path.resolve(__dirname, 'public', 'dist.zip');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Content-Disposition', 'attachment; filename="dtc-express-dist.zip"');
    res.setHeader('Content-Type', 'application/zip');
    res.sendFile(zipPath);
  });

  // Static assets for brand logo folders
  const publicDir = path.resolve(__dirname, 'public');
  app.use(express.static(publicDir));
  app.use('/logo', express.static(path.resolve(publicDir, 'logo')));
  app.use('/log', express.static(path.resolve(publicDir, 'log')));
  app.use('/photos', express.static(path.resolve(publicDir, 'photos')));

  if (isDev) {
    // Development mode with Vite middleware (only active when NODE_ENV === 'development')
    const { createServer } = await import('vite');
    const vite = await createServer({
      server: {
        middlewareMode: true,
        host: '0.0.0.0',
        port: PORT,
        hmr: process.env.DISABLE_HMR !== 'true',
        watch: process.env.DISABLE_HMR === 'true' ? null : {}
      },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    // Production static file serving: Pre-bundled dist assets, never serving source code
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`DTC Express Cargo Movers server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
