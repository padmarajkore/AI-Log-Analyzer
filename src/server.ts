import express, { Request, Response } from 'express';
import cors from 'cors';
import path from 'path';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { TypeSafeLogAnalyzer, LogEntry, AnalysisResult, BatchAnalysisResult } from './typesafe-analyzer.js';
import { LogSimulator } from './log-simulator.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, '../public')));

const analyzer = new TypeSafeLogAnalyzer();

// ── SSE clients ──────────────────────────────────────────────────────────────
const sseClients: Response[] = [];
const batchSseClients: Response[] = [];

function broadcastToClients(data: AnalysisResult) {
  const payload = `data: ${JSON.stringify(data)}\n\n`;
  sseClients.forEach(client => { try { client.write(payload); } catch (_) {} });
}

function broadcastBatchResult(result: BatchAnalysisResult) {
  const payload = `data: ${JSON.stringify(result)}\n\n`;
  batchSseClients.forEach(client => { try { client.write(payload); } catch (_) {} });
}

function broadcastRawLog(entry: LogEntry) {
  // Broadcast raw (un-analyzed) logs to batch stream clients so UI can count them fast
  const payload = `data: ${JSON.stringify({ type: 'RAW_LOG', entry })}\n\n`;
  batchSseClients.forEach(client => { try { client.write(payload); } catch (_) {} });
}

// ── In-memory buffers ────────────────────────────────────────────────────────
const recentSingleLogs: AnalysisResult[] = [];
const recentBatches: BatchAnalysisResult[] = [];

// ── Single-log queue (original mode) ─────────────────────────────────────────
let isProcessingSingleLog = false;
const singleQueue: LogEntry[] = [];

async function processSingleQueue() {
  if (isProcessingSingleLog || singleQueue.length === 0) return;
  isProcessingSingleLog = true;
  const entry = singleQueue.shift()!;
  try {
    const result = await analyzer.analyze(entry);
    recentSingleLogs.unshift(result);
    if (recentSingleLogs.length > 50) recentSingleLogs.pop();
    broadcastToClients(result);
    console.log(`[Single] [${entry.service}] [${entry.level}] ${result.latencyMs}ms | Outage: ${(result.judgments.impendingOutageRisk.probability * 100).toFixed(0)}% | Leak: ${result.judgments.sensitiveDataLeak.leakType} | Sev: ${result.judgments.severityScore.score}`);
  } catch (err: any) {
    console.error('Single-log analysis error:', err.message);
  } finally {
    isProcessingSingleLog = false;
    if (singleQueue.length > 0) setImmediate(processSingleQueue);
  }
}

// ── Batch window engine ───────────────────────────────────────────────────────
// The batch collector accumulates all logs produced during the window,
// then fires ONE Jev call for the entire window. This lets the simulator run
// at 100+/s while Jev sees batches of N logs per window.

interface BatchEngineConfig {
  mode: 'single' | 'batch';
  windowMs: number; // 1000, 2000, 5000
}

const batchConfig: BatchEngineConfig = { mode: 'batch', windowMs: 2000 };

let batchWindow: LogEntry[] = [];
let batchTimer: NodeJS.Timeout | null = null;
let isBatchProcessing = false;
let batchStats = {
  totalRawLogs: 0,
  totalBatches: 0,
  totalLeaks: 0,
  totalOutages: 0,
  totalCritical: 0,
  lastBatchSize: 0,
  lastWindowMs: 0,
};

function scheduleBatchWindow() {
  if (batchTimer) return; // already scheduled
  batchTimer = setTimeout(async () => {
    batchTimer = null;
    await flushBatchWindow();
  }, batchConfig.windowMs);
}

async function flushBatchWindow() {
  if (batchWindow.length === 0) return;
  if (isBatchProcessing) {
    // reschedule if a flush is already in flight
    scheduleBatchWindow();
    return;
  }

  const logsToProcess = batchWindow.splice(0, batchWindow.length);
  isBatchProcessing = true;
  batchStats.lastBatchSize = logsToProcess.length;
  batchStats.lastWindowMs = batchConfig.windowMs;
  batchStats.totalBatches++;

  try {
    console.log(`\n[Batch] ⚡ Window closed — ${logsToProcess.length} logs in ${batchConfig.windowMs}ms → Sending to Jev...`);
    const result = await analyzer.analyzeBatch(logsToProcess, batchConfig.windowMs);

    recentBatches.unshift(result);
    if (recentBatches.length > 20) recentBatches.pop();

    // Update stats
    if (result.highestUrgency === 'CRITICAL') batchStats.totalCritical++;
    if (result.topThreats.some(t => t.includes('leak') || t.includes('Credential'))) batchStats.totalLeaks++;
    if (result.topThreats.some(t => t.includes('Outage') || t.includes('outage'))) batchStats.totalOutages++;

    broadcastBatchResult(result);

    console.log(`[Batch] ✅ Done in ${result.latencyMs}ms | Health: ${result.systemHealthScore}/10 (${result.systemHealthLabel}) | Urgency: ${result.highestUrgency} | Tokens: ${result.tokens.input}`);
    result.topThreats.forEach(t => console.log(`  → ${t}`));
  } catch (err: any) {
    console.error('[Batch] Analysis error:', err.message);
  } finally {
    isBatchProcessing = false;
  }
}

// ── Simulator ────────────────────────────────────────────────────────────────
const simulator = new LogSimulator((entry) => {
  batchStats.totalRawLogs++;

  // Always broadcast raw log event so UI counter updates in real-time
  broadcastRawLog(entry);

  if (batchConfig.mode === 'batch') {
    // Accumulate into the batch window (no size cap — we want ALL logs)
    batchWindow.push(entry);
    scheduleBatchWindow();
  } else {
    // Single-log mode (original)
    if (singleQueue.length < 15) {
      singleQueue.push(entry);
      processSingleQueue();
    }
  }
}, 10); // Default 10ms = ~100 logs/sec

// ── SSE: Single-log stream ────────────────────────────────────────────────────
app.get('/api/logs/stream', (req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  sseClients.push(res);
  res.write(`data: ${JSON.stringify({ type: 'CONNECTED', message: 'Single-log stream active' })}\n\n`);
  req.on('close', () => { const i = sseClients.indexOf(res); if (i !== -1) sseClients.splice(i, 1); });
});

// ── SSE: Batch stream (raw logs + batch results) ──────────────────────────────
app.get('/api/logs/batch-stream', (req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  batchSseClients.push(res);
  res.write(`data: ${JSON.stringify({ type: 'CONNECTED', message: 'Batch stream active' })}\n\n`);
  req.on('close', () => { const i = batchSseClients.indexOf(res); if (i !== -1) batchSseClients.splice(i, 1); });
});

// ── Single log analyze ───────────────────────────────────────────────────────
app.post('/api/logs/analyze', async (req: Request, res: Response) => {
  try {
    const logEntry: LogEntry = req.body;
    if (!logEntry?.message) return res.status(400).json({ error: 'Field "message" is required.' });
    const result = await analyzer.analyze(logEntry);
    recentSingleLogs.unshift(result);
    if (recentSingleLogs.length > 50) recentSingleLogs.pop();
    broadcastToClients(result);
    return res.json({ success: true, analysis: result });
  } catch (error: any) {
    return res.status(500).json({ error: error.message || 'Analysis failed' });
  }
});

// ── Manual batch submit (send logs from your own app) ─────────────────────────
app.post('/api/logs/batch', async (req: Request, res: Response) => {
  try {
    const { logs, windowMs = 5000 } = req.body;
    if (!Array.isArray(logs) || logs.length === 0) {
      return res.status(400).json({ error: 'Array of "logs" is required.' });
    }
    const result = await analyzer.analyzeBatch(logs, windowMs);
    recentBatches.unshift(result);
    if (recentBatches.length > 20) recentBatches.pop();
    broadcastBatchResult(result);
    return res.json({ success: true, batch: result });
  } catch (error: any) {
    return res.status(500).json({ error: error.message });
  }
});

// ── History ──────────────────────────────────────────────────────────────────
app.get('/api/logs/history', (_req: Request, res: Response) => {
  res.json({ recentLogs: recentSingleLogs });
});

app.get('/api/logs/batch-history', (_req: Request, res: Response) => {
  res.json({ recentBatches });
});

// ── Presets ──────────────────────────────────────────────────────────────────
app.get('/api/presets', (_req: Request, res: Response) => {
  res.json([
    { id: 'password_leak', name: 'Plain Password Leak in DB Connection', category: 'Security Risk', service: 'auth-service', level: 'ERROR', message: 'Failed to connect to postgresql://admin:SuperSecretP@ssw0rd123!@db.internal:5432/users. Connection refused.' },
    { id: 'pool_exhaustion', name: 'DB Connection Pool Exhaustion (Outage Risk)', category: 'System Failure Risk', service: 'order-api', level: 'WARN', message: 'HikariPool-1 - Connection is not available, request timed out after 30005ms (total=50, active=50, idle=0, waiting=284). Cascade rejection started.' },
    { id: 'memory_oom', name: 'Heap Memory Approaching OOM', category: 'System Failure Risk', service: 'image-processor', level: 'WARN', message: 'JVM GC overhead limit exceeded. OldGen allocation at 97.4% (3.89GB / 4.00GB). Consecutive Full GC failed to reclaim memory. Process freeze imminent.' },
    { id: 'token_exposure', name: 'Raw JWT Bearer Token Exposed in Log', category: 'Security Risk', service: 'api-gateway', level: 'INFO', message: 'Incoming request to /v1/user/profile with Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c' },
    { id: 'normal_access', name: 'Normal HTTP 200 Access Log', category: 'Benign Traffic', service: 'web-frontend', level: 'INFO', message: 'GET /api/v2/products?category=electronics&page=1 HTTP/1.1 200 OK 42ms IP: 198.51.100.4' },
  ]);
});

// ── Batch mode config ────────────────────────────────────────────────────────
app.post('/api/batch-config', (req: Request, res: Response) => {
  const { mode, windowMs } = req.body || {};
  if (mode === 'single' || mode === 'batch') batchConfig.mode = mode;
  if (typeof windowMs === 'number' && windowMs >= 500) batchConfig.windowMs = windowMs;
  res.json({ success: true, config: batchConfig });
});

app.get('/api/batch-config', (_req: Request, res: Response) => {
  res.json({ config: batchConfig, stats: batchStats });
});

// ── Simulator control ────────────────────────────────────────────────────────
app.get('/api/simulator/status', (_req: Request, res: Response) => {
  res.json({ ...simulator.getStatus(), batchConfig, batchStats });
});

app.post('/api/simulator/start', (req: Request, res: Response) => {
  const { intervalMs } = req.body || {};
  simulator.start(intervalMs);
  res.json({ success: true, status: simulator.getStatus() });
});

app.post('/api/simulator/stop', (_req: Request, res: Response) => {
  simulator.stop();
  res.json({ success: true, status: simulator.getStatus() });
});

app.post('/api/simulator/speed', (req: Request, res: Response) => {
  const { intervalMs } = req.body || {};
  if (typeof intervalMs === 'number') simulator.setInterval(intervalMs);
  res.json({ success: true, status: simulator.getStatus() });
});

// ── Health ───────────────────────────────────────────────────────────────────
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({ status: 'online', timestamp: new Date().toISOString(), apiKeyConfigured: !!process.env.TYPESAFE_API_KEY });
});

// ── Boot ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n======================================================`);
  console.log(`🚀 TypeSafe AI Log Analyzer — Batch Window Mode`);
  console.log(`📡 Server: http://localhost:${PORT}`);
  console.log(`🪣 Batch window: ${batchConfig.windowMs}ms  |  Mode: ${batchConfig.mode}`);
  console.log(`======================================================\n`);
});
