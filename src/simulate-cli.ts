import dotenv from 'dotenv';
import { LogSimulator } from './log-simulator.js';

dotenv.config();

const API_URL = process.env.API_URL || 'http://localhost:3000/api/logs/analyze';
const INTERVAL = parseInt(process.env.INTERVAL_MS || '1000', 10);

console.log('\n======================================================');
console.log('⚡ TypeSafe Live Backend Log Traffic Generator (CLI)');
console.log(`📡 Ingesting into: ${API_URL}`);
console.log(`⏱️  Frequency: ~${Math.round(1000 / INTERVAL * 10) / 10} logs/sec (every ${INTERVAL}ms)`);
console.log('Press Ctrl+C to stop simulation.');
console.log('======================================================\n');

let sentCount = 0;

const simulator = new LogSimulator(async (entry) => {
  sentCount++;
  const num = sentCount;
  try {
    const res = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(entry),
    });

    if (!res.ok) {
      console.error(`[#${num}] Error (${res.status}): ${await res.text()}`);
      return;
    }

    const data: any = await res.json();
    const a = data.analysis;
    const j = a.judgments;
    const isLeak = j.sensitiveDataLeak.detected;
    const outage = (j.impendingOutageRisk.probability * 100).toFixed(0);

    const leakTag = isLeak ? `🔒 LEAK: ${j.sensitiveDataLeak.leakType}` : '';
    const outageTag = j.impendingOutageRisk.isHighRisk ? `⚠️ OUTAGE RISK (${outage}%)` : `Outage: ${outage}%`;
    const sevTag = `Sev: ${j.severityScore.score}`;

    console.log(`[#${num}] [${a.service}] [${a.level}] ${a.latencyMs}ms | ${outageTag} | ${sevTag} ${leakTag}`);
    if (a.alert.triggered) {
      console.log(`     🚨 ALERT: ${a.alert.headline} (${a.alert.urgency})`);
    }
  } catch (err: any) {
    console.error(`[#${num}] Failed to send log:`, err.message);
  }
}, INTERVAL);

simulator.start();

process.on('SIGINT', () => {
  console.log('\nStopping log generator...');
  simulator.stop();
  process.exit(0);
});
