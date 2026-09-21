import dotenv from 'dotenv';
import { TypeSafeLogAnalyzer } from '../src/typesafe-analyzer.js';

dotenv.config();

async function runTests() {
  console.log('\n=============================================================');
  console.log('🧪 TypeSafe System One (Jev) - Real-Time Log Analyzer Tests');
  console.log('=============================================================\n');

  const analyzer = new TypeSafeLogAnalyzer();

  const testCases = [
    {
      name: 'Password Leak in Postgres URI',
      service: 'auth-service',
      level: 'ERROR',
      message: 'Failed to connect to postgresql://admin:SuperSecretP@ssw0rd123!@db.internal:5432/users. Connection refused.',
    },
    {
      name: 'Hikari Connection Pool Timeout (Outage Risk)',
      service: 'order-api',
      level: 'WARN',
      message: 'HikariPool-1 - Connection is not available, request timed out after 30005ms (total=50, active=50, idle=0, waiting=284). Cascade rejection started.',
    },
    {
      name: 'JVM Heap Exhaustion (Imminent Crash)',
      service: 'image-processor',
      level: 'WARN',
      message: 'JVM GC overhead limit exceeded. OldGen allocation at 97.4% (3.89GB / 4.00GB). Consecutive Full GC failed to reclaim memory. Process freeze imminent.',
    },
    {
      name: 'JWT Bearer Token Exposed in Log',
      service: 'api-gateway',
      level: 'INFO',
      message: 'Incoming request to /v1/user/profile with Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    },
    {
      name: 'Normal HTTP 200 Trace',
      service: 'web-frontend',
      level: 'INFO',
      message: 'GET /api/v2/products?category=electronics&page=1 HTTP/1.1 200 OK 42ms IP: 198.51.100.4 User-Agent: Mozilla/5.0',
    },
  ];

  for (let i = 0; i < testCases.length; i++) {
    const tc = testCases[i];
    console.log(`[${i + 1}/${testCases.length}] Evaluating: ${tc.name}...`);

    const result = await analyzer.analyze(tc);

    console.log(`   ⏱️  Latency: ${result.latencyMs} ms | Model: ${result.model}`);
    console.log(`   🔒 Leak Detected: ${result.judgments.sensitiveDataLeak.detected} (${result.judgments.sensitiveDataLeak.leakType} - Conf: ${(result.judgments.sensitiveDataLeak.confidence * 100).toFixed(0)}%)`);
    console.log(`   ⚠️  Outage Risk: ${(result.judgments.impendingOutageRisk.probability * 100).toFixed(0)}% (isHighRisk: ${result.judgments.impendingOutageRisk.isHighRisk})`);
    console.log(`   📊 Severity Score: ${result.judgments.severityScore.score} / 5.0 (Conf: ${(result.judgments.severityScore.confidence * 100).toFixed(0)}%)`);
    console.log(`   🎯 Recommended Action: ${result.judgments.recommendedAction.action}`);
    console.log(`   🏷️  Failure Domain: ${result.judgments.failureDomain.domain}`);
    console.log(`   🚨 Alert Triggered: ${result.alert.triggered} [${result.alert.urgency}] - "${result.alert.headline}"`);
    console.log(`   ✂️  Redacted Payload: ${result.redactedMessage}\n`);
  }

  console.log('✅ All TypeSafe System One scenario tests completed successfully!\n');
}

runTests().catch(err => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
