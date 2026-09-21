import { LogEntry } from './typesafe-analyzer.js';

const SERVICES = [
  'auth-service', 'payment-gateway', 'order-api', 'user-db',
  'cache-redis', 'api-gateway', 'inventory-worker', 'search-indexer',
  'notification-svc', 'billing-engine', 'session-manager', 'cdn-edge',
];

const rand = (min: number, max: number) => Math.floor(Math.random() * (max - min + 1)) + min;
const pick = <T>(arr: T[]): T => arr[rand(0, arr.length - 1)];
const ms = () => rand(8, 450);
const ip = () => `${rand(10,200)}.${rand(1,254)}.${rand(1,254)}.${rand(1,254)}`;
const uid = () => `usr_${rand(100000, 999999)}`;
const oid = () => `ord_${rand(10000000, 99999999)}`;
const pid = () => `pod-${Math.random().toString(36).substring(2,8)}`;
const traceId = () => Math.random().toString(16).substring(2,18);
const methods = ['GET','POST','PUT','PATCH','DELETE'];
const paths = ['/api/v2/orders','/api/v2/users','/api/v1/products','/api/v3/payments','/auth/token','/api/v2/cart','/api/v1/search','/api/v2/checkout','/webhook/stripe','/api/v3/reports'];
const codes = [200,200,200,200,201,204,400,401,403,404,422,500,502,503];
const method = () => pick(methods);
const path = () => pick(paths);

// ──────────────────────────────────────────────
// ROUTINE LOGS (healthy traffic, 55%)
// ──────────────────────────────────────────────
const ROUTINE_LOGS: Array<{level:string;template:()=>string}> = [
  { level:'INFO',  template:()=>`${method()} ${path()}?page=${rand(1,20)} HTTP/1.1 200 OK ${ms()}ms trace=${traceId()} pod=${pid()}` },
  { level:'INFO',  template:()=>`${method()} ${path()} HTTP/1.1 201 Created ${ms()}ms user=${uid()} ip=${ip()}` },
  { level:'INFO',  template:()=>`${method()} ${path()} HTTP/1.1 204 No Content ${ms()}ms` },
  { level:'INFO',  template:()=>`Cache HIT for key session:${uid()} (TTL ${rand(300,7200)}s remaining) bytes=${rand(120,8000)}` },
  { level:'INFO',  template:()=>`Cache MISS for key product:${rand(1000,9999)} — fetching from PostgreSQL` },
  { level:'DEBUG', template:()=>`PostgreSQL query OK: SELECT id,status,total FROM orders WHERE customer_id=$1 rows=${rand(1,50)} exec_time=${(Math.random()*8+0.5).toFixed(2)}ms` },
  { level:'DEBUG', template:()=>`Kafka consumer [orders-consumer] committed offset ${rand(100000,9000000)} partition=${rand(0,7)} lag=${rand(0,50)}` },
  { level:'INFO',  template:()=>`Scheduled job [DailyReportSync] completed — rows=${rand(500,5000)} duration=${(Math.random()*4+0.5).toFixed(2)}s` },
  { level:'INFO',  template:()=>`Healthcheck /healthz 200 OK pod=${pid()} uptime=${rand(100,864000)}s` },
  { level:'INFO',  template:()=>`Webhook dispatched 'order.paid' to https://hooks.shopify.com/webhook-${rand(1000,9999)} status=200 latency=${ms()}ms` },
  { level:'INFO',  template:()=>`JWT token validated for ${uid()} scope=read:orders exp_in=${rand(100,3600)}s` },
  { level:'INFO',  template:()=>`S3 presigned URL generated for invoice-${rand(10000,99999)}.pdf ttl=300s` },
  { level:'DEBUG', template:()=>`gRPC call UserService.GetProfile completed in ${ms()}ms status=OK` },
  { level:'INFO',  template:()=>`Email queued to finance@corp.internal template=monthly_summary msgId=${traceId()}` },
  { level:'INFO',  template:()=>`Rate limit check passed for ${ip()} endpoint=${path()} remaining=${rand(50,500)} rps` },
  { level:'INFO',  template:()=>`Elasticsearch indexing completed — docs=${rand(100,2000)} index=products_v3 time=${ms()}ms` },
  { level:'INFO',  template:()=>`Stripe payment intent created pi_${traceId()} amount=${rand(500,50000)} currency=USD` },
  { level:'INFO',  template:()=>`Session created for ${uid()} ip=${ip()} user-agent=Mozilla/5.0` },
  { level:'DEBUG', template:()=>`Connection pool checkout latency=${rand(1,12)}ms pool=primary-pg active=${rand(5,35)}/50` },
  { level:'INFO',  template:()=>`CDN cache PURGE for /assets/bundle.${rand(1000,9999)}.js completed across 42 edge nodes` },
  { level:'INFO',  template:()=>`gzip response body compressed: ${rand(80,95)}% ratio ${rand(20000,200000)}B -> ${rand(4000,30000)}B` },
  { level:'INFO',  template:()=>`Background job [CleanExpiredSessions] removed ${rand(50,800)} rows duration=${rand(200,1200)}ms` },
  { level:'DEBUG', template:()=>`Redis SET order:${oid()} EX=900 bytes=${rand(200,4000)} OK` },
  { level:'INFO',  template:()=>`SMS notification delivered to +1-555-${rand(1000,9999)} via Twilio sid=SM${traceId()}` },
];

// ──────────────────────────────────────────────
// WARNING LOGS (degraded but not broken, 20%)
// ──────────────────────────────────────────────
const WARNING_LOGS: Array<{level:string;template:()=>string}> = [
  { level:'WARN', template:()=>`Slow DB query ${rand(1200,4500)}ms: SELECT * FROM audit_events WHERE created_at > NOW() - INTERVAL '30 days' AND user_id=$1 — missing index on user_id` },
  { level:'WARN', template:()=>`Redis replica-02 connection retry ${rand(1,4)}/5 — socket timeout after 500ms host=redis-replica-02.internal:6379` },
  { level:'WARN', template:()=>`Thread pool [async-worker] pressure: active=${rand(80,95)}/100 queued=${rand(200,800)} tasks — consider scaling` },
  { level:'WARN', template:()=>`Downstream API /v1/rates returned 504 Gateway Timeout after ${rand(5000,30000)}ms — falling back to cached rates` },
  { level:'WARN', template:()=>`Circuit breaker [inventory-service] → HALF-OPEN after ${rand(3,8)} consecutive timeouts. Next probe in 10s` },
  { level:'WARN', template:()=>`Rate limiter THROTTLED ${rand(20,200)} requests for ip=${ip()} on endpoint /api/v2/checkout — potential bot` },
  { level:'WARN', template:()=>`JWT token near expiry for ${uid()} — exp_in=${rand(60,300)}s. Client should refresh.` },
  { level:'WARN', template:()=>`Kafka consumer lag WARNING: topic=orders partition=${rand(0,7)} lag=${rand(500,5000)} messages — consumer may be falling behind` },
  { level:'WARN', template:()=>`Memory usage elevated: heap used ${rand(70,85)}% (${rand(3,7)}.${rand(1,9)}GB/${rand(8,12)}GB) — GC pressure increasing` },
  { level:'WARN', template:()=>`Stripe webhook signature verification failed for event evt_${traceId()} — possible replay attack or misconfigured secret` },
  { level:'WARN', template:()=>`Database connection pool utilization at ${rand(75,89)}% (active=${rand(38,44)}/50) — approaching limit` },
  { level:'WARN', template:()=>`Disk I/O latency spike: ${rand(80,250)}ms avg write latency on /var/lib/postgresql (normal <10ms)` },
  { level:'WARN', template:()=>`SSL certificate for api.internal.prod expires in ${rand(7,25)} days — schedule renewal` },
  { level:'WARN', template:()=>`HTTP 429 Too Many Requests from upstream payment processor — backing off ${rand(1000,5000)}ms` },
  { level:'WARN', template:()=>`ElasticSearch cluster health: YELLOW — ${rand(1,3)} unassigned replica shards on index orders_v2` },
];

// ──────────────────────────────────────────────
// OUTAGE / CRITICAL FAILURE LOGS (14%)
// ──────────────────────────────────────────────
const OUTAGE_LOGS: Array<{level:string;template:()=>string}> = [
  { level:'ERROR', template:()=>`FATAL: HikariPool-primary — Connection not available after 30005ms timeout (total=50 active=50 idle=0 waiting=${rand(200,600)}). Cascading rejection started. New requests will fail immediately.` },
  { level:'ERROR', template:()=>`JVM OutOfMemoryError: GC overhead limit exceeded. OldGen at ${rand(95,99)}.${rand(0,9)}% (${(7.5+Math.random()*0.4).toFixed(2)}GB/8.00GB). Stop-the-World pause ${rand(4000,9000)}ms. Process freeze IMMINENT.` },
  { level:'ERROR', template:()=>`CRITICAL: Disk volume /var/lib/postgresql/data at ${rand(97,99)}.${rand(0,9)}% (${rand(100,400)}MB free). WAL write failure imminent. PostgreSQL entering READ-ONLY mode.` },
  { level:'ERROR', template:()=>`Redis master OOM: maxmemory ${rand(16,32)}GB exhausted. Policy=noeviction. Commands: SET rejected. All writes FAILING. Cache stampede possible.` },
  { level:'ERROR', template:()=>`Deadlock detected: thread [tx-worker-${rand(1,20)}] vs [db-syncer-${rand(1,10)}] on table 'wallet_ledger'. ${rand(3,15)} transactions rolled back. Abort threshold breached.` },
  { level:'ERROR', template:()=>`Node process exit: uncaughtException — RangeError: Maximum call stack size exceeded in /app/src/pricing/calculator.js:${rand(100,500)}. Service DOWN.` },
  { level:'ERROR', template:()=>`Kubernetes OOMKilled: pod ${pid()} container=api-server memory limit 2Gi exceeded — restarting (restart_count=${rand(3,15)})` },
  { level:'ERROR', template:()=>`Primary DB failover triggered: primary postgres-primary-01 unreachable for ${rand(30,90)}s. Promoting replica postgres-replica-02. Estimated downtime: ${rand(10,60)}s.` },
  { level:'ERROR', template:()=>`TCP connection pool exhausted to downstream service [billing-engine] — socket ETIMEDOUT after ${rand(5000,15000)}ms. All ${rand(50,200)} connections in use.` },
  { level:'ERROR', template:()=>`Elasticsearch OOM: JVM heap at 99.1% — cluster.routing.allocation.enable=none applied. ALL index writes SUSPENDED.` },
  { level:'ERROR', template:()=>`Filesystem inode exhaustion: /var/log inode usage ${rand(98,100)}% — cannot create new files. Log writes FAILING. Service may crash.` },
  { level:'ERROR', template:()=>`CPU throttling CRITICAL: container api-gateway throttled ${rand(80,99)}% of CPU time. p99 latency degraded to ${rand(5000,30000)}ms. SLA breach imminent.` },
];

// ──────────────────────────────────────────────
// SENSITIVE DATA LEAKS (11%)
// ──────────────────────────────────────────────
const LEAK_LOGS: Array<{level:string;template:()=>string}> = [
  // Plaintext passwords
  { level:'ERROR', template:()=>`DB connection failed: postgresql://dbadmin:SuperSecret${rand(100,999)}Pass!@prod-postgres-01.internal:5432/core_prod — ECONNREFUSED` },
  { level:'ERROR', template:()=>`MySQL connect error: host=mysql-primary, user=root, password="ProdRootP@ss${rand(10,99)}word" — Access denied` },
  { level:'DEBUG', template:()=>`Auth attempt for user finance@corp.internal password="P@ssw0rd_${rand(1000,9999)}!" — bcrypt mismatch` },
  { level:'INFO',  template:()=>`LDAP bind config: ldap://directory.corp.internal dn=cn=svc-account,dc=corp bind_pw=Corp${rand(2020,2026)}Secure!` },
  { level:'WARN',  template:()=>`Config reload: SMTP_PASSWORD=Smtp${rand(1000,9999)}SecretKey! HOST=mail.corp.internal PORT=587` },
  // JWT / API keys
  { level:'INFO',  template:()=>`Incoming request: POST /v1/auth Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c` },
  { level:'ERROR', template:()=>`AWS SDK error: InvalidClientTokenId for aws_access_key_id=AKIAIOSFODNN7EXAMPLE aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY region=us-east-1` },
  { level:'INFO',  template:()=>`Stripe API call failed: api_key=sk_live_${traceId()}${traceId()} — rate limit exceeded` },
  { level:'DEBUG', template:()=>`GitHub webhook delivered: X-Hub-Signature=sha256=${traceId()} secret=gh_webhook_secret_${rand(100000,999999)} event=push` },
  // PII / Credit cards
  { level:'WARN',  template:()=>`Payment debug dump: card_number="4532-${rand(1000,9999)}-${rand(1000,9999)}-8921" cvv="382" exp="0${rand(1,9)}/2${rand(6,9)}" — declined: insufficient funds` },
  { level:'INFO',  template:()=>`User profile export request for SSN=5${rand(10,99)}-${rand(10,99)}-${rand(1000,9999)} name="John Doe" dob=1985-04-${rand(10,28)}` },
  { level:'ERROR', template:()=>`Twilio SMS error: To=+1555${rand(1000000,9999999)} message contains PAN 5425-${rand(1000,9999)}-${rand(1000,9999)}-${rand(1000,9999)}` },
];

export class LogSimulator {
  private timer: NodeJS.Timeout | null = null;
  private isRunning = false;
  private intervalMs: number;
  private burstMode = false;
  private onLogGenerated: (entry: LogEntry) => void;
  private generatedCount = 0;

  constructor(onLogGenerated: (entry: LogEntry) => void, defaultIntervalMs = 1000) {
    this.onLogGenerated = onLogGenerated;
    this.intervalMs = defaultIntervalMs;
  }

  start(intervalMs?: number) {
    if (intervalMs) this.intervalMs = Math.max(150, intervalMs);
    if (this.isRunning) return;
    this.isRunning = true;
    this.scheduleNext();
    console.log(`🚀 [Simulator] Started — interval=${this.intervalMs}ms rate=~${(1000/this.intervalMs).toFixed(1)} logs/s`);
  }

  stop() {
    if (this.timer) { clearTimeout(this.timer); this.timer = null; }
    this.isRunning = false;
    console.log(`🛑 [Simulator] Stopped after ${this.generatedCount} logs generated`);
  }

  setInterval(ms: number) {
    this.intervalMs = Math.max(5, ms); // floor at 5ms (~200 logs/s max)
    if (this.isRunning) {
      if (this.timer) clearTimeout(this.timer);
      this.scheduleNext();
    }
  }

  getStatus() {
    return {
      isRunning: this.isRunning,
      intervalMs: this.intervalMs,
      ratePerSecond: Math.round(1000 / this.intervalMs * 10) / 10,
      totalGenerated: this.generatedCount,
    };
  }

  private scheduleNext() {
    if (!this.isRunning) return;
    // Occasionally emit a burst (2-4 logs at once) to simulate traffic spikes
    const burstChance = Math.random();
    const batchSize = burstChance < 0.05 ? rand(3, 5) : 1;

    this.timer = setTimeout(() => {
      for (let i = 0; i < batchSize; i++) {
        this.generateAndEmit();
      }
      this.scheduleNext();
    }, this.intervalMs);
  }

  private generateAndEmit() {
    const service = pick(SERVICES);
    const roll = Math.random();

    let chosen: { level: string; template: () => string };

    // Weighted distribution:
    //  11% → Credential / PII leaks
    //  14% → Outage / critical crash signatures
    //  20% → Warnings / degradation
    //  55% → Routine healthy traffic
    if (roll < 0.11) {
      chosen = pick(LEAK_LOGS);
    } else if (roll < 0.25) {
      chosen = pick(OUTAGE_LOGS);
    } else if (roll < 0.45) {
      chosen = pick(WARNING_LOGS);
    } else {
      chosen = pick(ROUTINE_LOGS);
    }

    this.generatedCount++;
    const entry: LogEntry = {
      id: `sim_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      service,
      level: chosen.level,
      message: chosen.template(),
      timestamp: new Date().toISOString(),
    };
    this.onLogGenerated(entry);
  }
}
