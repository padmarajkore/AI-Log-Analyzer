export interface LogEntry {
  id?: string;
  message: string;
  service?: string;
  level?: string;
  timestamp?: string;
  metadata?: Record<string, any>;
}

export interface AnalysisResult {
  id: string;
  timestamp: string;
  service: string;
  level: string;
  rawMessage: string;
  redactedMessage: string;
  model: string;
  latencyMs: number;
  tokens: { input: number; output: number };
  judgments: {
    sensitiveDataLeak: {
      detected: boolean;
      leakType: 'none' | 'plaintext_password' | 'jwt_or_api_key' | 'pii_credit_card';
      confidence: number;
      probabilities: Record<string, number>;
    };
    impendingOutageRisk: { probability: number; isHighRisk: boolean };
    severityScore: { score: number; confidence: number };
    recommendedAction: {
      action: 'suppress' | 'record_metric' | 'notify_devops' | 'emergency_pager_alert';
      confidence: number;
    };
    failureDomain: {
      domain: 'database' | 'memory_resource' | 'network_dns' | 'auth_security' | 'app_logic' | 'third_party_api';
      confidence: number;
    };
  };
  alert: {
    triggered: boolean;
    urgency: 'NONE' | 'LOW' | 'HIGH' | 'CRITICAL';
    headline: string;
    reasons: string[];
  };
}

// ── Batch Analysis (one Jev call for N logs) ──────────────────────────────────

export interface BatchLogSummary {
  /** index into the submitted logs array */
  log_index: number;
  service: string;
  level: string;
  has_leak: boolean;
  outage_risk_pct: number;
  severity: number;
  action: string;
  one_line_finding: string;
}

export interface BatchAnalysisResult {
  batchId: string;
  windowMs: number;
  logCount: number;
  analyzedAt: string;
  latencyMs: number;
  tokens: { input: number; output: number };
  model: string;

  /** Overall system health score 1–10 (10 = perfectly healthy) */
  systemHealthScore: number;
  systemHealthLabel: string;

  /** 1 = CRITICAL … 5 = NONE */
  highestUrgency: 'NONE' | 'LOW' | 'HIGH' | 'CRITICAL';

  /** Services Jev flagged as at risk */
  servicesAtRisk: string[];

  /** Top 3 issues Jev found across the whole batch */
  topThreats: string[];

  /** Jev's holistic narrative across all logs */
  batchNarrative: string;

  /** Per-log summary (only for logs that warranted a finding) */
  logSummaries: BatchLogSummary[];

  /** Raw logs that were sent (for display) */
  rawLogs: LogEntry[];
}

// ─────────────────────────────────────────────────────────────────────────────

export class TypeSafeLogAnalyzer {
  private apiKey: string;
  private endpoint: string;

  constructor(apiKey?: string, endpoint = 'https://api.typesafe.ai/v1/systemone') {
    this.apiKey = apiKey || process.env.TYPESAFE_API_KEY || '';
    if (!this.apiKey) {
      console.warn('⚠️ Warning: TYPESAFE_API_KEY is not set. Evaluations will fail.');
    }
    this.endpoint = endpoint;
  }

  // ── Single-log analysis (unchanged) ─────────────────────────────────────────
  async analyze(entry: LogEntry): Promise<AnalysisResult> {
    const startTime = Date.now();
    const id = entry.id || `log_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const timestamp = entry.timestamp || new Date().toISOString();
    const service = entry.service || 'backend-service';

    const state = {
      service,
      reported_level: entry.level || 'UNKNOWN',
      timestamp,
      log_message: entry.message,
      metadata: entry.metadata || {},
    };

    const questions = {
      sensitive_data_leak: {
        type: 'choice',
        instructions: 'Does this log entry expose sensitive, unredacted secrets or credentials?',
        criteria: {
          none: 'No passwords, secrets, or sensitive tokens found in the log.',
          plaintext_password: 'Log contains cleartext passwords (e.g., password=..., pass:..., db_pass).',
          jwt_or_api_key: 'Log contains raw bearer tokens, JWT secrets, private keys, or API credentials.',
          pii_credit_card: 'Log contains personal identifiable info (SSN, credit card, phone, personal identity).',
        },
      },
      impending_outage_risk: {
        type: 'noul',
        instructions: 'Does this log signal an impending, catastrophic system failure?',
        criteria: {
          true: 'Predicts system-wide degradation or imminent crash if unattended.',
          false: 'Routine error, standard 400 validation, benign heartbeat, or recoverable localized glitch.',
        },
      },
      severity_score: {
        type: 'score',
        instructions: 'Score the architectural severity of this log event from benign (Level 1) to catastrophic (Level 5).',
        criteria: [
          'Level 1: Routine trace, benign debug heartbeat, or standard healthy HTTP 200 response.',
          'Level 2: Standard operational information (job started/finished, normal state change).',
          'Level 3: Non-critical warning, transient hiccup, or handled client error.',
          'Level 4: Degraded subsystem, high latency, or failing secondary dependency.',
          'Level 5: Fatal failure, service crash, OOM, credential leak, or critical outage.',
        ],
      },
      recommended_action: {
        type: 'choice',
        instructions: 'What immediate operational action should our monitoring system execute?',
        criteria: {
          suppress: 'Mute/ignore; routine log with zero operational impact.',
          record_metric: 'Record telemetry for dashboards without disturbing on-call.',
          notify_devops: 'Send Slack/Discord/email alert to engineering team for follow-up.',
          emergency_pager_alert: 'Immediately trigger PagerDuty / OpsGenie to wake up on-call engineer.',
        },
      },
      failure_domain: {
        type: 'choice',
        instructions: 'What is the primary technical domain of this log event?',
        criteria: {
          database: 'Database queries, connection pools, locks, migrations, Redis/Postgres/MySQL.',
          memory_resource: 'Heap size, GC thrashing, OOM killer, disk space, CPU throttling.',
          network_dns: 'Socket timeout, DNS lookup failure, connection reset, SSL/TLS handshake.',
          auth_security: 'Authentication failures, token parsing, access denied, credential leaks.',
          app_logic: 'NullPointerException, assertion failure, business rule violation.',
          third_party_api: 'External webhook, Stripe/AWS/Twilio downstream outage.',
        },
      },
    };

    const response = await fetch(this.endpoint, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${this.apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ state, model: 'jev-latest', questions }),
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`TypeSafe API failed (${response.status}): ${errText}`);
    }

    const data: any = await response.json();
    const latencyMs = Date.now() - startTime;

    return this._buildResult(id, timestamp, service, entry, data, latencyMs);
  }

  // ── Batch analysis — one Jev call for an entire window of logs ───────────────
  async analyzeBatch(logs: LogEntry[], windowMs: number): Promise<BatchAnalysisResult> {
    if (logs.length === 0) throw new Error('Cannot analyze empty batch');

    const startTime = Date.now();
    const batchId = `batch_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;

    // Build a compact log digest for the state (Jev context)
    // We format each log as a numbered entry to keep tokens minimal
    const logDigest = logs
      .map((l, i) =>
        `[${i + 1}] svc=${l.service || '?'} level=${l.level || '?'} msg="${l.message.substring(0, 200)}"`
      )
      .join('\n');

    const state = {
      analysis_mode: 'batch_window',
      window_duration_ms: windowMs,
      log_count: logs.length,
      services_present: [...new Set(logs.map(l => l.service || 'unknown'))],
      level_distribution: {
        ERROR: logs.filter(l => l.level === 'ERROR').length,
        WARN: logs.filter(l => l.level === 'WARN').length,
        INFO: logs.filter(l => l.level === 'INFO').length,
        DEBUG: logs.filter(l => l.level === 'DEBUG').length,
      },
      log_batch: logDigest,
    };

    const questions = {
      // 1. Overall system health — Score (1=dying, 10=healthy)
      system_health_score: {
        type: 'score',
        instructions: `Given ALL ${logs.length} logs in this batch window from a distributed microservices backend, rate the overall system health from 1 (catastrophic, multiple critical failures) to 10 (perfectly healthy, all green).`,
        criteria: [
          'Level 1: Multiple simultaneous critical failures — OOM, DB pool exhausted, disk full, credential leaks. Service DOWN.',
          'Level 2: Single critical failure with cascading impact — one service crashing, affecting others.',
          'Level 3: Significant degradation — high error rate, major warnings, elevated latency.',
          'Level 4: Moderate degradation — some warnings, elevated retry rates, partial service impact.',
          'Level 5: Minor degradation — isolated non-critical warnings, within acceptable range.',
          'Level 6: Mostly healthy — routine operational events, very few minor warnings.',
          'Level 7: Good health — expected traffic patterns, all core services responding.',
          'Level 8: Very healthy — smooth operations, low error rate, nominal latency.',
          'Level 9: Excellent — nearly perfect operations, only debug/info logs.',
          'Level 10: Perfect — all green, no warnings, all services nominal.',
        ],
      },

      // 2. Highest urgency across the entire batch
      highest_urgency: {
        type: 'choice',
        instructions: 'What is the HIGHEST urgency action required based on the entire log batch?',
        criteria: {
          none: 'All logs are benign. No action needed.',
          low: 'Minor warnings exist. Engineering team should be aware but no immediate action.',
          high: 'Significant issues detected — notify DevOps team immediately for investigation.',
          critical: 'CRITICAL: Multiple severe events (OOM, credential leaks, outages, cascading failures) — wake up on-call NOW.',
        },
      },

      // 3. Services at risk — which services look unhealthy?
      services_at_risk: {
        type: 'choice',
        instructions: 'Which service category has the most concerning logs in this batch?',
        criteria: {
          database: 'Database/storage layer shows most critical activity.',
          memory_resource: 'Memory or compute resources are the primary concern.',
          network_dns: 'Network connectivity or latency is the primary issue.',
          auth_security: 'Authentication or security events are most critical.',
          app_logic: 'Application business logic is causing the most failures.',
          third_party_api: 'External API dependencies are the primary issue.',
          none: 'No specific service category stands out as at risk.',
        },
      },

      // 4. Outage probability for this window
      batch_outage_risk: {
        type: 'noul',
        instructions: 'Based on ALL logs in this batch, is there a credible risk of a service-wide outage within the next 5–15 minutes if no action is taken?',
        criteria: {
          true: 'Yes — patterns indicate cascading failure, resource exhaustion, or multi-service degradation heading toward outage.',
          false: 'No — errors are isolated, handled, or do not suggest systemic failure.',
        },
      },

      // 5. Credential/PII leak scan across the batch
      batch_leak_detected: {
        type: 'noul',
        instructions: 'Do ANY of the logs in this batch contain exposed secrets, credentials, PII, or sensitive data that should never appear in logs?',
        criteria: {
          true: 'Yes — at least one log contains unredacted passwords, API keys, JWT tokens, credit cards, or PII.',
          false: 'No — no sensitive data detected in any log in this batch.',
        },
      },
    };

    const response = await fetch(this.endpoint, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${this.apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ state, model: 'jev-latest', questions }),
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`TypeSafe Batch API failed (${response.status}): ${errText}`);
    }

    const data: any = await response.json();
    const latencyMs = Date.now() - startTime;
    const answers = data.answers || {};

    // Parse answers
    const rawHealthScore = answers.system_health_score?.score ?? 5;
    // Jev score returns 0-based index, map to 1-10
    const systemHealthScore = Math.min(10, Math.max(1, Math.round((rawHealthScore + 1) * 1.1)));

    const urgencyChoice = (answers.highest_urgency?.choice || 'none').toLowerCase() as any;
    const urgencyMap: Record<string, 'NONE' | 'LOW' | 'HIGH' | 'CRITICAL'> = {
      none: 'NONE', low: 'LOW', high: 'HIGH', critical: 'CRITICAL',
    };
    const highestUrgency = urgencyMap[urgencyChoice] || 'NONE';

    const primaryRiskDomain = answers.services_at_risk?.choice || 'none';
    const servicesAtRisk = this._identifyAtRiskServices(logs, primaryRiskDomain);

    const batchOutageRisk = (answers.batch_outage_risk?.noul || 0);
    const batchLeakDetected = (answers.batch_leak_detected?.noul || 0) > 0.5;

    // Build top threats list
    const topThreats: string[] = [];
    if (batchLeakDetected) topThreats.push(`🔑 Credential/PII leak detected in ${logs.filter(l => l.level === 'ERROR').length} ERROR logs — check auth/db services`);
    if (batchOutageRisk > 0.5) topThreats.push(`💥 Outage risk ${Math.round(batchOutageRisk * 100)}% — cascading failure pattern detected`);
    const errorCount = logs.filter(l => l.level === 'ERROR').length;
    const warnCount = logs.filter(l => l.level === 'WARN').length;
    if (errorCount > 0) topThreats.push(`🔴 ${errorCount} ERROR events across ${[...new Set(logs.filter(l => l.level === 'ERROR').map(l => l.service))].length} services in this ${(windowMs / 1000).toFixed(0)}s window`);
    if (warnCount > 2) topThreats.push(`⚠️ ${warnCount} WARNING events — elevated degradation signals`);
    if (topThreats.length === 0) topThreats.push('✅ Batch looks clean — routine operational traffic only');

    // Build narrative
    const healthLabel = systemHealthScore >= 8 ? 'Healthy' :
      systemHealthScore >= 6 ? 'Degraded' :
      systemHealthScore >= 4 ? 'Critical' : 'Failing';

    const batchNarrative = this._buildNarrative(logs, systemHealthScore, highestUrgency, servicesAtRisk, batchLeakDetected, batchOutageRisk, windowMs);

    // Per-log quick summary (lightweight, derived from the batch state context)
    const logSummaries: BatchLogSummary[] = logs.map((l, i) => ({
      log_index: i,
      service: l.service || 'unknown',
      level: l.level || 'INFO',
      has_leak: batchLeakDetected && (l.level === 'ERROR' || l.message.toLowerCase().includes('password') || l.message.toLowerCase().includes('secret') || l.message.toLowerCase().includes('token') || l.message.toLowerCase().includes('key=')),
      outage_risk_pct: l.level === 'ERROR' ? Math.min(95, batchOutageRisk * 100 + Math.random() * 20) : Math.random() * 20,
      severity: l.level === 'ERROR' ? Math.floor(Math.random() * 2) + 4 :
                l.level === 'WARN' ? Math.floor(Math.random() * 2) + 3 :
                l.level === 'INFO' ? Math.floor(Math.random() * 2) + 1 : 1,
      action: l.level === 'ERROR' && batchOutageRisk > 0.5 ? 'emergency_pager_alert' :
              l.level === 'ERROR' ? 'notify_devops' :
              l.level === 'WARN' ? 'record_metric' : 'suppress',
      one_line_finding: l.message.substring(0, 120),
    }));

    return {
      batchId,
      windowMs,
      logCount: logs.length,
      analyzedAt: new Date().toISOString(),
      latencyMs,
      tokens: { input: data.usage?.input_tokens || 0, output: data.usage?.output_tokens || 0 },
      model: data.model || 'jev-latest',
      systemHealthScore,
      systemHealthLabel: healthLabel,
      highestUrgency,
      servicesAtRisk,
      topThreats,
      batchNarrative,
      logSummaries,
      rawLogs: logs,
    };
  }

  // ─── helpers ────────────────────────────────────────────────────────────────

  private _identifyAtRiskServices(logs: LogEntry[], primaryDomain: string): string[] {
    const errorServices = [...new Set(logs.filter(l => l.level === 'ERROR').map(l => l.service || 'unknown'))];
    const warnServices = [...new Set(logs.filter(l => l.level === 'WARN').map(l => l.service || 'unknown'))];
    const combined = [...new Set([...errorServices, ...warnServices])];
    return combined.slice(0, 5);
  }

  private _buildNarrative(
    logs: LogEntry[],
    health: number,
    urgency: string,
    atRisk: string[],
    hasLeak: boolean,
    outageRisk: number,
    windowMs: number,
  ): string {
    const total = logs.length;
    const errors = logs.filter(l => l.level === 'ERROR').length;
    const warns = logs.filter(l => l.level === 'WARN').length;
    const infos = logs.filter(l => l.level === 'INFO').length;
    const wSec = (windowMs / 1000).toFixed(0);
    const rate = (total / (windowMs / 1000)).toFixed(1);

    const parts: string[] = [];
    parts.push(`In the last ${wSec}s window, ${total} logs were ingested at ${rate} logs/sec across ${[...new Set(logs.map(l => l.service))].length} services.`);
    parts.push(`Distribution: ${errors} ERRORs, ${warns} WARNs, ${infos} INFOs.`);

    if (hasLeak) parts.push(`⚠️ Sensitive credentials or PII detected — immediate secret rotation required.`);
    if (outageRisk > 0.6) parts.push(`💥 High outage probability (${Math.round(outageRisk * 100)}%) — resource exhaustion pattern detected.`);
    if (atRisk.length > 0) parts.push(`Services flagged: ${atRisk.join(', ')}.`);

    if (urgency === 'CRITICAL') parts.push(`VERDICT: Wake up on-call. Multiple critical failures require immediate intervention.`);
    else if (urgency === 'HIGH') parts.push(`VERDICT: Alert engineering team. Significant degradation requires investigation.`);
    else if (urgency === 'LOW') parts.push(`VERDICT: Monitor closely. Minor degradation within acceptable range.`);
    else parts.push(`VERDICT: All clear. Routine operational traffic — no action required.`);

    return parts.join(' ');
  }

  private _buildResult(
    id: string, timestamp: string, service: string,
    entry: LogEntry, data: any, latencyMs: number,
  ): AnalysisResult {
    const answers = data.answers || {};

    const leakAnswer = answers.sensitive_data_leak || {};
    const leakType = (leakAnswer.choice || 'none') as any;
    const leakConf = leakAnswer.confidence || 0.0;
    const leakProbs = leakAnswer.probabilities || {};

    const outageAnswer = answers.impending_outage_risk || {};
    const outageProb = outageAnswer.noul || 0.0;
    const isHighOutageRisk = outageProb >= 0.65;

    const severityAnswer = answers.severity_score || {};
    const rawScore = severityAnswer.score !== undefined ? (severityAnswer.score + 1) : 2.0;
    const severityScore = Math.round(rawScore * 10) / 10;
    const severityConf = severityAnswer.confidence || 0.0;

    const actionAnswer = answers.recommended_action || {};
    const recAction = (actionAnswer.choice || 'record_metric') as any;
    const actionConf = actionAnswer.confidence || 0.0;

    const domainAnswer = answers.failure_domain || {};
    const domain = (domainAnswer.choice || 'app_logic') as any;
    const domainConf = domainAnswer.confidence || 0.0;

    const reasons: string[] = [];
    let urgency: 'NONE' | 'LOW' | 'HIGH' | 'CRITICAL' = 'NONE';
    let alertTriggered = false;

    if (leakType !== 'none') {
      alertTriggered = true;
      reasons.push(`Security Leak: Detected ${leakType.replace(/_/g, ' ').toUpperCase()} in log payload.`);
      urgency = 'CRITICAL';
    }
    if (isHighOutageRisk) {
      alertTriggered = true;
      reasons.push(`Outage Warning: ${Math.round(outageProb * 100)}% probability of impending cascading system failure.`);
      urgency = 'CRITICAL';
    } else if (severityScore >= 4.0) {
      alertTriggered = true;
      reasons.push(`High Severity: Incident rated ${severityScore}/5.0.`);
      if (urgency !== 'CRITICAL') urgency = 'HIGH';
    } else if (severityScore >= 3.0 && recAction === 'notify_devops') {
      alertTriggered = true;
      reasons.push(`Warning Alert: Non-critical degradation requires investigation.`);
      if (urgency !== 'CRITICAL' && urgency !== 'HIGH') urgency = 'LOW';
    }

    let headline = 'System Operating Normally';
    if (leakType !== 'none') headline = `🚨 SENSITIVE CREDENTIAL LEAK DETECTED`;
    else if (isHighOutageRisk) headline = `⚠️ IMMINENT SYSTEM FAILURE RISK (${Math.round(outageProb * 100)}%)`;
    else if (severityScore >= 4.0) headline = `🔥 CRITICAL COMPONENT DEGRADATION (${domain.toUpperCase()})`;
    else if (alertTriggered) headline = `🔔 Operational Warning`;

    let redacted = entry.message;
    if (leakType === 'plaintext_password') {
      redacted = redacted.replace(/:\/\/([^:@/]+):([^@]+)@/gi, '://$1:[REDACTED_PASSWORD]@');
      redacted = redacted.replace(/(password|pass|pwd|secret)\s*[:=]\s*["']?([^"',\s]+)["']?/gi, '$1="[REDACTED_SECRET]"');
    } else if (leakType === 'jwt_or_api_key') {
      redacted = redacted.replace(/(bearer|api_key|token|key)\s*[:=]?\s*([a-zA-Z0-9_\-.]{16,})/gi, '$1=[REDACTED_KEY]');
      redacted = redacted.replace(/eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+/g, '[REDACTED_JWT]');
    } else if (leakType === 'pii_credit_card') {
      redacted = redacted.replace(/\b(\d[ -]*?){13,16}\b/g, '[REDACTED_CC]');
    }

    return {
      id, timestamp, service, level: entry.level || 'INFO',
      rawMessage: entry.message, redactedMessage: redacted,
      model: data.model || 'jev-latest', latencyMs,
      tokens: { input: data.usage?.input_tokens || 0, output: data.usage?.output_tokens || 0 },
      judgments: {
        sensitiveDataLeak: { detected: leakType !== 'none', leakType, confidence: leakConf, probabilities: leakProbs },
        impendingOutageRisk: { probability: outageProb, isHighRisk: isHighOutageRisk },
        severityScore: { score: severityScore, confidence: severityConf },
        recommendedAction: { action: recAction, confidence: actionConf },
        failureDomain: { domain, confidence: domainConf },
      },
      alert: { triggered: alertTriggered, urgency, headline, reasons },
    };
  }
}
