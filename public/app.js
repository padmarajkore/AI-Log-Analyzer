// TypeSafe Log Guardian — Batch Window Mode Client

document.addEventListener('DOMContentLoaded', () => {

  // ── State ──────────────────────────────────────────────────────────────────
  const state = {
    totalRawLogs: 0,
    totalBatches: 0,
    criticalBatches: 0,
    latencies: [],
    rawLogsThisSecond: 0,
    lastRateUpdate: Date.now(),
    currentRate: 0,
    simulatorRunning: false,
  };

  // ── DOM refs ───────────────────────────────────────────────────────────────
  const $ = (id) => document.getElementById(id);

  // KPI
  const kpiRawRate       = $('kpiRawRate');
  const kpiTotalLogs     = $('kpiTotalLogs');
  const kpiBatchCount    = $('kpiBatchCount');
  const kpiCriticalBatches = $('kpiCriticalBatches');
  const kpiAvgLatency    = $('kpiAvgLatency');
  const lastLatencyTag   = $('lastLatencyTag');

  // Simulator bar
  const simulatorBar     = $('simulatorBar');
  const simStatusBadge   = $('simStatusBadge');
  const simSpeedSelect   = $('simSpeedSelect');
  const batchWindowSelect= $('batchWindowSelect');
  const toggleSimBtn     = $('toggleSimulatorBtn');
  const simBtnIcon       = $('simBtnIcon');
  const simBtnText       = $('simBtnText');
  const simGenCount      = $('simGenCount');

  // Firehose
  const rawLogCounter    = $('rawLogCounter');
  const rateBarFill      = $('rateBarFill');
  const rateBarLabel     = $('rateBarLabel');
  const logTicker        = $('logTicker');
  const showRawToggle    = $('showRawToggle');

  // Batch inspector
  const batchEmptyState  = $('batchEmptyState');
  const batchContent     = $('batchContent');
  const batchId          = $('batchId');
  const batchLogCount    = $('batchLogCount');
  const batchWindow      = $('batchWindow');
  const batchLatency     = $('batchLatency');
  const healthScoreCircle= $('healthScoreCircle');
  const healthScoreNum   = $('healthScoreNum');
  const healthBarFill    = $('healthBarFill');
  const healthLabel      = $('healthLabel');
  const urgencyBadge     = $('urgencyBadge');
  const threatCount      = $('threatCount');
  const threatsList      = $('threatsList');
  const servicesSection  = $('servicesSection');
  const servicesList     = $('servicesList');
  const narrativeBox     = $('narrativeBox');
  const breakdownTable   = $('breakdownTable');
  const breakdownCount   = $('breakdownCount');
  const metaModelName    = $('metaModelName');
  const metaLatency      = $('metaLatency');
  const metaInputTokens  = $('metaInputTokens');
  const metaOutputTokens = $('metaOutputTokens');

  // Single log inspector (for manual analyze)
  const singleInspectorCard = $('singleInspectorCard');
  const analyzeBtn       = $('analyzeBtn');
  const analyzeSpinner   = $('analyzeSpinner');
  const logMessageInput  = $('logMessageInput');
  const serviceInput     = $('serviceInput');
  const levelInput       = $('levelInput');

  // Modals
  const integrationModal = $('integrationModal');
  const whyAiModal       = $('whyAiModal');

  // ── Rate counter (updates every second) ────────────────────────────────────
  let rateWindowLogs = 0;
  setInterval(() => {
    const rate = rateWindowLogs;
    rateWindowLogs = 0;
    state.currentRate = rate;
    if (kpiRawRate) kpiRawRate.textContent = rate;
    if (rateBarFill) rateBarFill.style.width = `${Math.min(100, (rate / 200) * 100)}%`;
    if (rateBarLabel) rateBarLabel.textContent = `${rate} logs/sec`;
    updateRateBarColor(rate);
  }, 1000);

  function updateRateBarColor(rate) {
    if (!rateBarFill) return;
    if (rate >= 100) rateBarFill.style.background = 'linear-gradient(90deg, #10b981, #06b6d4)';
    else if (rate >= 50) rateBarFill.style.background = 'linear-gradient(90deg, #f59e0b, #10b981)';
    else rateBarFill.style.background = 'linear-gradient(90deg, #6366f1, #3b82f6)';
  }

  // ── Ticker buffer (throttled display) ────────────────────────────────────
  let tickerQueue = [];
  let tickerRunning = false;

  function addToTicker(entry) {
    tickerQueue.push(entry);
    if (!tickerRunning) drainTicker();
  }

  function drainTicker() {
    if (tickerQueue.length === 0) { tickerRunning = false; return; }
    tickerRunning = true;

    // Remove empty state
    const empty = logTicker?.querySelector('.ticker-empty');
    if (empty) empty.remove();

    // Show at most 1 entry per frame — avoids DOM overload at 100/s
    const entry = tickerQueue.shift();
    if (showRawToggle?.checked && logTicker) {
      const row = document.createElement('div');
      row.className = 'ticker-row';
      const lvlClass = entry.level === 'ERROR' ? 'lvl-error' : entry.level === 'WARN' ? 'lvl-warn' : 'lvl-info';
      row.innerHTML = `<span class="ticker-level ${lvlClass}">${entry.level || 'INFO'}</span><span class="ticker-svc">${escapeHtml(entry.service || '?')}</span><span class="ticker-msg">${escapeHtml((entry.message || '').substring(0, 90))}</span>`;
      logTicker.prepend(row);

      // Cap ticker DOM to 30 rows
      while (logTicker.children.length > 30) logTicker.lastChild?.remove();
    }

    // Drain remaining in next frame
    requestAnimationFrame(drainTicker);
  }

  // ── Batch SSE stream ────────────────────────────────────────────────────────
  function initBatchSSE() {
    const sse = new EventSource('/api/logs/batch-stream');

    sse.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'CONNECTED') return;

        if (data.type === 'RAW_LOG') {
          // Raw log tick — update counter and ticker
          state.totalRawLogs++;
          rateWindowLogs++;
          if (kpiTotalLogs) kpiTotalLogs.textContent = state.totalRawLogs.toLocaleString();
          if (rawLogCounter) rawLogCounter.textContent = `${state.totalRawLogs.toLocaleString()} total`;
          addToTicker(data.entry);
          return;
        }

        // It's a BatchAnalysisResult
        renderBatchResult(data);

      } catch (e) {
        console.error('Batch SSE parse error', e);
      }
    };

    sse.onerror = () => console.warn('Batch SSE disconnected, retrying…');
  }

  // ── Render a batch result ───────────────────────────────────────────────────
  function renderBatchResult(result) {
    state.totalBatches++;
    if (result.highestUrgency === 'CRITICAL') state.criticalBatches++;

    const lat = result.latencyMs || 0;
    state.latencies.push(lat);
    if (state.latencies.length > 20) state.latencies.shift();
    const avgLat = Math.round(state.latencies.reduce((a, b) => a + b, 0) / state.latencies.length);

    // KPI updates
    if (kpiBatchCount) kpiBatchCount.textContent = state.totalBatches;
    if (kpiCriticalBatches) kpiCriticalBatches.textContent = state.criticalBatches;
    if (kpiAvgLatency) kpiAvgLatency.textContent = `${avgLat} ms`;
    if (lastLatencyTag) lastLatencyTag.textContent = `~${lat}ms`;

    // Show content, hide empty
    batchEmptyState?.classList.add('hidden');
    batchContent?.classList.remove('hidden');
    singleInspectorCard?.classList.add('hidden');

    // Batch header
    if (batchId) batchId.textContent = result.batchId?.substring(0, 20) + '…' || '—';
    if (batchLogCount) batchLogCount.textContent = `${result.logCount} logs`;
    if (batchWindow) batchWindow.textContent = `${(result.windowMs / 1000).toFixed(0)}s window`;
    if (batchLatency) batchLatency.textContent = `${result.latencyMs}ms`;

    // Health score
    const score = result.systemHealthScore || 5;
    if (healthScoreNum) healthScoreNum.textContent = score;
    if (healthBarFill) healthBarFill.style.width = `${(score / 10) * 100}%`;
    if (healthLabel) healthLabel.textContent = result.systemHealthLabel || '—';

    // Color health bar
    let healthColor, scoreCircleClass;
    if (score >= 8) { healthColor = '#10b981'; scoreCircleClass = 'score-healthy'; }
    else if (score >= 6) { healthColor = '#f59e0b'; scoreCircleClass = 'score-degraded'; }
    else if (score >= 4) { healthColor = '#ef4444'; scoreCircleClass = 'score-critical'; }
    else { healthColor = '#dc2626'; scoreCircleClass = 'score-failing'; }
    if (healthBarFill) healthBarFill.style.background = healthColor;
    if (healthScoreCircle) {
      healthScoreCircle.className = `health-score-circle ${scoreCircleClass}`;
    }

    // Urgency badge
    const urgencyColors = { NONE: 'badge-normal', LOW: 'badge-warning', HIGH: 'badge-high', CRITICAL: 'badge-critical' };
    if (urgencyBadge) {
      urgencyBadge.textContent = result.highestUrgency;
      urgencyBadge.className = `urgency-badge ${urgencyColors[result.highestUrgency] || 'badge-normal'}`;
    }

    // Top threats
    const threats = result.topThreats || [];
    if (threatCount) threatCount.textContent = `${threats.length} found`;
    if (threatsList) {
      threatsList.innerHTML = '';
      threats.forEach(t => {
        const item = document.createElement('div');
        item.className = 'threat-item';
        const isCrit = t.includes('💥') || t.includes('🔑') || t.includes('CRITICAL');
        item.classList.toggle('threat-critical', isCrit);
        item.textContent = t;
        threatsList.appendChild(item);
      });
    }

    // Services at risk
    const services = result.servicesAtRisk || [];
    if (servicesList) {
      servicesList.innerHTML = '';
      if (services.length === 0) {
        servicesSection?.classList.add('hidden');
      } else {
        servicesSection?.classList.remove('hidden');
        services.forEach(svc => {
          const chip = document.createElement('span');
          chip.className = 'service-chip';
          chip.textContent = svc;
          servicesList.appendChild(chip);
        });
      }
    }

    // Narrative
    if (narrativeBox) narrativeBox.textContent = result.batchNarrative || '—';

    // Log breakdown table (top 10)
    const summaries = (result.logSummaries || []).slice(0, 15);
    if (breakdownCount) breakdownCount.textContent = `${result.logCount} logs`;
    if (breakdownTable) {
      breakdownTable.innerHTML = '';
      summaries.forEach(s => {
        const row = document.createElement('div');
        row.className = 'breakdown-row';
        const lvlClass = s.level === 'ERROR' ? 'lvl-error' : s.level === 'WARN' ? 'lvl-warn' : 'lvl-info';
        const leakTag = s.has_leak ? `<span class="breakdown-tag tag-red">LEAK</span>` : '';
        const outTag = s.outage_risk_pct > 60 ? `<span class="breakdown-tag tag-amber">OUTAGE ${Math.round(s.outage_risk_pct)}%</span>` : '';
        row.innerHTML = `
          <span class="ticker-level ${lvlClass}">${s.level}</span>
          <span class="breakdown-svc">${escapeHtml(s.service)}</span>
          <span class="breakdown-msg">${escapeHtml(s.one_line_finding.substring(0, 80))}</span>
          <span class="breakdown-tags">${leakTag}${outTag}</span>
        `;
        breakdownTable.appendChild(row);
      });
    }

    // Meta
    if (metaModelName) metaModelName.textContent = result.model || 'jev';
    if (metaLatency) metaLatency.textContent = `${result.latencyMs} ms`;
    if (metaInputTokens) metaInputTokens.textContent = result.tokens?.input || '—';
    if (metaOutputTokens) metaOutputTokens.textContent = `${result.tokens?.output || 0} (free)`;

    // Flash the inspector
    batchContent?.classList.add('batch-flash');
    setTimeout(() => batchContent?.classList.remove('batch-flash'), 600);
  }

  // ── Simulator controls ──────────────────────────────────────────────────────
  function updateSimulatorUI(running) {
    state.simulatorRunning = running;
    if (running) {
      simulatorBar?.classList.add('streaming');
      if (simStatusBadge) { simStatusBadge.textContent = 'LIVE'; simStatusBadge.className = 'sim-badge badge-streaming'; }
      toggleSimBtn?.classList.add('running');
      if (simBtnIcon) simBtnIcon.textContent = '⏹';
      if (simBtnText) simBtnText.textContent = 'Stop';
    } else {
      simulatorBar?.classList.remove('streaming');
      if (simStatusBadge) { simStatusBadge.textContent = 'STOPPED'; simStatusBadge.className = 'sim-badge badge-idle'; }
      toggleSimBtn?.classList.remove('running');
      if (simBtnIcon) simBtnIcon.textContent = '▶';
      if (simBtnText) simBtnText.textContent = 'Start';
    }
  }

  toggleSimBtn?.addEventListener('click', async () => {
    try {
      const endpoint = state.simulatorRunning ? '/api/simulator/stop' : '/api/simulator/start';
      const intervalMs = parseInt(simSpeedSelect?.value || '10', 10);
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ intervalMs }),
      });
      const data = await res.json();
      updateSimulatorUI(data.status.isRunning);
    } catch (err) {
      console.error('Toggle error:', err);
    }
  });

  simSpeedSelect?.addEventListener('change', async () => {
    const intervalMs = parseInt(simSpeedSelect.value, 10);
    await fetch('/api/simulator/speed', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ intervalMs }),
    });
  });

  batchWindowSelect?.addEventListener('change', async () => {
    const windowMs = parseInt(batchWindowSelect.value, 10);
    await fetch('/api/batch-config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ windowMs, mode: 'batch' }),
    });
  });

  // Check initial status
  fetch('/api/simulator/status').then(r => r.json()).then(data => {
    updateSimulatorUI(data.isRunning);
    if (data.intervalMs && simSpeedSelect) simSpeedSelect.value = String(data.intervalMs);
    if (data.batchConfig?.windowMs && batchWindowSelect) batchWindowSelect.value = String(data.batchConfig.windowMs);
    if (data.batchStats) {
      state.totalRawLogs = data.batchStats.totalRawLogs || 0;
      state.totalBatches = data.batchStats.totalBatches || 0;
      state.criticalBatches = data.batchStats.totalCritical || 0;
      if (kpiTotalLogs) kpiTotalLogs.textContent = state.totalRawLogs.toLocaleString();
      if (kpiBatchCount) kpiBatchCount.textContent = state.totalBatches;
      if (kpiCriticalBatches) kpiCriticalBatches.textContent = state.criticalBatches;
      if (rawLogCounter) rawLogCounter.textContent = `${state.totalRawLogs.toLocaleString()} total`;
    }
  }).catch(() => {});

  // ── Single log analyze (manual) ─────────────────────────────────────────────
  async function triggerAnalysis() {
    const service = serviceInput?.value.trim() || 'backend-service';
    const level = levelInput?.value || 'INFO';
    const message = logMessageInput?.value.trim();
    if (!message) return;

    setLoading(true);
    try {
      const res = await fetch('/api/logs/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ service, level, message }),
      });
      if (!res.ok) throw new Error((await res.json()).error || 'Failed');
      const { analysis } = await res.json();
      renderSingleResult(analysis);
    } catch (err) {
      alert('Jev Error: ' + err.message);
    } finally {
      setLoading(false);
    }
  }

  function setLoading(loading) {
    if (analyzeBtn) analyzeBtn.disabled = loading;
    if (loading) analyzeSpinner?.classList.remove('hidden');
    else analyzeSpinner?.classList.add('hidden');
  }

  function renderSingleResult(item) {
    if (!item) return;

    // Show single inspector, hide batch empty
    batchEmptyState?.classList.add('hidden');
    batchContent?.classList.add('hidden');
    singleInspectorCard?.classList.remove('hidden');

    const j = item.judgments || {};
    const leak = j.sensitiveDataLeak || { leakType: 'none', confidence: 1, probabilities: {} };
    const outage = j.impendingOutageRisk || { probability: 0 };
    const severity = j.severityScore || { score: 1.0 };
    const action = j.recommendedAction || { action: 'suppress' };
    const domain = j.failureDomain || { domain: 'app_logic' };

    const isLeak = leak.leakType !== 'none';
    const outageProb = Math.round((outage.probability || 0) * 100);
    const sevScore = severity.score || 1.0;

    const alertBanner = $('inspectorAlertBanner');
    if (alertBanner) {
      alertBanner.className = 'alert-banner';
      if (isLeak) alertBanner.classList.add('alert-critical');
      else if (outageProb >= 65 || sevScore >= 4.0) alertBanner.classList.add('alert-critical');
      else if (outageProb >= 35 || sevScore >= 3.0) alertBanner.classList.add('alert-warning');
      else alertBanner.classList.add('alert-normal');
    }

    const alertH = $('alertHeadline');
    const alertR = $('alertReasonText');
    const alertB = $('alertUrgencyBadge');
    const alertI = $('alertIconWrap');

    if (isLeak) {
      if (alertH) alertH.textContent = '🚨 CREDENTIAL LEAK DETECTED';
      if (alertR) alertR.textContent = `Jev found a ${leak.leakType.toUpperCase().replace(/_/g, ' ')} in this log.`;
      if (alertB) { alertB.textContent = 'CRITICAL'; alertB.className = 'alert-badge badge-critical'; }
      if (alertI) alertI.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>`;
    } else if (outageProb >= 65 || sevScore >= 4.0) {
      if (alertH) alertH.textContent = `⚠️ HIGH SYSTEM FAILURE RISK (${outageProb}%)`;
      if (alertR) alertR.textContent = `Cascading failure pattern in ${domain.domain.toUpperCase()}.`;
      if (alertB) { alertB.textContent = 'HIGH RISK'; alertB.className = 'alert-badge badge-critical'; }
    } else if (outageProb >= 35 || sevScore >= 3.0) {
      if (alertH) alertH.textContent = '⚡ ELEVATED WARNING';
      if (alertR) alertR.textContent = 'Investigation advised.';
      if (alertB) { alertB.textContent = 'WARNING'; alertB.className = 'alert-badge badge-warning'; }
    } else {
      if (alertH) alertH.textContent = '✅ SYSTEM NORMAL';
      if (alertR) alertR.textContent = 'No threats detected.';
      if (alertB) { alertB.textContent = 'NORMAL'; alertB.className = 'alert-badge badge-normal'; }
    }

    const redactedBox = $('redactedMessageBox');
    if (redactedBox) redactedBox.textContent = item.redactedMessage || item.rawMessage;

    const rBadge = $('redactionBadge');
    if (rBadge) {
      rBadge.textContent = isLeak ? 'REDACTED' : 'CLEAN';
      rBadge.className = `badge-sm ${isLeak ? 'badge-red' : 'badge-green'}`;
    }

    const outBar = $('outageProgressBar');
    if (outBar) {
      outBar.style.width = `${outageProb}%`;
      outBar.style.backgroundColor = outageProb >= 65 ? 'var(--status-red)' : outageProb >= 35 ? 'var(--status-amber)' : 'var(--status-green)';
    }
    const outageProbText = $('outageProbText');
    if (outageProbText) outageProbText.textContent = `${outageProb}%`;
    const outageRiskDesc = $('outageRiskDesc');
    if (outageRiskDesc) outageRiskDesc.textContent = outageProb >= 65 ? 'Imminent Outage' : outageProb >= 35 ? 'Moderate Risk' : 'Low Risk';

    const leakBadge = $('leakTypeBadge');
    if (leakBadge) {
      leakBadge.textContent = leak.leakType.toUpperCase().replace(/_/g, ' ');
      leakBadge.className = `leak-type-badge ${isLeak ? 'badge-danger' : 'badge-safe'}`;
    }
    const leakConf = $('leakConfidenceTag');
    if (leakConf) leakConf.textContent = `Conf: ${Math.round(leak.confidence * 100)}%`;

    const leakBars = $('leakProbabilityBars');
    if (leakBars) {
      leakBars.innerHTML = '';
      Object.entries(leak.probabilities || {}).forEach(([key, val]) => {
        const pct = Math.round((val || 0) * 100);
        const row = document.createElement('div');
        row.className = 'prob-row';
        row.innerHTML = `<span>${escapeHtml(key)}</span><div class="prob-row-bar"><div class="prob-row-fill" style="width:${pct}%"></div></div><span>${pct}%</span>`;
        leakBars.appendChild(row);
      });
    }

    const sevText = $('severityScoreText');
    if (sevText) sevText.textContent = sevScore.toFixed(1);
    const sevDots = $('severityDots');
    if (sevDots) {
      sevDots.querySelectorAll('.dot').forEach((dot, idx) => {
        dot.className = 'dot';
        if (idx < Math.round(sevScore)) dot.classList.add(sevScore >= 4.0 ? 'danger' : 'active');
      });
    }

    const actText = $('actionText');
    if (actText) actText.textContent = (action.action || 'suppress').toUpperCase().replace(/_/g, ' ');
    const domBadge = $('failureDomainBadge');
    if (domBadge) domBadge.textContent = (domain.domain || 'app_logic').toUpperCase().replace(/_/g, ' ');

    const actPill = $('actionPill');
    if (actPill) {
      const a = action.action || 'suppress';
      if (a.includes('emergency')) { actPill.style.borderColor = 'var(--status-red-border)'; actPill.style.background = 'var(--status-red-bg)'; actPill.style.color = 'var(--status-red)'; }
      else if (a.includes('notify')) { actPill.style.borderColor = 'var(--status-amber-border)'; actPill.style.background = 'var(--status-amber-bg)'; actPill.style.color = 'var(--status-amber)'; }
      else { actPill.style.borderColor = 'var(--border-subtle)'; actPill.style.background = 'rgba(255,255,255,0.04)'; actPill.style.color = '#fff'; }
    }

    const sm = $('singleMetaModelName');
    if (sm) sm.textContent = item.model || 'jev';
    const sl = $('singleMetaLatency');
    if (sl) sl.textContent = `${item.latencyMs || 0} ms`;
    const st = $('singleMetaTokens');
    if (st) st.textContent = item.tokens?.input || '—';
  }

  analyzeBtn?.addEventListener('click', triggerAnalysis);

  // ── Presets ─────────────────────────────────────────────────────────────────
  async function loadPresets() {
    try {
      const res = await fetch('/api/presets');
      const presets = await res.json();
      const container = $('scenarioButtons');
      if (!container) return;
      container.innerHTML = '';
      presets.forEach(p => {
        const btn = document.createElement('button');
        btn.className = 'scenario-btn';
        const badgeClass = p.category.toLowerCase().includes('security') ? 'badge-red' :
                           p.category.toLowerCase().includes('failure') ? 'badge-amber' : 'badge-cyan';
        btn.innerHTML = `<div class="scenario-info"><div class="scenario-title">${escapeHtml(p.name)}</div><div class="scenario-desc">${escapeHtml(p.message.substring(0, 70))}…</div></div><span class="scenario-badge ${badgeClass}">${escapeHtml(p.category)}</span>`;
        btn.addEventListener('click', () => {
          if (serviceInput) serviceInput.value = p.service;
          if (levelInput) levelInput.value = p.level;
          if (logMessageInput) logMessageInput.value = p.message;
          triggerAnalysis();
        });
        container.appendChild(btn);
      });
    } catch (e) {
      console.error('Presets load failed', e);
    }
  }

  // ── Modals ──────────────────────────────────────────────────────────────────
  $('openIntegrationBtn')?.addEventListener('click', () => integrationModal?.classList.remove('hidden'));
  $('closeModalBtn')?.addEventListener('click', () => integrationModal?.classList.add('hidden'));
  integrationModal?.addEventListener('click', e => { if (e.target === integrationModal) integrationModal.classList.add('hidden'); });

  $('openWhyAiBtn')?.addEventListener('click', () => whyAiModal?.classList.remove('hidden'));
  $('closeWhyAiBtn')?.addEventListener('click', () => whyAiModal?.classList.add('hidden'));
  whyAiModal?.addEventListener('click', e => { if (e.target === whyAiModal) whyAiModal.classList.add('hidden'); });

  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.add('hidden'));
      btn.classList.add('active');
      document.getElementById(btn.dataset.tab)?.classList.remove('hidden');
    });
  });

  // ── Util ────────────────────────────────────────────────────────────────────
  function escapeHtml(text) {
    if (!text) return '';
    return String(text)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
  }

  // ── Init ────────────────────────────────────────────────────────────────────
  loadPresets();
  initBatchSSE();
});
