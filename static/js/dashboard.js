/**
 * dashboard.js
 * ============
 * Front-end controller for CyberGuard SOC Phishing URL Detector.
 * Handles AJAX requests, dynamic DOM rendering, Chart.js visualizations,
 * batch CSV processing, and history auditing with animated gauges and micro-interactions.
 */

// Global Chart Instances
let overviewDoughnutChart = null;
let overviewBarChart = null;
let featureImportanceChart = null;
let lastBatchResults = [];
let searchDebounceTimeout = null;

// DOM Initialization
document.addEventListener("DOMContentLoaded", () => {
  initAuth();
  initNavigation();
  initClock();
  initSidebarToggle();
  checkSystemHealth();
  loadOverviewTelemetry();
  loadScanHistory();
  loadModelPerformance();
  setupDropzone();
});

// Toast Notification System
function showToast(message, type = "info") {
  let container = document.getElementById("toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "toast-container";
    document.body.appendChild(container);
  }

  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  
  const iconMap = {
    safe: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#22C55E" stroke-width="2.5"><path d="M20 6L9 17l-5-5"/></svg>`,
    warning: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
    danger: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
    info: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#4C7DFF" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`
  };

  toast.innerHTML = `${iconMap[type] || iconMap.info}<span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(10px) scale(0.95)";
    setTimeout(() => toast.remove(), 250);
  }, 3600);
}

// Copy to Clipboard
function copyToClipboard(text, label = "URL") {
  if (!navigator.clipboard) {
    const el = document.createElement("textarea");
    el.value = text;
    document.body.appendChild(el);
    el.select();
    document.execCommand("copy");
    document.body.removeChild(el);
  } else {
    navigator.clipboard.writeText(text);
  }
  showToast(`Copied ${label} to clipboard`, "info");
}

// Clock
function initClock() {
  const clockEl = document.getElementById("live-time-clock");
  if (!clockEl) return;
  function update() {
    const now = new Date();
    clockEl.textContent = now.toUTCString().replace("GMT", "UTC");
  }
  update();
  setInterval(update, 1000);
}

// Mobile Sidebar Toggle
function initSidebarToggle() {
  const toggleBtn = document.getElementById("btn-toggle-sidebar");
  const sidebar = document.querySelector(".sidebar");
  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener("click", () => {
      sidebar.classList.toggle("open");
    });

    document.addEventListener("click", (e) => {
      if (window.innerWidth <= 768 && sidebar.classList.contains("open")) {
        if (!sidebar.contains(e.target) && !toggleBtn.contains(e.target)) {
          sidebar.classList.remove("open");
        }
      }
    });
  }
}

// Number Count-Up Animation
function animateValue(el, start, end, duration = 800) {
  if (!el) return;
  if (isNaN(end)) {
    el.textContent = end;
    return;
  }
  const range = end - start;
  let current = start;
  const increment = range / (duration / 16);
  const step = () => {
    current += increment;
    if ((increment > 0 && current >= end) || (increment < 0 && current <= end)) {
      el.textContent = Number(end).toLocaleString();
    } else {
      el.textContent = Math.round(current).toLocaleString();
      requestAnimationFrame(step);
    }
  };
  requestAnimationFrame(step);
}

// Navigation Tabs
function initNavigation() {
  const navItems = document.querySelectorAll(".nav-item");
  navItems.forEach(item => {
    item.addEventListener("click", () => {
      const tabId = item.getAttribute("data-tab");
      navigateToTab(tabId);
      if (window.innerWidth <= 768) {
        document.querySelector(".sidebar")?.classList.remove("open");
      }
    });
  });
}

function navigateToTab(tabId) {
  // Update sidebar active class
  document.querySelectorAll(".nav-item").forEach(el => {
    el.classList.toggle("active", el.getAttribute("data-tab") === tabId);
  });

  // Update views
  document.querySelectorAll(".tab-view").forEach(view => {
    view.classList.remove("active");
  });
  const targetView = document.getElementById(`view-${tabId}`);
  if (targetView) {
    targetView.classList.add("active");
  }

  // Update Topbar Title
  const titles = {
    "overview": "Security Operations Dashboard",
    "scanner": "Real-Time URL Threat Scanner",
    "batch": "CSV Batch URL Threat Pipeline",
    "history": "Historical Threat Audit Log",
    "model-perf": "ML Classifier Validation & Metrics",
    "about": "Architecture & Threat Model"
  };
  const titleEl = document.getElementById("page-title");
  if (titleEl) {
    titleEl.textContent = titles[tabId] || "Security Dashboard";
  }

  if (tabId === "overview") {
    loadOverviewTelemetry();
  } else if (tabId === "history") {
    loadScanHistory();
  } else if (tabId === "model-perf") {
    loadModelPerformance();
  }
}

// Health Check
async function checkSystemHealth() {
  try {
    const res = await fetch("/api/health");
    const data = await res.json();
    const dot = document.getElementById("system-status-dot");
    const text = document.getElementById("system-status-text");
    const chip = document.getElementById("model-status-chip");

    if (data.status === "healthy") {
      if (dot) {
        dot.style.backgroundColor = "var(--color-legit)";
        dot.style.boxShadow = "0 0 10px var(--color-legit)";
      }
      if (text) text.textContent = "System Operational";
      if (chip) chip.textContent = `Model: ${data.model_name} (Active)`;
    } else {
      if (dot) {
        dot.style.backgroundColor = "var(--color-phish)";
        dot.style.boxShadow = "0 0 10px var(--color-phish)";
      }
      if (text) text.textContent = "Model Degraded";
      if (chip) chip.textContent = "Model: Training Required";
    }
  } catch (err) {
    console.error("Health check error:", err);
  }
}

// Overview Telemetry & Stats
async function loadOverviewTelemetry() {
  try {
    const [statsRes, historyRes] = await Promise.all([
      fetch("/api/statistics"),
      fetch("/api/history?limit=5")
    ]);
    const stats = await statsRes.json();
    const historyData = await historyRes.json();

    // Update KPI numbers with animated count-up
    const totalEl = document.getElementById("kpi-total-scans");
    const phishEl = document.getElementById("kpi-phishing-count");
    const suspEl = document.getElementById("kpi-suspicious-count");
    const legitEl = document.getElementById("kpi-legitimate-count");

    if (totalEl) animateValue(totalEl, parseInt(totalEl.textContent) || 0, stats.total_scans || 0);
    if (phishEl) animateValue(phishEl, parseInt(phishEl.textContent) || 0, stats.phishing_count || 0);
    if (suspEl) animateValue(suspEl, parseInt(suspEl.textContent) || 0, stats.suspicious_count || 0);
    if (legitEl) animateValue(legitEl, parseInt(legitEl.textContent) || 0, stats.legitimate_count || 0);

    // Render Charts
    renderOverviewCharts(stats);

    // Render Recent Table
    renderRecentTable(historyData.history || []);
  } catch (err) {
    console.error("Error loading overview telemetry:", err);
  }
}

function renderOverviewCharts(stats) {
  const phish = stats.phishing_count || 0;
  const susp = stats.suspicious_count || 0;
  const legit = stats.legitimate_count || 0;
  const total = phish + susp + legit;

  // Chart 1: Doughnut
  const ctxDonut = document.getElementById("overviewThreatChart");
  if (ctxDonut) {
    if (overviewDoughnutChart) overviewDoughnutChart.destroy();
    overviewDoughnutChart = new Chart(ctxDonut, {
      type: "doughnut",
      data: {
        labels: ["Phishing", "Suspicious", "Legitimate"],
        datasets: [{
          data: total > 0 ? [phish, susp, legit] : [1, 1, 1],
          backgroundColor: ["#EF4444", "#F59E0B", "#22C55E"],
          borderColor: "#100C1F",
          borderWidth: 3,
          hoverOffset: 8
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 800, easing: "easeOutQuart" },
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              color: "#817993",
              font: { family: "Inter", size: 12, weight: 500 },
              padding: 16,
              usePointStyle: true,
              pointStyle: "circle"
            }
          },
          tooltip: {
            backgroundColor: "rgba(9, 6, 23, 0.95)",
            titleFont: { family: "Inter", weight: 700 },
            bodyFont: { family: "JetBrains Mono" },
            borderColor: "rgba(139, 61, 255, 0.25)",
            borderWidth: 1,
            padding: 12
          }
        },
        cutout: "72%"
      }
    });
  }

  // Chart 2: Bar Breakdown
  const ctxBar = document.getElementById("overviewBarChart");
  if (ctxBar) {
    if (overviewBarChart) overviewBarChart.destroy();
    overviewBarChart = new Chart(ctxBar, {
      type: "bar",
      data: {
        labels: ["Phishing", "Suspicious", "Legitimate"],
        datasets: [{
          label: "Scans Recorded",
          data: [phish, susp, legit],
          backgroundColor: [
            "rgba(239, 68, 68, 0.75)",
            "rgba(245, 158, 11, 0.75)",
            "rgba(34, 197, 94, 0.75)"
          ],
          borderColor: ["#EF4444", "#F59E0B", "#22C55E"],
          borderWidth: 1.5,
          borderRadius: 8
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 800, easing: "easeOutQuart" },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "rgba(9, 6, 23, 0.95)",
            titleFont: { family: "Inter", weight: 700 },
            bodyFont: { family: "JetBrains Mono" },
            borderColor: "rgba(139, 61, 255, 0.25)",
            borderWidth: 1,
            padding: 12
          }
        },
        scales: {
          x: {
            ticks: { color: "#817993", font: { family: "Inter", weight: 500 } },
            grid: { display: false }
          },
          y: {
            ticks: { color: "#817993", stepSize: 1, font: { family: "JetBrains Mono" } },
            grid: { color: "rgba(255, 255, 255, 0.05)" }
          }
        }
      }
    });
  }
}

function renderRecentTable(records) {
  const tbody = document.getElementById("overview-recent-tbody");
  if (!tbody) return;

  if (records.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 32px;">No scan telemetry recorded yet. Inspect a URL to populate.</td></tr>`;
    return;
  }

  tbody.innerHTML = records.map(r => `
    <tr>
      <td style="font-family: var(--font-mono); color: var(--color-cyan); font-weight: 700;">#${r.id}</td>
      <td>
        <div class="table-url-cell">
          <span class="url-mono" title="${escapeHtml(r.url)}">${escapeHtml(r.url)}</span>
          <button type="button" class="btn-copy-small" onclick="copyToClipboard('${escapeHtml(r.url)}', 'URL')" title="Copy URL">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          </button>
        </div>
      </td>
      <td><span class="badge ${getVerdictBadgeClass(r.prediction)}">${r.prediction}</span></td>
      <td style="font-family: var(--font-mono); font-weight: 700; color: ${getRiskScoreColor(r.risk_score)};">${r.risk_score} / 100</td>
      <td style="font-family: var(--font-mono);">${r.confidence}%</td>
      <td style="font-family: var(--font-mono); color: var(--color-legit);">${r.detection_time_ms ? r.detection_time_ms + ' ms' : '< 2 ms'}</td>
      <td style="font-size: 0.78rem; color: var(--text-muted); font-family: var(--font-mono);">${formatTimestamp(r.scan_time)}</td>
    </tr>
  `).join("");
}

// Single URL Scan
async function handleSingleScan(e) {
  e.preventDefault();
  const inputEl = document.getElementById("scan-url-input");
  const btnSubmit = document.getElementById("btn-scan-submit");
  const btnText = document.getElementById("btn-scan-text");
  const btnSpinner = document.getElementById("btn-scan-spinner");

  const url = inputEl.value.trim();
  if (!url) return;

  // Set loading state
  btnSubmit.disabled = true;
  btnText.style.display = "none";
  btnSpinner.style.display = "inline-block";

  try {
    const res = await fetch("/api/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    const data = await res.json();
    if (!res.ok) {
      showToast(`Scan Failed: ${data.message || 'Error occurred'}`, "danger");
      return;
    }

    displayScanResult(data);
    showToast(`Scan Complete: ${data.prediction} detected`, data.prediction === "Phishing" ? "danger" : (data.prediction === "Suspicious" ? "warning" : "safe"));
    loadOverviewTelemetry();
  } catch (err) {
    console.error("Scan error:", err);
    showToast("Connection error while requesting threat analysis.", "danger");
  } finally {
    btnSubmit.disabled = false;
    btnText.style.display = "inline-block";
    btnSpinner.style.display = "none";
  }
}

// Circular Risk Gauge Animation
function updateRiskGauge(score) {
  const circle = document.getElementById("risk-gauge-meter");
  const numEl = document.getElementById("result-risk-score-num");
  if (!circle) return;

  const radius = 45;
  const circumference = 2 * Math.PI * radius; // ~282.74
  const offset = circumference - (score / 100) * circumference;

  circle.style.strokeDasharray = `${circumference} ${circumference}`;
  circle.style.strokeDashoffset = offset;

  let color = "var(--color-legit)";
  if (score > 70) color = "var(--color-phish)";
  else if (score > 30) color = "var(--color-suspicious)";

  circle.style.stroke = color;
  if (numEl) {
    animateValue(numEl, parseInt(numEl.textContent) || 0, score, 600);
  }
}

function displayScanResult(data) {
  const resultCard = document.getElementById("scan-result-card");
  resultCard.classList.add("visible");
  resultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });

  // Update verdict badge
  const badge = document.getElementById("result-threat-badge");
  const verdictText = document.getElementById("result-threat-text");
  const threatLevelEl = document.getElementById("result-threat-level");

  badge.className = "threat-badge " + getVerdictBadgeClass(data.prediction, true);
  verdictText.textContent = data.prediction.toUpperCase() + (data.prediction === "Phishing" ? " DETECTED" : " URL");
  threatLevelEl.textContent = data.threat_level;
  threatLevelEl.style.color = getThreatLevelColor(data.threat_level);

  // Scanned URL
  document.getElementById("result-url-text").textContent = data.url;

  // Stats & Gauge
  const riskScoreEl = document.getElementById("result-risk-score");
  if (riskScoreEl) {
    riskScoreEl.textContent = `${data.risk_score} / 100`;
    riskScoreEl.style.color = getRiskScoreColor(data.risk_score);
  }

  updateRiskGauge(data.risk_score);

  document.getElementById("result-confidence").textContent = `${data.confidence}%`;
  document.getElementById("result-detection-time").textContent = `${data.detection_time_ms} ms`;

  // Explainable Indicators
  const indList = document.getElementById("result-indicators-list");
  if (data.indicators && data.indicators.length > 0) {
    indList.innerHTML = data.indicators.map((ind, i) => {
      let cssClass = "ind-safe";
      let icon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M20 6L9 17l-5-5"/></svg>`;
      if (ind.type === "danger") {
        cssClass = "ind-danger";
        icon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`;
      } else if (ind.type === "warning") {
        cssClass = "ind-warning";
        icon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
      }
      return `
        <div class="indicator-item ${cssClass}" style="animation-delay: ${i * 40}ms">
          <div class="indicator-icon">${icon}</div>
          <div>
            <div class="indicator-title">${escapeHtml(ind.title)}</div>
            <div class="indicator-desc">${escapeHtml(ind.description)}</div>
          </div>
        </div>
      `;
    }).join("");
  } else {
    indList.innerHTML = `<div style="color: var(--text-muted); padding: 12px;">No specific indicators generated.</div>`;
  }

  // Feature Summary
  const featGrid = document.getElementById("result-features-grid");
  if (data.features_summary) {
    const f = data.features_summary;
    featGrid.innerHTML = `
      <div class="feat-spec-item"><div class="feat-spec-key">URL Length</div><div class="feat-spec-val">${f.length} chars</div></div>
      <div class="feat-spec-item"><div class="feat-spec-key">Dots Count</div><div class="feat-spec-val">${f.dots}</div></div>
      <div class="feat-spec-item"><div class="feat-spec-key">HTTPS Protocol</div><div class="feat-spec-val">${f.has_https ? 'Active (SSL)' : 'Missing (Plain)'}</div></div>
      <div class="feat-spec-item"><div class="feat-spec-key">Direct IP Host</div><div class="feat-spec-val">${f.has_ip ? 'Yes (Danger)' : 'No (FQDN)'}</div></div>
      <div class="feat-spec-item"><div class="feat-spec-key">Subdomain Count</div><div class="feat-spec-val">${f.subdomains}</div></div>
      <div class="feat-spec-item"><div class="feat-spec-key">Hostname Entropy</div><div class="feat-spec-val">${f.entropy} bits</div></div>
      <div class="feat-spec-item"><div class="feat-spec-key">Suspicious Keywords</div><div class="feat-spec-val">${f.suspicious_keywords} found</div></div>
      <div class="feat-spec-item"><div class="feat-spec-key">Shortener Service</div><div class="feat-spec-val">${f.is_shortened ? 'Yes (Masked)' : 'No (Direct)'}</div></div>
    `;
  }
}

function loadPreset(url) {
  document.getElementById("scan-url-input").value = url;
  document.getElementById("url-scan-form").dispatchEvent(new Event("submit"));
}

// Batch Scanner Dropzone
function setupDropzone() {
  const dropzone = document.getElementById("csv-dropzone");
  if (!dropzone) return;

  ["dragenter", "dragover"].forEach(evt => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    });
  });

  ["dragleave", "drop"].forEach(evt => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
    });
  });

  dropzone.addEventListener("drop", (e) => {
    const dt = e.dataTransfer;
    if (dt && dt.files && dt.files.length > 0) {
      processBatchFile(dt.files[0]);
    }
  });
}

function handleFileSelect(e) {
  if (e.target.files && e.target.files.length > 0) {
    processBatchFile(e.target.files[0]);
  }
}

async function processBatchFile(file) {
  if (!file.name.toLowerCase().endsWith(".csv")) {
    showToast("Please select a valid CSV file (.csv).", "warning");
    return;
  }

  const promptEl = document.getElementById("dropzone-prompt");
  const progressEl = document.getElementById("batch-progress");
  const kpisEl = document.getElementById("batch-summary-kpis");
  const tableContainerEl = document.getElementById("batch-results-container");
  const tbody = document.getElementById("batch-results-tbody");
  const exportBtn = document.getElementById("btn-export-batch");

  promptEl.textContent = `Analyzing: ${file.name} (${(file.size / 1024).toFixed(1)} KB)...`;
  progressEl.style.display = "block";
  kpisEl.style.display = "none";
  tableContainerEl.style.display = "none";

  const formData = new FormData();
  formData.append("file", file);

  try {
    const res = await fetch("/api/batch-predict", {
      method: "POST",
      body: formData
    });

    const data = await res.json();
    if (!res.ok) {
      showToast(`Batch Error: ${data.message || 'Failed to process file'}`, "danger");
      promptEl.textContent = "Drag & Drop CSV file here, or click to browse";
      return;
    }

    lastBatchResults = data.results || [];

    // Update KPI cards with animated count
    animateValue(document.getElementById("batch-kpi-total"), 0, data.total_processed);
    animateValue(document.getElementById("batch-kpi-phish"), 0, data.phishing_count);
    animateValue(document.getElementById("batch-kpi-susp"), 0, data.suspicious_count);
    animateValue(document.getElementById("batch-kpi-legit"), 0, data.legitimate_count);

    kpisEl.style.display = "grid";

    // Populate Results Table
    tbody.innerHTML = lastBatchResults.map((r, i) => `
      <tr>
        <td style="font-family: var(--font-mono); color: var(--color-cyan); font-weight: 700;">#${i + 1}</td>
        <td>
          <div class="table-url-cell">
            <span class="url-mono" title="${escapeHtml(r.url)}">${escapeHtml(r.url)}</span>
            <button type="button" class="btn-copy-small" onclick="copyToClipboard('${escapeHtml(r.url)}', 'URL')" title="Copy URL">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            </button>
          </div>
        </td>
        <td><span class="badge ${getVerdictBadgeClass(r.prediction)}">${r.prediction}</span></td>
        <td style="font-family: var(--font-mono); font-weight: 700; color: ${getRiskScoreColor(r.risk_score)};">${r.risk_score} / 100</td>
        <td style="font-family: var(--font-mono);">${r.confidence}%</td>
        <td style="font-family: var(--font-mono); font-weight: 700; color: ${getThreatLevelColor(r.threat_level)};">${r.threat_level}</td>
      </tr>
    `).join("");

    tableContainerEl.style.display = "block";
    exportBtn.style.display = "inline-flex";
    promptEl.textContent = `Completed scan of ${data.total_processed} URLs from ${file.name}`;
    showToast(`Batch completed: ${data.total_processed} URLs scanned`, "safe");
    loadOverviewTelemetry();
  } catch (err) {
    console.error("Batch processing error:", err);
    showToast("Connection error during batch upload.", "danger");
  } finally {
    progressEl.style.display = "none";
  }
}

function downloadSampleCSV() {
  const sampleContent = `url\nhttps://www.google.com\nhttps://github.com/torvalds/linux\nhttp://192.168.1.10:8080/paypal-update/login.php?session=928472\nhttps://accounts.google.com-support-team.online/signin\nhttps://bit.ly/secure-account-login\nhttps://www.wikipedia.org\nhttps://login.appleid-support-team.xyz/verify.php?token=auth99\nhttps://netflix-billing-update.top/account-login\n`;
  const blob = new Blob([sampleContent], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "sample_phishing_benchmark.csv";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast("Downloaded sample benchmark CSV", "info");
}

function exportBatchCSV() {
  if (!lastBatchResults || lastBatchResults.length === 0) {
    showToast("No batch results to export.", "warning");
    return;
  }
  let csv = "url,prediction,risk_score,confidence,threat_level\n";
  lastBatchResults.forEach(r => {
    csv += `"${r.url.replace(/"/g, '""')}",${r.prediction},${r.risk_score},${r.confidence},${r.threat_level}\n`;
  });
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "scanned_urls_report.csv";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast("Exported scan report as CSV", "safe");
}

// Scan History
function debounceHistorySearch() {
  clearTimeout(searchDebounceTimeout);
  searchDebounceTimeout = setTimeout(() => {
    loadScanHistory();
  }, 300);
}

async function loadScanHistory() {
  const searchInput = document.getElementById("history-search");
  const filterSelect = document.getElementById("history-filter");
  const tbody = document.getElementById("history-table-tbody");

  const search = searchInput ? searchInput.value.trim() : "";
  const predFilter = filterSelect ? filterSelect.value : "all";

  let endpoint = `/api/history?limit=100`;
  if (search) endpoint += `&search=${encodeURIComponent(search)}`;
  if (predFilter && predFilter !== "all") endpoint += `&prediction=${encodeURIComponent(predFilter)}`;

  try {
    const res = await fetch(endpoint);
    const data = await res.json();
    const records = data.history || [];

    if (records.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 32px;">No audit records found matching query.</td></tr>`;
      return;
    }

    tbody.innerHTML = records.map(r => `
      <tr>
        <td style="font-family: var(--font-mono); color: var(--color-cyan); font-weight: 700;">#${r.id}</td>
        <td>
          <div class="table-url-cell">
            <span class="url-mono" title="${escapeHtml(r.url)}">${escapeHtml(r.url)}</span>
            <button type="button" class="btn-copy-small" onclick="copyToClipboard('${escapeHtml(r.url)}', 'URL')" title="Copy URL">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            </button>
          </div>
        </td>
        <td><span class="badge ${getVerdictBadgeClass(r.prediction)}">${r.prediction}</span></td>
        <td style="font-family: var(--font-mono); font-weight: 700; color: ${getRiskScoreColor(r.risk_score)};">${r.risk_score} / 100</td>
        <td style="font-family: var(--font-mono);">${r.confidence}%</td>
        <td style="font-family: var(--font-mono); font-weight: 700; color: ${getThreatLevelColor(r.threat_level)};">${r.threat_level}</td>
        <td style="font-family: var(--font-mono); color: var(--color-legit);">${r.detection_time_ms ? r.detection_time_ms + ' ms' : '< 2 ms'}</td>
        <td style="font-size: 0.78rem; color: var(--text-muted); font-family: var(--font-mono);">${formatTimestamp(r.scan_time)}</td>
      </tr>
    `).join("");
  } catch (err) {
    console.error("Error loading history:", err);
  }
}

// Model Performance & Confusion Matrix
async function loadModelPerformance() {
  try {
    const res = await fetch("/api/model-info");
    if (!res.ok) return;
    const meta = await res.json();

    // Model Config Details
    document.getElementById("perf-model-name").textContent = meta.model;
    document.getElementById("perf-train-samples").textContent = meta.training_samples.toLocaleString();
    document.getElementById("perf-test-samples").textContent = meta.test_samples.toLocaleString();
    document.getElementById("perf-total-features").textContent = meta.total_features;

    // Academic Metrics
    document.getElementById("perf-acc").textContent = `${(meta.accuracy * 100).toFixed(2)}%`;
    document.getElementById("perf-prec").textContent = `${(meta.precision * 100).toFixed(2)}%`;
    document.getElementById("perf-rec").textContent = `${(meta.recall * 100).toFixed(2)}%`;
    document.getElementById("perf-f1").textContent = meta.f1_score.toFixed(4);
    document.getElementById("perf-auc").textContent = meta.roc_auc.toFixed(4);

    // Confusion Matrix
    if (meta.confusion_matrix) {
      const cm = meta.confusion_matrix;
      document.getElementById("cm-tn-val").textContent = cm.true_negatives;
      document.getElementById("cm-fp-val").textContent = cm.false_positives;
      document.getElementById("cm-fn-val").textContent = cm.false_negatives;
      document.getElementById("cm-tp-val").textContent = cm.true_positives;
    }

    // Top Features Bar Chart
    if (meta.top_features && meta.top_features.length > 0) {
      renderFeatureImportanceChart(meta.top_features);
    }

    // Baseline Comparison Table
    renderModelComparisonTable(meta);
  } catch (err) {
    console.error("Error loading model info:", err);
  }
}

function renderFeatureImportanceChart(features) {
  const ctx = document.getElementById("featureImportanceChart");
  if (!ctx) return;

  const top10 = features.slice(0, 10);
  const labels = top10.map(f => f.feature.replace("number_of_", "# ").replace("has_", "").replace("is_", ""));
  const values = top10.map(f => f.importance);

  if (featureImportanceChart) featureImportanceChart.destroy();
  featureImportanceChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [{
        label: "Gini Feature Importance",
        data: values,
        backgroundColor: "rgba(139, 61, 255, 0.72)",
        borderColor: "#8B3DFF",
        borderWidth: 1.5,
        borderRadius: 6
      }]
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 800, easing: "easeOutQuart" },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "rgba(9, 6, 23, 0.95)",
          titleFont: { family: "Inter", weight: 700 },
          bodyFont: { family: "JetBrains Mono" },
          borderColor: "rgba(139, 61, 255, 0.25)",
          borderWidth: 1,
          padding: 12
        }
      },
      scales: {
        x: {
          ticks: { color: "#817993", font: { family: "JetBrains Mono" } },
          grid: { color: "rgba(255, 255, 255, 0.05)" }
        },
        y: {
          ticks: { color: "#B8B1CC", font: { family: "JetBrains Mono", size: 11, weight: 600 } },
          grid: { display: false }
        }
      }
    }
  });
}

function renderModelComparisonTable(meta) {
  const tbody = document.getElementById("model-comparison-tbody");
  if (!tbody) return;

  const rf = meta;
  const lr = meta.baseline_comparison || {
    model: "LogisticRegression",
    accuracy: 0.9955,
    precision: 0.9955,
    recall: 0.9955,
    f1_score: 0.9955,
    roc_auc: 0.9990
  };

  tbody.innerHTML = `
    <tr>
      <td style="font-weight: 700; color: #ffffff;">${rf.model}</td>
      <td><span class="badge" style="background: rgba(53, 107, 255, 0.15); color: #4C7DFF; border-color: rgba(53, 107, 255, 0.30);">PRIMARY (DEPLOYED)</span></td>
      <td style="font-family: var(--font-mono); font-weight: 700; color: var(--color-legit);">${(rf.accuracy * 100).toFixed(2)}%</td>
      <td style="font-family: var(--font-mono);">${(rf.precision * 100).toFixed(2)}%</td>
      <td style="font-family: var(--font-mono);">${(rf.recall * 100).toFixed(2)}%</td>
      <td style="font-family: var(--font-mono); font-weight: 700;">${rf.f1_score.toFixed(4)}</td>
      <td style="font-family: var(--font-mono);">${rf.roc_auc.toFixed(4)}</td>
      <td><span class="badge badge-legit">OPTIMAL (NON-LINEAR)</span></td>
    </tr>
    <tr>
      <td style="font-weight: 700; color: var(--text-secondary);">${lr.model}</td>
      <td><span class="badge" style="background: rgba(129, 121, 147, 0.12); color: #817993; border-color: rgba(129, 121, 147, 0.25);">BASELINE (BENCHMARK)</span></td>
      <td style="font-family: var(--font-mono);">${(lr.accuracy * 100).toFixed(2)}%</td>
      <td style="font-family: var(--font-mono);">${(lr.precision * 100).toFixed(2)}%</td>
      <td style="font-family: var(--font-mono);">${(lr.recall * 100).toFixed(2)}%</td>
      <td style="font-family: var(--font-mono);">${lr.f1_score.toFixed(4)}</td>
      <td style="font-family: var(--font-mono);">${lr.roc_auc.toFixed(4)}</td>
      <td><span class="badge badge-suspicious">LINEAR BASELINE</span></td>
    </tr>
  `;
}

// Utilities
function getVerdictBadgeClass(verdict, isThreatVerdict = false) {
  const v = (verdict || "").toLowerCase();
  if (isThreatVerdict) {
    if (v.includes("phish")) return "threat-phishing";
    if (v.includes("susp")) return "threat-suspicious";
    return "threat-legitimate";
  }
  if (v.includes("phish")) return "badge-phish";
  if (v.includes("susp")) return "badge-suspicious";
  return "badge-legit";
}

function getRiskScoreColor(score) {
  if (score <= 30) return "var(--color-legit)";
  if (score <= 70) return "var(--color-suspicious)";
  return "var(--color-phish)";
}

function getThreatLevelColor(level) {
  const l = (level || "").toUpperCase();
  if (l === "HIGH") return "var(--color-phish)";
  if (l === "MEDIUM") return "var(--color-suspicious)";
  return "var(--color-legit)";
}

function formatTimestamp(isoStr) {
  if (!isoStr) return "--";
  try {
    const d = new Date(isoStr);
    return d.toLocaleString();
  } catch {
    return isoStr;
  }
}

function escapeHtml(text) {
  if (!text) return "";
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return String(text).replace(/[&<>"']/g, m => map[m]);
}

// ==========================================================================
// Authentication & Guest Mode Controller
// ==========================================================================

function initAuth() {
  const currentRole = sessionStorage.getItem("cyberguard_auth_role");
  applyAuthState(currentRole);

  // Close dropdown when clicking outside
  document.addEventListener("click", (e) => {
    const userContainer = document.getElementById("user-menu-container");
    const dropdown = document.getElementById("user-dropdown");
    const btn = document.getElementById("btn-user-menu");
    if (userContainer && dropdown && !userContainer.contains(e.target)) {
      dropdown.style.display = "none";
      if (btn) btn.setAttribute("aria-expanded", "false");
    }
  });
}

function applyAuthState(role) {
  const authPortal = document.getElementById("auth-portal");
  const appContainer = document.getElementById("app-container");
  const guestBadge = document.getElementById("guest-mode-badge");
  const guestBanner = document.getElementById("guest-session-banner");
  const sidebarExit = document.getElementById("sidebar-guest-exit");
  const userDisplayName = document.getElementById("user-display-name");
  const dropdownUserRole = document.getElementById("dropdown-user-role");
  const dropdownUserEmail = document.getElementById("dropdown-user-email");
  const dropdownBadgeDemo = document.getElementById("dropdown-badge-demo");
  const dropdownBadgeAccess = document.getElementById("dropdown-badge-access");
  const exitBtnLabel = document.getElementById("exit-btn-label");

  if (role === "guest") {
    document.documentElement.classList.remove("auth-logged-out");
    document.documentElement.classList.add("auth-logged-in");
    if (authPortal) authPortal.style.display = "none";
    if (appContainer) appContainer.style.display = "flex";

    if (guestBadge) guestBadge.style.display = "inline-flex";
    if (guestBanner) guestBanner.style.display = "flex";
    if (sidebarExit) sidebarExit.style.display = "block";

    if (userDisplayName) userDisplayName.textContent = "Guest Analyst";
    if (dropdownUserRole) dropdownUserRole.textContent = "Guest Mode";
    if (dropdownUserEmail) dropdownUserEmail.textContent = "guest.sandbox@cyberguard.soc";
    if (dropdownBadgeDemo) dropdownBadgeDemo.style.display = "inline-flex";
    if (dropdownBadgeAccess) dropdownBadgeAccess.textContent = "Read & Scan Only";
    if (exitBtnLabel) exitBtnLabel.textContent = "Exit Guest Mode";
  } else if (role === "operator") {
    document.documentElement.classList.remove("auth-logged-out");
    document.documentElement.classList.add("auth-logged-in");
    if (authPortal) authPortal.style.display = "none";
    if (appContainer) appContainer.style.display = "flex";

    if (guestBadge) guestBadge.style.display = "none";
    if (guestBanner) guestBanner.style.display = "none";
    if (sidebarExit) sidebarExit.style.display = "none";

    const savedUser = sessionStorage.getItem("cyberguard_auth_user") || "Security Operator";
    if (userDisplayName) userDisplayName.textContent = savedUser.split("@")[0];
    if (dropdownUserRole) dropdownUserRole.textContent = "SOC Operator";
    if (dropdownUserEmail) dropdownUserEmail.textContent = savedUser.includes("@") ? savedUser : "operator@cyberguard.soc";
    if (dropdownBadgeDemo) dropdownBadgeDemo.style.display = "none";
    if (dropdownBadgeAccess) dropdownBadgeAccess.textContent = "Tier-1 Analyst (Full)";
    if (exitBtnLabel) exitBtnLabel.textContent = "Sign Out";
  } else {
    document.documentElement.classList.remove("auth-logged-in");
    document.documentElement.classList.add("auth-logged-out");
    if (authPortal) authPortal.style.display = "flex";
    if (appContainer) appContainer.style.display = "none";
    if (guestBadge) guestBadge.style.display = "none";
    if (guestBanner) guestBanner.style.display = "none";
    if (sidebarExit) sidebarExit.style.display = "none";
  }
}

function loginAsGuest() {
  sessionStorage.setItem("cyberguard_auth_role", "guest");
  sessionStorage.setItem("cyberguard_auth_user", "Guest Analyst");
  applyAuthState("guest");
  navigateToTab("overview");
  showToast("Guest Session Active: Full URL inspection & ML metrics accessible.", "info");
}

function handleSignIn(e) {
  if (e) e.preventDefault();
  const emailInput = document.getElementById("login-email");
  const email = emailInput ? emailInput.value.trim() : "";
  const user = email || "analyst@cyberguard.soc";

  sessionStorage.setItem("cyberguard_auth_role", "operator");
  sessionStorage.setItem("cyberguard_auth_user", user);

  applyAuthState("operator");
  navigateToTab("overview");
  showToast(`Welcome back, ${user}. SOC console initialized.`, "safe");
}

function handleRegister(e) {
  if (e) e.preventDefault();
  const nameInput = document.getElementById("reg-name");
  const emailInput = document.getElementById("reg-email");
  const name = nameInput ? nameInput.value.trim() : "";
  const email = emailInput ? emailInput.value.trim() : "analyst@cyberguard.soc";

  sessionStorage.setItem("cyberguard_auth_role", "operator");
  sessionStorage.setItem("cyberguard_auth_user", name || email);

  applyAuthState("operator");
  navigateToTab("overview");
  showToast("Account created successfully. Welcome to CyberGuard SOC.", "safe");
}

function exitGuestMode() {
  const currentRole = sessionStorage.getItem("cyberguard_auth_role");
  sessionStorage.removeItem("cyberguard_auth_role");
  sessionStorage.removeItem("cyberguard_auth_user");

  const dropdown = document.getElementById("user-dropdown");
  const btn = document.getElementById("btn-user-menu");
  if (dropdown) dropdown.style.display = "none";
  if (btn) btn.setAttribute("aria-expanded", "false");

  applyAuthState(null);
  showToast(currentRole === "guest" ? "Exited Guest Mode. Session concluded." : "Signed out of CyberGuard Console.", "info");
}

function toggleAuthForm(mode, e) {
  if (e) e.preventDefault();
  const loginForm = document.getElementById("login-form");
  const registerForm = document.getElementById("register-form");
  const titleText = document.getElementById("auth-title-text");
  const descText = document.getElementById("auth-desc-text");

  if (mode === "register") {
    if (loginForm) loginForm.style.display = "none";
    if (registerForm) registerForm.style.display = "flex";
    if (titleText) titleText.textContent = "Create SOC Analyst Account";
    if (descText) descText.textContent = "Register credentials for secure threat evaluation";
  } else {
    if (loginForm) loginForm.style.display = "flex";
    if (registerForm) registerForm.style.display = "none";
    if (titleText) titleText.textContent = "Sign In to Operations Console";
    if (descText) descText.textContent = "Enter your credentials or access via guest evaluation sandbox";
  }
}

function togglePasswordVisibility() {
  const pwdInput = document.getElementById("login-password");
  if (!pwdInput) return;
  pwdInput.type = pwdInput.type === "password" ? "text" : "password";
}

function handleForgotPassword(e) {
  if (e) e.preventDefault();
  showToast("Demo Security Protocol: Use 'Continue as Guest' or sign in with your analyst credentials.", "warning");
}

function toggleUserDropdown(e) {
  if (e) e.stopPropagation();
  const dropdown = document.getElementById("user-dropdown");
  const btn = document.getElementById("btn-user-menu");
  if (!dropdown) return;
  const isHidden = dropdown.style.display === "none" || !dropdown.style.display;
  dropdown.style.display = isHidden ? "block" : "none";
  if (btn) btn.setAttribute("aria-expanded", isHidden ? "true" : "false");
}

