/**
 * script.js — Email Traffic Analyzer Frontend
 * Handles: file upload, API calls, rendering, filtering, charts, export
 */

// ─── State ────────────────────────────────────────────────────────────────────
const API_BASE = "http://127.0.0.1:5000";

let analysisData   = null;   // full JSON from backend
let filteredPackets= [];     // currently displayed rows
let currentFilter  = "all";
let currentSearch  = "";
let protoChart     = null;   // Chart.js instance
let selectedRow    = null;   // highlighted table row

// ─── DOM Refs ─────────────────────────────────────────────────────────────────
const dropZone     = document.getElementById("drop-zone");
const fileInput    = document.getElementById("file-input");
const fileInfoRow  = document.getElementById("file-info-row");
const demoRow      = document.getElementById("demo-row");
const progressWrap = document.getElementById("progress-wrap");
const progressFill = document.getElementById("progress-fill");
const progressPct  = document.getElementById("progress-pct");
const progressLabel= document.getElementById("progress-label-text");
const resultsSection = document.getElementById("results-section");

// ─── Drag & Drop ──────────────────────────────────────────────────────────────
["dragenter","dragover"].forEach(e => dropZone.addEventListener(e, ev => {
  ev.preventDefault(); dropZone.classList.add("drag-over");
}));

["dragleave","dragend","drop"].forEach(e => dropZone.addEventListener(e, ev => {
  ev.preventDefault(); dropZone.classList.remove("drag-over");
}));

dropZone.addEventListener("drop", ev => {
  const file = ev.dataTransfer.files[0];
  if (file) handleFileSelected(file);
});

fileInput.addEventListener("change", () => {
  if (fileInput.files[0]) handleFileSelected(fileInput.files[0]);
});

function handleFileSelected(file) {
  const allowed = ["pcap","pcapng","cap"];
  const ext = file.name.split(".").pop().toLowerCase();
  if (!allowed.includes(ext)) {
    showToast("❌ Invalid file type. Use .pcap, .pcapng, or .cap", "error");
    return;
  }
  document.getElementById("selected-file-name").textContent = `📄 ${file.name}  (${(file.size/1024).toFixed(1)} KB)`;
  fileInfoRow.classList.remove("hidden");
  demoRow.classList.add("hidden");

  // Store for later
  fileInfoRow._pendingFile = file;
}

// ─── Analysis ─────────────────────────────────────────────────────────────────
async function startAnalysis() {
  const file = fileInfoRow._pendingFile;
  if (!file) { showToast("No file selected", "error"); return; }

  setStatus("Uploading…");
  showProgress("Uploading…", 10);

  const formData = new FormData();
  formData.append("pcap", file);

  try {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${API_BASE}/upload`);

    xhr.upload.onprogress = e => {
      if (e.lengthComputable) {
        const pct = Math.round((e.loaded / e.total) * 60);
        showProgress("Uploading…", pct);
      }
    };

    xhr.onload = () => {
      if (xhr.status === 200) {
        showProgress("Analyzing packets…", 80);
        setTimeout(() => {
          const data = JSON.parse(xhr.responseText);
          if (data.error) {
            showToast("❌ " + data.error, "error");
            hideProgress();
            setStatus("Error");
            return;
          }
          showProgress("Rendering results…", 95);
          setTimeout(() => {
            renderResults(data);
            hideProgress();
            setStatus("Analysis complete");
            showToast("✅ Analysis complete — " + data.total_packets + " email packets found", "ok");
          }, 300);
        }, 400);
      } else {
        let msg = "Upload failed";
        try { msg = JSON.parse(xhr.responseText).error || msg; } catch(_) {}
        showToast("❌ " + msg, "error");
        hideProgress();
        setStatus("Error");
      }
    };

    xhr.onerror = () => {
      showToast("❌ Cannot reach backend. Is Flask running on port 5000?", "error");
      hideProgress();
      setStatus("Offline");
    };

    xhr.send(formData);
  } catch (err) {
    showToast("❌ " + err.message, "error");
    hideProgress();
    setStatus("Error");
  }
}

// Load demo data from backend without file upload
async function loadDemo() {
  setStatus("Loading demo…");
  showProgress("Fetching demo data…", 30);
  try {
    const resp = await fetch(`${API_BASE}/demo`);
    if (!resp.ok) throw new Error("Demo endpoint failed");
    const data = await resp.json();
    showProgress("Rendering…", 80);
    setTimeout(() => {
      renderResults(data);
      hideProgress();
      setStatus("Demo loaded");
      showToast("▶ Demo loaded — explore the interface!", "ok");
    }, 300);
  } catch (err) {
    showToast("❌ Cannot reach backend. Is Flask running on port 5000?", "error");
    hideProgress();
    setStatus("Offline");
  }
}

function clearAll() {
  analysisData = null;
  filteredPackets = [];
  resultsSection.classList.add("hidden");
  fileInfoRow.classList.add("hidden");
  demoRow.classList.remove("hidden");
  fileInput.value = "";
  fileInfoRow._pendingFile = null;
  if (protoChart) { protoChart.destroy(); protoChart = null; }
  setStatus("Ready");
}

// ─── Render Results ───────────────────────────────────────────────────────────
function renderResults(data) {
  analysisData = data;

  // Show results section
  resultsSection.classList.remove("hidden");

  // Stats bar
  document.getElementById("stat-total").textContent   = data.total_packets || 0;
  document.getElementById("stat-smtp").textContent    = data.stats?.SMTP  || 0;
  document.getElementById("stat-pop3").textContent    = data.stats?.POP3  || 0;
  document.getElementById("stat-imap").textContent    = data.stats?.IMAP  || 0;

  const warningCount = (data.security || []).length + (data.anomalies || []).length;
  document.getElementById("stat-warnings").textContent = warningCount;

  // Table
  filteredPackets = data.packets || [];
  renderTable(filteredPackets);

  // Chart
  renderChart(data.stats || {});

  // Security
  renderSecurity(data.security || [], data.anomalies || []);

  // Emails
  renderEmails(data.emails || []);

  // Streams
  renderStreamSelector(data.streams || {});

  // Scroll into view
  resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ─── Table ────────────────────────────────────────────────────────────────────
function renderTable(packets) {
  const tbody = document.getElementById("packet-tbody");
  const empty = document.getElementById("empty-state");

  tbody.innerHTML = "";

  if (!packets.length) {
    empty.classList.remove("hidden");
    return;
  }
  empty.classList.add("hidden");

  packets.forEach((pkt, i) => {
    const tr = document.createElement("tr");
    if (pkt.suspicious) tr.classList.add("suspicious");

    tr.innerHTML = `
      <td class="text-dim">${pkt.id}</td>
      <td class="text-dim" style="font-size:10.5px;">${pkt.timestamp}</td>
      <td class="mono">${pkt.src_ip}</td>
      <td class="mono">${pkt.dst_ip}</td>
      <td><span class="badge badge-${pkt.protocol.toLowerCase()}">${pkt.protocol}</span></td>
      <td style="color:var(--text-bright); font-weight:500;">${pkt.command}</td>
      <td>${pkt.suspicious
            ? '<span class="badge badge-warn">⚠ ALERT</span>'
            : '<span class="badge badge-safe">✓ OK</span>'}</td>
      <td class="td-payload text-dim">${escHtml(pkt.payload)}</td>
    `;

    tr.addEventListener("click", () => openDrawer(pkt, tr));
    tbody.appendChild(tr);
  });
}

// ─── Filter & Search ──────────────────────────────────────────────────────────
function filterPackets(filter, btn) {
  currentFilter = filter;

  // Update active button
  document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
  btn.classList.add("active");

  applyFilters();
}

function searchPackets(q) {
  currentSearch = q.toLowerCase();
  applyFilters();
}

function applyFilters() {
  if (!analysisData) return;

  let packets = analysisData.packets || [];

  if (currentFilter === "suspicious") {
    packets = packets.filter(p => p.suspicious);
  } else if (currentFilter !== "all") {
    packets = packets.filter(p => p.protocol === currentFilter);
  }

  if (currentSearch) {
    packets = packets.filter(p =>
      p.src_ip.includes(currentSearch) ||
      p.dst_ip.includes(currentSearch) ||
      p.command.toLowerCase().includes(currentSearch) ||
      p.protocol.toLowerCase().includes(currentSearch) ||
      p.payload.toLowerCase().includes(currentSearch)
    );
  }

  filteredPackets = packets;
  renderTable(packets);
}

// ─── Chart ────────────────────────────────────────────────────────────────────
function renderChart(stats) {
  const ctx = document.getElementById("proto-chart").getContext("2d");

  const labels = Object.keys(stats);
  const values = Object.values(stats);
  const colors = { SMTP: "#3dd68c", POP3: "#f7b731", IMAP: "#a78bfa" };
  const bgColors = labels.map(l => colors[l] || "#00b4d8");

  if (protoChart) protoChart.destroy();

  protoChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels,
      datasets: [{
        data: values,
        backgroundColor: bgColors.map(c => c + "cc"),
        borderColor:     bgColors,
        borderWidth: 2,
        hoverOffset: 8,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "#0f1117",
          borderColor: "#2a3a50",
          borderWidth: 1,
          titleColor: "#eaf2ff",
          bodyColor: "#c8d8e8",
          callbacks: {
            label: ctx => ` ${ctx.label}: ${ctx.parsed} packets`
          }
        }
      },
      cutout: "65%",
    }
  });

  // Legend
  const legend = document.getElementById("chart-legend");
  legend.innerHTML = labels.map((l, i) => `
    <div class="legend-item">
      <div class="legend-dot" style="background:${bgColors[i]}"></div>
      <span class="legend-label">${l}</span>
      <span class="legend-count">${values[i]}</span>
    </div>
  `).join("");
}

// ─── Security Insights ────────────────────────────────────────────────────────
function renderSecurity(issues, anomalies) {
  const list = document.getElementById("security-list");
  list.innerHTML = "";

  if (!issues.length && !anomalies.length) {
    list.innerHTML = `
      <div class="security-item ok">
        <span class="si-icon">✅</span>
        <span>No security issues detected.</span>
      </div>`;
    return;
  }

  issues.forEach(issue => {
    const div = document.createElement("div");
    div.className = "security-item danger";
    div.innerHTML = `<span class="si-icon">🚨</span><span>${escHtml(issue)}</span>`;
    list.appendChild(div);
  });

  anomalies.forEach(anomaly => {
    const div = document.createElement("div");
    div.className = "security-item anomaly";
    div.innerHTML = `<span class="si-icon">⚠️</span><span>${escHtml(anomaly)}</span>`;
    list.appendChild(div);
  });
}

// ─── Email Chips ──────────────────────────────────────────────────────────────
function renderEmails(emails) {
  const chips = document.getElementById("email-chips");
  chips.innerHTML = !emails.length
    ? '<span class="text-dim" style="font-size:11px;">None found.</span>'
    : emails.map(e => `<span class="email-chip">✉ ${escHtml(e)}</span>`).join("");
}

// ─── TCP Stream Viewer ────────────────────────────────────────────────────────
function renderStreamSelector(streams) {
  const sel = document.getElementById("stream-select");
  sel.innerHTML = `<option value="">— Select a stream (${Object.keys(streams).length} found) —</option>`;

  Object.keys(streams).forEach(key => {
    const opt = document.createElement("option");
    opt.value = key;
    opt.textContent = key;
    sel.appendChild(opt);
  });
}

function renderStream() {
  const sel    = document.getElementById("stream-select");
  const term   = document.getElementById("stream-terminal");
  const streams= analysisData?.streams || {};
  const key    = sel.value;

  if (!key || !streams[key]) {
    term.innerHTML = `<span class="text-dim">Select a stream above to view reconstructed communication.</span>`;
    return;
  }

  const entries = streams[key];
  term.innerHTML = entries.map(entry => {
    const cls   = entry.direction === "client→server" ? "client" : "server";
    const arrow = entry.direction === "client→server" ? "→" : "←";
    const dir   = entry.direction;
    return `<div class="stream-line ${cls}">[${dir}] ${arrow} ${escHtml(entry.payload)}</div>`;
  }).join("");
}

// ─── Packet Detail Drawer ─────────────────────────────────────────────────────
function openDrawer(pkt, row) {
  if (selectedRow) selectedRow.classList.remove("selected");
  selectedRow = row;
  row.classList.add("selected");

  const body = document.getElementById("drawer-body");

  const rows = [
    ["Packet #",    pkt.id],
    ["Timestamp",   pkt.timestamp],
    ["Source",      `${pkt.src_ip}:${pkt.src_port}`],
    ["Destination", `${pkt.dst_ip}:${pkt.dst_port}`],
    ["Protocol",    `<span class="badge badge-${pkt.protocol.toLowerCase()}">${pkt.protocol}</span>`],
    ["Command",     `<strong>${pkt.command}</strong>`],
    ["Length",      `${pkt.length} bytes`],
    ["Encrypted",   pkt.encrypted ? '<span class="text-ok">✓ Yes (TLS)</span>' : '<span class="text-danger">✗ No (Plaintext)</span>'],
    ["Status",      pkt.suspicious ? '<span class="badge badge-warn">⚠ Suspicious</span>' : '<span class="badge badge-safe">✓ Clean</span>'],
    ["Emails",      pkt.emails.length ? pkt.emails.join(", ") : "—"],
  ];

  body.innerHTML = rows.map(([k,v]) => `
    <div class="detail-row">
      <div class="detail-key">${k}</div>
      <div class="detail-val">${v}</div>
    </div>
  `).join("");

  if (pkt.warnings.length) {
    body.innerHTML += `
      <div class="detail-row" style="grid-template-columns:1fr;">
        <div class="detail-key">Warnings</div>
        ${pkt.warnings.map(w => `<div class="security-item danger mt-12"><span class="si-icon">🚨</span><span>${escHtml(w)}</span></div>`).join("")}
      </div>`;
  }

  body.innerHTML += `
    <div style="margin-top:16px;">
      <div class="detail-key">Raw Payload</div>
      <div class="detail-payload">${escHtml(pkt.payload)}</div>
    </div>`;

  document.getElementById("detail-drawer").classList.add("open");
}

function closeDrawer() {
  document.getElementById("detail-drawer").classList.remove("open");
  if (selectedRow) { selectedRow.classList.remove("selected"); selectedRow = null; }
}

// Close drawer on Escape
document.addEventListener("keydown", e => { if (e.key === "Escape") closeDrawer(); });

// ─── Export ───────────────────────────────────────────────────────────────────
function exportJSON() {
  if (!analysisData) return;
  const blob = new Blob([JSON.stringify(analysisData, null, 2)], { type: "application/json" });
  downloadBlob(blob, "email_analysis.json");
  showToast("✅ JSON exported", "ok");
}

function exportCSV() {
  if (!analysisData?.packets?.length) return;

  const headers = ["id","timestamp","src_ip","dst_ip","src_port","dst_port","protocol","command","encrypted","suspicious","emails","warnings","length"];
  const rows = analysisData.packets.map(p => headers.map(h => {
    const v = p[h];
    if (Array.isArray(v)) return `"${v.join("; ")}"`;
    if (typeof v === "string" && v.includes(",")) return `"${v}"`;
    return v;
  }).join(","));

  const csv  = [headers.join(","), ...rows].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  downloadBlob(blob, "email_analysis.csv");
  showToast("✅ CSV exported", "ok");
}

function downloadBlob(blob, name) {
  const a   = document.createElement("a");
  a.href    = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ─── UI Helpers ───────────────────────────────────────────────────────────────
function showProgress(label, pct) {
  progressWrap.style.display = "block";
  progressLabel.textContent  = label;
  progressPct.textContent    = pct + "%";
  progressFill.style.width   = pct + "%";
}

function hideProgress() {
  setTimeout(() => {
    showProgress("Done", 100);
    setTimeout(() => { progressWrap.style.display = "none"; }, 600);
  }, 200);
}

function setStatus(msg) {
  document.getElementById("header-status-text").textContent = msg;
}

function showToast(msg, type = "ok") {
  const wrap  = document.getElementById("toast-wrap");
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.textContent = msg;
  wrap.appendChild(toast);
  setTimeout(() => { toast.style.opacity = "0"; toast.style.transition = "opacity 0.4s"; }, 3500);
  setTimeout(() => toast.remove(), 4000);
}

function escHtml(str) {
  if (typeof str !== "string") return String(str ?? "");
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}