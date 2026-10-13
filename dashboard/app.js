/* Syntactica dashboard — vanilla JS, no dependencies.
 * Reimplements the tokenizer + n-gram scorer so a visitor can score domains
 * entirely client-side, and renders every figure as inline SVG. */
"use strict";

const CTX_SEP = "\u001f"; // must match ngram._CTX_SEP
const ALPHABET = new Set("abcdefghijklmnopqrstuvwxyz0123456789-_".split(""));
const QTYPE_NAMES = { 1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY" };

/* ---------- tokenizer (mirror of tokenizer.py) ---------- */
function lengthBucket(n) {
  if (n <= 0) return "LEN=0";
  if (n <= 2) return "LEN=s";
  if (n <= 6) return "LEN=m";
  if (n <= 15) return "LEN=l";
  if (n <= 31) return "LEN=xl";
  if (n <= 63) return "LEN=xxl";
  return "LEN=ILLEGAL";
}
function tokenizeQuery(qname, qtype) {
  const toks = ["<bos>", "QR=0", "OP=QUERY", "QT=" + (QTYPE_NAMES[qtype] || "TYPE" + qtype), "QC=1"];
  const labels = qname.replace(/\.+$/, "").split(".").filter((x) => x.length);
  for (const label of labels) {
    toks.push(lengthBucket(label.length));
    for (const ch of label.toLowerCase()) toks.push(ALPHABET.has(ch) ? ch : "<oovc>");
    toks.push("<sep>");
  }
  toks.push("<root>", "<eos>");
  return toks;
}

/* ---------- n-gram grammar (mirror of ngram.py) ---------- */
class NGram {
  constructor(d) {
    this.order = d.order;
    this.lambdas = d.lambdas;
    this.floor = d.floor;
    this.vocabSize = d.vocab_size;
    this.counts = d.counts.map((entries) => {
      const m = new Map();
      // Each context is already a CTX_SEP-joined string key (see ngram.to_json).
      for (const [ctxKey, table] of entries) m.set(ctxKey, table);
      return m;
    });
    this.totals = this.counts.map((m) => {
      const t = new Map();
      for (const [k, table] of m) t.set(k, Object.values(table).reduce((a, b) => a + b, 0));
      return t;
    });
  }
  orderProb(n, ctxKey, tok) {
    const table = this.counts[n - 1].get(ctxKey);
    if (!table) return 0;
    const total = this.totals[n - 1].get(ctxKey);
    return total ? (table[tok] || 0) / total : 0;
  }
  tokenLogprob(history, tok) {
    let prob = this.floor / this.vocabSize;
    let idx = 0;
    for (let n = this.order; n >= 1; n--, idx++) {
      const lam = this.lambdas[idx] || 0;
      if (lam === 0) continue;
      const ctxKey = n > 1 ? history.slice(history.length - (n - 1)).join(CTX_SEP) : "";
      prob += lam * this.orderProb(n, ctxKey, tok);
    }
    return Math.log(Math.max(prob, 1e-12));
  }
  perTokenSurprisal(tokens) {
    const pad = Array(this.order - 1).fill("<bos>").concat(tokens);
    const out = [];
    for (let i = this.order - 1; i < pad.length; i++) {
      out.push([pad[i], -this.tokenLogprob(pad.slice(0, i), pad[i])]);
    }
    return out;
  }
  sequenceNll(tokens) {
    const s = this.perTokenSurprisal(tokens);
    return s.reduce((a, [, v]) => a + v, 0) / Math.max(s.length, 1);
  }
}

/* ---------- small helpers ---------- */
const $ = (sel) => document.querySelector(sel);
const svgEl = (tag, attrs = {}) => {
  const e = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const k in attrs) e.setAttribute(k, attrs[k]);
  return e;
};
/* surprisal -> background color (panel -> amber -> warn) */
function heatColor(s, max) {
  const t = Math.max(0, Math.min(1, s / (max || 1)));
  if (t < 0.5) return `color-mix(in srgb, var(--panel-2) ${100 - t * 2 * 60}%, var(--amber) ${t * 2 * 60}%)`;
  const u = (t - 0.5) * 2;
  return `color-mix(in srgb, var(--amber) ${100 - u * 100}%, var(--warn) ${u * 100}%)`;
}

/* ================= state ================= */
let NG = null;
let RESULTS = null;

/* ================= live scorer ================= */
function renderScore() {
  const qname = $("#domainInput").value.trim() || "example.com";
  const qtype = parseInt($("#qtypeSelect").value, 10);
  const tokens = tokenizeQuery(qname, qtype);
  const perTok = NG.perTokenSurprisal(tokens);
  const score = perTok.reduce((a, [, v]) => a + v, 0) / perTok.length;
  const thr = RESULTS.models.ngram.threshold;
  const violation = score >= thr;

  const v = $("#verdict");
  v.className = "verdict " + (violation ? "bad" : "ok");
  const fillPct = Math.min(100, (score / (thr * 2)) * 100);
  v.innerHTML = `
    <div class="big">${violation ? "VIOLATION" : "CONFORMS"}</div>
    <div class="meter">
      <div class="meter-track"><div class="meter-fill" style="width:${fillPct}%"></div></div>
      <div class="meter-labels"><span>surprisal ${score.toFixed(3)} nats/token</span><span>threshold ${thr.toFixed(3)}</span></div>
    </div>`;

  const roles = { "QR=": "header", "OP=": "header", "QT=": "header", "QC=": "header", "LEN=": "length" };
  const roleOf = (t) => {
    if (t === "<sep>" || t === "<root>") return "delimiter";
    if (t === "<bos>" || t === "<eos>") return "frame";
    if (t === "<oovc>") return "illegal";
    for (const p in roles) if (t.startsWith(p)) return roles[p];
    return "payload";
  };
  const maxS = Math.max(...perTok.map(([, s]) => s), 3);
  const heat = $("#tokenHeat");
  heat.innerHTML = "";
  for (const [tok, s] of perTok) {
    const span = document.createElement("span");
    span.className = "tok";
    span.style.background = heatColor(s, maxS);
    span.style.borderColor = "var(--border)";
    const label = tok === "<sep>" ? "·" : tok;
    span.innerHTML = `${escapeHtml(label)}<small>${s.toFixed(1)}</small>`;
    span.title = `${tok} — ${roleOf(tok)} — surprisal ${s.toFixed(3)}`;
    heat.appendChild(span);
  }
}
function escapeHtml(s) { return s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])); }

const SAMPLES = [
  ["www.google.com", 1, "benign"],
  ["mail.protonmail.com", 15, "benign"],
  ["mfrggzdfmztwq2lkuhqg23tpobyxe43u.tunnel.example.com", 16, "tunnel"],
  ["kquevxzmbnrtplahsyw.com", 1, "dga"],
  ["qzxkvbwmxrtplahsdfghj.exfil.net", 16, "exfil"],
];
function renderSamples() {
  const box = $("#samples");
  box.innerHTML = "<span class='muted' style='align-self:center'>try:</span>";
  for (const [name, qt, tag] of SAMPLES) {
    const b = document.createElement("button");
    b.textContent = `${tag}: ${name.length > 34 ? name.slice(0, 32) + "…" : name}`;
    b.onclick = () => { $("#domainInput").value = name; $("#qtypeSelect").value = qt; renderScore(); };
    box.appendChild(b);
  }
}

/* ================= hero + stat cards ================= */
function renderHero() {
  const m = RESULTS.models.ngram, t = RESULTS.models.transformer;
  const ds = RESULTS.meta.dataset;
  const badges = [
    `<span class="chip good">n-gram ROC-AUC <b>${m.roc_auc}</b></span>`,
    t ? `<span class="chip good">Transformer ROC-AUC <b>${t.roc_auc}</b></span>` : "",
    `<span class="chip">false-positive rate <b>${(m.operating_point.false_positive_rate * 100).toFixed(1)}%</b></span>`,
    `<span class="chip">${ds.train_benign.toLocaleString()} benign flows &middot; <b>0</b> attack labels used</span>`,
  ];
  $("#heroBadges").innerHTML = badges.join("");
  $("#genAt").textContent = RESULTS.meta.generated_at;
  $("#genSec").textContent = RESULTS.meta.elapsed_sec;
}
function statCard(num, lbl, cls = "") {
  return `<div class="card stat"><span class="num ${cls}">${num}</span><span class="lbl">${lbl}</span></div>`;
}
function renderStats() {
  const m = RESULTS.models.ngram, t = RESULTS.models.transformer, op = m.operating_point;
  const cards = [
    statCard(m.roc_auc, "n-gram ROC-AUC", "accent"),
    t ? statCard(t.roc_auc, "Transformer ROC-AUC", "primary") : statCard("—", "Transformer"),
    statCard((op.recall * 100).toFixed(1) + "%", "attack recall"),
    statCard((op.false_positive_rate * 100).toFixed(1) + "%", "false-positive rate"),
  ];
  $("#statCards").innerHTML = cards.join("");
}

/* ================= ROC chart ================= */
function renderRoc() {
  const W = 500, H = 320, pad = 42;
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart", role: "img" });
  const x = (v) => pad + v * (W - pad - 14);
  const y = (v) => H - pad - v * (H - pad - 14);
  // grid + diagonal
  for (let g = 0; g <= 1.0001; g += 0.25) {
    svg.appendChild(svgEl("line", { x1: x(g), y1: y(0), x2: x(g), y2: y(1), class: "gridline" }));
    svg.appendChild(svgEl("line", { x1: x(0), y1: y(g), x2: x(1), y2: y(g), class: "gridline" }));
  }
  svg.appendChild(svgEl("line", { x1: x(0), y1: y(0), x2: x(1), y2: y(1), stroke: "var(--text-faint)", "stroke-dasharray": "4 4", "stroke-width": 1 }));
  svg.appendChild(svgEl("line", { x1: x(0), y1: y(0), x2: x(0), y2: y(1), class: "axis" }));
  svg.appendChild(svgEl("line", { x1: x(0), y1: y(0), x2: x(1), y2: y(0), class: "axis" }));

  const series = [["ngram", "var(--accent)"], ["transformer", "var(--primary)"]];
  for (const [name, color] of series) {
    const mdl = RESULTS.models[name];
    if (!mdl) continue;
    const { fpr, tpr } = mdl.roc_curve;
    let d = "";
    for (let i = 0; i < fpr.length; i++) d += (i ? "L" : "M") + x(fpr[i]) + "," + y(tpr[i]);
    svg.appendChild(svgEl("path", { d, fill: "none", stroke: color, "stroke-width": 2.4, "stroke-linejoin": "round" }));
  }
  // labels
  const tx = (t, xx, yy, anchor = "middle", cls = "axis-label") => {
    const e = svgEl("text", { x: xx, y: yy, "text-anchor": anchor, class: cls }); e.textContent = t; svg.appendChild(e);
  };
  tx("false-positive rate", x(0.5), H - 8);
  const yl = svgEl("text", { x: 12, y: y(0.5), "text-anchor": "middle", class: "axis-label", transform: `rotate(-90 12 ${y(0.5)})` }); yl.textContent = "true-positive rate"; svg.appendChild(yl);
  tx("0", x(0), H - pad + 16); tx("1", x(1), H - pad + 16);
  // legend
  let lx = pad + 6;
  for (const [name, color] of series) {
    if (!RESULTS.models[name]) continue;
    svg.appendChild(svgEl("rect", { x: lx, y: 14, width: 12, height: 12, rx: 3, fill: color }));
    tx(name === "ngram" ? "n-gram" : "Transformer", lx + 18, 24, "start"); lx += 118;
  }
  $("#rocChart").appendChild(svg);
}

/* ================= family bars ================= */
function renderFamilies() {
  const per = RESULTS.models.ngram.per_family;
  const order = ["tunnel", "dga", "malformed", "benign"];
  const box = $("#familyBars");
  box.innerHTML = "";
  for (const fam of order) {
    if (!per[fam]) continue;
    const rate = per[fam].detection_rate;
    const isBenign = fam === "benign";
    const pct = (rate * 100).toFixed(1) + "%";
    const color = isBenign ? "var(--text-faint)" : "linear-gradient(90deg,var(--accent),var(--primary))";
    const label = isBenign ? "false alarms" : "detected";
    box.insertAdjacentHTML("beforeend", `
      <div class="fam-row">
        <span class="fam-name">${fam}</span>
        <div class="fam-track"><div class="fam-fill" style="width:${rate * 100}%;background:${color}"></div></div>
        <span class="fam-val">${pct}</span>
      </div>
      <div class="muted" style="margin:-6px 0 8px 102px;font-size:11px">${label} &middot; n=${per[fam].n}</div>`);
  }
}

/* ================= histogram ================= */
function renderHist() {
  const h = RESULTS.models.ngram.score_hist;
  const bins = h.bins, counts = h.counts;
  const fams = ["benign", "tunnel", "dga", "malformed"].filter((f) => counts[f]);
  const colors = { benign: "var(--accent)", tunnel: "var(--warn)", dga: "var(--amber)", malformed: "var(--primary)" };
  const W = 900, H = 300, pad = 40;
  const nb = bins.length - 1;
  const maxC = Math.max(...fams.flatMap((f) => counts[f]));
  const x = (i) => pad + (i / nb) * (W - pad - 12);
  const y = (v) => H - pad - (v / maxC) * (H - pad - 20);
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart" });
  svg.appendChild(svgEl("line", { x1: pad, y1: y(0), x2: W - 12, y2: y(0), class: "axis" }));
  // draw each family as a semi-transparent area (log-ish readability via sqrt not needed; counts fine)
  for (const fam of fams) {
    let d = `M${x(0)},${y(0)}`;
    for (let i = 0; i < nb; i++) { d += `L${x(i)},${y(counts[fam][i])}L${x(i + 1)},${y(counts[fam][i])}`; }
    d += `L${x(nb)},${y(0)}Z`;
    svg.appendChild(svgEl("path", { d, fill: colors[fam], "fill-opacity": fam === "benign" ? 0.5 : 0.32, stroke: colors[fam], "stroke-width": 1.4 }));
  }
  // threshold line
  const thr = RESULTS.models.ngram.threshold;
  const ti = ((thr - bins[0]) / (bins[nb] - bins[0])) * nb;
  if (ti >= 0 && ti <= nb) {
    svg.appendChild(svgEl("line", { x1: x(ti), y1: 20, x2: x(ti), y2: y(0), stroke: "var(--text)", "stroke-dasharray": "5 4", "stroke-width": 1.5 }));
    const tl = svgEl("text", { x: x(ti) + 6, y: 28, class: "axis-label" }); tl.textContent = "threshold"; svg.appendChild(tl);
  }
  const xl = svgEl("text", { x: W / 2, y: H - 6, "text-anchor": "middle", class: "axis-label" }); xl.textContent = "surprisal (nats / token)  →"; svg.appendChild(xl);
  // legend
  let lx = pad + 4;
  for (const fam of fams) {
    svg.appendChild(svgEl("rect", { x: lx, y: 8, width: 11, height: 11, rx: 3, fill: colors[fam], "fill-opacity": 0.7 }));
    const t = svgEl("text", { x: lx + 16, y: 17, class: "axis-label" }); t.textContent = fam; svg.appendChild(t); lx += 92;
  }
  $("#histChart").appendChild(svg);
}

/* ================= automaton transition matrix ================= */
function renderAutomaton() {
  const a = RESULTS.automaton;
  const nodes = a.nodes;
  // build prob matrix
  const idx = Object.fromEntries(nodes.map((n, i) => [n, i]));
  const M = nodes.map(() => nodes.map(() => 0));
  for (const e of a.edges) if (e.from in idx && e.to in idx) M[idx[e.from]][idx[e.to]] = e.prob;

  const cell = 62, labelW = 78, top = 60, N = nodes.length;
  const W = labelW + N * cell + 20, H = top + N * cell + 20;
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart" });
  const short = (n) => n.replace("LEN=", "");
  // column headers
  nodes.forEach((n, j) => {
    const t = svgEl("text", { x: labelW + j * cell + cell / 2, y: top - 12, "text-anchor": "middle", class: "axis-label" });
    t.textContent = short(n); svg.appendChild(t);
  });
  const capTo = svgEl("text", { x: labelW + (N * cell) / 2, y: 20, "text-anchor": "middle", class: "axis-label" }); capTo.textContent = "to state →"; svg.appendChild(capTo);
  nodes.forEach((from, i) => {
    const t = svgEl("text", { x: labelW - 8, y: top + i * cell + cell / 2 + 4, "text-anchor": "end", class: "axis-label" });
    t.textContent = short(from); svg.appendChild(t);
    nodes.forEach((to, j) => {
      const p = M[i][j];
      const gx = labelW + j * cell, gy = top + i * cell;
      const bg = p > 0 ? `color-mix(in srgb, var(--panel-2) ${100 - p * 82}%, var(--primary) ${p * 82}%)` : "var(--panel-2)";
      svg.appendChild(svgEl("rect", { x: gx + 2, y: gy + 2, width: cell - 4, height: cell - 4, rx: 8, fill: bg, stroke: "var(--border)" }));
      if (p >= 0.01) {
        const tt = svgEl("text", { x: gx + cell / 2, y: gy + cell / 2 + 4, "text-anchor": "middle", class: "axis-label", fill: p > 0.5 ? "white" : "var(--text-dim)" });
        tt.textContent = p.toFixed(2); svg.appendChild(tt);
      }
    });
  });
  $("#automaton").appendChild(svg);

  // caption: dominant benign path from START
  const startEdges = a.edges.filter((e) => e.from === "START").sort((x, y) => y.prob - x.prob);
  const top2 = startEdges.slice(0, 2).map((e) => `${e.to.replace("LEN=", "")} (${(e.prob * 100).toFixed(0)}%)`).join(" and ");
  $("#automatonCaption").innerHTML =
    `Benign names almost always start with a medium/long label (${top2}) and never enter <code style="font-family:var(--mono)">xxl</code> or <code style="font-family:var(--mono)">ILLEGAL</code> — the states tunnelling and over-long-label attacks are forced into.`;
}

/* ================= fuzzing chart ================= */
function renderFuzz() {
  const data = RESULTS.fuzzing;
  const W = 900, H = 320, pad = 50;
  const Ts = data.map((d) => d.temperature);
  const tmin = Math.min(...Ts), tmax = Math.max(...Ts);
  const novMax = Math.max(...data.map((d) => d.mean_novelty)) * 1.1;
  const x = (t) => pad + ((t - tmin) / (tmax - tmin)) * (W - pad - pad);
  const yV = (v) => H - pad - v * (H - pad - 24); // validity 0..1 (left)
  const yN = (v) => H - pad - (v / novMax) * (H - pad - 24); // novelty (right)
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart" });
  for (let g = 0; g <= 1.0001; g += 0.25) svg.appendChild(svgEl("line", { x1: pad, y1: yV(g), x2: W - pad, y2: yV(g), class: "gridline" }));
  svg.appendChild(svgEl("line", { x1: pad, y1: yV(0), x2: W - pad, y2: yV(0), class: "axis" }));
  // validity line (accent)
  const line = (accessor, yfn, color, dash) => {
    let d = "";
    data.forEach((pt, i) => { d += (i ? "L" : "M") + x(pt.temperature) + "," + yfn(accessor(pt)); });
    svg.appendChild(svgEl("path", { d, fill: "none", stroke: color, "stroke-width": 2.6, "stroke-dasharray": dash || "none", "stroke-linejoin": "round" }));
    data.forEach((pt) => svg.appendChild(svgEl("circle", { cx: x(pt.temperature), cy: yfn(accessor(pt)), r: 4, fill: color })));
  };
  line((p) => p.validity_rate, yV, "var(--accent)");
  line((p) => p.mean_novelty, yN, "var(--primary)", "6 4");
  // axes labels
  const tx = (t, xx, yy, anchor = "middle", cls = "axis-label", rot) => { const e = svgEl("text", { x: xx, y: yy, "text-anchor": anchor, class: cls }); if (rot) e.setAttribute("transform", rot); e.textContent = t; svg.appendChild(e); };
  data.forEach((pt) => tx("T=" + pt.temperature, x(pt.temperature), H - pad + 18));
  tx("sampling temperature", W / 2, H - 10);
  tx("validity", 14, yV(0.5), "middle", "axis-label", `rotate(-90 14 ${yV(0.5)})`);
  tx("novelty", W - 12, yN(novMax / 2), "middle", "axis-label", `rotate(-90 ${W - 12} ${yN(novMax / 2)})`);
  $("#fuzzChart").appendChild(svg);
}

/* ================= worked examples ================= */
function renderExamples() {
  const box = $("#examplesList");
  box.innerHTML = "";
  const order = ["tunnel", "dga", "malformed", "benign"];
  const byFam = Object.fromEntries(RESULTS.examples.map((e) => [e.family, e]));
  for (const fam of order) {
    const ex = byFam[fam];
    if (!ex) continue;
    const maxS = Math.max(...ex.profile.map((c) => c.s), 3);
    const toks = ex.profile.map((c) => {
      const label = c.t === "<sep>" ? "·" : c.t;
      const isHot = ex.hotspot && c.t === ex.hotspot.token && Math.abs(c.s - ex.hotspot.surprisal) < 1e-6;
      const border = isHot ? "border-color:var(--warn);box-shadow:0 0 0 2px color-mix(in srgb,var(--warn) 40%,transparent)" : "border-color:var(--border)";
      return `<span class="tok" style="background:${heatColor(c.s, maxS)};${border}" title="${c.t} — surprisal ${c.s}">${escapeHtml(label)}<small>${c.s.toFixed(1)}</small></span>`;
    }).join("");
    const hs = ex.hotspot;
    box.insertAdjacentHTML("beforeend", `
      <div class="ex">
        <div class="head">
          <span class="tag ${fam}">${fam}</span>
          <span class="qname">${escapeHtml(ex.qname.length > 70 ? ex.qname.slice(0, 68) + "…" : ex.qname)}</span>
          <span class="muted" style="margin-left:auto">score ${ex.score} &middot; ${ex.is_violation ? "flagged" : "conforming"}</span>
        </div>
        <div class="tokens">${toks}</div>
        ${hs ? `<p class="muted" style="margin:10px 0 0">smoking gun: <code style="font-family:var(--mono);color:var(--warn)">${escapeHtml(hs.token)}</code> (${hs.role}, surprisal ${hs.surprisal})</p>` : ""}
      </div>`);
  }
}

/* ================= theme ================= */
function initTheme() {
  const saved = (() => { try { return localStorage.getItem("syntactica-theme"); } catch (e) { return null; } })();
  if (saved) document.documentElement.setAttribute("data-theme", saved);
  $("#themeToggle").onclick = () => {
    const cur = document.documentElement.getAttribute("data-theme");
    const isDark = cur ? cur === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    const next = isDark ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("syntactica-theme", next); } catch (e) {}
  };
}

/* ================= conformal table ================= */
function renderConformal() {
  const c = RESULTS.conformal;
  if (!c) return;
  const rows = c.points.map((p) => `
    <tr>
      <td>&le; ${(p.alpha * 100).toFixed(1)}%</td>
      <td>${p.threshold.toFixed(3)}</td>
      <td>${(p.empirical_fpr * 100).toFixed(2)}%</td>
      <td>${(p.attack_recall * 100).toFixed(1)}%</td>
    </tr>`).join("");
  $("#conformalTable").innerHTML =
    `<thead><tr><th>target &alpha; (guarantee)</th><th>threshold</th><th>empirical FPR</th><th>attack recall</th></tr></thead>
     <tbody>${rows}</tbody>`;
}

/* ================= learned-representation scatter ================= */
function renderEmbedding() {
  const e = RESULTS.embedding;
  if (!e || !e.points || !e.points.length) return;
  const colors = { benign: "var(--accent)", tunnel: "var(--warn)", dga: "var(--amber)", malformed: "var(--primary)" };
  const W = 760, H = 440, pad = 24;
  const clamp = (v) => Math.max(-3.2, Math.min(3.2, v));
  const xs = e.points.map((p) => clamp(p.x)), ys = e.points.map((p) => clamp(p.y));
  const xmin = Math.min(...xs), xmax = Math.max(...xs), ymin = Math.min(...ys), ymax = Math.max(...ys);
  const x = (v) => pad + ((clamp(v) - xmin) / (xmax - xmin || 1)) * (W - 2 * pad);
  const y = (v) => H - pad - ((clamp(v) - ymin) / (ymax - ymin || 1)) * (H - 2 * pad);
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart" });
  // benign first (under), then attacks on top
  const order = ["benign", "malformed", "dga", "tunnel"];
  const pts = [...e.points].sort((a, b) => order.indexOf(a.f) - order.indexOf(b.f));
  for (const p of pts) {
    svg.appendChild(svgEl("circle", {
      cx: x(p.x), cy: y(p.y), r: p.f === "benign" ? 2.6 : 3.2,
      fill: colors[p.f] || "var(--text-faint)", "fill-opacity": p.f === "benign" ? 0.5 : 0.8,
    }));
  }
  $("#embedChart").appendChild(svg);
  const ev = e.explained_variance || [];
  $("#embedLegend").innerHTML =
    order.map((f) => `<span style="color:${colors[f]}">&#9679;</span><span>${f}</span>`).join("  ") +
    (ev.length ? `<span style="margin-left:auto;color:var(--text-faint)">PC1 ${(ev[0] * 100).toFixed(0)}% &middot; PC2 ${(ev[1] * 100).toFixed(0)}% variance</span>` : "");
}

/* ================= closed-loop mitigation ================= */
function renderMitigation() {
  const mit = RESULTS.mitigation;
  if (!mit) return;
  const labels = { none: "no mitigation", global: "global rate cap", adaptive: "adaptive (ours)" };
  const box = $("#mitigationCards");
  box.innerHTML = "";
  for (const key of ["none", "global", "adaptive"]) {
    const p = mit.policies[key];
    if (!p) continue;
    const best = key === "adaptive" ? " best" : "";
    box.insertAdjacentHTML("beforeend", `
      <div class="card policy-card${best}">
        <div class="pname">${labels[key]}</div>
        <div class="policy-metric"><span class="k">legit goodput</span><span class="v" style="color:var(--accent)">${(p.legit_goodput * 100).toFixed(0)}%</span></div>
        <div class="policy-metric"><span class="k">attack blocked</span><span class="v" style="color:var(--warn)">${(p.attack_blocked * 100).toFixed(0)}%</span></div>
      </div>`);
  }
  // time-series stacked columns
  const ts = mit.timeseries;
  const bins = ts.legit_ok.length;
  const W = 900, H = 300, pad = 40;
  const maxTotal = Math.max(...Array.from({ length: bins }, (_, i) =>
    ts.legit_ok[i] + ts.legit_drop[i] + ts.attack_ok[i] + ts.attack_drop[i])) || 1;
  const bw = (W - pad - 12) / bins;
  const yv = (v) => H - pad - (v / maxTotal) * (H - pad - 20);
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart" });
  svg.appendChild(svgEl("line", { x1: pad, y1: yv(0), x2: W - 12, y2: yv(0), class: "axis" }));
  const seg = [
    ["legit_ok", "var(--accent)", 0.85],
    ["attack_drop", "var(--warn)", 0.30],
    ["attack_ok", "var(--warn)", 0.95],
    ["legit_drop", "var(--text-faint)", 0.6],
  ];
  for (let i = 0; i < bins; i++) {
    let base = 0;
    for (const [k, color, op] of seg) {
      const v = ts[k][i];
      if (!v) continue;
      const h = (v / maxTotal) * (H - pad - 20);
      svg.appendChild(svgEl("rect", {
        x: pad + i * bw + 1, y: yv(base) - h, width: Math.max(1, bw - 1.5), height: h,
        fill: color, "fill-opacity": op,
      }));
      base += v;
    }
  }
  const xl = svgEl("text", { x: W / 2, y: H - 8, "text-anchor": "middle", class: "axis-label" });
  xl.textContent = `time (${(ts.bin_width_sec * bins).toFixed(0)}s window)  →`;
  svg.appendChild(xl);
  $("#mitigationChart").appendChild(svg);
  $("#mitigationLegend").innerHTML =
    `<span style="color:var(--accent)">&#9632;</span><span>legit admitted</span>
     <span style="color:var(--warn);opacity:.4;margin-left:10px">&#9632;</span><span>attack throttled</span>
     <span style="color:var(--warn);margin-left:10px">&#9632;</span><span>attack leaked</span>`;
}

/* ================= online self-learning ================= */
function renderOnline() {
  const on = RESULTS.online;
  if (!on) return;
  const box = $("#onlineCards");
  box.innerHTML = `
    <div class="card policy-card">
      <div class="pname">static model (frozen)</div>
      <div class="policy-metric"><span class="k">false alarms after drift</span><span class="v" style="color:var(--warn)">${(on.static.drift_false_alarm * 100).toFixed(0)}%</span></div>
      <div class="policy-metric"><span class="k">attack recall</span><span class="v" style="color:var(--accent)">${(on.static.attack_recall * 100).toFixed(0)}%</span></div>
    </div>
    <div class="card policy-card best">
      <div class="pname">self-learning (online)</div>
      <div class="policy-metric"><span class="k">false alarms after drift</span><span class="v" style="color:var(--accent)">${(on.online.drift_false_alarm * 100).toFixed(1)}%</span></div>
      <div class="policy-metric"><span class="k">attack recall</span><span class="v" style="color:var(--accent)">${(on.online.attack_recall * 100).toFixed(0)}%</span></div>
    </div>
    <div class="card policy-card">
      <div class="pname">online, by family</div>
      <div class="policy-metric"><span class="k">tunnelling</span><span class="v" style="color:var(--warn)">${(on.online.tunnel_recall * 100).toFixed(0)}%</span></div>
      <div class="policy-metric"><span class="k">DGA</span><span class="v" style="color:var(--warn)">${(on.online.dga_recall * 100).toFixed(0)}%</span></div>
    </div>`;

  const ts = on.timeseries;
  const n = ts.static_fa.length;
  const W = 900, H = 300, pad = 44;
  const x = (i) => pad + (i / (n - 1)) * (W - pad - 14);
  const y = (v) => H - pad - v * (H - pad - 22);
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart" });
  for (let g = 0; g <= 1.0001; g += 0.25) {
    svg.appendChild(svgEl("line", { x1: pad, y1: y(g), x2: W - 14, y2: y(g), class: "gridline" }));
    const t = svgEl("text", { x: pad - 8, y: y(g) + 4, "text-anchor": "end", class: "axis-label" });
    t.textContent = (g * 100).toFixed(0) + "%"; svg.appendChild(t);
  }
  svg.appendChild(svgEl("line", { x1: pad, y1: y(0), x2: W - 14, y2: y(0), class: "axis" }));
  // drift marker
  const db = on.scenario.drift_bin;
  svg.appendChild(svgEl("line", { x1: x(db), y1: 16, x2: x(db), y2: y(0), stroke: "var(--text)", "stroke-dasharray": "5 4", "stroke-width": 1.5 }));
  const dl = svgEl("text", { x: x(db) + 6, y: 26, class: "axis-label" }); dl.textContent = "benign traffic shifts"; svg.appendChild(dl);
  const line = (arr, color, dash) => {
    let d = "";
    arr.forEach((v, i) => { d += (i ? "L" : "M") + x(i) + "," + y(v); });
    svg.appendChild(svgEl("path", { d, fill: "none", stroke: color, "stroke-width": 2.6, "stroke-dasharray": dash || "none", "stroke-linejoin": "round" }));
  };
  line(ts.static_fa, "var(--warn)");
  line(ts.online_fa, "var(--accent)");
  const xl = svgEl("text", { x: W / 2, y: H - 8, "text-anchor": "middle", class: "axis-label" });
  xl.textContent = "time (query stream)  →"; svg.appendChild(xl);
  $("#onlineChart").appendChild(svg);
  $("#onlineLegend").innerHTML =
    `<span style="color:var(--warn)">&#9632;</span><span>static model false alarms</span>
     <span style="color:var(--accent);margin-left:12px">&#9632;</span><span>self-learning false alarms</span>`;
}

/* ================= boot ================= */
async function boot() {
  initTheme();
  try {
    const [g, r] = await Promise.all([
      fetch("data/grammar.json").then((x) => x.json()),
      fetch("data/results.json").then((x) => x.json()),
    ]);
    NG = new NGram(g);
    RESULTS = r;
  } catch (e) {
    document.querySelector("main").insertAdjacentHTML("afterbegin",
      `<div class="loading">Could not load model artefacts. Serve this folder over HTTP (e.g. <code>python -m http.server</code>) rather than opening the file directly.</div>`);
    return;
  }
  renderHero();
  renderSamples();
  renderStats();
  renderRoc();
  renderFamilies();
  renderHist();
  renderConformal();
  renderEmbedding();
  renderAutomaton();
  renderMitigation();
  renderOnline();
  renderFuzz();
  renderExamples();
  $("#scoreBtn").onclick = renderScore;
  $("#domainInput").addEventListener("keydown", (e) => { if (e.key === "Enter") renderScore(); });
  $("#domainInput").addEventListener("input", renderScore);
  $("#qtypeSelect").addEventListener("change", renderScore);
  renderScore();
}
document.addEventListener("DOMContentLoaded", boot);
