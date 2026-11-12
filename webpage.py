"""The browser client: one self-contained HTML page (no external files, works fully offline).

It is kept inside a Python string so the PyInstaller .exe needs no data files. The page speaks the
same JSON protocol as the desktop client, carried in WebSocket text frames (see web.py), including the
reliability rules: sequence numbers with gap resync, msg_id + ACK, a retransmit timer,
heartbeat PING/PONG with latency, and automatic reconnect (also to a standby server).
"""

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>LAN Whiteboard</title>
<style>
:root{--bg:#f3f4f6;--fg:#111827;--mut:#6b7280;--card:#fff;--line:#d1d5db;--acc:#2563eb;--bad:#c62828;--ok:#2e7d32}
@media(prefers-color-scheme:dark){:root{--bg:#111827;--fg:#f3f4f6;--mut:#9ca3af;--card:#1f2937;--line:#374151;--acc:#60a5fa}}
*{box-sizing:border-box}html,body{margin:0;height:100%}
body{background:var(--bg);color:var(--fg);font:15px system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;overflow-x:hidden}
#join{max-width:380px;margin:0 auto;padding:24px 16px}
#join h1{font-size:22px;margin:8px 0 4px}#join p{color:var(--mut);margin:0 0 16px}
label{display:block;font-size:13px;color:var(--mut);margin:12px 0 4px}
input[type=text],input[type=password]{width:100%;padding:11px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg);font-size:16px}
button{font:inherit;border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:8px;padding:8px 11px;cursor:pointer;white-space:nowrap}
button.primary{background:var(--acc);border-color:var(--acc);color:#fff;width:100%;padding:12px;margin-top:18px;font-weight:600}
button.on{background:var(--acc);border-color:var(--acc);color:#fff}
#err{color:var(--bad);min-height:20px;margin-top:10px}
#app{display:none;flex-direction:column;height:100%}
#bar{display:flex;gap:6px;padding:6px 8px;overflow-x:auto;align-items:center;background:var(--card);border-bottom:1px solid var(--line)}
#bar input[type=color]{width:38px;height:36px;border:1px solid var(--line);border-radius:8px;padding:2px;background:var(--card);flex:none}
#bar input[type=range]{width:90px;flex:none}
#status{display:flex;gap:10px;padding:5px 10px;font-size:13px;color:var(--mut);flex-wrap:wrap;align-items:center}
#status b{color:var(--fg)}#lat{margin-left:auto;font-variant-numeric:tabular-nums}
#chaos{display:none;background:#fff3cd;color:#664d03;padding:5px 10px;font-size:13px}
#wrap{flex:1;min-height:0;display:flex;justify-content:center;align-items:flex-start;padding:6px}
canvas{background:#fff;border:1px solid var(--line);max-width:100%;max-height:100%;touch-action:none;border-radius:4px}
#chat{display:none;position:fixed;right:0;bottom:0;width:min(360px,100%);height:55%;background:var(--card);border:1px solid var(--line);border-radius:10px 10px 0 0;flex-direction:column;box-shadow:0 -4px 20px rgba(0,0,0,.2)}
#log{flex:1;overflow-y:auto;padding:8px 10px;font-size:14px;overflow-wrap:anywhere}
#log .sys{color:var(--mut);font-style:italic}
#chat form{display:flex;gap:6px;padding:8px;border-top:1px solid var(--line)}
#chat input{flex:1}
</style></head><body>
<div id="join">
  <h1>LAN Whiteboard</h1><p id="sub">Join the shared board from this browser.</p>
  <label for="name">Your name</label><input id="name" type="text" maxlength="20" autocomplete="off">
  <div id="manual">
    <label for="pw">Account password (leave empty if the server has no accounts)</label><input id="pw" type="password">
    <label for="room">Room code</label><input id="room" type="text" maxlength="5" autocapitalize="characters" autocomplete="off">
    <label for="rpw">Room password (optional)</label><input id="rpw" type="password">
  </div>
  <button class="primary" id="go">Join board</button><div id="err"></div>
</div>
<div id="app">
  <div id="bar"></div>
  <div id="status"><span>Room <b id="sroom"></b></span><span id="sme"></span><span id="susers"></span><span id="lat">connecting</span></div>
  <div id="chaos"></div>
  <div id="wrap"><canvas id="c" width="1000" height="640"></canvas></div>
  <div id="chat"><div id="log"></div><form id="cf"><input id="ci" type="text" maxlength="1000" placeholder="Message" autocomplete="off"><button>Send</button></form></div>
</div>
<script>
"use strict";
const $ = id => document.getElementById(id), Q = new URLSearchParams(location.search);
const W = 1000, H = 640, cv = $("c"), g = cv.getContext("2d");
let ws = null, joined = false, dead = false, me = "", room = "", role = "editor", token = "", jwt = null, authOn = true;
let users = [], objs = new Map(), lastSeq = 0, resyncing = false, resyncAt = 0, seqAtPong = -1;
let outbox = [], rn = 0, rto = 800, tries = 0, rtt = null, rtts = [];
let tool = "pen", color = "#000000", width = 3, cur = null, live = {}, cursors = {}, lasers = {}, imgs = {};
let hosts = [location.host], hostIdx = 0, opened = false, dirty = true, lastLive = 0, lastCur = 0, erased = new Set();
const uid = () => Array.from({length: 4}, () => Math.random().toString(16).slice(2, 10)).join("");
const now = () => Date.now();

// ---------------------------------------------------------------- connection
function joinMsg() {
  const m = {type: "JOIN_ROOM", user: $("name").value.trim(), room: (Q.get("room") || $("room").value).trim().toUpperCase(),
             password: $("rpw").value, token: token};
  if (Q.get("invite")) m.invite = Q.get("invite"); else if (jwt) m.jwt = jwt;
  return m;
}
function firstMsg() {
  if (Q.get("invite") || jwt || !authOn || !$("pw").value) return joinMsg();
  return {type: "LOGIN", user: $("name").value.trim(), password: $("pw").value};
}
function connect() {
  opened = false;
  try { ws = new WebSocket("ws://" + hosts[hostIdx % hosts.length] + "/ws"); } catch (e) { return retry(); }
  const mine = ws;
  ws.onopen = () => { opened = true; raw(firstMsg()); };
  ws.onmessage = e => { if (mine === ws) handle(JSON.parse(e.data)); };
  ws.onclose = () => { if (mine === ws) retry(); };
}
function retry() {
  ws = null;
  if (dead) return;
  if (!joined) { if (!$("err").textContent) $("err").textContent = "Cannot reach the server."; $("go").disabled = false; return; }
  if (!opened) hostIdx++;                        // that server did not answer: try the next one (standby)
  $("lat").textContent = "● reconnecting…"; $("lat").style.color = "var(--bad)";
  setTimeout(connect, 1000);
}
function raw(m) { if (ws && ws.readyState === 1) ws.send(JSON.stringify(m)); }
// Reliable request: numbered (rn), kept in the outbox until the server ACKs its msg_id.
function rel(m) { m.msg_id = uid(); m.rn = ++rn; outbox.push(m); if (outbox.length === 1) { sentAt = now(); tries = 0; } raw(m); }
let sentAt = 0;
setInterval(() => {                               // retransmit timer: resend everything unACKed, in order
  if (!joined || !ws || ws.readyState !== 1) return;
  const t = now();
  if (outbox.length && t - sentAt > rto * Math.min(8, 2 ** tries)) { outbox.forEach(raw); sentAt = t; tries++; }
  if (resyncing && t - resyncAt > Math.max(1500, rto)) { resyncAt = t; raw({type: "RESYNC_REQ", since: lastSeq}); }
}, 200);
setInterval(() => { if (joined) raw({type: "PING", t: now(), rtt: rtt}); }, 1000);

function handle(m) {
  switch (m.type) {
    case "AUTH_OK": jwt = m.jwt; $("name").value = m.user; raw(joinMsg()); break;
    case "AUTH_ERR": fail(m.text); break;
    case "JOIN_ERR":
      if (joined && m.code === "STANDBY") { hostIdx++; opened = true; ws.close(); break; }
      if (joined) { dead = true; sys("! " + m.text); $("lat").textContent = "● disconnected"; } else fail(m.text);
      break;
    case "JOIN_OK":
      me = m.user; room = m.room; role = m.role; token = m.token; users = m.users;
      try { sessionStorage.setItem("wb_token_" + room, token); } catch (e) {}
      if (!joined) { joined = true; $("join").style.display = "none"; $("app").style.display = "flex"; $("log").innerHTML = ""; m.chat.forEach(chatLine); }
      $("sroom").textContent = room; $("sme").textContent = me + (role === "viewer" ? " (view only)" : "");
      snapshot(m.snapshot); showUsers(); showChaos(m.chaos); setBackups(m.backups);
      outbox.forEach((x, i) => { x.rn = i + 1; }); rn = outbox.length;      // new connection: renumber, resend
      outbox.forEach(raw); sentAt = now(); tries = 0;
      break;
    case "ACK": outbox = outbox.filter(x => x.msg_id !== m.msg_id); sentAt = now(); tries = 0; break;
    case "OP": applyOp(m); break;
    case "OPS_SINCE": resyncing = false; m.ops.forEach(applyOp); break;
    case "SNAPSHOT": snapshot(m); break;
    case "PONG":
      if (m.t != null) { rtt = Math.max(0, now() - m.t); rtts.push(rtt); if (rtts.length > 20) rtts.shift();
        rto = Math.min(3000, Math.max(600, 3 * rtts.reduce((a, b) => a + b, 0) / rtts.length)); showLat(); }
      if (m.stats && m.stats.room_seq > lastSeq && !resyncing) {            // heartbeat anti-entropy
        if (seqAtPong === lastSeq) { resyncing = true; resyncAt = now(); raw({type: "RESYNC_REQ", since: lastSeq}); }
        seqAtPong = lastSeq;
      } else seqAtPong = -1;
      break;
    case "LIVE": live[m.user] = m; dirty = true; break;
    case "CURSOR": cursors[m.user] = {x: m.x, y: m.y, t: now()}; dirty = true; break;
    case "LASER": (lasers[m.user] = lasers[m.user] || []).push({x: m.x, y: m.y, t: now()}); dirty = true; break;
    case "CHAT": chatLine(m); break;
    case "USERS": users = m.users; { const u = users.find(u => u.name === me); if (u) { role = u.role; $("sme").textContent = me + (role === "viewer" ? " (view only)" : ""); } } showUsers(); break;
    case "INFO": sys("* " + m.text); break;
    case "ERROR": sys("! " + m.text); break;
    case "CHAOS": showChaos(m.chaos); sys(m.chaos ? "* chaos lab ON (set by " + m.by + ")" : "* chaos lab off"); break;
    case "BACKUPS": setBackups(m.backups); break;
    case "KICKED": dead = true; sys("! " + m.text); $("lat").textContent = "● removed"; $("lat").style.color = "var(--bad)"; break;
  }
}
function fail(t) { $("err").textContent = t; $("go").disabled = false; if (ws) { const w = ws; ws = null; w.close(); } }
function setBackups(b) { hosts = [location.host].concat((b || []).filter(x => x.web).map(x => x.host + ":" + x.web)); }
function showLat() {
  const el = $("lat"); el.textContent = "● " + rtt.toFixed(0) + " ms";
  el.style.color = rtt < 50 ? "var(--ok)" : rtt < 150 ? "#ef6c00" : "var(--bad)";
}
function showChaos(c) {
  const el = $("chaos"); el.style.display = c ? "block" : "none";
  if (c) el.textContent = "⚡ Chaos lab: " + c.loss + "% loss, " + c.delay + " ms delay ± " + c.jitter + " ms" + (c.bw ? ", " + c.bw + " kbit/s cap" : "") + " — the board repairs itself";
}
function showUsers() { $("susers").textContent = users.filter(u => u.online).length + " online"; }
function sys(t) { const d = document.createElement("div"); d.className = "sys"; d.textContent = t; $("log").appendChild(d); $("log").scrollTop = 1e9; }
function chatLine(c) { const d = document.createElement("div"); d.textContent = "[" + c.ts + "] " + c.user + ": " + c.text; $("log").appendChild(d); $("log").scrollTop = 1e9; }

// ---------------------------------------------------------------- board state (same rules as the desktop client)
function snapshot(s) {
  objs = new Map(); s.objects.forEach(o => objs.set(o.id, {obj: o, visible: o.visible}));
  lastSeq = s.seq; resyncing = false; live = {}; erased.clear(); dirty = true;
}
function applyOp(op) {
  if (op.seq <= lastSeq) return;                          // duplicate
  if (op.seq !== lastSeq + 1) {                           // gap: ask for what we missed
    if (!resyncing) { resyncing = true; resyncAt = now(); raw({type: "RESYNC_REQ", since: lastSeq}); }
    return;
  }
  lastSeq = op.seq;
  if (op.op === "ADD") { objs.set(op.obj.id, {obj: op.obj, visible: true}); delete live[op.by]; if (op.by === me) pending = pending.filter(p => p.id !== op.obj.id); }
  else op.ids.forEach(i => { const r = objs.get(i); if (r) r.visible = op.visible; erased.delete(i); });
  dirty = true;
}
let pending = [];                                         // my own objects not yet confirmed (drawn at once)

// ---------------------------------------------------------------- drawing
function pastel(c) { return "#" + [1, 3, 5].map(i => { const v = parseInt(c.substr(i, 2), 16); return Math.round(v + (255 - v) * .7).toString(16).padStart(2, "0"); }).join(""); }
function wrapText(t, maxw) { const out = []; let line = ""; t.split(/\s+/).forEach(w => { const s = line ? line + " " + w : w; if (g.measureText(s).width > maxw && line) { out.push(line); line = w; } else line = s; }); if (line) out.push(line); return out; }
function shape(o) {
  const p = o.points, k = o.kind; g.strokeStyle = g.fillStyle = o.color; g.lineWidth = o.width; g.lineCap = g.lineJoin = "round";
  if (k === "stroke") {
    if (p.length === 1) { g.beginPath(); g.arc(p[0][0], p[0][1], Math.max(o.width / 2, 1), 0, 7); g.fill(); return; }
    g.beginPath(); g.moveTo(p[0][0], p[0][1]); for (let i = 1; i < p.length; i++) g.lineTo(p[i][0], p[i][1]); g.stroke();
  } else if (k === "line") { g.beginPath(); g.moveTo(p[0][0], p[0][1]); g.lineTo(p[1][0], p[1][1]); g.stroke(); }
  else if (k === "rect") { g.lineJoin = "miter"; g.strokeRect(p[0][0], p[0][1], p[1][0] - p[0][0], p[1][1] - p[0][1]); }
  else if (k === "oval") { g.beginPath(); g.ellipse((p[0][0] + p[1][0]) / 2, (p[0][1] + p[1][1]) / 2, Math.abs(p[1][0] - p[0][0]) / 2, Math.abs(p[1][1] - p[0][1]) / 2, 0, 0, 7); g.stroke(); }
  else if (k === "text") { g.font = Math.round((o.width * 3 + 8) * 1.33) + "px Arial"; g.textBaseline = "top"; g.fillText(o.text || "", p[0][0], p[0][1]); }
  else if (k === "sticky") {
    const x = p[0][0], y = p[0][1]; g.fillStyle = pastel(o.color); g.fillRect(x, y, 160, 120); g.lineWidth = 2; g.lineJoin = "miter"; g.strokeRect(x, y, 160, 120);
    g.fillStyle = "#000"; g.font = "15px Arial"; g.textBaseline = "top"; wrapText(o.text || "", 144).slice(0, 6).forEach((ln, i) => g.fillText(ln, x + 8, y + 8 + i * 18));
  } else if (k === "image") {
    let im = imgs[o.id]; if (!im) { im = imgs[o.id] = new Image(); im.onload = () => { dirty = true; }; im.src = "data:image/png;base64," + o.data; }
    if (im.complete && im.naturalWidth) g.drawImage(im, p[0][0], p[0][1]);
  }
}
function frame() {
  requestAnimationFrame(frame);
  const t = now(); let anim = false;
  for (const u in lasers) { lasers[u] = lasers[u].filter(q => t - q.t < 900); if (lasers[u].length) anim = true; else delete lasers[u]; }
  if (!dirty && !anim) return; dirty = false;
  g.clearRect(0, 0, W, H);
  objs.forEach(r => { if (r.visible) shape(r.obj); });
  pending.forEach(shape);
  for (const u in live) { const m = live[u]; if (m.points.length > 1) shape({kind: "stroke", points: m.points, color: m.color, width: m.width}); }
  if (cur) shape(cur);
  for (const u in lasers) lasers[u].forEach(q => { const a = 1 - (t - q.t) / 900; g.beginPath(); g.fillStyle = "rgba(255,23,68," + a.toFixed(2) + ")"; g.arc(q.x, q.y, 3 + 6 * a, 0, 7); g.fill(); });
  for (const u in cursors) { const c = cursors[u], usr = users.find(x => x.name === u); if (!usr || !usr.online) continue;
    g.fillStyle = usr.color; g.beginPath(); g.arc(c.x, c.y, 4, 0, 7); g.fill(); g.font = "12px Arial"; g.textBaseline = "middle"; g.fillText(u, c.x + 8, c.y + 2); }
}
// Ramer-Douglas-Peucker: fewer points per stroke = fewer bytes on the wire
function rdp(p, eps) {
  if (p.length < 3) return p;
  const keep = new Uint8Array(p.length); keep[0] = keep[p.length - 1] = 1; const st = [[0, p.length - 1]];
  while (st.length) { const [a, b] = st.pop(), dx = p[b][0] - p[a][0], dy = p[b][1] - p[a][1], n = Math.hypot(dx, dy); let worst = 0, idx = -1;
    for (let i = a + 1; i < b; i++) { const d = n ? Math.abs(dy * (p[i][0] - p[a][0]) - dx * (p[i][1] - p[a][1])) / n : Math.hypot(p[i][0] - p[a][0], p[i][1] - p[a][1]); if (d > worst) { worst = d; idx = i; } }
    if (worst > eps) { keep[idx] = 1; st.push([a, idx], [idx, b]); } }
  return p.filter((_, i) => keep[i]);
}

// ---------------------------------------------------------------- input
function pos(e) { const r = cv.getBoundingClientRect(); return [Math.round((e.clientX - r.left) * W / r.width), Math.round((e.clientY - r.top) * H / r.height)]; }
function add(o) { o.id = uid(); pending.push(o); rel({type: "ADD", obj: o}); dirty = true; }
function hit(o, x, y, r) {
  const p = o.points, k = o.kind;
  if (k === "stroke" || k === "line") { for (let i = 0; i < p.length; i++) { const a = p[i], b = p[Math.min(i + 1, p.length - 1)], dx = b[0] - a[0], dy = b[1] - a[1], L = dx * dx + dy * dy;
      const u = L ? Math.max(0, Math.min(1, ((x - a[0]) * dx + (y - a[1]) * dy) / L)) : 0; if (Math.hypot(x - a[0] - u * dx, y - a[1] - u * dy) <= r + o.width / 2) return true; } return false; }
  let x0, y0, x1, y1;
  if (k === "rect" || k === "oval") { x0 = Math.min(p[0][0], p[1][0]); x1 = Math.max(p[0][0], p[1][0]); y0 = Math.min(p[0][1], p[1][1]); y1 = Math.max(p[0][1], p[1][1]); }
  else if (k === "sticky") { x0 = p[0][0]; y0 = p[0][1]; x1 = x0 + 160; y1 = y0 + 120; }
  else if (k === "image") { x0 = p[0][0]; y0 = p[0][1]; x1 = x0 + o.w; y1 = y0 + o.h; }
  else { x0 = p[0][0]; y0 = p[0][1]; x1 = x0 + (o.text || "").length * (o.width * 2 + 6); y1 = y0 + o.width * 4 + 12; }
  return x >= x0 - r && x <= x1 + r && y >= y0 - r && y <= y1 + r;
}
function eraseAt(x, y) {
  const ids = []; objs.forEach((r, id) => { if (r.visible && !erased.has(id) && hit(r.obj, x, y, 5 + width)) ids.push(id); });
  if (ids.length) { ids.forEach(i => erased.add(i)); rel({type: "ERASE", ids: ids}); }
}
cv.addEventListener("pointerdown", e => {
  if (dead) return; e.preventDefault(); cv.setPointerCapture(e.pointerId); const [x, y] = pos(e);
  if (tool === "laser") { cur = null; laser(x, y); cv._down = true; return; }
  if (role !== "editor") return;
  cv._down = true;
  if (tool === "text" || tool === "sticky") { cv._down = false; const s = prompt(tool === "text" ? "Enter text:" : "Note text:"); if (s) add({kind: tool, color: color, width: width, points: [[x, y]], text: s.slice(0, tool === "text" ? 500 : 300)}); }
  else if (tool === "eraser") eraseAt(x, y);
  else cur = {kind: tool === "pen" ? "stroke" : tool, color: color, width: width, points: tool === "pen" ? [[x, y]] : [[x, y], [x, y]]};
  dirty = true;
});
cv.addEventListener("pointermove", e => {
  const [x, y] = pos(e), t = now();
  if (joined && t - lastCur > 70) { lastCur = t; raw({type: "CURSOR", x: x, y: y}); }
  if (!cv._down) return;
  if (tool === "laser") return laser(x, y);
  if (tool === "eraser") return eraseAt(x, y);
  if (!cur) return;
  if (cur.kind === "stroke") { const l = cur.points[cur.points.length - 1]; if (Math.abs(x - l[0]) + Math.abs(y - l[1]) < 2) return; cur.points.push([x, y]);
    if (t - lastLive > 40) { lastLive = t; raw({type: "LIVE", color: color, width: width, points: cur.points.slice(-50)}); } }
  else cur.points[1] = [x, y];
  dirty = true;
});
function up() { cv._down = false; if (!cur) return; const o = cur; cur = null; if (o.kind === "stroke") o.points = rdp(o.points, 1.0); add(o); }
cv.addEventListener("pointerup", up); cv.addEventListener("pointercancel", up);
function laser(x, y) { (lasers[me] = lasers[me] || []).push({x: x, y: y, t: now()}); raw({type: "LASER", x: x, y: y}); dirty = true; }

// ---------------------------------------------------------------- toolbar
const bar = $("bar"), tools = ["pen", "eraser", "line", "rect", "oval", "text", "sticky", "laser"];
tools.forEach(t => { const b = document.createElement("button"); b.textContent = t[0].toUpperCase() + t.slice(1); b.dataset.t = t; if (t === tool) b.className = "on";
  b.onclick = () => { tool = t; bar.querySelectorAll("button[data-t]").forEach(x => x.className = x.dataset.t === t ? "on" : ""); }; bar.appendChild(b); });
const col = document.createElement("input"); col.type = "color"; col.value = color; col.setAttribute("aria-label", "Colour"); col.oninput = () => { color = col.value; }; bar.appendChild(col);
const wid = document.createElement("input"); wid.type = "range"; wid.min = 1; wid.max = 20; wid.value = 3; wid.setAttribute("aria-label", "Line width"); wid.oninput = () => { width = +wid.value; }; bar.appendChild(wid);
[["Undo", () => rel({type: "UNDO"})], ["Redo", () => rel({type: "REDO"})], ["Chat", () => { const c = $("chat"); c.style.display = c.style.display === "flex" ? "none" : "flex"; }]]
  .forEach(([t, f]) => { const b = document.createElement("button"); b.textContent = t; b.onclick = f; bar.appendChild(b); });
$("cf").onsubmit = e => { e.preventDefault(); const t = $("ci").value.trim(); if (t) { rel({type: "CHAT", text: t}); $("ci").value = ""; } };

// ---------------------------------------------------------------- start
if (Q.get("invite")) { $("manual").style.display = "none"; $("sub").textContent = "You were invited to room " + (Q.get("room") || "") + ". Pick a name and join."; }
if (Q.get("room")) { $("room").value = Q.get("room"); try { token = sessionStorage.getItem("wb_token_" + Q.get("room")) || ""; } catch (e) {} }
fetch("/info").then(r => r.json()).then(i => { authOn = i.auth; }).catch(() => {});
$("go").onclick = () => {
  $("err").textContent = "";
  if (!$("name").value.trim()) return $("err").textContent = "Enter your name.";
  if (!Q.get("invite") && !$("room").value.trim()) return $("err").textContent = "Enter the room code.";
  $("go").disabled = true; connect();
};
$("name").addEventListener("keydown", e => { if (e.key === "Enter") $("go").click(); });
requestAnimationFrame(frame);
</script></body></html>
"""


ADMIN_PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Whiteboard server dashboard</title>
<style>
:root{--bg:#f3f4f6;--fg:#111827;--mut:#6b7280;--card:#fff;--line:#e5e7eb;--in:#2563eb;--out:#d97706;--ok:#15803d;--bad:#b91c1c}
@media(prefers-color-scheme:dark){:root{--bg:#0f172a;--fg:#f1f5f9;--mut:#94a3b8;--card:#1e293b;--line:#334155;--in:#60a5fa;--out:#fbbf24;--ok:#4ade80;--bad:#f87171}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;padding:16px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:14px;margin:0 0 10px;color:var(--mut);font-weight:600;text-transform:uppercase;letter-spacing:.04em}
#sub{color:var(--mut);margin-bottom:14px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.kpi b{display:block;font-size:24px;font-variant-numeric:tabular-nums;line-height:1.2}.kpi span{color:var(--mut);font-size:12px}
.grid{display:grid;grid-template-columns:minmax(0,3fr) minmax(0,2fr);gap:12px}@media(max-width:900px){.grid{grid-template-columns:minmax(0,1fr)}}
canvas{width:100%;height:190px;display:block}
.legend{display:flex;gap:16px;font-size:12px;color:var(--mut);margin-bottom:6px}.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px}
table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}th{text-align:left;color:var(--mut);font-weight:600;font-size:12px;padding:4px 8px 4px 0;border-bottom:1px solid var(--line)}
td{padding:6px 8px 6px 0;border-bottom:1px solid var(--line);vertical-align:top}.scroll{overflow-x:auto}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;border:1px solid var(--line);margin:1px 3px 1px 0;white-space:nowrap}
.warn{color:var(--out);font-weight:600}.okc{color:var(--ok)}.badc{color:var(--bad)}
#log{height:300px;overflow-y:auto;font:12px ui-monospace,Menlo,Consolas,monospace;overflow-wrap:anywhere}#log div{padding:2px 0;border-bottom:1px solid var(--line)}
#log time{color:var(--mut);margin-right:8px}
</style></head><body>
<h1>Whiteboard server dashboard</h1><div id="sub">connecting…</div>
<div class="kpis" id="kpis"></div>
<div class="grid">
  <div>
    <div class="card" style="margin-bottom:12px"><h2>Traffic, last 60 seconds (KB/s)</h2>
      <div class="legend"><span><i style="background:var(--in)"></i>received from clients</span><span><i style="background:var(--out)"></i>sent to clients</span></div>
      <canvas id="chart"></canvas></div>
    <div class="card"><h2>Rooms</h2><div class="scroll"><table><thead><tr><th>Room</th><th>Host</th><th>Seq</th><th>Objects</th><th>Online clients (latency)</th><th>Emulated link</th></tr></thead><tbody id="rooms"></tbody></table></div></div>
  </div>
  <div>
    <div class="card" style="margin-bottom:12px"><h2>Counters</h2><table><tbody id="counters"></tbody></table></div>
    <div class="card"><h2>Event log</h2><div id="log"></div></div>
  </div>
</div>
<script>
"use strict";
const $ = id => document.getElementById(id), key = new URLSearchParams(location.search).get("key") || "";
let prev = null, hist = [], lastEvents = 0;
const esc = s => String(s).replace(/[&<>"]/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"}[c]));
const css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
function fmtUp(s) { const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60); return (h ? h + " h " : "") + m + " min " + (s % 60) + " s"; }
function kpi(label, value, cls) { return '<div class="card kpi"><b class="' + (cls || "") + '">' + esc(value) + "</b><span>" + esc(label) + "</span></div>"; }
function draw() {
  const c = $("chart"), r = c.getBoundingClientRect(), d = devicePixelRatio || 1; c.width = r.width * d; c.height = r.height * d;
  const g = c.getContext("2d"); g.scale(d, d); const W = r.width, H = r.height, L = 38, B = 18, T = 6;
  const top = Math.max(1, ...hist.map(h => Math.max(h.i, h.o))) * 1.15;
  g.font = "11px system-ui"; g.fillStyle = css("--mut"); g.strokeStyle = css("--line"); g.lineWidth = 1;
  for (let k = 0; k <= 4; k++) { const y = T + (H - B - T) * k / 4; g.beginPath(); g.moveTo(L, y); g.lineTo(W, y); g.stroke(); g.textAlign = "right"; g.fillText((top * (1 - k / 4)).toFixed(top < 10 ? 1 : 0), L - 6, y + 4); }
  g.textAlign = "left"; g.fillText("60 s ago", L, H - 4); g.textAlign = "right"; g.fillText("now", W, H - 4);
  [["i", "--in"], ["o", "--out"]].forEach(([k, col]) => { g.strokeStyle = css(col); g.lineWidth = 2; g.beginPath();
    hist.forEach((h, i) => { const x = W - (hist.length - 1 - i) * (W - L) / 59, y = T + (H - B - T) * (1 - h[k] / top); i ? g.lineTo(x, y) : g.moveTo(x, y); }); g.stroke(); });
}
async function tick() {
  let s;
  try { const r = await fetch("/admin/state?key=" + encodeURIComponent(key)); if (!r.ok) throw new Error(await r.text()); s = await r.json(); }
  catch (e) { $("sub").innerHTML = '<span class="badc">Server not reachable: ' + esc(e.message) + "</span>"; return; }
  const st = s.stats, online = s.rooms.reduce((a, r) => a + r.clients.length, 0);
  let i = 0, o = 0;
  if (prev) { const dt = Math.max(.2, s.now - prev.now); i = (st.bytes_in - prev.stats.bytes_in) / dt / 1024; o = (st.bytes_out - prev.stats.bytes_out) / dt / 1024; if (i < 0 || o < 0) i = o = 0; }
  prev = s; hist.push({i: i, o: o}); if (hist.length > 60) hist.shift();
  $("sub").textContent = s.ip + ":" + s.port + " · " + (s.tls ? "TLS on" : "TLS off") + " · " + (s.auth ? s.accounts + " accounts" : "no accounts") + " · compression " + (s.compress ? "on" : "off")
    + " · web port " + (s.web || "off") + " · voice port " + (s.voice || "off") + " · standby servers: " + (s.standbys.length ? s.standbys.map(b => b.host + ":" + b.port).join(", ") : "none");
  $("kpis").innerHTML = kpi("role", s.role.toUpperCase(), s.role === "primary" ? "okc" : "warn") + kpi("uptime", fmtUp(st.uptime)) + kpi("clients online", online) + kpi("rooms", s.rooms.length)
    + kpi("ops committed", st.ops) + kpi("KB/s in", i.toFixed(1)) + kpi("KB/s out", o.toFixed(1));
  $("rooms").innerHTML = s.rooms.map(r => "<tr><td><b>" + esc(r.code) + "</b>" + (r.password ? " 🔒" : "") + "</td><td>" + esc(r.host) + "</td><td>" + r.seq + "</td><td>" + r.objects + "</td><td>"
    + (r.clients.map(c => '<span class="pill">' + esc(c.name) + " · " + (c.kind === "web" ? "browser" : "desktop") + " · " + (c.rtt == null ? "?" : Math.round(c.rtt) + " ms") + "</span>").join("") || '<span style="color:var(--mut)">nobody online</span>') + "</td><td>"
    + (r.chaos ? '<span class="warn">' + r.chaos.loss + "% loss, " + r.chaos.delay + "±" + r.chaos.jitter + " ms" + (r.chaos.bw ? ", " + r.chaos.bw + " kbit/s" : "") + "</span><br>dropped " + (r.chaos_n.in + r.chaos_n.out) : "normal") + "</td></tr>").join("")
    || '<tr><td colspan="6" style="color:var(--mut)">No rooms yet</td></tr>';
  const rows = [["Connections accepted", st.conns], ["of which browsers (WebSocket)", st.web_conns], ["Messages in / out", st.msgs_in + " / " + st.msgs_out], ["Bytes saved by compression", (st.z_saved / 1024).toFixed(1) + " KB"],
    ["Duplicates ignored", st.dups], ["Requests held for ordering", st.out_of_order], ["Dropped by chaos lab", st.chaos_drops], ["Stale cursor frames shed", st.shed], ["Rate limited", st.rate_limited],
    ["Reconnects / timeouts", st.reconnects + " / " + st.timeouts], ["Slow clients dropped", st.slow_drops], ["Logins / failed", st.logins + " / " + st.login_fails], ["Discovery replies (UDP)", st.discovery],
    ["Voice packets relayed (UDP)", st.voice_pkts], ["Files introduced (peer to peer)", st.file_offers], ["Replication events", st.repl_events], ["Database writes", st.db_writes]];
  $("counters").innerHTML = rows.map(r => "<tr><td>" + r[0] + '</td><td style="text-align:right">' + r[1] + "</td></tr>").join("");
  if (s.events.length !== lastEvents || !$("log").children.length) { lastEvents = s.events.length;
    $("log").innerHTML = s.events.slice().reverse().map(e => "<div><time>" + esc(e[0]) + "</time>" + esc(e[1]) + "</div>").join(""); }
  draw();
}
tick(); setInterval(tick, 1000); addEventListener("resize", draw);
</script></body></html>
"""
