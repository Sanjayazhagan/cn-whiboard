const pptxgen = require("pptxgenjs");
const fs = require("fs");
const { applyTheme } = require("/root/.claude/skills/synced/2fd135d7-f40c-4031-a366-e152bb70dc9c_4b4e3114-589e-41a2-afd2-6551486009c6/pptx/scripts/apply_theme.js");
const DIMS = JSON.parse(fs.readFileSync(__dirname + "/img/dims.json"));
const OUT = process.argv[2] || "LAN-Collaborative-Whiteboard.pptx";

const THEME = {
  name: "Whiteboard", headFontFace: "Calibri", bodyFontFace: "Calibri",
  colors: { dk1: "0B1F3A", lt1: "FFFFFF", dk2: "475569", lt2: "EEF3F8", accent1: "0D9488", accent2: "F59E0B",
            accent3: "2563EB", accent4: "E11D48", accent5: "7C3AED", accent6: "94A3B8", hlink: "0D9488", folHlink: "7C3AED" },
};
const pres = new pptxgen();
pres.layout = "LAYOUT_16x9";
pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
pres.title = "LAN Collaborative Whiteboard";
pres.subject = "Computer Networks lab project";
const C = pres.SchemeColor;
const FOOT = "LAN Collaborative Whiteboard  |  Computer Networks Lab";

pres.defineSlideMaster({
  title: "TITLE_DARK", background: { color: C.text1 },
  objects: [
    { placeholder: { options: { name: "title", type: "title", x: 0.6, y: 1.55, w: 5.6, h: 1.5, fontSize: 38, bold: true, color: C.background1, valign: "top", align: "left", margin: 0 }, text: "" } },
    { placeholder: { options: { name: "body", type: "body", x: 0.6, y: 3.15, w: 5.4, h: 0.8, fontSize: 16, color: C.accent6, valign: "top", align: "left", margin: 0 }, text: "" } },
  ],
});
pres.defineSlideMaster({
  title: "CONTENT", background: { color: C.background2 },
  objects: [
    { placeholder: { options: { name: "title", type: "title", x: 0.5, y: 0.52, w: 9, h: 0.6, fontSize: 25, bold: true, color: C.text1, valign: "middle", align: "left", margin: 0 }, text: "" } },
    { text: { text: FOOT, options: { x: 0.5, y: 5.25, w: 6, h: 0.25, fontSize: 9, color: C.accent6, margin: 0 } } },
  ],
  slideNumber: { x: 9.0, y: 5.25, w: 0.5, h: 0.25, fontSize: 9, color: C.accent6, align: "right" },
});
pres.defineSlideMaster({
  title: "CONTENT_DARK", background: { color: C.text1 },
  objects: [
    { placeholder: { options: { name: "title", type: "title", x: 0.5, y: 0.52, w: 9, h: 0.6, fontSize: 25, bold: true, color: C.background1, valign: "middle", align: "left", margin: 0 }, text: "" } },
    { text: { text: FOOT, options: { x: 0.5, y: 5.25, w: 6, h: 0.25, fontSize: 9, color: C.accent6, margin: 0 } } },
  ],
  slideNumber: { x: 9.0, y: 5.25, w: 0.5, h: 0.25, fontSize: 9, color: C.accent6, align: "right" },
});

let n = 0, section = "";
const nm = (s) => `${s} ${++n}`;
function sec(t) { section = t; pres.addSection({ title: t }); }
function slide(title, eyebrow, notes, master = "CONTENT") {
  const s = pres.addSlide({ masterName: master, sectionTitle: section });
  s.addText(title, { placeholder: "title" });
  if (eyebrow) s.addText(eyebrow.toUpperCase(), { x: 0.5, y: 0.3, w: 6, h: 0.22, fontSize: 10, bold: true, charSpacing: 2,
    color: master === "CONTENT" ? C.accent1 : C.accent2, margin: 0, isTextBox: true, objectName: nm("Eyebrow") });
  if (notes) s.addNotes(notes);
  return s;
}
const shadow = () => ({ type: "outer", color: "0B1F3A", blur: 6, offset: 2, angle: 90, opacity: 0.12 });
function box(s, x, y, w, h, fill = C.background1, opts = {}) {
  s.addShape(pres.ShapeType.roundRect, { x, y, w, h, rectRadius: 0.08, fill: { color: fill }, line: { color: fill, width: 0 },
    shadow: opts.noShadow ? undefined : shadow(), objectName: nm("Card"), ...opts.extra });
}
function card(s, x, y, w, h, head, body, color = C.accent1, o = {}) {
  box(s, x, y, w, h);
  s.addText(head, { x: x + 0.15, y: y + 0.1, w: w - 0.3, h: 0.3, fontSize: o.hs || 13, bold: true, color, margin: 0, isTextBox: true, valign: "middle", objectName: nm("Card head") });
  s.addText(body, { x: x + 0.15, y: y + 0.42, w: w - 0.3, h: h - 0.5, fontSize: o.bs || 11, color: C.text2, margin: 0, isTextBox: true, valign: "top", objectName: nm("Card body") });
}
function num(s, x, y, t, color = C.accent1, d = 0.36) {
  s.addText(String(t), { shape: pres.ShapeType.ellipse, x, y, w: d, h: d, fill: { color }, color: C.background1, bold: true, fontSize: 12,
    align: "center", valign: "middle", margin: 0, objectName: nm("Badge") });
}
function row(s, x, y, w, i, head, body, color = C.accent1, hgt = 0.62) {
  num(s, x, y + 0.03, i, color);
  s.addText([{ text: head, options: { bold: true, color: C.text1, breakLine: true } }, { text: body, options: { color: C.text2 } }],
    { x: x + 0.5, y, w: w - 0.5, h: hgt, fontSize: 11, margin: 0, isTextBox: true, valign: "top", objectName: nm("Row") });
}
function stat(s, x, y, w, big, label, color = C.accent1, dark = false) {
  s.addText(big, { x, y, w, h: 0.6, fontSize: 30, bold: true, color, margin: 0, isTextBox: true, align: "center", valign: "middle", objectName: nm("Stat") });
  s.addText(label, { x, y: y + 0.6, w, h: 0.5, fontSize: 10.5, color: dark ? C.accent6 : C.text2, margin: 0, isTextBox: true, align: "center", valign: "top", objectName: nm("Stat label") });
}
function img(s, key, x, y, w, h, alt) {         // fit inside the box, centred, with a white frame
  const [iw, ih] = DIMS[key]; const r = Math.min(w / iw, h / ih); const ww = iw * r, hh = ih * r;
  const xx = x + (w - ww) / 2, yy = y + (h - hh) / 2;
  s.addShape(pres.ShapeType.rect, { x: xx - 0.05, y: yy - 0.05, w: ww + 0.1, h: hh + 0.1, fill: { color: C.background1 }, line: { color: C.background1, width: 0 }, shadow: shadow(), objectName: nm("Frame") });
  s.addImage({ path: `${__dirname}/img/${key}.png`, x: xx, y: yy, w: ww, h: hh, altText: alt, objectName: nm("Screenshot") });
  return { x: xx, y: yy, w: ww, h: hh };
}
function cap(s, x, y, w, t) { s.addText(t, { x, y, w, h: 0.25, fontSize: 9.5, italic: true, color: C.text2, margin: 0, align: "center", isTextBox: true, objectName: nm("Caption") }); }
function node(s, x, y, w, h, t, fill, color = C.background1, fs = 11) {
  s.addText(t, { shape: pres.ShapeType.roundRect, rectRadius: 0.06, x, y, w, h, fill: { color: fill }, line: { color: fill, width: 0 }, color, fontSize: fs, bold: true,
    align: "center", valign: "middle", margin: 2, objectName: nm("Node") });
}
function link(s, x1, y1, x2, y2, color = C.accent6, o = {}) {
  s.addShape(pres.ShapeType.line, { x: Math.min(x1, x2), y: Math.min(y1, y2), w: Math.abs(x2 - x1), h: Math.abs(y2 - y1),
    flipH: x2 < x1, flipV: y2 < y1, line: { color, width: o.width || 1.5, dashType: o.dash ? "dash" : "solid", endArrowType: o.arrow === false ? "none" : "triangle", beginArrowType: o.both ? "triangle" : "none" }, objectName: nm("Link") });
}
function label(s, x, y, w, t, color = C.text2, o = {}) {
  s.addText(t, { x, y, w, h: o.h || 0.22, fontSize: o.fs || 9, color, margin: 0, align: o.align || "center", isTextBox: true, bold: !!o.bold, fontFace: o.mono ? "Courier New" : undefined, valign: "middle", objectName: nm("Label") });
}

// ---------------------------------------------------------------- 1 title
sec("Overview");
{
  const s = pres.addSlide({ masterName: "TITLE_DARK", sectionTitle: section });
  s.addText("COMPUTER NETWORKS LAB PROJECT", { x: 0.6, y: 1.1, w: 5, h: 0.25, fontSize: 11, bold: true, charSpacing: 3, color: C.accent2, margin: 0, isTextBox: true, objectName: nm("Eyebrow") });
  s.addText("LAN Collaborative Whiteboard", { placeholder: "title" });
  s.addText("A real-time shared drawing board built directly on TCP and UDP sockets", { placeholder: "body" });
  s.addText("Team: [member names and roll numbers]   |   November 2026", { x: 0.6, y: 4.6, w: 6, h: 0.3, fontSize: 12, color: C.background1, margin: 0, isTextBox: true, objectName: nm("Team") });
  // small star network: one server, five clients
  const cx = 7.75, cy = 2.75, pts = [[6.45, 1.35], [9.0, 1.3], [9.3, 3.0], [8.55, 4.3], [6.5, 4.05]];
  const names = ["Windows", "Linux", "Phone", "Standby", "Tablet"];
  pts.forEach(([x, y]) => link(s, cx, cy, x, y, C.accent6, { arrow: false, width: 1.25 }));
  pts.forEach(([x, y], i) => s.addText(names[i], { shape: pres.ShapeType.ellipse, x: x - 0.45, y: y - 0.45, w: 0.9, h: 0.9, fill: { color: C.text1 },
    line: { color: i === 3 ? C.accent2 : C.accent1, width: 2 }, color: C.background1, fontSize: 9.5, align: "center", valign: "middle", margin: 0, objectName: nm("Client node") }));
  s.addText("Server", { shape: pres.ShapeType.ellipse, x: cx - 0.7, y: cy - 0.7, w: 1.4, h: 1.4, fill: { color: C.accent1 }, line: { color: C.accent1, width: 0 },
    color: C.background1, fontSize: 15, bold: true, align: "center", valign: "middle", margin: 0, objectName: nm("Server node") });
  s.addNotes("Introduce the team and the one-line idea: several people on the same LAN draw on one board at the same time, with no internet. Everything in the networking path is written by us on top of plain sockets.");
}

// ---------------------------------------------------------------- 2 problem
{
  const s = slide("Many people, one board, no internet", "The problem",
    "The brief: a multi-user whiteboard for a LAN, client-server over TCP, working fully offline, demonstrated on Windows and Linux. The hard part is not drawing, it is keeping every screen identical when messages are delayed, lost or arrive in a different order.");
  s.addText([
    { text: "The brief", options: { bold: true, color: C.text1, breakLine: true } },
    { text: "A client-server whiteboard for a local network. Several users draw, type and chat on the same board and everyone sees the same thing.", options: { color: C.text2, breakLine: true } },
    { text: " ", options: { breakLine: true, fontSize: 6 } },
    { text: "The real difficulty", options: { bold: true, color: C.text1, breakLine: true } },
    { text: "Two users draw at the same moment, a packet is late, a laptop drops off Wi-Fi. Every screen must still end up identical.", options: { color: C.text2 } },
  ], { x: 0.5, y: 1.35, w: 3.6, h: 3.4, fontSize: 13.5, margin: 0, isTextBox: true, valign: "top", paraSpaceAfter: 4, objectName: nm("Body") });
  const g = [["Real time", "Strokes appear on other screens while they are still being drawn.", C.accent1],
             ["Consistent", "The server gives every change a sequence number, so all boards apply the same order.", C.accent3],
             ["Reliable", "Lost or duplicated messages are detected and repaired automatically.", C.accent2],
             ["Secure and portable", "Accounts, TLS and one code base that runs on Windows and Linux, offline.", C.accent5]];
  g.forEach(([h, b, c], i) => card(s, 4.4 + (i % 2) * 2.6, 1.35 + Math.floor(i / 2) * 1.75, 2.45, 1.6, h, b, c, { bs: 12.5, hs: 14 }));
}

// ---------------------------------------------------------------- 3 what users can do
{
  const s = slide("What the whiteboard does", "The product",
    "Quick tour of the client. Tools along the top, participants with live latency on the right, chat below. The bottom bar opens the networking tools we will show later: Phone join, Replay, Chaos lab, Inspector and Network statistics.");
  img(s, "board", 0.5, 1.35, 5.6, 3.1, "Whiteboard client window with drawings, sticky notes, participants and chat");
  cap(s, 0.5, 4.55, 5.6, "Desktop client (Python, Tkinter): two users in one room");
  const items = [["Draw together", "Pen, eraser, shapes, text, sticky notes, images, laser pointer"],
                 ["Rooms and roles", "Room codes, host and viewer roles, kick, chat"],
                 ["Undo and history", "Per-user undo and redo, saved versions, PNG export"],
                 ["Find and join", "Servers on the LAN are discovered automatically over UDP"],
                 ["Survive restarts", "Every room is stored in SQLite and restored at start-up"]];
  items.forEach(([h, b], i) => row(s, 6.4, 1.35 + i * 0.7, 3.1, i + 1, h, b));
}

// ---------------------------------------------------------------- 4 architecture
sec("Design");
{
  const s = slide("One server, four kinds of socket", "Architecture",
    "Walk the diagram left to right. Desktop clients use our own protocol over TCP inside TLS. Browsers cannot open raw TCP, so the server also speaks HTTP and WebSocket on a second port. Two UDP ports handle discovery and voice. The server keeps rooms in memory, logs every operation to SQLite and streams it to a standby server.");
  // clients
  node(s, 0.5, 1.45, 1.9, 0.6, "Desktop client\nWindows / Linux", C.accent3, C.background1, 10.5);
  node(s, 0.5, 2.3, 1.9, 0.6, "Desktop client\nWindows / Linux", C.accent3, C.background1, 10.5);
  node(s, 0.5, 3.15, 1.9, 0.6, "Phone / tablet\nbrowser", C.accent5, C.background1, 10.5);
  node(s, 0.5, 4.0, 1.9, 0.6, "Any PC on the LAN", C.accent6, C.text1, 10.5);
  // server
  box(s, 4.4, 1.35, 2.7, 3.4, C.text1);
  label(s, 4.4, 1.42, 2.7, "SERVER (Python, one thread per client)", C.accent2, { bold: true });
  const mods = ["Rooms: op log + sequence numbers", "Accounts, JWT, roles", "Send queues with priorities", "HTTP + WebSocket server", "UDP discovery and voice relay"];
  mods.forEach((m, i) => node(s, 4.55, 1.75 + i * 0.58, 2.4, 0.46, m, C.text2, C.background1, 10));
  // links with port labels
  const L = [[1.75, "TCP 5050  TLS  length-prefixed JSON", C.accent3], [2.6, "", C.accent3], [3.45, "TCP 8080  HTTP then WebSocket", C.accent5], [4.3, "UDP 5051 discovery   UDP 5053 voice", C.accent6]];
  L.forEach(([y, t, c]) => { link(s, 2.45, y, 4.35, y, c, { both: true }); if (t) label(s, 2.45, y - 0.24, 1.9, t, C.text2, { fs: 8 }); });
  // right side
  node(s, 7.9, 1.6, 1.6, 0.7, "SQLite\nwhiteboard.db", C.accent1, C.background1, 10.5);
  node(s, 7.9, 3.4, 1.6, 0.7, "Standby\nserver", C.accent2, C.text1, 10.5);
  link(s, 7.15, 1.95, 7.85, 1.95, C.accent1);
  link(s, 7.15, 3.75, 7.85, 3.75, C.accent2, { dash: true });
  label(s, 7.3, 2.35, 2.3, "users, rooms, every operation", C.text2, { fs: 8.5 });
  label(s, 7.3, 4.15, 2.3, "live copy of every operation", C.text2, { fs: 8.5 });
}

// ---------------------------------------------------------------- 5 protocol
{
  const s = slide("Our application protocol on top of TCP", "Protocol",
    "TCP gives a byte stream, not messages, so we add framing: a 4-byte big-endian length, then a JSON body. The top bit of the length says the body is zlib-compressed. The table groups the main message types. We also wrote a Wireshark dissector for this format.");
  // frame diagram
  label(s, 0.5, 1.3, 9, "One frame on the wire", C.text1, { bold: true, align: "left", fs: 12 });
  node(s, 0.5, 1.62, 0.9, 0.6, "Z\n1 bit", C.accent2, C.text1, 10);
  node(s, 1.45, 1.62, 2.2, 0.6, "Length\n31 bits, big-endian", C.accent1, C.background1, 10);
  node(s, 3.7, 1.62, 5.8, 0.6, 'Body: UTF-8 JSON, for example {"type":"ADD","msg_id":"a7","rn":12,"obj":{...}}', C.text1, C.background1, 10);
  label(s, 0.5, 2.26, 3.15, "4-byte header", C.text2);
  label(s, 3.7, 2.26, 5.8, "Z = 1 means the body is zlib-compressed (only when that makes it smaller)", C.text2);
  const hdr = (t) => ({ text: t, options: { bold: true, color: C.background1, fill: { color: C.text1 } } });
  const rows = [[hdr("Group"), hdr("Messages"), hdr("Purpose")],
    ["Session", "REGISTER, LOGIN, JOIN_ROOM, JOIN_OK", "Authenticate, enter a room, receive the full board"],
    ["Board changes", "ADD, ERASE, UNDO, REDO then ACK", "Every change is numbered by the server and acknowledged"],
    ["Recovery", "RESYNC_REQ, OPS_SINCE, SNAPSHOT", "Fetch missed operations after a gap or a reconnect"],
    ["Liveness", "PING, PONG", "Round-trip time, timeout detection, sequence check"],
    ["Ephemeral", "CURSOR, LIVE, LASER", "Low-priority previews that may be dropped"]];
  s.addTable(rows, { x: 0.5, y: 2.7, w: 9, colW: [1.5, 3.4, 4.1], fontSize: 10.5, color: C.text2, fill: { color: C.background1 },
    border: { type: "solid", color: "DDE5EE", pt: 0.75 }, rowH: 0.36, valign: "middle", objectName: nm("Message table") });
}

// ---------------------------------------------------------------- 6 consistency
{
  const s = slide("How every screen stays identical", "Consistency",
    "The server is the single source of order. A client never decides the final position of its own change. It sends a request, the server appends it to the room's operation log with the next sequence number and broadcasts it. Every client applies operations strictly in sequence order, so all boards converge.");
  const steps = [["Client draws", "Stroke shown locally at once, sent as ADD with a message id", C.accent3],
                 ["Server orders", "Appended to the room's op log with the next sequence number", C.accent1],
                 ["Server stores", "Written to SQLite and streamed to the standby", C.accent1],
                 ["Broadcast", "Sent to every member; the author gets an ACK", C.accent2],
                 ["Clients apply", "Applied strictly in sequence order; a gap triggers a resync", C.accent3]];
  const w = 1.64, gap = 0.2;
  steps.forEach(([h, b, c], i) => {
    const x = 0.5 + i * (w + gap);
    box(s, x, 1.5, w, 2.0);
    num(s, x + 0.15, 1.65, i + 1, c);
    s.addText(h, { x: x + 0.15, y: 2.1, w: w - 0.3, h: 0.3, fontSize: 12.5, bold: true, color: C.text1, margin: 0, isTextBox: true, objectName: nm("Step head") });
    s.addText(b, { x: x + 0.15, y: 2.42, w: w - 0.3, h: 1.0, fontSize: 10.5, color: C.text2, margin: 0, isTextBox: true, valign: "top", objectName: nm("Step body") });
    if (i < 4) link(s, x + w + 0.02, 2.5, x + w + gap - 0.02, 2.5, C.accent6);
  });
  box(s, 0.5, 3.8, 9, 0.95, C.text1);
  s.addText([{ text: "Why not let clients talk to each other directly?  ", options: { bold: true, color: C.accent2 } },
    { text: "With one sequencer there is exactly one order of events, so there is nothing to merge. It is the same idea as a primary in state-machine replication, and it is why a late joiner can rebuild the board by replaying the log.", options: { color: C.background1 } }],
    { x: 0.7, y: 3.85, w: 8.6, h: 0.85, fontSize: 11.5, margin: 0, isTextBox: true, valign: "middle", objectName: nm("Callout") });
}

// ---------------------------------------------------------------- 7 reliability
sec("Reliability");
{
  const s = slide("Reliability above TCP: what we had to add", "Reliability",
    "TCP is reliable only while one connection lives. Across a reconnect, a failover or a slow client, the application can still lose or repeat messages. These five mechanisms are the same ideas as in the transport layer, rebuilt at the application layer. The screenshot is our own inspector showing a real exchange.");
  const r = [["Message ids and ACKs", "Each request stays in an outbox until the server acknowledges it"],
             ["Retransmission timer", "RTO = 3 x average RTT, kept between 0.6 s and 3 s, doubled on each retry"],
             ["Duplicate filter", "The server remembers message ids, so a resend is never applied twice"],
             ["Reorder buffer", "Per-client request numbers; early arrivals are held until the gap is filled"],
             ["Gap detection and resync", "A missing sequence number or a heartbeat mismatch fetches the missed operations"]];
  r.forEach(([h, b], i) => row(s, 0.5, 1.35 + i * 0.7, 4.3, i + 1, h, b, C.accent2));
  img(s, "sequence", 5.1, 1.35, 4.4, 3.1, "Sequence diagram from the packet inspector showing requests, ACKs and a retransmission");
  cap(s, 5.1, 4.55, 4.4, "Built-in inspector: sequence diagram of a live session");
}

// ---------------------------------------------------------------- 8 chaos lab
{
  const s = slide("Chaos lab: we break the network on purpose", "Reliability, proven",
    "A LAN in a lab is too good to show reliability, so the host can inject loss, delay, jitter and a bandwidth cap for one room. The server drops and delays real messages. In our test at 30 percent loss with 120 plus or minus 40 milliseconds of delay, two clients drew 24 strokes and every one arrived exactly once on both boards.");
  img(s, "chaos", 0.5, 1.3, 3.2, 3.5, "Chaos lab window with a network map, loss and delay sliders and repair counters");
  box(s, 4.0, 1.35, 5.5, 1.45);
  stat(s, 4.05, 1.5, 1.8, "30%", "messages dropped by the server", C.accent4);
  stat(s, 5.85, 1.5, 1.8, "120 ms", "added delay, with 40 ms jitter", C.accent2);
  stat(s, 7.65, 1.5, 1.8, "24 / 24", "strokes arrived exactly once", C.accent1);
  s.addText([
    { text: "The host sets loss, delay, jitter and a bandwidth cap for one room.", options: { bullet: { indent: 14 }, breakLine: true } },
    { text: "Counters show the damage done and how the client repaired it: retransmissions, duplicate ACKs, resyncs.", options: { bullet: { indent: 14 }, breakLine: true } },
    { text: "The last line compares the client's sequence number with the server's: IN SYNC.", options: { bullet: { indent: 14 }, breakLine: true } },
    { text: "The live map colours each link by its measured round-trip time.", options: { bullet: { indent: 14 } } },
  ], { x: 4.0, y: 3.0, w: 5.5, h: 1.8, fontSize: 12, color: C.text2, margin: 0, isTextBox: true, valign: "top", paraSpaceAfter: 5, objectName: nm("Body") });
}

// ---------------------------------------------------------------- 9 failover
{
  const s = slide("The server dies and the session carries on", "Fault tolerance",
    "A standby server connects to the primary with a shared cluster key and receives every operation as it happens. Clients learn the standby's address and certificate fingerprint when they join. When the primary stops answering, clients reconnect to the standby and resend anything unacknowledged. In our test the switch took about 1.1 seconds. Replication is asynchronous and there is no automatic fail-back.");
  // diagram
  node(s, 0.5, 1.45, 1.7, 0.65, "Primary", C.accent4, C.background1, 12);
  node(s, 2.9, 1.45, 1.7, 0.65, "Standby", C.accent1, C.background1, 12);
  link(s, 2.25, 1.78, 2.85, 1.78, C.accent6, { dash: true });
  label(s, 1.95, 1.22, 1.2, "replication", C.text2, { fs: 8.5 });
  node(s, 0.5, 3.0, 1.7, 0.55, "Client A", C.accent3, C.background1, 11);
  node(s, 2.9, 3.0, 1.7, 0.55, "Client B", C.accent3, C.background1, 11);
  link(s, 1.35, 2.95, 1.35, 2.15, C.accent4, { dash: true });
  link(s, 3.75, 2.95, 3.75, 2.15, C.accent1);
  link(s, 1.7, 2.95, 3.3, 2.15, C.accent1);
  label(s, 0.5, 2.42, 0.8, "lost", C.accent4, { bold: true });
  label(s, 3.85, 2.42, 0.9, "failover", C.accent1, { bold: true });
  box(s, 0.5, 3.8, 4.1, 1.0);
  stat(s, 0.5, 3.82, 2.05, "1.1 s", "client failover in our test", C.accent1);
  stat(s, 2.55, 3.82, 2.05, "0", "strokes lost", C.accent1);
  img(s, "failover", 4.9, 1.35, 4.6, 2.55, "Client after failover: chat shows it is now connected to the standby server");
  cap(s, 4.9, 3.98, 4.6, "After the primary was killed: FAILOVER in chat, drawing continues");
  s.addText("Limits: replication is asynchronous and fail-back is manual.", { x: 4.9, y: 4.35, w: 4.6, h: 0.4, fontSize: 10.5, color: C.text2, margin: 0, isTextBox: true, objectName: nm("Limits") });
}

// ---------------------------------------------------------------- 10 security
sec("Security");
{
  const s = slide("Four layers of security, all written by hand", "Security",
    "Passwords are never stored, only a salted PBKDF2 hash. Login returns a JWT that we sign and verify ourselves with HMAC-SHA256. Everything travels inside TLS with a self-signed certificate that clients pin on first use. On top, a room can turn on end-to-end encryption so even the server only stores ciphertext.");
  const L = [["Accounts", "PBKDF2-HMAC-SHA256, random salt, 200,000 rounds. Constant-time compare, login rate limit.", C.accent3],
             ["Tokens", "Hand-written JWT (HS256), valid 24 h. The user name comes from the verified token, so nobody can draw as someone else.", C.accent1],
             ["Transport", "TLS on the TCP port. Self-signed certificate, trust on first use, warning if the fingerprint changes.", C.accent2],
             ["End to end", "Optional room key. Drawings and chat are encrypted on the client; the server relays and stores only ciphertext.", C.accent5]];
  L.forEach(([h, b, c], i) => card(s, 0.5, 1.35 + i * 0.87, 4.3, 0.78, h, b, c, { bs: 10, hs: 12 }));
  // fix card body offset for short cards
  img(s, "e2e", 5.1, 1.35, 4.4, 2.5, "Client with end-to-end encryption on; a member without the key sees an encrypted message notice");
  cap(s, 5.1, 3.95, 4.4, "E2E on: without the key, chat shows only an encrypted notice");
  s.addText("E2E design: key from the passphrase with PBKDF2, HMAC-SHA256 in counter mode, encrypt-then-MAC. Standard library only.",
    { x: 5.1, y: 4.3, w: 4.4, h: 0.5, fontSize: 10, color: C.text2, margin: 0, isTextBox: true, objectName: nm("E2E note") });
}

// ---------------------------------------------------------------- 11 phone join
sec("Beyond the brief");
{
  const s = slide("Join from a phone: our own WebSocket server", "Beyond the brief",
    "A browser cannot open a raw TCP socket, so we wrote an HTTP and WebSocket server by hand using only the standard library. The handshake is the SHA-1 of the client's key plus a fixed GUID. After the 101 response the same TCP connection carries WebSocket frames, each holding the same JSON our desktop client sends. The host shows a QR code containing a one-hour invite token.");
  img(s, "phone", 0.5, 1.3, 1.75, 3.5, "The whiteboard running in a phone browser");
  img(s, "qr", 2.5, 1.3, 2.4, 2.15, "Phone join window showing a QR code and the invite link");
  cap(s, 2.5, 3.55, 2.4, "Scan to join, no install");
  const r = [["HTTP GET /", "The server sends one self-contained HTML page: the web client"],
             ["Upgrade handshake", "Sec-WebSocket-Accept = base64(SHA-1(key + GUID)), then 101 Switching Protocols"],
             ["WebSocket frames", "We parse FIN, opcode, length and the 4-byte mask ourselves (RFC 6455)"],
             ["Same room logic", "Each frame carries the same JSON message, so the room cannot tell the clients apart"]];
  r.forEach(([h, b], i) => row(s, 5.2, 1.35 + i * 0.72, 4.3, i + 1, h, b, C.accent5));
  s.addText("Invite link carries a 1-hour JWT; guests appear as \"name (web)\".", { x: 5.2, y: 4.35, w: 4.3, h: 0.4, fontSize: 10.5, italic: true, color: C.text2, margin: 0, isTextBox: true, objectName: nm("Note") });
}

// ---------------------------------------------------------------- 12 inspector + replay
{
  const s = slide("See the protocol: packet inspector and replay", "Beyond the brief",
    "The inspector lists every frame the client sends and receives with its type, size, sequence number and whether it was compressed or retransmitted. Replay asks the server for the room's operation log and lets you scrub through the whole session, which also demonstrates that the log alone is enough to rebuild the board.");
  img(s, "inspector", 0.5, 1.35, 4.35, 2.75, "Packet inspector listing frames with direction, type, size and sequence numbers");
  img(s, "replay", 5.15, 1.35, 4.35, 2.75, "Replay window with a timeline slider over the session's operations");
  s.addText([{ text: "Packet inspector  ", options: { bold: true, color: C.text1 } }, { text: "Every frame in and out: type, bytes on the wire, sequence number, zlib flag, retransmissions in red.", options: { color: C.text2 } }],
    { x: 0.5, y: 4.25, w: 4.35, h: 0.6, fontSize: 11, margin: 0, isTextBox: true, valign: "top", objectName: nm("Caption") });
  s.addText([{ text: "Time-travel replay  ", options: { bold: true, color: C.text1 } }, { text: "The server returns the op log and the client rebuilds the board at any point in time.", options: { color: C.text2 } }],
    { x: 5.15, y: 4.25, w: 4.35, h: 0.6, fontSize: 11, margin: 0, isTextBox: true, valign: "top", objectName: nm("Caption") });
}

// ---------------------------------------------------------------- 13 performance
{
  const s = slide("Fewer bytes, and the important bytes first", "Performance and QoS",
    "Two ideas. First, send less: frames are zlib-compressed when that helps, and pen strokes are simplified with the Ramer-Douglas-Peucker algorithm before sending. Second, when the link is slow, send the right thing first: board operations go in a high-priority queue, cursors and previews in a low-priority one, and stale low-priority frames are dropped. Numbers are from our own tests.");
  s.addChart(pres.charts.BAR, [{ name: "Bytes on the wire", labels: ["JOIN_OK frame, raw", "JOIN_OK frame, zlib"], values: [14367, 3906] }], {
    x: 0.5, y: 1.3, w: 4.4, h: 3.5, barDir: "col", chartColors: [THEME.colors.accent1], showTitle: true, title: "Joining a room: bytes on the wire",
    titleFontSize: 12, titleColor: THEME.colors.dk1, titleFontFace: "+mn-lt", showValue: true, dataLabelPosition: "outEnd", dataLabelFontSize: 11, dataLabelFontFace: "+mn-lt",
    dataLabelColor: THEME.colors.dk1, dataLabelFormatCode: "#,##0", catAxisLabelColor: THEME.colors.dk2, valAxisLabelColor: THEME.colors.dk2, catAxisLabelFontFace: "+mn-lt", valAxisLabelFontFace: "+mn-lt",
    catAxisLabelFontSize: 10, valAxisLabelFontSize: 9, valGridLine: { color: "DDE5EE", size: 0.5 }, catGridLine: { style: "none" }, showLegend: false, barGapWidthPct: 80,
    plotArea: { fill: { color: "FFFFFF" } }, objectName: nm("Compression chart") });
  box(s, 5.2, 1.35, 4.3, 1.4);
  stat(s, 5.25, 1.48, 1.4, "73%", "smaller join frame", C.accent1);
  stat(s, 6.65, 1.48, 1.4, "2.2x", "fewer points per stroke (480 to 216)", C.accent3);
  stat(s, 8.05, 1.48, 1.4, "42", "stale cursors shed", C.accent2);
  // fix: middle stat is long -> smaller font handled below
  const r = [["Compression flag", "Top bit of the length prefix marks a zlib body; negotiated at join"],
             ["Stroke simplification", "Ramer-Douglas-Peucker removes points that do not change the shape"],
             ["Two-priority send queues", "On a 16 kbit/s link a stroke overtook queued cursor updates"]];
  r.forEach(([h, b], i) => row(s, 5.2, 2.95 + i * 0.63, 4.3, i + 1, h, b));
}

// ---------------------------------------------------------------- 14 voice + p2p
{
  const s = slide("Choosing the transport: UDP for voice, direct TCP for files", "Beyond the brief",
    "Two features that show transport choice. Voice uses UDP because a late audio packet is useless, so we never retransmit; a jitter buffer smooths arrival times and we measure jitter the RFC 3550 way. File transfer uses the server only for signalling: the offer and the answer. The bytes go over a direct TCP connection between the two PCs, with resume and a SHA-256 check.");
  card(s, 0.5, 1.35, 4.35, 1.75, "Voice chat over UDP", "8 kHz G.711 mu-law, one packet every 20 ms, relayed by the server on UDP 5053. Sequence numbers and timestamps feed a jitter buffer. Lost packets are concealed, never resent.", C.accent1, { bs: 12.5, hs: 14 });
  card(s, 5.15, 1.35, 4.35, 1.75, "Peer-to-peer file transfer", "The server only carries FILE_OFFER and FILE_REPLY (signalling). The file travels on a direct TCP connection between the two clients, resumes after a break and is verified with SHA-256.", C.accent3, { bs: 12.5, hs: 14 });
  box(s, 0.5, 3.3, 4.35, 1.5);
  stat(s, 0.55, 3.45, 2.1, "100 / 100", "voice packets delivered on a clean link", C.accent1);
  stat(s, 2.7, 3.45, 2.1, "30% loss", "stream kept playing without stalling", C.accent2);
  box(s, 5.15, 3.3, 4.35, 1.5);
  stat(s, 5.2, 3.45, 2.1, "3 MB", "file sent, interrupted and resumed", C.accent3);
  stat(s, 7.35, 3.45, 2.1, "SHA-256", "matched after the transfer", C.accent3);
}

// ---------------------------------------------------------------- 15 operations
{
  const s = slide("Tools for the person running the server", "Operations",
    "Connection diagnostics answers the question 'why can't I connect' one layer at a time: addresses, TCP handshake, TLS, our PING, the web port, UDP discovery and the route. It distinguishes a refused connection from a timeout, which point to different causes. The admin dashboard is served by the same hand-written HTTP server. The server also listens on IPv4 and IPv6.");
  img(s, "dash", 0.5, 1.35, 4.35, 2.9, "Browser admin dashboard with rooms, clients, traffic and recent events");
  cap(s, 0.5, 4.35, 4.35, "Admin dashboard in a browser, protected by a key");
  img(s, "diag", 5.15, 1.35, 4.35, 1.65, "Diagnose connection output listing checks from addresses up to the application layer");
  cap(s, 5.15, 3.08, 4.35, "Diagnose connection: one check per layer");
  const r = [["Refused or timed out?", "RST means no server on that port; silence means wrong IP or a firewall"],
             ["Dual stack", "One listening socket accepts IPv4 and IPv6 clients"]];
  r.forEach(([h, b], i) => row(s, 5.15, 3.5 + i * 0.65, 4.35, i + 1, h, b));
}

// ---------------------------------------------------------------- 16 CN concepts
sec("Wrap-up");
{
  const s = slide("Course concepts and where they live in the code", "Syllabus map",
    "This is the slide for viva questions. Each row is a topic from the course and the place in our project where we implemented it ourselves rather than calling a library.");
  const hdr = (t) => ({ text: t, options: { bold: true, color: C.background1, fill: { color: C.text1 } } });
  const b = (t) => ({ text: t, options: { bold: true, color: C.text1 } });
  const rows = [[hdr("Layer / topic"), hdr("Concept"), hdr("In our project")],
    [b("Application"), "Protocol design, HTTP, WebSocket", "Length-prefixed JSON protocol, hand-written HTTP/1.1 and RFC 6455 server"],
    [b("Transport"), "TCP vs UDP, framing, sockets", "TCP for board data, UDP for discovery and voice, one thread per client"],
    [b("Reliability"), "ACK, timeout, retransmission, ordering", "Message ids, adaptive RTO with backoff, reorder buffer, resync"],
    [b("Flow and congestion"), "Queues, rate limiting, QoS", "Per-client priority queues, token bucket, shedding of stale frames"],
    [b("Network"), "IPv4 / IPv6, broadcast, routing", "Dual-stack listener, UDP broadcast discovery, traceroute in diagnostics"],
    [b("Security"), "Hashing, MAC, TLS, tokens", "PBKDF2, HMAC-signed JWT, TLS with pinning, end-to-end encryption"],
    [b("Distributed systems"), "Replication, failover", "Primary and hot standby with client failover"]];
  s.addTable(rows, { x: 0.5, y: 1.35, w: 9, colW: [1.9, 2.9, 4.2], fontSize: 10.5, color: C.text2, fill: { color: C.background1 },
    border: { type: "solid", color: "DDE5EE", pt: 0.75 }, rowH: 0.42, valign: "middle", objectName: nm("Concept table") });
}

// ---------------------------------------------------------------- 17 testing & limits
{
  const s = slide("How we tested it, and what is still open", "Testing and limits",
    "Be straightforward here. The automated tests start real servers and real clients, including the GUI under a virtual display, and cover the features on the left. The items on the right are known limits or things we have not been able to verify in the test environment. Update this slide after the Windows and phone checks.");
  box(s, 0.5, 1.35, 4.35, 3.45);
  s.addText("Automated tests", { x: 0.7, y: 1.45, w: 4, h: 0.3, fontSize: 13, bold: true, color: C.accent1, margin: 0, isTextBox: true, objectName: nm("Head") });
  s.addText([
    { text: "13 test scripts start real servers and clients over real sockets", options: { bullet: { indent: 14 }, breakLine: true } },
    { text: "Protocol, rooms, undo, persistence and restart", options: { bullet: { indent: 14 }, breakLine: true } },
    { text: "Accounts, JWT tampering, TLS and certificate change", options: { bullet: { indent: 14 }, breakLine: true } },
    { text: "Loss, delay and reordering through the chaos lab", options: { bullet: { indent: 14 }, breakLine: true } },
    { text: "Failover, WebSocket join, file transfer, voice relay, E2E", options: { bullet: { indent: 14 }, breakLine: true } },
    { text: "GUI tests drive the real Tkinter client", options: { bullet: { indent: 14 } } },
  ], { x: 0.7, y: 1.8, w: 4.0, h: 2.9, fontSize: 13, color: C.text2, margin: 0, isTextBox: true, valign: "top", paraSpaceAfter: 8, objectName: nm("Body") });
  box(s, 5.15, 1.35, 4.35, 3.45);
  s.addText("Known limits", { x: 5.35, y: 1.45, w: 4, h: 0.3, fontSize: 13, bold: true, color: C.accent4, margin: 0, isTextBox: true, objectName: nm("Head") });
  s.addText([
    { text: "The server is the single sequencer: simple and consistent, but all traffic passes through it", options: { bullet: { indent: 14 }, breakLine: true } },
    { text: "Replication to the standby is asynchronous; fail-back is manual", options: { bullet: { indent: 14 }, breakLine: true } },
    { text: "The web page is served over plain HTTP on the LAN", options: { bullet: { indent: 14 }, breakLine: true } },
    { text: "Self-signed certificate: trust on first use, no certificate authority", options: { bullet: { indent: 14 }, breakLine: true } },
    { text: "Voice is narrow-band and has no echo cancellation", options: { bullet: { indent: 14 } } },
  ], { x: 5.35, y: 1.8, w: 4.0, h: 2.9, fontSize: 13, color: C.text2, margin: 0, isTextBox: true, valign: "top", paraSpaceAfter: 8, objectName: nm("Body") });
}

// ---------------------------------------------------------------- 18 demo
{
  const s = slide("Live demo in three minutes", "Demo",
    "Demo order. Start the primary and the standby before the talk. Keep the Chaos lab on the Bad link preset ready. If the phone cannot join because of the lab Wi-Fi, use a browser on a second laptop with the same link.", "CONTENT_DARK");
  const st = [["Join", "Two desktop clients and a phone scan the QR code and draw together"],
              ["Break", "Chaos lab on Bad link: latency turns red, counters climb, boards stay identical"],
              ["Inspect", "Sequence diagram shows a retransmission in red and a zlib frame"],
              ["Replay", "Scrub through the whole session from the op log"],
              ["Kill", "Stop the primary server: clients fail over and drawing continues"]];
  const w = 1.64, gap = 0.2;
  st.forEach(([h, b], i) => {
    const x = 0.5 + i * (w + gap);
    box(s, x, 1.6, w, 2.6, C.text2, { noShadow: true });
    num(s, x + 0.15, 1.78, i + 1, i === 4 ? C.accent4 : C.accent1, 0.42);
    s.addText(h, { x: x + 0.15, y: 2.35, w: w - 0.3, h: 0.35, fontSize: 15, bold: true, color: C.background1, margin: 0, isTextBox: true, objectName: nm("Step head") });
    s.addText(b, { x: x + 0.15, y: 2.75, w: w - 0.3, h: 1.35, fontSize: 11, color: C.background2, margin: 0, isTextBox: true, valign: "top", objectName: nm("Step body") });
  });
  s.addText("Ports to allow in the firewall: TCP 5050, UDP 5051, TCP 8080, UDP 5053", { x: 0.5, y: 4.5, w: 9, h: 0.3, fontSize: 11, color: C.accent6, margin: 0, isTextBox: true, objectName: nm("Ports") });
}

// ---------------------------------------------------------------- 19 conclusion
{
  const s = slide("What we built and what we learned", "Conclusion",
    "Close with the three takeaways, then invite questions. If asked what we would do next: synchronous replication with automatic fail-back, HTTPS for the web client, and a wider-band voice codec.", "CONTENT_DARK");
  const t = [["A complete product", "Shared board with rooms, roles, history, persistence and accounts, on Windows, Linux and phones."],
             ["Networking written by hand", "Our own framing, reliability, WebSocket server, TLS pinning, replication and voice transport on plain sockets."],
             ["Measured, not claimed", "Loss, delay and server failure are injected on purpose and the repair is shown on screen."]];
  t.forEach(([h, b], i) => {
    const x = 0.5 + i * 3.07;
    box(s, x, 1.5, 2.86, 2.2, C.text2, { noShadow: true });
    num(s, x + 0.18, 1.68, i + 1, C.accent2, 0.42);
    s.addText(h, { x: x + 0.18, y: 2.22, w: 2.5, h: 0.35, fontSize: 14, bold: true, color: C.background1, margin: 0, isTextBox: true, objectName: nm("Head") });
    s.addText(b, { x: x + 0.18, y: 2.6, w: 2.5, h: 1.0, fontSize: 11, color: C.background2, margin: 0, isTextBox: true, valign: "top", objectName: nm("Body") });
  });
  s.addText("Thank you. Questions?", { x: 0.5, y: 4.05, w: 9, h: 0.6, fontSize: 26, bold: true, color: C.accent2, margin: 0, isTextBox: true, objectName: nm("Thanks") });
}

(async () => {
  await pres.writeFile({ fileName: OUT });
  await applyTheme(OUT, THEME);
  console.log("wrote", OUT);
})();
