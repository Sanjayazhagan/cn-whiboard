-- Wireshark dissector for the LAN Whiteboard protocol (CN lab project).
--
-- TCP 5050: every message = 4-byte big-endian length + UTF-8 JSON body.
--           One TCP segment can carry several messages, and one big message
--           (e.g. JOIN_OK with a snapshot) is split over many segments;
--           dissect_tcp_pdus() reassembles them using the length prefix.
-- UDP 5051: LAN discovery (WB_DISCOVER_V1 broadcast, JSON WB_SERVER reply).
--
-- With TLS on (the default) the TCP payload is encrypted: Wireshark shows only TLS records.
-- To see inside for the report, start the CLIENT with the environment variable
-- SSLKEYLOGFILE=C:\path\keys.log (Linux: SSLKEYLOGFILE=~/keys.log python client.py) and set
-- Edit > Preferences > Protocols > TLS > (Pre)-Master-Secret log filename to that file;
-- the decrypted messages are then shown by this dissector too.
--
-- Install: copy this file into Wireshark's personal plugins folder
--   Windows: %APPDATA%\Wireshark\plugins\        Linux: ~/.local/lib/wireshark/plugins/
-- (Help > About Wireshark > Folders shows the exact path), then restart Wireshark
-- or press Ctrl+Shift+L. Display filter examples:  whiteboard   whiteboard.type == "OP"
-- If you run the server on another port: Edit > Preferences > Protocols > WHITEBOARD.

local wb = Proto("whiteboard", "LAN Whiteboard Protocol")
local f_len    = ProtoField.uint32("whiteboard.length", "Body length (bytes)", base.DEC)
local f_type   = ProtoField.string("whiteboard.type", "Message type")
local f_op     = ProtoField.string("whiteboard.op", "Canvas op")
local f_seq    = ProtoField.uint32("whiteboard.seq", "Sequence number", base.DEC)
local f_msgid  = ProtoField.string("whiteboard.msg_id", "msg_id")
local f_user   = ProtoField.string("whiteboard.user", "User")
local f_body   = ProtoField.string("whiteboard.json", "JSON body")
wb.fields = { f_len, f_type, f_op, f_seq, f_msgid, f_user, f_body }
wb.prefs.port = Pref.uint("TCP port", 5050, "Whiteboard server TCP port")

local json = Dissector.get("json")
local tls = Dissector.get("tls")

local function pdu_len(tvb, pinfo, offset)
    return tvb(offset, 4):uint() + 4
end

local function dissect_pdu(tvb, pinfo, tree)
    local len = tvb(0, 4):uint()
    local body = tvb(4, len)
    -- only look at the start of huge bodies (snapshots, images) for the summary fields
    local head = body:range(0, math.min(len, 400)):string()
    local typ = head:match('^{"type":"([^"]+)"') or head:match('"type":"([^"]+)"') or "?"
    local op = head:match('"op":"([^"]+)"')
    local seq = head:match('"seq":(%d+)')
    local mid = head:match('"msg_id":"([^"]+)"')
    local user = head:match('"user":"([^"]+)"') or head:match('"by":"([^"]+)"')

    local label = typ
    if op then label = label .. " " .. op end
    if seq then label = label .. " seq=" .. seq end
    local t = tree:add(wb, tvb(0, len + 4), "LAN Whiteboard: " .. label .. " (" .. len .. " bytes)")
    t:add(f_len, tvb(0, 4))
    t:add(f_type, body, typ)
    if op then t:add(f_op, body, op) end
    if seq then t:add(f_seq, body, tonumber(seq)) end
    if mid then t:add(f_msgid, body, mid) end
    if user then t:add(f_user, body, user) end
    local before = tostring(pinfo.cols.info)
    if json and len < 65536 then
        json:call(body:tvb(), pinfo, t)          -- full JSON tree (the JSON dissector also edits the columns)
    else
        t:add(f_body, body, head .. (len > 400 and " ..." or ""))
    end
    pinfo.cols.protocol = "WHITEBOARD"
    pinfo.cols.info:set(before .. label .. "  ")
    return len + 4
end

function wb.dissector(tvb, pinfo, tree)
    -- A TLS record starts with content type 20-23 and version 3.x. Our own frames start with a 4-byte
    -- length, and a first byte of 20-23 would mean a frame of >300 MB, which never happens.
    local first = tvb(0, 1):uint()
    if tvb:len() >= 2 and first >= 20 and first <= 23 and tvb(1, 1):uint() == 3 then
        return tls:call(tvb, pinfo, tree)
    end
    pinfo.cols.protocol = "WHITEBOARD"
    pinfo.cols.info:set(pinfo.src_port == wb.prefs.port and "S->C  " or "C->S  ")
    dissect_tcp_pdus(tvb, tree, 4, pdu_len, dissect_pdu, true)
    return tvb:len()
end

local tcp_table = DissectorTable.get("tcp.port")
local tls_table = DissectorTable.get("tls.port")      -- decrypted TLS payload on this port comes back to us
local current_port = 5050
tcp_table:add(current_port, wb)
tls_table:add(current_port, wb)
function wb.prefs_changed()
    tcp_table:remove(current_port, wb)
    tls_table:remove(current_port, wb)
    current_port = wb.prefs.port
    tcp_table:add(current_port, wb)
    tls_table:add(current_port, wb)
end

-- UDP discovery
local disc = Proto("whiteboard_disc", "LAN Whiteboard Discovery")
local d_kind = ProtoField.string("whiteboard_disc.kind", "Kind")
local d_text = ProtoField.string("whiteboard_disc.payload", "Payload")
disc.fields = { d_kind, d_text }

function disc.dissector(tvb, pinfo, tree)
    pinfo.cols.protocol = "WB-DISCOVERY"
    local s = tvb():string()
    local kind = s:find("WB_DISCOVER", 1, true) == 1 and "DISCOVER (broadcast request)" or "WB_SERVER (reply)"
    local t = tree:add(disc, tvb(), "LAN Whiteboard Discovery: " .. kind)
    t:add(d_kind, tvb(), kind)
    t:add(d_text, tvb(), s)
    pinfo.cols.info:set(kind .. "  " .. s)
    return tvb:len()
end
DissectorTable.get("udp.port"):add(5051, disc)
