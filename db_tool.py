"""Look inside the server's database (safe to run while the server is running).

  python db_tool.py                    list rooms with counts
  python db_tool.py ROOMCODE           details of one room: members, op log summary, chat, versions
  python db_tool.py --sql "SELECT ..." run any SQL query (e.g. for screenshots in the report)
  add --db path/to/whiteboard.db if the file is somewhere else
"""
import argparse
import sqlite3
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("room", nargs="?")
    ap.add_argument("--db", default="whiteboard.db")
    ap.add_argument("--sql")
    a = ap.parse_args()
    con = sqlite3.connect(f"file:{a.db}?mode=ro", uri=True)

    if a.sql:
        cur = con.execute(a.sql)
        print(" | ".join(d[0] for d in cur.description))
        for row in cur:
            print(" | ".join(str(v)[:60] for v in row))
        return

    if not a.room:
        print(f"{'room':6} {'host':14} {'created':17} {'members':>7} {'ops':>6} {'chat':>5} {'versions':>8}  password")
        for code, host, created, pw in con.execute("SELECT code, host, created, password FROM rooms ORDER BY created"):
            n = lambda t: con.execute(f"SELECT COUNT(*) FROM {t} WHERE room=?", (code,)).fetchone()[0]
            print(f"{code:6} {host:14} {time.strftime('%Y-%m-%d %H:%M', time.localtime(created)):17} "
                  f"{n('members'):7} {n('ops'):6} {n('chat'):5} {n('versions'):8}  {'yes' if pw else 'no'}")
        return

    code = a.room.upper()
    print(f"Room {code}")
    print("\nMembers:")
    for name, color, role in con.execute("SELECT name, color, role FROM members WHERE room=?", (code,)):
        print(f"  {name:16} {role:7} {color}")
    for (name,) in con.execute("SELECT name FROM banned WHERE room=?", (code,)):
        print(f"  {name:16} (kicked)")
    print("\nOp log by user and kind:")
    for by, kind, cnt in con.execute("SELECT by, kind, COUNT(*) FROM ops WHERE room=? GROUP BY by, kind", (code,)):
        print(f"  {by or '-':16} {kind:4} {cnt}")
    print("\nLast 10 ops:")
    for seq, ts, by, kind, size in con.execute(
            "SELECT seq, ts, by, kind, LENGTH(body) FROM ops WHERE room=? ORDER BY seq DESC LIMIT 10", (code,)):
        print(f"  seq {seq:5}  {time.strftime('%H:%M:%S', time.localtime(ts))}  {by or '-':12} {kind:4} {size} bytes")
    print("\nChat:")
    for ts, user, text in con.execute("SELECT ts, user, text FROM chat WHERE room=? ORDER BY id", (code,)):
        print(f"  [{ts}] {user}: {text}")
    print("\nVersions:")
    for vid, label, ts, seq in con.execute("SELECT id, label, ts, seq FROM versions WHERE room=? ORDER BY id", (code,)):
        print(f"  #{vid:<3} {ts}  {label}  (at seq {seq})")


if __name__ == "__main__":
    main()
