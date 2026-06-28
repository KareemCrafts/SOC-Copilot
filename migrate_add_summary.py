import sqlite3
conn = sqlite3.connect("soc_copilot.db")
cur = conn.cursor()
try:
    cur.execute("ALTER TABLE incidents ADD COLUMN ai_summary TEXT")
    conn.commit()
    print("[+] Column added")
except sqlite3.OperationalError as e:
    print(f"[!] {e}")
conn.close()