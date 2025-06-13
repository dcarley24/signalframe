import sqlite3
from datetime import datetime

def check_alerts(db):
    with sqlite3.connect(db) as conn:
        c = conn.cursor()
        c.execute("SELECT value FROM config WHERE key = 'active_dataset'")
        dataset = c.fetchone()[0]

        c.execute("SELECT ip, COUNT(*) FROM logs WHERE dataset = ? GROUP BY ip HAVING COUNT(*) > 5", (dataset,))
        suspicious_ips = c.fetchall()
        for ip, count in suspicious_ips:
            msg = f"High volume from {ip} ({count} requests)"
            now = datetime.now().isoformat()
            c.execute("SELECT COUNT(*) FROM alerts WHERE message = ? AND dataset = ?", (msg, dataset))
            if c.fetchone()[0] == 0:
                c.execute("INSERT INTO alerts (message, timestamp, dataset) VALUES (?, ?, ?)", (msg, now, dataset))
