import sqlite3
from datetime import datetime

def run_playbooks(db):
    with sqlite3.connect(db) as conn:
        c = conn.cursor()
        c.execute("SELECT value FROM config WHERE key = 'active_dataset'")
        dataset = c.fetchone()[0]

        # Playbook 1: Block IPs with >10 log entries
        c.execute("SELECT ip, COUNT(*) FROM logs WHERE dataset = ? GROUP BY ip HAVING COUNT(*) > 10", (dataset,))
        offenders = c.fetchall()
        for ip, count in offenders:
            description = f"Blocked IP {ip} due to excessive activity ({count} logs)"
            timestamp = datetime.now().isoformat()
            c.execute("SELECT COUNT(*) FROM playbook_actions WHERE description = ? AND dataset = ?", (description, dataset))
            if c.fetchone()[0] == 0:
                c.execute("INSERT INTO playbook_actions (name, description, timestamp, dataset) VALUES (?, ?, ?, ?)",
                          ("Block Repetitive IP", description, timestamp, dataset))

        # Playbook 2: Escalate IPs with 10+ non-BENIGN label entries
        c.execute("SELECT ip, COUNT(*) FROM logs WHERE dataset = ? AND action != 'BENIGN' GROUP BY ip HAVING COUNT(*) >= 10", (dataset,))
        suspicious = c.fetchall()
        for ip, count in suspicious:
            description = f"Escalated IP {ip} due to {count} suspicious Label entries"
            timestamp = datetime.now().isoformat()
            c.execute("SELECT COUNT(*) FROM playbook_actions WHERE description = ? AND dataset = ?", (description, dataset))
            if c.fetchone()[0] == 0:
                c.execute("INSERT INTO playbook_actions (name, description, timestamp, dataset) VALUES (?, ?, ?, ?)",
                          ("Escalate Suspicious Label Activity", description, timestamp, dataset))

        # Playbook 3: Detect port scanning (IP hitting 10+ unique ports)
        c.execute("SELECT ip, COUNT(DISTINCT dst_port) FROM logs WHERE dataset = ? AND dst_port IS NOT NULL GROUP BY ip HAVING COUNT(DISTINCT dst_port) >= 10", (dataset,))
        scanners = c.fetchall()
        for ip, port_count in scanners:
            description = f"Port scan detected from IP {ip} (accessed {port_count} ports)"
            timestamp = datetime.now().isoformat()
            c.execute("SELECT COUNT(*) FROM playbook_actions WHERE description = ? AND dataset = ?", (description, dataset))
            if c.fetchone()[0] == 0:
                c.execute("INSERT INTO playbook_actions (name, description, timestamp, dataset) VALUES (?, ?, ?, ?)",
                          ("Port Scan Detection", description, timestamp, dataset))
