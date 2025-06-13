
#!/usr/bin/env python3
import sqlite3

def create_flows_table(db_path='database.db'):
    with sqlite3.connect(db_path) as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                packet_count INTEGER,
                byte_count INTEGER,
                start_time TEXT,
                end_time TEXT,
                dataset TEXT
            )
        """)
        conn.commit()
        print("✅ 'flows' table created.")

if __name__ == '__main__':
    create_flows_table()

