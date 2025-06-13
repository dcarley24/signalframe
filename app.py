from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
import os
import sqlite3
import csv
import datetime
import random
from scapy.all import rdpcap, IP, TCP, UDP
from rules import check_alerts
from playbooks import run_playbooks

app = Flask(__name__)
# Get secret key from environment variable, provide a fallback for development if not set
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_very_insecure_fallback_key_DO_NOT_USE_IN_PRODUCTION')
UPLOAD_FOLDER = 'uploads'
DB = 'database.db'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def init_db():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY, ip TEXT, action TEXT, timestamp TEXT, dst_port INTEGER, dataset TEXT DEFAULT 'default')''')
        c.execute('''CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY, message TEXT, timestamp TEXT, dataset TEXT DEFAULT 'default')''')
        c.execute('''CREATE TABLE IF NOT EXISTS playbook_actions (id INTEGER PRIMARY KEY, name TEXT, description TEXT, timestamp TEXT, dataset TEXT DEFAULT 'default')''')
        c.execute('''CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)''')
        # --- NEW: Create the flows table for PCAP analysis ---
        c.execute('''CREATE TABLE IF NOT EXISTS flows (
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
            dataset TEXT DEFAULT 'default'
        )''')
        # --- END NEW ---
        c.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('active_dataset', 'default')")
        # Ensure 'datasets' table exists for dataset management
        c.execute('''CREATE TABLE IF NOT EXISTS datasets (name TEXT PRIMARY KEY)''')
        c.execute("INSERT OR IGNORE INTO datasets (name) VALUES ('default')")


def get_active_dataset():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT value FROM config WHERE key = 'active_dataset'")
        return c.fetchone()[0]

def match_column(headers, target_options):
    for option in target_options:
        for header in headers:
            if header.strip().lower() == option:
                return header
    return None

@app.route('/')
def index():
    active = get_active_dataset()
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM logs WHERE dataset = ?", (active,))
        total_logs = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM alerts WHERE dataset = ?", (active,))
        total_alerts = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM playbook_actions WHERE dataset = ?", (active,))
        total_playbooks = c.fetchone()[0]

        c.execute("SELECT ip, COUNT(*) as count FROM logs WHERE dataset = ? GROUP BY ip ORDER BY count DESC LIMIT 5", (active,))
        top_ips = c.fetchall()

    return render_template('index.html',
                           total_logs=total_logs,
                           total_alerts=total_alerts,
                           total_playbooks=total_playbooks,
                           top_ips=top_ips)

@app.route('/logs', methods=['GET', 'POST'])
def logs():
    skipped = 0
    active = get_active_dataset()
    if request.method == 'POST':
        file = request.files['logfile']
        if file:
            filepath = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(filepath)
            with open(filepath, newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                headers = reader.fieldnames

                ip_col = match_column(headers, ['ip', 'source_ip', 'client_ip'])
                action_col = match_column(headers, ['action', 'event', 'event_type'])
                time_col = match_column(headers, ['timestamp', 'time', 'datetime'])
                port_col = match_column(headers, ['dst_port', 'port', 'destination_port'])

                fallback_used = False
                if not ip_col and 'Dst Port' in headers:
                    ip_col = 'Dst Port'
                    fallback_used = True
                if not action_col and 'Label' in headers:
                    action_col = 'Label'
                    fallback_used = True
                if not time_col and 'Timestamp' in headers:
                    time_col = 'Timestamp'
                    fallback_used = True

                missing = []
                if not ip_col:
                    missing.append('IP')
                if not action_col:
                    missing.append('Action')
                if not time_col:
                    missing.append('Timestamp')

                if missing:
                    detected_headers = ', '.join(headers)
                    flash(f"Missing expected column(s): {', '.join(missing)}.<br>Detected headers: {detected_headers}", 'danger')
                    return redirect(url_for('logs'))

                if fallback_used:
                    flash("Fallback field mapping applied — using nonstandard headers (e.g., 'Dst Port', 'Label').", 'info')

                # --- NEW: Prepare for batch insert ---
                log_entries_to_insert = []
                # --- END NEW ---
                with sqlite3.connect(DB) as conn:
                    c = conn.cursor()
                    for row in reader:
                        try:
                            # Original: values = (str(row[ip_col]), row[action_col], row[time_col], active)
                            # Original: c.execute("INSERT INTO logs (ip, action, timestamp, dataset) VALUES (?, ?, ?, ?)", values)
                            # --- NEW: Append to list for batch insert ---
                            log_entries_to_insert.append((
                                str(row[ip_col]),
                                row[action_col],
                                row[time_col],
                                row.get(port_col) if port_col else None, # Include dst_port for logs
                                active
                            ))
                            # --- END NEW ---
                        except Exception: # Consider more specific exceptions like KeyError, ValueError
                            skipped += 1
                    # --- NEW: Execute batch insert ---
                    if log_entries_to_insert:
                        c.executemany("INSERT INTO logs (ip, action, timestamp, dst_port, dataset) VALUES (?, ?, ?, ?, ?)", log_entries_to_insert)
                    # --- END NEW ---

            if skipped > 0:
                flash(f'{skipped} log entries were skipped due to formatting issues.', 'warning')
            else:
                flash('Log file uploaded successfully.', 'success')
            check_alerts(DB)
            run_playbooks(DB)
            return redirect(url_for('logs'))

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM logs WHERE dataset = ? ORDER BY id DESC LIMIT 100", (active,))
        log_entries = c.fetchall()
    return render_template('logs.html', logs=log_entries)

@app.route('/alerts')
def alerts():
    active = get_active_dataset()
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM alerts WHERE dataset = ? ORDER BY id DESC", (active,))
        alerts = c.fetchall()
    return render_template('alerts.html', alerts=alerts)

@app.route('/playbooks')
def playbooks():
    active = get_active_dataset()
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM playbook_actions WHERE dataset = ? ORDER BY id DESC", (active,))
        playbooks = c.fetchall()
    return render_template('playbooks.html', playbooks=playbooks)

@app.route('/simulate', methods=['GET', 'POST'])
def simulate():
    def random_ip():
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def random_port():
        return random.randint(1024, 65535)

    def random_action():
        return random.choice(['login_failed', 'DoS_HULK', 'scan', 'Trojan.Win32', 'BENIGN'])

    if request.method == 'POST':
        sim_type = request.form.get('sim')
        action = request.form.get('action')
        count = int(request.form.get('count', 30))
        now = datetime.datetime.now()
        active = get_active_dataset()
        rows = []

        cluster_ips = ['192.168.1.10', '192.168.1.20', '192.168.1.30']
        cluster_weight = 0.7

        for _ in range(count):
            ip = random.choice(cluster_ips) if random.random() < cluster_weight else random_ip()
            action_type = random_action() if sim_type == 'mixed' else sim_type
            timestamp = (now + datetime.timedelta(seconds=random.randint(0, 300))).isoformat()

            row = {
                'ip': ip,
                'action': action_type,
                'timestamp': timestamp
            }

            if action_type in ['scan', 'DoS_HULK']:
                row['dst_port'] = random_port()

            rows.append(row)

        if action == 'download':
            fieldnames = sorted(set().union(*[row.keys() for row in rows]))
            csv_path = 'simulated_output.csv'
            with open(csv_path, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for row in rows:
                    writer.writerow(row)
            return send_file(csv_path, as_attachment=True)

        elif action == 'inject':
            # --- NEW: Prepare for batch insert ---
            log_entries_to_insert = []
            # --- END NEW ---
            with sqlite3.connect(DB) as conn:
                c = conn.cursor()
                for row in rows:
                    ip = row['ip']
                    act = row['action']
                    ts = row['timestamp']
                    port = row.get('dst_port')
                    # Original: if port:
                    # Original:    c.execute("INSERT INTO logs (ip, action, dst_port, timestamp, dataset) VALUES (?, ?, ?, ?, ?)",
                    # Original:             (ip, act, port, ts, active))
                    # Original: else:
                    # Original:    c.execute("INSERT INTO logs (ip, action, timestamp, dataset) VALUES (?, ?, ?, ?)",
                    # Original:             (ip, act, ts, active))
                    # --- NEW: Append to list for batch insert, ensuring dst_port is always present (even if None) ---
                    log_entries_to_insert.append((ip, act, ts, port, active))
                    # --- END NEW ---
                # --- NEW: Execute batch insert ---
                if log_entries_to_insert:
                    c.executemany("INSERT INTO logs (ip, action, timestamp, dst_port, dataset) VALUES (?, ?, ?, ?, ?)", log_entries_to_insert)
                # --- END NEW ---
            check_alerts(DB)
            run_playbooks(DB)
            flash(f"Simulation '{sim_type}' injected at {now.isoformat()}", "success")
            return redirect(url_for('simulate'))

    return render_template('simulate.html')

@app.route('/datasets', methods=['GET', 'POST'])
def manage_datasets():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        # Ensure 'datasets' table exists if somehow missed by init_db (good for robustness)
        c.execute('''CREATE TABLE IF NOT EXISTS datasets (name TEXT PRIMARY KEY)''')
        c.execute("INSERT OR IGNORE INTO datasets (name) VALUES ('default')") # Ensure default dataset exists

        c.execute("SELECT value FROM config WHERE key = 'active_dataset'")
        current = c.fetchone()[0]

        if request.method == 'POST':
            action = request.form.get('action')

            if action == 'create':
                new_ds = request.form.get('new_dataset').strip()
                if new_ds:
                    c.execute("INSERT OR IGNORE INTO datasets (name) VALUES (?)", (new_ds,))
                    c.execute("UPDATE config SET value = ? WHERE key = 'active_dataset'", (new_ds,))
                    flash(f"Dataset '{new_ds}' created and set active.", "success")
                    current = new_ds

            elif action == 'switch':
                selected = request.form.get('active')
                c.execute("UPDATE config SET value = ? WHERE key = 'active_dataset'", (selected,))
                flash(f"Active dataset switched to '{selected}'", "info")
                current = selected

            elif action == 'delete':
                delete_ds = request.form.get('delete')
                if delete_ds != current:
                    for table in ['logs', 'alerts', 'playbook_actions', 'flows']: # Add 'flows' to deletion list
                        c.execute(f"DELETE FROM {table} WHERE dataset = ?", (delete_ds,))
                    c.execute("DELETE FROM datasets WHERE name = ?", (delete_ds,))
                    flash(f"Dataset '{delete_ds}' deleted.", "warning")
                else:
                    flash("Cannot delete the active dataset.", "danger")

        c.execute("SELECT name FROM datasets ORDER BY name")
        datasets = [row[0] for row in c.fetchall()]

    return render_template('datasets.html', datasets=datasets, current=current)

@app.route('/upload_pcap', methods=['GET', 'POST'])
def upload_pcap():
    if request.method == 'POST':
        file = request.files.get('pcapfile')
        if not file:
            flash("No PCAP file selected.", "danger")
            return redirect(url_for('upload_pcap'))

        # --- NEW: Generate a unique dataset name for the PCAP ---
        pcap_dataset_name = f"pcap_{os.path.splitext(file.filename)[0]}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
        # --- END NEW ---

        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)

        packets = rdpcap(filepath)
        flows = {}
        log_entries_to_insert = []
        flow_entries_to_insert = []

        for pkt in packets:
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                proto = pkt[IP].proto
                timestamp = datetime.datetime.fromtimestamp(float(pkt.time)).isoformat()
                sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else None)
                dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)
                proto_name = 'TCP' if TCP in pkt else 'UDP' if UDP in pkt else 'IP'

                # --- NEW: Use the unique pcap_dataset_name ---
                log_entries_to_insert.append((src, 'packet_capture', timestamp, dport, pcap_dataset_name))
                # --- END NEW ---

                key = (src, dst, sport, dport, proto_name)
                if key not in flows:
                    flows[key] = {
                        'packet_count': 1,
                        'byte_count': len(pkt),
                        'start_time': timestamp,
                        'end_time': timestamp
                    }
                else:
                    flows[key]['packet_count'] += 1
                    flows[key]['byte_count'] += len(pkt)
                    flows[key]['end_time'] = timestamp

        for (src, dst, sport, dport, proto), stats in flows.items():
            # --- NEW: Use the unique pcap_dataset_name ---
            flow_entries_to_insert.append((
                src, dst, sport, dport, proto,
                stats['packet_count'], stats['byte_count'],
                stats['start_time'], stats['end_time'], pcap_dataset_name
            ))
            # --- END NEW ---

        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            # --- NEW: Insert the new PCAP dataset into datasets table and set it as active ---
            c.execute("INSERT OR IGNORE INTO datasets (name) VALUES (?)", (pcap_dataset_name,))
            c.execute("UPDATE config SET value = ? WHERE key = 'active_dataset'", (pcap_dataset_name,))
            # --- END NEW ---

            if log_entries_to_insert:
                c.executemany("INSERT INTO logs (ip, action, timestamp, dst_port, dataset) VALUES (?, ?, ?, ?, ?)", log_entries_to_insert)

            if flow_entries_to_insert:
                c.executemany("""
                    INSERT INTO flows (
                        src_ip, dst_ip, src_port, dst_port, protocol,
                        packet_count, byte_count, start_time, end_time, dataset
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, flow_entries_to_insert)

        check_alerts(DB)
        run_playbooks(DB)
        flash(f"PCAP analysis complete. {len(log_entries_to_insert)} packets processed into logs and {len(flow_entries_to_insert)} flows. Now viewing dataset: '{pcap_dataset_name}'", "success")
        # --- NEW: Redirect to flows page, pre-selecting the new PCAP dataset ---
        return redirect(url_for('flows', dataset_name=pcap_dataset_name))
        # --- END NEW ---

    return render_template('upload_pcap.html')

@app.route('/flows')
def flows():
    # --- NEW: Allow selecting a specific dataset via URL parameter ---
    selected_dataset = request.args.get('dataset_name')
    if selected_dataset:
        active = selected_dataset
    else:
        active = get_active_dataset()
    # --- END NEW ---

    src_ip = request.args.get('src_ip', '').strip()
    dst_ip = request.args.get('dst_ip', '').strip()
    protocol = request.args.get('protocol', '').strip()
    min_packets = request.args.get('min_packets', '').strip()

    query = """
        SELECT src_ip, dst_ip, protocol, src_port, dst_port,
               packet_count, byte_count, start_time, end_time
        FROM flows WHERE dataset = ?
    """
    params = [active]

    if src_ip:
        query += " AND src_ip LIKE ?"
        params.append(f"%{src_ip}%")
    if dst_ip:
        query += " AND dst_ip LIKE ?"
        params.append(f"%{dst_ip}%")
    if protocol:
        query += " AND protocol LIKE ?"
        params.append(f"%{protocol}%")
    if min_packets:
        try:
            min_packets_int = int(min_packets)
            query += " AND packet_count >= ?"
            params.append(min_packets_int)
        except ValueError:
            flash("Invalid value for Minimum Packets. Please enter a number.", "danger")
            results = []
            # --- NEW: Fetch PCAP datasets for the dropdown even on error ---
            with sqlite3.connect(DB) as conn:
                c = conn.cursor()
                c.execute("SELECT name FROM datasets WHERE name LIKE 'pcap_%' ORDER BY name DESC")
                pcap_datasets = [row[0] for row in c.fetchall()]
            # --- END NEW ---
            return render_template("flows.html", flows=results, pcap_datasets=pcap_datasets,
                                   src_ip=src_ip, dst_ip=dst_ip, protocol=protocol, min_packets=min_packets,
                                   current_pcap_dataset=active) # Pass active dataset

    query += " ORDER BY packet_count DESC"

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute(query, tuple(params))
        results = c.fetchall()

    # --- NEW: Always fetch PCAP datasets for the dropdown ---
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT name FROM datasets WHERE name LIKE 'pcap_%' ORDER BY name DESC")
        pcap_datasets = [row[0] for row in c.fetchall()]
    # --- END NEW ---

    # --- NEW: Improve flash message for empty results ---
    if not results and active.startswith("pcap_"):
        flash(f"No flow data found for PCAP dataset '{active}' matching the criteria. Please upload a PCAP file or adjust filters.", "info")
    elif not results and not active.startswith("pcap_"):
        flash(f"No flow data found for active dataset '{active}'. Upload a PCAP file or switch to a PCAP dataset to view flows.", "info")
    # --- END NEW ---


    return render_template("flows.html", flows=results, pcap_datasets=pcap_datasets,
                           src_ip=src_ip, dst_ip=dst_ip, protocol=protocol, min_packets=min_packets,
                           current_pcap_dataset=active)

@app.route('/flows_data')
def flows_data():
    # --- NEW: Allow selecting a specific dataset via URL parameter for the API ---
    selected_dataset = request.args.get('dataset_name')
    if selected_dataset:
        active = selected_dataset
    else:
        active = get_active_dataset()
    # --- END NEW ---

    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("""
            SELECT src_ip, dst_ip, packet_count
            FROM flows
            WHERE dataset = ?
        """, (active,))
        results = c.fetchall()

    nodes = {}
    links = []

    for src, dst, count in results:
        # Ensure nodes are indexed for D3.js
        if src not in nodes:
            nodes[src] = {"id": src}
        if dst not in nodes:
            nodes[dst] = {"id": dst}

        links.append({
            "source": src, # Use IP string as source/target for D3 for simpler handling
            "target": dst,
            "value": count
        })

    # Return nodes as a list of objects with 'id' property
    return jsonify({
        "nodes": list(nodes.values()),
        "links": links
    })

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5002, debug=True)
