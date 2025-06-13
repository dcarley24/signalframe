SignalFrame: Security Operations Playground
SignalFrame (formerly SecOps Playground) is a lightweight, Flask-based web application designed to help you quickly triage and analyze security-related data, specifically CSV-formatted logs and PCAP network captures. It provides a simple, intuitive interface to ingest data, identify potential issues, and visualize network flows without the complexity of traditional security tools.

The primary goal of SignalFrame is to make initial security assessment (triage) of "weird-looking" logs or network traffic straightforward, even for non-security experts.

Features
Log Ingestion (CSV): Upload CSV log files with intelligent header matching for common fields (IP, action, timestamp, destination port).

PCAP Analysis & Flow Visualization: Upload PCAP files for automatic parsing of network packets into aggregated flows. Visualize these flows as an interactive force-directed graph to quickly understand network communication patterns.

Dataset Management: Create, switch between, and delete isolated datasets for different analysis scenarios, ensuring your data remains organized.

Simulated Data Generation: Generate synthetic security events (e.g., login failures, DoS attacks, port scans) to populate your active dataset for testing and demonstration.

Basic Alerting: Automatically detect simple alert conditions based on log volume.

Automated Playbooks: Simulate automated responses (e.g., blocking suspicious IPs, escalating suspicious activity, detecting port scans) based on predefined rules.

Intuitive Web Interface: A clean, responsive web interface for viewing logs, alerts, playbook actions, and network flows.

Getting Started
These instructions will get your SignalFrame application up and running on your Ubuntu server.

Prerequisites
Python 3.10+: Ensure Python 3.10 or newer is installed on your Ubuntu server.

pip: Python package installer.

venv: Python virtual environment module (usually comes with Python 3).

git: For cloning the repository.

ffmpeg, v4l-utils, pulseaudio, alsa-utils, xvfb, x11-utils, libgl1: Required for potential screen/webcam/audio capture features (though not actively used in the current core functionality, they are common dependencies in a development environment for similar projects).

sudo apt update && sudo apt install -y \
    ffmpeg \
    v4l-utils \
    pulseaudio \
    alsa-utils \
    xvfb \
    x11-utils \
    python3-venv \
    libgl1 \
    git \
    git-filter-repo # Needed if you need to clean Git history

Installation
Clone the Repository:

git clone https://github.com/dcarley24/signalframe.git
cd signalframe

Create and Activate a Virtual Environment:
It's highly recommended to use a virtual environment to manage dependencies.

python3 -m venv venv
source venv/bin/activate

(You'll see (venv) in your terminal prompt, indicating the environment is active.)

Install Python Dependencies:

pip install Flask scapy
# If you later encounter specific missing packages, install them:
# pip install requests pandas numpy opencv-python Pillow torch transformers
# (based on your pythondev report, you have many of these already)

Set the Flask Secret Key:
For security, Flask requires a secret key. This should be a long, random string. Do NOT hardcode this in app.py for production.
Generate a random key (e.g., using python3 -c 'import os; print(os.urandom(24))') and set it as an environment variable.
To make it persistent, add this line to your ~/.bashrc file:

echo 'export FLASK_SECRET_KEY="YOUR_GENERATED_RANDOM_KEY_HERE"' >> ~/.bashrc
source ~/.bashrc

(Replace YOUR_GENERATED_RANDOM_KEY_HERE with your actual key.)

Running the Application
For a persistent background process on your Ubuntu server:

# Ensure you are in the signalframe directory and virtual environment is active
# source venv/bin/activate # If not already active

nohup python3 app.py > app.log 2>&1 &

This will start the Flask application on http://0.0.0.0:5002. You can then access it from your web browser using your server's IP address (e.g., http://your_server_ip:5002).

Database Initialization
The app.py script automatically initializes the SQLite database.db and necessary tables (logs, alerts, playbook_actions, flows, datasets) upon its first run if the database file does not exist.

Project Structure
signalframe/
├── templates/                 # HTML templates (Jinja2)
│   ├── base.html              # Base layout and shared CSS
│   ├── index.html             # Dashboard
│   ├── logs.html              # Log upload and viewing
│   ├── alerts.html            # Alerts display
│   ├── playbooks.html         # Playbook actions display
│   ├── simulate.html          # Traffic simulation
│   ├── datasets.html          # Dataset management
│   └── flows.html             # Network flow visualization
├── uploads/                   # Directory for uploaded PCAP/CSV files (ignored by Git)
├── app.py                     # Main Flask application
├── pcapgen.py                 # Utility to generate sample PCAP files
├── playbooks.py               # Automated response logic
├── rules.py                   # Alerting logic
├── database.db                # SQLite database (ignored by Git)
├── .gitignore                 # Specifies files/folders to ignore in Git
└── README.md                  # This file

Usage
Upload Logs or PCAPs: Navigate to the "Logs" or "PCAP Upload" sections to ingest your data.

Simulate Traffic: Use the "Simulate" page to generate synthetic data for testing.

View Flows: Go to the "Flows" page to see network communication visualized. You can select specific PCAP datasets from a dropdown.

Check Alerts & Playbooks: Monitor detected security alerts and automated actions on their respective pages.

Manage Datasets: Organize your analysis by creating, switching, or deleting datasets.

Contributing
SignalFrame is a personal project, but contributions are welcome! Feel free to fork the repository, make improvements, and submit pull requests.

License
This project is open-source. See the LICENSE file for details (if you plan to add one).
