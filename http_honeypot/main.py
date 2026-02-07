from flask import Flask, request, render_template
import logging

app = Flask(__name__)

import datetime

def custom_formatter(msg):
    timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    return f'{timestamp} - {msg}'

# Custom logger to control format
logger = logging.getLogger()
logger.setLevel(logging.INFO)
handler = logging.FileHandler('/app/logs/honeypot.log')
formatter = logging.Formatter('%(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    ip_addr = request.remote_addr
    user_agent = request.headers.get('User-Agent')

    log_msg = f"[INFO] Admin access attempt | IP={ip_addr} | UA={user_agent}"
    print(f"[!] {log_msg}")
    logger.info(custom_formatter(log_msg))

    return render_template('admin.html'), 403

if __name__ == '__main__':
    print("[*] Flask honeypot started")
    app.run(host='0.0.0.0', port=8080)