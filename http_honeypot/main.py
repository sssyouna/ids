from flask import Flask, request, render_template
import logging

app = Flask(__name__)

logging.basicConfig(
    filename='honeypot.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    ip_addr = request.remote_addr
    user_agent = request.headers.get('User-Agent')

    log_msg = f"Admin access attempt | IP={ip_addr} | UA={user_agent}"
    print(f"[!] {log_msg}")
    logging.info(log_msg)

    return render_template('admin.html'), 403
    
if __name__ == '__main__':
    ids_thread = threading.Thread(target=start_ids, daemon=True)
    ids_thread.start()

    print("[*] Flask honeypot started")
    app.run(host='0.0.0.0', port=8080)