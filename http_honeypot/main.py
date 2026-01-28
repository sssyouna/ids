import scapy.all as scapy
from flask import Flask,request,redirect,render_template
import logging

"""
HTTP Honey Pot
This script sets up a simple HTTP honeypot using Flask. When accessed, it logs the attacker's IP address and denies access.
"""

app = Flask(__name__)
logging.basicConfig(filename='honeypot.log', level=logging.INFO,format='%(asctime)s - %(message)s')


@app.route('/')
def index():
    return render_template('index.html')



@app.route('/admin')
def admin():
    # Log the intruder's IP address
    ip_addr = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    log_msg = f"Attacker detected: IP={ip_addr}, User-Agent={user_agent}"
    
    print(f"[!] {log_msg}") # Print to console
    logging.info(log_msg) # Log to file
    
    return "403 Forbidden: Admin access denied.", 403


if __name__ == '__main__':
    app.run(debug=True)
