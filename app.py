import threading
import time
import logging
import nmap
import sqlite3
from datetime import datetime
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO

# تنظیم لاگ‌ها
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, async_mode='threading')

# تنظیمات اسکن
SCAN_INTERVAL = 10               # ثانیه
NETWORK_RANGE = '192.168.1.0/24'   # محدوده شبکه
OFFLINE_THRESHOLD = 30           # آستانه زمان آفلاین بودن (ثانیه)
DATABASE = 'network_logs.db'

# دیکشنری نگهداری اطلاعات دستگاه‌ها:
# ساختار: { 'IP': { 'status': 'up' یا 'down', 'last_seen': datetime } }
devices_info = {}

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    online_count INTEGER,
                    offline_count INTEGER
                )''')
    conn.commit()
    conn.close()

init_db()

def insert_scan_history(timestamp, online_count, offline_count):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("INSERT INTO scan_history (timestamp, online_count, offline_count) VALUES (?, ?, ?)",
              (timestamp, online_count, offline_count))
    conn.commit()
    conn.close()

def scan_network():
    nm = nmap.PortScanner()
    global devices_info
    while True:
        try:
            logging.info("شروع اسکن شبکه...")
            nm.scan(hosts=NETWORK_RANGE, arguments='-sn')
            current_time = datetime.now()
            current_devices = set(nm.all_hosts())

            # به‌روزرسانی یا اضافه کردن دستگاه‌های آنلاین
            for host in current_devices:
                devices_info[host] = {'status': 'up', 'last_seen': current_time}

            # علامت‌گذاری دستگاه‌هایی که دیده نمی‌شوند
            for host in list(devices_info.keys()):
                if host not in current_devices:
                    devices_info[host]['status'] = 'down'

            # تعیین تغییرات
            changes = {}
            for host, info in devices_info.items():
                if info['status'] == 'down':
                    offline_duration = (current_time - info['last_seen']).total_seconds()
                    if offline_duration >= OFFLINE_THRESHOLD:
                        changes[host] = f"آفلاین از {info['last_seen'].strftime('%H:%M:%S')} ({int(offline_duration)} ثانیه)"
                    else:
                        changes[host] = "دستگاه آفلاین"
                else:
                    changes[host] = "دستگاه آنلاین"

            # ذخیره سابقه اسکن در پایگاه داده
            online_count = sum(1 for host in devices_info if devices_info[host]['status'] == 'up')
            offline_count = sum(1 for host in devices_info if devices_info[host]['status'] == 'down')
            timestamp_str = current_time.strftime("%H:%M:%S")
            insert_scan_history(timestamp_str, online_count, offline_count)

            # ارسال اطلاعات به کلاینت
            payload = {
                'devices': {host: {'status': info['status'],
                                   'last_seen': info['last_seen'].strftime("%H:%M:%S")}
                            for host, info in devices_info.items()},
                'changes': changes
            }
            socketio.emit('network_update', payload)
            logging.info("اسکن پایان یافت. تغییرات: %s", changes)
        except Exception as e:
            logging.error("خطا در حین اسکن: %s", e)
            socketio.emit('error', {'error': str(e)})
        time.sleep(SCAN_INTERVAL)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/device/<ip>')
def device_detail(ip):
    """
    اسکن عمیق روی یک دستگاه برای دریافت جزئیات پورت‌ها و سرویس‌ها.
    """
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, arguments='-sV -Pn')
        details = {}
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                details[proto] = []
                for port in nm[ip][proto]:
                    port_info = nm[ip][proto][port]
                    details[proto].append({
                        'port': port,
                        'state': port_info.get('state'),
                        'name': port_info.get('name'),
                        'product': port_info.get('product'),
                        'version': port_info.get('version')
                    })
        return jsonify({'ip': ip, 'details': details})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/history')
def history():
    """
    بازیابی سابقه 50 آخرین اسکن از پایگاه داده.
    """
    try:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('SELECT timestamp, online_count, offline_count FROM scan_history ORDER BY id DESC LIMIT 50')
        rows = c.fetchall()
        conn.close()
        rows.reverse()  # نمایش به ترتیب زمانی صعودی
        history_data = [{'timestamp': row[0], 'online_count': row[1], 'offline_count': row[2]} for row in rows]
        return jsonify(history_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    scan_thread = threading.Thread(target=scan_network)
    scan_thread.daemon = True
    scan_thread.start()
    socketio.run(app, debug=True)
