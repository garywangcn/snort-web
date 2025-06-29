from flask import Flask, request, render_template
import os, subprocess, json, psutil
from config import *

SNORT_CONF = '/home/ubuntu/snort3/snort3/lua/snort.lua'
SNORT_BIN = 'snort'
UPLOAD_FOLDER = '/tmp/uploads'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def get_snort_status():
    for proc in psutil.process_iter(['name']):
        if 'snort' in proc.info['name'].lower():
            return 'Running'
    return 'Stopped'

def get_server_stats():
    return {
        'cpu_percent': psutil.cpu_percent(),
        'mem_percent': psutil.virtual_memory().percent,
        'disk_percent': psutil.disk_usage('/').percent,
        'snort_status': get_snort_status()
    }

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    snort_output = []
    snort_alerts = []
    stats = get_server_stats()

    if request.method == 'POST':
        file = request.files['pcap']
        if file and file.filename.endswith('.pcap'):
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(filepath)

            cmd = [
                SNORT_BIN,
                '-c', SNORT_CONF,
                '--daq-dir', '/usr/local/daq/lib/daq/',
                '--pcap-list', filepath,
                '-q'
            ]

            try:
                result = subprocess.run(cmd, capture_output=True, check=False, text=False)
                output = result.stdout.decode(errors='ignore')
                snort_alerts = output.strip().split('\n')
            except subprocess.CalledProcessError as e:
                error_msg = e.stderr.decode(errors='ignore')
                snort_alerts = [f"Snort failed: {error_msg}"]

            print(snort_alerts)
    return render_template('index.html', output=snort_alerts, stats=stats)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

