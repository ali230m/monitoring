from flask import Flask, render_template, request, redirect, url_for, flash
from scapy.all import rdpcap
import matplotlib.pyplot as plt
import seaborn as sns
import io
import base64
from sklearn.ensemble import IsolationForest
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import psutil
import time
import threading
import json
import os
import nmap
from werkzeug.utils import secure_filename
from scapy.all import ARP, Ether, srp

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './uploads'
app.secret_key = 'your_secret_key'

# إعدادات البريد الإلكتروني
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
EMAIL_ADDRESS = 'maa82950@gmail.com'
EMAIL_PASSWORD = 'bsaxaoqmoqznalzs'
ALERT_RECIPIENT = 'maa82950@gmail.com'

monitoring = False
monitoring_thread = None

# تعريف حدود الحزمة لتحديد أنواع الشذوذ
LARGE_PACKET_THRESHOLD = 1500  # حجم الحزمة الكبيرة بالبايت
SMALL_PACKET_THRESHOLD = 50    # حجم الحزمة الصغيرة بالبايت
KNOWN_SOURCES = ['192.168.1.1', '10.0.0.1']  # قائمة بمصادر الحزم الموثوقة

# تحليل ملفات PCAP
def analyze_pcap(file_path):
    packets = rdpcap(file_path)
    packet_sizes = []
    source_ips = {}
    for packet in packets:
        if packet.haslayer('IP'):
            size = len(packet)
            src_ip = packet['IP'].src
            packet_sizes.append(size)
            if src_ip in source_ips:
                source_ips[src_ip] += 1
            else:
                source_ips[src_ip] = 1
    return packet_sizes, source_ips

# كشف نوع الشذوذ
def detect_anomaly_type(packet_size, source_ip):
    anomaly_type = "Normal"
    if packet_size > LARGE_PACKET_THRESHOLD:
        anomaly_type = "Large Packet"
    elif packet_size < SMALL_PACKET_THRESHOLD:
        anomaly_type = "Small Packet"
    elif source_ip not in KNOWN_SOURCES:
        anomaly_type = "Unknown Source"
    
    return anomaly_type

# إنشاء الرسوم البيانية
def generate_plot(packet_sizes):
    if not packet_sizes:
        return None  # إذا لم تكن هناك بيانات، أعد لا شيء لتجنب محاولة إنشاء رسم بياني فارغ.

    plt.figure(figsize=(10, 6))
    sns.histplot(packet_sizes, bins=30, kde=True)
    plt.title('Packet Size Distribution')
    plt.xlabel('Packet Size (bytes)')
    plt.ylabel('Frequency')

    img = io.BytesIO()
    plt.savefig(img, format='png')
    plt.close()
    img.seek(0)
    return base64.b64encode(img.getvalue()).decode()


# إرسال تنبيه بالبريد الإلكتروني
def send_alert(packet_size, anomaly_type):
    subject = f"Network Anomaly Detected: {anomaly_type}"
    body = f"An anomaly of type '{anomaly_type}' was detected in network traffic. Packet size: {packet_size} bytes."
    
    msg = MIMEMultipart()
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = ALERT_RECIPIENT
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        text = msg.as_string()
        server.sendmail(EMAIL_ADDRESS, ALERT_RECIPIENT, text)
        server.quit()
        print(f"Alert email sent successfully to {ALERT_RECIPIENT}.")
    except Exception as e:
        print(f"Failed to send email alert. Error: {e}")

# التعامل مع الشذوذات
def handle_anomaly(anomaly_type, packet_size, source_ip):
    if anomaly_type == "Large Packet":
        print(f"Handling large packet anomaly. Size: {packet_size}")
    elif anomaly_type == "Small Packet":
        print(f"Handling small packet anomaly. Size: {packet_size}")
    elif anomaly_type == "Unknown Source":
        print(f"Handling unknown source anomaly. Source IP: {source_ip}")
    else:
        print(f"Unhandled anomaly type: {anomaly_type}")

# بدء كشف الشذوذات
def start_anomaly_detection(packet_sizes, source_ips):
    if not packet_sizes or not source_ips:
        return []

    # التأكد من أن source_ips هي قائمة
    if not isinstance(source_ips, list):
        print(f"Warning: Expected list for source_ips but got {type(source_ips)}. Converting to list.")
        source_ips = list(source_ips)

    # تقليل القوائم بناءً على الطول المشترك
    min_length = min(len(packet_sizes), len(source_ips))

    # قطع القوائم إلى الطول المتساوي
    packet_sizes = packet_sizes[:min_length]
    source_ips = source_ips[:min_length]

    clf = IsolationForest()
    packet_sizes_reshaped = [[size] for size in packet_sizes]
    clf.fit(packet_sizes_reshaped)
    predictions = clf.predict(packet_sizes_reshaped)

    anomalies_json = []
    for i, size in enumerate(packet_sizes_reshaped):
        is_anomaly = predictions[i] == -1
        anomaly_type = detect_anomaly_type(size[0], source_ips[i])
        if is_anomaly:
            handle_anomaly(anomaly_type, size[0], source_ips[i])
            send_alert(size[0], anomaly_type)
            anomalies_json.append({
                'size': size[0],
                'detected': int(is_anomaly),
                'type': anomaly_type
            })

    return anomalies_json

# قراءة ملفات JSON
def read_json_file(file_path, default_value=None):
    if not os.path.exists(file_path):
        return default_value
    try:
        with open(file_path, 'r') as f:
            content = f.read().strip()
            if not content:
                return default_value
            return json.loads(content)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from file: {file_path}. Error: {e}")
        return default_value

# كتابة ملفات JSON
def write_json_file(file_path, data):
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f)
    except Exception as e:
        print(f"Error writing JSON to file: {file_path}. Error: {e}")

def scan_network(ip_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments='-sn')  # -sn: Ping Scan, no port scan
    devices = []

    for host in nm.all_hosts():
        if 'mac' in nm[host]['addresses']:
            devices.append({
                'ip': nm[host]['addresses']['ipv4'],
                'mac': nm[host]['addresses']['mac']
            })
        else:
            devices.append({
                'ip': nm[host]['addresses']['ipv4'],
                'mac': 'Unknown'
            })
    return devices

# مراقبة حركة المرور في الشبكة
def monitor_network_traffic():
    global monitoring
    recent_sizes = []
    source_ips = []
    while monitoring:
        net_io = psutil.net_io_counters()
        current_data = {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv
        }
        
        previous_data = read_json_file('network_traffic.json', {'bytes_sent': 0, 'bytes_recv': 0})
        
        sent_diff = current_data['bytes_sent'] - previous_data['bytes_sent']
        recv_diff = current_data['bytes_recv'] - previous_data['bytes_recv']
        
        write_json_file('network_traffic.json', current_data)
        
        if sent_diff > 0:
            recent_sizes.append(sent_diff)
            source_ips.append('unknown')
        if recv_diff > 0:
            recent_sizes.append(recv_diff)
            source_ips.append('unknown')
        
        anomalies = start_anomaly_detection(recent_sizes, source_ips)
        write_json_file('anomalies.json', {'anomalies': anomalies})
        
        print(f"Bytes Sent: {current_data['bytes_sent']}, Bytes Received: {current_data['bytes_recv']}")
        time.sleep(10)

@app.route('/')
def index():
    network_data = read_json_file('network_traffic.json', {'bytes_sent': 0, 'bytes_recv': 0})
    anomalies_data = read_json_file('anomalies.json', {'anomalies': []})

    # إنشاء الرسوم البيانية
    packet_sizes = [anomaly['size'] for anomaly in anomalies_data['anomalies']]
    plot_img = generate_plot(packet_sizes)

    monitoring_status = "Active" if monitoring else "Inactive"

    return render_template('index.html',
                           network_data=network_data,
                           anomalies_data=anomalies_data,
                           monitoring_status=monitoring_status,
                           plot_img=plot_img,  # تأكد من إرسال الرسم البياني للواجهة
                           monitoring=monitoring)


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('index'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('index'))
    
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # تحليل ملف PCAP
        packet_sizes, source_ips = analyze_pcap(filepath)
        plot_img = generate_plot(packet_sizes)
        anomalies = start_anomaly_detection(packet_sizes, source_ips)
        
        # طباعة الشذوذات للتأكد
        print("Anomalies detected:", anomalies)
        
        network_data = read_json_file('network_traffic.json', {'bytes_sent': 0, 'bytes_recv': 0})
        anomalies_data = read_json_file('anomalies.json', {'anomalies': []})
        
        return render_template('index.html', 
                               packet_sizes=packet_sizes, 
                               source_ips=source_ips, 
                               plot_img=plot_img, 
                               anomalies=anomalies,
                               network_data=network_data,
                               anomalies_data=anomalies_data,
                               monitoring=monitoring)

@app.route('/start_monitoring', methods=['POST'])
def start_monitoring():
    global monitoring, monitoring_thread
    if not monitoring:
        monitoring = True
        monitoring_thread = threading.Thread(target=monitor_network_traffic)
        monitoring_thread.daemon = True
        monitoring_thread.start()
    return redirect('/')

@app.route('/stop_monitoring', methods=['POST'])
def stop_monitoring():
    global monitoring
    if monitoring:
        monitoring = False
        if monitoring_thread:
            monitoring_thread.join()
    return redirect('/')

@app.route('/network_devices', methods=['GET'])
def show_network_devices():
    ip_range = "192.168.1.0/24"
    devices = scan_network(ip_range)
    if not devices:
        print("No devices found on the network.")
    return render_template('network_devices.html', devices=devices)

if __name__ == '__main__':
    app.run(debug=True)
