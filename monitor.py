import pyshark
import matplotlib.pyplot as plt
import seaborn as sns
import io
import base64
from sklearn.ensemble import IsolationForest

def analyze_pcap(file_path):
    """تحليل ملف PCAP واستخراج بيانات حجم الحزم وعناوين IP المصدر"""
    capture = pyshark.FileCapture(file_path)
    packet_sizes = []
    source_ips = {}
    for packet in capture:
        try:
            size = int(packet.length)
            src_ip = packet.ip.src
            packet_sizes.append(size)
            if src_ip in source_ips:
                source_ips[src_ip] += 1
            else:
                source_ips[src_ip] = 1
        except AttributeError:
            continue
    capture.close()
    return packet_sizes, source_ips

def generate_plot(packet_sizes):
    """إنشاء رسم بياني لتوزيع أحجام الحزم وتحويله إلى تنسيق Base64"""
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

def start_anomaly_detection(packet_sizes):
    """تشغيل الكشف عن الشذوذ باستخدام خوارزمية Isolation Forest"""
    if not packet_sizes:
        return []
    clf = IsolationForest()
    packet_sizes = [[size] for size in packet_sizes]
    clf.fit(packet_sizes)
    anomalies = clf.predict(packet_sizes) == -1
    return anomalies
