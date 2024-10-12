import pyshark

def analyze_pcap(file_path):
    capture = pyshark.FileCapture(file_path)
    results = []
    for packet in capture:
        try:
            results.append({
                'source_ip': packet.ip.src,
                'destination_ip': packet.ip.dst,
                'size': packet.length
            })
        except AttributeError as e:
            continue
    capture.close()
    return results

if __name__ == "__main__":
    file_path = r"C:\Users\Rana&Mariam\Documents\PCAP.pcap"
    results = analyze_pcap(file_path)
    
    # طباعة النتائج لتأكيد أن الكود عمل بنجاح
    if results:
        print("Captured packets:")
        for result in results:
            print(f"Source IP: {result['source_ip']} -> Destination IP: {result['destination_ip']}, Size: {result['size']}")
    else:
        print("No packets captured.")
