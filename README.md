# DDOS-Detection-using-AI
You can find a complete code to detect and generate the alert whenever your system is undergo any DDOs attacks and you will get the pcap files containing the details of logs during attacks and additionally the suspicious ip addresses will be blocked automatically.

# Function to generate report
def generate_report(network_data, potential_attackers, anomalies):
    # Create a summary report
    report_content = "Network Monitoring Report\n"
    report_content += "="*50 + "\n"
    report_content += f"Number of Packets Captured: {len(network_data)}\n"
    
    # Summary statistics
    if network_data:
        packet_sizes = [entry['packet_size'] for entry in network_data]
        avg_packet_size = np.mean(packet_sizes) if packet_sizes else 0
        max_packet_size = np.max(packet_sizes) if packet_sizes else 0
        min_packet_size = np.min(packet_sizes) if packet_sizes else 0
        
        report_content += f"Average Packet Size: {avg_packet_size:.2f} bytes\n"
        report_content += f"Max Packet Size: {max_packet_size} bytes\n"
        report_content += f"Min Packet Size: {min_packet_size} bytes\n"
    
    report_content += "="*50 + "\n"
    
    # Table of potential attackers
    if potential_attackers:
        report_content += "Potential Attackers:\n"
        report_content += "-"*50 + "\n"
        report_content += f"{'IP Address':<15} | {'Packet Count':<10}\n"
        report_content += "-"*50 + "\n"
        for ip, count in potential_attackers.items():
            report_content += f"{ip:<15} | {count:<10}\n"
    else:
        report_content += "No potential attackers detected.\n"
    
    # Anomalies
    if anomalies:
        report_content += "="*50 + "\n"
        report_content += "Detected Anomalies:\n"
        report_content += "-"*50 + "\n"
        report_content += f"{'Timestamp':<20} | {'IP Source':<15} | {'IP Destination':<15} | {'Packet Size':<10}\n"
        report_content += "-"*50 + "\n"
        for entry in anomalies:
            timestamp = datetime.fromtimestamp(entry['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            report_content += f"{timestamp:<20} | {entry['ip_src']:<15} | {entry['ip_dst']:<15} | {entry['packet_size']:<10}\n"
    else:
        report_content += "No anomalies detected.\n"
    
    return report_content

# Function to save network data as CSV
def save_network_data_as_csv(network_data):
    current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    csv_file_path = f"Network_Data_{current_time}.csv"

    with open(csv_file_path, 'w', newline='') as csvfile:
        fieldnames = [
            'timestamp', 'ip_src', 'ip_dst', 'protocol', 'src_port', 'dst_port', 'packet_size', 
            'payload_size', 'entropy', 'flags', 'window_size', 'anomaly'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerows(network_data)
    
    print(f"Network data saved as {csv_file_path}")
    return csv_file_path

# Function to save network data as PCAP
def save_network_data_as_pcap(network_data):
    # Create Scapy packets from the network data
    packets = []
    for entry in network_data:
        if 'ip_src' in entry and 'ip_dst' in entry:
            pkt = Ether() / IP(src=entry['ip_src'], dst=entry['ip_dst'])
            if entry['protocol'] == "TCP":
                pkt /= TCP(sport=int(entry['src_port']), dport=int(entry['dst_port']))
            elif entry['protocol'] == "UDP":
                pkt /= UDP(sport=int(entry['src_port']), dport=int(entry['dst_port']))
            packets.append(pkt)

    if not packets:
        print("No valid packets to save.")
        return None

    current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    pcap_file_path = f"Network_Data_{current_time}.pcap"
    
    # Save the packets to a PCAP file
    try:
        wrpcap(pcap_file_path, packets)
        print(f"Network data saved as {pcap_file_path}")
    except Exception as e:
        print(f"An error occurred while saving PCAP file: {e}")
        pcap_file_path = None

    return pcap_file_path

# Function to show pop-up alert
def show_alert(message):
    messagebox.showwarning("Alert", message)
