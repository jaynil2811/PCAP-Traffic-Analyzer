from flask import Flask, render_template, request, jsonify
import scapy.all as scapy
from collections import Counter, defaultdict
import pandas as pd
from datetime import datetime
import json
import os
import numpy as np
import matplotlib
matplotlib.use('Agg')  # Set backend before importing pyplot
import matplotlib.pyplot as plt
import io
import base64
from matplotlib.figure import Figure

app = Flask(__name__, static_folder='static')

def create_traffic_plot(timestamps, packet_sizes):
    try:
        plt.switch_backend('Agg')
        fig = Figure(figsize=(10, 4), facecolor='none')
        ax = fig.add_subplot(1, 1, 1)
        ax.plot(timestamps, packet_sizes, color='#2196F3')
        ax.set_title('Network Traffic Flow', color='white')
        ax.set_xlabel('Time', color='white')
        ax.set_ylabel('Packet Size (bytes)', color='white')
        ax.grid(True, alpha=0.3)
        ax.tick_params(colors='white')
        
        for spine in ax.spines.values():
            spine.set_color('white')
            
        fig.autofmt_xdate()
        
        buf = io.BytesIO()
        fig.savefig(buf, format='png', bbox_inches='tight', transparent=True, dpi=100)
        plt.close(fig)
        buf.seek(0)
        return base64.b64encode(buf.getvalue()).decode('utf-8')
    except Exception as e:
        print(f"Error in plot creation: {e}")
        return None

def analyze_pcap(pcap_file):
    try:
        packets = scapy.rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading PCAP file: {e}")
        return None

    analysis_data = {
        'total_packets': len(packets),
        'protocols': defaultdict(int),
        'ip_stats': defaultdict(lambda: {
            'packets_sent': 0,
            'packets_received': 0,
            'total_bytes': 0,
            'protocols': set()
        }),
        'packet_sizes': [],
        'timestamps': [],
        'conversations': [],
        'protocol_details': {
            'tcp': {'connections': 0},
            'udp': {'datagrams': 0},
            'icmp': {'messages': 0},
            'arp': {'messages': 0},
            'dns': {'queries': 0},
            'http': {'requests': 0},
            'others': {'count': 0}
        },
        'bandwidth_usage': {
            'peak': 0,
            'average': 0,
            'total_mb': 0
        }
    }

    try:
        for packet in packets:
            try:
                # Basic packet info
                packet_size = len(packet)
                analysis_data['packet_sizes'].append(packet_size)
                timestamp = datetime.fromtimestamp(float(packet.time))
                analysis_data['timestamps'].append(timestamp.strftime('%H:%M:%S'))

                # Layer 2 - ARP
                if packet.haslayer(scapy.ARP):
                    analysis_data['protocols']['ARP'] += 1
                    analysis_data['protocol_details']['arp']['messages'] += 1
                    continue

                # Layer 3/4 protocols
                if packet.haslayer(scapy.IP):
                    src_ip = packet[scapy.IP].src
                    dst_ip = packet[scapy.IP].dst
                    
                    # Update IP stats
                    analysis_data['ip_stats'][src_ip]['packets_sent'] += 1
                    analysis_data['ip_stats'][dst_ip]['packets_received'] += 1
                    analysis_data['ip_stats'][src_ip]['total_bytes'] += packet_size

                    # TCP
                    if packet.haslayer(scapy.TCP):
                        analysis_data['protocols']['TCP'] += 1
                        analysis_data['protocol_details']['tcp']['connections'] += 1
                        
                        # HTTP Detection
                        if packet[scapy.TCP].dport == 80 or packet[scapy.TCP].sport == 80:
                            analysis_data['protocols']['HTTP'] += 1
                            analysis_data['protocol_details']['http']['requests'] += 1

                    # UDP
                    elif packet.haslayer(scapy.UDP):
                        analysis_data['protocols']['UDP'] += 1
                        analysis_data['protocol_details']['udp']['datagrams'] += 1
                        
                        # DNS Detection
                        if packet.haslayer(scapy.DNS):
                            analysis_data['protocols']['DNS'] += 1
                            analysis_data['protocol_details']['dns']['queries'] += 1

                    # ICMP
                    elif packet.haslayer(scapy.ICMP):
                        analysis_data['protocols']['ICMP'] += 1
                        analysis_data['protocol_details']['icmp']['messages'] += 1

                    # Record conversation
                    analysis_data['conversations'].append({
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'protocol': packet.lastlayer().name,
                        'size': packet_size,
                        'timestamp': timestamp.strftime('%H:%M:%S')
                    })
                else:
                    analysis_data['protocol_details']['others']['count'] += 1

            except Exception as packet_error:
                print(f"Error processing packet: {packet_error}")
                continue

        # Calculate bandwidth metrics
        if analysis_data['packet_sizes']:
            total_bytes = sum(analysis_data['packet_sizes'])
            duration = len(analysis_data['packet_sizes'])  # in seconds
            analysis_data['bandwidth_usage'].update({
                'peak': max(analysis_data['packet_sizes']),
                'average': total_bytes / duration if duration > 0 else 0,
                'total_mb': total_bytes / (1024 * 1024)
            })

        # Generate traffic plot
        if analysis_data['timestamps']:
            traffic_plot = create_traffic_plot(
                analysis_data['timestamps'][-100:],
                analysis_data['packet_sizes'][-100:]
            )
            analysis_data['traffic_plot'] = traffic_plot

        # Convert protocol sets to lists for JSON serialization
        for ip in analysis_data['ip_stats']:
            analysis_data['ip_stats'][ip]['protocols'] = list(analysis_data['ip_stats'][ip]['protocols'])

        return analysis_data

    except Exception as e:
        print(f"Error in packet analysis: {e}")
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analytics')
def analytics():
    return render_template('analytics.html')

@app.route('/filter')
def filter():
    return render_template('filter.html')

@app.route('/report')
def report():
    return render_template('report.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'pcap_file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['pcap_file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not file.filename.endswith(('.pcap', '.pcapng')):
        return jsonify({'error': 'Invalid file format'}), 400

    temp_path = os.path.join(os.path.dirname(__file__), 'temp.pcap')
    try:
        file.save(temp_path)
        analysis_results = analyze_pcap(temp_path)
        if analysis_results is None:
            return jsonify({'error': 'Failed to analyze PCAP file'}), 500
        return jsonify({
            'success': True,
            'data': analysis_results
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception as e:
                print(f"Error removing temporary file: {e}")

@app.route('/analyze', methods=['POST'])
def analyze():
    temp_path = os.path.join(os.path.dirname(__file__), 'temp.pcap')
    try:
        if 'pcap_file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'}), 400
        
        file = request.files['pcap_file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400

        if file and allowed_file(file.filename):
            # Save the file
            file.save(temp_path)
            
            # Process the file
            analysis_data = analyze_pcap(temp_path)
            
            if analysis_data is None:
                return jsonify({
                    'success': False,
                    'error': 'Failed to analyze PCAP file'
                }), 500

            return jsonify({
                'success': True,
                'data': analysis_data,
                'message': 'Analysis completed successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid file type'
            }), 400

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception as e:
                print(f"Error removing temporary file: {e}")

ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')

if __name__ == '__main__':
    app.run(debug=True, port=5000)