"""
============================================
WIPS DASHBOARD - Green Lantern Security Corps
Flask Backend Server
============================================
"""

from flask import Flask, render_template, request, jsonify
from datetime import datetime
import json
import os
import socket

app = Flask(__name__)

# Store alerts in memory
alerts = []
alert_count = 0

# Log file
LOG_FILE = "alerts.txt"

def get_local_ip():
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return '127.0.0.1'

@app.route('/')
def index():
    """Serve the dashboard homepage"""
    return render_template('index.html')

@app.route('/api/alert', methods=['POST'])
def receive_alert():
    """Receive alerts from ESP32"""
    global alert_count
    
    try:
        # Get JSON data from ESP32
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No data received"}), 400
        
        # Add timestamp
        data['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        data['id'] = alert_count
        alert_count += 1
        
        # Store in memory
        alerts.append(data)
        
        # Keep only last 100 alerts
        if len(alerts) > 100:
            alerts.pop(0)
        
        # Log to file
        log_alert(data)
        
        print(f"[ALERT] {data['type'].upper()} - {data.get('ssid', 'Unknown')}")
        
        return jsonify({"status": "success", "id": data['id']}), 200
        
    except Exception as e:
        print(f"[ERROR] {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get all alerts (for dashboard auto-refresh)"""
    return jsonify(alerts)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get statistics"""
    deauth_count = sum(1 for a in alerts if a.get('type') == 'deauth')
    evil_twin_count = sum(1 for a in alerts if a.get('type') == 'evil_twin')
    
    return jsonify({
        'total': len(alerts),
        'deauth': deauth_count,
        'evil_twin': evil_twin_count,
        'last_alert': alerts[-1]['timestamp'] if alerts else 'None'
    })

@app.route('/api/export', methods=['GET'])
def export_logs():
    """Export all alerts as text"""
    if not alerts:
        return "No alerts to export", 404
    
    export_text = "=" * 60 + "\n"
    export_text += "WIPS ALERT LOG - Green Lantern Security Corps\n"
    export_text += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    export_text += "=" * 60 + "\n\n"
    
    for alert in alerts:
        export_text += f"[{alert['timestamp']}]\n"
        export_text += f"  Type: {alert['type'].upper()}\n"
        
        if alert['type'] == 'deauth':
            export_text += f"  SSID: {alert.get('ssid', 'Unknown')}\n"
            export_text += f"  Attacker MAC: {alert.get('mac', 'Unknown')}\n"
            export_text += f"  Packets: {alert.get('packets', 0)}\n"
        elif alert['type'] == 'evil_twin':
            export_text += f"  SSID: {alert.get('ssid', 'Unknown')}\n"
            export_text += f"  Trusted AP: {alert.get('trusted_mac', 'Unknown')}\n"
            export_text += f"  Rogue AP: {alert.get('rogue_mac', 'Unknown')}\n"
        
        export_text += "\n"
    
    export_text += "=" * 60 + "\n"
    export_text += "End of log\n"
    
    return export_text, 200, {'Content-Type': 'text/plain'}

def log_alert(alert):
    """Save alert to log file"""
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(f"[{alert['timestamp']}] {alert['type'].upper()}\n")
            f.write(json.dumps(alert) + "\n")
            f.write("-" * 40 + "\n")
    except Exception as e:
        print(f"[LOG ERROR] {e}")
@app.route('/api/clear', methods=['POST'])
def clear_alerts():
    """Clear all alerts from server"""
    global alerts
    alerts = []
    return jsonify({"status": "cleared"}), 200

if __name__ == '__main__':
    print("\n" + "=" * 50)
    print("  🟢 WIPS DASHBOARD - Green Lantern Corps")
    print("=" * 50)
    
    ip = get_local_ip()
    print(f"  Starting server on: http://{ip}:5000")
    print("  Or on: http://localhost:5000")
    print("  Press CTRL+C to stop")
    print("=" * 50 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)

