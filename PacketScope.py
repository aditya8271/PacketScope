from flask import Flask, render_template_string, Response, jsonify
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw
import threading
import queue
import time
import os
import sys

# --- Backend Configuration ---
app = Flask(__name__)
packet_queue = queue.Queue()
# Add a small delay to make the UI flow smoother, especially on mobile.
PACKET_PROCESS_DELAY = 0.05
stats = {'total': 0, 'tcp': 0, 'udp': 0, 'icmp': 0, 'arp': 0, 'other': 0}

# --- Frontend Template ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PacketScope - Network Analyzer</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        :root {
            --bg-dark-blue: #0d1117;
            --card-bg: rgba(22, 27, 34, 0.75);
            --border-color: rgba(255, 255, 255, 0.1);
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-blue: #388bfd;
            --accent-green: #238636;
            --tcp-color: #f78166;
            --udp-color: #58a6ff;
            --icmp-color: #a371f7;
            --arp-color: #e3b341;
            --other-color: #7d8590;
        }

        @keyframes gradient-animation {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-dark-blue);
            background-image: linear-gradient(-45deg, #0d1117, #161b22, #010409);
            background-size: 400% 400%;
            animation: gradient-animation 15s ease infinite;
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }

        .header {
            text-align: center;
            margin-bottom: 2rem;
        }
        .header h1 {
            font-size: 2.8rem;
            font-weight: 700;
            color: white;
        }
        .header i { color: var(--accent-blue); }
        .header p { color: var(--text-secondary); font-size: 1.1rem; }

        .dashboard {
            display: grid;
            grid-template-columns: 1fr 320px;
            gap: 2rem;
        }

        .card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            backdrop-filter: blur(20px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }

        .card-header {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .card-title {
            font-size: 1.25rem;
            font-weight: 600;
            color: white;
        }

        .btn {
            background-color: transparent;
            color: var(--text-primary);
            border: 1px solid var(--border-color);
            padding: 0.5rem 1rem;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.9rem;
            font-weight: 500;
            transition: all 0.2s ease;
            margin-left: 0.5rem;
        }
        .btn:hover {
            background-color: var(--accent-blue);
            color: white;
            border-color: var(--accent-blue);
        }
        .btn.paused {
            background-color: var(--accent-green);
            color: white;
            border-color: var(--accent-green);
        }

        .stats-list li {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border-color);
            list-style: none;
        }
        .stats-list li:last-child { border: none; }
        .stats-list .stat-value { font-weight: 700; font-size: 1.1rem; }

        /* --- Desktop Table View --- */
        .desktop-table-container {
            max-height: 65vh;
            overflow-y: auto;
        }
        .desktop-table {
            width: 100%;
            border-collapse: collapse;
            table-layout: fixed; /* CRITICAL: Prevents content from expanding columns */
        }
        .desktop-table th, .desktop-table td {
            padding: 0.85rem 1.5rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
            word-wrap: break-word; /* Ensure long words break */
        }
        /* Define column widths */
        .desktop-table th:nth-child(1) { width: 10%; } /* Time */
        .desktop-table th:nth-child(2) { width: 20%; } /* Source */
        .desktop-table th:nth-child(3) { width: 20%; } /* Destination */
        .desktop-table th:nth-child(4) { width: 10%; } /* Protocol */
        .desktop-table th:nth-child(5) { width: 10%; } /* Size */
        .desktop-table th:nth-child(6) { width: 30%; } /* Payload */
        
        .desktop-table thead th {
            position: sticky;
            top: 0;
            background-color: rgba(22, 27, 34, 0.9);
            backdrop-filter: blur(10px);
            font-weight: 600;
        }
        .desktop-table tbody tr:hover {
            background-color: rgba(36, 41, 47, 0.7);
        }
        .no-packets-msg {
            text-align: center;
            padding: 4rem;
            color: var(--text-secondary);
        }
        .protocol-tag { font-weight: bold; }
        .protocol-tcp { color: var(--tcp-color); }
        .protocol-udp { color: var(--udp-color); }
        .protocol-icmp { color: var(--icmp-color); }
        .protocol-arp { color: var(--arp-color); }
        .protocol-other { color: var(--other-color); }
        
        .payload-cell {
            font-family: 'Courier New', Courier, monospace;
            font-size: 0.85rem;
            color: var(--text-secondary);
            white-space: normal; /* Allow text to wrap */
        }

        /* Hide mobile elements on desktop */
        .mobile-packet-box { display: none; }

        /* --- Responsive Design --- */
        @media (max-width: 1024px) {
            .dashboard {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 768px) {
            .container { padding: 1rem; }
            .header h1 { font-size: 2rem; }

            /* Hide desktop table and show mobile box */
            .desktop-table-container { display: none; }
            .mobile-packet-box {
                display: flex;
                flex-direction: column;
                height: 60vh;
                padding: 0.5rem;
                overflow-y: auto;
            }

            .packet-item {
                background-color: rgba(36, 41, 47, 0.5);
                border: 1px solid var(--border-color);
                border-radius: 8px;
                padding: 1rem;
                margin-bottom: 0.75rem;
                display: flex;
                flex-direction: column;
            }
            .packet-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 0.75rem;
                padding-bottom: 0.75rem;
                border-bottom: 1px solid var(--border-color);
            }
            .packet-ips {
                font-weight: 600;
                color: white;
                word-break: break-all;
            }
            .packet-details {
                display: flex;
                flex-direction: column;
                gap: 0.5rem;
                font-size: 0.9rem;
            }
            .detail-row {
                display: flex;
                justify-content: space-between;
            }
            .detail-label {
                color: var(--text-secondary);
                font-weight: 500;
                margin-right: 1rem;
            }
            .detail-value {
                text-align: right;
                word-break: break-all;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1><i class="fa-solid fa-shield-halved"></i> PacketScope</h1>
            <p>Professional Network Packet Analyzer</p>
        </header>

        <div class="dashboard">
            <main class="main-content card">
                <div class="card-header">
                    <h2 class="card-title"><i class="fa-solid fa-stream"></i> Live Packet Stream</h2>
                    <div class="controls">
                        <button id="pause-btn" class="btn"><i class="fa-solid fa-pause"></i> Pause</button>
                        <button id="clear-btn" class="btn"><i class="fa-solid fa-trash"></i> Clear</button>
                    </div>
                </div>
                <!-- Container for Desktop Table -->
                <div class="desktop-table-container">
                    <table class="desktop-table">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Source</th>
                                <th>Destination</th>
                                <th>Protocol</th>
                                <th>Size</th>
                                <th>Payload Data (first 32 bytes)</th>
                            </tr>
                        </thead>
                        <tbody id="packet-table-desktop">
                            <tr><td colspan="6" class="no-packets-msg"><i class="fa-solid fa-satellite-dish"></i> Awaiting network traffic...</td></tr>
                        </tbody>
                    </table>
                </div>
                <!-- Container for Mobile Packet Box -->
                <div class="mobile-packet-box" id="packet-box-mobile">
                     <div class="no-packets-msg" id="mobile-no-packets-msg"><i class="fa-solid fa-satellite-dish"></i> Awaiting network traffic...</div>
                </div>
            </main>
            <aside class="sidebar card">
                <div class="card-header">
                    <h2 class="card-title"><i class="fa-solid fa-chart-pie"></i> Traffic Statistics</h2>
                </div>
                <ul class="stats-list">
                    <li><span><i class="fa-solid fa-globe"></i> Total Packets</span> <span class="stat-value" id="stat-total">0</span></li>
                    <li><span class="protocol-tcp"><i class="fa-solid fa-arrow-right-arrow-left"></i> TCP</span> <span class="stat-value" id="stat-tcp">0</span></li>
                    <li><span class="protocol-udp"><i class="fa-solid fa-paper-plane"></i> UDP</span> <span class="stat-value" id="stat-udp">0</span></li>
                    <li><span class="protocol-icmp"><i class="fa-solid fa-heart-pulse"></i> ICMP</span> <span class="stat-value" id="stat-icmp">0</span></li>
                    <li><span class="protocol-arp"><i class="fa-solid fa-route"></i> ARP</span> <span class="stat-value" id="stat-arp">0</span></li>
                    <li><span class="protocol-other"><i class="fa-solid fa-question-circle"></i> Other</span> <span class="stat-value" id="stat-other">0</span></li>
                </ul>
            </aside>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const pauseBtn = document.getElementById('pause-btn');
            const clearBtn = document.getElementById('clear-btn');
            const desktopTableBody = document.getElementById('packet-table-desktop');
            const mobilePacketBox = document.getElementById('packet-box-mobile');
            const mobileMsg = document.getElementById('mobile-no-packets-msg');
            let isCapturing = true;
            const isMobile = window.matchMedia("(max-width: 768px)").matches;

            pauseBtn.addEventListener('click', () => {
                isCapturing = !isCapturing;
                pauseBtn.innerHTML = isCapturing ? '<i class="fa-solid fa-pause"></i> Pause' : '<i class="fa-solid fa-play"></i> Resume';
                pauseBtn.classList.toggle('paused', !isCapturing);
            });

            clearBtn.addEventListener('click', () => {
                if (isMobile) {
                    mobilePacketBox.innerHTML = '<div class="no-packets-msg"><i class="fa-solid fa-broom"></i> Box cleared.</div>';
                } else {
                    desktopTableBody.innerHTML = '<tr><td colspan="6" class="no-packets-msg"><i class="fa-solid fa-broom"></i> Table cleared.</td></tr>';
                }
            });

            function updateStats() {
                fetch('/stats')
                    .then(response => response.json())
                    .then(data => {
                        for (const key in data) {
                            const el = document.getElementById(`stat-${key}`);
                            if (el) el.textContent = data[key];
                        }
                    });
            }

            async function fetchPackets() {
                try {
                    const response = await fetch('/stream');
                    const reader = response.body.getReader();
                    const decoder = new TextDecoder();

                    while (true) {
                        const { done, value } = await reader.read();
                        if (done) break;

                        const packetStr = decoder.decode(value).trim();
                        if (packetStr && isCapturing) {
                            addPacketToView(packetStr);
                        }
                    }
                } catch (error) {
                    console.error('Stream connection lost. Retrying...', error);
                    setTimeout(fetchPackets, 3000);
                }
            }

            function addPacketToView(packetStr) {
                const fields = packetStr.split('|');
                if (fields.length !== 6) return;
                
                if (isMobile) {
                    addPacketToMobileBox(fields);
                } else {
                    addPacketToDesktopTable(fields);
                }
                updateStats();
            }

            function addPacketToDesktopTable(fields) {
                const [timestamp, src, dst, proto, len, payload] = fields;
                if (desktopTableBody.querySelector('.no-packets-msg')) {
                    desktopTableBody.innerHTML = '';
                }
                
                const row = desktopTableBody.insertRow(0);
                row.innerHTML = `
                    <td>${new Date(parseFloat(timestamp) * 1000).toLocaleTimeString()}</td>
                    <td>${src}</td>
                    <td>${dst}</td>
                    <td><span class="protocol-tag protocol-${proto.toLowerCase()}">${proto}</span></td>
                    <td>${len} bytes</td>
                    <td class="payload-cell">${payload || 'N/A'}</td>
                `;
                while (desktopTableBody.rows.length > 150) {
                    desktopTableBody.deleteRow(-1);
                }
            }

            function addPacketToMobileBox(fields) {
                const [timestamp, src, dst, proto, len, payload] = fields;
                if (mobilePacketBox.querySelector('.no-packets-msg')) {
                    mobilePacketBox.innerHTML = '';
                }

                const packetItem = document.createElement('div');
                packetItem.className = 'packet-item';
                packetItem.innerHTML = `
                    <div class="packet-header">
                        <div class="packet-ips">${src} → ${dst}</div>
                        <div class="protocol-tag protocol-${proto.toLowerCase()}">${proto}</div>
                    </div>
                    <div class="packet-details">
                        <div class="detail-row">
                            <span class="detail-label">Time</span>
                            <span class="detail-value">${new Date(parseFloat(timestamp) * 1000).toLocaleTimeString()}</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Size</span>
                            <span class="detail-value">${len} bytes</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Payload</span>
                            <span class="detail-value payload-cell">${payload || 'N/A'}</span>
                        </div>
                    </div>
                `;
                mobilePacketBox.insertBefore(packetItem, mobilePacketBox.firstChild);
                while (mobilePacketBox.children.length > 150) {
                    mobilePacketBox.removeChild(mobilePacketBox.lastChild);
                }
            }

            fetchPackets();
            setInterval(updateStats, 2500);
        });
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    """Serves the main HTML page."""
    return render_template_string(HTML_TEMPLATE)

@app.route('/stream')
def stream():
    """Streams captured packets to the client."""
    def event_stream():
        while True:
            try:
                packet_data = packet_queue.get(timeout=1)
                yield f"{packet_data}\n"
            except queue.Empty:
                continue
    return Response(event_stream(), mimetype='text/plain')

@app.route('/stats')
def get_stats():
    """Provides traffic statistics as JSON."""
    return jsonify(stats)

def packet_callback(packet):
    """
    Processes each captured packet, adds a delay, and puts it in the queue.
    """
    global stats
    timestamp = time.time()
    payload_hex = ""

    # Extract payload if a raw data layer exists
    if packet.haslayer(Raw):
        payload_bytes = bytes(packet[Raw].load)
        # Get first 32 bytes and convert to a space-separated hex string for readability
        payload_hex = " ".join(f"{b:02x}" for b in payload_bytes[:32])

    # Process IP layer packets
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "Other"

        if packet.haslayer(TCP):
            proto = "TCP"
            stats['tcp'] += 1
        elif packet.haslayer(UDP):
            proto = "UDP"
            stats['udp'] += 1
        elif packet.haslayer(ICMP):
            proto = "ICMP"
            stats['icmp'] += 1
        else:
            stats['other'] += 1
        
        stats['total'] += 1
        data_str = f"{timestamp}|{src}|{dst}|{proto}|{len(packet)}|{payload_hex}"
        packet_queue.put(data_str)

    # Process ARP packets
    elif packet.haslayer(ARP):
        src = packet[ARP].psrc
        dst = packet[ARP].pdst
        proto = "ARP"
        
        stats['arp'] += 1
        stats['total'] += 1
        # ARP packets don't have a payload in the same way, so payload_hex will be empty
        data_str = f"{timestamp}|{src}|{dst}|{proto}|{len(packet)}|{payload_hex}"
        packet_queue.put(data_str)
    
    # Introduce a delay to control the packet flow rate to the frontend
    time.sleep(PACKET_PROCESS_DELAY)


def start_sniffing():
    """Starts the Scapy packet sniffer."""
    print("🚀 Starting packet capture...")
    try:
        sniff(prn=packet_callback, store=False, filter="")
    except PermissionError:
        # This error is expected on unprivileged environments like Render
        print("\n❌ CRITICAL ERROR: Permission to capture packets denied.", file=sys.stderr)
        print("This application requires root/administrator privileges to access network sockets.", file=sys.stderr)
        print("Packet sniffing will NOT work on standard cloud hosting services like Render.", file=sys.stderr)
        print("The web interface will load, but no data will be captured.", file=sys.stderr)
    except Exception as e:
        print(f"❌ An unexpected error occurred during sniffing: {e}", file=sys.stderr)

# --- Deployment-Ready Execution ---
# Check if the environment is likely a production environment (like Render)
# Render sets the 'RENDER' environment variable.
IS_PROD = 'RENDER' in os.environ

# Only start the sniffer thread if NOT in a production environment
# or if running as root (which won't be the case on Render).
# The `hasattr(os, 'geteuid')` check handles non-Unix systems like Windows.
can_sniff = not IS_PROD and (not hasattr(os, 'geteuid') or os.geteuid() == 0)

if can_sniff:
    sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniffer_thread.start()
else:
    print("⚠️ WARNING: Running in a restricted environment or without root privileges.")
    print("Packet sniffing thread will not be started.")
    print("Web UI will be active, but no packets will be captured.")


# The following block is for LOCAL DEVELOPMENT ONLY.
# Render will use Gunicorn to run the 'app' object directly.
if __name__ == '__main__':
    print("🔥 PacketScope - Local Development Server 🔥")
    print("="*45)
    if not can_sniff:
        print("Reminder: Run with 'sudo python your_script_name.py' for packet capture.")
    
    print(f"🌐 Web interface available at http://127.0.0.1:5000")
    print("👉 Press Ctrl+C to stop the server.")
    
    # Flask's development server is not suitable for production.
    app.run(host='0.0.0.0', port=5000, debug=False)


