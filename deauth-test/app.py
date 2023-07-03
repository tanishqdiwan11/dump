from flask import Flask, render_template
import pyshark
import threading

app = Flask(__name__)

capture_thread = None
stop_capture = False
captured_packets = []

def packet_capture():
    global stop_capture
    global captured_packets

    # Start packet capture on wlan0 interface
    capture = pyshark.LiveCapture(interface='wlan0', bpf_filter='wlan.fc.type_subtype == 0x0C')

    # Process captured packets
    for packet in capture.sniff_continuously():
        # Add packet to the list
        captured_packets.append(packet)

        # Stop packet capture if flag is set
        if stop_capture:
            capture.close()
            break

@app.route('/')
def index():
    return render_template('index.html', captured_packets=captured_packets)

@app.route('/start_capture')
def start_capture():
    global capture_thread
    global stop_capture
    global captured_packets

    # Reset captured packets
    captured_packets = []

    # Stop any ongoing capture thread
    if capture_thread and capture_thread.is_alive():
        stop_capture = True
        capture_thread.join()

    # Start new capture thread
    stop_capture = False
    capture_thread = threading.Thread(target=packet_capture)
    capture_thread.start()

    return render_template('index.html', captured_packets=captured_packets)

@app.route('/stop_capture')
def stop_capture():
    global capture_thread
    global stop_capture

    # Set stop flag to stop packet capture
    stop_capture = True

    # Wait for the capture thread to finish
    if capture_thread and capture_thread.is_alive():
        capture_thread.join()

    return render_template('index.html', captured_packets=captured_packets)

if __name__ == '__main__':
    app.run()
