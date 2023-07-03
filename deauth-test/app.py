from flask import Flask, render_template
from flask_socketio import SocketIO, emit
import pyshark
import threading

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'
socketio = SocketIO(app)

capture_thread = None
stop_capture = False

def packet_capture():
    global stop_capture

    # Start packet capture on wlan0 interface
    capture = pyshark.LiveCapture(interface='wlan0', bpf_filter='wlan.fc.type_subtype == 0x0C')

    # Process captured packets
    for packet in capture.sniff_continuously():
        # Emit packet to the client
        socketio.emit('packet', packet, namespace='/capture')

        # Stop packet capture if flag is set
        if stop_capture:
            capture.close()
            break

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_capture')
def start_capture():
    global capture_thread
    global stop_capture

    # Stop any ongoing capture thread
    if capture_thread and capture_thread.is_alive():
        stop_capture = True
        capture_thread.join()

    # Start new capture thread
    stop_capture = False
    capture_thread = threading.Thread(target=packet_capture)
    capture_thread.start()

    return 'Packet capture started.'

@app.route('/stop_capture')
def stop_capture():
    global capture_thread
    global stop_capture

    # Set stop flag to stop packet capture
    stop_capture = True

    # Wait for the capture thread to finish
    if capture_thread and capture_thread.is_alive():
        capture_thread.join()

    return 'Packet capture stopped.'

@socketio.on('connect', namespace='/capture')
def connect():
    print('Client connected')

@socketio.on('disconnect', namespace='/capture')
def disconnect():
    print('Client disconnected')

if __name__ == '__main__':
    socketio.run(app)
