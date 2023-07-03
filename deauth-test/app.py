from flask import Flask, render_template
import pyshark

app = Flask(__name__)

@app.route('/')
def index():
    # Start packet capture on wlan0 interface
    capture = pyshark.LiveCapture(interface='wlan0', bpf_filter='wlan.fc.type_subtype == 0x0C')

    # Initialize deauth attack counter
    deauth_count = 0

    # Process captured packets
    for packet in capture.sniff_continuously():
        # Check if the packet is a deauth frame
        if '802.11 Management Frame' in packet and 'Deauthentication' in packet:
            deauth_count += 1
            # You can perform additional actions here, like logging or sending alerts

    # Stop packet capture
    capture.close()

    return render_template('deauth_detection.html', deauth_count=deauth_count)

if __name__ == '__main__':
    app.run()
