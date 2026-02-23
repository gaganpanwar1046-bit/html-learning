from flask import Flask, request, jsonify
from flask_cors import CORS
from scapy.all import sniff
import threading

app = Flask(__name__)
CORS(app)

sniffing = False
logs = []

def packet_handler(packet):
    global logs
    logs.append(packet.summary())
    if len(logs) > 20:
        logs.pop(0)

def start_sniffer():
    global sniffing
    sniffing = True
    sniff(prn=packet_handler, stop_filter=lambda x: not sniffing)

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    if data["email"] and data["password"]:
        return jsonify({"status": "success"})
    return jsonify({"status": "fail"}), 401

@app.route("/start", methods=["POST"])
def start():
    global sniffing
    if not sniffing:
        t = threading.Thread(target=start_sniffer)
        t.daemon = True
        t.start()
    return jsonify({"message": "Sniffing started"})

@app.route("/stop", methods=["POST"])
def stop():
    global sniffing
    sniffing = False
    return jsonify({"message": "Sniffing stopped"})

@app.route("/logs", methods=["GET"])
def get_logs():
    return jsonify(logs)

if __name__ == "__main__":
    app.run(debug=True)
