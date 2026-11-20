
from datetime import datetime

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

from sniffing.alerts import save_alert
from sniffing.detector import detect_port_scan
from database.models import NetworkLog


from extensions import db


FLASK_APP = None


def process_packet(packet):

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = "Other"
    src_port = None
    dst_port = None

    # Identify TCP packets
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        protocol = "TCP"
        src_port = tcp.sport
        dst_port = tcp.dport

    # Identify UDP packets
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        protocol = "UDP"
        src_port = udp.sport
        dst_port = udp.dport

    print(f"[PACKET] {src_ip} -> {dst_ip} ({protocol})")

    try:
        with FLASK_APP.app_context():

            log = NetworkLog(
                source_ip=src_ip,
                destination_ip=dst_ip,
                protocol=protocol,
                source_port=src_port,
                destination_port=dst_port,
                timestamp=datetime.utcnow()
            )

            db.session.add(log)
            db.session.commit()

            print("[DB] Network packet logged")

    except Exception as error:
        print(f"[LOG ERROR] {error}")

        with FLASK_APP.app_context():
            db.session.rollback()

    # Existing port scan detection
    if packet.haslayer(TCP):

        tcp = packet[TCP]

        if tcp.flags & 0x02 and not tcp.flags & 0x10:

            print(f"[SYN] {src_ip} -> {dst_ip}:{dst_port}")

            suspicious = detect_port_scan(
                src_ip,
                dst_ip,
                dst_port
            )

            if suspicious:

                print(
                    f"[ALERT] Port Scan Detected: "
                    f"{src_ip} -> {dst_ip}"
                )

                try:
                    with FLASK_APP.app_context():

                        saved = save_alert(
                            src_ip,
                            "Port Scanning",
                            "TCP"
                        )

                        if saved:
                            print("[DB] Alert saved successfully")

                except Exception as error:
                    print(f"[DB ERROR] {error}")


def start_sniffing(app):

    global FLASK_APP
    FLASK_APP = app

    print("=== IDS SNIFFER STARTED ===")

    sniff(
        prn=process_packet,
        store=False
    )
