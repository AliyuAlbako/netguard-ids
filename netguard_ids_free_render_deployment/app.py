import os
import threading
from datetime import datetime, timedelta

from flask import Flask, render_template

from extensions import db
from database.models import Alert, NetworkLog
from sniffing.sniffer import start_sniffing

app = Flask(__name__)
os.makedirs(app.instance_path, exist_ok=True)

# Render's free filesystem is temporary. The hosted demonstration uses a
# temporary SQLite database and repopulates it with clearly labelled sample data.
database_url = os.environ.get("DATABASE_URL")
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url or "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)


def seed_demo_data():
    """Create clearly identified sample records for the public demonstration."""
    if os.environ.get("DEMO_MODE", "false").lower() not in {"1", "true", "yes"}:
        return

    if Alert.query.first() or NetworkLog.query.first():
        return

    now = datetime.utcnow()
    sample_alerts = [
        Alert(ip_address="198.51.100.10", attack_type="Port Scanning",
              protocol="TCP", timestamp=now - timedelta(minutes=8)),
        Alert(ip_address="203.0.113.25", attack_type="Port Scanning",
              protocol="TCP", timestamp=now - timedelta(minutes=23)),
        Alert(ip_address="192.0.2.45", attack_type="Port Scanning",
              protocol="TCP", timestamp=now - timedelta(hours=1, minutes=5)),
    ]

    sample_logs = []
    examples = [
        ("198.51.100.10", "198.51.100.20", "TCP", 51520, 22),
        ("198.51.100.10", "198.51.100.20", "TCP", 51521, 80),
        ("203.0.113.25", "198.51.100.20", "TCP", 51522, 443),
        ("192.0.2.45", "198.51.100.20", "UDP", 53000, 53),
        ("198.51.100.10", "198.51.100.20", "TCP", 51523, 21),
        ("203.0.113.25", "198.51.100.20", "UDP", 53001, 123),
        ("192.0.2.45", "198.51.100.20", "TCP", 51524, 8080),
        ("198.51.100.10", "198.51.100.20", "TCP", 51525, 25),
        ("203.0.113.25", "198.51.100.20", "TCP", 51526, 110),
        ("192.0.2.45", "198.51.100.20", "UDP", 53002, 161),
        ("198.51.100.10", "198.51.100.20", "TCP", 51527, 143),
        ("203.0.113.25", "198.51.100.20", "TCP", 51528, 3306),
        ("192.0.2.45", "198.51.100.20", "TCP", 51529, 3389),
        ("198.51.100.10", "198.51.100.20", "UDP", 53003, 500),
        ("203.0.113.25", "198.51.100.20", "TCP", 51530, 8081),
    ]
    for index, item in enumerate(examples):
        src, dst, protocol, src_port, dst_port = item
        sample_logs.append(NetworkLog(
            source_ip=src,
            destination_ip=dst,
            protocol=protocol,
            source_port=src_port,
            destination_port=dst_port,
            timestamp=now - timedelta(minutes=index * 3)
        ))

    db.session.add_all(sample_alerts + sample_logs)
    db.session.commit()


with app.app_context():
    db.create_all()
    seed_demo_data()


@app.context_processor
def inject_demo_mode():
    return {
        "demo_mode": os.environ.get("DEMO_MODE", "false").lower()
        in {"1", "true", "yes"}
    }


@app.route("/")
def index():
    alerts = Alert.query.order_by(Alert.timestamp.desc()).all()
    return render_template("index.html", alerts=alerts)


@app.route("/alerts")
def alerts():
    alert_records = Alert.query.order_by(Alert.timestamp.desc()).all()
    return render_template("alerts.html", alerts=alert_records)


@app.route("/logs")
def logs():
    network_logs = NetworkLog.query.order_by(
        NetworkLog.timestamp.desc()
    ).limit(200).all()
    return render_template("logs.html", logs=network_logs)


if __name__ == "__main__":
    # Packet capture is only enabled when explicitly requested on a local host.
    if os.environ.get("ENABLE_SNIFFER", "true").lower() in {"1", "true", "yes"}:
        sniffer_thread = threading.Thread(
            target=start_sniffing, args=(app,), daemon=True
        )
        sniffer_thread.start()

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
        use_reloader=False
    )
