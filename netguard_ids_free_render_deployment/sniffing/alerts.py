
from extensions import db
from database.models import Alert


def save_alert(ip, attack_type, protocol):

    try:
        alert = Alert(
            ip_address=ip,
            attack_type=attack_type,
            protocol=protocol
        )

        db.session.add(alert)
        db.session.commit()

        print(f"[DB] Alert saved: {ip} - {attack_type}")

        return True

    except Exception as error:

        db.session.rollback()

        print(f"[DB ERROR] Failed to save alert: {error}")

        return False
