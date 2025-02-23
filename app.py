import asyncio
import aiohttp
import configparser
from apns2.client import APNsClient
from apns2.payload import Payload
from apns2.credentials import TokenCredentials
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

config = configparser.ConfigParser()
config.read('config.ini')

REGISTER_AUTH = config.get('AUTH', 'REGISTER_AUTH', fallback=None)
MANAGE_AUTH = config.get('AUTH', 'MANAGE_AUTH', fallback=None)
SQLALCHEMY_DATABASE_URI = config.get('DATABASE', 'SQLALCHEMY_DATABASE_URI', fallback='sqlite:///device_tokens.db')
auth_key_path = config.get('APNS', 'auth_key_path', fallback='./APNSAuthKey.p8')
auth_key_id = config.get('APNS', 'auth_key_id', fallback=None)
team_id = config.get('APNS', 'team_id', fallback=None)
topic = config.get('APNS', 'topic', fallback=None)
results_api = config.get('API', 'resultsapi', fallback='https://sat-api.tservic.es/api/v1/results')


if not all([REGISTER_AUTH, MANAGE_AUTH, auth_key_id, team_id, topic, results_api]):
    raise ValueError("Fehlende Pflichtfelder in der Konfiguration!")


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
db = SQLAlchemy(app)

def authenticate(request, required_token):
    auth_header = request.headers.get("Authorization")
    return auth_header == f"Bearer {required_token}"


class DeviceToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_token = db.Column(db.String(256), nullable=False, unique=True)

class NotificationLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    result_uuid = db.Column(db.String(256), nullable=False, unique=True)
    sent_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


def create_apns_client():
    token_credentials = TokenCredentials(
        auth_key_path=auth_key_path,
        auth_key_id=auth_key_id,
        team_id=team_id
    )
    return APNsClient(credentials=token_credentials, use_sandbox=False)

def send_notification(device_token, title, subtitle, text):
    try:
        apns_client = create_apns_client()
        payload = Payload(alert=title, sound="default", badge=1, custom={"subtitle": subtitle, "text": text})
        apns_client.send_notification(device_token, payload, topic)
    except Exception as e:
        print(f"Fehler beim Senden der Benachrichtigung: {e}")

async def fetch_results_and_send_notifications():
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(results_api) as response:
                if response.status != 200:
                    raise Exception(f"API Fehler: {response.status}")
                results = await response.json()
                results = results.get('ergebnisse', {})
                if not results:
                    raise ValueError("Keine Ergebnisse gefunden.")

                device_tokens = DeviceToken.query.all()
                for result in results.values():
                    winner_bahn = result[result['winner']]
                    title = f"{result['title']} Ergebnis: {winner_bahn['boot']} gewinnt mit {winner_bahn['zeit']}"
                    subtitle = f"{winner_bahn['boot']} gewinnt mit {winner_bahn['zeit']}"
                    text = "Klicke hier, um die Ergebnisse anzusehen"

                    if NotificationLog.query.filter_by(result_uuid=result['uuid']).first():
                        continue

                    for token in device_tokens:
                        send_notification(token.device_token, title, subtitle, text)

                    new_log = NotificationLog(result_uuid=result['uuid'])
                    db.session.add(new_log)
                    db.session.commit()
    except Exception as e:
        print(f"Fehler beim Abrufen und Senden von Benachrichtigungen: {e}")

@app.route("/api/getresults", methods=["POST"])
def get_results():
    if not authenticate(request, MANAGE_AUTH):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(fetch_results_and_send_notifications())
        return jsonify({"message": "Benachrichtigungen gesendet"}), 200
    except Exception as e:
        return jsonify({'error': 'Interner Serverfehler', 'details': str(e)}), 500

@app.route("/api/registerDeviceToken", methods=["POST"])
def register_device_token():
    if not authenticate(request, REGISTER_AUTH):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        data = request.get_json()
        if 'device_token' not in data:
            return jsonify({'error': 'device_token fehlt'}), 400

        new_device_token = DeviceToken(device_token=data['device_token'])
        db.session.add(new_device_token)
        db.session.commit()
        return jsonify({'message': 'Device Token erfolgreich registriert'}), 200
    except Exception as e:
        return jsonify({'error': 'Interner Serverfehler', 'details': str(e)}), 500

@app.route("/showdevicetokens", methods=["GET"])
def show_device_tokens():
    tokens = DeviceToken.query.all()
    return {"device_tokens": [token.device_token for token in tokens]}

@app.route("/shownotificationlog", methods=["GET"])
def show_notification_log():
    logs = NotificationLog.query.all()
    log_data = [{
        'result_uuid': log.result_uuid,
        'sent_at': log.sent_at.strftime('%Y-%m-%d %H:%M:%S')
    } for log in logs]
    return jsonify({'notification_logs': log_data}), 200

@app.route("/api/deleteAllDeviceTokens", methods=["POST"])
def delete_all_device_tokens():
    if not authenticate(request, MANAGE_AUTH):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        db.session.query(DeviceToken).delete()
        db.session.commit()
        return jsonify({'message': 'Alle Device Tokens wurden gelöscht'}), 200
    except Exception as e:
        return jsonify({'error': 'Interner Serverfehler', 'details': str(e)}), 500

@app.route("/api/customnotify", methods=["POST"])
def custom_notify():
    if not authenticate(request, MANAGE_AUTH):
        return jsonify({"error": "Unauthorized"}), 401

    try:
        data = request.get_json()
        severity = data.get("severity")
        notification_text = data.get("notification")

        if not severity or not notification_text:
            return jsonify({"error": "severity und notification sind erforderlich"}), 400

        severity_icons = {
            "info": "",
            "warning": "⚠️ ",
            "urgent": "❗️ ",
            "danger": "❌ "
        }

        if severity not in severity_icons:
            return jsonify({"error": "Ungültige severity"}), 400

        title = f"{severity_icons[severity]}{notification_text}"
        subtitle = "ignore"
        text = "ignore"

        device_tokens = DeviceToken.query.all()
        for token in device_tokens:
            send_notification(token.device_token, title, subtitle, text)

        return jsonify({"message": "Benachrichtigungen gesendet"}), 200
    except Exception as e:
        return jsonify({'error': 'Interner Serverfehler', 'details': str(e)}), 500


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=3000)
