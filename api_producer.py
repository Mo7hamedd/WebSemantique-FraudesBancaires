"""
api_producer.py
===============
API REST Flask qui reçoit des transactions via HTTP POST
et les publie sur Kafka (topic "transactions") au format JSON-LD.

Corrections (v3) :
  - Coordonnées en xsd:double (au lieu de xsd:float) pour que la
    fonction Haversine de Virtuoso (bif:sin/bif:cos) fonctionne.
  - Prise en charge des champs optionnels : commerçant, statut,
    IP, device (transmis dans le JSON-LD).

Usage :
    python api_producer.py

Puis :
    curl -X POST http://localhost:5000/transaction \
         -H "Content-Type: application/json" \
         -d '{"montant": 7500, "devise": "MAD", "type": "Paiement en ligne",
              "pays": "Maroc", "ville": "Casablanca",
              "latitude": 33.5731, "longitude": -7.5898,
              "compte": "compte_809888dd", "carte": "carte_test_809888dd"}'
"""

import json
import uuid
from datetime import datetime

from flask import Flask, jsonify, request
from kafka import KafkaProducer

# ---------- Configuration ----------
import os
KAFKA_SERVER = os.environ.get("KAFKA_SERVER", "localhost:9092")
TOPIC        = "transactions"
NS           = "http://www.semanticweb.org/dell/ontologies/2026/7/Fraude-bancaires-corrigee#"

app = Flask(__name__)

producer = KafkaProducer(
    bootstrap_servers=KAFKA_SERVER,
    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
)


# ---------- Helpers ----------
def _bad_request(msg):
    return jsonify({"statut": "erreur", "message": msg}), 400


def _valider(data):
    """Vérifie que les champs obligatoires sont présents."""
    obligatoires = ["montant", "pays", "ville", "compte", "latitude", "longitude"]
    for champ in obligatoires:
        if champ not in data:
            return f"Champ obligatoire manquant : '{champ}'"
    try:
        float(data["montant"])
    except (TypeError, ValueError):
        return "'montant' doit être numérique"
    try:
        lat = float(data["latitude"])
        lng = float(data["longitude"])
    except (TypeError, ValueError):
        return "'latitude' et 'longitude' doivent être numériques"
    if not (-90.0 <= lat <= 90.0):
        return "'latitude' doit être entre -90 et 90"
    if not (-180.0 <= lng <= 180.0):
        return "'longitude' doit être entre -180 et 180"
    return None


def _construire_jsonld(data):
    """Transforme le JSON reçu en message JSON-LD aligné sur l'ontologie."""
    tx_id  = f"txn_{uuid.uuid4().hex[:8]}"
    loc_id = f"loc_{uuid.uuid4().hex[:8]}"

    # Timestamp : permet de simuler pour tester R011
    if data.get("timestamp"):
        ts = data["timestamp"]
    else:
        ts = datetime.now().isoformat(timespec="seconds")

    message = {
        "@context": {
            "@vocab": NS,
            "xsd": "http://www.w3.org/2001/XMLSchema#"
        },
        "@type": "Transaction",
        "@id": tx_id,

        "transactionID":      tx_id,
        "transactionAmount":  {"@value": float(data["montant"]), "@type": "xsd:decimal"},
        "transactionCurrency": data.get("devise", "MAD"),
        "transactionType":    data.get("type", "Paiement"),
        "transactionTimestamp": {"@value": ts, "@type": "xsd:dateTime"},
        "transactionStatus":  data.get("statut", "Validee"),

        "hasSource":  {"@id": data["compte"]},

        "hasLocation": {
            "@type": "Localisation",
            "@id": loc_id,
            "locationCountry":   data["pays"],
            "locationCity":      data["ville"],
            # xsd:double (et non xsd:float) pour compatibilité Haversine
            "locationLatitude":  {"@value": float(data["latitude"]),  "@type": "xsd:double"},
            "locationLongitude": {"@value": float(data["longitude"]), "@type": "xsd:double"},
        },
    }

    if data.get("carte"):
        message["usesCard"] = {"@id": data["carte"]}

    if data.get("commercant"):
        message["transactionMerchant"] = data["commercant"]

    # Champs optionnels pour localisation (IP / device)
    if data.get("ip"):
        message["hasLocation"]["locationIP"] = data["ip"]
    if data.get("device"):
        message["hasLocation"]["locationDevice"] = data["device"]

    return message


# ---------- Route principale ----------
@app.route("/transaction", methods=["POST"])
def transaction():
    data = request.get_json(silent=True)

    if not data:
        return _bad_request("Corps JSON manquant ou invalide")

    erreur = _valider(data)
    if erreur:
        return _bad_request(erreur)

    message = _construire_jsonld(data)
    producer.send(TOPIC, value=message)
    producer.flush()

    return jsonify({
        "statut":  "acceptee",
        "txn_id":  message["@id"],
        "topic":   TOPIC,
        "message": "Transaction publiée sur Kafka",
    }), 201


# ---------- Lancement ----------
if __name__ == "__main__":
    print(f"[OK] API Producer démarrée")
    print(f"[OK] Kafka : {KAFKA_SERVER}")
    print(f"[OK] Topic : {TOPIC}")
    print(f"\n→ Endpoint : POST http://localhost:5000/transaction\n")
    app.run(host="0.0.0.0", port=5000, debug=False)