"""
consumer_detection.py
=====================
Consumer Kafka qui détecte la fraude en temps réel.

Pipeline :
    1. Lit un message JSON-LD sur le topic "transactions"
    2. Insère la transaction dans Virtuoso
    3. Exécute les 10 règles SPARQL
    4. Publie les alertes sur le topic "alertes"

Usage :
    python consumer_detection.py
"""

import json
import signal
import sys
import uuid
from datetime import datetime

from kafka import KafkaConsumer, KafkaProducer

from sparql_engine import FraudEngine

# ---------- Configuration ----------
#KAFKA_SERVER   = "localhost:9092"
import os
KAFKA_SERVER   = os.environ.get("KAFKA_SERVER", "localhost:9092")
TOPIC_IN       = "transactions"
TOPIC_OUT      = "alertes"
GROUP_ID       = "detection-groupe"
NS             = "http://www.semanticweb.org/dell/ontologies/2026/7/Fraude-bancaires-corrigee#"

# ---------- Initialisation ----------
print("[INFO] Initialisation du moteur SPARQL...")
engine = FraudEngine()
print("[OK] Moteur SPARQL prêt")

print(f"[INFO] Connexion à Kafka ({KAFKA_SERVER})...")
consumer = KafkaConsumer(
    TOPIC_IN,
    bootstrap_servers=KAFKA_SERVER,
    group_id=GROUP_ID,
    auto_offset_reset="earliest",
    enable_auto_commit=True,
    value_deserializer=lambda m: json.loads(m.decode("utf-8")),
)

producer = KafkaProducer(
    bootstrap_servers=KAFKA_SERVER,
    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
)
print(f"[OK] Consumer connecté sur '{TOPIC_IN}'")
print(f"[OK] Producer prêt pour '{TOPIC_OUT}'")


# ---------- Transformation JSON-LD → dict simple ----------
def extraire_transaction(message):
    """Transforme un message JSON-LD en dict exploitable par sparql_engine."""
    return {
        "id":      message["@id"],
        "montant": message["transactionAmount"]["@value"],
        "devise":  message.get("transactionCurrency", "MAD"),
        "type":    message.get("transactionType", "Paiement"),
        "date":    message["transactionTimestamp"]["@value"],
        "pays":    message["hasLocation"]["locationCountry"],
        "ville":   message["hasLocation"]["locationCity"],
        "compte":  message["hasSource"]["@id"],
        "carte":   message.get("usesCard", {}).get("@id") if message.get("usesCard") else None,
    }


def construire_message_alerte(alerte, tx_id):
    """Construit le JSON-LD d'une alerte pour publication sur Kafka."""
    alerte_id = f"alerte_{uuid.uuid4().hex[:8]}"
    preuve_id = f"preuve_{uuid.uuid4().hex[:8]}"
    ts = datetime.now().isoformat(timespec="seconds")

    classes = {
        "R001": "AlerteFraudeMontant",
        "R002": "AlerteFraudePays",
        "R003": "AlerteFraudeHeure",
        "R004": "AlerteFraudeFrequence",
        "R005": "AlerteFraudeCumul",
        "R006": "AlerteFraudeMultiPays",
        "R007": "AlerteFraudeHistorique",
        "R008": "AlerteFraudeSolde",
        "R009": "AlerteFraudePlafond",
        "R010": "AlerteFraudeLocalisation",
    }
    classe = classes.get(alerte["regle"], "AlerteFraude")

    return {
        "@context": {
            "@vocab": NS,
            "xsd": "http://www.w3.org/2001/XMLSchema#"
        },
        "@type": classe,
        "@id": alerte_id,

        "alertID":         str(uuid.uuid4()),
        "alertType":       alerte["regle"],
        "alertSeverity":   alerte["severite"],
        "alertStatus":     "Ouverte",
        "alertTimestamp":  {"@value": ts, "@type": "xsd:dateTime"},
        "alertDescription": alerte["detail"],

        "triggeredBy":   {"@id": tx_id},
        "triggersRule":  {"@id": f"regle_{alerte['regle']}"},

        "hasAlertEvidence": {
            "@type": "Preuve",
            "@id": preuve_id,
            "evidenceDescription": alerte["detail"],
            "evidenceTimestamp":   {"@value": ts, "@type": "xsd:dateTime"},
            "hasViolatedRule":     {"@id": f"regle_{alerte['regle']}"},
            "concernsTransaction": {"@id": tx_id},
        },
    }


# ---------- Traitement d'une transaction ----------
def traiter(message, numero):
    """Pipeline complet : insertion → détection → publication."""
    tx = extraire_transaction(message)

    print(f"\n[{numero:03d}] ─── {tx['id']} ───")
    print(f"     Montant : {tx['montant']} {tx['devise']} | {tx['type']}")
    print(f"     Lieu    : {tx['ville']}, {tx['pays']}")
    print(f"     Compte  : {tx['compte']} | Carte : {tx['carte'] or 'aucune'}")

    # 1. Insertion dans Virtuoso
    try:
        engine.inserer_transaction(tx)
        print(f"     [OK] Transaction insérée dans Virtuoso")
    except Exception as e:
        print(f"     [ERREUR] Insertion : {e}")
        return

    # 2. Détection (les 10 règles + journalisation des alertes)
    try:
        alertes = engine.detecter(tx["id"], journaliser=True)
    except Exception as e:
        print(f"     [ERREUR] Détection : {e}")
        return

    # 3. Publication des alertes sur Kafka
    if alertes:
        print(f"     ⚠️  {len(alertes)} alerte(s) détectée(s) :")
        for a in alertes:
            print(f"          [{a['regle']}] {a['severite']:8s} — {a['detail']}")
            message_alerte = construire_message_alerte(a, tx["id"])
            producer.send(TOPIC_OUT, value=message_alerte)
        producer.flush()
        print(f"     [OK] Alertes publiées sur '{TOPIC_OUT}'")
    else:
        print(f"     ✅ Aucune alerte (transaction normale)")


# ---------- Boucle principale ----------
def main():
    print(f"\n{'=' * 70}")
    print(f"  Consumer de détection démarré")
    print(f"  Écoute sur '{TOPIC_IN}' | Publie sur '{TOPIC_OUT}'")
    print(f"  Ctrl+C pour arrêter")
    print(f"{'=' * 70}\n")

    numero = 0
    for message in consumer:
        numero += 1
        try:
            traiter(message.value, numero)
        except Exception as e:
            print(f"[ERREUR] Traitement message #{numero} : {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[INFO] Arrêt demandé")
        consumer.close()
        producer.close()
        print("[OK] Consumer et producer fermés")
        sys.exit(0)