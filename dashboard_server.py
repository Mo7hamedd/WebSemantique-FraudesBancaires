"""
dashboard_server.py
===================
Serveur Flask qui affiche les alertes de fraude en temps réel.

- Consomme le topic Kafka "alertes" en arrière-plan
- Expose un endpoint SSE /stream qui pousse les alertes au navigateur
- Sert la page HTML dashboard.html

Usage :
    python dashboard_server.py
Puis ouvrir : http://localhost:5001
"""

import json
import threading
import time
from collections import deque

from flask import Flask, Response, jsonify, send_from_directory
from kafka import KafkaConsumer
from SPARQLWrapper import SPARQLWrapper, JSON as SPARQL_JSON

# ---------- Configuration Virtuoso ----------
#VIRTUOSO_ENDPOINT = "http://localhost:8890/sparql"
#VIRTUOSO_GRAPH    = "http://localhost:8890/fraudes"
VIRTUOSO_ENDPOINT = os.environ.get("VIRTUOSO_ENDPOINT", "http://localhost:8890/sparql")
VIRTUOSO_GRAPH    = os.environ.get("VIRTUOSO_GRAPH",    "http://localhost:8890/fraudes")
NS                = "http://www.semanticweb.org/dell/ontologies/2026/7/Fraude-bancaires-corrigee#"
# ---------- Configuration ----------
#KAFKA_SERVER = "localhost:9092"
import os
KAFKA_SERVER = os.environ.get("KAFKA_SERVER", "localhost:9092")
TOPIC        = "alertes"
GROUP_ID     = "dashboard-groupe"

app = Flask(__name__, static_folder=".")

# Stockage en mémoire des N dernières alertes
alertes_recentes = deque(maxlen=200)
# Files d'attente des clients SSE connectés
clients_sse = []
# Verrou pour éviter les accès concurrents
verrou = threading.Lock()


# ---------- Consumer Kafka en arrière-plan ----------
def consommer_alertes():
    """Boucle infinie : lit les alertes de Kafka et les pousse aux clients SSE."""
    consumer = KafkaConsumer(
        TOPIC,
        bootstrap_servers=KAFKA_SERVER,
        group_id=GROUP_ID,
        auto_offset_reset="latest",
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
    )
    print(f"[OK] Consumer dashboard connecté sur '{TOPIC}'")

    for message in consumer:
        alerte = message.value

        with verrou:
            alertes_recentes.append(alerte)
            # Push vers tous les clients SSE connectés
            payload = json.dumps(alerte, ensure_ascii=False)
            for queue in list(clients_sse):
                try:
                    queue.append(payload)
                except Exception:
                    pass

        # Log dans le terminal
        type_alerte = alerte.get("alertType", "?")
        severite    = alerte.get("alertSeverity", "?")
        desc        = alerte.get("alertDescription", "")
        tx          = alerte.get("triggeredBy", {})
        tx_id       = tx.get("@id", "?") if isinstance(tx, dict) else "?"
        print(f"[ALERTE] {type_alerte:5s} | {severite:8s} | {tx_id:20s} | {desc}")


# ---------- Routes Flask ----------
@app.route("/")
def index():
    """Sert la page HTML du dashboard."""
    return send_from_directory(".", "dashboard.html")


@app.route("/alertes")
def lister_alertes():
    """Retourne les N dernières alertes (chargement initial)."""
    with verrou:
        return jsonify(list(alertes_recentes))


@app.route("/stats")
def stats():
    """Stats temps réel (mémoire) + total historique (SPARQL)."""
    with verrou:
        total_recent = len(alertes_recentes)

    # Total historique depuis Virtuoso
    total_historique = 0
    try:
        sparql = SPARQLWrapper(VIRTUOSO_ENDPOINT)
        sparql.setReturnFormat(SPARQL_JSON)
        sparql.setQuery(f"""
            PREFIX : <{NS}>
            SELECT (COUNT(DISTINCT ?alerte) AS ?total) WHERE {{
              GRAPH <{VIRTUOSO_GRAPH}> {{ ?alerte a :AlerteFraude . }}
            }}
        """)
        result = sparql.query().convert()
        total_historique = int(result["results"]["bindings"][0]["total"]["value"])
    except Exception as e:
        print(f"[ERREUR SPARQL /stats] {e}")

    return jsonify({
        "temps_reel": {"total_recent": total_recent},
        "historique": {"total": total_historique},
    })
# ---------- Helper SPARQL ----------
def requete_sparql(query):
    """Exécute une requête SPARQL et retourne les bindings."""
    sparql = SPARQLWrapper(VIRTUOSO_ENDPOINT)
    sparql.setReturnFormat(SPARQL_JSON)
    sparql.setQuery(f"PREFIX : <{NS}>\nPREFIX xsd: <http://www.w3.org/2001/XMLSchema#>\n" + query)
    result = sparql.query().convert()
    return result["results"]["bindings"]


@app.route("/analytics")
def analytics():
    """Toutes les statistiques analytiques en un seul appel (SPARQL sur Virtuoso)."""
    try:
        top_regles = requete_sparql(f"""
            SELECT ?regle (COUNT(?alerte) AS ?nb) WHERE {{
              GRAPH <{VIRTUOSO_GRAPH}> {{ ?alerte :alertType ?regle . }}
            }} GROUP BY ?regle ORDER BY DESC(?nb) LIMIT 5
        """)

        par_severite = requete_sparql(f"""
            SELECT ?severite (COUNT(?alerte) AS ?nb) WHERE {{
              GRAPH <{VIRTUOSO_GRAPH}> {{ ?alerte :alertSeverity ?severite . }}
            }} GROUP BY ?severite
        """)

        par_heure = requete_sparql(f"""
            SELECT (SUBSTR(STR(?ts), 12, 2) AS ?heure) (COUNT(?alerte) AS ?nb) WHERE {{
              GRAPH <{VIRTUOSO_GRAPH}> {{ ?alerte :alertTimestamp ?ts . }}
            }} GROUP BY (SUBSTR(STR(?ts), 12, 2)) ORDER BY ?heure
        """)

        top_clients = requete_sparql(f"""
            SELECT ?client (COUNT(?alerte) AS ?nb) WHERE {{
              GRAPH <{VIRTUOSO_GRAPH}> {{
                ?alerte :triggeredBy ?tx .
                ?tx :hasSource ?compte .
                ?compte :belongsTo ?client .
              }}
            }} GROUP BY ?client ORDER BY DESC(?nb) LIMIT 5
        """)

        distribution = requete_sparql(f"""
            SELECT ?tranche (COUNT(?tx) AS ?nb) WHERE {{
              GRAPH <{VIRTUOSO_GRAPH}> {{
                ?tx :transactionAmount ?m .
                BIND(IF(?m < 500, "0-500",
                     IF(?m < 2000, "500-2000",
                     IF(?m < 5000, "2000-5000",
                     IF(?m < 10000, "5000-10000", "10000+")))) AS ?tranche)
              }}
            }} GROUP BY ?tranche ORDER BY ?tranche
        """)

        # Nettoyage : on retourne des dicts simples
        def simplifier(rows, *cles):
            out = []
            for r in rows:
                out.append({k: r[k]["value"] for k in cles})
            return out

        return jsonify({
            "top_regles":     simplifier(top_regles, "regle", "nb"),
            "par_severite":   simplifier(par_severite, "severite", "nb"),
            "par_heure":      simplifier(par_heure, "heure", "nb"),
            "top_clients":    simplifier(top_clients, "client", "nb"),
            "distribution":   simplifier(distribution, "tranche", "nb"),
        })

    except Exception as e:
        print(f"[ERREUR /analytics] {e}")
        return jsonify({"erreur": str(e)}), 500

@app.route("/stream")
def stream():
    """Endpoint SSE : pousse les alertes en temps réel au navigateur."""
    def event_generator():
        queue = []
        with verrou:
            clients_sse.append(queue)

        try:
            # Message initial pour confirmer la connexion
            yield f"data: {json.dumps({'type': 'connected'})}\n\n"

            while True:
                if queue:
                    payload = queue.pop(0)
                    yield f"data: {payload}\n\n"
                else:
                    # Heartbeat pour garder la connexion ouverte
                    yield ": heartbeat\n\n"
                    time.sleep(1)
        except GeneratorExit:
            with verrou:
                if queue in clients_sse:
                    clients_sse.remove(queue)

    return Response(
        event_generator(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ---------- Lancement ----------
if __name__ == "__main__":
    # Démarre le consumer Kafka dans un thread séparé
    thread = threading.Thread(target=consommer_alertes, daemon=True)
    thread.start()

    print(f"[OK] Dashboard démarré")
    print(f"[OK] URL      : http://localhost:5001")
    print(f"[OK] Endpoints: / (HTML) | /alertes (JSON) | /stats | /stream (SSE)")
    print(f"[OK] Ctrl+C pour arrêter\n")

    app.run(host="0.0.0.0", port=5001, debug=False, threaded=True)