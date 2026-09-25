"""
sparql_engine.py
================
Moteur de détection de fraude 100% SPARQL sur Virtuoso.

Contient les 11 règles (R001 à R011) sous forme de fonctions Python.
Chaque fonction envoie une requête SPARQL à Virtuoso et retourne
la liste des détections (vide si la règle ne se déclenche pas).

Usage :
    from sparql_engine import FraudEngine
    engine = FraudEngine()
    alertes = engine.detecter("txn_98e8caca")
"""

from SPARQLWrapper import SPARQLWrapper, JSON

import os

class FraudEngine:

    ENDPOINT = os.environ.get("VIRTUOSO_ENDPOINT", "http://localhost:8890/sparql")
    GRAPH    = os.environ.get("VIRTUOSO_GRAPH",    "http://localhost:8890/fraudes")
    PREFIXES = """
PREFIX :    <http://www.semanticweb.org/dell/ontologies/2026/7/Fraude-bancaires-corrigee#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs:<http://www.w3.org/2000/01/rdf-schema#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>
"""

    def __init__(self):
        self.sparql = SPARQLWrapper(self.ENDPOINT)
        self.sparql.setReturnFormat(JSON)

    # ------------------------------------------------------------------ #
    # Méthode interne                                                    #
    # ------------------------------------------------------------------ #

    def _select(self, query):
        self.sparql.setQuery(self.PREFIXES + query)
        result = self.sparql.query().convert()
        return result["results"]["bindings"]

    def _val(self, row, key):
        return row[key]["value"] if key in row else None

    # ------------------------------------------------------------------ #
    # Les 10 règles existantes (R001 à R010) — inchangées                #
    # ------------------------------------------------------------------ #

    def r001_montant(self, tx):
        rows = self._select(f"""
            SELECT ?montant ?seuil WHERE {{
              GRAPH <{self.GRAPH}> {{
                <{self._uri(tx)}> :transactionAmount ?montant .
                ?r :ruleID "R001" ; :ruleThreshold ?seuil .
                FILTER(?montant > ?seuil)
              }}
            }}
        """)
        return [{"regle": "R001", "severite": "Critique",
                 "montant": self._val(r, "montant"),
                 "seuil": self._val(r, "seuil"),
                 "detail": f"Montant {self._val(r,'montant')} > seuil {self._val(r,'seuil')}"}
                for r in rows]

    def r002_pays(self, tx):
        rows = self._select(f"""
            SELECT ?paysTx ?paysHab WHERE {{
              GRAPH <{self.GRAPH}> {{
                <{self._uri(tx)}> :hasLocation ?loc ; :hasSource ?compte .
                ?loc :locationCountry ?paysTx .
                ?compte :belongsTo ?client .
                ?client :hasUsualLocation ?locHab .
                ?locHab :locationCountry ?paysHab .
                FILTER(?paysTx != ?paysHab)
              }}
            }}
        """)
        return [{"regle": "R002", "severite": "Elevee",
                 "paysTx": self._val(r, "paysTx"),
                 "paysHab": self._val(r, "paysHab"),
                 "detail": f"Pays {self._val(r,'paysTx')} != habituel {self._val(r,'paysHab')}"}
                for r in rows]

    def r003_heure(self, tx):
        rows = self._select(f"""
            SELECT ?heure WHERE {{
              GRAPH <{self.GRAPH}> {{
                <{self._uri(tx)}> :transactionTimestamp ?ts .
                BIND(HOURS(?ts) AS ?heure)
                FILTER(?heure >= 23 || ?heure < 6)
              }}
            }}
        """)
        return [{"regle": "R003", "severite": "Elevee",
                 "heure": self._val(r, "heure"),
                 "detail": f"Heure {self._val(r,'heure')}h (plage 23h-6h)"}
                for r in rows]

    def r004_frequence(self, tx):
        rows = self._select(f"""
            SELECT (COUNT(?autre) AS ?nb) WHERE {{
              GRAPH <{self.GRAPH}> {{
                <{self._uri(tx)}> :usesCard ?carte ; :transactionTimestamp ?ts .
                ?autre :usesCard ?carte ; :transactionTimestamp ?ts2 .
                FILTER(?ts2 <= ?ts)
                FILTER(?ts2 >= ?ts - "PT5M"^^xsd:duration)
              }}
            }}
        """)
        if not rows:
            return []
        nb = int(rows[0]["nb"]["value"])
        if nb <= 10:
            return []
        return [{"regle": "R004", "severite": "Elevee",
                 "nb": nb,
                 "detail": f"{nb} transactions en 5 min (seuil 10)"}]

    def r005_cumul(self, tx):
        rows = self._select(f"""
            SELECT (SUM(?m) AS ?cumul) WHERE {{
              GRAPH <{self.GRAPH}> {{
                <{self._uri(tx)}> :hasSource ?compte ; :transactionTimestamp ?ts .
                ?autre :hasSource ?compte ; :transactionAmount ?m ; :transactionTimestamp ?ts2 .
                FILTER(SUBSTR(STR(?ts2), 1, 10) = SUBSTR(STR(?ts), 1, 10))
                FILTER(?ts2 <= ?ts)
              }}
            }}
        """)
        if not rows:
            return []
        if "cumul" not in rows[0] or not rows[0]["cumul"]["value"]:
            return []
        cumul = float(rows[0]["cumul"]["value"])
        if cumul <= 10000:
            return []
        return [{"regle": "R005", "severite": "Elevee",
                 "cumul": cumul,
                 "detail": f"Cumul journalier {cumul:.0f} > 10000"}]

    def r006_multipays(self, tx):
        rows = self._select(f"""
            SELECT (COUNT(DISTINCT ?pays) AS ?nb) WHERE {{
              GRAPH <{self.GRAPH}> {{
                <{self._uri(tx)}> :usesCard ?carte ; :transactionTimestamp ?ts .
                ?autre :usesCard ?carte ; :hasLocation ?loc ; :transactionTimestamp ?ts2 .
                ?loc :locationCountry ?pays .
                FILTER(?ts2 <= ?ts)
                FILTER(bif:datediff('minute', ?ts2, ?ts) <= 60)
              }}
            }}
        """)
        if not rows:
            return []
        nb = int(rows[0]["nb"]["value"])
        if nb <= 2:
            return []
        return [{"regle": "R006", "severite": "Critique",
                 "nb_pays": nb,
                 "detail": f"{nb} pays en 1h (seuil 2)"}]

    def r007_historique(self, tx):
        rows = self._select(f"""
            SELECT ?montant ?moyenne ?nb WHERE {{
              GRAPH <{self.GRAPH}> {{
                <{self._uri(tx)}> :transactionAmount ?montant ; :hasSource ?compte .
                {{
                  SELECT ?compte (AVG(?m) AS ?moyenne) (COUNT(?t) AS ?nb) WHERE {{
                    GRAPH <{self.GRAPH}> {{
                      ?t :hasSource ?compte ; :transactionAmount ?m .
                    }}
                  }}
                  GROUP BY ?compte
                }}
                FILTER(?nb >= 3 && ?montant > 3 * ?moyenne)
              }}
            }}
        """)
        return [{"regle": "R007", "severite": "Elevee",
                 "montant": self._val(r, "montant"),
                 "moyenne": self._val(r, "moyenne"),
                 "nb": self._val(r, "nb"),
                 "detail": f"{self._val(r,'montant')} > 3x moyenne ({self._val(r,'moyenne')})"}
                for r in rows]

    def r008_solde(self, tx):
        rows = self._select(f"""
            SELECT ?montant ?solde WHERE {{
              GRAPH <{self.GRAPH}> {{
                <{self._uri(tx)}> :transactionAmount ?montant ;
                                :hasSource ?compte ;
                                :transactionType ?type .
                ?compte :accountBalance ?solde .
                FILTER(?montant > ?solde)
                FILTER(LCASE(STR(?type)) = "retrait" || LCASE(STR(?type)) = "withdrawal")
              }}
            }}
        """)
        return [{"regle": "R008", "severite": "Elevee",
                 "montant": self._val(r, "montant"),
                 "solde": self._val(r, "solde"),
                 "detail": f"Retrait {self._val(r,'montant')} > solde {self._val(r,'solde')}"}
                for r in rows]

    def r009_plafond(self, tx):
        rows = self._select(f"""
            SELECT ?montant ?plafond WHERE {{
              GRAPH <{self.GRAPH}> {{
                <{self._uri(tx)}> :transactionAmount ?montant ;
                                :hasSource ?compte .
                ?compte :hasCard ?carte .
                ?carte :cardLimit ?plafond .
                FILTER(?montant > ?plafond)
              }}
            }}
        """)
        return [{"regle": "R009", "severite": "Elevee",
                 "montant": self._val(r, "montant"),
                 "plafond": self._val(r, "plafond"),
                 "detail": f"Montant {self._val(r,'montant')} > plafond {self._val(r,'plafond')}"}
                for r in rows]

    def r010_localisation(self, tx):
        rows = self._select(f"""
            SELECT ?paysTx ?villeTx ?paysCur ?villeCur WHERE {{
              GRAPH <{self.GRAPH}> {{
                <{self._uri(tx)}> :hasLocation ?loc ; :hasSource ?compte .
                ?loc :locationCountry ?paysTx ; :locationCity ?villeTx .
                ?compte :belongsTo ?client .
                ?client :hasCurrentLocation ?locCur .
                ?locCur :locationCountry ?paysCur ; :locationCity ?villeCur .
                FILTER(?paysTx != ?paysCur || ?villeTx != ?villeCur)
              }}
            }}
        """)
        return [{"regle": "R010", "severite": "Elevee",
                 "villeTx": self._val(r, "villeTx"),
                 "paysTx": self._val(r, "paysTx"),
                 "villeCur": self._val(r, "villeCur"),
                 "paysCur": self._val(r, "paysCur"),
                 "detail": f"Tx {self._val(r,'villeTx')}/{self._val(r,'paysTx')} != actuel {self._val(r,'villeCur')}/{self._val(r,'paysCur')}"}
                for r in rows]

    # ------------------------------------------------------------------ #
    # R011 — VOYAGE IMPOSSIBLE (nouvelle règle)                          #
    # ------------------------------------------------------------------ #

    def r011_voyage_impossible(self, tx):
        """
        R011 : deux transactions successives sur la même carte donnent
        une vitesse implicite > 900 km/h (seuil lu dans l'ontologie).
        Utilise la formule de Haversine en SPARQL (fonctions Virtuoso).
        """
        rows = self._select(f"""
            SELECT ?txn1 ?ville1 ?pays1 ?ville2 ?pays2
                   ?dist ?deltaH ?vitesse ?seuil WHERE {{

              GRAPH <{self.GRAPH}> {{

                # Transaction courante (txn2)
                <{self._uri(tx)}> :usesCard ?carte ;
                                  :transactionTimestamp ?ts2 ;
                                  :hasLocation ?loc2 .
                ?loc2 :locationLatitude  ?lat2 ;
                      :locationLongitude ?lon2 ;
                      :locationCity      ?ville2 ;
                      :locationCountry   ?pays2 .

                # Transaction précédente sur la même carte (txn1)
                ?txn1 :usesCard ?carte ;
                      :transactionTimestamp ?ts1 ;
                      :hasLocation ?loc1 .
                ?loc1 :locationLatitude  ?lat1 ;
                      :locationLongitude ?lon1 ;
                      :locationCity      ?ville1 ;
                      :locationCountry   ?pays1 .

                FILTER(?ts1 < ?ts2)

                # Empêche de comparer à une transaction plus récente
                # que txn1 mais plus ancienne que txn2 (garde la plus récente)
                FILTER NOT EXISTS {{
                  ?txnX :usesCard ?carte ; :transactionTimestamp ?tsX .
                  FILTER(?ts1 < ?tsX && ?tsX < ?ts2)
                }}

                # Fenêtre max : 6 heures
                BIND(bif:datediff('minute', ?ts1, ?ts2) / 60.0 AS ?deltaH)
                FILTER(?deltaH > 0 && ?deltaH <= 6)

                # --- Haversine (Virtuoso : bif:pi(), bif:sin, bif:cos, bif:asin, bif:sqrt) ---
                BIND(?lat1 * bif:pi() / 180.0 AS ?phi1)
                BIND(?lat2 * bif:pi() / 180.0 AS ?phi2)
                BIND((?lat2 - ?lat1) * bif:pi() / 180.0 AS ?dphi)
                BIND((?lon2 - ?lon1) * bif:pi() / 180.0 AS ?dlambda)

                BIND(
                  bif:sin(?dphi/2) * bif:sin(?dphi/2) +
                  bif:cos(?phi1) * bif:cos(?phi2) *
                  bif:sin(?dlambda/2) * bif:sin(?dlambda/2)
                  AS ?a
                )
                BIND(2 * bif:asin(bif:sqrt(?a)) AS ?c)
                BIND(6371.0 * ?c AS ?dist)

                # Seuil lu depuis l'ontologie (regle_R011 :ruleThreshold 900.0)
                ?r :ruleID "R011" ; :ruleThreshold ?seuil .

                BIND(?dist / ?deltaH AS ?vitesse)
                FILTER(?vitesse > ?seuil)
              }}
            }}
        """)

        resultats = []
        for r in rows:
            v1   = self._val(r, "ville1")
            p1   = self._val(r, "pays1")
            v2   = self._val(r, "ville2")
            p2   = self._val(r, "pays2")
            dist = float(self._val(r, "dist"))
            dh   = float(self._val(r, "deltaH"))
            vit  = float(self._val(r, "vitesse"))
            seuil = float(self._val(r, "seuil"))
            txn1 = self._val(r, "txn1").split("#")[-1]
            resultats.append({
                "regle":    "R011",
                "severite": "Critique",
                "txn_precedente": txn1,
                "de":  f"{v1}, {p1}",
                "vers": f"{v2}, {p2}",
                "distance_km": round(dist, 1),
                "delta_h":     round(dh, 3),
                "vitesse_kmh": round(vit, 1),
                "seuil":       seuil,
                "detail": (f"Voyage impossible : {v1} ({p1}) → {v2} ({p2}) "
                           f"en {dh:.2f} h, {dist:.0f} km → {vit:.0f} km/h "
                           f"(seuil {seuil:.0f} km/h)")
            })
        return resultats

    # ------------------------------------------------------------------ #
    # Écriture dans Virtuoso                                             #
    # ------------------------------------------------------------------ #

    def _update(self, query):
        import urllib.request
        import urllib.parse

        full_query = self.PREFIXES + query
        data = urllib.parse.urlencode({"query": full_query}).encode("utf-8")
        req = urllib.request.Request(
            self.ENDPOINT,
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/sparql-results+json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            return resp.read().decode("utf-8")

    def inserer_transaction(self, tx):
        """
        Insère une nouvelle transaction + sa localisation (avec coordonnées)
        dans Virtuoso.

        Args:
            tx (dict) : id, montant, devise, type, pays, ville,
                        latitude, longitude, date, compte, carte (optionnel).
        """
        import uuid

        tx_id   = tx.get("id") or f"txn_{uuid.uuid4().hex[:8]}"
        montant = float(tx.get("montant", 0))
        devise  = tx.get("devise", "MAD")
        type_tx = tx.get("type", "Paiement")
        pays    = tx.get("pays", "France")
        ville   = tx.get("ville", "Paris")
        date    = tx.get("date", "2026-01-01T00:00:00")
        compte  = tx.get("compte")
        carte   = tx.get("carte")
        lat     = tx.get("latitude")
        lng     = tx.get("longitude")

        loc_id = f"loc_{uuid.uuid4().hex[:8]}"

        # Localisation : on ajoute lat/lng seulement s'ils sont fournis
        loc_triples = [
            f":{loc_id} a :Localisation ;",
            f'  :locationCountry "{pays}" ;',
            f'  :locationCity "{ville}"',
        ]
        if lat is not None and lng is not None:
            loc_triples[-1] += " ;"
            loc_triples.append(f'  :locationLatitude  {float(lat)} ;')
            loc_triples.append(f'  :locationLongitude {float(lng)} .')
        else:
            loc_triples[-1] += " ."

        triples = [
            f":{tx_id} a :Transaction ;",
            f'  :transactionID "{tx_id}" ;',
            f'  :transactionAmount {montant} ;',
            f'  :transactionCurrency "{devise}" ;',
            f'  :transactionType "{type_tx}" ;',
            f'  :transactionTimestamp "{date}"^^xsd:dateTime ;',
            f"  :hasLocation :{loc_id} .",
        ] + loc_triples

        if compte:
            triples.append(f":{tx_id} :hasSource :{compte} .")
        if carte:
            triples.append(f":{tx_id} :usesCard :{carte} .")

        body = "\n".join(triples)

        query = f"""
            INSERT DATA {{
              GRAPH <{self.GRAPH}> {{
                {body}
              }}
            }}
        """
        self._update(query)
        return tx_id

    def inserer_alerte(self, tx_id, alerte):
        """Insère une alerte typée OWL + sa preuve dans Virtuoso."""
        import uuid
        from datetime import datetime

        alerte_uri = f":alerte_{uuid.uuid4().hex[:8]}"
        preuve_uri = f":preuve_{uuid.uuid4().hex[:8]}"
        tx_uri     = f"<{self._uri(tx_id)}>"
        now        = datetime.now().isoformat()

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
            "R011": "AlerteFraudeVoyageImpossible",
        }
        classe = classes.get(alerte["regle"], "AlerteFraude")

        # Échappe les guillemets dans le détail
        detail = alerte["detail"].replace('"', '\\"')

        query = f"""
            INSERT DATA {{
              GRAPH <{self.GRAPH}> {{
                {alerte_uri} a :{classe} , :AlerteFraude ;
                  :alertID "{uuid.uuid4()}" ;
                  :alertType "{alerte['regle']}" ;
                  :alertSeverity "{alerte['severite']}" ;
                  :alertStatus "Ouverte" ;
                  :alertTimestamp "{now}"^^xsd:dateTime ;
                  :alertDescription "{detail}" ;
                  :triggeredBy {tx_uri} ;
                  :triggersRule :regle_{alerte['regle']} ;
                  :hasAlertEvidence {preuve_uri} .

                {preuve_uri} a :Preuve ;
                  :evidenceDescription "{detail}" ;
                  :evidenceTimestamp "{now}"^^xsd:dateTime ;
                  :concernsTransaction {tx_uri} ;
                  :hasViolatedRule :regle_{alerte['regle']} .

                {tx_uri} :generatesAlert {alerte_uri} .
              }}
            }}
        """
        self._update(query)
        return alerte_uri

    # ------------------------------------------------------------------ #
    # Orchestration                                                      #
    # ------------------------------------------------------------------ #

    def _uri(self, tx_id):
        if tx_id.startswith("http://"):
            return tx_id
        return f"http://www.semanticweb.org/dell/ontologies/2026/7/Fraude-bancaires-corrigee#{tx_id}"

    def detecter(self, tx_id, journaliser=True):
        """Exécute les 11 règles et insère les alertes dans Virtuoso."""
        regles = [
            self.r001_montant, self.r002_pays, self.r003_heure,
            self.r004_frequence, self.r005_cumul, self.r006_multipays,
            self.r007_historique, self.r008_solde, self.r009_plafond,
            self.r010_localisation, self.r011_voyage_impossible,
        ]
        alertes = []
        for regle in regles:
            try:
                resultats = regle(tx_id)
                for a in resultats:
                    if journaliser:
                        a["alerte_uri"] = self.inserer_alerte(tx_id, a)
                    alertes.append(a)
            except Exception as e:
                print(f"[ERREUR] {regle.__name__} : {e}")
        return alertes


# ------------------------------------------------------------------ #
# Test                                                               #
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    engine = FraudEngine()

    print("=== Test : insertion d'une transaction avec coordonnées ===")
    nouvelle = {
        "montant": 7500.0,
        "devise": "MAD",
        "type": "Paiement en ligne",
        "pays": "Maroc",
        "ville": "Casablanca",
        "latitude": 33.5731,
        "longitude": -7.5898,
        "date": "2026-09-11T03:15:00",
        "compte": "compte_809888dd",
        "carte": "carte_test_809888dd",
    }
    tx_id = engine.inserer_transaction(nouvelle)
    print(f"  → Transaction insérée : {tx_id}\n")

    print(f"=== Détection sur {tx_id} ===")
    alertes = engine.detecter(tx_id, journaliser=False)
    for a in alertes:
        print(f"  [{a['regle']}] {a['detail']}")
    print(f"  → {len(alertes)} alerte(s)")