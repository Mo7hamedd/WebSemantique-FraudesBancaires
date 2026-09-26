"""
sparql_engine.py
================
Moteur de détection de fraude 100% SPARQL sur Virtuoso.

Contient les 11 règles (R001 à R011) sous forme de fonctions Python.
Chaque fonction envoie une requête SPARQL à Virtuoso et retourne
la liste des détections (vide si la règle ne se déclenche pas).

Corrections (v5) :
  - Tous les seuils sont lus dans l'ontologie.
  - R004 : filtrage temporel en Python (bif:dateadd non supporté).
  - R011 : Haversine en Python (bif:sin/bif:cos échouent avec variables).
  - inserer_transaction : coordonnées en xsd:double + champs enrichis.

Usage :
    from sparql_engine import FraudEngine
    engine = FraudEngine()
    alertes = engine.detecter("txn_98e8caca")
"""

from SPARQLWrapper import SPARQLWrapper, JSON
import os
import math
from datetime import datetime, timedelta


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
    # Méthodes internes                                                  #
    # ------------------------------------------------------------------ #

    def _select(self, query):
        self.sparql.setQuery(self.PREFIXES + query)
        result = self.sparql.query().convert()
        return result["results"]["bindings"]

    def _val(self, row, key):
        return row[key]["value"] if key in row else None

    def _uri(self, tx_id):
        if tx_id.startswith("http://"):
            return tx_id
        return ("http://www.semanticweb.org/dell/ontologies/2026/7/"
                f"Fraude-bancaires-corrigee#{tx_id}")

    @staticmethod
    def _parse_ts(s):
        """Parse un timestamp ISO, gère le suffixe Z."""
        if s is None:
            return None
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        # Gérer les microsecondes sur 6 chiffres (Python accepte, mais
        # certains formats Virtuoso sont exotiques)
        return datetime.fromisoformat(s)

    # ------------------------------------------------------------------ #
    # R001 — Montant anormal                                             #
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
                 "seuil":   self._val(r, "seuil"),
                 "detail": f"Montant {self._val(r,'montant')} > seuil {self._val(r,'seuil')}"}
                for r in rows]

    # ------------------------------------------------------------------ #
    # R002 — Pays inhabituel                                             #
    # ------------------------------------------------------------------ #

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
                 "paysTx":  self._val(r, "paysTx"),
                 "paysHab": self._val(r, "paysHab"),
                 "detail": f"Pays {self._val(r,'paysTx')} != habituel {self._val(r,'paysHab')}"}
                for r in rows]

    # ------------------------------------------------------------------ #
    # R003 — Heure inhabituelle                                          #
    # ------------------------------------------------------------------ #

    def r003_heure(self, tx):
        rows = self._select(f"""
            SELECT ?heure ?minH ?maxH WHERE {{
              GRAPH <{self.GRAPH}> {{
                <{self._uri(tx)}> :transactionTimestamp ?ts .
                BIND(HOURS(?ts) AS ?heure)
                ?r :ruleID "R003" ;
                   :ruleThresholdMin ?minH ;
                   :ruleThresholdMax ?maxH .
                FILTER(?heure >= ?minH || ?heure < ?maxH)
              }}
            }}
        """)
        return [{"regle": "R003", "severite": "Elevee",
                 "heure": self._val(r, "heure"),
                 "detail": (f"Heure {self._val(r,'heure')}h "
                            f"(plage {self._val(r,'minH')}h-{self._val(r,'maxH')}h)")}
                for r in rows]

    # ------------------------------------------------------------------ #
    # R004 — Fréquence anormale (CORRIGÉE v5)                            #
    # Seuil : :ruleThreshold + :ruleWindowMinutes                        #
    # Filtrage temporel en Python (bif:dateadd non supporté).            #
    # ------------------------------------------------------------------ #

    def r004_frequence(self, tx):
        """
        R004 : fréquence anormale — plus de N transactions sur la
        même carte dans une fenêtre glissante.

        SPARQL ne fait que récupérer la carte et les seuils ;
        le filtrage temporel est fait en Python.
        """
        # 1. Récupérer la carte + les seuils
        info = self._select(f"""
            SELECT ?carte ?ts ?seuil ?fenetre WHERE {{
              GRAPH <{self.GRAPH}> {{
                <{self._uri(tx)}> :usesCard ?carte ; :transactionTimestamp ?ts .
                ?r :ruleID "R004" ;
                   :ruleThreshold ?seuil ;
                   :ruleWindowMinutes ?fenetre .
              }}
            }}
        """)
        if not info:
            return []

        carte   = self._val(info[0], "carte")
        ts_cur  = self._parse_ts(self._val(info[0], "ts"))
        seuil   = float(self._val(info[0], "seuil"))
        fenetre = int(float(self._val(info[0], "fenetre")))

        if ts_cur is None:
            return []
        ts_min = ts_cur - timedelta(minutes=fenetre)

        # 2. Récupérer toutes les transactions sur la même carte
        rows = self._select(f"""
            SELECT ?ts2 WHERE {{
              GRAPH <{self.GRAPH}> {{
                ?autre :usesCard <{carte}> ; :transactionTimestamp ?ts2 .
              }}
            }}
        """)

        # 3. Filtrer la fenêtre en Python
        nb = 0
        for r in rows:
            ts2 = self._parse_ts(self._val(r, "ts2"))
            if ts2 is None:
                continue
            if ts_min <= ts2 <= ts_cur:
                nb += 1

        if nb <= seuil:
            return []

        return [{"regle": "R004", "severite": "Elevee",
                 "nb": nb, "seuil": seuil, "fenetre": fenetre,
                 "detail": f"{nb} transactions en {fenetre} min (seuil {int(seuil)})"}]

    # ------------------------------------------------------------------ #
    # R005 — Cumul journalier                                            #
    # ------------------------------------------------------------------ #

    def r005_cumul(self, tx):
        rows = self._select(f"""
            SELECT (SUM(?m) AS ?cumul) ?seuil WHERE {{
              GRAPH <{self.GRAPH}> {{
                <{self._uri(tx)}> :hasSource ?compte ; :transactionTimestamp ?ts .
                ?r :ruleID "R005" ; :ruleThreshold ?seuil .
                ?autre :hasSource ?compte ; :transactionAmount ?m ; :transactionTimestamp ?ts2 .
                FILTER(SUBSTR(STR(?ts2), 1, 10) = SUBSTR(STR(?ts), 1, 10))
                FILTER(?ts2 <= ?ts)
              }}
            }}
            GROUP BY ?seuil
        """)
        if not rows or "cumul" not in rows[0]:
            return []
        cumul = float(rows[0]["cumul"]["value"])
        seuil = float(self._val(rows[0], "seuil"))
        if cumul <= seuil:
            return []
        return [{"regle": "R005", "severite": "Elevee",
                 "cumul": cumul, "seuil": seuil,
                 "detail": f"Cumul journalier {cumul:.0f} > {seuil:.0f}"}]

    # ------------------------------------------------------------------ #
    # R006 — Multi-pays (CORRIGÉE v5 : filtrage Python)                  #
    # Seuil : :ruleThreshold + :ruleWindowMinutes                        #
    # ------------------------------------------------------------------ #

    def r006_multipays(self, tx):
        """
        R006 : carte utilisée dans plusieurs pays sur une fenêtre.

        SPARQL récupère la carte, le seuil, la fenêtre et toutes les
        transactions ; le filtrage temporel est fait en Python.
        """
        # 1. Carte + seuils
        info = self._select(f"""
            SELECT ?carte ?ts ?seuil ?fenetre WHERE {{
              GRAPH <{self.GRAPH}> {{
                <{self._uri(tx)}> :usesCard ?carte ; :transactionTimestamp ?ts .
                ?r :ruleID "R006" ;
                   :ruleThreshold ?seuil ;
                   :ruleWindowMinutes ?fenetre .
              }}
            }}
        """)
        if not info:
            return []

        carte   = self._val(info[0], "carte")
        ts_cur  = self._parse_ts(self._val(info[0], "ts"))
        seuil   = float(self._val(info[0], "seuil"))
        fenetre = int(float(self._val(info[0], "fenetre")))

        if ts_cur is None:
            return []
        ts_min = ts_cur - timedelta(minutes=fenetre)

        # 2. Transactions sur la même carte + leur pays
        rows = self._select(f"""
            SELECT ?pays ?ts2 WHERE {{
              GRAPH <{self.GRAPH}> {{
                ?autre :usesCard <{carte}> ;
                       :hasLocation ?loc ;
                       :transactionTimestamp ?ts2 .
                ?loc :locationCountry ?pays .
              }}
            }}
        """)

        # 3. Filtrer et compter les pays distincts
        pays_distincts = set()
        for r in rows:
            ts2 = self._parse_ts(self._val(r, "ts2"))
            if ts2 is None:
                continue
            if ts_min <= ts2 <= ts_cur:
                pays_distincts.add(self._val(r, "pays"))

        nb = len(pays_distincts)
        if nb <= seuil:
            return []

        return [{"regle": "R006", "severite": "Critique",
                 "nb_pays": nb, "seuil": seuil, "fenetre": fenetre,
                 "detail": f"{nb} pays en {fenetre} min (seuil {int(seuil)})"}]

    # ------------------------------------------------------------------ #
    # R007 — Historique incohérent                                       #
    # ------------------------------------------------------------------ #

    def r007_historique(self, tx):
        rows = self._select(f"""
            SELECT ?montant ?moyenne ?nb ?mult ?minN WHERE {{
              GRAPH <{self.GRAPH}> {{
                <{self._uri(tx)}> :transactionAmount ?montant ; :hasSource ?compte .
                ?r :ruleID "R007" ;
                   :ruleMultiplier ?mult ;
                   :ruleMinSampleSize ?minN .
                {{
                  SELECT ?compte (AVG(?m) AS ?moyenne) (COUNT(?t) AS ?nb) WHERE {{
                    GRAPH <{self.GRAPH}> {{
                      ?t :hasSource ?compte ; :transactionAmount ?m .
                      FILTER(?t != <{self._uri(tx)}>)
                    }}
                  }}
                  GROUP BY ?compte
                }}
                FILTER(?nb >= ?minN && ?montant > ?mult * ?moyenne)
              }}
            }}
        """)
        return [{"regle": "R007", "severite": "Elevee",
                 "montant": self._val(r, "montant"),
                 "moyenne": self._val(r, "moyenne"),
                 "nb":      self._val(r, "nb"),
                 "mult":    self._val(r, "mult"),
                 "detail": (f"{self._val(r,'montant')} > "
                            f"{self._val(r,'mult')}x moyenne ({self._val(r,'moyenne')})")}
                for r in rows]

    # ------------------------------------------------------------------ #
    # R008 — Solde insuffisant                                           #
    # ------------------------------------------------------------------ #

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
                 "solde":   self._val(r, "solde"),
                 "detail": f"Retrait {self._val(r,'montant')} > solde {self._val(r,'solde')}"}
                for r in rows]

    # ------------------------------------------------------------------ #
    # R009 — Plafond dépassé                                             #
    # ------------------------------------------------------------------ #

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
                 "montant":  self._val(r, "montant"),
                 "plafond":  self._val(r, "plafond"),
                 "detail": f"Montant {self._val(r,'montant')} > plafond {self._val(r,'plafond')}"}
                for r in rows]

    # ------------------------------------------------------------------ #
    # R010 — Localisation incohérente                                    #
    # ------------------------------------------------------------------ #

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
                 "villeTx":  self._val(r, "villeTx"),
                 "paysTx":   self._val(r, "paysTx"),
                 "villeCur": self._val(r, "villeCur"),
                 "paysCur":  self._val(r, "paysCur"),
                 "detail": (f"Tx {self._val(r,'villeTx')}/{self._val(r,'paysTx')} "
                            f"!= actuel {self._val(r,'villeCur')}/{self._val(r,'paysCur')}")}
                for r in rows]

    # ------------------------------------------------------------------ #
    # R011 — Voyage impossible (CORRIGÉE v5 : Haversine Python)          #
    # ------------------------------------------------------------------ #

    def r011_voyage_impossible(self, tx):
        """
        R011 : voyage impossible — deux transactions successives sur la
        même carte donnent une vitesse implicite > seuil (lu dans
        l'ontologie).

        SPARQL sélectionne les paires candidates ; la distance
        Haversine est calculée en Python (bif:sin/bif:cos échouent
        silencieusement dans Virtuoso).
        """
        rows = self._select(f"""
            SELECT ?txn1 ?ville1 ?pays1 ?lat1 ?lon1
                   ?ville2 ?pays2 ?lat2 ?lon2
                   ?deltaH ?seuil WHERE {{
              GRAPH <{self.GRAPH}> {{

                # Transaction courante (txn2)
                <{self._uri(tx)}> :usesCard ?carte ;
                                  :transactionTimestamp ?ts2 ;
                                  :hasLocation ?loc2 .
                ?loc2 :locationLatitude  ?lat2 ;
                      :locationLongitude ?lon2 ;
                      :locationCity      ?ville2 ;
                      :locationCountry   ?pays2 .

                # Transaction précédente (txn1)
                ?txn1 :usesCard ?carte ;
                      :transactionTimestamp ?ts1 ;
                      :hasLocation ?loc1 .
                ?loc1 :locationLatitude  ?lat1 ;
                      :locationLongitude ?lon1 ;
                      :locationCity      ?ville1 ;
                      :locationCountry   ?pays1 .

                FILTER(?ts1 < ?ts2)

                FILTER NOT EXISTS {{
                  ?txnX :usesCard ?carte ; :transactionTimestamp ?tsX .
                  FILTER(?tsX > ?ts1 && ?tsX < ?ts2)
                }}

                BIND(bif:datediff('minute', ?ts1, ?ts2) / 60.0 AS ?deltaH)
                FILTER(?deltaH > 0 && ?deltaH <= 6)

                ?r :ruleID "R011" ; :ruleThreshold ?seuil .
              }}
            }}
        """)

        resultats = []
        for r in rows:
            try:
                lat1  = float(self._val(r, "lat1"))
                lon1  = float(self._val(r, "lon1"))
                lat2  = float(self._val(r, "lat2"))
                lon2  = float(self._val(r, "lon2"))
                dh    = float(self._val(r, "deltaH"))
                seuil = float(self._val(r, "seuil"))
            except (TypeError, ValueError):
                continue

            # --- Haversine en Python ---
            R = 6371.0
            phi1 = math.radians(lat1)
            phi2 = math.radians(lat2)
            dphi = math.radians(lat2 - lat1)
            dlmb = math.radians(lon2 - lon1)

            a = (math.sin(dphi / 2) ** 2
                 + math.cos(phi1) * math.cos(phi2) * math.sin(dlmb / 2) ** 2)
            a = max(0.0, min(1.0, a))
            c = 2 * math.asin(math.sqrt(a))
            dist = R * c

            if dh <= 0:
                continue
            vitesse = dist / dh
            if vitesse <= seuil:
                continue

            v1 = self._val(r, "ville1")
            p1 = self._val(r, "pays1")
            v2 = self._val(r, "ville2")
            p2 = self._val(r, "pays2")
            txn1 = self._val(r, "txn1").split("#")[-1]

            resultats.append({
                "regle":          "R011",
                "severite":       "Critique",
                "txn_precedente": txn1,
                "de":             f"{v1}, {p1}",
                "vers":           f"{v2}, {p2}",
                "distance_km":    round(dist, 1),
                "delta_h":        round(dh, 3),
                "vitesse_kmh":    round(vitesse, 1),
                "seuil":          seuil,
                "detail": (f"Voyage impossible : {v1} ({p1}) → {v2} ({p2}) "
                           f"en {dh:.2f} h, {dist:.0f} km → {vitesse:.0f} km/h "
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
                "Accept":     "application/sparql-results+json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            return resp.read().decode("utf-8")

    def inserer_transaction(self, tx):
        """
        Insère une transaction + sa localisation dans Virtuoso.
        Coordonnées en xsd:double pour compatibilité Haversine.
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
        merchant = tx.get("commercant") or tx.get("merchant")
        status   = tx.get("statut") or tx.get("status", "Validee")
        ip       = tx.get("ip")
        device   = tx.get("device")

        loc_id = f"loc_{uuid.uuid4().hex[:8]}"

        triples = []
        triples.append(f":{tx_id} a :Transaction .")
        triples.append(f':{tx_id} :transactionID "{tx_id}" .')
        triples.append(f':{tx_id} :transactionAmount {montant} .')
        triples.append(f':{tx_id} :transactionCurrency "{devise}" .')
        triples.append(f':{tx_id} :transactionType "{type_tx}" .')
        triples.append(f':{tx_id} :transactionTimestamp "{date}"^^xsd:dateTime .')
        triples.append(f':{tx_id} :transactionStatus "{status}" .')
        triples.append(f':{tx_id} :hasLocation :{loc_id} .')
        if merchant:
            triples.append(f':{tx_id} :transactionMerchant "{merchant}" .')
        if compte:
            triples.append(f':{tx_id} :hasSource :{compte} .')
        if carte:
            triples.append(f':{tx_id} :usesCard :{carte} .')

        triples.append(f":{loc_id} a :Localisation .")
        triples.append(f':{loc_id} :locationCountry "{pays}" .')
        triples.append(f':{loc_id} :locationCity "{ville}" .')
        if lat is not None and lng is not None:
            triples.append(f':{loc_id} :locationLatitude "{float(lat)}"^^xsd:double .')
            triples.append(f':{loc_id} :locationLongitude "{float(lng)}"^^xsd:double .')
        if ip:
            triples.append(f':{loc_id} :locationIP "{ip}" .')
        if device:
            triples.append(f':{loc_id} :locationDevice "{device}" .')

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
    print("FraudEngine OK — méthodes disponibles :")
    for m in ("inserer_transaction", "inserer_alerte", "detecter",
              "r001_montant", "r004_frequence", "r006_multipays",
              "r011_voyage_impossible"):
        print(f"  {'OK' if hasattr(engine, m) else 'MANQUANT'}  {m}")