"""
sparql_engine.py
================
Moteur de détection de fraude 100% SPARQL sur Virtuoso.

Contient les 10 règles (R001 à R010) sous forme de fonctions Python.
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

    ##ENDPOINT = "http://localhost:8890/sparql"
    ##GRAPH    = "http://localhost:8890/fraudes"
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
        """Envoie une requête SELECT et retourne les lignes (liste de dicts)."""
        self.sparql.setQuery(self.PREFIXES + query)
        result = self.sparql.query().convert()
        return result["results"]["bindings"]

    def _val(self, row, key):
        """Extrait la valeur d'une variable dans une ligne de résultat."""
        return row[key]["value"] if key in row else None

    # ------------------------------------------------------------------ #
    # Les 10 règles                                                      #
    # ------------------------------------------------------------------ #

    def r001_montant(self, tx):
        """R001 : montant > seuil critique (lu dans l'ontologie)."""
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
        """R002 : pays de la transaction != pays habituel du client."""
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
        """R003 : transaction entre 23h et 6h."""
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
        """R004 : > 10 transactions en 5 min sur la même carte."""
        rows = self._select(f"""
            SELECT (COUNT(?autre) AS ?nb) WHERE {{
              GRAPH <{self.GRAPH}> {{
                <{self._uri(tx)}> :usesCard ?carte ; :transactionTimestamp ?ts .
                ?autre :usesCard ?carte ; :transactionTimestamp ?ts2 .
                FILTER(?ts2 <= ?ts)
                FILTER(bif:datediff('minute', ?ts2, ?ts) <= 5)
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
        """R005 : cumul journalier > 10000."""
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
        # Vérifie que ?cumul est bien présent ET non vide
        if "cumul" not in rows[0] or not rows[0]["cumul"]["value"]:
            return []
        cumul = float(rows[0]["cumul"]["value"])
        if cumul <= 10000:
            return []
        return [{"regle": "R005", "severite": "Elevee",
                 "cumul": cumul,
                 "detail": f"Cumul journalier {cumul:.0f} > 10000"}]
    def r006_multipays(self, tx):
        """R006 : > 2 pays en 1h sur la même carte."""
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
        """R007 : montant > 3x la moyenne historique du client."""
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
        """R008 : retrait > solde disponible."""
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
        """R009 : montant > plafond de la carte."""
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
        """R010 : localisation transaction != localisation actuelle client."""
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
    # Écriture dans Virtuoso                                             #
    # ------------------------------------------------------------------ #

    def _update(self, query):
        """Envoie une requête INSERT/DELETE à Virtuoso via POST."""
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
        Insère une nouvelle transaction + sa localisation dans Virtuoso.

        Args:
            tx (dict) : doit contenir id, montant, devise, type,
                        pays, ville, date, compte, carte (optionnel).

        Returns:
            str : l'ID court de la transaction insérée (ex: 'txn_abc123').
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

        loc_id = f"loc_{uuid.uuid4().hex[:8]}"

        triples = [
            f":{tx_id} a :Transaction ;",
            f'  :transactionID "{tx_id}" ;',
            f'  :transactionAmount {montant} ;',
            f'  :transactionCurrency "{devise}" ;',
            f'  :transactionType "{type_tx}" ;',
            f'  :transactionTimestamp "{date}"^^xsd:dateTime ;',
            f"  :hasLocation :{loc_id} .",
            f":{loc_id} a :Localisation ;",
            f'  :locationCountry "{pays}" ;',
            f'  :locationCity "{ville}" .',
        ]
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
        }
        classe = classes.get(alerte["regle"], "AlerteFraude")

        query = f"""
            INSERT DATA {{
              GRAPH <{self.GRAPH}> {{
                {alerte_uri} a :{classe} , :AlerteFraude ;
                  :alertID "{uuid.uuid4()}" ;
                  :alertType "{alerte['regle']}" ;
                  :alertSeverity "{alerte['severite']}" ;
                  :alertStatus "Ouverte" ;
                  :alertTimestamp "{now}"^^xsd:dateTime ;
                  :alertDescription "{alerte['detail']}" ;
                  :triggeredBy {tx_uri} ;
                  :triggersRule :regle_{alerte['regle']} ;
                  :hasAlertEvidence {preuve_uri} .

                {preuve_uri} a :Preuve ;
                  :evidenceDescription "{alerte['detail']}" ;
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
        """Construit l'URI complète depuis l'ID court (ex: txn_98e8caca)."""
        if tx_id.startswith("http://"):
            return tx_id
        return f"http://www.semanticweb.org/dell/ontologies/2026/7/Fraude-bancaires-corrigee#{tx_id}"

    def detecter(self, tx_id, journaliser=True):
        """Exécute les 10 règles et insère les alertes dans Virtuoso."""
        regles = [
            self.r001_montant, self.r002_pays, self.r003_heure,
            self.r004_frequence, self.r005_cumul, self.r006_multipays,
            self.r007_historique, self.r008_solde, self.r009_plafond,
            self.r010_localisation,
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

    # ---------- Test 1 : détection sur transaction existante ----------
    print("=== Test 1 : détection sur txn_98e8caca ===")
    alertes = engine.detecter("txn_98e8caca", journaliser=False)
    for a in alertes:
        print(f"  [{a['regle']}] {a['detail']}")
    print(f"  → {len(alertes)} alerte(s)\n")

    # ---------- Test 2 : insertion d'une nouvelle transaction ----------
    print("=== Test 2 : insertion d'une nouvelle transaction ===")
    nouvelle = {
        "montant": 7500.0,
        "devise": "MAD",
        "type": "Paiement en ligne",
        "pays": "Maroc",
        "ville": "Casablanca",
        "date": "2026-09-11T03:15:00",
        "compte": "compte_809888dd",
        "carte": "carte_test_809888dd",
    }
    tx_id = engine.inserer_transaction(nouvelle)
    print(f"  → Transaction insérée : {tx_id}\n")

    # ---------- Test 3 : détection immédiate sur la nouvelle tx ----------
    print(f"=== Test 3 : détection sur {tx_id} ===")
    alertes = engine.detecter(tx_id, journaliser=False)
    for a in alertes:
        print(f"  [{a['regle']}] {a['detail']}")
    print(f"  → {len(alertes)} alerte(s)")