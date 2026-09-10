"""
test_connexion.py
=================
Vérifie que Python peut interroger Virtuoso via SPARQL.
"""

from SPARQLWrapper import SPARQLWrapper, JSON

ENDPOINT = "http://localhost:8890/sparql"
GRAPH    = "http://localhost:8890/fraudes"

PREFIXES = """
PREFIX :    <http://www.semanticweb.org/dell/ontologies/2026/7/Fraude-bancaires-corrigee#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs:<http://www.w3.org/2000/01/rdf-schema#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>
"""


def select(query):
    """Envoie une requête SELECT à Virtuoso et retourne les lignes."""
    sparql = SPARQLWrapper(ENDPOINT)
    sparql.setQuery(PREFIXES + query)
    sparql.setReturnFormat(JSON)
    return sparql.query().convert()["results"]["bindings"]


if __name__ == "__main__":
    print("Test 1 : compter les clients")
    rows = select(f"""
        SELECT (COUNT(?c) AS ?n) WHERE {{
          GRAPH <{GRAPH}> {{ ?c a :Client }}
        }}
    """)
    print(f"  → {rows[0]['n']['value']} client(s)")

    print("\nTest 2 : compter les transactions")
    rows = select(f"""
        SELECT (COUNT(?t) AS ?n) WHERE {{
          GRAPH <{GRAPH}> {{ ?t a :Transaction }}
        }}
    """)
    print(f"  → {rows[0]['n']['value']} transaction(s)")

    print("\nTest 3 : tester R001 sur txn_98e8caca")
    rows = select(f"""
        SELECT ?montant ?seuil WHERE {{
          GRAPH <{GRAPH}> {{
            :txn_98e8caca :transactionAmount ?montant .
            ?r :ruleID "R001" ; :ruleThreshold ?seuil .
            FILTER(?montant > ?seuil)
          }}
        }}
    """)
    for r in rows:
        print(f"  → montant={r['montant']['value']}, seuil={r['seuil']['value']}")