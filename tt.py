from sparql_engine import FraudEngine

e = FraudEngine()
tx_id = "txn_8b7e6e59"

# Étape 1 — requête info (celle qui devrait matcher)
info = e._select(f"""
    SELECT ?carte ?ts ?seuil ?fenetre WHERE {{
      GRAPH <{e.GRAPH}> {{
        <{e._uri(tx_id)}> :usesCard ?carte ; :transactionTimestamp ?ts .
        ?r :ruleID "R004" ;
           :ruleThreshold ?seuil ;
           :ruleWindowMinutes ?fenetre .
      }}
    }}
""")
print("ÉTAPE 1 — info :", info)

# Étape 2 — parsing
if info:
    carte   = e._val(info[0], "carte")
    ts_cur  = e._parse_ts(e._val(info[0], "ts"))
    seuil   = float(e._val(info[0], "seuil"))
    fenetre = int(float(e._val(info[0], "fenetre")))
    print(f"ÉTAPE 2 — carte={carte}")
    print(f"         ts_cur={ts_cur}  (type={type(ts_cur).__name__})")
    print(f"         seuil={seuil}  fenetre={fenetre}")

    # Étape 3 — transactions sur la même carte
    rows = e._select(f"""
        SELECT ?ts2 WHERE {{
          GRAPH <{e.GRAPH}> {{
            ?autre :usesCard <{carte}> ; :transactionTimestamp ?ts2 .
          }}
        }}
    """)
    print(f"ÉTAPE 3 — rows={len(rows)}")

    # Étape 4 — filtrage
    from datetime import timedelta
    ts_min = ts_cur - timedelta(minutes=fenetre)
    print(f"ÉTAPE 4 — ts_min={ts_min}")
    nb = 0
    for r in rows:
        ts2 = e._parse_ts(e._val(r, "ts2"))
        if ts2 is not None and ts_min <= ts2 <= ts_cur:
            nb += 1
    print(f"         nb={nb}  (seuil={seuil})")

# Étape 5 — appel direct de la fonction
print("\nÉTAPE 5 — r004_frequence :", e.r004_frequence(tx_id))