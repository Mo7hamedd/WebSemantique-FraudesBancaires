"""
generer_instances.py
====================
Génère un jeu de données réaliste pour tester le moteur de détection.

Produit un fichier Turtle : instances_generated.ttl

Corrections apportées :
  - Coordonnées lat/lng pour chaque localisation (xsd:double)
  - hasCurrentLocation sur chaque client
  - Devise cohérente avec le pays (EUR / MAD)
  - Propriétés manquantes : clientPhone, clientAddress, accountNumber,
    accountOpeningDate, cardExpiryDate, transactionMerchant,
    transactionStatus, locationIP, locationDevice
  - Scénarios contrôlés : R004 (rafale), R006 (multi-pays), R011 (voyage impossible)
"""

import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path

# ---------- Reproductibilité ----------
random.seed(42)

# ---------- Préfixes ----------
NS = "http://www.semanticweb.org/dell/ontologies/2026/7/Fraude-bancaires-corrigee#"

# ---------- Référentiels ----------

# (pays, ville) -> (lat, lng)
COORDONNEES = {
    ("France", "Paris"):       (48.8566,  2.3522),
    ("France", "Lyon"):        (45.7640,  4.8357),
    ("France", "Marseille"):   (43.2965,  5.3698),
    ("France", "MaryBourg"):   (48.8566,  2.3522),   # fictif
    ("France", "Toulouse"):    (43.6047,  1.4442),
    ("Maroc",  "Casablanca"):  (33.5731, -7.5898),
    ("Maroc",  "Rabat"):       (34.0209, -6.8416),
    ("Maroc",  "Marrakech"):   (31.6295, -7.9811),
    ("Espagne","Madrid"):      (40.4168, -3.7038),
    ("Espagne","Barcelone"):   (41.3851,  2.1734),
    ("Italie", "Rome"):        (41.9028, 12.4964),
    ("Italie", "Milan"):       (45.4642,  9.1900),
    ("Allemagne", "Berlin"):   (52.5200, 13.4050),
}

# Devise locale par pays
DEVISES = {
    "France": "EUR", "Espagne": "EUR", "Italie": "EUR",
    "Allemagne": "EUR", "Maroc": "MAD",
}

# Villes par pays (pour le tirage)
PAYS_VILLES = list(COORDONNEES.keys())

NOMS = [
    "Luce Letellier", "Denis Lefevre", "Marie Dupont", "Jean Martin",
    "Sophie Bernard", "Pierre Dubois", "Camille Thomas", "Lucas Robert",
    "Emma Richard", "Hugo Petit", "Léa Durand", "Nathan Leroy",
    "Chloé Moreau", "Enzo Simon", "Manon Laurent", "Louis Michel",
    "Sarah Garcia", "Théo Roux", "Inès Fournier", "Paul Girard",
    "Jade Bonnet", "Romain Dupont", "Lina Lambert", "Alexandre Faure",
    "Zoé Rousseau", "Baptiste Vincent", "Alice Muller", "Gabriel Lefebvre",
    "Louise Caron", "Jules Fernandez", "Rose Garnier", "Adam Chevalier",
    "Nina Francois", "Raphaël Henry", "Mila Gauthier", "Arthur Perrin",
    "Léna Robin", "Tom Clement", "Eva Morin", "Noah Nicolas",
    "Aya Henry", "Liam Marie", "Maya Schmitt", "Ethan Julien",
    "Mila Payet", "Yanis Marchand", "Lila Dufour", "Marius Blanchard",
    "Nour Berger", "Côme Renault",
]

TYPES_CARTE   = ["Visa", "Mastercard", "Visa Electron"]
TYPES_COMPTE  = ["Courant", "Epargne"]
TYPES_TX      = ["Paiement", "Retrait", "Virement", "Paiement en ligne"]
MERCHANTS     = ["Amazon", "Carrefour", "SNCF", "Uber", "Netflix",
                 "Apple Store", "Fnac", "Decathlon", "Total", "Booking"]
DEVICES       = ["iPhone 14", "Samsung S23", "MacBook Pro", "Windows PC", "Pixel 7"]

# ---------- Helpers ----------
def uri(local):
    return f"<{NS}{local}>"

def esc(s):
    return s.replace('"', '\\"')

def new_id(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:8]}"

# ---------- Génération ----------
def generer():
    lines = []
    lines.append(f"@prefix : <{NS}> .")
    lines.append("@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n")

    # ---------------------------------------------------------------
    # 1. Localisations (avec lat/lng en xsd:double)
    # ---------------------------------------------------------------
    loc_map = {}
    for (pays, ville), (lat, lng) in COORDONNEES.items():
        loc_id = new_id("loc")
        loc_map[(pays, ville)] = loc_id
        lines.append(f":{loc_id} a :Localisation ;")
        lines.append(f'    :locationCountry "{pays}" ;')
        lines.append(f'    :locationCity "{ville}" ;')
        lines.append(f'    :locationLatitude "{lat}"^^xsd:double ;')
        lines.append(f'    :locationLongitude "{lng}"^^xsd:double .\n')

    # ---------------------------------------------------------------
    # 2. Clients (avec hasCurrentLocation + champs manquants)
    # ---------------------------------------------------------------
    clients = []
    for nom in NOMS:
        cid = new_id("client")
        pays_hab, ville_hab = random.choice(PAYS_VILLES[:5])  # majorité France
        loc_hab = loc_map[(pays_hab, ville_hab)]

        # 80% des clients : localisation actuelle = localisation habituelle
        # 20% : localisation actuelle différente (pour tester R010)
        if random.random() < 0.8:
            pays_cur, ville_cur = pays_hab, ville_hab
        else:
            pays_cur, ville_cur = random.choice(PAYS_VILLES)
        loc_cur = loc_map[(pays_cur, ville_cur)]

        lines.append(f":{cid} a :Client ;")
        lines.append(f'    :clientName "{esc(nom)}" ;')
        lines.append(f'    :clientEmail "{nom.lower().replace(" ", ".")}@example.com" ;')
        lines.append(f'    :clientPhone "+33 {random.randint(1,9)} {random.randint(10,99)} '
                     f'{random.randint(10,99)} {random.randint(10,99)} {random.randint(10,99)}" ;')
        lines.append(f'    :clientAddress "{random.randint(1,999)}, rue '
                     f'{random.choice(["de la Paix","Victor Hugo","des Fleurs","du Port"])} '
                     f'{random.randint(10000,99999)} {ville_hab}" ;')
        lines.append(f'    :clientRiskScore "{random.uniform(0.1, 0.9):.2f}"^^xsd:float ;')
        lines.append(f'    :hasUsualLocation :{loc_hab} ;')
        lines.append(f'    :hasCurrentLocation :{loc_cur} .\n')

        clients.append({
            "id": cid,
            "pays_hab": pays_hab, "ville_hab": ville_hab, "loc_hab": loc_hab,
            "pays_cur": pays_cur, "ville_cur": ville_cur, "loc_cur": loc_cur,
        })

    # ---------------------------------------------------------------
    # 3. Comptes + Cartes (avec champs manquants)
    # ---------------------------------------------------------------
    comptes = []
    for c in clients:
        nb_comptes = random.choice([1, 1, 1, 2])
        for _ in range(nb_comptes):
            cpt_id = new_id("compte")
            iban   = "FR" + "".join(str(random.randint(0, 9)) for _ in range(20))
            solde  = round(random.uniform(500, 50000), 2)
            date_ouverture = datetime(2020, 1, 1) + timedelta(
                days=random.randint(0, 2000))

            lines.append(f":{cpt_id} a :CompteBancaire ;")
            lines.append(f'    :accountNumber "{random.randint(10**10, 10**11 - 1)}" ;')
            lines.append(f'    :accountIBAN "{iban}" ;')
            lines.append(f'    :accountBalance {solde} ;')
            lines.append(f'    :accountType "{random.choice(TYPES_COMPTE)}" ;')
            lines.append(f'    :accountStatus "Actif" ;')
            lines.append(f'    :accountOpeningDate "{date_ouverture.isoformat()}"^^xsd:dateTime ;')
            lines.append(f'    :belongsTo :{c["id"]} .\n')

            carte_id = new_id("carte")
            plafond  = random.choice([5000.0, 10000.0, 15000.0, 20000.0])
            date_exp = datetime(2027, 1, 1) + timedelta(days=random.randint(0, 1000))

            lines.append(f":{carte_id} a :CarteBancaire ;")
            lines.append(f'    :cardNumberMasked "****-****-****-{random.randint(1000,9999)}" ;')
            lines.append(f'    :cardType "{random.choice(TYPES_CARTE)}" ;')
            lines.append(f'    :cardLimit {plafond} ;')
            lines.append(f'    :cardExpiryDate "{date_exp.isoformat()}"^^xsd:dateTimeStamp ;')
            lines.append(f'    :cardStatus "Active" ;')
            lines.append(f'    :linkedTo :{cpt_id} .\n')

            lines.append(f":{cpt_id} :hasCard :{carte_id} .\n")

            comptes.append({
                "id": cpt_id, "client": c["id"], "carte": carte_id,
                "plafond": plafond, "solde": solde,
                "pays_hab": c["pays_hab"], "ville_hab": c["ville_hab"],
                "loc_hab": c["loc_hab"],
            })

    # ---------------------------------------------------------------
    # 4. Transactions normales
    # ---------------------------------------------------------------
    date_debut = datetime(2026, 6, 1)
    date_fin   = datetime(2026, 8, 31)
    nb_total   = 0

    def ecrire_transaction(tx_id, compte, pays, ville, montant,
                           ts, type_tx, status="Validee"):
        nonlocal nb_total
        nb_total += 1
        loc = loc_map[(pays, ville)]
        devise = DEVISES.get(pays, "MAD")
        merchant = random.choice(MERCHANTS) if type_tx in ("Paiement", "Paiement en ligne") else "N/A"
        device = random.choice(DEVICES)
        ip = f"{random.randint(1,255)}.{random.randint(0,255)}." \
             f"{random.randint(0,255)}.{random.randint(1,254)}"

        lines.append(f":{tx_id} a :Transaction ;")
        lines.append(f'    :transactionID "{tx_id}" ;')
        lines.append(f'    :transactionAmount {montant} ;')
        lines.append(f'    :transactionCurrency "{devise}" ;')
        lines.append(f'    :transactionType "{type_tx}" ;')
        lines.append(f'    :transactionTimestamp "{ts.isoformat()}"^^xsd:dateTime ;')
        lines.append(f'    :transactionMerchant "{esc(merchant)}" ;')
        lines.append(f'    :transactionStatus "{status}" ;')
        lines.append(f'    :hasSource :{compte["id"]} ;')
        lines.append(f'    :usesCard :{compte["carte"]} ;')
        lines.append(f'    :hasLocation :{loc} .\n')

        # Enrichir la localisation avec IP/device (mêmes URI que loc_map)
        # On écrit ces propriétés sur l'instance de localisation si absentes.
        # Pour éviter les doublons, on les ajoute une seule fois par loc_id.
        if loc not in loc_enrichies:
            lines.append(f":{loc} :locationIP \"{ip}\" ;")
            lines.append(f'    :locationDevice "{device}" .\n')
            loc_enrichies.add(loc)

    loc_enrichies = set()

    for cpt in comptes:
        nb_tx = random.randint(5, 15)
        for _ in range(nb_tx):
            tx_id = new_id("txn")

            # 90% des tx dans le pays habituel
            if random.random() < 0.9:
                pays, ville = cpt["pays_hab"], cpt["ville_hab"]
            else:
                pays, ville = random.choice(PAYS_VILLES)

            # Montant : log-normale + quelques gros montants
            montant = round(random.lognormvariate(4, 1.2), 2)
            if random.random() < 0.05:
                montant = round(random.uniform(6000, 25000), 2)

            # Timestamp aléatoire
            delta = (date_fin - date_debut).total_seconds()
            ts = date_debut + timedelta(seconds=random.uniform(0, delta))

            # 5% nocturnes
            if random.random() < 0.05:
                ts = ts.replace(hour=random.randint(0, 5))

            type_tx = random.choices(TYPES_TX, weights=[70, 10, 10, 10])[0]
            ecrire_transaction(tx_id, cpt, pays, ville, montant, ts, type_tx)

    # ---------------------------------------------------------------
    # 5. Scénarios contrôlés (pour déclencher R004, R006, R011)
    # ---------------------------------------------------------------
    if comptes:
        cpt_test = comptes[0]  # on utilise le premier compte

        # --- Scénario R011 : Voyage impossible ---
        # Casablanca -> Paris -> Tokyo en < 1h sur la même carte
        base = datetime(2026, 9, 1, 10, 0, 0)
        scenario_voyage = [
            ("Maroc",   "Casablanca", 100.0, base),
            ("France",  "Paris",      200.0, base + timedelta(minutes=30)),
            # Tokyo n'est pas dans COORDONNEES -> on utilise une ville proche
            # On ajoute Tokyo manuellement pour ce scénario
        ]
        # Ajout explicite de Tokyo
        tokyo_id = new_id("loc")
        loc_map[("Japon", "Tokyo")] = tokyo_id
        lines.append(f":{tokyo_id} a :Localisation ;")
        lines.append('    :locationCountry "Japon" ;')
        lines.append('    :locationCity "Tokyo" ;')
        lines.append('    :locationLatitude "35.6762"^^xsd:double ;')
        lines.append('    :locationLongitude "139.6503"^^xsd:double .\n')

        for pays, ville, montant, ts in scenario_voyage:
            ecrire_transaction(new_id("txn"), cpt_test, pays, ville,
                               montant, ts, "Paiement")
        # 3e transaction : Tokyo
        ecrire_transaction(new_id("txn"), cpt_test, "Japon", "Tokyo",
                           300.0, base + timedelta(minutes=40), "Paiement")

        # --- Scénario R004 : rafale de 12 transactions en 4 min ---
        base_r004 = datetime(2026, 9, 2, 15, 0, 0)
        for i in range(12):
            ecrire_transaction(
                new_id("txn"), cpt_test,
                cpt_test["pays_hab"], cpt_test["ville_hab"],
                round(random.uniform(10, 100), 2),
                base_r004 + timedelta(seconds=i * 20),
                "Paiement",
            )

        # --- Scénario R005/R007 : cumul journalier > 10000 ---
        base_r005 = datetime(2026, 9, 3, 9, 0, 0)
        for i in range(5):
            ecrire_transaction(
                new_id("txn"), cpt_test,
                cpt_test["pays_hab"], cpt_test["ville_hab"],
                2500.0,
                base_r005 + timedelta(minutes=i * 30),
                "Paiement",
            )

    # ---------------------------------------------------------------
    # Statistiques
    # ---------------------------------------------------------------
    print(f"[OK] {len(clients)} clients")
    print(f"[OK] {len(comptes)} comptes")
    print(f"[OK] {len(comptes)} cartes")
    print(f"[OK] {nb_total} transactions")
    print(f"[OK] {len(loc_map)} localisations")

    return "\n".join(lines)


if __name__ == "__main__":
    contenu = generer()
    out = Path("instances_generated.ttl")
    out.write_text(contenu, encoding="utf-8")
    print(f"\n→ Fichier écrit : {out.resolve()}")
    print(f"→ Taille : {out.stat().st_size / 1024:.1f} Ko")