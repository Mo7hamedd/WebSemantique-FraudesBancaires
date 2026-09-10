"""
generer_instances.py
====================
Génère un jeu de données réaliste pour tester le moteur de détection.

Produit un fichier Turtle : instances_generated.ttl
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
PAYS_VILLES = [
    ("France", "Paris"), ("France", "Lyon"), ("France", "Marseille"),
    ("France", "MaryBourg"), ("France", "Toulouse"),
    ("Maroc", "Casablanca"), ("Maroc", "Rabat"), ("Maroc", "Marrakech"),
    ("Espagne", "Madrid"), ("Espagne", "Barcelone"),
    ("Italie", "Rome"), ("Italie", "Milan"),
    ("Allemagne", "Berlin"),
]

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

TYPES_CARTE = ["Visa", "Mastercard", "Visa Electron"]
TYPES_COMPTE = ["Courant", "Epargne"]
TYPES_TX = ["Paiement", "Retrait", "Virement", "Paiement en ligne"]

# ---------- Helpers ----------
def uri(local):
    return f"<{NS}{local}>"

def esc(s):
    """Échappe les guillemets pour Turtle."""
    return s.replace('"', '\\"')

# ---------- Génération ----------
def generer():
    lines = []

    # Préfixes Turtle
    lines.append(f"@prefix : <{NS}> .")
    lines.append("@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n")

    # 1. Localisations (villes uniques)
    loc_map = {}
    for i, (pays, ville) in enumerate(PAYS_VILLES):
        loc_id = f"loc_{uuid.uuid4().hex[:8]}"
        loc_map[(pays, ville)] = loc_id
        lines.append(f":{loc_id} a :Localisation ;")
        lines.append(f'    :locationCountry "{pays}" ;')
        lines.append(f'    :locationCity "{ville}" .\n')

    # 2. Clients
    clients = []
    for i, nom in enumerate(NOMS):
        cid = f"client_{uuid.uuid4().hex[:8]}"
        pays_hab, ville_hab = random.choice(PAYS_VILLES[:5])  # 80% France
        loc_hab = loc_map[(pays_hab, ville_hab)]

        lines.append(f":{cid} a :Client ;")
        lines.append(f'    :clientName "{esc(nom)}" ;')
        lines.append(f'    :clientEmail "{nom.lower().replace(" ", ".")}@example.com" ;')
        lines.append(f'    :clientRiskScore "{random.uniform(0.1, 0.9):.2f}"^^xsd:float ;')
        lines.append(f'    :hasUsualLocation :{loc_hab} .')

        clients.append({
            "id": cid,
            "pays_hab": pays_hab,
            "ville_hab": ville_hab,
            "loc_hab": loc_hab,
        })
        lines.append("")

    # 3. Comptes + Cartes (1 à 2 comptes par client)
    comptes = []
    for c in clients:
        nb_comptes = random.choice([1, 1, 1, 2])
        for _ in range(nb_comptes):
            cpt_id = f"compte_{uuid.uuid4().hex[:8]}"
            iban = "FR" + "".join([str(random.randint(0, 9)) for _ in range(20)])
            solde = round(random.uniform(500, 50000), 2)

            lines.append(f":{cpt_id} a :CompteBancaire ;")
            lines.append(f'    :accountIBAN "{iban}" ;')
            lines.append(f'    :accountBalance {solde} ;')
            lines.append(f'    :accountType "{random.choice(TYPES_COMPTE)}" ;')
            lines.append(f'    :accountStatus "Actif" ;')
            lines.append(f'    :belongsTo :{c["id"]} .')

            # Carte liée
            carte_id = f"carte_{uuid.uuid4().hex[:8]}"
            plafond = random.choice([5000.0, 10000.0, 15000.0, 20000.0])

            lines.append(f":{carte_id} a :CarteBancaire ;")
            lines.append(f'    :cardNumberMasked "****-****-****-{random.randint(1000,9999)}" ;')
            lines.append(f'    :cardType "{random.choice(TYPES_CARTE)}" ;')
            lines.append(f'    :cardLimit {plafond} ;')
            lines.append(f'    :cardStatus "Active" ;')
            lines.append(f'    :linkedTo :{cpt_id} .')

            lines.append(f":{cpt_id} :hasCard :{carte_id} .")
            lines.append("")

            comptes.append({
                "id": cpt_id,
                "client": c["id"],
                "carte": carte_id,
                "plafond": plafond,
                "solde": solde,
                "pays_hab": c["pays_hab"],
                "ville_hab": c["ville_hab"],
                "loc_hab": c["loc_hab"],
            })

    # 4. Transactions
    date_debut = datetime(2026, 6, 1)
    date_fin = datetime(2026, 8, 31)
    nb_total = 0

    for cpt in comptes:
        # Nombre de transactions pour ce compte
        nb_tx = random.randint(5, 15)

        for _ in range(nb_tx):
            tx_id = f"txn_{uuid.uuid4().hex[:8]}"
            nb_total += 1

            # 90% des tx en France (pays habituel)
            if random.random() < 0.9:
                pays, ville = cpt["pays_hab"], cpt["ville_hab"]
            else:
                pays, ville = random.choice(PAYS_VILLES)
            loc = loc_map[(pays, ville)]

            # Montant : loi log-normale pour réalisme
            montant = round(random.lognormvariate(4, 1.2), 2)
            # Quelques gros montants (5%)
            if random.random() < 0.05:
                montant = round(random.uniform(6000, 25000), 2)

            # Timestamp aléatoire
            delta = (date_fin - date_debut).total_seconds()
            ts = date_debut + timedelta(seconds=random.uniform(0, delta))

            # 5% nocturnes
            if random.random() < 0.05:
                ts = ts.replace(hour=random.randint(0, 5))

            # Type
            type_tx = random.choices(
                TYPES_TX,
                weights=[70, 10, 10, 10],
            )[0]

            lines.append(f":{tx_id} a :Transaction ;")
            lines.append(f'    :transactionID "{tx_id}" ;')
            lines.append(f'    :transactionAmount {montant} ;')
            lines.append(f'    :transactionCurrency "MAD" ;')
            lines.append(f'    :transactionType "{type_tx}" ;')
            lines.append(f'    :transactionTimestamp "{ts.isoformat()}"^^xsd:dateTime ;')
            lines.append(f'    :hasSource :{cpt["id"]} ;')
            lines.append(f'    :usesCard :{cpt["carte"]} ;')
            lines.append(f'    :hasLocation :{loc} .')
            lines.append("")

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