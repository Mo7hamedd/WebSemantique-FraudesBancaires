"""
distance_ville.py
=================
Calcule la distance entre deux villes saisies en interactif.

Format de saisie :
    <ville> <pays> , <ville> <pays>
    Ex : Paris France, Casablanca Maroc
    Ex : Paris, France, Casablanca, Maroc

Tapez 'q' ou 'quit' pour quitter.

Le fichier worldcities.csv doit être dans le même dossier.
"""

import csv
import math
import os
import sys
from difflib import get_close_matches


CSV_FILE = os.path.join(os.path.dirname(__file__), "worldcities.csv")

VITESSES = {
    "Avion":   800.0,
    "Train":   120.0,
    "Voiture":  90.0,
    "Vélo":     15.0,
    "À pied":    5.0,
}


# ------------------------------------------------------------------ #
# Chargement du CSV                                                  #
# ------------------------------------------------------------------ #

def charger_villes(chemin):
    villes = []
    with open(chemin, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                villes.append({
                    "city":       row["city"].strip(),
                    "ascii":      row["city_ascii"].strip(),
                    "lat":        float(row["lat"]),
                    "lng":        float(row["lng"]),
                    "country":    row["country"].strip(),
                    "iso2":       row["iso2"].strip().upper(),
                    "iso3":       row["iso3"].strip().upper(),
                    "admin":      row["admin_name"].strip(),
                    "population": float(row["population"]) if row["population"] else 0.0,
                })
            except (ValueError, KeyError):
                continue
    return villes


# ------------------------------------------------------------------ #
# Recherche ville + pays                                              #
# ------------------------------------------------------------------ #

def _match_pays(ville, pays):
    """Vérifie si la ville correspond au pays donné (nom, ISO2, ISO3)."""
    p = pays.strip().lower()
    return (p == ville["country"].lower()
            or p == ville["iso2"].lower()
            or p == ville["iso3"].lower())


def chercher_ville(nom_ville, nom_pays, villes):
    """
    Cherche les villes correspondant au nom ET au pays.
    Retourne une liste triée par population décroissante.
    """
    nom_ville = nom_ville.strip().lower()
    nom_pays  = nom_pays.strip()

    # 1. Match exact ville + pays
    exact = [v for v in villes
             if (v["city"].lower() == nom_ville or v["ascii"].lower() == nom_ville)
             and _match_pays(v, nom_pays)]
    if exact:
        return sorted(exact, key=lambda v: v["population"], reverse=True)

    # 2. Match partiel ville + pays
    partiel = [v for v in villes
               if (nom_ville in v["city"].lower() or nom_ville in v["ascii"].lower())
               and _match_pays(v, nom_pays)]
    if partiel:
        return sorted(partiel, key=lambda v: v["population"], reverse=True)

    # 3. Match flou ville + pays
    candidats = [v for v in villes if _match_pays(v, nom_pays)]
    if not candidats:
        return []
    noms = list({v["ascii"] for v in candidats})
    proches = get_close_matches(nom_ville, noms, n=5, cutoff=0.75)
    return [v for v in candidats if v["ascii"] in proches]


def choisir_ville(nom_ville, nom_pays, villes):
    """Retourne la meilleure correspondance ou demande à l'utilisateur."""
    resultats = chercher_ville(nom_ville, nom_pays, villes)
    if not resultats:
        raise ValueError(f"Ville introuvable : '{nom_ville}' en '{nom_pays}'")

    if len(resultats) == 1:
        return resultats[0]

    print(f"\n  Plusieurs villes trouvées pour '{nom_ville}, {nom_pays}' :")
    for i, v in enumerate(resultats[:10], 1):
        print(f"    {i}. {v['city']}, {v['admin']}, {v['country']} "
              f"(pop. {int(v['population']):,})")

    while True:
        try:
            choix = int(input("  Choix (numéro) : "))
            if 1 <= choix <= min(len(resultats), 10):
                return resultats[choix - 1]
        except (ValueError, EOFError):
            pass
        print("  Choix invalide.")


# ------------------------------------------------------------------ #
# Distance de Haversine                                              #
# ------------------------------------------------------------------ #

def haversine(lat1, lon1, lat2, lon2):
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi    = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = (math.sin(dphi / 2) ** 2
         + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2)
    return 2 * R * math.asin(math.sqrt(a))


# ------------------------------------------------------------------ #
# Affichage                                                          #
# ------------------------------------------------------------------ #

def formater_duree(heures):
    h = int(heures)
    m = int(round((heures - h) * 60))
    if m == 60:
        h += 1
        m = 0
    return f"{h}h{m:02d}"


def afficher_resultat(v1, v2, distance):
    print(f"\n{'=' * 60}")
    print(f"  {v1['city']} ({v1['country']})")
    print(f"  → {v2['city']} ({v2['country']})")
    print(f"{'=' * 60}")
    print(f"  Coordonnées A : {v1['lat']:.4f}, {v1['lng']:.4f}")
    print(f"  Coordonnées B : {v2['lat']:.4f}, {v2['lng']:.4f}")
    print(f"  Distance orthodromique : {distance:,.1f} km")
    print(f"\n  Durées estimées (porte-à-porte) :")
    for mode, vitesse in VITESSES.items():
        heures = distance / vitesse
        print(f"    {mode:8s} : {formater_duree(heures):>8s}  "
              f"({vitesse:.0f} km/h)")
    print(f"{'=' * 60}\n")


# ------------------------------------------------------------------ #
# Parsing de la saisie                                               #
# ------------------------------------------------------------------ #

def parser_saisie(ligne):
    """
    Accepte :
        Paris France, Casablanca Maroc
        Paris, France, Casablanca, Maroc
    Retourne ((ville1, pays1), (ville2, pays2)).
    """
    ligne = ligne.strip()
    if not ligne:
        raise ValueError("Saisie vide.")

    if "," in ligne:
        parties = [p.strip() for p in ligne.split(",")]
        # Cas "Paris, France, Casablanca, Maroc" → 4 parties
        if len(parties) == 4:
            return (parties[0], parties[1]), (parties[2], parties[3])
        # Cas "Paris France, Casablanca Maroc" → 2 parties
        if len(parties) == 2:
            p1 = parties[0].rsplit(" ", 1)
            p2 = parties[1].rsplit(" ", 1)
            if len(p1) != 2 or len(p2) != 2:
                raise ValueError("Format attendu : <ville> <pays>, <ville> <pays>")
            return (p1[0], p1[1]), (p2[0], p2[1])
        raise ValueError("Format attendu : <ville> <pays>, <ville> <pays>")

    raise ValueError("Format attendu : <ville> <pays>, <ville> <pays>")


# ------------------------------------------------------------------ #
# Boucle principale                                                  #
# ------------------------------------------------------------------ #

def main():
    if not os.path.exists(CSV_FILE):
        print(f"[ERREUR] Fichier introuvable : {CSV_FILE}")
        sys.exit(1)

    print("[INFO] Chargement de worldcities.csv...")
    villes = charger_villes(CSV_FILE)
    print(f"[OK] {len(villes):,} villes chargées\n")

    print("=" * 60)
    print("  Calcul de distance entre deux villes")
    print("=" * 60)
    print("  Format : <ville> <pays>, <ville> <pays>")
    print("  Exemple : Paris France, Casablanca Maroc")
    print("  Tapez 'q' ou 'quit' pour quitter.")
    print("=" * 60)

    while True:
        try:
            ligne = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[INFO] Arrêt.")
            break

        if ligne.lower() in ("q", "quit", "exit"):
            print("[INFO] Au revoir.")
            break

        if not ligne:
            continue

        try:
            (ville1, pays1), (ville2, pays2) = parser_saisie(ligne)
            v1 = choisir_ville(ville1, pays1, villes)
            v2 = choisir_ville(ville2, pays2, villes)
            distance = haversine(v1["lat"], v1["lng"], v2["lat"], v2["lng"])
            afficher_resultat(v1, v2, distance)
        except ValueError as e:
            print(f"[ERREUR] {e}")
        except Exception as e:
            print(f"[ERREUR] {e}")


if __name__ == "__main__":
    main()