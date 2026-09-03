"""
LogSec - Rapport de securite d'un poste.

Assemble les deux briques precedentes : le collecteur lit les journaux,
le catalogue dit ce qui compte, ce module presente le resultat a un humain.

Utilisation :
    py agent/rapport.py
    py agent/rapport.py 90        (pour remonter sur 90 jours)
"""

import sys
from datetime import datetime

import collecteur
import signaux

# Windows affiche par defaut dans un encodage ancien qui ne connait pas les
# accents. Les messages Windows en contiennent. On force donc l'UTF-8 en
# sortie, sinon le programme plante sur un simple "a ete installe".
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass

ORDRE_GRAVITE = {signaux.GRAVE: 0, signaux.ATTENTION: 1, signaux.INFO: 2}
ETIQUETTE = {signaux.GRAVE: "[GRAVE]", signaux.ATTENTION: "[ATTENTION]",
             signaux.INFO: "[info]"}


def analyser(jours):
    """Lit tous les journaux surveilles et ne garde que ce qui est catalogue.

    Renvoie deux choses : les constats retenus, et l'etat de chaque journal
    (car un journal muet parce qu'il est desactive est une information de
    securite en soi, pas une absence de probleme).
    """
    constats = []
    etats = {}

    for nom_journal in signaux.journaux_surveilles():
        etat, nombre = collecteur.etat_journal(nom_journal)
        etats[nom_journal] = (etat, nombre)
        if etat != collecteur.LISIBLE:
            continue

        for evenement in collecteur.lire_journal(nom_journal, jours=jours, maximum=20000):
            signal = signaux.signal_pour(nom_journal, evenement["id"])
            if signal is None:
                continue  # evenement non catalogue : c'est du bruit
            if not signaux.retenir(signal, evenement["proprietes"]):
                continue  # signal connu, mais rien d'anormal dans ce cas precis
            proprietes = evenement["proprietes"]
            details = {nom: collecteur.champ(evenement, signal, nom)
                       for nom in signal.get("champs", {})}
            constats.append({
                "date": evenement["date"],
                "signal": signal,
                "details": details,
                "cle": signaux.cle_de_regroupement(signal, proprietes),
                "libelle": signaux.libelle(signal, proprietes),
            })

    constats = regrouper(constats)
    constats.sort(key=lambda c: (ORDRE_GRAVITE[c["signal"]["gravite"]], c["date"]),
                  reverse=False)
    return constats, etats


# Deux evenements separes de moins de ce delai, portant le meme signal et la
# meme cle, decrivent le meme fait. Une seconde suffirait pour un branchement
# USB ; on prend large pour absorber les enchainements un peu lents.
DELAI_REGROUPEMENT_SECONDES = 120


def regrouper(constats):
    """Fusionne les constats qui decrivent un seul et meme fait.

    Brancher une cle USB produit deux evenements Windows : le peripherique
    physique, puis le disque qu'il expose. Les signaler deux fois serait du
    bruit, et le bruit est l'ennemi numero un de cet outil.

    On ne fusionne que si trois conditions sont reunies : meme signal, meme
    cle de regroupement, et proximite dans le temps. Un meme disque branche
    le matin puis le soir doit rester deux constats distincts.
    """
    constats.sort(key=lambda c: c["date"])
    regroupes = []

    for constat in constats:
        if constat["cle"]:
            precedent = _constat_a_fusionner(regroupes, constat)
            if precedent is not None:
                precedent["occurrences"] += 1
                # Un seul des evenements d'un meme materiel porte sa marque et
                # son modele ; les autres rendent une chaine vide. On garde
                # donc le premier libelle non vide rencontre.
                if not precedent["libelle"]:
                    precedent["libelle"] = constat["libelle"]
                continue
        constat["occurrences"] = 1
        regroupes.append(constat)

    return regroupes


def _constat_a_fusionner(deja_vus, constat):
    """Cherche un constat anterieur decrivant le meme fait, ou None."""
    for candidat in reversed(deja_vus):
        if candidat["signal"] is not constat["signal"]:
            continue
        if candidat["cle"] != constat["cle"]:
            continue
        if _ecart_secondes(candidat["date"], constat["date"]) <= DELAI_REGROUPEMENT_SECONDES:
            return candidat
    return None


def _ecart_secondes(date_a, date_b):
    """Nombre de secondes entre deux dates au format 2026-01-17T19:08:29."""
    debut = datetime.strptime(date_a, "%Y-%m-%dT%H:%M:%S")
    fin = datetime.strptime(date_b, "%Y-%m-%dT%H:%M:%S")
    return abs((fin - debut).total_seconds())


def afficher(constats, etats, jours):
    print("=" * 72)
    print("LogSec - rapport de poste   (" + str(jours) + " derniers jours)")
    print("=" * 72)

    print("\nSOURCES DE DONNEES")
    for nom_journal, (etat, nombre) in etats.items():
        detail = str(nombre) + " enregistrements" if etat == collecteur.LISIBLE else ""
        print("  " + etat.ljust(14) + nom_journal + "  " + detail)

    inaccessibles = [n for n, (e, _) in etats.items() if e != collecteur.LISIBLE]
    if inaccessibles:
        print("\n  Journaux muets : la surveillance est partielle.")

    print("\nCONSTATS : " + str(len(constats)))
    if not constats:
        print("  Rien de catalogue sur la periode.")
        return

    gravite_precedente = None
    for constat in constats:
        signal = constat["signal"]
        if signal["gravite"] != gravite_precedente:
            print("")
            gravite_precedente = signal["gravite"]
        ligne = ("  " + ETIQUETTE[signal["gravite"]].ljust(12)
                 + constat["date"].replace("T", " ") + "  " + signal["titre"])
        if constat["libelle"]:
            ligne += " : " + constat["libelle"]
        print(ligne)
        for nom, valeur in constat["details"].items():
            if valeur:
                print("               " + nom + " : " + valeur)

    print("\nPOURQUOI CES CONSTATS COMPTENT")
    deja_dit = set()
    for constat in constats:
        signal = constat["signal"]
        if signal["gravite"] == signaux.INFO or signal["id"] in deja_dit:
            continue
        deja_dit.add(signal["id"])
        print("  " + signal["titre"])
        print("    " + signal["pourquoi"])


def main():
    jours = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    constats, etats = analyser(jours)
    afficher(constats, etats, jours)


if __name__ == "__main__":
    main()
