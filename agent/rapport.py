"""
LogSec - Rapport de securite d'un poste.

Assemble les deux briques precedentes : le collecteur lit les journaux,
le catalogue dit ce qui compte, ce module presente le resultat a un humain.

Utilisation :
    py agent/rapport.py
    py agent/rapport.py 90        (pour remonter sur 90 jours)
"""

import sys

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
            details = {nom: collecteur.champ(evenement, signal, nom)
                       for nom in signal.get("champs", {})}
            constats.append({"date": evenement["date"], "signal": signal,
                             "details": details})

    constats.sort(key=lambda c: (ORDRE_GRAVITE[c["signal"]["gravite"]], c["date"]),
                  reverse=False)
    return constats, etats


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
