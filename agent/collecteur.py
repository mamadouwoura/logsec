"""
LogSec - Collecteur d'evenements Windows.

Ce module ne sait qu'une chose : aller chercher des evenements dans les
journaux de Windows et les ramener en donnees Python. Il ignore totalement
ce qui est grave ou non : ce jugement appartient a signaux.py.

Choix technique : plutot que la bibliotheque pywin32, on demande a PowerShell
de lire les journaux et de nous rendre le resultat en JSON. Zero dependance a
installer, et PowerShell est present sur tout Windows. On basculera vers
pywin32 en phase 4, quand la vitesse comptera.

Regle d'or appliquee ici : on ramene les PROPRIETES STRUCTUREES de chaque
evenement, pas seulement son message. Le message est traduit dans la langue
de Windows ; les proprietes, elles, sont identiques sur un poste anglais.
"""

import io
import json
import os
import subprocess
import tempfile

# Etats possibles d'un journal, du point de vue de notre agent.
LISIBLE = "lisible"
DESACTIVE = "desactive"          # existe mais Windows ne le remplit pas
INACCESSIBLE = "inaccessible"    # droits insuffisants, ou n'existe pas


def _powershell(commande):
    """Execute une commande PowerShell et renvoie sa sortie texte.

    La sortie transite par un fichier temporaire, pas par le tuyau standard.
    Raison : Windows et Python ne s'accordent pas toujours sur l'encodage du
    tuyau, et les accents des messages Windows arrivent alors abimes
    ("Demarrage" devient "D?marrage"). Ecrire dans un fichier en UTF-8
    explicite supprime le probleme, et evite aussi la limite de taille du
    tuyau quand on ramene des milliers d'evenements.
    """
    descripteur, fichier = tempfile.mkstemp(suffix=".json", prefix="logsec_")
    os.close(descripteur)
    try:
        subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
             "$ErrorActionPreference='SilentlyContinue'; "
             "$sortie = @( " + commande + " ); "
             # Entre apostrophes, PowerShell prend l'antislash au pied de la
             # lettre : le chemin Windows passe tel quel, sans echappement.
             "[System.IO.File]::WriteAllText('" + fichier + "', "
             "($sortie -join [Environment]::NewLine), "
             "(New-Object System.Text.UTF8Encoding($false)))"],
            capture_output=True,
        )
        with io.open(fichier, encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    finally:
        # On nettoie toujours, meme si la lecture a echoue : un agent qui
        # tourne en permanence ne doit pas remplir le disque de residus.
        if os.path.exists(fichier):
            os.remove(fichier)


def etat_journal(nom_journal):
    """Dit si un journal est lisible, desactive, ou inaccessible.

    Attention, piege Windows : sans droits administrateur, un journal
    protege comme Security n'est pas signale 'acces refuse' mais
    'introuvable'. Windows refuse de reveler ce qu'on n'a pas le droit de
    voir. On ne peut donc pas distinguer les deux cas ici, d'ou le nom
    volontairement prudent INACCESSIBLE.
    """
    sortie = _powershell(
        "$l = Get-WinEvent -ListLog '" + nom_journal + "' -ErrorAction SilentlyContinue; "
        "if ($null -eq $l) { 'INTROUVABLE' } "
        "elseif (-not $l.IsEnabled) { 'DESACTIVE' } "
        "else { 'ACTIF ' + $l.RecordCount }"
    )
    if sortie.startswith("ACTIF"):
        return LISIBLE, int(sortie.split()[1])
    if sortie == "DESACTIVE":
        return DESACTIVE, 0
    return INACCESSIBLE, 0


def lire_journal(nom_journal, jours=7, maximum=2000):
    """Lit un journal et renvoie une liste d'evenements.

    Chaque evenement est un dictionnaire :
      date       texte trie chronologiquement, ex "2026-01-17T19:08:29"
      id         identifiant de l'evenement, ex 7045
      niveau     libelle Windows (Information, Avertissement, Erreur)
      source     composant qui a ecrit l'evenement
      message    premiere ligne, POUR AFFICHAGE UNIQUEMENT
      proprietes liste des donnees structurees, POUR LES REGLES
    """
    commande = (
        "$e = Get-WinEvent -FilterHashtable @{LogName='" + nom_journal + "'; "
        "StartTime=(Get-Date).AddDays(-" + str(jours) + ")} "
        "-MaxEvents " + str(maximum) + " -ErrorAction SilentlyContinue; "
        # On construit l'objet explicitement plutot qu'avec Select-Object :
        # une propriete calculee qui renvoie un tableau est emballee par
        # PowerShell dans un objet {value, Count}, illisible cote Python.
        "$e | ForEach-Object { [pscustomobject]@{ "
        "  date = $_.TimeCreated.ToString('s'); "
        "  id = $_.Id; "
        "  niveau = [string]$_.LevelDisplayName; "
        "  source = [string]$_.ProviderName; "
        "  message = ($_.Message -split [char]10)[0].Trim(); "
        "  proprietes = @($_.Properties | ForEach-Object { "
        "    if ($null -eq $_.Value) { '' } else { [string]$_.Value } }) "
        "} } | ConvertTo-Json -Compress -Depth 4"
    )
    sortie = _powershell(commande)
    if not sortie:
        return []

    donnees = json.loads(sortie)
    # PowerShell renvoie un objet seul, pas une liste, quand il n'y a qu'un
    # resultat. On uniformise pour toujours travailler sur une liste.
    if isinstance(donnees, dict):
        donnees = [donnees]

    # Meme uniformisation pour les proprietes d'un evenement qui n'en a qu'une.
    for evenement in donnees:
        proprietes = evenement.get("proprietes")
        if proprietes is None:
            proprietes = []
        elif isinstance(proprietes, dict):
            # Ceinture et bretelles : si PowerShell emballe malgre tout le
            # tableau dans {value, Count}, on le deballe. Un agent doit
            # survivre aux surprises de ce qu'il consomme.
            proprietes = proprietes.get("value", [])
        elif not isinstance(proprietes, list):
            proprietes = [proprietes]
        evenement["proprietes"] = proprietes
        evenement["journal"] = nom_journal
    return donnees


def champ(evenement, signal, nom_champ):
    """Extrait une donnee utile d'un evenement, en s'appuyant sur le catalogue.

    Renvoie une chaine vide si la donnee est absente, plutot que de planter :
    un agent de securite qui s'arrete sur un evenement inattendu ne surveille
    plus rien.
    """
    position = signal.get("champs", {}).get(nom_champ)
    if position is None:
        return ""
    proprietes = evenement.get("proprietes", [])
    if position >= len(proprietes):
        return ""
    return str(proprietes[position]).strip()
