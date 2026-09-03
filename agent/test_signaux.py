"""
LogSec - Tests des conditions de detection.

Pourquoi ce fichier existe : une condition de detection est du code qui decide
si on derange un humain ou non. Se tromper dans un sens produit du bruit, se
tromper dans l'autre laisse passer une intrusion. On ne verifie pas ce genre
de code "a l'oeil".

Chaque test donne un cas connu et dit ce qu'on attend. Les chaines sont
ecrites en r"..." (chaine brute) pour que les antislashs des chemins Windows
soient pris tels quels, sans avoir a les doubler.

Lance-le apres chaque modification des conditions :

    py agent/test_signaux.py
"""

import sys

import signaux

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass

resultats = []


def verifier(intitule, obtenu, attendu):
    reussi = obtenu == attendu
    resultats.append(reussi)
    print("  " + ("OK   " if reussi else "ECHEC") + "  " + intitule)
    if not reussi:
        print("         attendu " + str(attendu) + ", obtenu " + str(obtenu))


print("Installation d'un service (evenement 7045)")
verifier("un service dans Program Files est normal",
         signaux.service_hors_dossiers_habituels(
             ["WSL", r'"C:\Program Files\WSL\wslservice.exe"', "", "", ""]),
         False)
verifier("un pilote dans system32 est normal",
         signaux.service_hors_dossiers_habituels(
             ["KslD", r"system32\drivers\wd\KslD.sys", "", "", ""]),
         False)
verifier("un service dans DriverStore est normal",
         signaux.service_hors_dossiers_habituels(
             ["Intel", r"%SystemRoot%\System32\DriverStore\x\svc.exe", "", "", ""]),
         False)
verifier("un service lance depuis un dossier temporaire est ANORMAL",
         signaux.service_hors_dossiers_habituels(
             ["x", r"C:\Users\Bob\AppData\Local\Temp\svc.exe", "", "", ""]),
         True)
verifier("un service lance depuis ProgramData est ANORMAL",
         signaux.service_hors_dossiers_habituels(
             ["x", r"C:\ProgramData\outil\agent.exe", "", "", ""]),
         True)
verifier("un service sans chemin connu ne declenche rien",
         signaux.service_hors_dossiers_habituels(["x"]),
         False)

print("\nOuverture de session (evenement 21)")
verifier("une session au clavier du poste n'est pas une session distante",
         signaux.session_vraiment_distante([r"PC\Bob", "1", "LOCAL"]),
         False)
verifier("une session depuis une adresse reseau est distante",
         signaux.session_vraiment_distante([r"PC\Bob", "1", "192.168.1.20"]),
         True)
verifier("une origine vide ne declenche rien",
         signaux.session_vraiment_distante([r"PC\Bob", "1", ""]),
         False)

print("\nPeripheriques branches (evenement 410)")
verifier("un disque externe USB est du stockage",
         signaux.peripherique_de_stockage(
             [r"USBSTOR\Disk&Ven_TOSHIBA&Prod_EXTERNAL_USB", "disk.inf", "g", "disk"]),
         True)
verifier("une cle USB vue par son pilote est du stockage",
         signaux.peripherique_de_stockage(
             [r"USB\VID_090C&PID_1000\SCYEFX", "usbstor.inf", "g", "USBSTOR"]),
         True)
verifier("une carte son n'est pas du stockage",
         signaux.peripherique_de_stockage(
             [r"SWD\MMDEVAPI\x", "audioendpoint.inf", "g", ""]),
         False)
verifier("un ecran n'est pas du stockage",
         signaux.peripherique_de_stockage(
             [r"DISPLAY\LEN40A9\x", "oem40.inf", "g", "monitor"]),
         False)
verifier("un instantane de disque n'est pas du stockage amovible",
         signaux.peripherique_de_stockage(
             [r"STORAGE\VolumeSnapshot\HarddiskVolumeSnapshot1", "volsnap.inf", "g", ""]),
         False)
verifier("un evenement sans propriete ne fait pas planter l'agent",
         signaux.peripherique_de_stockage([]),
         False)

print("\n" + str(sum(resultats)) + " / " + str(len(resultats)) + " tests reussis")
sys.exit(0 if all(resultats) else 1)
