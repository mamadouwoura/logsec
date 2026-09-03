"""
LogSec - Catalogue des signaux surveilles.

Ce fichier ne contient AUCUNE technique : c'est le savoir metier du projet.
Il repond a une seule question : parmi les milliers d'evenements que Windows
enregistre, lesquels veulent dire quelque chose, et quoi ?

Separer ce savoir du code qui lit les journaux permet d'enrichir la detection
sans jamais toucher a la mecanique de lecture.

Champ "champs" : position des donnees utiles dans les proprietes structurees
de l'evenement. On lit ces positions et jamais le texte du message, car le
message est traduit dans la langue de Windows et changerait sur un poste
anglais.
"""

# Niveaux de gravite, du moins au plus urgent.
INFO = "info"            # a savoir, pas d'action
ATTENTION = "attention"  # a verifier par un humain
GRAVE = "grave"          # alerte immediate

JOURNAL_DEFENDER = "Microsoft-Windows-Windows Defender/Operational"
JOURNAL_PNP = "Microsoft-Windows-Kernel-PnP/Configuration"
JOURNAL_BUREAU_DISTANT = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"

# ---------------------------------------------------------------------------
# CONDITIONS
#
# Un identifiant d'evenement ne suffit jamais. "Un service a ete installe" se
# produit a chaque mise a jour de pilote ; "une session s'est ouverte" se
# produit chaque matin. Sans condition qui separe le normal de l'anormal, on
# noie l'utilisateur sous des centaines de fausses alertes et l'outil finit
# ignore.
#
# Chaque condition recoit les proprietes structurees de l'evenement et
# repond : faut-il retenir ce fait, oui ou non ?
# ---------------------------------------------------------------------------

# Emplacements ou un logiciel legitime s'installe. Un service dont le
# programme se trouve ailleurs (dossier temporaire, AppData, ProgramData,
# dossier utilisateur) est anormal : c'est la signature d'une installation
# qui n'est pas passee par les canaux habituels.
DOSSIERS_DE_CONFIANCE = (
    "program files",
    "system32",
    "syswow64",
    "systemroot",
    "driverstore",
    "windowsapps",
    "windows\\",
)


def _texte(proprietes, position):
    """Lit une propriete sans jamais planter si elle manque."""
    if position < len(proprietes):
        return str(proprietes[position]).strip()
    return ""


def service_hors_dossiers_habituels(proprietes):
    """Vrai si le programme du service n'est pas la ou on l'attend."""
    chemin = _texte(proprietes, 1).lower().replace('"', "")
    chemin = chemin.replace("%systemroot%", "windows")
    if not chemin:
        return False
    return not any(dossier in chemin for dossier in DOSSIERS_DE_CONFIANCE)


def session_vraiment_distante(proprietes):
    """Vrai seulement si la session vient du reseau, pas du clavier du poste.

    Windows utilise le meme evenement pour les deux cas. Le troisieme champ
    vaut "LOCAL" quand la personne est physiquement devant la machine, et
    contient une adresse reseau quand elle se connecte a distance.
    """
    return _texte(proprietes, 2).upper() not in ("", "LOCAL")


def peripherique_de_stockage(proprietes):
    """Vrai pour une cle USB ou un disque externe, faux pour un ecran.

    Le journal enregistre TOUS les peripheriques, y compris la carte son et
    les instantanes de disque. Seul le stockage amovible nous interesse :
    c'est lui qui transporte les virus et fait sortir les donnees.
    """
    identifiant = _texte(proprietes, 0).upper()
    pilote = _texte(proprietes, 3).upper()
    return identifiant.startswith("USBSTOR\\") or pilote == "USBSTOR"


SIGNAUX = [
    # --- Journal System : ce que fait le systeme lui-meme ---
    {
        "journal": "System", "id": 7045, "gravite": ATTENTION,
        "titre": "Un service Windows a ete installe",
        "pourquoi": "Technique de persistance la plus courante : un service "
                    "demarre tout seul, avant meme qu'un utilisateur ouvre "
                    "sa session, souvent avec les pleins pouvoirs.",
        "champs": {"nom": 0, "chemin": 1, "demarrage": 3, "compte": 4},
        "condition": service_hors_dossiers_habituels,
    },
    {
        "journal": "System", "id": 104, "gravite": GRAVE,
        "titre": "Un journal d'evenements a ete efface",
        "pourquoi": "Effacer un journal n'a presque jamais de raison "
                    "legitime. C'est un effacement de traces.",
        "champs": {},
    },
    {
        "journal": "System", "id": 6008, "gravite": INFO,
        "titre": "Arret inattendu de la machine",
        "pourquoi": "Coupure de courant, plantage, ou extinction brutale. "
                    "Isole c'est banal, repete c'est un materiel qui lache.",
        "champs": {},
    },

    # --- Journal Defender : l'antivirus ---
    {
        "journal": JOURNAL_DEFENDER, "id": 1116, "gravite": GRAVE,
        "titre": "Logiciel malveillant detecte",
        "pourquoi": "Une menace a ete trouvee sur le poste.",
        "champs": {},
    },
    {
        "journal": JOURNAL_DEFENDER, "id": 1117, "gravite": ATTENTION,
        "titre": "Action appliquee contre un logiciel malveillant",
        "pourquoi": "La menace a ete traitee. Confirme que 1116 a ete suivi "
                    "d'effet.",
        "champs": {},
    },
    {
        "journal": JOURNAL_DEFENDER, "id": 1118, "gravite": GRAVE,
        "titre": "ECHEC du traitement d'un logiciel malveillant",
        "pourquoi": "La menace est detectee mais toujours presente. "
                    "Plus grave qu'une detection simple.",
        "champs": {},
    },
    {
        "journal": JOURNAL_DEFENDER, "id": 5001, "gravite": GRAVE,
        "titre": "Protection en temps reel DESACTIVEE",
        "pourquoi": "Le poste n'est plus protege. Soit un employe l'a "
                    "desactivee parce que 'ca ralentit', soit un logiciel "
                    "malveillant l'a fait avant de s'installer.",
        "champs": {},
    },

    # --- Journal Kernel-PnP : les peripheriques branches ---
    {
        "journal": JOURNAL_PNP, "id": 410, "gravite": INFO,
        "titre": "Peripherique de stockage amovible branche",
        "pourquoi": "Cle USB ou disque externe. Vecteur numero un "
                    "d'infection, et principal moyen de faire sortir des "
                    "donnees d'une entreprise.",
        "champs": {"peripherique": 0},
        "condition": peripherique_de_stockage,
    },

    # --- Journal Bureau a distance ---
    {
        "journal": JOURNAL_BUREAU_DISTANT, "id": 21, "gravite": ATTENTION,
        "titre": "Ouverture de session a distance",
        "pourquoi": "Quelqu'un a pris la main sur le poste depuis le reseau. "
                    "Legitime pour un depannage, anormal sinon.",
        "champs": {"utilisateur": 0, "origine": 2},
        "condition": session_vraiment_distante,
    },

    # --- Journal Security : NECESSITE LES DROITS ADMINISTRATEUR ---
    # Ces signaux ne sont pas encore lisibles. Ils sont documentes ici pour
    # que la cible soit ecrite, et seront actives en phase 4 quand l'agent
    # tournera en service sous le compte SYSTEME.
    {
        "journal": "Security", "id": 4625, "gravite": ATTENTION,
        "titre": "Echec d'ouverture de session",
        "pourquoi": "Isole c'est un mot de passe mal tape. En rafale c'est "
                    "une tentative de forcage.",
        "champs": {"cible": 5, "source": 19},
        "admin_requis": True,
    },
    {
        "journal": "Security", "id": 4720, "gravite": GRAVE,
        "titre": "Un compte utilisateur a ete cree",
        "pourquoi": "Dans une PME, la creation d'un compte est un evenement "
                    "rare et decide. Non planifiee, c'est une porte derobee.",
        "champs": {"nouveau_compte": 0, "par": 4},
        "admin_requis": True,
    },
    {
        "journal": "Security", "id": 4732, "gravite": GRAVE,
        "titre": "Un compte a ete ajoute a un groupe privilegie",
        "pourquoi": "Quelqu'un vient d'obtenir les droits administrateur.",
        "champs": {},
        "admin_requis": True,
    },
    {
        "journal": "Security", "id": 1102, "gravite": GRAVE,
        "titre": "Le journal de securite a ete efface",
        "pourquoi": "Effacement de traces delibere. Aucune raison legitime.",
        "champs": {},
        "admin_requis": True,
    },
]


def signal_pour(journal, identifiant):
    """Renvoie la fiche du signal, ou None si l'evenement ne nous interesse pas."""
    for signal in SIGNAUX:
        if signal["journal"] == journal and signal["id"] == identifiant:
            return signal
    return None


def journaux_surveilles(inclure_admin=False):
    """Liste des journaux a lire, sans doublon."""
    noms = []
    for signal in SIGNAUX:
        if signal.get("admin_requis") and not inclure_admin:
            continue
        if signal["journal"] not in noms:
            noms.append(signal["journal"])
    return noms


def retenir(signal, proprietes):
    """Applique la condition du signal. Sans condition, le fait est retenu."""
    condition = signal.get("condition")
    if condition is None:
        return True
    return condition(proprietes)
