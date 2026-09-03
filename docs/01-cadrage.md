# LogSec - Document de cadrage

Date : 2 septembre 2026

## 1. Objectif

Permettre au responsable d'une PME, sans etre informaticien, de savoir en
permanence dans quel etat sont ses ordinateurs, et d'etre prevenu le jour ou
quelque chose de grave commence.

Toute decision future se tranche avec cette phrase : est-ce que cette
fonctionnalite sert cet objectif ? Si non, on ne la construit pas.

## 2. Utilisateur cible

Structure de 10 a 30 postes Windows, sans service informatique :
PME, ecole, clinique, agence, association.
La personne qui utilise LogSec est le gerant ou un employe polyvalent,
pas un administrateur systeme.

Consequences directes sur la conception :
- l'interface est en francais et sans jargon
- l'installation doit etre faisable par un non-informaticien
- une alerte doit dire quoi faire, pas seulement ce qui s'est passe

## 3. Les incidents que l'on vise

Par ordre de gravite reelle pour une PME :

1. Rancongiciel (chiffrement massif des fichiers)
2. Fuite de donnees par cle USB ou disque externe
3. Antivirus desactive ou perime sur un poste
4. Compte administrateur cree ou detourne
5. Journal d'evenements efface (effacement de traces)
6. Postes en retard de mises a jour de securite
7. Absence de sauvegarde

## 4. Ce que LogSec fait

- Observer : lire les journaux d'evenements Windows sur chaque poste
- Inventorier : etat de l'antivirus, du pare-feu, des mises a jour, des comptes
- Detecter : appliquer des regles precises sur ce qui est observe
- Alerter : prevenir la bonne personne la ou elle regarde deja
- Conserver : garder une trace exploitable apres un incident

## 5. Ce que LogSec ne fait PAS (hors perimetre)

Decisions fermes, a ne pas rediscuter sans raison forte :

- Pas d'antivirus : on s'appuie sur Windows Defender, on ne le remplace pas
- Pas de pare-feu, pas de VPN, pas de gestionnaire de mots de passe
- Pas de pilote noyau : risque trop eleve de rendre une machine inutilisable
- Pas de blocage automatique en version 1 : on observe et on alerte.
  Un outil qui bloque a tort paralyse l'entreprise et se fait desinstaller.
- Pas de detection par intelligence artificielle en version 1 :
  sans donnees etiquetees, cela produit des faux positifs en masse et
  l'outil finit ignore. Regles precises d'abord, mesure ensuite.

## 6. Contraintes techniques connues

- Le journal Security de Windows (connexions, echecs de mot de passe,
  creation de comptes) est illisible sans droits administrateur.
  L'agent devra donc tourner en service Windows sous le compte SYSTEM.
- Poste de developpement : Windows 11 Pro, Python 3.13 (commande `py`),
  PowerShell 5.1, Git. Pas de carte graphique dediee.

## 7. Feuille de route

Chaque phase produit quelque chose qui fonctionne et qui sert seul.
On ne passe a la suivante que lorsque la precedente est maitrisee.

| Phase | Contenu | Etat |
|---|---|---|
| 0 | Cadrage et environnement | FAIT |
| 1 | Collecteur : lire les journaux Windows depuis Python | FAIT |
| 2 | Regles de detection : transformer les evenements en alertes | en cours |
| 3 | Inventaire du poste : antivirus, pare-feu, MAJ, comptes, USB | a faire |
| 4 | Service Windows : tourner en SYSTEM, au demarrage, en continu | a faire |
| 5 | Serveur central et base de donnees : plusieurs postes remontent | a faire |
| 6 | Console web : la vue du parc pour le responsable | a faire |
| 7 | Alertes : email, Telegram ou WhatsApp | a faire |
| 8 | Installateur : deploiement par un non-informaticien | a faire |

## 8. Questions ouvertes

- Acces a une vraie PME pour tester en conditions reelles : non tranche.
- Modele economique : non tranche.

## 9. Journal des decisions techniques

**Lire les proprietes structurees, jamais le texte des messages.**
Le message d'un evenement Windows est traduit dans la langue du systeme.
Une regle qui cherche "Demarrage automatique" ne detecte plus rien sur un
poste anglais. Les proprietes, elles, occupent toujours la meme position.

**Un identifiant d'evenement n'est pas une detection.**
Premiere mesure reelle sur un poste, sur 30 jours : 116 constats bruts, dont
55 fausses sessions distantes (c'etaient des ouvertures de session locales),
40 peripheriques internes (ecran, carte son, instantanes de disque) et 27
installations de services toutes legitimes. Apres ajout d'une condition
discriminante par signal : 5 constats, tous exacts. Chaque signal doit donc
porter une condition, et cette condition doit etre testee.

**Detecter un service suspect par son emplacement.**
Un logiciel legitime s'installe dans Program Files, System32, DriverStore ou
WindowsApps. Un service dont le programme se trouve ailleurs (dossier
temporaire, AppData, ProgramData) est anormal. Verifie sur 27 installations
reelles : aucune fausse alerte.

**Distinguer une session distante d'une session locale.**
Windows utilise le meme evenement 21 pour les deux. Le troisieme champ vaut
"LOCAL" quand la personne est devant la machine.

**Distinguer le stockage amovible du reste.**
Le journal Kernel-PnP enregistre tous les peripheriques. Seuls ceux dont
l'identifiant commence par USBSTOR, ou dont le pilote est USBSTOR, sont des
cles USB ou des disques externes.
