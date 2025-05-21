"""
traitementFichier.py

Ce module contient des fonctions pour :
- Afficher des menus interactifs liés à l'analyse réseau
- Afficher des paquets réseau capturés
- Extraire les informations utiles des paquets
- Construire et afficher une base de données minimale
- Tester les données SMB2 extraites

Dépendance : pyshark (analyse de fichiers .pcap)
"""

import pyshark
import time

# === MENUS INTERACTIFS ===

def pick(listPick):
    """
    Demande à l'utilisateur de saisir un choix parmi ceux disponibles.

    :param listPick: liste des valeurs valides
    :return: valeur sélectionnée par l'utilisateur
    """
    choix = -1
    while choix not in listPick:
        try:
            choix = int(input("Entrer votre choix : "))
        except ValueError:
            print("Veuillez entrer un nombre valide.")
    print("\n")
    return choix

def menuMain():
    """Affiche le menu principal."""
    print(" - MENU - ")
    print(" 1 - Lecture des trames ")
    print(" 2 - Construction d'une mini-bdd des paquets ")
    print(" 90 - TEST : ")

def menuPacketPrint():
    """Affiche le sous-menu pour l'affichage des trames."""
    print(" -- Affichage des trames -- ")
    print(" 1 - Affichage de toutes les trames ")
    print(" 2 - Affichage d'une trame spécifique ")

def menuPacketInfoBuilder():
    """Affiche le sous-menu pour la construction de la mini-base de données."""
    print(" -- Construction d'une mini BDD -- ")
    print(" 1 - Affichage de la BDD ")
    print(" 2 - Ne pas afficher la BDD ")

# === TRAITEMENT DES PAQUETS ===

def packetPrint(capture):
    """
    Affiche les paquets selon le choix de l'utilisateur.

    :param capture: objet pyshark contenant les paquets
    """
    menuPacketPrint()
    choix = pick([1, 2])
    if choix == 1:
        for packet in capture:
            print(packet)
    elif choix == 2:
        try:
            pkt = capture[5]
            print("Adr IP SRC :", pkt.ip.src)
            print("Adr IP DST :", pkt.ip.dst)
            print("Adr MAC SRC :", pkt.eth.src)
            print("Adr MAC DST :", pkt.eth.dst)
            print("Fichier demandé :", pkt.smb2.filename)
            print("Accès demandé (7 = O/W/R) :", pkt.smb2.smb_share_access)
        except IndexError:
            print("Le paquet numéro 5 n'existe pas.")
        except AttributeError:
            print("Certaines informations ne sont pas disponibles dans ce paquet.")

def traitementPacket(packet, i):
    """
    Extrait les informations utiles d'un paquet sous forme de dictionnaire.

    :param packet: paquet pyshark
    :param i: identifiant du paquet (index)
    :return: dictionnaire de données extraites
    """
    data = {"IDENT": i}

    if 'IP' in packet:
        data["IP SRC"] = packet.ip.src
        data["IP DST"] = packet.ip.dst
    else:
        data["IP SRC"] = ""
        data["IP DST"] = ""

    if 'ETH' in packet:
        data["MAC SRC"] = packet.eth.src
        data["MAC DST"] = packet.eth.dst
    else:
        data["MAC SRC"] = ""
        data["MAC DST"] = ""

    if 'TCP' in packet:
        data["PORT SRC"] = packet.tcp.srcport
        data["PORT DST"] = packet.tcp.dstport
    else:
        data["PORT SRC"] = ""
        data["PORT DST"] = ""

    if 'SMB2' in packet:
        data["Filename"] = packet.smb2.filename if packet.smb2.get_field('filename') else ""
        data["Session ID"] = packet.smb2.sesid if packet.smb2.get_field('sesid') else ""

        if packet.smb2.get_field('flags.response') is not None:
            if packet.smb2.flags_response == 'True':
                data["Is"] = "Response"
                data["Rps ID"] = packet.smb2.msg_id
            elif packet.smb2.flags_response == 'False':
                data["Is"] = "Request"
                data["Rqt ID"] = packet.smb2.msg_id
        else:
            data["Is"] = ""
            data["Rps/Rqt ID"] = ""

    return data

def packetInfoBuilder(capture):
    """
    Construit une base de données à partir d'une capture réseau.

    :param capture: liste ou itérable de paquets pyshark
    :return: liste de dictionnaires contenant les infos des paquets
    """
    menuPacketInfoBuilder()
    choix = pick([1, 2])
    bdd = []

    for i, packet in enumerate(capture, start=1):
        data = traitementPacket(packet, i)
        bdd.append(data)

    if choix == 1:
        affichageMiniBdd(bdd)

    return bdd

def affichageMiniBdd(bdd):
    """
    Affiche le contenu de la mini base de données.

    :param bdd: liste de dictionnaires
    """
    for packet in bdd:
        print(packet)
        time.sleep(1)  # pause plus courte pour un affichage fluide

def main():
    """
    Fonction principale du module.

    - Charge un fichier .pcap avec un filtre sur SMB2 et LDAP.
    - Affiche un menu pour choisir l'action à effectuer :
        1. Afficher les paquets
        2. Construire une mini base de données
        90. Tester l'extraction SMB2
    - Boucle jusqu'à ce que l'utilisateur choisisse de quitter.
    """

    # Charger un fichier .pcap filtré sur SMB2 et LDAP
    capture = pyshark.FileCapture(
        "sauvegardes/Trame test Steph/Espion_08210_20250521070017.pcap",
        display_filter="ldap || smb2"
    )

    continuer = "y"
    while continuer.lower() != "n":
        menuMain()
        choix = pick([1, 2, 90])

        if choix == 1:
            packetPrint(capture)
        elif choix == 2:
            packetInfoBuilder(capture)
        elif choix == 90:
            fctTest(capture)

        continuer = input("Voulez-vous continuer le programme ? (y/n) : ")

# === FONCTIONS DE TEST ===

def fctTest(capture):
    """
    Fonction de test SMB2 : affiche les champs SMB2 du premier paquet trouvé.

    :param capture: liste de paquets pyshark
    """
    for pkt in capture:
        if 'smb2' in pkt:
            print(pkt.smb2._all_fields)
            if hasattr(pkt.smb2, 'flags'):
                print(pkt.smb2.flags_response)
            break  # évite d'afficher trop de paquets

