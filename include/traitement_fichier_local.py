"""
traitement_fichier_local.py

Ce module contient des fonctions pour :
- Extraire les informations utiles des paquets Pyshark
- Construire une base de données minimale à partir d'une capture locale

Dépendance : pyshark (analyse de fichiers .pcap)
"""

import pyshark
import time

# === VARIABLE GLOBALE === #
i = 0  # Compteur global pour numéroter les paquets

# === AFFICHAGE DE MENU ===

def menuPacketInfoBuilder():
    """Affiche une bannière pour la construction du dictionnaire."""
    print(" --- Nouveau Packet --- ")
    print(" -- Construction du dictionnaire --\n")

# === TRAITEMENT DES PAQUETS ===

def packetPrint(capture):
    """
    Affiche tous les paquets d'une capture.

    :param capture: objet pyshark contenant les paquets
    """
    print(" --- Affichage des paquets ---\n")
    for packet in capture:
        print(packet)

def traitementPacket(packet):
    """
    Extrait les informations utiles d'un paquet sous forme de dictionnaire.

    :param packet: paquet pyshark
    :return: dictionnaire de données extraites
    """
    global i
    data = {"IDENT": i}

    # IP
    data["IP SRC"] = packet.ip.src if 'IP' in packet else ""
    data["IP DST"] = packet.ip.dst if 'IP' in packet else ""

    # Ethernet
    data["MAC SRC"] = packet.eth.src if 'ETH' in packet else ""
    data["MAC DST"] = packet.eth.dst if 'ETH' in packet else ""

    # TCP
    data["PORT SRC"] = packet.tcp.srcport if 'TCP' in packet else ""
    data["PORT DST"] = packet.tcp.dstport if 'TCP' in packet else ""

    # SMB2
    if 'SMB2' in packet:
        smb2 = packet.smb2
        data["Filename"] = smb2.filename if smb2.get_field('filename') else ""
        data["Session ID"] = smb2.sesid if smb2.get_field('sesid') else ""
        if smb2.get_field('flags.response') is not None:
            if smb2.flags_response == 'True':
                data["Is"] = "Response"
                data["Rps ID"] = smb2.msg_id
            elif smb2.flags_response == 'False':
                data["Is"] = "Request"
                data["Rqt ID"] = smb2.msg_id
        else:
            data["Is"] = ""
            data["Rps/Rqt ID"] = ""

    i += 1
    return data

def packetInfoBuilder(capture):
    """
    Construit une base de données à partir d'une capture réseau.

    :param capture: liste ou itérable de paquets pyshark
    :return: liste de dictionnaires contenant les infos des paquets
    """
    menuPacketInfoBuilder()
    bdd = []
    for packet in capture:
        data = traitementPacket(packet)
        bdd.append(data)
    return bdd

def affichageMiniBdd(bdd):
    """
    Affiche le contenu de la mini base de données.

    :param bdd: liste de dictionnaires
    """
    print(" --- Affichage de la base de données ---\n")
    for packet in bdd:
        print(packet)
        time.sleep(0.5)  # Affichage fluide
