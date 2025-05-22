"""
traitement_fichier_live.py

Fonctions pour :
- Extraire des infos utiles des paquets Pyshark
- Construire une base de données minimale à partir d'une capture réseau live
- Insérer les données dans une base PostgreSQL

Dépendance : pyshark
"""

import pyshark
from include import gestion_bdd_live

# Compteur global pour numéroter les paquets
packet_counter = 0


def menu_packet_info_builder() -> None:
    """Affiche un sous-menu pour la construction du dictionnaire de données."""
    print(" -- Construction du dictionnaire -- ")


def traitement_packet(packet: pyshark.packet.packet.Packet) -> dict:
    """
    Extrait les informations utiles d'un paquet sous forme de dictionnaire.

    :param packet: paquet pyshark
    :return: dictionnaire des données extraites
    """
    global packet_counter
    data = {"IDENT": packet_counter}

    # Extraction IP
    if 'IP' in packet:
        data["IP SRC"] = packet.ip.src
        data["IP DST"] = packet.ip.dst
    else:
        data["IP SRC"] = ""
        data["IP DST"] = ""

    # Extraction Ethernet (MAC)
    if 'ETH' in packet:
        data["MAC SRC"] = packet.eth.src
        data["MAC DST"] = packet.eth.dst
    else:
        data["MAC SRC"] = ""
        data["MAC DST"] = ""

    # Extraction TCP ports
    if 'TCP' in packet:
        data["PORT SRC"] = packet.tcp.srcport
        data["PORT DST"] = packet.tcp.dstport
    else:
        data["PORT SRC"] = ""
        data["PORT DST"] = ""

    # Extraction SMB2 infos
    if 'SMB2' in packet:
        data["Filename"] = packet.smb2.filename if packet.smb2.get_field('filename') else ""
        data["Session ID"] = packet.smb2.sesid if packet.smb2.get_field('sesid') else ""

        flags_response = packet.smb2.get_field('flags.response')
        if flags_response is not None:
            if packet.smb2.flags_response == 'True':
                data["Is"] = "Response"
                data["Rps ID"] = packet.smb2.msg_id
            elif packet.smb2.flags_response == 'False':
                data["Is"] = "Request"
                data["Rqt ID"] = packet.smb2.msg_id
        else:
            data["Is"] = ""
            data["Rps/Rqt ID"] = ""

    packet_counter += 1
    return data


def packet_info_builder(capture: pyshark.LiveCapture, cursor, conn) -> None:
    """
    Construit une base de données minimale à partir d'une capture réseau live.

    :param capture: pyshark.LiveCapture
    :param cursor: curseur PostgreSQL
    :param conn: connexion PostgreSQL
    """
    menu_packet_info_builder()
    bdd = []

    for packet in capture.sniff_continuously():
        data = traitement_packet(packet)
        bdd.append(data)
        gestion_bdd_live.insertionBdd(cursor, bdd)
        bdd.clear()
        conn.commit()
        print("✅ Données insérées dans la base PostgreSQL.")
        
