"""
traitement_fichier_local.py

Ce module contient des fonctions pour :
- Extraire les informations utiles des paquets Pyshark
- Construire une base de données minimale à partir d'une capture locale

Dépendance : pyshark (analyse de fichiers .pcap)
"""

import pyshark
import time
from datetime import datetime
from include import gestion_bdd_local

# === VARIABLE GLOBALE === #
i = 0  # Compteur global pour numéroter les paquets

# === TRAITEMENT DES PAQUETS ===

def traitementPacket(packet,cursor):
    """
    Extrait les informations utiles d'un paquet sous forme de dictionnaire.
    Ignore les paquets SMB2 de type 'réponse'.

    :param packet: paquet pyshark
    :return: dictionnaire de données extraites ou None
    """
    #print("-- DEBUT Traitement packet --\n  ",packet.number)
    global i
    data = {"id": i}
    data["packet_id"]= packet.number

    # === DATE/HEURE DE CAPTURE ===
    if hasattr(packet, 'sniff_time'):
        data["Timestamp"] = packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S')
    else:
        data["Timestamp"] = ""

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
        data["Filename"] = packet.smb2.filename if packet.smb2.get_field('filename') else ""
        data["Session ID"] = packet.smb2.sesid if packet.smb2.get_field('sesid') else ""

        # Type de paquet : Requête ou Réponse
        if packet.smb2.get_field('flags.response') == '1' or packet.smb2.flags_response == 'True':
            data["Is"] = "Response"
        else:
            data["Is"] = "Request"

        data["Rqt ID"] = packet.smb2.msg_id if packet.smb2.get_field('msg_id') else ""

        # Code d’erreur (nt_status)
        if packet.smb2.get_field('nt_status'):
            err_code = packet.smb2.nt_status
            data["NT_STATUS"] = err_code
            data["Erreur SMB2"] = SMB2_ERRORS.get(err_code.lower(), "Erreur inconnue")
        else:
            data["NT_STATUS"] = ""
            data["Erreur SMB2"] = ""

        # Commande SMB2
        if packet.smb2.get_field('cmd'):
            cmd_code = packet.smb2.cmd
            cmd_desc = SMB2_COMMANDS.get(cmd_code, "Inconnu")
            if int(str(cmd_code), 0) == 0x12 :
                if(packet.smb2.lease_lease_flags == '0x00000001' ) :       
                    cmd_desc += "_LB_Not"
                else :
                    cmd_desc += "_LB_Ack"
            # Remplissage du dictionnaire
            data["SMB2 Command"] = cmd_code
            data["SMB2 Command Desc"] = cmd_desc
        else:
            data["SMB2 Command"] = ""
            data["SMB2 Command Desc"] = ""


    i += 1
    #print("-- FIN Traitement packet --\n  ",packet.number)
    gestion_bdd_local.insertionBdd(cursor, data)
