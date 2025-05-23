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

# === VARIABLE GLOBALE === #
i = 0  # Compteur global pour numéroter les paquets

# === TABLE DE DÉCODAGE DES ERREURS SMB2 === #
SMB2_ERRORS = {
    '0xc0000034': 'STATUS_OBJECT_NAME_NOT_FOUND',
    '0xc0000022': 'STATUS_ACCESS_DENIED',
    '0xc000000f': 'STATUS_NO_SUCH_FILE',
    '0xc000003a': 'STATUS_OBJECT_PATH_NOT_FOUND',
    '0xc0000061': 'STATUS_PRIVILEGE_NOT_HELD',
    '0x00000103': 'STATUS_PENDING',
    '0xc0000003': 'STATUS_INVALID_INFO_CLASS',
    '0x80000006': 'STATUS_NO_MORE_FILES',
    '0xc000019c': 'STATUS_FS_DRIVER_REQUIRED',
    '0xc0000023': 'STATUS_BUFFER_TOO_SMALL',
    '0xc0000120': 'STATUS_CANCELLED',
    '0xc00002b8': 'STATUS_JOURNAL_NOT_ACTIVE',
    '0xc0000225': 'STATUS_NOT_FOUND',
    '0x80000005': 'STATUS_BUFFER_OVERFLOW',
    '0x00000000': 'SUCCESS'
    # Ajoutez-en plus si besoin
}
# === TABLE DE CORRESPONDANCE DES COMMANDES SMB2 === #
SMB2_COMMANDS = {
    '0': 'NEGOTIATE',
    '1': 'SESSION_SETUP',
    '2': 'LOGOFF',
    '3': 'TREE_CONNECT',
    '4': 'TREE_DISCONNECT',
    '5': 'CREATE',
    '6': 'CLOSE',
    '7': 'FLUSH',
    '8': 'READ',
    '9': 'WRITE',
    '10': 'LOCK',
    '11': 'IOCTL',
    '12': 'CANCEL',
    '13': 'ECHO', 
    '14': 'FIND',          # ou QUERY_DIRECTORY
    '15': 'NOTIFY',
    '16': 'GETINFO',
    '17': 'SETINFO',
    '18': 'BREAK'
}

# === AFFICHAGE DE MENU ===

def menuPacketInfoBuilder():
    """Affiche une bannière pour la construction du dictionnaire."""
    print(" --- Nouvelle trame --- ")
    print(" -- Construction du dictionnaire --\n")

# === TRAITEMENT DES PAQUETS ===

def PacketPrint_local(capture):
    """
    Affiche tous les paquets d'une capture.

    :param capture: objet pyshark contenant les paquets
    """
    for packet in capture:
        time.sleep(1)
        print(packet)

def traitementPacket(packet):
    """
    Extrait les informations utiles d'un paquet sous forme de dictionnaire.
    Ignore les paquets SMB2 de type 'réponse'.

    :param packet: paquet pyshark
    :return: dictionnaire de données extraites ou None
    """
    global i
    data = {"IDENT": packet.number}

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
                print(packet.smb2.lease_lease_flags)
                if(packet.smb2.lease_lease_flags == '0x00000001' ) :
                    print(packet.number," Lease Break Notification détectée")              
                    cmd_desc += "_LB_Not"
                else :
                    print(packet.number," Lease Break Acknowledgment détectée")
                    cmd_desc += "_LB_Ack"
                    print(cmd_desc)
            # Remplissage du dictionnaire
            data["SMB2 Command"] = cmd_code
            data["SMB2 Command Desc"] = cmd_desc
        else:
            data["SMB2 Command"] = ""
            data["SMB2 Command Desc"] = ""


    i += 1
    return data

def packetInfoBuilder(capture):
    """
    Construit une base de données à partir d'une capture réseau.

    :param capture: liste ou itérable de paquets pyshark
    :return: liste de dictionnaires contenant les infos des paquets
    """
    menuPacketInfoBuilder()
    return [data for packet in capture if (data := traitementPacket(packet)) is not None]

def affichageMiniBdd(bdd):
    """
    Affiche le contenu de la mini base de données.

    :param bdd: liste de dictionnaires
    """
    for packet in bdd:
        print(packet)
        time.sleep(0.5)  # Affichage fluide
