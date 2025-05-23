"""
insertionBdd.py

Ce script :
- Se connecte à une base PostgreSQL locale
- Crée une table pour stocker des paquets réseau
- Lit un fichier .pcap (analyse réseau)
- Extrait les informations utiles via un module externe
- Insère les données dans la base PostgreSQL

Dépendances : psycopg2, pyshark, traitement_fichier_local.py
"""

import psycopg2
from include import traitement_fichier_local
import pyshark
from include import gestion_bdd
from include import db_management


# === INSERTION DES DONNÉES ===

def insert_into_db(cursor, packet):
    """
    Inserts extracted packet data into a PostgreSQL database using the provided cursor.

    :param cursor: PostgreSQL database cursor used to execute the insert query.
    :param packet: Dictionary containing extracted packet information.
                   Expected keys include SMB2 command fields, network addresses,
                   session identifiers, and error codes.
    """
    insert_query = db_management.query_creation()

    # Get SMB2 command code and description
    cmd_code = packet.get("SMB2 Command", "")
    cmd_description = packet.get("SMB2 Command Desc", "")

    # Extract values from the packet in the expected order
    values = [packet.get(key, "") for key in [
        "id", "packet_id", "Timestamp", "IP SRC", "IP DST", "MAC SRC", "MAC DST",
        "PORT SRC", "PORT DST", "Filename", "Session ID",
        "Is", "Rqt ID", "NT_STATUS", "Erreur SMB2"
    ]]

    # Append the SMB2 command code and description at the end
    values.extend([cmd_code, cmd_description])

    # Execute the insert query with the prepared values
    cursor.execute(insert_query, values)
    # print("-- Packet added to the database --\n")
