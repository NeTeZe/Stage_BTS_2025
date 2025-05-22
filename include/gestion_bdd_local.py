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

# === CONNEXION À LA BASE DE DONNÉES ===

def connectionBdd(pwd):
    """
    Initialise une connexion à la base de données PostgreSQL.

    :param pwd: mot de passe de l'utilisateur 'postgres'
    :return: objet connection psycopg2
    """
    conn = psycopg2.connect(
        database="Serveur local trames",
        user="postgres",
        host='localhost',
        password=pwd,
        port=5432
    )
    return conn

# === GESTION DE LA TABLE ===

def createTable(cursor):
    """
    Supprime la table 'packet_local' si elle existe, puis la recrée avec la structure complète.

    :param cursor: curseur de la connexion PostgreSQL
    """
    cursor.execute("DROP TABLE IF EXISTS packet_local")
    cursor.execute("""
        CREATE TABLE packet_local (
            packet_id INTEGER PRIMARY KEY,
            timestamp TIMESTAMP,
            ip_src VARCHAR(500),
            ip_dst VARCHAR(500),
            mac_src VARCHAR(500), 
            mac_dst VARCHAR(500), 
            port_src VARCHAR(500), 
            port_dst VARCHAR(500),
            filename VARCHAR(500),
            session_id VARCHAR(50), 
            is_a VARCHAR(500),
            id_echange VARCHAR(500),
            nt_status VARCHAR(20),
            erreur_smb2 VARCHAR(500),
            smb2_command VARCHAR(20),
            smb2_command_desc VARCHAR(50)
        );
    """)

# === INSERTION DES DONNÉES ===

def insertionBdd(cursor, bdd):
    """
    Insère les données extraites dans la base de données PostgreSQL.

    :param cursor: curseur PostgreSQL
    :param bdd: liste de dictionnaires (base de données en mémoire)
    """
    insert_query = """
        INSERT INTO packet_local(
            packet_id, timestamp, ip_src, ip_dst, mac_src, mac_dst,
            port_src, port_dst, filename, session_id,
            is_a, id_echange, nt_status, erreur_smb2,
            smb2_command, smb2_command_desc
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    for packet in bdd:
        # Récupération du code de commande SMB2 (sous forme de chaîne) et de sa correspondance
        cmd = packet.get("SMB2 Command", "")
        cmd_str = SMB2_COMMANDS.get(cmd, "") if cmd else ""
        
        valeurs = [packet.get(cle, "") for cle in [
            "IDENT", "Timestamp", "IP SRC", "IP DST", "MAC SRC", "MAC DST",
            "PORT SRC", "PORT DST", "Filename", "Session ID",
            "Is", "Rqt ID", "NT_STATUS", "Erreur SMB2"
        ]]
        # Ajouter les deux nouvelles valeurs à la fin
        valeurs.extend([cmd, cmd_str])
        cursor.execute(insert_query, valeurs)

# === EXEMPLE D’UTILISATION ===
# À adapter si tu veux faire tourner ce script en tant que main

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Usage : python insertionBdd.py <mot_de_passe> <fichier_pcap>")
        sys.exit(1)

    pwd = sys.argv[1]
    fichier_pcap = sys.argv[2]

    # Connexion à la base
    conn = connectionBdd(pwd)
    cursor = conn.cursor()

    # Création de la table
    createTable(cursor)

    # Lecture du fichier pcap
    capture = pyshark.FileCapture(fichier_pcap)
    bdd = traitement_fichier_local.packetInfoBuilder(capture)

    # Insertion des données
    insertionBdd(cursor, bdd)
    conn.commit()
    conn.close()

    print("Insertion terminée avec succès.")
