"""
insertionBdd.py

Ce script :
- Se connecte à une base PostgreSQL locale
- Crée une table pour stocker des paquets réseau
- Lit un fichier .pcap (analyse réseau)
- Extrait les informations utiles via un module externe
- Insère les données dans la base PostgreSQL

Dépendances : psycopg2, pyshark, traitementFichier.py
"""

import psycopg2
from include import traitement_fichier
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
    Supprime la table 'packet' si elle existe, puis la recrée avec la bonne structure.

    :param cursor: curseur de la connexion PostgreSQL
    """
    cursor.execute("DROP TABLE IF EXISTS packet")
    cursor.execute("""
        CREATE TABLE packet(
            packet_id INTEGER PRIMARY KEY,
            ip_src VARCHAR(100),
            ip_dst VARCHAR(100),
            mac_src VARCHAR(100), 
            mac_dst VARCHAR(100), 
            port_src VARCHAR(100), 
            port_dst VARCHAR(100),
            filename VARCHAR(100),
            session_id VARCHAR(100), 
            is_a VARCHAR(100),
            id_echange VARCHAR(100)
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
        INSERT INTO packet(
            packet_id, ip_src, ip_dst, mac_src, mac_dst, 
            port_src, port_dst, filename, session_id, 
            is_a, id_echange
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    for packet in bdd:
        # Convertir le dictionnaire en liste ordonnée
        valeurs = [packet.get(cle, "") for cle in [
            "IDENT", "IP SRC", "IP DST", "MAC SRC", "MAC DST",
            "PORT SRC", "PORT DST", "Filename", "Session ID",
            "Is", "Rps ID" if "Rps ID" in packet else "Rqt ID"
        ]]
        cursor.execute(insert_query, valeurs)

# === MAIN PROGRAMME ===

def main():
    """
    Fonction principale du programme :
    - Demande le mot de passe PostgreSQL
    - Crée la table 'packet'
    - Extrait les paquets réseau depuis un fichier .pcap
    - Insère les données dans la base
    """
    pwd = input("Entrer le mot de passe PostgreSQL : ")

    # Connexion à la base
    conn = connectionBdd(pwd)
    cur = conn.cursor()

    # Création de la table
    createTable(cur)

    # Extraction des données depuis un fichier PCAP
    capture = pyshark.FileCapture(
        "sauvegardes/Trame test Steph/Espion_08212_20250521070217.pcap",
        display_filter="ldap || smb2"
    )

    bdd = traitement_fichier.packetInfoBuilder(capture)

    # Insertion dans la base
    insertionBdd(cur, bdd)

    # Commit & fermeture
    conn.commit()
    cur.close()
    conn.close()

# === POINT D'ENTRÉE ===

