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
    Supprime la table 'packet' si elle existe, puis la recrée avec la bonne structure.

    :param cursor: curseur de la connexion PostgreSQL
    """
    cursor.execute("DROP TABLE IF EXISTS packet_local")
    cursor.execute("""
        CREATE TABLE packet_local(
            packet_id INTEGER PRIMARY KEY,
            ip_src VARCHAR(500),
            ip_dst VARCHAR(500),
            mac_src VARCHAR(500), 
            mac_dst VARCHAR(500), 
            port_src VARCHAR(500), 
            port_dst VARCHAR(500),
            filename VARCHAR(500),
            session_id VARCHAR(50), 
            is_a VARCHAR(500),
            id_echange VARCHAR(500)
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


