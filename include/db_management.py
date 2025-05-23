"""
gestion_bdd.py

This module contains the main functions for managing and interacting with
a PostgreSQL database via pgAdmin. It includes connection handling,
query execution, and database utility operations.

"""
import psycopg2
import pyshark

# == Database connection == #
def connectionBdd(pwd):
    """
    Initializes a connection to the PostgreSQL database.

    :param pwd: user password 'postgres'
    :return: object connection psycopg2
    """
    
    conn = psycopg2.connect(
        database="Serveur local trames",
        user="postgres",
        host='localhost',
        password=pwd,
        port=5432
    )
    return conn

# == Table creation == #
def createTable(cursor):
    """
    Deletes the ‘packet_local’ table if it exists, then recreates it with the full structure.

    :param cursor: PostgreSQL connection cursor
    """
    cursor.execute("DROP TABLE IF EXISTS packet_local")
    cursor.execute("""
        CREATE TABLE packet_local (
            id INTEGER PRIMARY KEY,
            packet_id INTEGER,
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
            smb2_command_desc VARCHAR(500)
        );
    """)

# == Creating the query == #
def query_creation() : 
    insert_query = """
        INSERT INTO packet_local(
            id,packet_id, timestamp, ip_src, ip_dst, mac_src, mac_dst,
            port_src, port_dst, filename, session_id,
            is_a, id_echange, nt_status, erreur_smb2,
            smb2_command, smb2_command_desc
        ) VALUES (%s,%s,%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    return insert_query

# == Init the database connection and the database == #
def database_init() :
    pwd = input("Mot de passe PostgreSQL : ")
    conn = connectionBdd(pwd)
    cur = conn.cursor()
    createTable(cur)
    return cur,conn 