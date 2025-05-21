# === INCLUDES === #
import psycopg2
import traitementFichier
import pyshark
# === FONCTION === #

#Fonction qui initialise la connection
def connectionBdd(pwd) : 
    conn = psycopg2.connect(database = "Serveur local trames", 
                        user = "postgres", 
                        host= 'localhost',
                        password = pwd,
                        port = 5432)
    return conn

# Fonction qui crée la table dans la bdd
def createTable(cursor) : 
    cursor.execute("""DROP TABLE IF EXISTS packet""")
    cursor.execute("""CREATE TABLE packet(
            packet_id INTEGER PRIMARY KEY,
            ip_src VARCHAR (100),
            ip_dst VARCHAR (100),
            mac_src VARCHAR (100), 
            mac_dst VARCHAR (100), 
            port_src VARCHAR (100), 
            port_dst VARCHAR (100),
            filename VARCHAR (100),
            session_id VARCHAR (100), 
            is_a VARCHAR (100),
            id_echange VARCHAR (100));
            """)

# Fonction qui insère les data dans la bdd    
def insertionBdd(cursor,bdd) : 
    insert_query ="""INSERT INTO 
                    packet(packet_id,ip_src,ip_dst,mac_src,mac_dst,port_src,port_dst,filename,session_id,is_a,id_echange)
                    Values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
    for packet in bdd:
        tbl_valeur = [] 
        for cle, valeur in packet.items() :

            tbl_valeur.append(valeur)
        print(tbl_valeur)    
        cursor.execute(insert_query,(tbl_valeur[0],tbl_valeur[1],
                                    tbl_valeur[2],tbl_valeur[3],
                                    tbl_valeur[4],tbl_valeur[5],
                                    tbl_valeur[6],tbl_valeur[7],
                                    tbl_valeur[8],tbl_valeur[9],tbl_valeur[10]))

def main():
    pwd = input("Entrer le password : \n")
    #Création de la connection
    conn = connectionBdd(pwd)
    #Création d'un curseur sur la connection 
    cur = conn.cursor()
    #Creation de la table 
    createTable(cur)
    capture = pyshark.FileCapture("sauvegardes\Trame test Steph\Espion_08210_20250521070017.pcap",display_filter="ldap||smb2")
    #Création de la bdd 
    bdd = traitementFichier.packetInfoBuilder(capture)
    #Insertion des données dans la tables
    insertionBdd(cur,bdd)


    # Validation des changements
    conn.commit()
    
    # Fermeture des connections
    cur.close()
    conn.close()

# === MAIN === #
print("--- DEBUT DU PROGRAMME ---")
main()
print("\n --- FIN DU PROGRAMME --- \n")