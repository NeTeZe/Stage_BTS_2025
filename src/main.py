"""
main.py

Point d’entrée du projet. Centralise les appels aux fonctionnalités :
- Lecture de trames
- Construction de mini base
- Insertion dans PostgreSQL

Dépend de : traitement_fichier.py, gestion_bdd.py, analyse_reseau.py
"""
import pyshark
import sys
import os

# On ajoute le dossier parent du projet au sys.path pour que Python trouve 'include'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from include import analyse_reseau
from include import gestion_bdd
from include import traitement_fichier



def menuPrincipal():
    print("\n=== MENU PRINCIPAL ===")
    print("1 - Lire et afficher les trames")
    print("2 - Construire une mini base des paquets")
    print("3 - Insertion des paquets dans PostgreSQL")
    print("4 - Analyse du réseau en live (non fonctionnel)")
    print("90 - Test (ne pas utiliser si on ne sait pas ce qu'il s'y passe)")
    print("0 - Quitter")

def main():
    capture_path = "sauvegardes/Trame test Steph/Espion_08212_20250521070217.pcap"
    display_filter = "ldap || smb2"
    capture = pyshark.FileCapture(capture_path, display_filter=display_filter)

    continuer = True
    while continuer:
        menuPrincipal()
        choix = traitement_fichier.pick([0, 1, 2, 3, 4, 90])

        if choix == 1:
            traitement_fichier.packetPrint(capture)

        elif choix == 2:
            traitement_fichier.packetInfoBuilder(capture)

        elif choix == 3:
            pwd = input("Mot de passe PostgreSQL : ")
            conn = gestion_bdd.connectionBdd(pwd)
            cur = conn.cursor()
            gestion_bdd.createTable(cur)
            bdd = traitement_fichier.packetInfoBuilder(capture)
            gestion_bdd.insertionBdd(cur, bdd)
            conn.commit()
            cur.close()
            conn.close()
            print("✅ Données insérées dans la base PostgreSQL.")
        
        elif choix == 4 : 
            analyse_reseau.analyse_live()
        elif choix == 90:
            traitement_fichier.fctTest(capture)

        elif choix == 0:
            continuer = False

    print("\n--- Fin du programme ---\n")

# === POINT D’ENTRÉE ===
if __name__ == "__main__":
    print("--- DÉBUT DU PROGRAMME ---")
    main()
