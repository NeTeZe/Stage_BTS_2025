import pyshark
import sys
import os
import signal
import time
import shutil

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from include import analyse_reseau
from include import gestion_bdd_local
from include import gestion_bdd_live
from include import traitement_fichier_local
from include import db_management


def handler(sig, frame):
    answer = input("\nVeux-tu vraiment quitter ? (o/n) : ")
    if answer.lower() == 'o':
        print("Arrêt du programme.")
        exit(0)
    else:
        print("Reprise du programme.")


def menu_principal():
    print("\n=== MENU PRINCIPAL ===")
    print("1 - Lire et afficher les trames")
    print("2 - Construction de la mini bdd + Insertion dans PostgreSQL")
    print("3 - Analyse du réseau en live + ajout dans PostgreSQL")
    print("0 - Quitter")


def pick(listChoices):
    choice = -1
    while choice not in listChoices:
        try:
            choice = int(input("Entrer votre choice : "))
        except ValueError:
            print("Veuillez entrer un nombre valide.")
    print("\n")
    return choice


def main():
    directory_path = "incoming_files" # Set the folder for the files to be processed
    directory_dst_path = "proccessed_files" # Set file folder after processing
    display_filter = "ldap || smb2" # Add the filters you want to use for the capture
    all_files = [f for f in os.listdir(directory_path) if f.endswith('.pcap')] # Create a list of files in your folder

    while True:
        menu_principal() # Displays the main menu function
        choice = pick([0, 1, 2]) # Executes the selection function with the list passed as a parameter
        
        if choice == 1:
            cur,conn = db_management.database_init() # Initializes cur and conn variables
            for file in all_files: # Browse files in the files variable
                print("         ---- FICHIER EN COURS ----\n        ",file)
                full_path = os.path.join(directory_path, file)
                capture = pyshark.FileCapture(full_path, display_filter=display_filter)
                for packet in capture : 
                    traitement_fichier_local.traitementPacket(packet,cur)
                try:
                    # Move the file if everything went well
                    shutil.move(full_path, directory_dst_path)
                    print(f"✅ File successfully moved to: {directory_dst_path}")
                except (shutil.Error, OSError) as e:
                    print(f"❌ Error while moving file {full_path} → {directory_dst_path}: {e}")
                
                capture.close()
            
            conn.commit()
            cur.close()
            conn.close()
            print("✅ Data successfully inserted into the PostgreSQL database.")

        elif choice == 2:
            cur,conn = db_management.database_init()

            # Utilisation du module analyse_reseau pour la capture live
            analyse_reseau.analyse_live(cur, conn)

            cur.close()
            conn.close()

        elif choice == 0:
            break


if __name__ == "__main__":
    print("--- DÉBUT DU PROGRAMME ---")
    signal.signal(signal.SIGINT, handler)
    main()
    print("\n--- Fin du programme ---\n")