import pyshark
import sys
import os
import signal

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from include import analyse_reseau
from include import gestion_bdd_local
from include import gestion_bdd_live
from include import traitement_fichier_local


def handler(sig, frame):
    answer = input("\nVeux-tu vraiment quitter ? (o/n) : ")
    if answer.lower() == 'o':
        print("Arrêt du programme.")
        exit(0)
    else:
        print("Reprise du programme.")
signal.signal(signal.SIGINT, handler)


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
    directory_path = "sauvegardes"
    display_filter = "ldap || smb2"
    files = [f for f in os.listdir(directory_path) if f.endswith('.pcap')]

    while True:
        menu_principal()
        choice = pick([0, 1, 2, 3])

        if choice == 1:
            for file in files:
                full_path = os.path.join(directory_path, file)
                capture = pyshark.FileCapture(full_path, display_filter=display_filter)
                traitement_fichier_local.packetPrint_local(capture)

        elif choice == 2:
            pwd = input("Mot de passe PostgreSQL : ")
            conn = gestion_bdd_local.connectionBdd(pwd)
            cur = conn.cursor()
            gestion_bdd_local.createTable(cur)

            for file in files:
                full_path = os.path.join(directory_path, file)
                capture = pyshark.FileCapture(full_path, display_filter=display_filter)
                bdd = traitement_fichier_local.packetInfoBuilder(capture)
                if bdd is not None : 
                    gestion_bdd_local.insertionBdd(cur, bdd)
                capture.close()

            conn.commit()
            cur.close()
            conn.close()
            print("✅ Données insérées dans la base PostgreSQL.")

        elif choice == 3:
            pwd = input("Mot de passe PostgreSQL : ")
            conn = gestion_bdd_live.connectionBdd(pwd)
            cur = conn.cursor()
            gestion_bdd_live.createTable(cur)

            # Utilisation du module analyse_reseau pour la capture live
            analyse_reseau.analyse_live(cur, conn)

            cur.close()
            conn.close()

        elif choice == 0:
            print("\n--- Fin du programme ---\n")
            break


if __name__ == "__main__":
    print("--- DÉBUT DU PROGRAMME ---")
    main()
