# === INCLUDES === #
#  DOCUMENTATION  https://github.com/KimiNewt/pyshark?tab=readme-ov-file
import pyshark 

# === FONCTIONS === #
# Fonction pick qui permet de retourner
# une valeur saisie par le user
def pick() : 
    listPick = [1,2]
    pick = -1
    while listPick.count(pick) != 1 : 
        pick = int(input("Entrer votre choix : "))
    print("\n")
    return pick

# Fonction menu qui permet d'afficher un menu
def menu():
    print(" - MENU - ")
    print(" 1 - Lecture des trames ")

# Fonction qui permet d'afficher les trames extraites 
def packetPrint(capture) : 
    print(" -- Affichage des trames -- ")
    print(" 1 - Affichage de toutes les trames ")
    print(" 2 - Affichage d'une trame spécifiques ")
    pickPacketPrint = pick()
    if(pickPacketPrint == 1) : 
        for packet in capture : print(packet) #affichage des toutes les trames
    elif(pickPacketPrint == 2):
        #n = int(input("Entrer le numéro de la trame voulue :  "))
        dir(capture[5].smb2) 
        print("Adr IP SRC : ",capture[5].ip.src)
        print("Adr IP SRC : ",capture[5].ip.src)
        print("Adr IP DST : ",capture[5].ip.dst)
        print("Adr MAC SRC : ",capture[5].eth.src)
        print("Adr MAC DST : ",capture[5].eth.dst)
        print("Fichier demandé : ",capture[5].smb2.filename)
        print("Accès demandé : (7 = O/W/R) ",capture[5].smb2.smb_share_access)
    else: 
        exit()



# === MAIN === #
print("--- DEBUT DU PROGRAMME ---")
# extraction de la capture .pcap et stocker dans la variable capture
capture = pyshark.FileCapture("Stage_BTS_2025\sauvegardes\Espion_03832_20250518054123.pcap",display_filter='smb2') 
# appel à la fonction menu
continu = "y"
while continu != "n" : 
    menu() 
    pickMain = pick()
    print("pick",pickMain)
    if(pickMain == 1) : 
        packetPrint(capture)
    continu = input("Voulez-vous continuer le programme ? : (y/n) ")
print("--- FIN DU PROGRAMME ---")