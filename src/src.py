# === INCLUDES === #
#  
import pyshark 

# === FONCTIONS === #

# Fonction menu qui permet d'afficher un menu
# et de return le choix effectué  
def menu():
    pick = -1
    listPick = [1]
    print(" - MENU - ")
    print(" 1 - Lecture des trames ")
    while listPick.count(pick) != 1 : 
        pick = int(input("Entrer votre choix : "))
    return pick

# Fonction qui permet d'afficher les trames extraites 
def packetPrint(capture) : 
    print(" -- Affichage des trames -- ")
    for packet in capture : 
        print(packet)


# === MAIN === #

# extraction de la capture .pcap et stocker dans la variable capture
capture = pyshark.FileCapture("Stage_BTS_2025\sauvegardes\Espion_03832_20250518054123.pcap") 
# appel à la fonction menu
pick = menu() 
if(pick == 1) : 
    packetPrint(capture)
