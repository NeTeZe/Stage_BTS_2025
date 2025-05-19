# === INCLUDES === # 
import pyshark 

# === FONCTIONS === #
def menu():
    pick = -1
    listPick = [1]
    print(" - MENU - ")
    print(" 1 - Lecture des trames ")
    while listPick.count(pick) != 1 : 
        pick = int(input("Entrer votre choix : "))
    return pick

def packetPrint(capture) : 
    print(" -- Affichage des trames -- ")
    for packet in capture : 
        print(packet)


# === MAIN === #
capture = pyshark.FileCapture("Stage_BTS_2025\sauvegardes\Espion_03832_20250518054123.pcap")
pick = menu()
if(pick == 1) : 
    packetPrint(capture)
