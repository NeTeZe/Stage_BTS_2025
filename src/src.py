# === INCLUDES === # 
import pyshark 

# === FONCTIONS === #
def menu():
    pick = -1
    listPick = [1]
    while listPick.count(pick) != 1 : 
        pick = int(input("Entrer votre choix : "))
    print(" - MENU - ")
    print(" 1 - ")



# === MAIN === #
readFile = pyshark.FileCapture("Stage_BTS_2025\sauvegardes\Espion_03832_20250518054123.pcap")
readFile
pick = menu()
