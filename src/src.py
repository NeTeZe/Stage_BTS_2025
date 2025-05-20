# === INCLUDES === #
#  DOCUMENTATION  https://github.com/KimiNewt/pyshark?tab=readme-ov-file
import pyshark 


# === FONCTIONS === #
# Fonction pick qui permet de retourner
# une valeur saisie par le user
def pick(listPick) : 
    pick = -1
    while listPick.count(pick) != 1 : 
        pick = int(input("Entrer votre choix : "))
    print("\n")
    return pick

# Fonction menu qui permet d'afficher le menu du main
def menuMain():
    print(" - MENU - ")
    print(" 1 - Lecture des trames ")
    print(" 2 - Construction d'une mini-bdd des packets ")
    print(" 90 - TEST : ")

# Fonction menu qui permet d'afficher le menu de la fonction packetPrint
def menuPacketPrint(): 
    print(" -- Affichage des trames -- ")
    print(" 1 - Affichage de toutes les trames ")
    print(" 2 - Affichage d'une trame spécifiques ")

# Fonction menu qui permet d'afficher le menu de la fonction menuPacketInfoBuilder
def menuPacketInfoBuilder() : 
    print(" -- Construction d'une mini bdd de la capture -- ")

# Fonction qui permet d'afficher les trames extraites 
def packetPrint(capture) : 
    menuPacketPrint()
    pickPacketPrint = pick([1,2])
    if(pickPacketPrint == 1) : 
        for packet in capture : print(packet) #affichage des toutes les trames
    elif(pickPacketPrint == 2):
        print("Adr IP SRC : ",capture[5].ip.src)
        print("Adr IP SRC : ",capture[5].ip.src)
        print("Adr IP DST : ",capture[5].ip.dst)
        print("Adr MAC SRC : ",capture[5].eth.src)
        print("Adr MAC DST : ",capture[5].eth.dst)
        print("Fichier demandé : ",capture[5].smb2.filename)
        print("Accès demandé (7 = O/W/R) :  ",capture[5].smb2.smb_share_access)
    else: 
        exit()
    print("\n")


def packetInfoBuilder(capture) : 
    menuPacketInfoBuilder()
    bdd = []
    i=1
    for packet in capture : 
        bdd.append({"IDENT : ": i})
        if ('IP' in packet) : 
            bdd.append({"IP SRC : ": packet.ip.src, "IP DST : ":packet.ip.dst})
        if('ETH' in packet) : 
            bdd.append({"MAC SRC : ":packet.eth.src,"MAC DST : ":packet.eth.dst})
        if('TCP' in packet) : 
            bdd.append({"PORT SRC : ":packet.tcp.srcport,"PORT DST : ":packet.tcp.dstport})
        i += 1
    
    for trames in bdd:
        for info in trames.items() : 
            print(info)
        


# === MAIN === #
print("--- DEBUT DU PROGRAMME ---")
# extraction de la capture .pcap et stocker dans la variable capture
capture = pyshark.FileCapture("Stage_BTS_2025\sauvegardes\Espion_03832_20250518054123.pcap") 
# appel à la fonction menu
continu = "y"
while continu != "n" : 
    menuMain() 
    pickMain = pick([1,2,90])
    if(pickMain == 1) : 
        packetPrint(capture)
    elif(pickMain == 2) : 
        packetInfoBuilder(capture)
    elif(pickMain == 90) :
        print("TEST")
    continu = input("Voulez-vous continuer le programme ? : (y/n) ")


print("\n --- FIN DU PROGRAMME --- \n")