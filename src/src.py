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
    print(" 90 - TEST : Afficher les attributs")

# Fonction menu qui permet d'afficher le menu de la fonction attributePrint
def menuAttribute(): 
    print(" -- Affichage des attributes par protocole -- ")
    print(" 1 - Ethernet ")
    print(" 2 - IP ")
    print(" 3 - TCP ")
    print(" 4 - SMB2 ")
    
# Fonction menu qui permet d'afficher le menu de la fonction packetPrint
def menuPacketPrint(): 
    print(" -- Affichage des trames -- ")
    print(" 1 - Affichage de toutes les trames ")
    print(" 2 - Affichage d'une trame spécifiques ")

# Fonction qui permet d'afficher les trames extraites 
def packetPrint(capture) : 
    menuPacketPrint()
    pickPacketPrint = pick([1,2])
    if(pickPacketPrint == 1) : 
        for packet in capture : print(packet) #affichage des toutes les trames
    elif(pickPacketPrint == 2):
        print(dir(capture[5].eth))
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


def attributePrint(capture) : 
    menuAttribute()
    proto = pick([1,2,3,4])
    if(proto == 1) : 
        print(dir(capture[5].eth))
    elif(proto == 2) : 
        print(dir(capture[5].ip))
    elif(proto == 3) : 
        print(dir(capture[5].tcp))
    elif(proto == 4) : 
        print(dir(capture[5].smb2))
    else :
        exit()
# === MAIN === #
print("--- DEBUT DU PROGRAMME ---")
# extraction de la capture .pcap et stocker dans la variable capture
capture = pyshark.FileCapture("Stage_BTS_2025\sauvegardes\Espion_03832_20250518054123.pcap",display_filter='smb2') 
# appel à la fonction menu
continu = "y"
while continu != "n" : 
    menuMain() 
    pickMain = pick([1,90])
    if(pickMain == 1) : 
        packetPrint(capture)
    elif(pickMain == 90) :
        attributePrint(capture)
    continu = input("Voulez-vous continuer le programme ? : (y/n) ")


print("\n --- FIN DU PROGRAMME --- \n")