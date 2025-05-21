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

# Fonction qui traite le packet, construit le dictionnaire
# et le renvoie
def traitementPacket(packet,i) :
    data = {"IDENT": i}  # Un dictionnaire unique pour chaque paquet
    if 'IP' in packet:
        data["IP SRC"] = packet.ip.src
        data["IP DST"] = packet.ip.dst
    if 'ETH' in packet:
        data["MAC SRC"] = packet.eth.src
        data["MAC DST"] = packet.eth.dst
    if 'TCP' in packet:
        data["PORT SRC"] = packet.tcp.srcport
        data["PORT DST"] = packet.tcp.dstport
    if 'SMB2' in packet:
        if packet.smb2.get_field('filename') is not None:
            data["Filename"] = packet.smb2.filename
        if packet.smb2.get_field('sesid') is not None:
            data["Session ID"] = packet.smb2.sesid
        if packet.smb2.get_field('flags.response') is not None:
            if packet.smb2.flags_response == 'True':
                data["Is"] = "Response" 
                data["Rps ID"] = packet.smb2.msg_id # message ID de la réponse
            elif packet.smb2.flags_response == 'False' : 
                data["Is"] = "Request" 
                data["Rqt ID"] = packet.smb2.msg_id # message ID de la requête
    return data

# Fonction qui construit le dictionnaire
# et qui l'affiche
def packetInfoBuilder(capture) : 
    menuPacketInfoBuilder()
    bdd = []
    i = 1
    for packet in capture : 
        i += 1
        data = traitementPacket(packet,i)
        bdd.append(data)
        for packet in bdd :
            print(packet)
    
# Fonction de test
def fctTest(capture): 
    for pkt in capture:
        if 'smb2' in pkt:
            print(pkt.smb2._all_fields)
            if (pkt.smb2.flags) is not None :
                print(pkt.smb2.flags_response)
            break  # Pour ne pas spammer


def main() :
    # extraction de la capture .pcap et stocker dans la variable capture
    capture = pyshark.FileCapture("sauvegardes\Trame test Steph\Espion_08210_20250521070017.pcap",display_filter="ldap||smb2")
    # appel à la fonction menu
    continu = "y"
    while continu != "n" : 
        menuMain() 
        pickMain = pick([1,2,3,90])
        if(pickMain == 1) : 
            packetPrint(capture)
        elif(pickMain == 2) : 
            packetInfoBuilder(capture)
        elif(pickMain == 90) :
            fctTest(capture)
        continu = input("Voulez-vous continuer le programme ? : (y/n) ")

# === MAIN === #
print("--- DEBUT DU PROGRAMME ---")
main()
print("\n --- FIN DU PROGRAMME --- \n")
