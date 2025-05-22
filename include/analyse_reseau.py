import pyshark
from include import traitement_fichier_live
from include import gestion_bdd_live


def analyse_live(cur, conn):
    """
    Initialise une analyse du réseau en direct.

    - Lance une capture sur l'interface 'Ethernet 5'.
    - Transmet les paquets à traitement_fichier_live.packet_info_builder.
    """
    capture = pyshark.LiveCapture(interface='Ethernet 5')
    traitement_fichier_live.packet_info_builder(capture, cur, conn)
