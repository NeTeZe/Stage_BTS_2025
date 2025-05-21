"""
analyse_reseau.py

Ce script effectue une capture réseau en temps réel à l'aide de PyShark,
puis transmet les paquets capturés à une fonction de traitement définie
dans un module externe (traitementFichier.py).

Documentation de PyShark : https://github.com/KimiNewt/pyshark
"""

import pyshark
from include import traitement_fichier


def analyse_live():
    """
    Initialise une analyse du réseau en direct.

    Étapes :
    - Démarre une capture réseau sur l'interface 'Ethernet 5'.
    - Affiche les 5 premiers paquets reçus.
    - Capture ensuite 10 paquets supplémentaires pour traitement.
    """

    # Lance une capture en direct sur l'interface réseau spécifiée
    capture = pyshark.LiveCapture(interface='Ethernet 5')

    # Capture initiale : attend jusqu'à 1 seconde ou 5 paquets
    capture.sniff(timeout=1)

    print("\n[INFO] Affichage des 5 premiers paquets :")
    for packet in capture.sniff_continuously(packet_count=5):
        print('Nouveau paquet reçu :', packet)

    # Capture supplémentaire pour traitement
    print("\n[INFO] Capture de 10 paquets supplémentaires pour traitement...")
    packets_to_process = capture.sniff_continuously(packet_count=10)

    # Appel du module de traitement
    traitement_fichier.packetInfoBuilder(packets_to_process)


