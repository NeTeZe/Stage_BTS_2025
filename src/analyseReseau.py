# === INCLUDES === #
#  DOCUMENTATION  https://github.com/KimiNewt/pyshark?tab=readme-ov-file
import pyshark 
import traitementFichier

# === FONCTION === #

# === MAIN === #
print("--- DEBUT DU PROGRAMME ---")

capture = pyshark.LiveCapture(interface='Ethernet 5')
capture.sniff(timeout=1)
for packet in capture.sniff_continuously(packet_count=5):
    print('Just arrived',packet)
while capture.sniff_continuously(packet_count=5) : 
    traitementFichier.packetInfoBuilder(capture.sniff_continuously(packet_count=10))
print("\n --- FIN DU PROGRAMME --- \n")