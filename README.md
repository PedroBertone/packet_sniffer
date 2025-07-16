# packet_sniffer
Packet Sniffer with Scapy for Python

#primeiro instale o scapy (cmd no windows = pip install scapy) (linux/mac = sudo python sniffer.py)
--------------------------------------------------------------------------------------------------
from scapy.all import sniff

def exibir_pacote(pacote):
    if pacote.haslayer("IP"):
        ip_origem = pacote["IP"].src
        ip_destino = pacote["IP"].dst
        protocolo = pacote["IP"].proto

        print(f"[+] IP: {ip_origem} -> {ip_destino} | Protocolo: {protocolo}")

# Captura 0 significa infinito, ou use count=10 para limitar
print("📡 Sniffando pacotes... Pressione CTRL+C para parar.")
sniff(prn=exibir_pacote, count=0)

---------------------------------------------------------------------------------------------------
#filtrar apenas TCP
sniff(filter="tcp", prn=exibir_pacote, store=False)
---------------------------------------------------------------------------------------------------
#salvar pacotes
sniff(prn=exibir_pacote, count=10, store=True).wrpcap("saida.pcap")
---------------------------------------------------------------------------------------------------

