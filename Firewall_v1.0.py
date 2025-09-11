from scapy.all import sniff, IP, TCP

# Lista de IPs bloqueados
ip_bloqueado = ["192.168.1.103", "8009"]

# Portas bloqueadas
portas_bloqueadas = [23, 445]  # Ex: Telnet e SMB

def analisar_pacote(pacote):
    if IP in pacote:
        ip_origem = pacote[IP].src
        ip_destino = pacote[IP].dst

        if TCP in pacote:
            porta_origem = pacote[TCP].sport
            porta_destino = pacote[TCP].dport

            if ip_origem in ip_bloqueado or ip_destino in ip_bloqueado:
                print(f"[BLOQUEADO] Conexão com IP bloqueado: {ip_origem} -> {ip_destino}")
                return

            if porta_origem in portas_bloqueadas or porta_destino in portas_bloqueadas:
                print(f"[BLOQUEADO] Conexão com porta bloqueada: {porta_origem} -> {porta_destino}")
                return

            print(f"[PERMITIDO] {ip_origem}:{porta_origem} -> {ip_destino}:{porta_destino}")
        else:
            print(f"[INFO] Pacote IP sem TCP: {ip_origem} -> {ip_destino}")
    else:
        print("[INFO] Pacote sem camada IP.")

print("Iniciando firewall... Pressione Ctrl+C para parar.")

sniff(prn=analisar_pacote, store=0)
