import json
import tkinter as tk
from threading import Thread
from scapy.all import sniff, IP, TCP, UDP, send
from logger import log  # Importa do arquivo logger.py

# Regras de bloqueio
ip_bloqueado = ["127.0.0.1", "8.8.8.8"]  # IPs bloqueados
portas_bloqueadas = [23, 445, 80]  # Portas bloqueadas

# Contadores para estatísticas
contadores = {'permitidos': 0, 'bloqueados': 0}

def analisar_pacote(pacote):
    # Verifica se o pacote tem uma camada IP
    if IP in pacote:
        ip_origem = pacote[IP].src
        ip_destino = pacote[IP].dst

        # Extrai informações de porta e protocolo (se existirem)
        porta_origem = None
        porta_destino = None
        protocolo = "Outro"

        # Verifica se o pacote tem a camada TCP ou UDP
        if TCP in pacote:
            porta_origem = pacote[TCP].sport
            porta_destino = pacote[TCP].dport
            protocolo = "TCP"
        elif UDP in pacote:
            porta_origem = pacote[UDP].sport
            porta_destino = pacote[UDP].dport
            protocolo = "UDP"

        # Verifica se o IP de origem ou destino está na lista de bloqueados
        # Apenas verifica, não bloqueia efetivamente nenhum dos dois.
        if ip_origem in ip_bloqueado or ip_destino in ip_bloqueado:
            msg = f"[BLOQUEADO] Conexão com IP bloqueado: {ip_origem} <-> {ip_destino}"
            log(msg, log_text=log_text, is_blocked=True, contadores=contadores)
            # Para realmente bloquear, descomente o trecho abaixo
            # if TCP in pacote:
            #     rst_pkt = IP(src=ip_destino, dst=ip_origem)/TCP(sport=pacote[TCP].dport, dport=pacote[TCP].sport, flags="R")
            #     send(rst_pkt, verbose=0)
            return
        
        # Verifica se a porta acessada está na lista de portas bloqueadas
        if porta_origem in portas_bloqueadas or porta_destino in portas_bloqueadas:
            msg = f"[BLOQUEADO] Conexão com porta bloqueada: {porta_origem} -> {porta_destino}"
            log(msg, log_text=log_text, is_blocked=True, contadores=contadores)
            # if protocolo == "TCP":
            #     # Enviar RST para resetar a conexão
            #     rst_pkt = IP(src=ip_destino, dst=ip_origem)/TCP(sport=porta_destino, dport=porta_origem, flags="R")
            #     send(rst_pkt, verbose=0)
            return

        # Se passou por todas as verificações, o pacote é permitido
        if protocolo in ["TCP", "UDP"]:
            msg = f"[PERMITIDO] {ip_origem}:{porta_origem} -> {ip_destino}:{porta_destino} ({protocolo})"
        else:
            msg = f"[PERMITIDO] Pacote IP ({ip_origem} -> {ip_destino}) sem TCP/UDP"
            
        log(msg, log_text=log_text, contadores=contadores)
        
    else:
        msg = "[INFO] Pacote sem camada IP."
        log(msg, log_text=log_text)

# Configurar GUI
root = tk.Tk()
root.title("Firewall Caseiro v1.1")
log_text = tk.Text(root, height=20, width=80) 
log_text.pack()

# Função para mostrar estatísticas ao fechar
def on_closing():
    msg = f"Estatísticas: Permitidos: {contadores['permitidos']}, Bloqueados: {contadores['bloqueados']}"
    log(msg, log_text=log_text)
    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_closing)

# Iniciar captura de tráfego de rede em uma thread separada
def start_sniff():
    log("Iniciando firewall... Feche a janela para parar.", log_text=log_text)
    sniff(prn=analisar_pacote, store=0)

sniff_thread = Thread(target=start_sniff)
sniff_thread.daemon = True
sniff_thread.start()

# Rodar GUI
root.mainloop()