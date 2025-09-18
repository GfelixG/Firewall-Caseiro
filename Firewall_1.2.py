import logging
import ipaddress
import time
from collections import defaultdict
from Blocklist import carregar_lista_de_blocks, salvar_lista_de_blocks # Importa do arquivo Blocklist.py

# Ativando o pydivert para poder bloquear pacotes
try:
    import pydivert
except Exception as e:
    print("Erro ao importar pydivert. Certifique-se de ter instalado 'pydivert' e estar executando como Administrador.")
    raise

# Variáveis de bloqueio
LISTA_DE_BLOCKS = "blocklist.json"
bloqueados = {"ips_blocked": set(), "ports_blocked": set()}
bloqueados = carregar_lista_de_blocks(LISTA_DE_BLOCKS)  # IPs e portas bloqueados
conexoes_control = defaultdict(list)
portas_control = defaultdict(list)

DOS_LIMIT = 100       # Máx. conexões em X segundos (DOS_INTERVAL)
DOS_INTERVAL = 10     
SCAN_LIMIT = 10       # Máx. portas diferentes em X segundos (SCAN_INTERVAL)
SCAN_INTERVAL = 30

# Guarda o estado atual do programa
estado = {
    "blocks": bloqueados,
    "conexoes": conexoes_control, # Controlador das conexões
    "portas": portas_control, # Controlador das portas
    "pacotes_permitidos": 0, # Contador para estatística
    "pacotes_bloqueados": 0 # Contador para estatística
}

# Funções auxiliares
def valid_ip(ip_str): # Verifica se o IP é válido
    try:
        ipaddress.ip_address(ip_str)
        return True
    except Exception:
        return False

def add_block_ip (ip):
    if valid_ip(ip):
        estado["blocks"]["ips_blocked"].add(ip)
        logging.info(f"ADD {ip}")
        print(f"Adicionado: {ip}")
    else:
        print("IP inválido.")

def remove_block_ip (ip):
    if valid_ip(ip):
        estado["blocks"]["ips_blocked"].remove(ip)
        logging.info(f"REMOVE {ip}")
        print(f"Removido: {ip}")
    else:
        print("IP inválido.")

def add_block_port (port):
    if port < 1 or port > 65535:
        print("Porta inválida.")

    else:
        estado["blocks"]["ports_blocked"].add(port)
        logging.info(f"ADD {port}")
        print(f"Adicionado: {port}")

def remove_block_port (port):
    if port < 1 or port > 65535:
        print("Porta inválida.")

    else:
        estado["blocks"]["ports_blocked"].remove(port)
        logging.info(f"REMOVE {port}")
        print(f"Removido: {port}")

# Funções das regras que geram bloqueios de IPs ou portas
def na_lista_de_blocks (n, var="ip", stts=estado["blocks"]):
    if var == "ip":
        if n in stts["ips_blocked"]:
            return "IP na lista de IPs bloqueados"
    
    # Se não for um IP, será uma porta
    elif var == "porta" or var == "port":
        if n in stts["ports_blocked"]:
            return "Porta na lista de portas bloqueadas"
    
    else:
        print("Por favor, especifique o tipo do valor")

    return None

def ataque_DoS (ip, stts=estado["conexoes"]):
    tempo_agora = time.time()

    stts[ip].append(tempo_agora)
    stts[ip] = [t for t in stts[ip] if tempo_agora - t < DOS_INTERVAL]
    
    if len(stts[ip]) > DOS_LIMIT:
        return "Ataque DoS detectado"
    
    return None

def varredura_de_portas (ip, port, stts=estado["portas"]):
    tempo_agora = time.time()

    stts[ip].append((port, tempo_agora))
    stts[ip] = [(p, t) for (p, t) in stts[ip] if tempo_agora - t < SCAN_INTERVAL]
    portas_unicas = set(p for (p, _) in stts[ip])

    if len(portas_unicas) > SCAN_LIMIT:
        return "Varredura de portas detectada"
    
    return None

def main():
    print("Firewall ativo! Capturando pacotes...")
    print(estado["blocks"])
    
    with pydivert.WinDivert("ip") as w:
        for packet in w:
            ip_origem = packet.src_addr
            port_destino = getattr(packet, "dst_port", None)
            motivo = None

            if na_lista_de_blocks(ip_origem):
                motivo = na_lista_de_blocks(ip_origem)
                print(f"[BLOQUEADO] {ip_origem} -> {packet.dst_addr}:{port_destino} ({motivo})")
                add_block_ip(ip_origem)
                continue  # Descarta o pacote

            elif na_lista_de_blocks(port_destino, var = "porta"):
                motivo = na_lista_de_blocks(port_destino, var = "porta")
                print(f"[BLOQUEADO] {ip_origem} -> {packet.dst_addr}:{port_destino} ({motivo})")
                add_block_ip(ip_origem)
                continue  # Descarta o pacote
            
            elif ataque_DoS(ip_origem):
                motivo = ataque_DoS(ip_origem)
                print(f"[BLOQUEADO] {ip_origem} -> {packet.dst_addr}:{port_destino} ({motivo})")
                add_block_ip(ip_origem)
                continue  # Descarta o pacote

            elif varredura_de_portas(ip_origem, port_destino):
                motivo = varredura_de_portas(ip_origem, port_destino)
                print(f"[BLOQUEADO] {ip_origem} -> {packet.dst_addr}:{port_destino} ({motivo})")
                add_block_ip(ip_origem)
                continue  # Descarta o pacote
            
            # Se ele atendeu todos os requisitos, o pacote pode ser entregue
            else:
                print(f"[PERMITIDO] {ip_origem} -> {packet.dst_addr}:{port_destino}")
                w.send(packet)  # Libera o pacote normalmente  
                
if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        print("\nFirewall encerrado.")

    finally:
        salvar_lista_de_blocks(lista_de_blocks=estado["blocks"], path=LISTA_DE_BLOCKS) # Atualiza a lista com os novos blocks
        print(estado["blocks"])