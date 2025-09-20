import logging
import ipaddress
import time
from collections import defaultdict
from threading import Thread, Event, Lock
import queue
import json
import streamlit as st
from Blocklist import carregar_lista_de_blocks, salvar_lista_de_blocks  # Importa do arquivo Blocklist.py

# Ativando o pydivert para poder bloquear pacotes
try:
    import pydivert
except Exception as e:
    print("Erro ao importar pydivert. Certifique-se de ter instalado 'pydivert' e estar executando como Administrador.")
    raise

# Variáveis de bloqueio
LISTA_DE_BLOCKS = "blocklist.json"

DOS_LIMIT = 100       # Máx. conexões em X segundos (DOS_INTERVAL)
DOS_INTERVAL = 10     
SCAN_LIMIT = 10       # Máx. portas diferentes em X segundos (SCAN_INTERVAL)
SCAN_INTERVAL = 30

# Funções auxiliares
def valid_ip(ip_str):  # Verifica se o IP é válido
    try:
        ipaddress.ip_address(ip_str)
        return True
    except Exception:
        return False

def add_block_ip(ip, estado, lock):
    if valid_ip(ip):
        with lock:
            estado["blocks"]["ips_blocked"].add(ip)
            ips = sorted(list(estado["blocks"]["ips_blocked"]))
            ports = sorted(list(estado["blocks"]["ports_blocked"]))
        logging.info(f"ADD {ip}")
        try:
            with open(LISTA_DE_BLOCKS, "w") as f:
                json.dump({"ips_blocked": ips, "ports_blocked": ports}, f, indent=2)
            logging.info(f"Blocklist salva em {LISTA_DE_BLOCKS}")
        except Exception as e:
            logging.exception("Erro ao salvar blocklist: %s", e)
        return True
    return False

def remove_block_ip(ip, estado, lock):
    with lock:
        if ip in estado["blocks"]["ips_blocked"]:
            estado["blocks"]["ips_blocked"].remove(ip)
            ips = sorted(list(estado["blocks"]["ips_blocked"]))
            ports = sorted(list(estado["blocks"]["ports_blocked"]))
            logging.info(f"REMOVE IP: {ip}")
            try:
                with open(LISTA_DE_BLOCKS, "w") as f:
                    json.dump({"ips_blocked": ips, "ports_blocked": ports}, f, indent=2)
                logging.info(f"Blocklist salva em {LISTA_DE_BLOCKS}")
            except Exception as e:
                logging.exception("Erro ao salvar blocklist: %s", e)
            return True
    return False

def add_block_port(port, estado, lock):
    try:
        port = int(port)
        if 1 <= port <= 65535:
            with lock:
                estado["blocks"]["ports_blocked"].add(port)
                ips = sorted(list(estado["blocks"]["ips_blocked"]))
                ports = sorted(list(estado["blocks"]["ports_blocked"]))
            logging.info(f"ADD PORT: {port}")
            try:
                with open(LISTA_DE_BLOCKS, "w") as f:
                    json.dump({"ips_blocked": ips, "ports_blocked": ports}, f, indent=2)
                logging.info(f"Blocklist salva em {LISTA_DE_BLOCKS}")
            except Exception as e:
                logging.exception("Erro ao salvar blocklist: %s", e)
            return True
    except ValueError:
        pass
    return False

def remove_block_port(port, estado, lock):
    try:
        port = int(port)
        with lock:
            if port in estado["blocks"]["ports_blocked"]:
                estado["blocks"]["ports_blocked"].remove(port)
                ips = sorted(list(estado["blocks"]["ips_blocked"]))
                ports = sorted(list(estado["blocks"]["ports_blocked"]))
                logging.info(f"REMOVE PORT: {port}")
                try:
                    with open(LISTA_DE_BLOCKS, "w") as f:
                        json.dump({"ips_blocked": ips, "ports_blocked": ports}, f, indent=2)
                    logging.info(f"Blocklist salva em {LISTA_DE_BLOCKS}")
                except Exception as e:
                    logging.exception("Erro ao salvar blocklist: %s", e)
                return True
    except ValueError:
        pass
    return False

# Funções das regras que geram bloqueios de IPs ou portas
def na_lista_de_blocks(n, var="ip", estado=None, lock=None):
    with lock:
        if var == "ip":
            if n in estado["blocks"]["ips_blocked"]:
                return "IP na lista de IPs bloqueados"
        
        elif var == "porta" or var == "port":
            if n in estado["blocks"]["ports_blocked"]:
                return "Porta na lista de portas bloqueadas"
        
    return None

def ataque_DoS(ip, estado, lock):
    tempo_agora = time.time()
    with lock:
        estado["conexoes"][ip].append(tempo_agora)
        estado["conexoes"][ip] = [t for t in estado["conexoes"][ip] if tempo_agora - t < DOS_INTERVAL]
        
        if len(estado["conexoes"][ip]) > DOS_LIMIT:
            return "Ataque DoS detectado"
        
    return None

def varredura_de_portas(ip, port, estado, lock):
    tempo_agora = time.time()
    with lock:
        estado["portas"][ip].append((port, tempo_agora))
        estado["portas"][ip] = [(p, t) for (p, t) in estado["portas"][ip] if tempo_agora - t < SCAN_INTERVAL]
        portas_unicas = set(p for (p, _) in estado["portas"][ip])

        if len(portas_unicas) > SCAN_LIMIT:
            return "Varredura de portas detectada"
        
    return None

# Função principal do firewall (roda em thread)
def main(log_queue, estado, stop_event, lock):
    def put_log(msg, color):
        timestamp = time.strftime('%H:%M:%S')
        log_queue.put((msg, color, timestamp))
        print(f"[{timestamp}] {msg}")
        logging.info(msg)
    
    put_log("Firewall ativo! Capturando pacotes...", "black")
    
    with pydivert.WinDivert("ip") as w:
        while not stop_event.is_set():
            try:
                packet = w.recv()  # Recebe pacote (bloqueante, mas em thread OK)
                ip_origem = packet.src_addr
                port_destino = getattr(packet, "dst_port", None)
                motivo = None

                # Verificações sem redundância
                motivo_ip = na_lista_de_blocks(ip_origem, var="ip", estado=estado, lock=lock)
                if motivo_ip:
                    motivo = motivo_ip
                else:
                    motivo_porta = na_lista_de_blocks(port_destino, var="porta", estado=estado, lock=lock)
                    if motivo_porta:
                        motivo = motivo_porta
                    else:
                        motivo_dos = ataque_DoS(ip_origem, estado, lock)
                        if motivo_dos:
                            motivo = motivo_dos
                            add_block_ip(ip_origem, estado, lock)
                        else:
                            motivo_scan = varredura_de_portas(ip_origem, port_destino, estado, lock)
                            if motivo_scan:
                                motivo = motivo_scan
                                add_block_ip(ip_origem, estado, lock)

                if motivo:
                    put_log(f"[BLOQUEADO] {ip_origem} -> {packet.dst_addr}:{port_destino} ({motivo})", "red")
                    with lock:
                        estado["pacotes_bloqueados"] += 1
                    continue  # Descarta pacote (bloqueia)
                
                # Permitido
                put_log(f"[PERMITIDO] {ip_origem} -> {packet.dst_addr}:{port_destino}", "green")
                with lock:
                    estado["pacotes_permitidos"] += 1
                w.send(packet)  # Libera pacote
            except Exception as e:
                put_log(f"Erro ao processar pacote: {e}", "orange")

    put_log("Firewall parado.", "black")

# Configuração da UI com Streamlit
def setup_ui():
    st.title("Firewall Caseiro")

    # Inicializar estado da sessão
    if 'estado' not in st.session_state:
        blocks = carregar_lista_de_blocks(LISTA_DE_BLOCKS)
        st.session_state.estado = {
            "blocks": blocks,
            "conexoes": defaultdict(list),
            "portas": defaultdict(list),
            "pacotes_permitidos": 0,
            "pacotes_bloqueados": 0
        }
    if 'logs' not in st.session_state:
        st.session_state.logs = []
    if 'running' not in st.session_state:
        st.session_state.running = False
    if 'stop_event' not in st.session_state:
        st.session_state.stop_event = Event()
    if 'firewall_thread' not in st.session_state:
        st.session_state.firewall_thread = None
    if 'log_queue' not in st.session_state:
        st.session_state.log_queue = queue.Queue()
    if 'estado_lock' not in st.session_state:
        st.session_state.estado_lock = Lock()

    log_queue = st.session_state.log_queue
    lock = st.session_state.estado_lock
    estado = st.session_state.estado

    # Process logs from queue
    while not log_queue.empty():
        msg, color, timestamp = log_queue.get()
        st.session_state.logs.append((f"[{timestamp}] {msg}", color))

    # Tabs
    tab_logs, tab_regras, tab_estatisticas = st.tabs(["Logs", "Regras", "Estatísticas"])

    with tab_logs:
        st.subheader("Logs")
        for msg, color in st.session_state.logs:
            st.markdown(f'<p style="color:{color};">{msg}</p>', unsafe_allow_html=True)
        if st.button("Limpar Logs"):
            st.session_state.logs = []
            st.rerun()

    with tab_regras:
        st.subheader("Regras")

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("IPs Bloqueados")
            with lock:
                ips = sorted(estado["blocks"]["ips_blocked"])
            st.write("\n".join(ips) if ips else "Nenhum IP bloqueado.")
            
            ip_input = st.text_input("Adicionar IP")
            if st.button("Adicionar IP"):
                if add_block_ip(ip_input, estado, lock):
                    st.success("IP adicionado!")
                else:
                    st.error("IP inválido.")
                st.rerun()
            
            if ips:
                ip_to_remove = st.selectbox("Selecione IP para remover", ips)
                if st.button("Remover IP"):
                    if remove_block_ip(ip_to_remove, estado, lock):
                        st.success("IP removido!")
                    else:
                        st.error("Erro ao remover IP.")
                    st.rerun()

        with col2:
            st.subheader("Portas Bloqueadas")
            with lock:
                ports = sorted(estado["blocks"]["ports_blocked"])
            st.write("\n".join(map(str, ports)) if ports else "Nenhuma porta bloqueada.")
            
            port_input = st.text_input("Adicionar Porta")
            if st.button("Adicionar Porta"):
                if add_block_port(port_input, estado, lock):
                    st.success("Porta adicionada!")
                else:
                    st.error("Porta inválida (1-65535).")
                st.rerun()
            
            if ports:
                port_to_remove = st.selectbox("Selecione Porta para remover", ports)
                if st.button("Remover Porta"):
                    if remove_block_port(port_to_remove, estado, lock):
                        st.success("Porta removida!")
                    else:
                        st.error("Erro ao remover porta.")
                    st.rerun()

    with tab_estatisticas:
        st.subheader("Estatísticas")
        with lock:
            st.metric("Pacotes Permitidos", estado["pacotes_permitidos"])
            st.metric("Pacotes Bloqueados", estado["pacotes_bloqueados"])

    # Botão Iniciar/Parar
    if not st.session_state.running:
        if st.button("Iniciar Firewall", type="primary"):
            st.session_state.stop_event.clear()
            st.session_state.firewall_thread = Thread(target=main, args=(log_queue, estado, st.session_state.stop_event, lock))
            st.session_state.firewall_thread.daemon = True
            st.session_state.firewall_thread.start()
            st.session_state.running = True
            st.rerun()
    else:
        if st.button("Parar Firewall"):
            st.session_state.stop_event.set()
            if st.session_state.firewall_thread:
                st.session_state.firewall_thread.join(timeout=5)  # Espera um pouco para parar
            st.session_state.running = False
            with lock:
                ips = sorted(list(estado["blocks"]["ips_blocked"]))
                ports = sorted(list(estado["blocks"]["ports_blocked"]))
            try:
                with open(LISTA_DE_BLOCKS, "w") as f:
                    json.dump({"ips_blocked": ips, "ports_blocked": ports}, f, indent=2)
                logging.info(f"Blocklist salva em {LISTA_DE_BLOCKS}")
            except Exception as e:
                logging.exception("Erro ao salvar blocklist: %s", e)
            st.rerun()

    # Atualização automática quando rodando
    if st.session_state.running:
        time.sleep(1)  # Atualiza a cada 1 segundo
        st.rerun()

if __name__ == "__main__":
    logging.basicConfig(filename='firewall_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')
    setup_ui()