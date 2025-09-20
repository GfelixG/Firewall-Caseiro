import logging
import ipaddress
import time
from collections import defaultdict
from threading import Thread, Event
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
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
    "conexoes": conexoes_control,  # Controlador das conexões
    "portas": portas_control,      # Controlador das portas
    "pacotes_permitidos": 0,       # Contador para estatística
    "pacotes_bloqueados": 0        # Contador para estatística
}

# Evento para parar a thread do firewall
stop_event = Event()

# Funções auxiliares
def valid_ip(ip_str): # Verifica se o IP é válido
    try:
        ipaddress.ip_address(ip_str)
        return True
    except Exception:
        return False

def add_block_ip (ip, refresh_ui=None):
    if valid_ip(ip):
        estado["blocks"]["ips_blocked"].add(ip)
        logging.info(f"ADD {ip}")
        if refresh_ui:
            refresh_ui()  # Atualiza Listbox na UI
        return True

def remove_block_ip(ip, refresh_ui=None):
    if ip in estado["blocks"]["ips_blocked"]:
        estado["blocks"]["ips_blocked"].remove(ip)
        logging.info(f"REMOVE IP: {ip}")
        if refresh_ui:
            refresh_ui()
        return True
    return False

def add_block_port(port, refresh_ui=None):
    try:
        port = int(port)
        if 1 <= port <= 65535:
            estado["blocks"]["ports_blocked"].add(port)
            logging.info(f"ADD PORT: {port}")
            if refresh_ui:
                refresh_ui()
            return True
    except ValueError:
        pass
    return False

def remove_block_port(port, refresh_ui=None):
    try:
        port = int(port)
        if port in estado["blocks"]["ports_blocked"]:
            estado["blocks"]["ports_blocked"].remove(port)
            logging.info(f"REMOVE PORT: {port}")
            if refresh_ui:
                refresh_ui()
            return True
    except ValueError:
        pass
    return False

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

# Função principal do firewall (roda em thread)
def main(log_func, stats_update_func):
    print("Firewall ativo! Capturando pacotes...")
    log_func("Firewall ativo! Capturando pacotes...")
    
    with pydivert.WinDivert("ip") as w:
        while not stop_event.is_set():
            try:
                packet = w.recv()  # Recebe pacote (bloqueante, mas em thread OK)
                ip_origem = packet.src_addr
                port_destino = getattr(packet, "dst_port", None)
                motivo = None

                # Verificações sem redundância
                motivo_ip = na_lista_de_blocks(ip_origem)
                if motivo_ip:
                    motivo = motivo_ip
                else:
                    motivo_porta = na_lista_de_blocks(port_destino, var="porta")
                    if motivo_porta:
                        motivo = motivo_porta
                    else:
                        motivo_dos = ataque_DoS(ip_origem)
                        if motivo_dos:
                            motivo = motivo_dos
                            add_block_ip(ip_origem)
                        else:
                            motivo_scan = varredura_de_portas(ip_origem, port_destino)
                            if motivo_scan:
                                motivo = motivo_scan
                                add_block_ip(ip_origem)

                if motivo:
                    log_func(f"[BLOQUEADO] {ip_origem} -> {packet.dst_addr}:{port_destino} ({motivo})", color="red")
                    estado["pacotes_bloqueados"] += 1
                    stats_update_func()  # Atualiza stats na UI
                    continue  # Descarta pacote (bloqueia)
                
                # Permitido
                log_func(f"[PERMITIDO] {ip_origem} -> {packet.dst_addr}:{port_destino}", color="green")
                estado["pacotes_permitidos"] += 1
                stats_update_func()
                w.send(packet)  # Libera pacote
            except Exception as e:
                log_func(f"Erro ao processar pacote: {e}", color="orange")

    log_func("Firewall parado.")
                
# Configuração da UI com Tkinter
def setup_ui():
    root = tk.Tk()
    root.title("Firewall Caseiro")
    root.geometry("800x600")
    root.config(bg="#F1BBBB")

    style = ttk.Style()
    style.configure("TNotebook", background="#F1BBBB")
    style.configure("TFrame", background="#F1BBBB")
    # Removendo a linha problemática do estilo
    # style.configure("TLabelFrame", background="#E6D8CB", foreground="#2F3559", font=("Arial", 12, "bold"))

    # Notebook para tabs
    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=10, pady=10)

    # Tab Logs
    log_frame = ttk.Frame(notebook, style="TFrame")
    notebook.add(log_frame, text="Logs")
    log_text = scrolledtext.ScrolledText(log_frame, height=25, width=90, wrap=tk.WORD, bg="#E6D8CB", fg="#2F3559", font=("Arial", 10))
    log_text.pack(pady=10, padx=10)

    def log_to_ui(msg, color="black"):
        log_text.tag_configure(color, foreground=color)
        log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {msg}\n", color)
        log_text.see(tk.END)
        print(msg)
        logging.info(msg)

    # Tab Regras
    rules_frame = ttk.Frame(notebook)
    notebook.add(rules_frame, text="Regras")

    # Seção IPs Bloqueados (removendo o estilo customizado)
    ip_frame = ttk.LabelFrame(rules_frame, text="IPs Bloqueados")
    ip_frame.pack(side="left", padx=20, pady=20, fill="y")
    ip_listbox = tk.Listbox(ip_frame, height=15, width=30, bg="#E6D8CB", fg="#2F3559", font=("Arial", 10))
    ip_listbox.pack(pady=5)
    ip_entry = tk.Entry(ip_frame, bg="#E6D8CB", fg="#2F3559", font=("Arial", 10))
    ip_entry.pack(pady=5)
    add_ip_btn = tk.Button(ip_frame, text="Adicionar IP", command=lambda: add_block_ip(ip_entry.get(), refresh_rules) if add_block_ip(ip_entry.get(), refresh_rules) else messagebox.showerror("Erro", "IP inválido"), bg="#9A5071", fg="white", font=("Arial", 10, "bold"))
    add_ip_btn.pack(pady=5)
    remove_ip_btn = tk.Button(ip_frame, text="Remover IP", command=lambda: remove_block_ip(ip_listbox.get(tk.ACTIVE), refresh_rules) if remove_block_ip(ip_listbox.get(tk.ACTIVE), refresh_rules) else messagebox.showerror("Erro", "Selecione um IP"), bg="#2F3559", fg="white", font=("Arial", 10, "bold"))
    remove_ip_btn.pack(pady=5)

    # Seção Portas Bloqueadas (removendo o estilo customizado)
    port_frame = ttk.LabelFrame(rules_frame, text="Portas Bloqueadas")
    port_frame.pack(side="right", padx=20, pady=20, fill="y")
    port_listbox = tk.Listbox(port_frame, height=15, width=30, bg="#E6D8CB", fg="#2F3559", font=("Arial", 10))
    port_listbox.pack(pady=5)
    port_entry = tk.Entry(port_frame, bg="#E6D8CB", fg="#2F3559", font=("Arial", 10))
    port_entry.pack(pady=5)
    add_port_btn = tk.Button(port_frame, text="Adicionar Porta", command=lambda: add_block_port(port_entry.get(), refresh_rules) if add_block_port(port_entry.get(), refresh_rules) else messagebox.showerror("Erro", "Porta inválida (1-65535)"), bg="#9A5071", fg="white", font=("Arial", 10, "bold"))
    add_port_btn.pack(pady=5)
    remove_port_btn = tk.Button(port_frame, text="Remover Porta", command=lambda: remove_block_port(port_listbox.get(tk.ACTIVE), refresh_rules) if remove_block_port(port_listbox.get(tk.ACTIVE), refresh_rules) else messagebox.showerror("Erro", "Selecione uma porta"), bg="#2F3559", fg="white", font=("Arial", 10, "bold"))
    remove_port_btn.pack(pady=5)

    # Função para atualizar Listboxes
    def refresh_rules():
        ip_listbox.delete(0, tk.END)
        for ip in sorted(estado["blocks"]["ips_blocked"]):
            ip_listbox.insert(tk.END, ip)
        port_listbox.delete(0, tk.END)
        for port in sorted(estado["blocks"]["ports_blocked"]):
            port_listbox.insert(tk.END, port)
        salvar_lista_de_blocks(estado["blocks"], LISTA_DE_BLOCKS)  # Salva ao editar

    refresh_rules()  # Inicial

    # Tab Estatísticas
    stats_frame = ttk.Frame(notebook, style="TFrame")
    notebook.add(stats_frame, text="Estatísticas")
    permitidos_label = tk.Label(stats_frame, text="Pacotes Permitidos: 0", font=("Arial", 14, "bold"), bg="#F1BBBB", fg="#2F3559")
    permitidos_label.pack(pady=20)
    bloqueados_label = tk.Label(stats_frame, text="Pacotes Bloqueados: 0", font=("Arial", 14, "bold"), bg="#F1BBBB", fg="#2F3559")
    bloqueados_label.pack(pady=20)

    def update_stats():
        permitidos_label.config(text=f"Pacotes Permitidos: {estado['pacotes_permitidos']}")
        bloqueados_label.config(text=f"Pacotes Bloqueados: {estado['pacotes_bloqueados']}")

    # Botão Iniciar/Parar (abaixo das tabs)
    firewall_running = False
    def toggle_firewall():
        nonlocal firewall_running
        if not firewall_running:
            stop_event.clear()
            thread = Thread(target=main, args=(log_to_ui, update_stats))
            thread.daemon = True
            thread.start()
            start_btn.config(text="Parar Firewall", bg="#2F3559")
            firewall_running = True
        else:
            stop_event.set()
            start_btn.config(text="Iniciar Firewall", bg="#9A5071")
            firewall_running = False
            salvar_lista_de_blocks(estado["blocks"], LISTA_DE_BLOCKS)

    start_btn = tk.Button(root, text="Iniciar Firewall", command=toggle_firewall, bg="#9A5071", fg="white", font=("Arial", 12, "bold"), relief="raised", padx=10, pady=5)
    start_btn.pack(pady=10)

    # Ao fechar janela, parar e salvar
    def on_closing():
        stop_event.set()
        salvar_lista_de_blocks(estado["blocks"], LISTA_DE_BLOCKS)
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)

    root.mainloop()

if __name__ == "__main__":
    logging.basicConfig(filename='firewall_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')
    setup_ui()