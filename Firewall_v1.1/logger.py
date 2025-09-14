import datetime
import logging

# Configurar logging em arquivo (uma vez só)
logging.basicConfig(filename='firewall_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

def log(msg, log_text=None, is_blocked=False, contadores=None):
    """
    Função para logar mensagens em console, arquivo e GUI.
    - log_text: Widget Text do Tkinter (opcional, pra GUI).
    - is_blocked: Se True, incrementa contador de bloqueados.
    - contadores: Dicionário com {'permitidos': 0, 'bloqueados': 0} pra atualizar stats.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_msg = f"[{timestamp}] {msg}"
    
    # Console
    print(full_msg)
    
    # Arquivo
    logging.info(full_msg)
    
    # GUI (se existir)
    if log_text:
        log_text.insert('end', full_msg + "\n")
        log_text.see('end')
    
    # Atualizar contadores (se fornecidos)
    if contadores:
        if is_blocked:
            contadores['bloqueados'] += 1
        else:
            contadores['permitidos'] += 1
            