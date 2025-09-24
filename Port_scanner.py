import socket
from concurrent.futures import ThreadPoolExecutor

TARGET = "192.168.56.101"   # IP do alvo
PORTS = range(1, 200)       # Portas a varrer
TIMEOUT = 0.3

# Estabelece uma conexão (por porta p)
def try_port(p):
    s = socket.socket()
    s.settimeout(TIMEOUT)

    try:
        s.connect((TARGET, p))
        s.close()
        return p, True
    
    except Exception:
        return p, False

# Abre as portas e inicia o ataque
if __name__ == "__main__":
    with ThreadPoolExecutor(max_workers=200) as ex:
        for port, open_ in ex.map(try_port, PORTS):
            if open_:
                print(f"Porta aberta: {port}")
