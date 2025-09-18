import ipaddress
import json
import logging

# Arquivo que guarda os IPs bloqueados
arq = "blocklist.json"

def carregar_lista_de_blocks(path=arq):
    lista_de_blocks = {"ips_blocked": set(), "ports_blocked": set()}

    try:
        with open(path, "r") as f:
            data = json.load(f)
        ips = set(data.get("ips_blocked", []))
        ports = set(data.get("ports_blocked", []))

        # Validar IPs
        valid = set()
        for ip in ips:
            try:
                ipaddress.ip_address(ip)
                valid.add(ip)
            except Exception:
                logging.warning(f"Ignorando IP inválido no arquivo: {ip}")

        lista_de_blocks["ips_blocked"] = valid
        lista_de_blocks["ports_blocked"] = ports
        logging.info(f"Lista de IPs bloqueados carregada ({len(valid)} IPs) de {path}")
        logging.info(f"Lista de portas bloqueadas carregada ({len(ports)} portas) de {path}")

    except FileNotFoundError:
        logging.info("Nenhum blocklist.json encontrado — iniciando com a lista vazia")

    except Exception as e:
        logging.exception("Erro ao carregar lista de blocks: %s", e)
    
    return lista_de_blocks

def salvar_lista_de_blocks(lista_de_blocks, path=arq):
    try:
        with open(path, "w") as f:
            json.dump({"ips_blocked": sorted(list(lista_de_blocks["ips_blocked"])),
                       "ports_blocked": sorted(list(lista_de_blocks["ports_blocked"]))}, f, indent=2)
        logging.info(f"Blocklist salva em {path}")
    
    except Exception as e:
        logging.exception("Erro ao salvar blocklist: %s", e)