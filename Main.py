import subprocess

print("Menu des attaques :")
print("[1] Brute Force")
print("[2] DDOS")
print("[3] Phishing")
print("[4] Scan de port")
select = input("Quelle attaque voulez vous faire ? : ")

if select == "1":
    subprocess.run(["python", "SSH.py"])
    print("Brute Force lancé")
elif select == "2":
    subprocess.run(["python", "DOS.py"])
    print("DDOS lancé")
elif select == "3":
    subprocess.run(["python", "Phishing/phishing.py"])
    print("Phishing lancé")
elif select == "4":
    subprocess.run(["python", "SSH.py"])
    print("Scan de port lancé")
else:
    print("Option invalide")