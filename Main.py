import subprocess

# Montre à l'utilisateur les attaques disponnibles
print("Menu des attaques :")
print("[1] Brute Force")
print("[2] DDOS")
print("[3] Phishing")
print("[4] Scan de port")
select = input("Quelle attaque voulez vous faire ? : ")

if select == "1":
    # Lance le script BruteForce.py
    subprocess.run(["python", "BruteForce.py"])
    print("Brute Force lancé")
elif select == "2":
    # Lance le script DOS.py
    subprocess.run(["python", "DOS.py"])
    print("DDOS lancé")
elif select == "3":
    # Lance le script phishing.py
    subprocess.run(["python", "Phishing/phishing.py"])
    print("Phishing lancé")
elif select == "4":
    # Lance le script SSH.py
    subprocess.run(["python", "SSH.py"])
    print("Scan de port lancé")
else:
    # Informe l'utilisateur que l'option est invalide
    print("Option invalide")