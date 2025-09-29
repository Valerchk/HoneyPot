import subprocess, sys

def ScanSSH():

    ip = input("Quelle est l'ip cible ? : ")

    Scan = input("Quel type de scan voulez vous faire ? [1] Scan complet [2] Scan rapide : ")
    if Scan == "1":
        commande = "nmap -p- -Pn -sS -vv " + ip
    elif Scan == "2":
        commande = "nmap --top-ports 100 -sT -Pn " + ip
    else:
        print("Option invalide")
        return

    print("Scan des ports en cours, veuillez patienter...")
    resultat = subprocess.run(
        ["powershell", "-Command", commande],
        capture_output=True,
        text=True
    )
    print(resultat.stdout)
    result = resultat.stdout
    search = "22/tcpopenssh"
    if search in result.replace(" ", ""):
        print("Le port ssh est open")
        finish = False
        while not finish:
            user = input("Donnez un nom d'utilisateur : ")
            commande = "ssh " + user + "@" + ip
            resultat = subprocess.run(
                ["powershell", "-Command", commande],
                capture_output=True,
                text=True
            )
            print(resultat.stdout)
            result = resultat.stdout
            search = "Last login"
            if search in result:
                print("connecté")
                finish = True
            else:
                print("connection échoué")
                fin = input("Voulez vous continuer ? [y/n] : ")
                if fin == "n":
                    finish = True


    else:
        print("Le port ssh est fermé")


if __name__ == "__main__":
    ScanSSH()