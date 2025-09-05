-- Install T-pot on Windows --

Prerequisites : 
  - Install Docker desktop : ```http://docs.docker.com/desktop/install/windows-install```
  - Enable the command : ``` Set-ExecutionPolicy RemoteSigned -Scope CurrentUser ```

Step 1: Clone T-pot
```
git clone https://github.com/telekom-security/tpotce
```

Step 2: Go into the case tpotce
```
cd ~/tpotce
```

Step 3: copy minimal composer file
```
cp compose/mac_win.yml ./docker-compose.yml
```

Step 4: create user to enter UI
```
 ~/tpotce/genuserwin.ps1
```
```
Create a user; save login and password and special tocken genereted for WEB_USER => []
```

Step 5: Change .env TPOT_OSTYPE
```
In the end of .env change variable in order of your system

TPOT_OSTYPE=win
```

Step 6: Launch the server, he can take a few minutes
```
docker compose up -d
```

Step 7: Connect in browser
```
https://localhost:64297
```

To stop the container:
```
docker compose stop
```
