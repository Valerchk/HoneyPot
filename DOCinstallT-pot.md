-- Install T-pot on MAC Os --

Step 1: Clone T-pot

    cd ~

    git clone https://github.com/telekom-security/tpotce

cd tpotce

Step 2: copy minimal composer file

    cp compose/mac_win.yml ./docker-compose.yml

Step 3: create user to enter UI

    chmod +x ./genuser.sh

    ./genuser.sh

    Create a user; save login and password and special tocken genereted for WEB_USER => []

Step 4: Change .env TPOT_OSTYPE

    In the end of .env change variable in order of your system

    TPOT_OSTYPE=mac

Step 5:

    docker compose up -d

Step 6: launch in browser

    https://localhost:64297

To stop the container:

    docker compose stop
