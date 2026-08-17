#!/bin/bash
tty() {
# Pick the default TTY used to open the graphical interface or user access
read -p "Input your number of default TTY: " tty_atual

# Loop through all ttys avaibles on >> /dev/tty*
for tty in /dev/tty*
do
    # Extract the path complet to TTY 
    tty_numero=${tty#/dev/tty}

    # Disable all TTY encountered on folder
    if [[ $tty_numero != $tty_atual ]]
    then
        sudo systemctl stop getty@$tty_numero.service
        sudo systemctl disable getty@$tty_numero.service
        echo "TTY $tty_numero disabled"
    fi
done
}
tty
