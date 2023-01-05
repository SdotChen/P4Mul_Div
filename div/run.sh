#!/bin/bash

menu(){
    echo "################################################################"
    echo "|                 Welcome to P4Divider                         |"
    echo "|                                                              |"
    echo "|        (c)      Change dividend and divisor                  |"
    echo "|        (t)      Transmit a packet(Tofino model only)         |"
    echo "|        (s)      Show the result                              |"
    echo "|        (m)      Show Menu                                    |"
    echo "|        (q)      Quit Menu                                    |"
    echo "|                                                              |"
    echo "################################################################"
}

menu
while :
do
    read -p "Please input your choice:" choice
    case "$choice" in
    c)
        $SDE/run_bfshell.sh -i -b $PWD/mod.py
        menu
        ;;
    t)
        python $PWD/send.py
        menu
        ;;
    s)
        $SDE/run_bfshell.sh -b $PWD/get.py
        menu
        ;;
    q)
        break
        ;;
    m)
        menu
        ;;
    "")
        ;;
    *)
        echo "Invalid input, please input your choice again"
    esac
done
