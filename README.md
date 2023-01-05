This work shows how to implement multiplication and division in P4.Both multiplication and division implementation contain 2 methods for verifying, respectively by `run.sh` script and by automatic verification defined in P4 data plane.



First, to compile the program, execute the command

`$SDE/p4_build.sh {program}`



If you tend to play it in Tofino Model, execute the command

`$SDE/run_tofino_model.sh -p {program}`

`$SDE/install/bin/veth_setup.sh`



And run the program

`$SDE/run_switchd.sh -p {program}`



# run.sh

After entering **bfshell** interface,  start a new CLI to execute `run.sh`, and follow the guide on it.

1. First, type in "c" to set the numbers you want.
2. Second, send a packet to the switch.
3. Third, type in "s" to get the result.



# Automatic verification

After entering **bfshell** interface, start a new CLI and keep sending packets to the switch.

1. First, run the script by `$SDE/run_bfshell.sh -b $PWD/test.py`
2. Then, you will see the statistics information.