Pretty much simple collect statistics agent for Linux.

collects statistics and sent it via UDP / Multicast as Json files.

Compiling:
sudo apt-get update
sudo apt-get install libssl-dev
sudo apt install -y libboost-all-dev

g++ -o https_post https_post.cpp -lboost_system -lboost_filesystem -lssl -lcrypto -lboost_thread -lpthread


Starting:

./sys_monitor_agent HOSTNAME UDP_PORT default_timeout --actions='actions - comma separated' [-p | -d]
possible actions:
cpu:SEC             - CPU monitoring     
disk:SEC[/;/data]   - disk space checking   - in this case check '/' and '/data' mountpoint
ps:SEC              - list of ALL processes 
df:SEC[/;/data]     - almost the same as 'disk'
memory:SEC          - memory usage
python:SEC          - Python processes
docker:SEC          - docker containers

example - for test print:
./sys_monitor_agent 127.0.0.1 9999 30 --actions='tcp:30,disk:30[/],ps:30,df:30[/],net:30,memory:30,python:30,docker:60' -p

example - for prod as daemon:
./sys_monitor_agent 127.0.0.1 9999 30 --actions='tcp:30,disk:30[/],ps:30,df:30[/],net:30,memory:30,python:30,docker:60' -d
