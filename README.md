# router

## Description:
One-to-one mapping of ip in multi-dial environment


## Usages:
1. echo 1 > /proc/sys/net/ipv4/ip_forward
2. echo 1 > /proc/sys/net/ipv4/conf/all/forwarding
3. run rt_tables.sh to create route table. e.g.:
    
   create 20 tables: sh rt_tables.sh 20
4. put scripts 01ipmap-up and 01ipmap-down to /etc/ppp/ip-up.d/ and /etc/ppp/ip-down directory.
5. run macvlan.py to create macvlan interface:
    
    a. --ip: the first ip address of lan interface
   
    b. --num: the number of machines in the lan
   
    c. --name: the prefix of the macvlan's name, the script will add seq automatic.
   
    d. --eth: the parent interface of macvlan
   
6. config the pppoe
7. config the dhcp server, the lan ip range in dhcpserver's configuration must be same with the 
   configuration of macvlan.py.


