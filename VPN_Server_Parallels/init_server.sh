#bin/bash!
sleep 2
sudo ip addr add 10.0.4.1/24 dev tun0
sudo ifconfig tun0 up
sudo route add -net 10.0.5.0 netmask 255.255.255.0 dev tun0
