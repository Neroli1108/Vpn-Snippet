#run as server
all:
	gcc -o tunneludp ../tunneludp.c
run:
	bash init_server.sh &
	sudo ./tunneludp -i tun0 -s 