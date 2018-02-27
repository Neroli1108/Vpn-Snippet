# run as client
all:
	gcc -o tunneludp ../tunneludp.c
run:
	bash init_client.sh &
	sudo ./tunneludp -i tun0 -c 10.211.55.6
