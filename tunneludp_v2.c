/**************************************************************************
 * udptunnel_v2.c                                                         *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and UDP. Handles (badly) IPv4 for tun, ARP and IPv4 for     *
 * tap.                                                                   *
 *                                                                        *
 * idea: this program will allocate a vitual network interface card both  *
 *       working in server or client. After allocating, you need assign   *
 *       an ip address to it and let it work, just like init_*.sh does.   *
 *       After connection estanblished, there are not server and client   *
 *       any more. Both side are equal in this situation. When a packet   *
 *       is sending from A to B, it is sent to A's virtual NIC, and then  *
 *       the whole packet is captured. Next, the whole packet will be     *
 *       added a new UDP header, and send to real NIC. In B's side, the   *
 *       packet from real NIC will be sent to virtual NIC first, and then *
 *       it will be captured and decrypted. Just like diagram in the      *
 *       VPN project instruction.                                         *
 *                                                                        *
 * compile: gcc -o simpletun ../simpletun.c                               *
 *                                                                        *
 * running:                                                               *
 *   -- server:                                                           *
 *      1. sudo ./simpletun -i $(NIC name) -s (-p $(port))                *
 *      2. bash init_server.sh                                            *
 *   -- client:                                                           *
 *      1. sudo ./simpletun -i $(NIC name) -c $(server ip) (-p $(port))   *
 *      2. bash init_client.sh                                            *
 *                                                                        *
 * reference from:                                                        *
 * http://backreference.org/2010/03/26/tuntap-interface-tutorial          *
 * original program use TCP link: simpletun.c                             *
 *                                                                        *
 * -- author: Yunding Li                                                *
 * -- version                                                             *
 *  v1.0 just complete conversion from TCP version                        *
 *  v1.1 add some comments and improve code structure                     *
 *                                                                        *
 *************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>


/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 4096
#define CLIENT 0
#define SERVER 1
#define PORT 5588

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

char *progname;
char MAGIC_WORD[] = "Wazaaaaaaaaaaahhhh !";

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {
    
    struct ifreq ifr;
    int fd, err;
    
    if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
        perror("Opening /dev/net/tun");
        return fd;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    
    ifr.ifr_flags = flags;
    
    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }
    
    if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return err;
    }
    
    strcpy(dev, ifr.ifr_name);
    
    return fd;
}


/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>]\n", progname);
    fprintf(stderr, "%s -h\n", progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
    fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
    fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55566\n");
    exit(1);
}

int main(int argc, char *argv[]) {
    
    int tap_fd, option;
    int flags = IFF_TUN;
    char if_name[IFNAMSIZ] = "";
    int header_len = IP_HDR_LEN;
    int maxfd;
    uint16_t nread, nwrite, plength;
    //  uint16_t total_len, ethertype;
    char buffer[BUFSIZE];
    struct sockaddr_in server_addr, client_addr, remote_addr, read_addr;
    char server_ip[16] = "";
    unsigned short int port = PORT;
    int sock_fd, optval = 1;
    socklen_t clientlen = sizeof(client_addr);
    socklen_t serverlen = sizeof(server_addr);
    socklen_t readlen = sizeof(read_addr);
    int cliserv = -1;    /* must be specified on cmd line */
    int tap_count = 0, sock_count = 0;
    
    progname = argv[0];
    
    /* Check command line options */
    while((option = getopt(argc, argv, "i:sc:p:uahd")) > 0){
        switch(option) {
            case 'h':
                usage();
                break;
            case 'i':
                strncpy(if_name,optarg,IFNAMSIZ-1);
                break;
            case 's':
                cliserv = SERVER;
                break;
            case 'c':
                cliserv = CLIENT;
                strncpy(server_ip,optarg,15);
                break;
            case 'p':
                port = atoi(optarg);
                break;
            default:
                printf("Unknown option %c\n", option);
                usage();
        }
    }
    
    argv += optind;
    argc -= optind;
    
    if(argc > 0){
        perror("Too many options!\n");
        usage();
    }
    
    if(*if_name == '\0'){
        perror("Must specify interface name!\n");
        usage();
    }else if(cliserv < 0){
        perror("Must specify client or server mode!\n");
        usage();
    }else if((cliserv == CLIENT)&&(*server_ip == '\0')){
        perror("Must specify server address!\n");
        usage();
    }
    
    /* initialize tun/tap interface */
    if ((tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
        printf("Error connecting to tun/tap interface %s!\n", if_name);
        exit(1);
    }
    
    printf("Successfully connected to interface %s\n", if_name);
    
    // socket(PF_INET, SOCK_DGRAM, 0) is socket with UDP
    // socket(AF_INET, SOCK_STREAM, 0) is socket with TCP
    if ((sock_fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket()");
        exit(1);
    }
    
    if(cliserv==CLIENT){
        memset(&client_addr, 0, sizeof(client_addr));
        client_addr.sin_family = AF_INET;
        client_addr.sin_addr.s_addr = htonl(INADDR_ANY); // self
        client_addr.sin_port = htons(port);
        
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        inet_aton(server_ip, &server_addr.sin_addr);
        
        if (bind(sock_fd,(struct sockaddr *)&client_addr, sizeof(client_addr)) < 0){
            perror("bind");
            exit(1);
        }
        
        if (sendto(sock_fd, MAGIC_WORD, sizeof(MAGIC_WORD), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
            perror("sendto magic word");
        
        if (recvfrom(sock_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&server_addr, &serverlen) < 0)
            perror("recvfrom");
        if (strncmp(MAGIC_WORD, buffer, sizeof(MAGIC_WORD) != 0)){
            perror("Bad magic word for peer\n");
            exit(1);
        }
        
        printf("Connection with %s:%i established\n", (char *)inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port));
        
        remote_addr = server_addr;
    } else {
        /* Server, wait for connections */
        
        /* avoid EADDRINUSE error on bind() */
        // SO_REUSEADDR: allow to reuse (socket address) port number, optval=1 allow, 0 deny
        // for setsockopt() and getsockopt() function:
        // http://blog.csdn.net/lixungogogo/article/details/52563391
        if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
            perror("setsockopt");
            exit(1);
        }
        
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        server_addr.sin_port = htons(port);
        if (bind(sock_fd, (struct sockaddr*) &server_addr, sizeof(server_addr)) < 0){
            perror("bind");
            exit(1);
        }

        /* wait for connection request */
        
        // below are UDP connection
        // server side waiting for a UDP connection
        if (recvfrom(sock_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, &clientlen) < 0)
                perror("recvfrom");
        if (strncmp(MAGIC_WORD, buffer, sizeof(MAGIC_WORD)) != 0){
            perror("Bad magic word for peer\n");
            exit(1);
        }
        
        // once receive connect request, resend to check
        if (sendto(sock_fd, MAGIC_WORD, sizeof(MAGIC_WORD), 0, (struct sockaddr *)&client_addr, clientlen) < 0)
            perror("sendto");
 
        printf("SERVER: Client connected from %s\n", inet_ntoa(client_addr.sin_addr));
        remote_addr = client_addr;
    }
    
    /* use select() to handle two descriptors at once */
    maxfd = (tap_fd > sock_fd)?tap_fd:sock_fd;
    
    while(1) {
        int ret;
        fd_set rd_set;
        
        FD_ZERO(&rd_set);
        FD_SET(sock_fd, &rd_set);
        FD_SET(tap_fd, &rd_set);
        
        ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);
        
        if (ret < 0 && errno == EINTR) continue;

        if (ret < 0) {
            perror("select()");
            exit(1);
        }
        if(FD_ISSET(tap_fd, &rd_set)){
              /* data from tun/tap: just read it and write it to the network */
            if(read(tap_fd, buffer, sizeof(buffer)))
                perror("read from virtual");
            if(sendto(sock_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) < 0)
                perror("sendto network");
         
            printf("Get packet from virtual -> real NIC %d\n", tap_count++);
        }
        
        if(FD_ISSET(sock_fd, &rd_set)){
            /* data from the network: read it, and write it to the tun/tap interface.
             * We need to read the length first, and then the packet */
            if(recvfrom(sock_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&read_addr, &readlen))
                perror("read from network");
            remote_addr = read_addr;
            if(write(tap_fd, buffer, sizeof(buffer)) < 0)
                perror("write to virtual");
            
            printf("Get packet from real -> virtual NIC %d\n", sock_count++);
        }
    }
    
    return(0);
}
