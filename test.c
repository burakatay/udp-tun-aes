/**************************************************************************
 * simpletun.c                                                            *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and TCP. Handles (badly) IPv4 for tun, ARP and IPv4 for     *
 * tap. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.                     *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2009 Davide Brini.                                                 *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
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
#include <stdint.h>
#include "aes.h"

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2048   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

int debug;
char *progname;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;

  // See more code comments on: 
  // http://backreference.org/2010/03/26/tuntap-interface-tutorial/
  
  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  // Q: Should we check the size of dev?
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
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n))<0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n))<0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left))==0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){
  
  va_list argp;
  
  if(debug){
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d] [-t <protocol>] \n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  fprintf(stderr, "-t <protocol> use tcp or udp (default)");
  exit(1);
}

int main(int argc, char *argv[]) {
  
  int tap_fd, option;
  int flags = IFF_TUN;
  int protocol = SOCK_DGRAM;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  int maxfd; uint16_t nread, nwrite, plength; //  uint16_t total_len, ethertype;
  char buffer[BUFSIZE];
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";
  unsigned short int port = PORT;
  int sock_fd, net_fd, optval = 1;
  socklen_t remotelen;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;

  progname = argv[0];
  
  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:p:uahdt:")) > 0){
    switch(option) {
      case 'd':
        debug = 1;
        break;
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
        strncpy(remote_ip,optarg,15);
        break;
      case 'p':
 	port = atoi(optarg); 
	break; 
      case 'u':
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP; header_len = ETH_HDR_LEN;
        break;
      case 't':
	if (strcmp(optarg, "tcp")==0){
	  do_debug("Use TCP\n"); 
	  protocol = SOCK_STREAM;
	}
	break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0){
    my_err("Too many options!\n");
    usage();
  }

  if(*if_name == '\0'){
    my_err("Must specify interface name!\n");
    usage();
  }else if(cliserv < 0){
    my_err("Must specify client or server mode!\n");
    usage();
  }else if((cliserv == CLIENT)&&(*remote_ip == '\0')){
    my_err("Must specify server address!\n");
    usage();
  }

  /* initialize tun/tap interface */
  if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }

  do_debug("Successfully connected to interface %s\n", if_name);

  if ( (sock_fd = socket(AF_INET, protocol, 0)) < 0) {
    perror("socket()");
    exit(1);
  }

  if(cliserv==CLIENT){
    /* Client, try to connect to server */

    /* assign the destination address */
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(remote_ip);
    remote.sin_port = htons(port);

    if(protocol == SOCK_STREAM){
      /* It's a TCP, so we try to establish connection. */
      if (connect(sock_fd, (struct sockaddr*) &remote, sizeof(remote)) < 0){
	perror("connect()");
	exit(1);
      }

      do_debug("CLIENT: Connected to server %s\n", inet_ntoa(remote.sin_addr));
    }
    net_fd = sock_fd;
    
  } else {
    /* Server, wait for connections */

    /* avoid EADDRINUSE error on bind() */
    if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
      perror("setsockopt()");
      exit(1);
    }
    
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);
    if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0){
      perror("bind()");
      exit(1);
    }
    
    memset(&remote, 0, sizeof(remote));
    remotelen = sizeof(remote);
    
    if (protocol == SOCK_STREAM){
      if (listen(sock_fd, 5) < 0){
	perror("listen()");
	exit(1);
      }
 
      /* wait for connection request */
      if ((net_fd = accept(sock_fd, (struct sockaddr*)&remote, &remotelen)) < 0){
        perror("accept()");
        exit(1);
      }
      do_debug("SERVER: Client connected from %s\n", inet_ntoa(remote.sin_addr));
    }else{
		net_fd = sock_fd;
	}
  }
  
  /* use select() to handle two descriptors at once */
  maxfd = (tap_fd > net_fd)?tap_fd:net_fd;

  while(1) {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set); FD_SET(net_fd, &rd_set);

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) { perror("select()"); exit(1);
    }

    if(FD_ISSET(tap_fd, &rd_set)){
      /* data from tun/tap: just read it and write it to the network */
      
      nread = cread(tap_fd, buffer, BUFSIZE);

      tap2net++;
      do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);
  uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
  uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
 uint8_t buffer1[2048];
  uint8_t buffer2[2048];
uint8_t buffer3[2048];
char buffer4[2048];
int i=0;
for(i=0;i<2048;i++)
{
if(i<nread)
buffer1[i]= buffer[i];
else
buffer1[i]= 0x00;
}
AES128_CBC_encrypt_buffer(buffer2, buffer1, 2048, key, iv);
  
for(i=0;i<2048;i++)
{
if(i<2048)
buffer4[i]= buffer2[i];

}


      /* write length + packet */
      plength = htons(nread);
      if(protocol == SOCK_DGRAM){
      	/* UDP */
	if ((nwrite = sendto(net_fd, (char *)&plength, sizeof(plength), 0, (struct sockaddr *)&remote, sizeof(remote))) <0){
	  perror("sendto");
	} 
	if ((nwrite = sendto(net_fd, buffer4, 2048, 0, (struct sockaddr *)&remote, sizeof(remote))) <0){
	  perror("sendto");
	}
      }else{
      	/* TCP */
	nwrite = cwrite(net_fd, (char *)&plength, sizeof(plength));
        nwrite = cwrite(net_fd, buffer, nread);
      }
      do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
    }
      
    if(FD_ISSET(net_fd, &rd_set)){
      /* data from the network: read it, and write it to the tun/tap interface. 
       * We need to read the length first, and then the packet */
       
      /* Read length */ 
      if(protocol == SOCK_DGRAM){
        nread = recvfrom(net_fd, (char *)&plength, sizeof(plength), 0,  (struct sockaddr *)&remote, &remotelen);	
		do_debug("Read %d bytes from the network (UDP).\n", nread);
      }else{
	nread = read_n(net_fd, (char *)&plength, sizeof(plength));
      }
      if(nread == 0) {
	/* ctrl-c at the other end */
	break;
      }

      net2tap++;
      
      /* read packet */
      if(protocol == SOCK_DGRAM){
	nread = recvfrom(net_fd, buffer, 2048, 0, (struct sockaddr *)&remote, &remotelen);	
      }else{ 
	nread = read_n(net_fd, buffer, ntohs(plength));
      }
  uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
  uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
 uint8_t buffer1[2048];
  uint8_t buffer2[2048];
uint8_t buffer3[2048];

int i=0;
int t=2048;
for(i=0;i<2048;i++)
{
if(i<nread)
buffer1[i]= buffer[i];
else
buffer1[i]= 0x00;
}
  AES128_CBC_decrypt_buffer(buffer1+0, buffer+0,  nread, key, iv);
for(i=0;i<2048;i++)
{
if(buffer1[i]==0x00)
if(i<2048)
if(buffer1[i+1]==0x00)
t=i;

}
char buffer4[t];
 
for(i=0;i<2048;i++)
{
if(i<t)
buffer4[i]= buffer1[i];

}
      do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

      /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
      nwrite = cwrite(tap_fd, buffer4, t);
      do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    }    
  } 
  return(0);
}
