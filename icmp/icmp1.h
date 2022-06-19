#ifndef _ICMP1_H
#define _ICMP1_H





unsigned short cal_chksum(unsigned short *addr,int len);

void send_packet(int pack_num,int sockfd,int pid, char*buf,struct sockaddr_in dest_addr);

int pack(int pack_num,pid_t pid,char*buf);

void start_cmd(char *bd_ip,char*buf,int sockfd);

int randnum();

#endif /* _ICMP_H */