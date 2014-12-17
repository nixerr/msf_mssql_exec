#include <stdio.h>
#include <winsock.h>
 
int main(int argc, char *argv[])
{
    int i, res;
    struct hostent *he;
    struct in_addr **addr_list;
	char domain[500];
	char ipaddr[500];
	FILE *fd, *wr;
 
	WSADATA version;
	WORD mkword = MAKEWORD(2,2);
	int what = WSAStartup(mkword, &version);
	if (what != 0)
	{
		printf("[-] Bad WSAStartup!\n");
		return 0;
	}
	
    if (argc != 3) {
        fprintf(stderr,"usage: %s filename towrite\n", argv[0]);
        return 1;
    }
	
	fd = fopen(argv[1], "r");
	wr = fopen(argv[2], "w+");
	if (fd == NULL || wr == NULL) {
		perror("Cant read file");
		return(-1);
	}
	
	while(fgets(domain, 500, fd)) {
		int l = strlen(domain);
		domain[l-1] = '\x00';
	    he = gethostbyname(domain);
		if (he == NULL) {
			printf("Host not found %s\n", domain);
			continue;
		}
		
		printf("Name is: %s\n", he->h_name);
		printf("    IP addresses: ");
		addr_list = (struct in_addr **)he->h_addr_list;
		for(i = 0; addr_list[i] != NULL; i++) {
			printf("%s ", inet_ntoa(*addr_list[i]));
		}
		printf("\n");
		
		SOCKET u_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (u_sock == INVALID_SOCKET)
		{
			printf("Cant create socket\n");
			continue;
		}
		
		struct sockaddr_in addr;
		addr.sin_family = AF_INET;
//		inet_aton(*addr_list[0], &addr);
		addr.sin_addr.s_addr = inet_addr(inet_ntoa(*addr_list[0]));
//		strncpy(&addr.sin_addr.s_addr,*addr_list[0], 4);
		addr.sin_port = htons(1433);
		
		res = connect(u_sock, (struct sockaddr*)&addr, sizeof(addr));
		if (res == SOCKET_ERROR) {
			closesocket(u_sock);
			continue;
		} else {
			closesocket(u_sock);
			fprintf(wr, "%s\n", inet_ntoa(*addr_list[0]));
		}
	}
 
    return 0;
}