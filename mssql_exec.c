#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <memory.h>

#ifndef MINGW


#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define SOCKET int
#define SOCKADDR struct sockaddr
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
#define Sleep(x) sleep(x/1000)


#else

#include <winsock2.h>


#endif

#define ENCRYPT_OFF		0x00
#define ENCRYPT_ON		0x01
#define ENCRYPT_NOT_SUP		0x02
#define ENCRYPT_REQ		0x03

#define TYPE_SQL_BATCH		1
#define TYPE_PRE_TDS7_LOGIN	2
#define TYPE_RPC		3
#define TYPE_TABLE_RESPONSE	4
#define TYPE_ATTENTION_SIGNAL	6
#define TYPE_BULK_LOAD		7
#define TYPE_TRANSACTION_MANAGER_REQUEST 14
#define TYPE_TDS7_LOGIN		16
#define TYPE_SSPI_MESSAGE	17
#define TYPE_PRE_LOGIN_MESSAGE	18

#define STATUS_NORMAL		0x00
#define STATUS_END_OF_MESSAGE	0x01
#define STATUS_IGNORE_EVENT	0x02
#define STATUS_RESETCONNECTION	0x08
#define STATUS_RESETCONNECTIONSKIPTRAN 0x10

static SOCKET sock;
static uint32_t auth = 0;

/* all big-endian */
/* header: packet has its always  */
struct p_hdr {
	uint8_t		type;
	uint8_t		status;
	uint16_t	length;
	uint16_t	spid;
	uint8_t		packetid;
	uint8_t		window;
} __attribute__ ((__packed__));

/* token: token is used in preLogin */
struct token {
	uint8_t		token;
	uint16_t	offset;
	uint16_t	length;
} __attribute__ ((__packed__));

/* authenticate is used it */
struct p_auth {
	uint32_t	dummySize;
	uint32_t	TDSVersion;
	uint32_t	size;
	uint32_t	version;
	uint32_t	PID;
	uint32_t	connectionID;
	uint8_t		flags1;
	uint8_t		flags2;
	uint8_t		sqlTypeFlags;
	uint8_t		reservedFlags;
	uint32_t	timeZone;
	uint32_t	collation;
} __attribute__ ((__packed__));

/* all big-endian */
/* as is token it is used in preLogin */
struct p_data_token {
	uint8_t		tVersion;   /* 0x00 */
	uint16_t	oVersion;  /* idx = 21 size of pkt_data_token */
	uint16_t	lVersion;  /* length of struct version... see up */

	uint8_t		tEncryption;/* 0x01 */
	uint16_t	oEncryption;
	uint16_t	lEncryption;/* 0x01 */

	uint8_t		tInstOpt;   /* 0x02 */
	uint16_t	oInstOpt;
	uint16_t	lInstOpt;

	uint8_t		tThreadid;  /* 0x03 */
	uint16_t	oThreadid;
	uint16_t	lThreadid; /* 0x04 */

	uint8_t		end; /* 0xFF */
} __attribute__ ((__packed__));

void printhex(unsigned char *buf, int size )
{
	int x, y;
	for ( x=1; x<=size; x++ )
	{
		if ( x == 1 )
			printf( "%04x ", x-1 );
		printf( "%02x ", buf[x-1] );
		if ( x % 8 == 0 )
			printf( " " );
		if ( x % 16 == 0 )
		{
			printf( " " );
			for( y = x - 15; y <= x; y++ )
			{
				if ( isprint( buf[y-1] ) )
					printf( "%c", buf[y-1] );
				else
					printf( "." );
				if ( y % 8 == 0 )
					printf( " " );
			}
			if ( x < size )
				printf( "\n%04x ", x );
		}
	}
	x--;
	if ( x % 16 != 0 )
	{
		for ( y = x+1; y <= x + (16-(x % 16)); y++ )
		{
			printf( " " );
			if( y % 8 == 0 ) printf( " " );
		};
		printf( " " );
		for ( y = (x+1) - (x % 16); y <= x; y++ )
		{
			if ( isprint( buf[y-1] ) )
				printf( "%c", buf[y-1] );
			else
				printf( "." );
			if( y % 8 == 0 )
				printf( " " );
		}
	}
	printf( "\n" );
}

/* all little-endian */
struct version {
	uint32_t	hernya1; /* 0x55010008 */
	uint16_t	hernya2; /* 0x0000 */
} __attribute__ ((__packed__));


/* stupid function is used for converting to unicode */
void toUnicode(const char *string, char *output)
{
	const char *ptr;
	char null[] = {0x00};
	int i = 0;
	for (ptr=string; *ptr; ptr++)
	{
		memcpy(&output[i*2+1], (void *)null, 1);
		memcpy(&output[i*2], (void *)ptr, 1);
		i++;
	}
}

/* From unicode is bigger stupid than toUnicode func */ 
void fromUnicode(const char *string, char *output, uint32_t len)
{
	const char *ptr = output;
	int i;

	for(i=0; i<=len; i+=2 )
	{
		output[i/2] = string[i];
	}
}

void RandStr(char *dst, uint32_t length)
{
	uint32_t i = length;
	while ( i-- > 0 )
		dst[(length-i)-1] = rand() % 255;
}


uint32_t mssqlParseRet(char *data)
{
	uint32_t ret;
	char *ptr = data;


	memcpy(&ret, ptr, 4);

	ret = ntohl(ret);

	return 4;
}

uint32_t mssqlParseDone(char *data)
{
	char *ptr = data;
	uint16_t status, cmd;
	uint32_t rows, ret=0;

	memcpy(&status, ptr, 2);
	ptr += 2;

	memcpy(&cmd, ptr, 2);
	ptr += 2;

	memcpy(&rows, ptr, 4);
	ptr += 4;

	return ptr-data;
}


uint32_t mssqlParseError(char *data)
{
	char *ptr = data;
	uint16_t len;
	char buffer[1000];
	char emsg[1000];
	char *ptremsg = emsg;
	char *p = buffer;
	uint32_t ret = 0;
	uint32_t errnoo;
	uint16_t elen;
	uint8_t state, sev;

	memcpy(&len, ptr, 2);
	ptr += 2;

	memcpy(p, ptr, len);
	ptr += len;

//	printhex(p, len);

	memcpy(&errnoo, p, 4);
	p+=4;
	memcpy(&state, p, 1);
	p+=1;
	memcpy(&sev, p, 1);
	p+=1;
	memcpy(&elen, p, 2);
	p+=2;

	fromUnicode(p, ptremsg, elen*2);
	printf("SQL Server Error #%d (State:%d Severity:%d): %s\n", errnoo, state, sev, ptremsg);

	return ptr-data;
}

uint32_t mssqlParseInfo(char *data)
{
	char *ptr = data;
	uint16_t len;
	char buffer[1000];
	char emsg[1000];
	char *ptremsg = emsg;
	char *p = buffer;
	uint32_t ret = 0;
	uint32_t errnoo;
	uint16_t elen;
	uint8_t state, sev;

	memcpy(&len, ptr, 2);
	ptr += 2;

	memcpy(p, ptr, len);
	ptr += len;

	memcpy(&errnoo, p, 4);
	p+=4;
	memcpy(&state, p, 1);
	p+=1;
	memcpy(&sev, p, 1);
	p+=1;
	memcpy(&elen, p, 2);
	p+=2;

	fromUnicode(p, ptremsg, elen);

	printf("SQL Server Info #%d (State:%d Severity:%d): %s\n", errnoo, state, sev, ptremsg);

	return ptr-data;
}

uint32_t mssqlParseEnv(char *data)
{
	char *ptr = data;
	uint32_t ret;
	uint16_t len;
	uint8_t type, nlen, olen;
	char buffer[1000];
	char *p = buffer;

	memcpy(&len, ptr, 2);
	ptr += 2;

	memcpy(p, ptr, len);
	ptr += len;

	return ptr-data;
	/* Что-то делаем с переменными окружения
	 * но зачем они нам нужны если метасплойт
	 * их никак не испольует?
	 * */
	memcpy(&type, p, 1);
	p += 1;

	memcpy(&nlen, p, 1);
	ptr += 1;
	ret += 1;

}


uint32_t mssqlParseLoginAck(char *data)
{
	auth = 1;
	uint16_t len;
	uint32_t ret=0;
	char buffer[1000];
	char *p = buffer;
	char *ptr = data;

	memcpy(&len, ptr, 2);
	ptr += 2;

	memcpy(p, ptr, len);
	ptr += len;

	return ptr-data;
}

/*
 * parse TDS Reply and Parse TDS Row dont rewrite from msf
 * they are very big and not neecessary for my situation
 */
uint32_t mssqlParseTdsReply(char *data)
{

}

uint32_t mssqlParseTdsRow(char *data)
{

}

void mssqlParseReply(char *data)
{
	struct p_hdr pHeader;
	struct token *ptrToken;
	struct token pToken;
	char *ptr = data;
	int32_t count=0, ret;
	uint16_t size;
	uint8_t token;
	char bufinfo[1000];

	memcpy(&pHeader, ptr, 8);
	ptr += 8;

	size = ntohs(pHeader.length)-8;
//	printf("Size from header = %d\n", size);
//	printhex(ptr, size+8);

	while(size)
	{
		token = *(uint8_t*)ptr;
		ptr++;
		size--;
		printf("Count = %d\n", size);

		switch(token)
		{
			case 0x81:
				printf("mssqlParseTdsReply();\n");
				Sleep(1000);
				exit(1);
				break;
			case 0xd1:
				printf("mssqlParseTdsRow();\n");
				Sleep(1000);
				exit(1);
				break;
			case 0xe3:
				printf("mssqlParseEnv()\n");
				ret = mssqlParseEnv(ptr);
				size -= ret;
				ptr += ret;
				break;
			case 0x79:
				printf("mssqlParseRet();\n");
				mssqlParseRet(ptr);
				size -= 4;
				ptr += 4;
				break;
			case 0xfd:
			case 0xfe:
			case 0xff:
				printf("mssqlParseDone();\n");
				ret = mssqlParseDone(ptr);
				size -= 8;
				ptr += 8;
				break;
			case 0xad:
				printf("mssqlParseLoginAck();\n");
				ret = mssqlParseLoginAck(ptr);
				size -= ret;
				ptr += ret;
				break;
			case 0xab:
				printf("mssqlParseInfo();\n");
				ret = mssqlParseInfo(ptr);
				size -= ret;
				ptr += ret;
				break;
			case 0xaa:
				printf("mssqlParseError();\n");
				ret = mssqlParseError(ptr);
				size -= ret;
				ptr += ret;
				break;
//			case '\0':
//				break;				
			default:
				printf("Unsupported TOKEN %x\n", pToken.token);
				break;
		}
	}
	
}

/* Function "encrypts" password */
void mssqlTDSEncrypt(const char *pass, char *output)
{
	char buff[1000];
	uint8_t c;
	char *ptrBuff = buff;
	char *ptrOutput = output;
	uint32_t len;

	len = strlen(pass);

	toUnicode(pass, ptrBuff);

	int i;
	for(i = 0; i <= len*2; i++)
	{
		c = (uint8_t)ptrBuff[i];
		ptrOutput[i] = (((c & 0x0F) << 4) + ((c & 0xF0) >> 4) ^ 0xA5);
	}
}

/* important function, if answer is bigger than 4096 or 8192 (didnt remember)
 * then crash :)
 */
int mssqlSendRecv(void *packet, uint32_t packetSize, void *recvPacket)
{
	uint32_t done = 0;

	char head[8];
	char buffer1[8192];
	void *ptr = head;
	void *ptr2 = recvPacket;

	struct p_hdr *header;
	int32_t count;
	uint16_t len;

	printf("Send packet size = %d\n", packetSize);
	printhex(packet, packetSize);
	printf("\n");

	if ((send(sock, packet, packetSize, 0))<0)
	{
		printf("Cant send data to server... die\n");
		exit(1);
	}

	while (!done)
	{
		count = recv(sock, ptr, 8, 0);
		header = ptr;
		if (count != 8)
			return 0;

		if (header->status == 0x01)
			done = 1;

		memcpy(ptr2, ptr, 8);
		ptr2 += 8;

		len = ntohs(header->length) - 8;
		ptr = buffer1;

		while(len>0)
		{
			if ((count = recv(sock, ptr, len, 0)) < 0) {
				printf("I got -1 while recv answer from server... die\n");
				exit(1);
			}
			memcpy(ptr2, ptr, count);
			len -= count;
			ptr2 += count;
		}
	}

	ptr2 = recvPacket;
	printf("Got packet size = %d\n", ntohs(header->length));
	printhex(ptr2, ntohs(header->length));
	printf("\n");

	return 1;
}

/* Sends info query before auth... */
int mssqlPreLogin()
{
	time_t t;
	srand((unsigned) time(&t));

	struct p_hdr		pHeader;
	struct p_data_token	pDataToken;
	struct version		pVer;

	char p[8+21+6+1+12+4];

	uint8_t encryption = ENCRYPT_NOT_SUP;
	char instoptdata[] = "MSSQLServer";

	uint16_t idx = 21;

	char answer[1024];
	char *answerPacket = answer;

	uint32_t threadid;
	RandStr((char *)&threadid, 4);
	threadid = threadid & 0x0000ffff;


	memset(&pHeader, '\0', sizeof(struct p_hdr));
	pHeader.type	= TYPE_PRE_LOGIN_MESSAGE;
	pHeader.status	= STATUS_END_OF_MESSAGE;
	pHeader.length	= htons(sizeof(struct p_data_token) + sizeof(struct version) + 1 + sizeof(instoptdata) + 4 + 8);

	pVer.hernya1 = 0x55010008;
	pVer.hernya2 = 0x0000;

	memset(&pDataToken, '\0', sizeof(struct p_data_token));

	pDataToken.tVersion = 0x00;
	pDataToken.oVersion = htons(idx);
	pDataToken.lVersion = htons(sizeof(struct version));

	pDataToken.tEncryption = 0x01;
	pDataToken.oEncryption = htons(idx + sizeof(struct version));
	pDataToken.lEncryption = htons(0x01);

	pDataToken.tInstOpt = 0x02;
	pDataToken.oInstOpt = htons(idx + sizeof(struct version) + 1);
	pDataToken.lInstOpt = htons(sizeof(instoptdata));

	pDataToken.tThreadid = 0x03;
	pDataToken.oThreadid = htons(idx + sizeof(struct version) + 1 + sizeof(instoptdata));
	pDataToken.lThreadid = htons(0x04);

	pDataToken.end = 0xFF;


	memset(p, '\0', sizeof(p));
	memcpy(p, &pHeader, sizeof(struct p_hdr));
	memcpy(p+8, &pDataToken, 21);
	memcpy(p+8+21, &pVer, 6);
	memcpy(p+8+21+6, &encryption, 1);
	memcpy(p+8+21+6+1, instoptdata, 12);
	memcpy(p+8+21+6+1+12, &threadid, 4);

//	printhex(p, sizeof(p));

	if (mssqlSendRecv(p, 52, answerPacket) == 0)
	{
		printf("Got NULL from mssqlSendRecv in mssqlPreLogin()\n");
		exit(1);
	}

	idx = 0;

	memcpy((void *)&pHeader, answerPacket, 8);
	int len  = ntohs(pHeader.length) - 8;

	int count = 1;
	struct token foken;
	struct token *ptrToken = (struct token *)(answerPacket+8);
	while(ptrToken->token != 0xFF && len>5)
	{
		//memcpy((void *)&foken, (void *)ptrToken, 5);
		//if (foken.token == 0x01)
		printf("Token [0x%02x][0x%04x][0x%04x]\n", ptrToken->token, ntohs(ptrToken->offset), ntohs(ptrToken->length));
		if (ptrToken->token == 0x01)
		{
			// idx = ntohs(foken.length) - (count * 5);
			idx = ntohs(ptrToken->offset);
			break;
		}
		ptrToken += 5;
		//len -= 5;
		count++;
	}

	printf("Got encryption parametr. ptrToken->token = %d, ptrToken->offset = %d\n", ptrToken->token, idx);
	if(idx > 0)
	{
		encryption = (uint8_t)answerPacket[8+idx];
	}
	else
	{
		encryption = ENCRYPT_NOT_SUP;
	}

	if(encryption != ENCRYPT_NOT_SUP) {
		printf("Encryption is not supported!\n");
		exit(1);
	}

	return	encryption;
}


/* Functions does authorizatiob is server */
int mssqlLogin(char *user, char *pass, char *db)
{
	if (mssqlPreLogin() != ENCRYPT_NOT_SUP)
		return 0;
	
	uint16_t idx = 0;

	struct p_hdr pHeader;
	struct p_auth pAuth;
	char packet[1024];
	char *p = packet;

	uint32_t lenCname = 3; /* rand() % 8 + 1; */
	char cname[18];	/* alpha random */
	toUnicode("ABC", (char *)&cname);

	uint32_t lenUname = strlen(user);
	char uname[99];	/* user */
	toUnicode(user, (char *)&uname);

	uint32_t lenPname = strlen(pass);
	char pname[99];	/* mssql_tds_encrypt(pass) */
	mssqlTDSEncrypt(pass, (char *)&pname);

	uint32_t lenAname = 3; /* rand() % 8 + 1; */
	char aname[18];	/* alpha random */
	toUnicode("HEL", (char *)&aname);

	uint32_t lenSname = sizeof("10.0.70.98");
	char sname[99];	/* rhost */
	toUnicode("10.0.70.98", (char *)&sname);

	uint32_t lenDname = strlen(db);
	char dname[99];	/* db */
	toUnicode(db, (char *)&dname);

	memset((void *)&pHeader, '\0', 8);
	pHeader.type = TYPE_TDS7_LOGIN;
	pHeader.status = STATUS_END_OF_MESSAGE;
	pHeader.packetid = 0x01;

	pAuth.dummySize		= 0x00000000;
	pAuth.TDSVersion	= 0x71000001;
	pAuth.size		= 0x00000000;
	pAuth.version		= 0x00000007;
	pAuth.PID		= rand() % 1025;
	pAuth.connectionID	= 0x00000000;
	pAuth.flags1		= 0xE0;
	pAuth.flags2		= 0x03;
	pAuth.sqlTypeFlags	= 0x00;
	pAuth.reservedFlags	= 0x00;
	pAuth.timeZone		= 0x00000000;
	pAuth.collation		= 0x00000000;

	memset(p, '\0', sizeof(packet));

	memcpy(p, &pHeader, 8);
	p += 8;
	memcpy(p, &pAuth, 36);
	p += 36;

	idx = 36+50; /* pAuth.size = 36 */

	memcpy(p, &idx, 2);
	p += 2;
	memcpy(p, &lenCname, 2);
	p += 2;
	idx += lenCname*2;

	memcpy(p, &idx, 2);
	p += 2;
	memcpy(p, &lenUname, 2);
	p += 2;
	idx += lenUname*2;

	memcpy(p, &idx, 2);
	p += 2;
	memcpy(p, &lenPname, 2);
	p += 2;
	idx += lenPname*2;
	
	memcpy(p, &idx, 2);
	p += 2;
	memcpy(p, &lenAname, 2);
	p += 2;
	idx += lenAname*2;

	memcpy(p, &idx, 2);
	p += 2;
	memcpy(p, &lenSname, 2);
	p += 2;
	idx += lenSname*2;
	
	p += 4;
	
	memcpy(p, &idx, 2);
	p += 2;
	memcpy(p, &lenAname, 2);
	p += 2;
	idx += lenAname*2;

	memcpy(p, &idx, 2);
	p += 2;
	p += 2;

	memcpy(p, &idx, 2);
	p += 2;
	memcpy(p, &lenDname, 2);
	p += 2;

	p += 2;
	p += 4;

	char somestring[] = {0x12, 0x34, 0x56, 0x78};

	memcpy(p, somestring, 4);
	char *ptrPizdecKonechno = p;
	p += 4;
	memcpy(p, somestring, 4);
	p += 4;

	memcpy(p, (char *)&cname, lenCname*2);
	p += lenCname*2;

	memcpy(p, (char *)&uname, lenUname*2);
	p += lenUname*2;

	memcpy(p, (char *)&pname, lenPname*2);
	p += lenPname*2;

	memcpy(p, (char *)&aname, lenAname*2);
	p += lenAname*2;

	memcpy(p, (char *)&sname, lenSname*2);
	p += lenSname*2;

	memcpy(p, (char *)&aname, lenAname*2);
	p += lenAname*2;

	memcpy(p, (char *)&dname, lenDname*2);
	p += lenDname*2;

	uint32_t pSize = p - packet - 8;
	p = packet;

	memcpy(ptrPizdecKonechno, &pSize, 4);
	memcpy(ptrPizdecKonechno+4, &pSize, 4);
	memcpy(p+8, &pSize, 4);
	pSize = htons(pSize+8);
	memcpy(p+2, &pSize, 2);

//	printhex(packet, ntohs(pSize));
	pSize = ntohs(pSize);
	char answer[4096];
	char *ptrAnswer = answer;
	mssqlSendRecv(p, pSize, ptrAnswer);

	memcpy((void *)&pHeader, ptrAnswer, 8);
	int len  = ntohs(pHeader.length) - 8;

	printf("Got %d bytes answer\n", len);
	mssqlParseReply(ptrAnswer);
}


/* Does query */
uint32_t mssqlQuery(char *sqla)
{
	char packet[4096];
	char sql[8192];
	char answer[4096];
	char *ptrPacket = packet;
	char *ptrSql = sql;
	char *ptrSqla = sqla;
	char *ptrAnswer = answer;
	char one[] = {0x01};
	char nil[] = {0x00};
	uint32_t lenSqla = strlen(ptrSqla);
	uint32_t lenSql = lenSqla*2;
	uint32_t bsize = 4096-8;
	uint32_t idx = 0;
	uint8_t flg;
	uint16_t chan = 0;
	uint16_t size;

	toUnicode(ptrSqla, ptrSql);

	while(idx < lenSql)
	{
		flg = lenSql < bsize ? 0x01 : 0x00;
		size = htons(lenSql+8);
		chan = htons(chan);

		memcpy(ptrPacket, one, 1);
		ptrPacket++;

		memcpy(ptrPacket, &flg, 1);
		ptrPacket++;

		memcpy(ptrPacket, &size, 2);
		ptrPacket += 2;

		memcpy(ptrPacket, &chan, 2);
		ptrPacket += 2;

		memcpy(ptrPacket, &one, 1);
		ptrPacket++;

		memcpy(ptrPacket, &nil, 1);
		ptrPacket++;

		memcpy(ptrPacket, ptrSql, lenSql);

		idx += bsize;
	}

	ptrPacket = packet;
	if (mssqlSendRecv(ptrPacket, ntohs(size), ptrAnswer) == 0)
	{
		printf("mssqlSendRecv return NULL in mssqlQuery\n");
		exit(1);
	}
	mssqlParseReply(ptrAnswer);
}

int main(int argc, const char **argv)
{
	char *user;
	char *pass;
	char *host;
	char *query;

	if (argc != 5) {
		printf("Usage: %s ip user pass query\n", argv[0]);
		exit(1);
	}

#ifdef MINGW
	WSADATA version;
	WORD mkword = MAKEWORD(2,2);
	int what = WSAStartup(mkword, &version);
	if (what != 0)
	{
		printf("[-] Bad WSAStartup!\n");
		return 0;
	}
#endif

	host = (char *)argv[1];
	user = (char *)argv[2];
	pass = (char *)argv[3];
	query = (char *)argv[4];

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET)
	{
		printf("Cant create socket\n");
		exit(1);
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(host);
	addr.sin_port = htons(1433);

	if (connect(sock, (SOCKADDR *)&addr, sizeof(SOCKADDR)) == INVALID_SOCKET) {
		closesocket(sock);
		printf("Connect error!\n");
		exit(1);
	}
	mssqlLogin(user,pass,"");
	if (auth == 1) {
		mssqlQuery(query);
	}
	Sleep(1000);

	return 0;
}

/*
 Пизженно с метасплойта:

  # Re-enable the xp_cmdshell stored procedure in 2005 and 2008
  def mssql_xpcmdshell_enable(opts={})
    "exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;"
  end

  # Re-enable the xp_cmdshell stored procedure on 2000
  def mssql_xpcmdshell_enable_2000(opts={})
    "exec sp_addextendedproc 'xp_cmdshell','xp_log70.dll';exec sp_addextendedproc 'xp_cmdshell', 'C:\\Program Files\\Microsoft SQL Server\\MSSQL\\Binn\\xplog70.dll';"
  end

  # Disable the xp_cmdshell stored procedure on 2005 and 2008
  def mssql_xpcmdshell_disable(opts={})
    "exec sp_configure 'xp_cmdshell', 0 ;RECONFIGURE;exec sp_configure 'show advanced options', 0 ;RECONFIGURE;"
  end

  # Disable the xp_cmdshell stored procedure in 2000
  def mssql_sql_xpcmdshell_disable_2000(opts={})
    "exec sp_dropextendedproc 'xp_cmdshell';"
  end

  # Rebuild xp_cmdshell if it was deleted
  def mssql_rebuild_xpcmdshell(opts={})
    "CREATE PROCEDURE xp_cmdshell(@cmd varchar(255), @Wait int = 0) AS;DECLARE @result int, @OLEResult int, @RunResult int;DECLARE @ShellID int;EXECUTE @OLEResult = sp_OACreate 'WScript.Shell', @ShellID OUT;IF @OLEResult <> 0 SELECT @result = @OLEResult;IF @OLEResult <> 0 RAISERROR ('CreateObject %0X', 14, 1, @OLEResult);EXECUTE @OLEResult = sp_OAMethod @ShellID, 'Run', Null, @cmd, 0, @Wait;IF @OLEResult <> 0 SELECT @result = @OLEResult;IF @OLEResult <> 0 RAISERROR ('Run %0X', 14, 1, @OLEResult);EXECUTE @OLEResult = sp_OADestroy @ShellID;return @result;"
  end

  # Turn on RDP
  def mssql_rdp_enable(opts={})
    "exec master..xp_cmdshell 'REG ADD 'HKLM\\SYSTEM\\CurrentControlSet\\Control\Terminal Server' /v fDenyTSConnections /t REG_DWORD /f /d 0';"
  end

  # Grab servername
  def mssql_enumerate_servername(opts={})
    "SELECT @@SERVERNAME"
  end

  # Get SQL Server Version Info
  def mssql_sql_info(opts={})
    "SELECT @@VERSION"
  end

*/
