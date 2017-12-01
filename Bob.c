#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "aes.h"
#include "common.h"

#define ID			"Bob"
#define SECRET_KEY	"1200120012001200"
#define ADDRESS		"127.0.0.1"
#define PORT		30000

int main()
{
	int cliSocket;
	struct sockaddr_in localAddr;
	struct sockaddr_in remoteAddrSource;
	socklen_t addrlen;

	addrlen = sizeof(struct sockaddr_in);

	cliSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	
	memset((char *) &localAddr, 0, sizeof(localAddr));
	localAddr.sin_family = AF_INET;
	localAddr.sin_port = htons(PORT);
	localAddr.sin_addr.s_addr = inet_addr(ADDRESS);

	bind(cliSocket, (const struct sockaddr *) &localAddr, sizeof(localAddr));

	char buffer[MAX_BUFFER_SIZE];
	char IV[PLAINTEXT_KEY_SIZE];
	int len;

	memset(IV, 'X', PLAINTEXT_KEY_SIZE);

	// Receive Request from Source
	struct ticket_s *ticket = (struct ticket_s *) malloc(sizeof(struct ticket_s));
	len = recvfrom(cliSocket, (void *) ticket, sizeof(struct ticket_s), 0, (struct sockaddr *) &remoteAddrSource, (socklen_t *) &addrlen);
	if (len != sizeof(struct ticket_s))
		goto main_END;	
	decrypt((void *) ticket, sizeof(struct ticket_s), IV, SECRET_KEY, PLAINTEXT_KEY_SIZE);
	printf("%lld: Received <encrypted ticket> from %s [%s, %s]\n", getTimestamp_usec(), ticket->senderHostname, ticket->senderHostname, ticket->sessionKey);

	// Send R2 to Source
	long R2 = rand();
	memset((void *) buffer, 0, 16);
	snprintf(buffer, 16, "%ld", R2);
	buffer[16] = '\0';
	printf("%lld: Sending R2 to %s [%s]\n", getTimestamp_usec(), ticket->senderHostname, buffer);
	encrypt((void *) buffer, 16, IV, ticket->sessionKey, PLAINTEXT_KEY_SIZE);
	len = sendto(cliSocket, (void *) buffer, 16, 0, (const struct sockaddr*) &remoteAddrSource, (socklen_t) addrlen);
	if(len == -1)
		goto main_END;
		
	// Receive R2 - 1 from Source
	memset((void *) buffer, 0, 16);
	len = recvfrom(cliSocket, (void *) buffer, 16, 0, (struct sockaddr *) &remoteAddrSource, (socklen_t *) &addrlen);
	if (len != 16)
		goto main_END;
	buffer[len] = '\0';
	decrypt((void *) buffer, 16, IV, ticket->sessionKey, PLAINTEXT_KEY_SIZE);
	printf("%lld: Received R2 - 1 from %s [%s]\n", getTimestamp_usec(), ticket->senderHostname, buffer);
	if (atoi(buffer) != R2 - 1)
		printf("FAIL!\n");
	else
		printf("SUCCESS\n");
	
main_END:
	close(cliSocket);
	return 0;
}