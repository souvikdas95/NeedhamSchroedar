#include <stdio.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

#include "aes.h"
#include "common.h"

#define ID			"KDC"
#define ADDRESS		"127.0.0.1"
#define PORT		10000

struct host_s gHost[MAX_HOSTS];

struct host_s* getHost(const char *hostname)
{
	int i = 0;
	for (i = 0; i < MAX_HOSTS; ++i)
	{
		if (!strcmp(gHost[i].hostname, hostname))
		{
			return &gHost[i];
		}
	}
	return NULL;
}

int main()
{
	int servSocket;
	struct sockaddr_in remoteAddr;
	struct sockaddr_in localAddr;
	socklen_t addrlen;

	addrlen = sizeof(remoteAddr);

	servSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	
	bzero(&localAddr, sizeof(localAddr));
	localAddr.sin_family = AF_INET;
	localAddr.sin_port = htons(PORT);
	localAddr.sin_addr.s_addr = inet_addr(ADDRESS);

	bind(servSocket, (const struct sockaddr *) &localAddr, sizeof(localAddr));
	
	char buffer[MAX_BUFFER_SIZE];
	char IV[PLAINTEXT_KEY_SIZE];
	int len;

	memset(IV, 'X', PLAINTEXT_KEY_SIZE);

	strcpy(gHost[0].hostname, "Alice");
	strcpy(gHost[0].secretKey, "1000100010001000");
	strcpy(gHost[1].hostname, "Bob");
	strcpy(gHost[1].secretKey, "1200120012001200");
	strcpy(gHost[2].hostname, "Eve");
	strcpy(gHost[2].secretKey, "1230123012301230");

	while(1)
	{
		struct kdc_request_s *request = (struct kdc_request_s *) malloc(sizeof(struct kdc_request_s));
		len = recvfrom(servSocket, (void *) request, sizeof(struct kdc_request_s), 0, (struct sockaddr *) &remoteAddr, (socklen_t *) &addrlen);
		if(len != sizeof(struct kdc_request_s))
			break;
		printf("%lld: Received Request from %s [%s %s %ld]\n", getTimestamp_usec(), request->senderHostname, request->senderHostname, request->receiverHostname, request->R1);

		struct kdc_reply_s *reply = (struct kdc_reply_s *) malloc (sizeof(struct kdc_reply_s));
		reply->R1 = request->R1;
		strcpy(reply->receiverHostname, request->receiverHostname);

		struct host_s *senderHost = getHost(request->senderHostname);
		struct host_s *receiverHost = getHost(request->receiverHostname);

		struct session_s *session = createSession(senderHost, receiverHost);
		strcpy(reply->sessionKey, session->sessionKey);
		printf("%lld: Created Session Key [%s]\n", getTimestamp_usec(), session->sessionKey);

		struct ticket_s *ticket = (struct ticket_s *) malloc (sizeof(struct ticket_s));
		strcpy(ticket->senderHostname, request->senderHostname);
		strcpy(ticket->sessionKey, session->sessionKey);
		printf("%lld: Created Ticket for %s [%s, %s]\n", getTimestamp_usec(), request->receiverHostname, ticket->senderHostname, ticket->sessionKey);

		memcpy((void *) (reply->encryptedTicket), ticket, sizeof(struct ticket_s));
		encrypt((void *) (reply->encryptedTicket), sizeof(struct ticket_s), IV, receiverHost->secretKey, strlen(receiverHost->secretKey));
		
		printf("%lld: Sending Reply to %s [%ld, %s, %s, <encrypted ticket>]\n", getTimestamp_usec(), request->senderHostname, reply->R1, reply->receiverHostname, reply->sessionKey);
		encrypt((void *) reply, sizeof(struct kdc_reply_s), IV, senderHost->secretKey, strlen(senderHost->secretKey));
		len = sendto(servSocket, (void *) reply, sizeof(struct kdc_reply_s), 0, (const struct sockaddr*) &remoteAddr, (socklen_t) addrlen);
		if(len == -1)
			break;
	}
	
	close(servSocket);
	return 0;
}