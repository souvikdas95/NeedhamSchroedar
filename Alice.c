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

#define ID				"Alice"
#define SECRET_KEY		"1000100010001000"
#define ADDRESS			"127.0.0.1"
#define PORT			20000

#define KDC_ID			"KDC"
#define KDC_ADDRESS		"127.0.0.1"
#define KDC_PORT		10000

#define TARGET_ID		"Bob"
#define TARGET_ADDRESS	"127.0.0.1"
#define TARGET_PORT		30000

int main()
{
	int cliSocket;
	struct sockaddr_in localAddr;
	struct sockaddr_in remoteAddrKDC, remoteAddrTarget;
	socklen_t addrlen;

	addrlen = sizeof(struct sockaddr_in);

	cliSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	
	memset((char *) &localAddr, 0, sizeof(localAddr));
	localAddr.sin_family = AF_INET;
	localAddr.sin_port = htons(PORT);
	localAddr.sin_addr.s_addr = inet_addr(ADDRESS);

	bind(cliSocket, (const struct sockaddr *) &localAddr, sizeof(localAddr));

	memset((char *) &remoteAddrKDC, 0, sizeof(remoteAddrKDC));
	remoteAddrKDC.sin_family = AF_INET;
	remoteAddrKDC.sin_port = htons(KDC_PORT);
	remoteAddrKDC.sin_addr.s_addr = inet_addr(KDC_ADDRESS);
	
	memset((char *) &remoteAddrTarget, 0, sizeof(remoteAddrTarget));
	remoteAddrTarget.sin_family = AF_INET;
	remoteAddrTarget.sin_port = htons(TARGET_PORT);
	remoteAddrTarget.sin_addr.s_addr = inet_addr(TARGET_ADDRESS);

	char buffer[MAX_BUFFER_SIZE];
	char IV[PLAINTEXT_KEY_SIZE];
	int len;

	memset(IV, 'X', PLAINTEXT_KEY_SIZE);

	// Send Request to KDC
	struct kdc_request_s *request = (struct kdc_request_s *) malloc(sizeof(struct kdc_request_s));
	strcpy(request->senderHostname, ID);
	strcpy(request->receiverHostname, TARGET_ID);
	request->R1 = rand();
	printf("%lld: Sending Request to %s [%s, %s, %ld]\n", getTimestamp_usec(), KDC_ID, request->senderHostname, request->receiverHostname, request->R1);
	len = sendto(cliSocket, (void *) request, sizeof(struct kdc_request_s), 0, (const struct sockaddr*) &remoteAddrKDC, (socklen_t) addrlen);
	if(len == -1)
		goto main_END;
		
	// Receive Reply from KDC
	struct kdc_reply_s *kdcReply = (struct kdc_reply_s *) malloc (sizeof(struct kdc_reply_s));
	len = recvfrom(cliSocket, (void *) kdcReply, sizeof(struct kdc_reply_s), 0, (struct sockaddr *) &remoteAddrKDC, (socklen_t *) &addrlen);
	if (len != sizeof(struct kdc_reply_s))
		goto main_END;
	decrypt((void *) kdcReply, sizeof(struct kdc_reply_s), IV, SECRET_KEY, PLAINTEXT_KEY_SIZE);
	printf("%lld: Received Reply from %s [%ld, %s, %s, <encrypted ticket>]\n", getTimestamp_usec(), KDC_ID, kdcReply->R1, kdcReply->receiverHostname, kdcReply->sessionKey);

	// Send Encrypted Ticket to TARGET
	printf("%lld: Sending <encrypted ticket> to %s\n", getTimestamp_usec(), TARGET_ID);
	sendto(cliSocket, (void *) (kdcReply->encryptedTicket), sizeof(struct ticket_s), 0, (const struct sockaddr*) &remoteAddrTarget, (socklen_t) addrlen);
	if(len == -1)
		goto main_END;

	// Receive R2 from TARGET
	memset((void *) buffer, 0, 16);
	len = recvfrom(cliSocket, (void *) buffer, 16, 0, (struct sockaddr *) &remoteAddrTarget, (socklen_t *) &addrlen);
	if (len != 16)
		goto main_END;
	buffer[len] = '\0';
	decrypt((void *) buffer, 16, IV, kdcReply->sessionKey, strlen(kdcReply->sessionKey));
	printf("%lld: Received R2 from %s [%s]\n", getTimestamp_usec(), TARGET_ID, buffer);
	long R2 = atoi(buffer);

	// Send R2 - 1 to TARGET
	memset((void *) buffer, 0, 16);
	snprintf(buffer, 16, "%ld", R2 - 1);
	buffer[16] = '\0';
	printf("%lld: Sending R2 - 1 to %s [%s]\n", getTimestamp_usec(), TARGET_ID, buffer);
	encrypt((void *) buffer, 16, IV, kdcReply->sessionKey, strlen(kdcReply->sessionKey));
	len = sendto(cliSocket, (void *) buffer, 16, 0, (const struct sockaddr*) &remoteAddrTarget, (socklen_t) addrlen);
	if(len == -1)
		goto main_END;
	
main_END:
	close(cliSocket);
	return 0;
}