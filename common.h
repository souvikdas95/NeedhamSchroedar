#ifndef COMMON_H
#define COMMON_H

#include <time.h>       /* time_t, time (for timestamp in second) */
#include <sys/timeb.h>  /* ftime, timeb (for timestamp in millisecond) */
#include <sys/time.h>   /* gettimeofday, timeval (for timestamp in microsecond) */

#define MAX_BUFFER_SIZE		720
#define MAX_HOSTS			3
#define PLAINTEXT_KEY_SIZE	16
#define HOSTNAME_SIZE		32

// DO NOT SERIALIZE
struct host_s
{
	char hostname[HOSTNAME_SIZE * 2];
	char secretKey[PLAINTEXT_KEY_SIZE * 2];
};

// DO NOT SERIALIZE
struct session_s
{
	struct host_s *host1;
	struct host_s *host2;
	char sessionKey[PLAINTEXT_KEY_SIZE * 2];
};

struct kdc_request_s
{
	char senderHostname[HOSTNAME_SIZE * 2];
	char receiverHostname[HOSTNAME_SIZE * 2];
	long R1;
	char padding[8];
};

struct ticket_s
{
	char senderHostname[HOSTNAME_SIZE * 2];
	char sessionKey[PLAINTEXT_KEY_SIZE * 2];
};

struct kdc_reply_s
{
	long R1;
	char receiverHostname[HOSTNAME_SIZE * 2];
	char sessionKey[PLAINTEXT_KEY_SIZE * 2];
	char encryptedTicket[sizeof(struct ticket_s)];
	char padding[8];
};

void allocateRandomString(char *str, size_t size)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#'?!";
    if (size)
    {
        for (size_t n = 0; n < size; ++n)
        {
            int key = rand() % (int) (sizeof(charset) - 1);
            str[n] = charset[key];
        }
        str[size] = '\0';
    }
}

struct session_s* createSession(struct host_s *host1, struct host_s *host2)
{
	struct session_s *ret = (struct session_s *) malloc (sizeof(struct session_s));
	ret->host1 = host1;
	ret->host2 = host2;
	allocateRandomString(ret->sessionKey, PLAINTEXT_KEY_SIZE);
	return ret;
}

long long int getTimestamp_usec()
{
	struct timeval timer_usec; 
	long long int timestamp_usec; /* timestamp in microsecond */
	if (!gettimeofday(&timer_usec, NULL))
	{
		timestamp_usec = ((long long int) timer_usec.tv_sec) * 1000000ll + (long long int) timer_usec.tv_usec;
	}
	else
	{
		timestamp_usec = -1;
	}
	return timestamp_usec;
}

#endif //	COMMON_H
