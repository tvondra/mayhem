#include <stdlib.h>
#include <sys/socket.h>
#include <dlfcn.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <unistd.h>

#define	TYPE_DISK		0x01
#define	TYPE_NETWORK	0x02
#define TYPE_KERNEL		0x04

#define MAX_DELAY_DISK		 10000000L
#define MAX_DELAY_NETWORK	100000000L
#define MAX_DELAY_KERNEL	  1000000L

#define THRESHOLD_NETWORK	2048L
#define THRESHOLD_DISK		8192L

static long delay_disk = 0;
static long delay_network = 0;
static long delay_kernel = 0;
static long delay_pid = 0;
static long delay_calls = 0;

static size_t	disk_bytes = 0;
static size_t	network_bytes = 0;

static void
refresh_delays(void)
{
	delay_calls--;

	if ((delay_pid == getpid()) && (delay_calls >= 0))
		return;

	delay_calls = random() % 100000;
	delay_pid = getpid();

	srand48(delay_pid);

	delay_disk = random() % MAX_DELAY_DISK;
	delay_network = random() % MAX_DELAY_NETWORK;
	delay_kernel = random() % MAX_DELAY_KERNEL;
}


static void
generate_delay(int type)
{
	struct timespec ts;

	ts.tv_sec = 0;
	ts.tv_nsec = 0;

	refresh_delays();

	switch (type)
	{
		case TYPE_DISK:
			ts.tv_sec = 0;
			ts.tv_nsec = delay_disk * pow(drand48(), 2);
			break;

		case TYPE_NETWORK:
						ts.tv_sec = 0;
						ts.tv_nsec = delay_network * pow(drand48(), 2);
						break;

		case TYPE_KERNEL:
			ts.tv_sec = 0;
			ts.tv_nsec = delay_kernel * pow(drand48(), 2);

		default:	/* unknown */
			return;
	}

	nanosleep(&ts, NULL);
}

ssize_t
send(int sockfd, const void *buf, size_t len, int flags)
{
	ssize_t	ret;
	static size_t (*send_func)(int, const void *, size_t, int) = NULL;

	network_bytes += len;

	if (!send_func)
		send_func = (size_t(*)(int, const void *, size_t, int)) dlsym(RTLD_NEXT, "send");

	if (network_bytes >= THRESHOLD_NETWORK)
		generate_delay(TYPE_NETWORK);

	ret = send_func(sockfd, buf, len, flags);

	if (network_bytes >= THRESHOLD_NETWORK)
	{
		generate_delay(TYPE_NETWORK);
		network_bytes = 0;
	}

	return ret;
}

ssize_t
sendto(int sockfd, const void *buf, size_t len, int flags,
	   const struct sockaddr *dest_addr, socklen_t addrlen)
{
	ssize_t	ret;
	static size_t (*sendto_func)(int, const void *, size_t, int, const struct sockaddr *, socklen_t) = NULL;

	network_bytes += len;

	if (!sendto_func)
			sendto_func = (size_t(*)(int, const void *, size_t, int, const struct sockaddr *, socklen_t)) dlsym(RTLD_NEXT, "sendto");

	if (network_bytes >= THRESHOLD_NETWORK)
		generate_delay(TYPE_NETWORK);

	ret = sendto_func(sockfd, buf, len, flags, dest_addr, addrlen);

	if (network_bytes >= THRESHOLD_NETWORK)
	{
		generate_delay(TYPE_NETWORK);
		network_bytes = 0;
	}

	return ret;
}

ssize_t
sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
	ssize_t	ret;
	static size_t (*sendmsg_func)(int, const struct msghdr *, int) = NULL;

	for (int i = 0; i < msg->msg_iovlen; i++)
		network_bytes += msg->msg_iov[i].iov_len;

	if (!sendmsg_func)
		sendmsg_func = (size_t(*)(int, const struct msghdr *, int)) dlsym(RTLD_NEXT, "send");

	if (network_bytes >= THRESHOLD_NETWORK)
		generate_delay(TYPE_NETWORK);

	ret = sendmsg_func(sockfd, msg, flags);

	if (network_bytes >= THRESHOLD_NETWORK)
	{
		generate_delay(TYPE_NETWORK);
		network_bytes = 0;
	}

	return ret;
}

off_t
lseek(int fd, off_t offset, int whence)
{
	off_t	ret;
	static size_t (*lseek_func)(int, off_t, int) = NULL;

	/* arbitrary length */
	disk_bytes += 1024L;

	if (!lseek_func)
		lseek_func = (size_t(*)(int, off_t, int)) dlsym(RTLD_NEXT, "lseek");

	if (disk_bytes >= THRESHOLD_DISK)
		generate_delay(TYPE_DISK);

	ret = lseek_func(fd, offset, whence);

	if (disk_bytes >= THRESHOLD_DISK)
	{
		generate_delay(TYPE_DISK);
		disk_bytes = 0;
	}

	return ret;
}

ssize_t
pread(int fd, void *buf, size_t count, off_t offset)
{
	ssize_t	ret;
	static size_t (*pread_func)(int, void *, size_t, off_t) = NULL;

		if (!pread_func)
				pread_func = (size_t(*)(int, void *, size_t, off_t)) dlsym(RTLD_NEXT, "pread");

	if (disk_bytes >= THRESHOLD_DISK)
		generate_delay(TYPE_DISK);

	ret = pread_func(fd, buf, count, offset);
	disk_bytes += (ret > 0) ? ret : 0;

	if (disk_bytes >= THRESHOLD_DISK)
	{
		generate_delay(TYPE_DISK);
		disk_bytes = 0;
	}

return ret;
}

ssize_t
pwrite(int fd, const void *buf, size_t count, off_t offset)
{
	ssize_t	ret;
	static size_t (*pwrite_func)(int, const void *, size_t, off_t) = NULL;

	disk_bytes += count;

	if (!pwrite_func)
		pwrite_func = (size_t(*)(int, const void *, size_t, off_t)) dlsym(RTLD_NEXT, "pwrite");

	if (disk_bytes >= THRESHOLD_DISK)
		generate_delay(TYPE_DISK);

	ret = pwrite_func(fd, buf, count, offset);

	if (disk_bytes >= THRESHOLD_DISK)
	{
		generate_delay(TYPE_DISK);
		disk_bytes = 0;
	}

	return ret;
}

ssize_t
recv(int sockfd, void *buf, size_t len, int flags)
{
	ssize_t	ret;
	static size_t (*recv_func)(int, void *, size_t, int) = NULL;

	if (!recv_func)
		recv_func = (size_t(*)(int, void *, size_t, int)) dlsym(RTLD_NEXT, "recv");

	if (network_bytes > THRESHOLD_NETWORK)
		generate_delay(TYPE_NETWORK);

	ret = recv_func(sockfd, buf, len, flags);
	network_bytes += (ret > 0) ? ret : 0;

	if (network_bytes >= THRESHOLD_NETWORK)
	{
		generate_delay(TYPE_NETWORK);
		network_bytes = 0;
	}

	return ret;
}

ssize_t
recvfrom(int sockfd, void * restrict buf, size_t len,
		 int flags,
		 struct sockaddr * restrict src_addr,
		 socklen_t * restrict addrlen)
{
	ssize_t	ret;
	static size_t (*recvfrom_func)(int, void * restrict, size_t, int, struct sockaddr * restrict, socklen_t * restrict) = NULL;

	if (!recvfrom_func)
		recvfrom_func = (size_t(*)(int, void * restrict, size_t, int, struct sockaddr * restrict, socklen_t * restrict)) dlsym(RTLD_NEXT, "recvfrom");

	if (network_bytes >= THRESHOLD_NETWORK)
		generate_delay(TYPE_NETWORK);

	ret = recvfrom_func(sockfd, buf, len, flags, src_addr, addrlen);
	network_bytes += (ret > 0) ? ret : 0;

	if (network_bytes >= THRESHOLD_NETWORK)
	{
		generate_delay(TYPE_NETWORK);
		network_bytes = 0;
	}

	return ret;
}

ssize_t
recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	ssize_t	ret;
	static size_t (*recvmsg_func)(int, struct msghdr *, int) = NULL;

	if (!recvmsg_func)
		recvmsg_func = (size_t(*)(int, struct msghdr *, int)) dlsym(RTLD_NEXT, "recvmsg");

	if (network_bytes >= THRESHOLD_NETWORK)
		generate_delay(TYPE_NETWORK);

	ret = recvmsg_func(sockfd, msg, flags);
	network_bytes += (ret > 0) ? ret : 0;

	if (network_bytes >= THRESHOLD_NETWORK)
	{
		generate_delay(TYPE_NETWORK);
		network_bytes = 0;
	}

	return ret;
}

pid_t
fork(void)
{
	pid_t	ret;
	static pid_t (*fork_func)(void) = NULL;

	if (!fork_func)
		fork_func = (pid_t(*)(void)) dlsym(RTLD_NEXT, "fork");

	generate_delay(TYPE_KERNEL);

	ret = fork_func();

	generate_delay(TYPE_KERNEL);

	return ret;
}
