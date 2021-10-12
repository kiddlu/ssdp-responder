/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Define to 1 if you have the `util' library (-lutil). */
/* #undef HAVE_LIBUTIL */

/* Define to 1 if you have the `pidfile' function. */
/* #undef HAVE_PIDFILE */

/* Define to 1 if you have the `strlcpy' function. */
/* #undef HAVE_STRLCPY */

/* Define to 1 if you have the `utimensat' function. */
#define HAVE_UTIMENSAT 1

/* Manufacturer in XML */
#define MANUFACTURER "Troglobit Software Systems"

/* Manufacturer URL in XML */
#define MANUFACTURER_URL ""

/* Model name in XML */
#define MODEL "Generic"

/* Name of package */
#define PACKAGE "ssdp-responder"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "https://github.com/troglobit/ssdp-responder/issues"

/* Define to the full name of this package. */
#define PACKAGE_NAME "ssdpd"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "ssdpd 1.8"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "ssdp-responder"

/* Define to the home page for this package. */
#define PACKAGE_URL "https://github.com/troglobit/ssdp-responder"

/* Define to the version of this package. */
#define PACKAGE_VERSION "1.8"

/* Loopback test mode */
/* #undef TEST_MODE */

/* Version number of package */
#define VERSION "1.8"



//ssdpd.c
/* SSDP responder
 *
 * Copyright (c) 2017-2021  Joachim Wiberg <troglobit@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.a
 */

#include <sys/utsname.h>	/* uname() for !__linux__ */
#include "ssdpd.h"



char  server_string[64] = "POSIX UPnP/1.0 " PACKAGE_NAME "/" PACKAGE_VERSION;
char  hostname[64];
char *ver = NULL;
char *os  = NULL;
char  uuid[42];

static char *supported_types[] = {
	SSDP_ST_ALL,
	"upnp:rootdevice",
	"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
	uuid,
	NULL
};

volatile sig_atomic_t running = 1;

extern void web_init(void);


static void compose_addr(struct sockaddr_in *sin, char *group, int port)
{
	memset(sin, 0, sizeof(*sin));
	sin->sin_family      = AF_INET;
	sin->sin_port        = htons(port);
	sin->sin_addr.s_addr = inet_addr(group);
}

static void compose_response(char *type, char *host, char *buf, size_t len)
{
	char usn[256];
	char date[42];
	time_t now;

	/* RFC1123 date, as specified in RFC2616 */
	now = time(NULL);
	strftime(date, sizeof(date), "%a, %d %b %Y %T %Z", gmtime(&now));

	if (type) {
		if (!strcmp(type, uuid))
			type = NULL;
		else
			snprintf(usn, sizeof(usn), "%s::%s", uuid, type);
	}

	if (!type)
		strlcpy(usn, uuid, sizeof(usn));

	snprintf(buf, len, "HTTP/1.1 200 OK\r\n"
		 "Server: %s\r\n"
		 "Date: %s\r\n"
		 "Location: http://%s:%d%s\r\n"
		 "ST: %s\r\n"
		 "EXT: \r\n"
		 "USN: %s\r\n"
		 "Cache-Control: max-age=%d\r\n"
		 "\r\n",
		 server_string,
		 date,
		 host, LOCATION_PORT, LOCATION_DESC,
		 type,
		 usn,
		 CACHE_TIMEOUT);
}

static void compose_notify(char *type, char *host, char *buf, size_t len)
{
	char usn[256];

	if (type) {
		if (!strcmp(type, SSDP_ST_ALL))
			type = NULL;
		else
			snprintf(usn, sizeof(usn), "%s::%s", uuid, type);
	}

	if (!type) {
		type = usn;
		strlcpy(usn, uuid, sizeof(usn));
	}

	snprintf(buf, len, "NOTIFY * HTTP/1.1\r\n"
		 "Host: %s:%d\r\n"
		 "Server: %s\r\n"
		 "Location: http://%s:%d%s\r\n"
		 "NT: %s\r\n"
		 "NTS: ssdp:alive\r\n"
		 "USN: %s\r\n"
		 "Cache-Control: max-age=%d\r\n"
		 "\r\n",
		 MC_SSDP_GROUP, MC_SSDP_PORT,
		 server_string,
		 host, LOCATION_PORT, LOCATION_DESC,
		 type,
		 usn,
		 CACHE_TIMEOUT);
}

size_t pktlen(unsigned char *buf)
{
	size_t hdr = sizeof(struct udphdr);

	return strlen((char *)buf + hdr) + hdr;
}

static void send_message(struct ifsock *ifs, char *type, struct sockaddr *sa, socklen_t salen)
{
	struct sockaddr_in dest;
	char host[NI_MAXHOST];
	char buf[MAX_PKT_SIZE];
	size_t note = 0;
	ssize_t num;
	int s;

	if (ifs->addr.sin_addr.s_addr == htonl(INADDR_ANY))
		return;

	gethostname(hostname, sizeof(hostname));
	s = getnameinfo((struct sockaddr *)&ifs->addr, sizeof(struct sockaddr_in), host, sizeof(host), NULL, 0, NI_NUMERICHOST);
	if (s) {
		logit(LOG_WARNING, "Failed getnameinfo(): %s", gai_strerror(s));
		return;
	}

	if (ifs->addr.sin_addr.s_addr == htonl(INADDR_ANY))
		return;

	if (!strcmp(type, SSDP_ST_ALL))
		type = NULL;

	memset(buf, 0, sizeof(buf));
	if (sa)
		compose_response(type, host, buf, sizeof(buf));
	else
		compose_notify(type, host, buf, sizeof(buf));

	if (!sa) {
		note = 1;
		compose_addr(&dest, MC_SSDP_GROUP, MC_SSDP_PORT);
		sa = (struct sockaddr *)&dest;
		salen = sizeof(struct sockaddr_in);
	}

	logit(LOG_DEBUG, "Sending %s from %s ...", !note ? "reply" : "notify", host);
	num = sendto(ifs->sd, buf, strlen(buf), 0, sa, salen);
	if (num < 0)
		logit(LOG_WARNING, "Failed sending SSDP %s, type: %s: %s", !note ? "reply" : "notify", type, strerror(errno));
}

static void ssdp_recv(int sd)
{
	char buf[MAX_PKT_SIZE + 1];
	struct sockaddr sa;
	socklen_t salen;
	ssize_t len;

	memset(buf, 0, sizeof(buf));
	salen = sizeof(sa);
	len = recvfrom(sd, buf, sizeof(buf) - 1, MSG_DONTWAIT, &sa, &salen);
	if (len > 0) {
		buf[len] = 0;

		if (sa.sa_family != AF_INET)
			return;

		if (strstr(buf, "M-SEARCH *")) {
			struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
			struct ifsock *ifs;
			char *ptr, *type;
			size_t i;

			ifs = ssdp_find(&sa);
			if (!ifs) {
				logit(LOG_DEBUG, "No matching socket for client %s", inet_ntoa(sin->sin_addr));
				return;
			}
			logit(LOG_DEBUG, "Matching socket for client %s", inet_ntoa(sin->sin_addr));

			type = strcasestr(buf, "\r\nST:");
			if (!type) {
				logit(LOG_DEBUG, "No Search Type (ST:) found in M-SEARCH *, assuming " SSDP_ST_ALL);
				type = SSDP_ST_ALL;
				send_message(ifs, type, &sa, salen);
				return;
			}

			type = strchr(type, ':');
			if (!type)
				return;
			type++;
			while (isspace(*type))
				type++;

			ptr = strstr(type, "\r\n");
			if (!ptr)
				return;
			*ptr = 0;

			for (i = 0; supported_types[i]; i++) {
				if (!strcmp(supported_types[i], type)) {
					logit(LOG_DEBUG, "M-SEARCH * ST: %s from %s port %d", type,
					      inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
					send_message(ifs, type, &sa, salen);
					return;
				}
			}

			logit(LOG_DEBUG, "M-SEARCH * for unsupported ST: %s from %s", type,
			      inet_ntoa(sin->sin_addr));
		}
	}
}

static void wait_message(time_t tmo)
{
	while (1) {
		int timeout;

		timeout = tmo - time(NULL);
		if (timeout < 0)
			break;

		if (ssdp_poll(timeout * 1000) == -1) {
			if (errno == EINTR)
				break;

			err(1, "Unrecoverable error");
		}
	}
}

static void announce(struct ifsock *ifs, int mod)
{
	if (mod && !ifs->mod)
		return;
	ifs->mod = 0;

	for (size_t i = 0; supported_types[i]; i++) {
		/* UUID sent in SSDP_ST_ALL, first announce */
		if (!strcmp(supported_types[i], uuid))
			continue;

		send_message(ifs, supported_types[i], NULL, 0);
	}
}

static char *strip_quotes(char *str)
{
	char *ptr;

	if (!str)
		return NULL;
	while (*str && isspace(*str))
		str++;
	if (*str == '"')
		str++;

	ptr = str;
	while (*ptr && !isspace(*ptr) && *ptr != '"')
		ptr++;
	*ptr = 0;

	return str;
}

static int os_init(void)
{
	const char *file = "/etc/os-release";
	char line[80];
	FILE *fp;

	fp = fopen(file, "r");
	if (!fp)
		return 1;

	while (fgets(line, sizeof(line), fp)) {
		char *ptr;

		line[strlen(line) - 1] = 0;

		if (!strncmp(line, "NAME", 4) && (ptr = strchr(line, '='))) {
			logit(LOG_DEBUG, "Found NAME:%s", ptr + 1);
			if (os)
				free(os);
			os = strdup(strip_quotes(++ptr));
		}

		if (!strncmp(line, "VERSION_ID", 10) && (ptr = strchr(line, '='))) {
			logit(LOG_DEBUG, "Found VERSION_ID:%s", ptr + 1);
			if (ver)
				free(ver);
			ver = strdup(strip_quotes(++ptr));
		}
	}

	logit(LOG_DEBUG, "Found os:%s ver:%s", os, ver);
	fclose(fp);

	return 0;
}

static void lsb_init(void)
{
	const char *file = "/etc/lsb-release";
	int severity = LOG_INFO;
	char line[80];
	char *ptr;
	FILE *fp;

	if (!os_init())
		goto fallback;

	fp = fopen(file, "r");
	if (!fp) {
#ifndef __linux__
		struct utsname uts;

		if (!uname(&uts)) {
			os  = strdup(uts.sysname);
			ver = strdup(uts.release);
		}
#endif
		goto fallback;
	}

	while (fgets(line, sizeof(line), fp)) {
		line[strlen(line) - 1] = 0;

		ptr = strstr(line, "DISTRIB_ID");
		if (ptr && (ptr = strchr(ptr, '='))) {
			if (os)
				free(os);
			os = strdup(++ptr);
		}

		ptr = strstr(line, "DISTRIB_RELEASE");
		if (ptr && (ptr = strchr(ptr, '='))) {
			if (ver)
				free(ver);
			ver = strdup(++ptr);
		}
	}
	fclose(fp);

fallback:
	if (os && ver)
		snprintf(server_string, sizeof(server_string), "%s/%s UPnP/1.0 %s/%s",
			 os, ver, PACKAGE_NAME, PACKAGE_VERSION);
	else {
		logit(LOG_WARNING, "No %s found on system, using built-in server string.", file);
		severity = LOG_WARNING;
	}

	logit(severity, "Server: %s", server_string);
}

static void lsb_exit(void)
{
	if (os)
		free(os);
	if (ver)
		free(ver);
}

/*
 * _CACHEDIR is the configurable fallback.  We only read that, if it
 * exists, otherwise we use the system _PATH_VARDB, which works on all
 * *BSD and GLIBC based Linux systems.  Some Linux systms don't have the
 * correct FHS /var/lib/misc for that define, so we check for that too.
 */
static FILE *fopen_cache(char *mode, char *fn, size_t len)
{
	snprintf(fn, len, _CACHEDIR "/" PACKAGE_NAME ".cache");
	if (access(fn, R_OK | W_OK)) {
		if (!access(_PATH_VARDB, W_OK))
			snprintf(fn, len, "%s/" PACKAGE_NAME ".cache", _PATH_VARDB);
	}

	return fopen(fn, mode);
}

/* https://en.wikipedia.org/wiki/Universally_unique_identifier */
static void uuidgen(void)
{
	char file[256];
	char buf[42];
	FILE *fp;

	fp = fopen_cache("r", file, sizeof(file));
	if (!fp) {
	generate:
		fp = fopen_cache("w", file, sizeof(file));
		if (!fp)
			logit(LOG_WARNING, "Cannot create UUID cache, %s: %s", file, strerror(errno));

		srand(time(NULL));
		snprintf(buf, sizeof(buf), "uuid:%8.8x-%4.4x-%4.4x-%4.4x-%6.6x%6.6x",
			 rand() & 0xFFFFFFFF,
			 rand() & 0xFFFF,
			 (rand() & 0x0FFF) | 0x4000, /* M  4 MSB version => version 4 */
			 (rand() & 0x1FFF) | 0x8000, /* N: 3 MSB variant => variant 1 */
			 rand() & 0xFFFFFF, rand() & 0xFFFFFF);

		if (fp) {
			logit(LOG_DEBUG, "Creating new UUID cache file, %s", file);
			fprintf(fp, "%s\n", buf);
			fclose(fp);
		}
	} else {
		if (!fgets(buf, sizeof(buf), fp)) {
			fclose(fp);
			goto generate;
		}
		buf[strlen(buf) - 1] = 0;
		fclose(fp);
	}

	strcpy(uuid, buf);
	logit(LOG_DEBUG, "URN: %s", uuid);
}

static void exit_handler(int signo)
{
	(void)signo;
	running = 0;
}

static void signal_init(void)
{
	signal(SIGTERM, exit_handler);
	signal(SIGINT,  exit_handler);
	signal(SIGHUP,  exit_handler);
	signal(SIGQUIT, exit_handler);
	signal(SIGPIPE, SIG_IGN); /* get EPIPE instead */
}

static int usage(int code)
{
	printf("Usage: %s [-hnsv] [-i SEC] [-l LEVEL] [-r SEC] [-t TTL] [IFACE [IFACE ...]]\n"
	       "\n"
	       "    -h        This help text\n"
	       "    -i SEC    SSDP notify interval (30-900), default %d sec\n"
	       "    -l LVL    Set log level: none, err, notice (default), info, debug\n"
	       "    -n        Run in foreground, do not daemonize by default\n"
	       "    -r SEC    Interface refresh interval (5-1800), default %d sec\n"
	       "    -s        Use syslog, default unless running in foreground, -n\n"
	       "    -t TTL    TTL for multicast frames, default 2, according to the UDA\n"
	       "    -v        Show program version\n"
	       "\n"
	       "Bug report address : %s\n", PACKAGE_NAME, NOTIFY_INTERVAL, REFRESH_INTERVAL, PACKAGE_BUGREPORT);
#ifdef PACKAGE_URL
        printf("Project homepage   : %s\n", PACKAGE_URL);
#endif

	return code;
}

int main(int argc, char *argv[])
{
	time_t now, rtmo = 0, itmo = 0;
	int background = 1;
	int interval = NOTIFY_INTERVAL;
	int refresh = REFRESH_INTERVAL;
	int ttl = MC_TTL_DEFAULT;
	int do_syslog = 1;
	int c;

	while ((c = getopt(argc, argv, "hi:l:nr:st:v")) != EOF) {
		switch (c) {
		case 'h':
			return usage(0);

		case 'i':
			interval = atoi(optarg);
			if (interval < 30 || interval > 900)
				errx(1, "Invalid announcement interval (30-900).");
			break;

		case 'l':
			log_level = log_str2lvl(optarg);
			if (-1 == log_level)
				return usage(1);
			break;

		case 'n':
			background = 0;
			do_syslog--;
			break;

		case 'r':
			refresh = atoi(optarg);
			if (refresh < 5 || refresh > 1800)
				errx(1, "Invalid refresh interval (5-1800).");
			break;

		case 's':
			do_syslog++;
			break;

		case 't':
			ttl = atoi(optarg);
			if (ttl < 1 || ttl > 255)
				errx(1, "Invalid TTL (1-255).");
			break;

		case 'v':
			puts(PACKAGE_VERSION);
			return 0;

		default:
			break;
		}
	}

	signal_init();

	if (background) {
		if (daemon(0, 0))
			err(1, "Failed daemonizing");
	}

	log_init(do_syslog);
	uuidgen();
	lsb_init();
	web_init();
	pidfile(PACKAGE_NAME);

	while (running) {
		now = time(NULL);

		if (rtmo <= now) {
			if (ssdp_init(ttl, 1, &argv[optind], argc - optind, ssdp_recv) > 0) {
				logit(LOG_INFO, "Sending SSDP NOTIFY on new interfaces ...");
				ssdp_foreach(announce, 1);
			}
			rtmo = now + refresh;
		}

		if (itmo <= now) {
			logit(LOG_INFO, "Sending SSDP NOTIFY ...");
			ssdp_foreach(announce, 0);
			itmo = now + interval;
		}

		wait_message(MIN(rtmo, itmo));
	}

	lsb_exit();
	log_exit();

	return ssdp_exit();
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */


//web.c
/* Micro web server for serving SSDP .xml file
 *
 * Copyright (c) 2017-2021  Joachim Wiberg <troglobit@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.a
 */

#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "ssdpd.h"

const char *xml =
	"<?xml version=\"1.0\"?>\r\n"
	"<root xmlns=\"urn:schemas-upnp-org:device-1-0\">\r\n"
	" <specVersion>\r\n"
	"   <major>1</major>\r\n"
	"   <minor>0</minor>\r\n"
	" </specVersion>\r\n"
	" <device>\r\n"
	"  <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>\r\n"
	"  <friendlyName>%s</friendlyName>\r\n"
	"  <manufacturer>%s</manufacturer>\r\n%s"
	"  <modelName>%s</modelName>\r\n"
	"  <UDN>uuid:%s</UDN>\r\n"
	"  <presentationURL>http://%s</presentationURL>\r\n"
	" </device>\r\n"
	"</root>\r\n"
	"\r\n";

extern char uuid[];

/* Peek into SOCK_STREAM on accepted client socket to figure out inbound interface */
static struct sockaddr_in *stream_peek(int sd, char *ifname, size_t iflen)
{
        static struct sockaddr_in sin;
        struct ifaddrs *ifaddr, *ifa;
        socklen_t len = sizeof(sin);

        if (-1 == getsockname(sd, (struct sockaddr *)&sin, &len))
                return NULL;

        if (-1 == getifaddrs(&ifaddr))
                return NULL;

        for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
                size_t inlen = sizeof(struct in_addr);
                struct sockaddr_in *iin;

                if (!ifa->ifa_addr)
                        continue;

                if (ifa->ifa_addr->sa_family != AF_INET)
                        continue;

                iin = (struct sockaddr_in *)ifa->ifa_addr;
                if (!memcmp(&sin.sin_addr, &iin->sin_addr, inlen)) {
                        strlcpy(ifname, ifa->ifa_name, iflen);
                        break;
                }
        }

        freeifaddrs(ifaddr);

        return &sin;
}

static int respond(int sd, struct sockaddr_in *sin)
{
	struct pollfd pfd = {
		.fd = sd,
		.events = POLLIN,
	};
	char *head = "HTTP/1.1 200 OK\r\n"
		"Content-Type: text/xml\r\n"
		"Connection: close\r\n"
		"\r\n";
	char hostname[64], url[128] = "";
	char mesg[1024], *reqline[3];
	int rc, rcvd;

	/* Check for early disconnect or client timeout */
	rc = poll(&pfd, 1, 1000);
	if (rc <= 0) {
		if (rc == 0)
			errno = ETIMEDOUT;
		return -1;
	}

	memset(mesg, 0, sizeof(mesg));
	rcvd = recv(sd, mesg, sizeof(mesg) - 1, 0);
	if (rcvd <= 0) {
		if (rcvd == -1)
			logit(LOG_WARNING, "web recv() error: %s", strerror(errno));
		return -1;
	}
	mesg[rcvd] = 0;

	logit(LOG_DEBUG, "%s", mesg);
	reqline[0] = strtok(mesg, " \t\n");
	if (strncmp(reqline[0], "GET", 4) == 0) {
		reqline[1] = strtok(NULL, " \t");
		reqline[2] = strtok(NULL, " \t\n");
		if (strncmp(reqline[2], "HTTP/1.0", 8) != 0 && strncmp(reqline[2], "HTTP/1.1", 8) != 0) {
			if (write(sd, "HTTP/1.1 400 Bad Request\r\n", 26) < 0)
				logit(LOG_WARNING, "Failed returning status 400 to client: %s", strerror(errno));
			return -1;
		}

		/* XXX: Add support for icon as well */
		if (!strstr(reqline[1], LOCATION_DESC)) {
			if (write(sd, "HTTP/1.1 404 Not Found\r\n", 24) < 0)
				logit(LOG_WARNING, "Failed returning status 404 to client: %s", strerror(errno));
			return -1;
		}

		gethostname(hostname, sizeof(hostname));
#ifdef MANUFACTURER_URL
		snprintf(url, sizeof(url), "  <manufacturerURL>%s</manufacturerURL>\r\n", MANUFACTURER_URL);
#endif
		logit(LOG_DEBUG, "Sending XML reply ...");
		if (send(sd, head, strlen(head), 0) < 0)
			goto fail;

		snprintf(mesg, sizeof(mesg), xml,
			 hostname,
			 MANUFACTURER,
			 url,
			 MODEL,
			 uuid,
			 inet_ntoa(sin->sin_addr));
		if (send(sd, mesg, strlen(mesg), 0) < 0) {
		fail:
			logit(LOG_WARNING, "Failed sending file to client: %s", strerror(errno));
			return -1;
		}
	}

	return 0;
}

void web_recv(int sd)
{
	int client;
	char ifname[IF_NAMESIZE + 1] = "UNKNOWN";
	struct sockaddr_in *sin;

	client = accept(sd, NULL, NULL);
	if (client < 0) {
		logit(LOG_ERR, "accept() error: %s", strerror(errno));
		return;
	}

	sin = stream_peek(client, ifname, sizeof(ifname));
	if (!sin) {
		logit(LOG_ERR, "Failed resolving client interface: %s", strerror(errno));
	} else if (!respond(client, sin))
		shutdown(client, SHUT_RDWR);

	close(client);
}

void web_init(void)
{
	struct sockaddr_in sin;
	int sd;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family      = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port        = htons(LOCATION_PORT);

	sd = socket(sin.sin_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (sd == -1) {
		logit(LOG_ERR, "Failed creating web socket: %s", strerror(errno));
		return;
	}

        ENABLE_SOCKOPT(sd, SOL_SOCKET, SO_REUSEADDR);
#ifdef SO_REUSEPORT
        ENABLE_SOCKOPT(sd, SOL_SOCKET, SO_REUSEPORT);
#endif

	if (bind(sd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		logit(LOG_ERR, "Failed binding web socket: %s", strerror(errno));
		close(sd);
		return;
	}

	if (listen(sd, 10) != 0) {
		logit(LOG_ERR, "Failed setting web listen backlog: %s", strerror(errno));
		close(sd);
		return;
	}

	if (!ssdp_register(sd, (struct sockaddr *)&sin, NULL, web_recv)) {
		char host[20];

		inet_ntop(AF_INET, &sin.sin_addr, host, sizeof(host));
		logit(LOG_INFO, "Listening to HTTP connections on %s:%d", host, ntohs(sin.sin_port));
	}
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */


/* SSDP helper functions
 *
 * Copyright (c) 2017-2021  Joachim Wiberg <troglobit@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.a
 */

 #define SYSLOG_NAMES
#include <stdarg.h>
#include "ssdpd.h"

typedef struct _code {
    char    *c_name;
    int c_val;
} CODE;

#define INTERNAL_NOPRI  0x10

CODE prioritynames[] =
  {
    { "alert", LOG_ALERT },
    { "crit", LOG_CRIT },
    { "debug", LOG_DEBUG },
    { "emerg", LOG_EMERG },
    { "err", LOG_ERR },
    { "error", LOG_ERR },       /* DEPRECATED */
    { "info", LOG_INFO },
    { "none", INTERNAL_NOPRI },     /* INTERNAL */
    { "notice", LOG_NOTICE },
    { "panic", LOG_EMERG },     /* DEPRECATED */
    { "warn", LOG_WARNING },        /* DEPRECATED */
    { "warning", LOG_WARNING },
    { NULL, -1 }
  };

LIST_HEAD(, ifsock) il = LIST_HEAD_INITIALIZER();

int log_level = LOG_NOTICE;
int log_opts  = LOG_PID;
int log_on    = 1;

void log_init(int enable)
{
	if (!enable) {
		log_on = 0;
		return;
	}

        openlog(PACKAGE_NAME, log_opts, LOG_DAEMON);
        setlogmask(LOG_UPTO(log_level));
}

void log_exit(void)
{
	if (!log_on)
		return;
	closelog();
}

int log_str2lvl(char *level)
{
    int i;

    for (i = 0; prioritynames[i].c_name; i++) {
	size_t len = MIN(strlen(prioritynames[i].c_name), strlen(level));

	if (!strncasecmp(prioritynames[i].c_name, level, len))
	    return prioritynames[i].c_val;
    }

    return atoi(level);
}

void logit(int severity, const char *format, ...)
{
	va_list ap;

	if (severity > log_level)
		return;

	va_start(ap, format);
	if (!log_on) {
		vfprintf(stderr, format, ap);
		fputs("\n", stderr);
	} else
		vsyslog(severity, format, ap);
	va_end(ap);
}

static void mark(void)
{
	struct ifsock *ifs;

	LIST_FOREACH(ifs, &il, link) {
		in_addr_t a, m;

		a = ifs->addr.sin_addr.s_addr;
		m = ifs->mask.sin_addr.s_addr;
		if (a == htonl(INADDR_ANY) || m == htonl(INADDR_ANY))
			continue;

		if (ifs->sd != -1)
			ifs->stale = 1;
		else
			ifs->stale = 0;
	}
}

static int sweep(void)
{
	struct ifsock *ifs, *tmp;
	int modified = 0;

	LIST_FOREACH_SAFE(ifs, &il, link, tmp) {
		if (!ifs->stale)
			continue;

		modified++;
		logit(LOG_DEBUG, "Removing stale ifs %s", inet_ntoa(ifs->addr.sin_addr));

		LIST_REMOVE(ifs, link);
		close(ifs->sd);
		free(ifs);
	}

	return modified;
}

/* Find interface in same subnet as sa */
struct ifsock *ssdp_find(struct sockaddr *sa)
{
	struct sockaddr_in *addr = (struct sockaddr_in *)sa;
	struct ifsock *ifs;
	in_addr_t cand;

	cand = addr->sin_addr.s_addr;
	LIST_FOREACH(ifs, &il, link) {
		in_addr_t a, m;

		a = ifs->addr.sin_addr.s_addr;
		m = ifs->mask.sin_addr.s_addr;
		if (a == htonl(INADDR_ANY) || m == htonl(INADDR_ANY))
			continue;

		if ((a & m) == (cand & m))
			return ifs;
	}

	return NULL;
}

/* Exact match, must be same ifaddr as sa */
static struct ifsock *find_iface(struct sockaddr *sa)
{
	struct sockaddr_in *addr = (struct sockaddr_in *)sa;
	struct ifsock *ifs;

	if (!sa)
		return NULL;

	LIST_FOREACH(ifs, &il, link) {
		if (ifs->addr.sin_addr.s_addr == addr->sin_addr.s_addr)
			return ifs;
	}

	return NULL;
}

static int filter_addr(struct sockaddr *sa)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;
	struct ifsock *ifs;

	if (!sa)
		return 1;

	if (sa->sa_family != AF_INET)
		return 1;

	if (sin->sin_addr.s_addr == htonl(INADDR_ANY))
		return 1;

#ifndef TEST_MODE
	if (sin->sin_addr.s_addr == htonl(INADDR_LOOPBACK))
		return 1;
#endif

	ifs = ssdp_find(sa);
	if (ifs) {
		if (ifs->addr.sin_addr.s_addr != htonl(INADDR_ANY))
			return 1;
	}

	return 0;
}

static int filter_iface(char *ifname, char *iflist[], size_t num)
{
	size_t i;

	if (!num) {
		logit(LOG_DEBUG, "No interfaces to filter, using all with an IP address.");
		return 0;
	}

	logit(LOG_DEBUG, "Filter %s?  Comparing %zd entries ...", ifname, num);
	for (i = 0; i < num; i++) {
		logit(LOG_DEBUG, "Filter %s?  Comparing with %s ...", ifname, iflist[i]);
		if (!strcmp(ifname, iflist[i]))
			return 0;
	}

	return 1;
}

static void handle_message(int sd)
{
	struct ifsock *ifs;

	LIST_FOREACH(ifs, &il, link) {
		if (ifs->sd != sd)
			continue;

		if (ifs->cb)
			ifs->cb(sd);
	}
}

int ssdp_poll(int timeout)
{
	struct pollfd pfd[MAX_NUM_IFACES];
	struct ifsock *ifs;
	size_t ifnum = 0;
	int num;

	LIST_FOREACH(ifs, &il, link) {
		pfd[ifnum].fd     = ifs->sd;
		pfd[ifnum].events = POLLIN;
		ifnum++;
	}

	num = poll(pfd, ifnum, timeout);
	if (num < 0)
		return -1;
	if (num == 0)
		return 0;

	for (size_t i = 0; i < ifnum; i++) {
		if (pfd[i].revents & POLLNVAL ||
		    pfd[i].revents & POLLHUP)
			continue;

		if (pfd[i].revents & POLLIN)
			handle_message(pfd[i].fd);
	}

	return num;
}

int ssdp_register(int sd, struct sockaddr *addr, struct sockaddr *mask, void (*cb)(int sd))
{
	struct sockaddr_in *address = (struct sockaddr_in *)addr;
	struct sockaddr_in *netmask = (struct sockaddr_in *)mask;
	struct ifsock *ifs;

	ifs = calloc(1, sizeof(*ifs));
	if (!ifs) {
		char *host = inet_ntoa(address->sin_addr);

		logit(LOG_ERR, "Failed registering host %s socket: %s", host, strerror(errno));
		return -1;
	}

	ifs->sd   = sd;
	ifs->mod  = 1;
	ifs->cb   = cb;
	if (address)
		ifs->addr = *address;
	if (mask)
		ifs->mask = *netmask;
	LIST_INSERT_HEAD(&il, ifs, link);

	return 0;
}

void ssdp_foreach(void (*cb)(struct ifsock *, int), int arg)
{
	struct ifsock *ifs;

	LIST_FOREACH(ifs, &il, link)
		cb(ifs, arg);
}

static int socket_open(char *ifname, struct sockaddr *addr, int ttl, int srv)
{
	struct sockaddr_in sin, *address = (struct sockaddr_in *)addr;
	int sd, rc;

	sd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (sd < 0)
		return -1;

        ENABLE_SOCKOPT(sd, SOL_SOCKET, SO_REUSEADDR);
#ifdef SO_REUSEPORT
        ENABLE_SOCKOPT(sd, SOL_SOCKET, SO_REUSEPORT);
#endif

	rc = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
	if (rc < 0) {
		close(sd);
		logit(LOG_ERR, "Failed setting multicast TTL: %s", strerror(errno));
		return -1;
	}

	rc = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_IF, &address->sin_addr, sizeof(address->sin_addr));
	if (rc < 0) {
		close(sd);
		logit(LOG_ERR, "Failed setting multicast interface: %s", strerror(errno));
		return -1;
	}

	logit(LOG_DEBUG, "Adding new interface %s with address %s", ifname, inet_ntoa(address->sin_addr));
	if (!srv)
		return sd;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(MC_SSDP_PORT);
	sin.sin_addr.s_addr = inet_addr("0.0.0.0");
	if (bind(sd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		logit(LOG_ERR, "Failed binding to %s:%d: %s", inet_ntoa(address->sin_addr),
 		      MC_SSDP_PORT, strerror(errno));
	}

	return sd;
}

int ssdp_exit(void)
{
	struct ifsock *ifs, *tmp;
	int ret = 0;

	LIST_FOREACH_SAFE(ifs, &il, link, tmp) {
		LIST_REMOVE(ifs, link);
		if (ifs->sd != -1)
			ret |= close(ifs->sd);
		free(ifs);
	}

	return ret;
}

/*
 * This one differs between BSD and Linux in that on BSD this
 * disables looping multicast back to all *other* sockets on
 * this machine.  Whereas Linux only disables looping it on
 * the given socket ... please prove me wrong.  --Troglobit
 */
static void multicast_loop(int sd)
{
	char loop = 0;
	int rc;

	rc = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));
	if (rc < 0)
		logit(LOG_WARNING, "Failed disabing multicast loop: %s", strerror(errno));
}

static int multicast_join(int sd, struct sockaddr *sa)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;
	struct ip_mreq imr;

	imr.imr_interface = sin->sin_addr;
	imr.imr_multiaddr.s_addr = inet_addr(MC_SSDP_GROUP);
        if (setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &imr, sizeof(imr))) {
		if (EADDRINUSE == errno)
			return 0;

		logit(LOG_ERR, "Failed joining group %s: %s", MC_SSDP_GROUP, strerror(errno));
		return -1;
	}

	return 0;
}

int ssdp_init(int ttl, int srv, char *iflist[], size_t num, void (*cb)(int sd))
{
	struct ifaddrs *ifaddrs, *ifa;
	int modified;
	size_t i;

	logit(LOG_INFO, "Updating interfaces ...");

	if (getifaddrs(&ifaddrs) < 0) {
		logit(LOG_ERR, "Failed getifaddrs(): %s", strerror(errno));
		return -1;
	}

	/* Mark all outbound interfaces as stale */
	mark();

	/* First pass, clear stale marker from exact matches */
	for (ifa = ifaddrs; ifa; ifa = ifa->ifa_next) {
		struct ifsock *ifs;

		/* Do we already have it? */
		ifs = find_iface(ifa->ifa_addr);
		if (ifs) {
			ifs->stale = 0;
			continue;
		}
	}

	/* Clean out any stale interface addresses */
	modified = sweep();

	/* Second pass, add new ones */
	for (ifa = ifaddrs; ifa; ifa = ifa->ifa_next) {
		int sd;

		/* Interface filtering, optional command line argument */
		if (filter_iface(ifa->ifa_name, iflist, num)) {
			logit(LOG_DEBUG, "Skipping %s, not in iflist.", ifa->ifa_name);
			continue;
		}

		/* Do we have another in the same subnet? */
		if (filter_addr(ifa->ifa_addr))
			continue;

		sd = socket_open(ifa->ifa_name, ifa->ifa_addr, ttl, srv);
		if (sd < 0)
			continue;

#ifdef __linux__
		multicast_loop(sd);
#endif

		if (!multicast_join(sd, ifa->ifa_addr))
			logit(LOG_DEBUG, "Joined group %s on interface %s", MC_SSDP_GROUP, ifa->ifa_name);

		if (ssdp_register(sd, ifa->ifa_addr, ifa->ifa_netmask, cb)) {
			close(sd);
			break;
		}

		logit(LOG_DEBUG, "Registered socket %d with ssd_recv() callback", sd);
		modified++;
	}

	freeifaddrs(ifaddrs);

	return modified;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */


/*	Updated by troglobit for libite/finit/uftpd projects 2016/07/04 */
/*	$OpenBSD: pidfile.c,v 1.11 2015/06/03 02:24:36 millert Exp $	*/
/*	$NetBSD: pidfile.c,v 1.4 2001/02/19 22:43:42 cgd Exp $	*/

/*-
 * Copyright (c) 1999 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/stat.h>		/* utimensat() */
#include <sys/time.h>		/* utimensat() on *BSD */
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef HAVE_UTIMENSAT
int utimensat(int dirfd, const char *pathname, const struct timespec ts[2], int flags);
#endif

static char *pidfile_path = NULL;
static pid_t pidfile_pid  = 0;

static void pidfile_cleanup(void);

const  char *__pidfile_path = _PIDFILEDIR;
const  char *__pidfile_name = NULL;

int
pidfile(const char *basename)
{
	int save_errno;
	int atexit_already;
	pid_t pid;
	FILE *f;

	if (basename == NULL) {
		errno = EINVAL;
		return (-1);
	}

	pid = getpid();
	atexit_already = 0;

	if (pidfile_path != NULL) {
		if (!access(pidfile_path, R_OK) && pid == pidfile_pid) {
			utimensat(0, pidfile_path, NULL, 0);
			return (0);
		}
		free(pidfile_path);
		pidfile_path = NULL;
		__pidfile_name = NULL;
		atexit_already = 1;
	}

	if (basename[0] != '/') {
		if (asprintf(&pidfile_path, "%s/%s.pid", __pidfile_path, basename) == -1)
			return (-1);
	} else {
		if (asprintf(&pidfile_path, "%s", basename) == -1)
			return (-1);
	}

	if ((f = fopen(pidfile_path, "w")) == NULL) {
		save_errno = errno;
		free(pidfile_path);
		pidfile_path = NULL;
		errno = save_errno;
		return (-1);
	}

	if (fprintf(f, "%ld\n", (long)pid) <= 0 || fflush(f) != 0) {
		save_errno = errno;
		(void) fclose(f);
		(void) unlink(pidfile_path);
		free(pidfile_path);
		pidfile_path = NULL;
		errno = save_errno;
		return (-1);
	}
	(void) fclose(f);
	__pidfile_name = pidfile_path;

	/*
	 * LITE extension, no need to set up another atexit() handler
	 * if user only called us to update the mtime of the PID file
	 */
	if (atexit_already)
		return (0);

	pidfile_pid = pid;
	if (atexit(pidfile_cleanup) < 0) {
		save_errno = errno;
		(void) unlink(pidfile_path);
		free(pidfile_path);
		pidfile_path = NULL;
		pidfile_pid = 0;
		errno = save_errno;
		return (-1);
	}

	return (0);
}

static void
pidfile_cleanup(void)
{
	if (pidfile_path != NULL && pidfile_pid == getpid()) {
		(void) unlink(pidfile_path);
		free(pidfile_path);
		pidfile_path = NULL;
	}
}




/*	$OpenBSD: strlcpy.c,v 1.12 2015/01/15 03:54:12 millert Exp $	*/

/*
 * Copyright (c) 1998, 2015 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <string.h>

/*
 * Copy string src to buffer dst of size dsize.  At most dsize-1
 * chars will be copied.  Always NUL terminates (unless dsize == 0).
 * Returns strlen(src); if retval >= dsize, truncation occurred.
 */
size_t
strlcpy(char *dst, const char *src, size_t dsize)
{
	const char *osrc = src;
	size_t nleft = dsize;

	/* Copy as many bytes as will fit. */
	if (nleft != 0) {
		while (--nleft != 0) {
			if ((*dst++ = *src++) == '\0')
				break;
		}
	}

	/* Not enough room in dst, add NUL and traverse rest of src. */
	if (nleft == 0) {
		if (dsize != 0)
			*dst = '\0';		/* NUL-terminate dst */
		while (*src++)
			;
	}

	return(src - osrc - 1);	/* count does not include NUL */
}
