/* ====================================================================
 * Copyright (c) 1997-2002 The Apache Group.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 5. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 *
 *  CVS $Id$
 */

/*
  Everyone wants strong authentication over the web.  For us, this means
  RADIUS.
  
  Using static passwords & RADIUS authentication over the web is a BAD IDEA.
  Everyone can sniff the passwords, as they're sent over the net in the clear.
  RADIUS web authentication is a REALLY BAD IDEA if you use the same RADIUS
  server for web and NAS (dial-up) or firewall users.  Then ANYONE can
  pretend to be you, and break through your firewall with minimal effort.

  PLEASE use a different RADIUS server for web authentication and dial-up
  or firewall users!  If you must use the same server, go for one-time
  passwords.  They're ever so much more secure.

  Also, do NOT have your RADIUS server visible to the external world.
  Doing so makes all kinds of attacks possible.

  **************************************************
  
  Add to Configuration file BEFORE mod_auth.o:
  Module radius_auth_module    mod_auth_radius.o
  
  Add to server configuration file
  AddRadiusAuth <server>[:port] <secret> [<seconds>[:<retries>]]
  AddRadiusCookieValid <minutes>
  AddModule modules/extra/mod_auth_radius.o              (for 1.3.x)
  
  Add to directory configuration
  AddRadiusAuth <server>[:port] <secret> [<seconds>]
  AuthRadiusBindAddress <local address/interface>
  AuthRadiusAuthoritative on
  AuthRadiusActive on
  AuthRadiusCookieValid <minutes>

  **************************************************

  Adding mod_auth_radius to the Configuration file before mod_auth
  allows you to have mod_auth_radius authoritative by default, but NOT
  have it interfere with the rest of your configuration.  The authentication
  methods are tried from the bottom of the list, on up.

  You must have at least one authentication method as authoritative.  If
  they all return "DECLINED", you get "server configuration error" message.

  AddRadiusAuth configures the RADIUS server name (and optional port).
  You must also specify the shared secret, and tell the RADIUS server that
  the web host machine is a valid RADIUS client.  The optional <seconds> field
  specifies how long Apache waits before giving up, and deciding that the
  RADIUS server is down.  It then returns a "DENIED" error.

  If you want, you can specify how long the returned cookies are valid.
  The time is in minutes, with the magic value of '0' meaning forever.


  The per-dir configuration Cookie Valid time does NOT over-ride the server
  configuration.  mod_auth_radius choose the most restrictive of the two to
  use.  This way, a site administrator can say all cookies are valid forever,
  and then make some directories a bit more secure, by forcing
  re-authentication every hour.

  If you want logging, use the standard Apache access log.  A log message
  is generated ONLY when a user has authenticated, and their name & file
  accessed is put in the log file.

  How it works
  ============

  The browser requests a page: http://www.example.com/index.html
  
  Apache notes that the directory is access controlled, and sends a
  "Authorization Required".

  The browser asks for a username & password, which it then sends to Apache,
  along with a request for the page again.

  Apache calls mod_auth_radius, which notes that there is no RADIUS cookie
  in the request.

  mod_auth_radius packages up the username/password into a RADIUS request,
  and sends it to the RADIUS server.

  The RADIUS server does its magic, and decides yes/no for authentication.

  If no, mod_auth_radius returns DENIED.

  If yes, mod_auth_radius returns a cookie containing MD5'd public+private
  information.

  The web browser uses this cookie on all subsequent requests, and
  mod_auth_radius verifies the cookie is valid, and doesn't contact the
  RADIUS server again.

  Some caveats
  ============

  This works fine for static passwords (i.e. "user", "password"), but needs
  a bit more attention for one-time passwords.  All of the browsers I've
  tested don't use the cookie immediately if you're accessing a directory
  as:

  http://www.example.com/

  What's hidden here is that the following files are checked for:

  http://www.example.com/
  http://www.example.com/home.html
  http://www.example.com/home.cgi
  http://www.example.com/index.cgi
  http://www.example.com/index.html

  etc., all in sequence.  This module does a 'stat', and returns "NOT FOUND"
  when anyone tries to access a file which doesn't exist.  However,
  it WILL authenticate for a file which does exists, but the browser may
  not use the returned cookie when accessing a different page.

  The way to fix this is to point the browser at a specific page. i.e.

  http://www.example.com/
         says "connect to our _secure_ site",  where _secure_ is a link to 

  http://www.example.com/secure/index.html


  People using static passwords don't need to do this, but if they don't,
  they'll notice that their RADIUS server is getting 1-4 hits for every web
  authentication request.


  Some browsers (I.E.) have a problem with sending cookies on initial
  requests. If you have a file index.html which includes img/foo.gif
  in the same directory.  The user authenticates, reads index.html
  (with the cookie in the request header), BUT on reading the gifs,
  the cookie is NOT included.
  
  This problem can be avoided by EITHER putting the gifs in the same
  directory as the index.html file, or putting moving the entire tree
  down a node, and having a NEW index.html which points to ./moved/index.html
  This is ridiculously ugly, but it seems to work.

  
  About the cookies
  =================

  The cookies are valid for a specified time, or until the browser dies.
  mod_auth_radius will forcibly try to expire cookies that it thinks are
  too old.  If your browser doesn't expire the cookie, you'll see an
  authorization required message over and over.  You must then exit the
  browser, and re-load the web page.

  Any questions or comments can be sent to me at: aland@freeradius.org


  Challenge-Response support
  ==========================

  As of 1.2.1, this module supports the full RADIUS challenge-response
  mechanism.  From the user's perspective, on authenticatation, type
  in username & garbage (or NUL) password.  Click <OK>, and you'll get
  an authentication failure.  This is fine, as mod_auth_radius has secretly
  set a cookie, and modified the Basic-Authentication-Realm.

  When the authentication fails, click <OK> to continue, and you'll get
  another username/password authentication window.  This time, however,
  you'll see your username displayed, along with the RADIUS Reply-Message
  at the top of the authentication window.  This message usually includes
  a challenge.

  Type in your username, and put the response to the challenge in the password
  field.  Click <OK> again, and you should be authenticated.

  The secret is that cookies are being magically set back and forth, and these
  cookies include the RADIUS state variable.

  The challenge-response works on Netscape 3.x and 4.x, HotJava, but NOT
  on Internet Explorer.  I.E. does not appear to follow the relevant RFCs
  properly.


  Version History
  ===============

  1.6.0  Reformat code, strip out support for Apache < 2.4.  If this is
         required still required, submit patches to add support via
         preprocessor macros.  We will no longer be maintaining per
         version copies of mod_auth_radius.c.

  1.5.4  Support for retries from John Lines <john.lines@integris.co.uk>
         Port to Apache 2.0 by Harrie Hazewinkel <harrie@mod-snmp.com>

  1.5.3 Bug fix from Bryan Stansell <bryan@stansell.org>, to set
        the right data element for the AddRadiusCookieValid configuration
    item.

  1.5.2 Updates for NAS-Identifier and NAS-IP-Address, based on ideas
        from Adrian Hosey <ahosey@systhug.com>.  The NAS-Identifier is
    the virtual server host name, and the NAS-IP-Address is the
    IP address of the base server.

    Also integrated code from http://www.wede.de/sw/mod_auth_radius/
        which had forked form this one after v1.3.3.

  1.5.1 Quick release, for bug found by f.garosi@usl7.toscana.it.

  1.5.0 Don't stat() proxy requests.

  1.3.3 Another minor bug fix and configuration hints for Apache 1.3.x
        Thanks to Hiroshi MIZOGUCHI <mizoguti@screen.co.jp>.

  1.3.2 Fixed a bug which sometimes caused a SEGV in debugging mode.
        Thanks to Tomi Leppikangas <tomilepp@ousrvr2.oulu.fi> for
        pointing it out.

  1.3.1 (minor) Added more error output on failed response

  1.3.0 Fixed for Apache 1.3.0

  1.2.5 Corrected typo in sscanf

  1.2.4 Added support for debugging, so people can see what's going
        on during the authentication process.  Define DEBUG_RADIUS
        in the code below to enable debugging.

  1.2.3 Corrected some problems with normal username/password
        authentication and re-loads.

  1.2.2: Cleaned up usage of IP addresses
         return failure on unknown RADIUS response code.

  1.2.1: Finalized challenge/response & tested it

  1.2 : Cookies are expired on authentication failure.
        Add to r->err_headers_out, NOT r->headers_out.

  1.1 : Bug fixes ("forever" is one month, not 12 minutes)
        Added proper error outputs

  1.0 : Initial version.

 */

#include <stdint.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "util_md5.h"
#include "apr_general.h"
#include "apr_tables.h"
#include "apr_strings.h"
/* Apache 2.1+ */
#include "ap_provider.h"
#include "mod_auth.h"

/* Apache 2.4+ */
#include "http_request.h"

module AP_MODULE_DECLARE_DATA radius_auth_module;

#define RADLOG_DEBUG(srv, fmt, ...) ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, srv, fmt,  ## __VA_ARGS__)
#define RADLOG_WARN(srv, fmt, ...) ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_WARNING, 0, srv, fmt,  ## __VA_ARGS__)

#define radcpy(STRING, ATTR) do { \
                  uint8_t len = ATTR->length; \
                  if (len >= 2) len-=2; \
                  memcpy(STRING, ATTR->data, len); \
                  (STRING)[len] = 0;} while (0)

/*
  RFC 2138 says that this port number is wrong, but everyone's using it.
  Use " AddRadiusAuth server:port secret " to change the port manually.
  */
#define RADIUS_AUTH_UDP_PORT         1645
#define RADIUS_PASSWORD_LEN          16
#define RADIUS_RANDOM_VECTOR_LEN     16

/* Per-attribute structure */
typedef struct attribute_t {
	uint8_t attribute;
	uint8_t length;
	uint8_t data[1];
} attribute_t;

/* Packet header structure */
typedef struct radius_packet_t {
	uint8_t code;
	uint8_t id;
	uint16_t length;
	uint8_t vector[RADIUS_RANDOM_VECTOR_LEN];
	attribute_t first;
} radius_packet_t;

#define RADIUS_HEADER_LEN             20

/* RADIUS ID definitions. See RFC 2138 */
#define RADIUS_ACCESS_REQUEST         1
#define RADIUS_ACCESS_ACCEPT          2
#define RADIUS_ACCESS_REJECT          3
#define RADIUS_ACCESS_CHALLENGE       11

/* RADIUS attribute definitions. Also from RFC 2138 */
#define RADIUS_USER_NAME              1
#define RADIUS_PASSWORD               2
#define RADIUS_NAS_IP_ADDRESS         4
#define RADIUS_SERVICE_TYPE           6
#define RADIUS_REPLY_MESSAGE          18
#define RADIUS_STATE                  24
#define RADIUS_SESSION_TIMEOUT        27
#define RADIUS_CALLING_STATION_ID     31
#define RADIUS_NAS_IDENTIFIER         32

/* service types : authenticate only for now */
#define RADIUS_AUTHENTICATE_ONLY      8

/* How large the packets may be */
#define RADIUS_PACKET_RECV_SIZE       1024
#define RADIUS_PACKET_SEND_SIZE       1024
#define APACHE_RADIUS_MAGIC_STATE     "f36809ad"

#ifndef FALSE
#  define FALSE 0
#endif

#ifndef TRUE
#  define TRUE !FALSE
#endif

/* Add a cookie to an outgoing request */
static const char *cookie_name = "RADIUS";

#define COOKIE_SIZE                   1024

/* per-server configuration structure */
typedef struct radius_server_config_rec_s {
	struct in_addr *radius_ip;
	/* server IP address */
	char *secret;
	/* server shared secret */
	int secret_len;
	/* length of the secret (to save time later) */
	int timeout;
	/* cookie valid time */
	int wait;
	/* wait for RADIUS server responses */
	int retries;
	/* number of retries on timeout */
	uint16_t port;
	/* RADIUS port number */
	unsigned long bind_address;
	/* bind socket to this local address */
	struct radius_server_config_rec_s *next; /* fallback server(s) */
} radius_server_config_rec_t;

/* per-server configuration create */
static void *radius_server_config_alloc(apr_pool_t *p, server_rec *s)
{
	radius_server_config_rec_t *scr;

	scr = (radius_server_config_rec_t *)apr_pcalloc(p, sizeof(radius_server_config_rec_t));
	scr->radius_ip = NULL;            /* no server yet */
	scr->port = RADIUS_AUTH_UDP_PORT; /* set the default port */
	scr->secret = NULL;               /* no secret yet */
	scr->secret_len = 0;
	scr->wait = 5;                    /* wait 5 sec before giving up on the packet */
	scr->retries = 0;                 /* no additional retries */
	scr->timeout = 60;                /* valid for one hour by default */
	scr->bind_address = INADDR_ANY;
	scr->next = NULL;

	return scr;
}

/*
 * This function gets called to merge two per-server configuration
 * records.  This is typically done to cope with things like virtual hosts and
 * the default server configuration. The routine has the responsibility of
 * creating a new record and merging the contents of the other two into it
 * appropriately. If the module doesn't declare a merge routine, the more
 * specific existing record is used exclusively.
 *
 * The routine MUST NOT modify any of its arguments!
 *
 * The return value is a pointer to the created module-specific structure
 * containing the merged values.
 */
static void *radius_server_config_merge(apr_pool_t *p,
					void *parent_config,
					void *newloc_config)
{
	radius_server_config_rec_t *merged_config = radius_server_config_alloc(p, NULL);
	radius_server_config_rec_t *old_configig = (radius_server_config_rec_t *)parent_config;
	radius_server_config_rec_t *new_config = (radius_server_config_rec_t *)newloc_config;
	void *result = NULL;

	result = (new_config->radius_ip == NULL) ? old_configig->radius_ip : new_config->radius_ip;
	if (result != NULL) {
		merged_config->radius_ip = apr_pcalloc(p, sizeof(struct in_addr));
		*merged_config->radius_ip = *((struct in_addr *)result); /* make a copy */
	}

	result = (new_config->secret == NULL) ? old_configig->secret : new_config->secret;
	if (result != NULL) {
		merged_config->secret = apr_pstrdup(p, (char *)result); /* make a copy */
		merged_config->secret_len = strlen(merged_config->secret);
	}

	merged_config->port = new_config->port;
	merged_config->wait = new_config->wait;
	merged_config->retries = new_config->retries;
	merged_config->timeout = new_config->timeout;
	merged_config->bind_address = new_config->bind_address;

	return (void *)merged_config;
}

/* RADIUS utility functions */
static struct in_addr *ip_addr_get(apr_pool_t *p,
				   const char *hostname)
{
	struct hostent *hp;

	if ((hp = gethostbyname(hostname)) != NULL) {
		struct in_addr *ipaddr = apr_pcalloc(p, sizeof(struct in_addr));
		*ipaddr = *(struct in_addr *)hp->h_addr; /* make a local copy */
		return ipaddr;
	}

	return NULL;
}

/* get a random vector */
static void random_vector_get(uint8_t *vector)
{
	struct timeval tv;
	struct timezone tz;
	static unsigned int session = 1; /* make the random number harder to guess */
	apr_md5_ctx_t my_md5;

	/*
	 * Use the time of day with the best resolution the system can
	 * give us -- often close to microsecond accuracy.
	 */
	gettimeofday(&tv, &tz);

	tv.tv_sec ^= getpid() * session++; /* add some secret information: session */

	/* Hash things to get some cryptographically strong pseudo-random numbers */
	apr_md5_init(&my_md5);
	apr_md5_update(&my_md5, (uint8_t *)&tv, sizeof(tv));
	apr_md5_update(&my_md5, (uint8_t *)&tz, sizeof(tz));
	apr_md5_final(vector, &my_md5);          /* set the final vector */
}

/* Per-dir configuration structure */
typedef struct radius_dir_config_rec {
	radius_server_config_rec_t *server;
	int active;
	/* Are we doing RADIUS in this dir? */
	int authoritative;
	/* is RADIUS authentication authoritative? */
	int timeout;
	/* cookie time valid */
	char *calling_station_id; /* custom value for specifying hardcoded calling station ID */
} radius_dir_config_rec_t;

/* Per-dir configuration create */
static void *radius_per_directory_config_alloc(apr_pool_t *p, char *d)
{
	radius_dir_config_rec_t *rec;

	rec = (radius_dir_config_rec_t *)apr_pcalloc(p, sizeof(radius_dir_config_rec_t));

	rec->server = NULL;             /* no valid server by default */
	rec->active = 1;                /* active by default */
	rec->authoritative = 1;         /* authoritative by default */
	rec->timeout = 0;               /* let the server config decide timeouts */
	rec->calling_station_id = NULL; /* no custom value for calling station ID yet ; use default behavior */

	return rec;
}

/*
 * This function gets called to merge two per-directory configuration
 * records.  This is typically done to cope with things like .htaccess files
 * or <Location> directives for directories that are beneath one for which a
 * configuration record was already created.  The routine has the
 * responsibility of creating a new record and merging the contents of the
 * other two into it appropriately.  If the module doesn't declare a merge
 * routine, the record for the closest ancestor location (that has one) is
 * used exclusively.
 *
 * The routine MUST NOT modify any of its arguments!
 *
 * The return value is a pointer to the created module-specific structure
 * containing the merged values.
 */
static void *radius_per_directory_config_merge(apr_pool_t *p,
					       void *parent_config,
					       void *newloc_config)
{
	radius_dir_config_rec_t *merged_config = radius_per_directory_config_alloc(p, NULL);
	radius_dir_config_rec_t *old_configig = (radius_dir_config_rec_t *)parent_config;
	radius_dir_config_rec_t *new_config = (radius_dir_config_rec_t *)newloc_config;
	void *result = NULL;

	result = (new_config->calling_station_id == NULL) ?
		old_configig->calling_station_id : new_config->calling_station_id;
	if (result != NULL) {
		merged_config->calling_station_id = apr_pstrdup(p, (char *)result); /* make a copy */
	}

	merged_config->active = new_config->active;
	merged_config->authoritative = new_config->authoritative;
	merged_config->timeout = new_config->timeout;

	return (void *)merged_config;
}

/* AddRadiusAuth: per-server set configuration */
static const char *radius_server_add(cmd_parms *cmd,
				     void *mconfig,
				     const char *server,
				     const char *secret,
				     const char *wait)
{
	radius_server_config_rec_t *scr;
	uint16_t port;
	char *p;

	scr = ap_get_module_config(cmd->server->module_config, &radius_auth_module);

	/* allocate and look up the RADIUS server's IP address */
	scr->radius_ip = (struct in_addr *)apr_pcalloc(cmd->pool, sizeof(struct in_addr));

	/* Check to see if there's a port in the server name */
	if ((p = strchr(server, ':')) != NULL) {
		*(p++) = 0;            /* hammer a zero in it */
		port = atoi(p);
		if (port < 1024) {
			return "AddRadiusAuth: server port number must be 1024 or greater for security reasons";
		}
		scr->port = (uint16_t)port;
	}

	if ((scr->radius_ip = ip_addr_get(cmd->pool, server)) == NULL) {
		return "AddRadiusAuth: Failed looking up RADIUS server IP address";
	}

	scr->secret = apr_pstrdup(cmd->pool, secret);
	scr->secret_len = strlen(scr->secret);
	if (wait != NULL) {
		if ((p = strchr(wait, ':')) != NULL) {
			*(p++) = 0;   /* null terminate the wait part of the string */
			scr->retries = atoi(p);
		}
		scr->wait = atoi(wait);
	} /* else it's already initialized */
	scr->bind_address = INADDR_ANY;

	return NULL;
}

/*
 * AuthRadiusBindAddress: Set the local address to which this client is bound.
 */
static const char *bind_address_set(cmd_parms *cmd,
				    void *mconfig,
				    const char *arg)
{
	radius_server_config_rec_t *scr;
	struct in_addr *a;

	scr = ap_get_module_config(cmd->server->module_config, &radius_auth_module);

	if ((a = ip_addr_get(cmd->pool, arg)) == NULL) return "AuthRadiusBindAddress: Invalid IP address";
	scr->bind_address = a->s_addr;

	return NULL;
}

/*
 * AddRadiusCookieValid: Set the cookie valid time.
 */
static const char *cookie_set_timeout(cmd_parms *cmd,
				      void *mconfig,
				      const char *arg)
{
	radius_server_config_rec_t *scr;

	scr = ap_get_module_config(cmd->server->module_config, &radius_auth_module);
	scr->timeout = atoi(arg);

	return NULL;
}

/* Table of which command does what */
static command_rec auth_cmds[] = {
	AP_INIT_TAKE23("AddRadiusAuth", radius_server_add,
		       NULL, RSRC_CONF,
		       "per-server configuration for RADIUS server name:port, shared secret, and optional timeout:retries"),

	AP_INIT_TAKE1("AuthRadiusBindAddress", bind_address_set,
		      NULL, RSRC_CONF,
		      "per-server binding local socket to this local IP address. RADIUS requests will be sent *from* this IP address."),

	AP_INIT_TAKE1("AddRadiusCookieValid", cookie_set_timeout,
		      NULL, RSRC_CONF,
		      "per-server time in minutes for which the returned cookie is valid. After this time, authentication will be requested again. Use '0' for forever."),

	AP_INIT_TAKE1("AddRadiusCallingStationID", ap_set_string_slot,
		      (void *)APR_OFFSETOF(radius_dir_config_rec_t, calling_station_id), OR_AUTHCFG,
		      "per-directory custom value for the calling station ID attribute. If unset, default is to use the client's remote IP address."),

	AP_INIT_FLAG("AuthRadiusAuthoritative", ap_set_flag_slot,
		     (void *)APR_OFFSETOF(radius_dir_config_rec_t, authoritative), OR_AUTHCFG,
		     "per-directory access on failed authentication. If set to 'no', then access control is passed along to lower modules on failed authentication."),

	AP_INIT_TAKE1("AuthRadiusCookieValid", ap_set_int_slot,
		      (void *)APR_OFFSETOF(radius_dir_config_rec_t, timeout), OR_AUTHCFG,
		      "per-directory time in minutes for which the returned cookie is valid. After this time, authentication will be requested again .Use 0 for forever."),

	AP_INIT_FLAG("AuthRadiusActive", ap_set_flag_slot,
		     (void *)APR_OFFSETOF(radius_dir_config_rec_t, active), OR_AUTHCFG,
		     "per-directory toggle the use of RADIUS authentication."),

	{ NULL }
};

static uint8_t *xor(uint8_t *p, uint8_t *q, int length)
{
	int i;
	uint8_t *response = p;

	for (i = 0; i < length; i++) *(p++) ^= *(q++);

	return response;
}

static int packet_verify(request_rec *r,
			 radius_packet_t *packet,
			 uint8_t *vector)
{
	apr_md5_ctx_t my_md5;
	server_rec *s = r->server;
	radius_server_config_rec_t *scr;
	uint8_t calculated[RADIUS_RANDOM_VECTOR_LEN];
	uint8_t reply[RADIUS_RANDOM_VECTOR_LEN];

	scr = (radius_server_config_rec_t *)ap_get_module_config(s->module_config, &radius_auth_module);

	/*
	 * We could dispense with the memcpy, and do MD5's of the packet
	 * + vector piece by piece.  This is easier understand, and probably faster.
	 */
	memcpy(reply, packet->vector, RADIUS_RANDOM_VECTOR_LEN); /* save the reply */
	memcpy(packet->vector, vector, RADIUS_RANDOM_VECTOR_LEN); /* sent vector */

	/* MD5(packet header + vector + packet data + secret) */
	apr_md5_init(&my_md5);
	apr_md5_update(&my_md5, (uint8_t *)packet, ntohs(packet->length));
	apr_md5_update(&my_md5, (uint8_t *)scr->secret, scr->secret_len);
	apr_md5_final(calculated, &my_md5);      /* set the final vector */

	/* Did he use the same random vector + shared secret? */
	if (memcmp(calculated, reply, RADIUS_RANDOM_VECTOR_LEN) != 0) return -1;

	return 0;
}

static void attribute_add(radius_packet_t *packet,
			  int type,
			  const uint8_t *data,
			  int length)
{
	attribute_t *p;

	p = (attribute_t *)((uint8_t *)packet + packet->length);
	p->attribute = type;
	p->length = length + 2;        /* the total size of the attribute */
	packet->length += p->length;

	memcpy(p->data, data, length);
}

/* make a cookie based on secret + public information */
static char *cookie_alloc(request_rec *r,
			  time_t expires,
			  const char *passwd,
			  const char *string)
{
	char one[COOKIE_SIZE], two[COOKIE_SIZE];
	char *cookie;
	conn_rec *c = r->connection;
	server_rec *s = r->server;
	radius_server_config_rec_t *scr;
	const char *hostname;

	cookie = apr_pcalloc(r->pool, COOKIE_SIZE);
	scr = (radius_server_config_rec_t *)ap_get_module_config(s->module_config, &radius_auth_module);

	if ((hostname = ap_get_remote_host(c, r->per_dir_config, REMOTE_NAME, NULL)) == NULL)
		hostname = "www.example.com";

	/*
	 * Arg! We can't use 'ntohs(c->remote_addr.sin_port)', because I.E.
	 * ignores keepalives, and opens a new connection on EVERY request!
	 * This is a BAD security problem!  It allows multiple users on the
	 * same machine to access the data.
	 *
	 * A derivative security problem is users authenticating from
	 * behind a firewall.
	 * All users appear to be coming from the firewall.  A malicious
	 * agent working in the same company as the authorized user can sniff
	 * the cookie, and and use it themselves.  Since they appear to be
	 * coming from the same IP address (firewall), they're let in.
	 * Oh well, at least the connection is traceable to a particular machine.
	 */

	/*
	 *  Piotr Klaban <makler@oryl.man.torun.pl> says:
	 *
	 *  > The "squid" proxy set HTTP_X_FORWARDED_FOR variable - the
	 *  > original IP of the client.  We can use HTTP_X_FORWARDED_FOR
	 *  > variable besides REMOTE_ADDR.
	 *
	 *  > If cookie is stolen, then atacker could use the same proxy as
	 *  > the client, to validate the cookie. If we would use
	 *  > HTTP_X_FORWARDED_FOR, then useing the proxy would not be
	 *  > sufficient.
	 *
	 *  We don't do this, mainly because I haven't gotten around to
	 *  writing the code...
	 */

	/*
	 * Make a cookie based on secret + public information.
	 *
	 * cookie = MAC(M) = apr_md5(secret, MD5(secret, M))
	 *
	 * See Scheier, B, "Applied Cryptography" 2nd Ed., p.458
	 * Also, RFC 2104.  I don't know if the HMAC gives any additional
	 * benefit here.
	 */
	apr_snprintf(one, COOKIE_SIZE, "%s%s%s%s%s%08x", scr->secret,
		     r->user, passwd, r->useragent_ip, hostname, (unsigned)expires);

/* if you're REALLY worried about what's going on */

#if 0
	RADLOG_DEBUG(r->server," secret     = %s", scr->secret);
	RADLOG_DEBUG(r->server," user       = %s", r->user);
	RADLOG_DEBUG(r->server," passwd     = %s", passwd);
	RADLOG_DEBUG(r->server," remote ip  = %s", r->useragent_ip);
	RADLOG_DEBUG(r->server," hostname   = %s", hostname);
	RADLOG_DEBUG(r->server," expiry     = %08x", expires);
#endif

	/* MD5 the cookie to make it secure, and add more secret information */
	apr_snprintf(two, COOKIE_SIZE, "%s%s", scr->secret, ap_md5(r->pool, (uint8_t *)one));

	if (string == NULL) {
		apr_snprintf(cookie, COOKIE_SIZE, "%s%08x",
			     ap_md5(r->pool, (uint8_t *)two), (unsigned)expires);
	} else {
		apr_snprintf(cookie, COOKIE_SIZE, "%s%08x%s",
			     ap_md5(r->pool, (uint8_t *)two), (unsigned)expires, string);
	}

	return cookie;
}

static int cookie_validate(request_rec *r,
			   const char *cookie,
			   const char *passwd)
{
	time_t expires, now;

	if (strlen(cookie) < (16 + 4) * 2) return FALSE; /* MD5 is 16 bytes, and expiry date is 4*/

	sscanf(&cookie[32], "%8lx", &expires);

	now = time(NULL);
	if (expires < now) return FALSE; /* valid only for a short window of time */

	/* Is the returned cookie identical to one made from our secret? */
	if (strcmp(cookie, cookie_alloc(r, expires, passwd, NULL)) == 0) return TRUE;

	return FALSE; /* cookie doesn't match: re-validate */
}

static void cookie_add(request_rec *r,
		       apr_table_t *header,
		       char *cookie,
		       time_t expires)
{
	char *new_cookie = apr_pcalloc(r->pool, COOKIE_SIZE); /* so it'll stick around */

	if (expires != 0) {
		char buffer[1024];

		strftime(buffer, sizeof(buffer), "%a %d-%b-%Y %H:%M:%S %Z",
			 gmtime(&expires));
		apr_snprintf(new_cookie, 1024, "%s=%s; path=/; expires=%s;",
			     cookie_name, cookie, buffer);
	} else {
		apr_snprintf(new_cookie, 1024,
			     "%s=%s; path=/; expires=Wed, 01-Oct-97 01:01:01 GMT;",
			     cookie_name, cookie);
	}

	apr_table_set(header, "Set-Cookie", new_cookie);
}

/* Spot a cookie in an incoming request */
static char *cookie_from_request(request_rec *r)
{
	const char *cookie;
	char *value;

	if ((cookie = apr_table_get(r->headers_in, "Cookie"))) {
		if ((value = strstr(cookie, cookie_name))) {
			char *cookiebuf, *cookieend;
			RADLOG_DEBUG(r->server, "Found Radius Cookie, now check if it's valid...");
			value += strlen(cookie_name); /* skip the name */

			/*
			 *  Ensure there's an '=' after the name.
			 */
			if (*value != '=') {
				return NULL;
			} else {
				value++;
			}

			cookiebuf = apr_pstrdup(r->pool, value);
			cookieend = strchr(cookiebuf, ';');
			if (cookieend) *cookieend = '\0';    /* Ignore anything after a ; */

			/* Set the cookie in a note, for logging */
			return cookiebuf; /* Theres already a cookie, no new one */
		}
	}

	return NULL; /* no cookie was found */
}

/* There's a lot of parameters to this function, but it does a lot of work */
static int radius_authenticate(request_rec *r,
			       radius_server_config_rec_t *scr,
			       int sockfd,
			       int code,
			       char *recv_buffer,
			       const char *user,
			       const char *passwd_in,
			       const char *state,
			       uint8_t *vector,
			       char *errstr)
{
	struct sockaddr_in *sin;
	struct sockaddr saremote;
	socklen_t salen;
	int total_length;
	fd_set set;
	int retries = scr->retries;
	struct timeval tv;
	int rcode = -1;
	struct in_addr *ip_addr;

	uint8_t misc[RADIUS_RANDOM_VECTOR_LEN];
	int password_len, i;
	uint8_t password[128];
	apr_md5_ctx_t md5_secret, my_md5;
	uint32_t service;

	uint8_t send_buffer[RADIUS_PACKET_SEND_SIZE];
	radius_packet_t *packet = (radius_packet_t *)send_buffer;
	radius_dir_config_rec_t *rec;

	rec = (radius_dir_config_rec_t *)ap_get_module_config(r->per_dir_config, &radius_auth_module);
	i = strlen(passwd_in);
	password_len = (i + 0x0f) & 0xfffffff0; /* round off to 16 */
	if (password_len == 0) {
		password_len = 16;        /* it's at least 15 bytes long */
	} else if (password_len > 128) { /* password too long, from RFC2138, p.22 */
		RADLOG_DEBUG(r->server, "password given by user %s is too long for RADIUS", user);
		return FALSE;
	}

	memset(password, 0, password_len);
	memcpy(password, passwd_in, i); /* don't use strcpy! */

	/* generate a random authentication vector */
	random_vector_get(vector);

	/* Fill in the packet header */
	memset(send_buffer, 0, sizeof(send_buffer));

	packet->code = code;
	packet->id = vector[0];    /* make a random request id */
	packet->length = RADIUS_HEADER_LEN;
	memcpy(packet->vector, vector, RADIUS_RANDOM_VECTOR_LEN);

	/* Fill in the user name attribute */
	attribute_add(packet, RADIUS_USER_NAME, (uint8_t *)user, strlen(user));

	/* encrypt the password */
	/* password : e[0] = p[0] ^ MD5(secret + vector) */
	apr_md5_init(&md5_secret);
	apr_md5_update(&md5_secret, scr->secret, scr->secret_len);
	my_md5 = md5_secret;        /* so we won't re-do the hash later */
	apr_md5_update(&my_md5, vector, RADIUS_RANDOM_VECTOR_LEN);
	apr_md5_final(misc, &my_md5);      /* set the final vector */
	xor(password, misc, RADIUS_PASSWORD_LEN);

	/* For each step through, e[i] = p[i] ^ MD5(secret + e[i-1]) */
	for (i = 1; i < (password_len >> 4); i++) {
		my_md5 = md5_secret;    /* grab old value of the hash */
		apr_md5_update(&my_md5, &password[(i - 1) * RADIUS_PASSWORD_LEN], RADIUS_PASSWORD_LEN);
		apr_md5_final(misc, &my_md5);      /* set the final vector */
		xor(&password[i * RADIUS_PASSWORD_LEN], misc, RADIUS_PASSWORD_LEN);
	}
	attribute_add(packet, RADIUS_PASSWORD, password, password_len);

	/* Tell the RADIUS server that we only want to authenticate */
	service = htonl(RADIUS_AUTHENTICATE_ONLY);
	attribute_add(packet, RADIUS_SERVICE_TYPE, (uint8_t *)&service,
		      sizeof(service));

	/* Tell the RADIUS server which virtual server we're coming from */
	attribute_add(packet, RADIUS_NAS_IDENTIFIER, (uint8_t *)r->server->server_hostname,
		      strlen(r->server->server_hostname));

	/* Tell the RADIUS server which IP address we're coming from */
	if (scr->radius_ip->s_addr == htonl(0x7f000001)) {
		ip_addr = scr->radius_ip; /* go to localhost through localhost */
	} else {
		ip_addr = ip_addr_get(r->pool, r->connection->base_server->server_hostname);
		if (ip_addr == NULL) {
			RADLOG_DEBUG(r->server, "cannot look up server hostname: %s",
				     r->connection->base_server->server_hostname);
			return FALSE;
		}
	}

	attribute_add(packet, RADIUS_NAS_IP_ADDRESS, (uint8_t *)&ip_addr->s_addr,
		      sizeof(ip_addr->s_addr));

	/* add calling station ID (if custom value not specified, add client IP address) */
	if (rec->calling_station_id == NULL) {
		attribute_add(packet, RADIUS_CALLING_STATION_ID, (uint8_t *)r->useragent_ip,
			      strlen(r->useragent_ip));
	} else {
		attribute_add(packet, RADIUS_CALLING_STATION_ID, (uint8_t *)rec->calling_station_id,
			      strlen((char *)rec->calling_station_id));
	}

	/* add state, if requested */
	if (state != NULL) {
		attribute_add(packet, RADIUS_STATE, (uint8_t *)state, strlen(state));
	}

	/* Now that we're done building the packet, we can send it */
	total_length = packet->length;
	packet->length = htons(packet->length);

	sin = (struct sockaddr_in *)&saremote;
	memset((char *)sin, '\0', sizeof(saremote));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = scr->radius_ip->s_addr;
	sin->sin_port = htons(scr->port);

	RADLOG_DEBUG(r->server, "Sending packet on %s:%i",
		     inet_ntoa(*scr->radius_ip), scr->port);

	while (retries >= 0) {
		if (sendto(sockfd, (char *)packet, total_length, 0,
			   &saremote, sizeof(struct sockaddr_in)) < 0) {
			RADLOG_DEBUG(r->server, "Error sending RADIUS packet for user %s: %s", user, strerror(errno));
			return FALSE;
		}

		wait_again:
		/* Wait for the response, and verify it. */
		salen = sizeof(saremote);
		tv.tv_sec = scr->wait;    /* wait for the specified time */
		tv.tv_usec = 0;

		FD_ZERO(&set);        /* clear out the set */
		FD_SET(sockfd, &set);    /* wait only for the RADIUS UDP socket */

		rcode = select(sockfd + 1, &set, NULL, NULL, &tv);
		if ((rcode < 0) && (errno == EINTR)) {
			goto wait_again;        /* signal, ignore it */
		}

		if (rcode == 0) {        /* done the select, with no data ready */
			retries--;
		} else {
			break;            /* exit from the 'while retries' loop */
		}
	} /* loop over the retries */

	/*
	 * Error.  Die.
	 */
	if (rcode < 0) {
		RADLOG_DEBUG(r->server, "Error waiting for RADIUS response: %s", strerror(errno));
		return FALSE;
	}

	/*
	 *  Time out.
	 */
	if (rcode == 0) {
		RADLOG_DEBUG(r->server, "RADIUS server %s failed to respond within %d seconds after each of %d retries",
			     inet_ntoa(*scr->radius_ip), scr->wait, scr->retries);
		return FALSE;
	}

	if ((total_length = recvfrom(sockfd, (char *)recv_buffer,
				     RADIUS_PACKET_RECV_SIZE, 0, &saremote, &salen)) < 0) {
		RADLOG_DEBUG(r->server, "Error reading RADIUS packet: %s", strerror(errno));
		return FALSE;
	}

	if (total_length < RADIUS_HEADER_LEN) {
		apr_snprintf(errstr, MAX_STRING_LEN, "Packet is too small");
		return FALSE;
	}

	packet = (radius_packet_t *)recv_buffer; /* we have a new packet */
	if ((ntohs(packet->length) > total_length) ||
	    (ntohs(packet->length) > RADIUS_PACKET_RECV_SIZE)) {
		RADLOG_DEBUG(r->server, "RADIUS packet corrupted");
		return FALSE;
	}

	/* Check if we've got everything OK.  We should also check packet->id...*/
	if (packet_verify(r, packet, vector)) {
		RADLOG_DEBUG(r->server, "RADIUS packet fails verification");
		return FALSE;
	}

	return TRUE;
}

/* Find a particular attribute.  All we really care about is STATE */
static attribute_t *attribute_find_by_num(radius_packet_t *packet, uint8_t type)
{
	attribute_t *attr = &packet->first;
	int len = ntohs(packet->length) - RADIUS_HEADER_LEN;

	if (!len) return NULL;

	while (attr->attribute != type) {
		if (attr->length < 2) return NULL;
		if ((len -= attr->length) <= 0) return NULL; /* not found */

		attr = (attribute_t *)((char *)attr + attr->length);
	}

	return attr;
}

/* authentication module utility functions */
static int password_check(request_rec *r,
			  radius_server_config_rec_t *scr,
			  const char *user,
			  const char *passwd_in,
			  const char *state,
			  char *message,
			  char *errstr)
{
	struct sockaddr_in *sin;
	struct sockaddr salocal;
	int sockfd;
	uint16_t local_port;
	uint8_t vector[RADIUS_RANDOM_VECTOR_LEN];
	uint8_t recv_buffer[RADIUS_PACKET_RECV_SIZE];
	radius_packet_t *packet;

	int rcode;

	/* connect to a port */
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		RADLOG_DEBUG(r->server, "error opening RADIUS socket for user %s: %s", user, strerror(errno));
		return FALSE;
	}

	sin = (struct sockaddr_in *)&salocal;
	memset((char *)sin, '\0', sizeof(salocal));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = scr->bind_address;

	local_port = 1025;
	do {
		local_port++;
		sin->sin_port = htons((uint16_t)local_port);
	} while ((bind(sockfd, &salocal, sizeof(struct sockaddr_in)) < 0) && (local_port < 64000));

	if (local_port >= 64000) {
		close(sockfd);
		RADLOG_DEBUG(r->server, "cannot bind to RADIUS socket for user %s", user);
		return FALSE;
	}

	rcode = radius_authenticate(r, scr, sockfd,
				    RADIUS_ACCESS_REQUEST, (char *)recv_buffer, user, passwd_in, state, vector, errstr);

	close(sockfd); /* we're done with it */

	if (rcode == FALSE) return FALSE;        /* error out */

	packet = (radius_packet_t *)recv_buffer;

	switch (packet->code) {
	case RADIUS_ACCESS_ACCEPT: {
		attribute_t *a_timeout;
		int i;

		a_timeout = attribute_find_by_num(packet, RADIUS_SESSION_TIMEOUT);
		if (a_timeout) {
			memcpy(&i, a_timeout->data, 4);
			i = ntohl(i);
		}

		*message = 0;  /* no message */
		return TRUE;   /* he likes you! */
	}

	case RADIUS_ACCESS_REJECT:
		RADLOG_DEBUG(r->server, "RADIUS authentication failed for user %s", user);
		break;

	case RADIUS_ACCESS_CHALLENGE: {
		attribute_t *a_state, *a_reply;
		time_t expires = time(NULL) + 120; /* state expires in two minutes */
		char server_state[256];
		char *p;

		if (((a_state = attribute_find_by_num(packet, RADIUS_STATE)) == NULL) ||
		    ((a_reply = attribute_find_by_num(packet, RADIUS_REPLY_MESSAGE)) == NULL)) {
			RADLOG_DEBUG(r->server, "RADIUS access-challenge received with State or Reply-Message missing");
			break;
		}

		if ((a_state->length <= 2) || (a_reply->length <= 2)) {
			apr_snprintf(errstr, MAX_STRING_LEN,
				     "RADIUS access-challenge received with invalid State or Reply-Message");
			break;
		}

		/* Copy magic state message to the state */
		strcpy(server_state, APACHE_RADIUS_MAGIC_STATE);
		radcpy(server_state + sizeof(APACHE_RADIUS_MAGIC_STATE) - 1, a_state);

		/* Copy the Reply-Message back to the caller : do CR/LF smashing */
		radcpy(message, a_reply);

		p = message; /* strip any control characters */
		while (*p) {
			if (*p < ' ')
				*p = ' ';
			p++;
		}

		/* set the magic cookie */
		cookie_add(r, r->err_headers_out, cookie_alloc(r, expires, "", server_state), expires);

		/* log the challenge, as it IS an error returned to the user */
		RADLOG_DEBUG(r->server, "RADIUS server requested challenge for user %s", user);
		break;
	}

	default: /* don't know what else to do */
		RADLOG_DEBUG(r->server, "RADIUS server returned unknown response %02x",
			     packet->code);
		break;
	}

	return FALSE; /* default to failing authentication */
}

void challenge_auth_failure(request_rec *r,
			    char *user,
			    char *message)
{
	if (!*message) { /* no message to print */
		/* note_basic_auth_failure(r); */
	} else {            /* print our magic message */
		apr_table_set(r->err_headers_out, "WWW-Authenticate",
			      apr_pstrcat(r->pool, "Basic realm=\"", ap_auth_name(r), " for ", user, " '", message, "'",
					  NULL));
	}
}

/* These functions return 0 if client is OK, and proper error status
 * if not... either HTTP_UNAUTHORIZED, if we made a check, and it failed, or
 * SERVER_ERROR, if things are so totally confused that we couldn't
 * figure out how to tell if the client is authorized or not.
 *
 * If they return DECLINED, and all other modules also decline, that's
 * treated by the server core as a configuration error, logged and
 * reported as such.
 */

/* Determine user ID, and check if it really is that user, for HTTP
 * basic authentication...
 */
int basic_authentication_common(request_rec *r,
				const char *user,
				const char *sent_pw)
{
	radius_dir_config_rec_t *rec;
	server_rec *s = r->server;
	radius_server_config_rec_t *scr;
	//conn_rec *c = r->connection;
	char errstr[MAX_STRING_LEN];
	int min;
	char *cookie;
	char *state = NULL;
	char message[256];
	time_t expires;
	//struct stat buf;

	rec = (radius_dir_config_rec_t *)ap_get_module_config(r->per_dir_config, &radius_auth_module);
	scr = (radius_server_config_rec_t *)ap_get_module_config(s->module_config, &radius_auth_module);

	/* not active here, just decline */
	if (!rec->active) return DECLINED;

	/* no server declared, decline but note for debugging purposes -joy */
	if (!scr->radius_ip) {
		RADLOG_WARN(r->server,
			    "AuthRadiusActive set, but no RADIUS server IP - missing AddRadiusAuth in this context?");
		return DECLINED;
	}

	if (r->user[0] == 0) return HTTP_UNAUTHORIZED; /* NUL users can never be let in */

	message[0] = 0;        /* no message for now */

	RADLOG_DEBUG(r->server, "Radius Auth for: %s requests %s : file=%s",
		     r->server->server_hostname, r->uri, r->filename);

	/* check for the existence of a cookie: do weak authentication if so */
	if ((cookie = cookie_from_request(r)) != NULL) {
		RADLOG_DEBUG(r->server, "Found cookie=%s for user=%s : ", cookie, r->user);

		/* are we in a Challenge-Response intermediate state? */
		if (((state = strstr(cookie, APACHE_RADIUS_MAGIC_STATE)) != NULL) &&
		    ((state - cookie) == 40)) { /* it's in the right place */
			RADLOG_DEBUG(r->server, "with RADIUS challenge state set.");
			/*
			 * If there's an authentication failure, ensure we delete the state.
			 * If authentication succeeds, the new cookie will supersede the old.
			 * (RFC 2109, 4.3.3)
			 */
			cookie_add(r, r->err_headers_out, cookie, 0);
			state += sizeof(APACHE_RADIUS_MAGIC_STATE) - 1; /* skip state string */

			/* valid username, passwd, and expiry date: don't do RADIUS */
		} else if (cookie_validate(r, cookie, sent_pw)) {
			RADLOG_DEBUG(r->server, "still valid.  Serving page.");
			return OK;
		} else {            /* the cookie has probably expired */
			/* don't bother logging the fact: we probably don't care */
			cookie_add(r, r->err_headers_out, cookie, 0);
			challenge_auth_failure(r, r->user, message);
			RADLOG_DEBUG(r->server, "Invalid or expired. telling browser to delete cookie");
			return HTTP_UNAUTHORIZED;
		}
	} else {
		RADLOG_DEBUG(r->server, "No cookie found.  Trying RADIUS authentication.");
	}

#if 0
	/*
	 *  This is for one-time passwords, so we don't get too badly out of sync .
	 *  Also, don't bother doing the stat for requests we're proxying.
	 */
	if ((strstr(r->filename, "proxy:") != r->filename) &&
	    (stat(r->filename, &buf) < 0)) {
	    return HTTP_NOT_FOUND; /* can't stat it, so we can't authenticate it */
	}
#endif

	/* Check the password, and fill in the error string if an error happens */
	if (!(password_check(r, scr, r->user, sent_pw, state, message, errstr))) {
		RADLOG_DEBUG(r->server, "RADIUS authentication for user=%s password=%s failed",
			     r->user, sent_pw);
		if (!(rec->authoritative)) {
			RADLOG_DEBUG(r->server, "We're not authoritative.  Never mind.");
			return DECLINED;        /* never mind */
		}
		challenge_auth_failure(r, r->user, message);
		RADLOG_DEBUG(r->server, "Sending failure message to user=%s", r->user);
		return HTTP_UNAUTHORIZED;
	}

	min = scr->timeout;      /* the server config is authoritative */
	if (scr->timeout == 0) { /* except that zero means forever */
		min = 24 * 30 * 60;      /* expire in one month (that's forever!) */
	}

	if ((rec->timeout != 0) &&  /* if we don't let the server choose */
	    (rec->timeout < min)) { /* and we're more restrictive than the server */
		min = rec->timeout;     /* use the directory config */
	}

	expires = time(NULL) + (min * 60);
	cookie = cookie_alloc(r, expires, sent_pw, NULL);

	RADLOG_DEBUG(r->server, "RADIUS Authentication for user=%s password=%s OK.  Cookie expiry in %d minutes",
		     r->user, sent_pw, min);

	RADLOG_DEBUG(r->server, "Adding cookie %s", cookie);

	cookie_add(r, r->headers_out, cookie, expires);

	return OK;
}

/* Apache 2.1+ */
static authn_status basic_auth_2_1(request_rec *r,
				   const char *user,
				   const char *password)
{
	int normalreturnvalue;

	normalreturnvalue = basic_authentication_common(r, user, password);

	if (normalreturnvalue == OK) return AUTH_GRANTED;
	else if (normalreturnvalue == HTTP_UNAUTHORIZED) return AUTH_DENIED;
	else return AUTH_GENERAL_ERROR;
	/* AUTH_USER_NOT_FOUND would be nice, but the typical RADIUS server
	   never gives any such information, it just sends an Access-Reject
	   packet, no reasons given
	 */
}

/* Apache 2.0 */
static int basic_auth(request_rec *r)
{
	int res;
	const char *sent_pw;

	/* this used to say just if ((res=...)), which relied on the fact that
	   OK is defined as 0, and the other states are non-0, which is then
	   used in a typical C fashion... but it's a bad idea, really, we should
	   explicitly check if it's not OK, whatever that may be -joy
	 */
	res = ap_get_basic_auth_pw(r, &sent_pw);
	if (res != OK) return res;

	return basic_authentication_common(r, r->user, sent_pw);
}

/* Apache 2.1+ */
static const authn_provider radius_authentication_provider = {
	&basic_auth_2_1,
	NULL
};

static void register_hooks(apr_pool_t *p)
{
	static const char *const aszPost[] = { "mod_authz_user.c", NULL };

	ap_register_provider(p, AUTHN_PROVIDER_GROUP, "radius", "0", &radius_authentication_provider);

	ap_hook_check_access(basic_auth,
			     NULL,
			     aszPost,
			     APR_HOOK_MIDDLE,
			     AP_AUTH_INTERNAL_PER_CONF);
}

module AP_MODULE_DECLARE_DATA
radius_auth_module = {
	STANDARD20_MODULE_STUFF,
	radius_per_directory_config_alloc,	/* dir config creater */
	radius_per_directory_config_merge,	/* dir merger --- default is to override */
	radius_server_config_alloc,		/* server config */
	radius_server_config_merge,		/* merge server config */
	auth_cmds,                      	/* command apr_table_t */
	register_hooks				/* register hooks */
};

