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

#include <netdb.h>
#include <openssl/md5.h>
#include <sys/stat.h>

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

module AP_MODULE_DECLARE_DATA radius_auth_module;


/*
  RFC 2138 says that this port number is wrong, but everyone's using it.
  Use " AddRadiusAuth server:port secret " to change the port manually.
  */
#define RADIUS_AUTH_UDP_PORT	     1645

#define RADIUS_PASSWORD_LEN	     16
#define RADIUS_RANDOM_VECTOR_LEN     16

/* Per-attribute structure */
typedef struct attribute_t {
  unsigned char attribute;
  unsigned char length;
  unsigned char data[1];
} attribute_t;

/* Packet header structure */
typedef struct radius_packet_t {
  unsigned char code;
  unsigned char id;
  unsigned short length;
  unsigned char vector[RADIUS_RANDOM_VECTOR_LEN];
  attribute_t first;
} radius_packet_t;

#define RADIUS_HEADER_LEN             20

/* RADIUS ID definitions. See RFC 2138 */
#define	RADIUS_ACCESS_REQUEST 1
#define	RADIUS_ACCESS_ACCEPT  2
#define	RADIUS_ACCESS_REJECT  3
#define RADIUS_ACCESS_CHALLENGE 11

/* RADIUS attribute definitions. Also from RFC 2138 */
#define	RADIUS_USER_NAME	      1
#define	RADIUS_PASSWORD		      2
#define	RADIUS_NAS_IP_ADDRESS	      4
#define RADIUS_SERVICE_TYPE           6
#define RADIUS_REPLY_MESSAGE          18
#define RADIUS_STATE		      24
#define RADIUS_SESSION_TIMEOUT        27
#define	RADIUS_CALLING_STATION_ID     31
#define	RADIUS_NAS_IDENTIFIER	      32

/* service types : authenticate only for now */
#define RADIUS_AUTHENTICATE_ONLY      8

/* How large the packets may be */
#define RADIUS_PACKET_RECV_SIZE       1024
#define RADIUS_PACKET_SEND_SIZE       1024
#define APACHE_RADIUS_MAGIC_STATE     "f36809ad"

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE !FALSE
#endif

/* per-server configuration structure */
typedef struct radius_server_config_struct {
  struct in_addr *radius_ip;	/* server IP address */
  unsigned char *secret;	/* server shared secret */
  int secret_len;		/* length of the secret (to save time later) */
  int timeout;			/* cookie valid time */
  int wait;			/* wait for RADIUS server responses */
  int retries;			/*  number of retries on timeout */
  unsigned short port;		/* RADIUS port number */
  unsigned long bind_address;	/* bind socket to this local address */
  struct radius_server_config_struct *next; /* fallback server(s) */
} radius_server_config_rec;

/* per-server configuration create */
static void *
create_radius_server_config(apr_pool_t *p, server_rec *s)
{
  radius_server_config_rec *scr = (radius_server_config_rec *) apr_pcalloc(p, sizeof(radius_server_config_rec) );

  scr->radius_ip = NULL;	/* no server yet */
  scr->port = RADIUS_AUTH_UDP_PORT; /* set the default port */
  scr->secret = NULL;		/* no secret yet */
  scr->secret_len = 0;
  scr->wait = 5;		/* wait 5 sec before giving up on the packet */
  scr->retries = 0;		/* no additional retries */
  scr->timeout = 60;		/* valid for one hour by default */
  scr->bind_address = INADDR_ANY;
  scr->next = NULL;

  return scr;
}

/* RADIUS utility functions */
static struct in_addr *
get_ip_addr(apr_pool_t *p, const char *hostname)
{
  struct hostent *hp;

  if ((hp = gethostbyname(hostname)) != NULL) {
    struct in_addr *ipaddr = apr_pcalloc(p, sizeof(struct in_addr));
    *ipaddr = *(struct in_addr *) hp->h_addr; /* make a local copy */
    return ipaddr;
  } else {
    return NULL;
  }
}

/* get a random vector */
static void
get_random_vector(unsigned char vector[RADIUS_RANDOM_VECTOR_LEN])
{
  struct timeval tv;
  struct timezone tz;
  static unsigned int session = 1; /* make the random number harder to guess */
  apr_md5_ctx_t my_md5;
  
  /* Use the time of day with the best resolution the system can
     give us -- often close to microsecond accuracy. */
  gettimeofday(&tv,&tz);

  tv.tv_sec ^= getpid() * session++; /* add some secret information: session */

  /* Hash things to get some cryptographically strong pseudo-random numbers */
  apr_md5_init(&my_md5);
  apr_md5_update(&my_md5, (unsigned char *) &tv, sizeof(tv));
  apr_md5_update(&my_md5, (unsigned char *) &tz, sizeof(tz));
  apr_md5_final(vector, &my_md5);	      /* set the final vector */
}

/* Per-dir configuration structure */
typedef struct radius_dir_config_struct {
  radius_server_config_rec* server;
  int active;                   /* Are we doing RADIUS in this dir? */
  int authoritative;		/* is RADIUS authentication authoritative? */
  int timeout;			/* cookie time valid */
} radius_dir_config_rec;

/* Per-dir configuration create */
static void *
create_radius_dir_config (apr_pool_t *p, char *d)
{
  
  radius_dir_config_rec *rec =
    (radius_dir_config_rec *) apr_pcalloc (p, sizeof(radius_dir_config_rec));

  rec->server = NULL;		/* no valid server by default */
  rec->active = 1;              /* active by default */  
  rec->authoritative = 1;	/* authoritative by default */
  rec->timeout = 0;		/* let the server config decide timeouts */

  return rec;
}

/* per-server set configuration */
static const char *
add_auth_radius(cmd_parms *cmd, void *mconfig,
		const char *server, const char *secret, const char *wait)
{
  radius_server_config_rec *scr;
  unsigned int port;
  char *p;

  scr = ap_get_module_config(cmd->server->module_config, &radius_auth_module);

  /* allocate and look up the RADIUS server's IP address */

  scr->radius_ip = (struct in_addr *)apr_pcalloc(cmd->pool, sizeof(struct in_addr));

  /* Check to see if there's a port in the server name */
  if ((p = strchr(server, ':')) != NULL) {
    *(p++) = 0;			/* hammer a zero in it */
    port = atoi(p);
    if (port < 1024) {
      return "AddRadiusAuth: server port number must be 1024 or greater for security reasons";
    }
    scr->port = (unsigned short) port;
  }

  if ((scr->radius_ip = get_ip_addr(cmd->pool, server)) == NULL) {
    return "AddRadiusAuth: Failed looking up RADIUS server IP address";
  }

  scr->secret = apr_pstrdup(cmd->pool, secret);
  scr->secret_len = strlen(scr->secret);
  if (wait != NULL) {
    if ((p = strchr(wait,':')) != NULL) {
      *(p++) = 0;   /* null terminate the wait part of the string */
      scr->retries = atoi(p);
    } 
    scr->wait = atoi(wait);
  } /* else it's already initialized */
  scr->bind_address = INADDR_ANY;

  return NULL;			/* everything's OK */
}

/*
 *  Set the local address to which this client is bound.
 */
static const char *
set_bind_address (cmd_parms *cmd, void *mconfig, const char *arg)
{
  radius_server_config_rec *scr;
  struct in_addr *a;

  scr = ap_get_module_config(cmd->server->module_config,
                                &radius_auth_module);
  if ((a = get_ip_addr(cmd->pool, arg)) == NULL)
      return "AuthRadiusBindAddress: invalid IP address";
  scr->bind_address = a->s_addr;
  return NULL;
}

/*
 *  Set the cookie valid time.
 */
static const char *
set_cookie_valid(cmd_parms *cmd, void *mconfig, const char *arg)
{
  radius_server_config_rec *scr;

  scr = ap_get_module_config(cmd->server->module_config,
			  &radius_auth_module);
  scr->timeout = atoi(arg);
  return NULL;			/* everything's OK */
}

static const char *
set_int_slot(cmd_parms *cmd, char *struct_ptr, const char *arg)
{
  int offset = (int)cmd->info; 
  *(int *)(struct_ptr + offset) = atoi(arg);
  return NULL;
}


/* Table of which command does what */
static command_rec auth_cmds[] = {
  AP_INIT_TAKE23("AddRadiusAuth", add_auth_radius,
    NULL, RSRC_CONF,
    "per-server configuration for RADIUS server name:port, shared secret, and optional timeout:retries"),

  AP_INIT_TAKE1("AuthRadiusBindAddress", set_bind_address,
    NULL, RSRC_CONF,
    "per-server binding local socket to this local IP address. RADIUS requests will be sent *from* this IP address."),

  AP_INIT_TAKE1("AddRadiusCookieValid", set_cookie_valid,
    NULL, RSRC_CONF, 
    "per-server time in minutes for which the returned cookie is valid. After this time, authentication will be requested again. Use '0' for forever."), 

  AP_INIT_FLAG("AuthRadiusAuthoritative", ap_set_flag_slot,
    (void*)APR_OFFSETOF(radius_dir_config_rec, authoritative), OR_AUTHCFG,
   "per-directory access on failed authentication. If set to 'no', then access control is passed along to lower modules on failed authentication."),

  AP_INIT_TAKE1("AuthRadiusCookieValid", set_int_slot,
    NULL,OR_AUTHCFG,
    "per-directory time in minutes for which the returned cookie is valid. After this time, authentication will be requested again .Use 0 for forever."),

  AP_INIT_FLAG("AuthRadiusActive", ap_set_flag_slot,
    (void*)APR_OFFSETOF(radius_dir_config_rec, active), OR_AUTHCFG,
    "per-directory toggle the use of RADIUS authentication."),
  { NULL }
};

static unsigned char *
xor(unsigned char *p, unsigned char *q, int length)
{
  int i;
  unsigned char *response = p;
  
  for (i = 0; i < length; i++)
    *(p++) ^= *(q++);
  return response;
}

static int
verify_packet(request_rec *r, radius_packet_t *packet,
	      unsigned char vector[RADIUS_RANDOM_VECTOR_LEN])
{
  server_rec *s = r->server; 
  radius_server_config_rec *scr = (radius_server_config_rec *)
    ap_get_module_config (s->module_config, &radius_auth_module);
  apr_md5_ctx_t my_md5;
  unsigned char	calculated[RADIUS_RANDOM_VECTOR_LEN];
  unsigned char	reply[RADIUS_RANDOM_VECTOR_LEN];
  
  /*
   * We could dispense with the memcpy, and do MD5's of the packet
   * + vector piece by piece.  This is easier understand, and probably faster.
   */
  memcpy(reply, packet->vector, RADIUS_RANDOM_VECTOR_LEN); /* save the reply */
  memcpy(packet->vector, vector, RADIUS_RANDOM_VECTOR_LEN); /* sent vector */
   
  /* MD5(packet header + vector + packet data + secret) */
  apr_md5_init(&my_md5);
  apr_md5_update(&my_md5, (unsigned char *) packet, ntohs(packet->length));
  apr_md5_update(&my_md5, scr->secret, scr->secret_len);
  apr_md5_final(calculated, &my_md5);      /* set the final vector */

  /* Did he use the same random vector + shared secret? */
  if(memcmp(calculated, reply, RADIUS_RANDOM_VECTOR_LEN) != 0) {
    return -1;
  }
  return 0;
}
static void
add_attribute(radius_packet_t *packet, int type, const unsigned char *data, int length)
{
  attribute_t *p;

  p = (attribute_t *) ((unsigned char *)packet + packet->length);
  p->attribute = type;
  p->length = length + 2;		/* the total size of the attribute */
  packet->length += p->length;
  memcpy(p->data, data, length);
}

#define COOKIE_SIZE 1024
/* make a cookie based on secret + public information */
static char *
make_cookie(request_rec *r, time_t expires, const char *passwd, const char *string)
{
  char one[COOKIE_SIZE], two[COOKIE_SIZE];
  char *cookie = apr_pcalloc(r->pool, COOKIE_SIZE);
  conn_rec *c = r->connection;
  server_rec *s = r->server;
  radius_server_config_rec *scr = (radius_server_config_rec *)
    ap_get_module_config (s->module_config, &radius_auth_module);
  const char *hostname;
  
  if ((hostname = ap_get_remote_host(c, r->per_dir_config, REMOTE_NAME, NULL)) == NULL)
    hostname = "no.one@example.com";

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
	      r->user, passwd, c->remote_ip, hostname, expires);

  /* if you're REALLY worried about what's going on */

#if 0
  ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server," secret     = %s\n", scr->secret);
  ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server," user       = %s\n", r->user);
  ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server," passwd     = %s\n", passwd);
  ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server," remote ip  = %s\n", c->remote_ip);
  ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server," hostname   = %s\n", hostname);
  ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server," expiry     = %08x\n", expires);
#endif

  /* MD5 the cookie to make it secure, and add more secret information */
  apr_snprintf(two, COOKIE_SIZE, "%s%s", scr->secret, ap_md5(r->pool, one));
  if (string == NULL) {
    apr_snprintf(cookie, COOKIE_SIZE, "%s%08x",
		ap_md5(r->pool, two), expires);
  } else {
    apr_snprintf(cookie, COOKIE_SIZE, "%s%08x%s",
		ap_md5(r->pool, two), expires, string);
  }
  return cookie;
}
static int
valid_cookie(request_rec *r, const char *cookie, const char *passwd)
{
  time_t expires, now;

  if (strlen(cookie) < (16 + 4)*2) { /* MD5 is 16 bytes, and expiry date is 4*/
    return FALSE;		/* invalid */
  }
    
  sscanf(&cookie[32], "%8lx", &expires);

  now = time(NULL);
  if (expires < now) {	/* valid only for a short window of time */
    return FALSE;		/* invalid: expired */
  }

  /* Is the returned cookie identical to one made from our secret? */
  if (strcmp(cookie, make_cookie(r, expires, passwd, NULL)) == 0)
    return TRUE;
  
  return FALSE;			/* cookie doesn't match: re-validate */
}
/* Add a cookie to an outgoing request */
static const char *cookie_name = "RADIUS";

static void
add_cookie(request_rec *r, apr_table_t *header, char *cookie, time_t expires)
{
  char *new_cookie = apr_pcalloc(r->pool, COOKIE_SIZE); /* so it'll stick around */

  if (expires != 0) {
    char buffer[1024];

    strftime(buffer, sizeof(buffer), "%a %d-%b-%Y %H:%M:%S %Z",
	     gmtime(&expires));
    apr_snprintf(new_cookie, 1024, "%s=%s; path=/ expires=%s;",
		cookie_name, cookie, buffer);
  } else {
    apr_snprintf(new_cookie, 1024,
		"%s=%s; path=/; expires=Wed, 01-Oct-97 01:01:01 GMT;",
		cookie_name, cookie);
  }
    
  apr_table_set(header,"Set-Cookie", new_cookie);
}
/* Spot a cookie in an incoming request */
static char *
spot_cookie(request_rec *r)
{
  const char *cookie;
  char *value;

  if ((cookie = apr_table_get(r->headers_in, "Cookie"))) {
    if ((value=strstr(cookie, cookie_name))) {
      char *cookiebuf, *cookieend;
      ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0,r->server,"Found Radius Cookie, now check if it's valid...");
      value += strlen(cookie_name); /* skip the name */

      /*
       *  Ensure there's an '=' after the name.
       */
      if (*value != '=') {
	return NULL;
      } else {
	value++;
      }
      
      cookiebuf = apr_pstrdup( r->pool, value );
      cookieend = strchr(cookiebuf,';');
      if (cookieend) *cookieend = '\0';	/* Ignore anything after a ; */
      
      /* Set the cookie in a note, for logging */
      return cookiebuf;          /* Theres already a cookie, no new one */
    }
  }
  return NULL;                        /* no cookie was found */
}

/* There's a lot of parameters to this function, but it does a lot of work */
static int
radius_authenticate(request_rec *r, radius_server_config_rec *scr, 
		    int sockfd, int code, char *recv_buffer,
		    const char *user, const char *passwd_in, const char *state, 
		    unsigned char *vector, char *errstr)
{
  struct sockaddr_in *sin;
  struct sockaddr saremote;
  int salen, total_length;
  fd_set set;
  int retries = scr->retries;
  struct timeval tv;
  int rcode;
  struct in_addr *ip_addr;
  
  unsigned char misc[RADIUS_RANDOM_VECTOR_LEN];
  int password_len, i;
  unsigned char password[128];
  apr_md5_ctx_t md5_secret, my_md5;
  uint32_t service;

  unsigned char send_buffer[RADIUS_PACKET_SEND_SIZE];
  radius_packet_t *packet = (radius_packet_t *) send_buffer;

  i = strlen(passwd_in);
  password_len = (i + 0x0f) & 0xfffffff0; /* round off to 16 */
  if (password_len == 0) {
    password_len = 16;		/* it's at least 15 bytes long */
  } else if (password_len > 128) { /* password too long, from RFC2138, p.22 */
    ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0,r->server,"password given by user %s is too long for RADIUS", user);
    return FALSE;
  }
  
  memset(password, 0, password_len);
  memcpy(password, passwd_in, i); /* don't use strcpy! */
  
  /* ************************************************************ */
  /* generate a random authentication vector */
  get_random_vector(vector);

  /* ************************************************************ */
  /* Fill in the packet header */
  memset(send_buffer, 0, sizeof(send_buffer));

  packet->code = code;
  packet->id = vector[0];	/* make a random request id */
  packet->length = RADIUS_HEADER_LEN;
  memcpy(packet->vector, vector, RADIUS_RANDOM_VECTOR_LEN);

  /* Fill in the user name attribute */
  add_attribute(packet, RADIUS_USER_NAME, user, strlen(user));

  /* ************************************************************ */
  /* encrypt the password */
  /* password : e[0] = p[0] ^ MD5(secret + vector) */
  apr_md5_init(&md5_secret);
  apr_md5_update(&md5_secret, scr->secret, scr->secret_len);
  my_md5 = md5_secret;		/* so we won't re-do the hash later */
  apr_md5_update(&my_md5, vector, RADIUS_RANDOM_VECTOR_LEN);
  apr_md5_final(misc, &my_md5);      /* set the final vector */
  xor(password, misc, RADIUS_PASSWORD_LEN);

  /* For each step through, e[i] = p[i] ^ MD5(secret + e[i-1]) */
  for (i = 1; i < (password_len >> 4); i++) {
    my_md5 = md5_secret;	/* grab old value of the hash */
    apr_md5_update(&my_md5, &password[(i-1) * RADIUS_PASSWORD_LEN], RADIUS_PASSWORD_LEN);
    apr_md5_final(misc, &my_md5);      /* set the final vector */
    xor(&password[i * RADIUS_PASSWORD_LEN], misc, RADIUS_PASSWORD_LEN);
  }
  add_attribute(packet, RADIUS_PASSWORD, password, password_len);

  /* ************************************************************ */
  /* Tell the RADIUS server that we only want to authenticate */
  service = htonl(RADIUS_AUTHENTICATE_ONLY);
  add_attribute(packet, RADIUS_SERVICE_TYPE, (unsigned char *) &service,
		sizeof(service));
  
  /* ************************************************************ */
  /* Tell the RADIUS server which virtual server we're coming from */
  add_attribute(packet, RADIUS_NAS_IDENTIFIER, r->server->server_hostname,
		strlen(r->server->server_hostname));

  /* ************************************************************ */
  /* Tell the RADIUS server which IP address we're coming from */
  if (scr->radius_ip->s_addr == htonl(0x7f000001)) {
    ip_addr = scr->radius_ip; /* go to localhost through localhost */
  } else {
    ip_addr = get_ip_addr(r->pool, r->connection->base_server->server_hostname);
    if (ip_addr == NULL) {
      ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0,r->server, "cannot look up server hostname %s",
		  r->connection->base_server->server_hostname);
      return FALSE;
    }
  }

  add_attribute(packet, RADIUS_NAS_IP_ADDRESS, (unsigned char *)&ip_addr->s_addr,
		sizeof(ip_addr->s_addr));
  
  
  /* ************************************************************ */
  /* add client IP address */
  add_attribute(packet, RADIUS_CALLING_STATION_ID, r->connection->remote_ip, strlen(r->connection->remote_ip));

  /* ************************************************************ */
  /* add state, if requested */
  if (state != NULL) {
    add_attribute(packet, RADIUS_STATE, state, strlen(state));
  }

  /* ************************************************************ */
  /* Now that we're done building the packet, we can send it */
  total_length = packet->length;
  packet->length = htons(packet->length);
  
  sin = (struct sockaddr_in *) &saremote;
  memset ((char *) sin, '\0', sizeof(saremote));
  sin->sin_family = AF_INET;
  sin->sin_addr.s_addr = scr->radius_ip->s_addr;
  sin->sin_port = htons(scr->port);

  ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server, "Sending packet on %s:%i", inet_ntoa(*scr->radius_ip), scr->port);

  while (retries >= 0) {
    if (sendto(sockfd, (char *) packet, total_length, 0,
	       &saremote, sizeof(struct sockaddr_in)) < 0) {
      ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server, "Error sending RADIUS packet for user %s: %s", user, strerror(errno));
      return FALSE;
    }

  wait_again:
    /* ************************************************************ */
    /* Wait for the response, and verify it. */
    salen = sizeof (saremote);
    tv.tv_sec = scr->wait;	/* wait for the specified time */
    tv.tv_usec = 0;
    FD_ZERO(&set);		/* clear out the set */
    FD_SET(sockfd, &set);	/* wait only for the RADIUS UDP socket */
    
    rcode = select(sockfd + 1, &set, NULL, NULL, &tv);
    if ((rcode < 0) && (errno == EINTR)) {
      goto wait_again;		/* signal, ignore it */
    }

    if (rcode == 0) {		/* done the select, with no data ready */
      retries--;
    } else {
      break;			/* exit from the 'while retries' loop */
    }
  } /* loop over the retries */

  /*
   *  Error.  Die.
   */
  if (rcode < 0) {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server, "Error waiting for RADIUS response: %s", strerror(errno));
    return FALSE;
  }
  
  /*
   *  Time out.
   */
  if (rcode == 0) {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server, "RADIUS server %s failed to respond within %d seconds after each of %d retries",
		inet_ntoa(*scr->radius_ip), scr->wait, scr->retries);
    return FALSE;
  }

  if ((total_length = recvfrom(sockfd, (char *) recv_buffer,
			       RADIUS_PACKET_RECV_SIZE,
			       0, &saremote, &salen)) < 0) {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server, "Error reading RADIUS packet: %s", strerror(errno));
    return FALSE;
  }

  if (total_length < RADIUS_HEADER_LEN) {
    apr_snprintf(errstr, MAX_STRING_LEN, "Packet is too small");
    return FALSE;
  }

  packet = (radius_packet_t *) recv_buffer; /* we have a new packet */
  if ((ntohs(packet->length) > total_length) ||
      (ntohs(packet->length) > RADIUS_PACKET_RECV_SIZE)) {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server, "RADIUS packet corrupted");
    return FALSE;
  }
  
  /* Check if we've got everything OK.  We should also check packet->id...*/
  if (verify_packet(r, packet, vector)) {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server, "RADIUS packet fails verification");
    return FALSE;
  }
  
  return TRUE;
}

/* Find a particular attribute.  All we really care about is STATE */
static attribute_t *
find_attribute(radius_packet_t *packet, unsigned char type)
{
  attribute_t *attr = &packet->first;
  int len = ntohs(packet->length) - RADIUS_HEADER_LEN;

  if (!len) return NULL;

  while (attr->attribute != type) {
    if (attr->length < 2) return NULL;

    if ((len -= attr->length) <= 0) {
      return NULL;		/* not found */
    }
    attr = (attribute_t *) ((char *) attr + attr->length);
  }
  return attr;
}
#define radcpy(STRING, ATTR) do { \
				  unsigned char len = ATTR->length; \
				  if (len >= 2) len-=2; \
				  memcpy(STRING, ATTR->data, len); \
				  (STRING)[len] = 0;} while (0)


/* authentication module utility functions */
static int
check_pw(request_rec *r, radius_server_config_rec *scr, const char *user, const char *passwd_in, const char *state, char *message, char *errstr)
{
  struct sockaddr_in *sin;
  struct sockaddr salocal;
  int sockfd;
  unsigned short local_port;

  unsigned char vector[RADIUS_RANDOM_VECTOR_LEN];
  unsigned char recv_buffer[RADIUS_PACKET_RECV_SIZE];
  radius_packet_t *packet;

  int rcode;

  /* ************************************************************ */
  /* connect to a port */
  if ((sockfd = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0,r->server, "error opening RADIUS socket for user %s: %s", user, strerror(errno));
    return FALSE;
  }

  sin = (struct sockaddr_in *) &salocal;
  memset((char *) sin, '\0', sizeof(salocal));
  sin->sin_family = AF_INET;
  sin->sin_addr.s_addr = scr->bind_address;
  
  local_port = 1025;
  do {
    local_port++;
    sin->sin_port = htons((unsigned short) local_port);
  } while((bind(sockfd, &salocal, sizeof(struct sockaddr_in)) < 0) &&
	  (local_port < 64000));
  if(local_port >= 64000) {
    close(sockfd);
    ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server, "cannot bind to RADIUS socket for user %s", user);
    return FALSE;
  }

  rcode = radius_authenticate(r, scr, sockfd, RADIUS_ACCESS_REQUEST, recv_buffer, user, passwd_in, state, vector, errstr);

  close(sockfd);		/* we're done with it */

  if (rcode == FALSE) {
    return FALSE;		/* error out */
  }
  
  packet = (radius_packet_t *) recv_buffer;

  switch (packet->code)
    {
      
    case RADIUS_ACCESS_ACCEPT:
      {
	attribute_t *a_timeout;
	int i;

	a_timeout = find_attribute(packet, RADIUS_SESSION_TIMEOUT);
	if (a_timeout) {
	  memcpy(&i, a_timeout->data, 4);
	  i = ntohl(i);
	}
      }
      *message = 0;		/* no message */
      return TRUE;		/* he likes you! */
      break;
      
    case RADIUS_ACCESS_REJECT:
      ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0,r->server, "RADIUS authentication failed for user %s", user);
      break;
      
    case RADIUS_ACCESS_CHALLENGE:
      {
	attribute_t *a_state, *a_reply;
	time_t expires = time(NULL) + 120; /* state expires in two minutes */
	char server_state[256];
	char *p;

	if (((a_state = find_attribute(packet, RADIUS_STATE)) == NULL) ||
	    ((a_reply = find_attribute(packet, RADIUS_REPLY_MESSAGE)) == NULL)) {
	  ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server, "RADIUS access-challenge received with State or Reply-Message missing");
	  break;
	}

	if ((a_state->length <= 2) || (a_reply->length <= 2)) {
	  apr_snprintf(errstr, MAX_STRING_LEN, "RADIUS access-challenge received with invalid State or Reply-Message");
	  break;
	}

	/* Copy magic state message to the state */
	strcpy(server_state, APACHE_RADIUS_MAGIC_STATE);
	radcpy(server_state + sizeof(APACHE_RADIUS_MAGIC_STATE) - 1,
	       a_state);
	
	/* Copy the Reply-Message back to the caller : do CR/LF smashing */
	radcpy(message, a_reply);
	
	p = message;		/* strip any control characters */
	while (*p) {
	  if (*p < ' ')
	    *p = ' ';
	  p++;
	}
	
	/* set the magic cookie */
	add_cookie(r, r->err_headers_out,make_cookie(r, expires, "", server_state), expires);
	
	/* log the challenge, as it IS an error returned to the user */
	ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server, "RADIUS server requested challenge for user %s", user);
	
      }
      break;
      
    default:			/* don't know what else to do */
      ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server, "RADIUS server returned unknown response %02x",
		  packet->code);
      break;
    }
  
  return FALSE;			/* default to failing authentication */
}

void
note_challenge_auth_failure(request_rec *r, char *user, char *message)
{
    if (!*message) {		/* no message to print */
      /* note_basic_auth_failure(r); */
    } else {			/* print our magic message */
      apr_table_set (r->err_headers_out, "WWW-Authenticate",
		 apr_pstrcat(r->pool, "Basic realm=\"", ap_auth_name(r), " for ", user, " '", message, "'", NULL));
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

/* common stuff for both Apache 2.0 and 2.1+ */
int
authenticate_basic_user_common(request_rec *r,
                               const char* user,
                               const char* sent_pw)
{
  radius_dir_config_rec *rec =
    (radius_dir_config_rec *)ap_get_module_config (r->per_dir_config, &radius_auth_module);
  server_rec *s = r->server; 
  radius_server_config_rec *scr = (radius_server_config_rec *)
    ap_get_module_config (s->module_config, &radius_auth_module);
  conn_rec *c = r->connection;
  char errstr[MAX_STRING_LEN];
  int min;
  char *cookie;
  char *state = NULL;
  char message[256];
  time_t expires;
  struct stat buf;
  
  /* not active here, just decline */
  if (!rec->active)
    return DECLINED;

  /* no server declared, decline but note for debugging purposes -joy */
  if (!scr->radius_ip) {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_WARNING, 0, r->server,
                 "AuthRadiusActive set, but no RADIUS server IP - missing AddRadiusAuth in this context?");
    return DECLINED;
  }
  
  if (r->user[0] == 0)		/* NUL users can never be let in */
    return HTTP_UNAUTHORIZED;

  message[0] = 0;		/* no message for now */

  ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server, "Radius Auth for: %s requests %s : file=%s",
	  r->server->server_hostname, r->uri, r->filename);

  /* check for the existence of a cookie: do weak authentication if so */
  if ((cookie = spot_cookie(r)) != NULL) {

    ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server, "Found cookie=%s for user=%s : ", cookie, r->user);
    /* are we in a Challenge-Response intermediate state? */
    if (((state = strstr(cookie, APACHE_RADIUS_MAGIC_STATE)) != NULL) &&
	((state - cookie) == 40)) { /* it's in the right place */
      ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server, "with RADIUS challenge state set.\n");
      /*
       * If there's an authentication failure, ensure we delete the state.
       * If authentication succeeds, the new cookie will supersede the old.
       * (RFC 2109, 4.3.3)
       */
      add_cookie(r, r->err_headers_out, cookie, 0);
      state += sizeof(APACHE_RADIUS_MAGIC_STATE) -1; /* skip state string */

      /* valid username, passwd, and expiry date: don't do RADIUS */
    } else if (valid_cookie(r, cookie, sent_pw)) {
      ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server,"still valid.  Serving page.\n");
      return OK;
    } else {			/* the cookie has probably expired */
      /* don't bother logging the fact: we probably don't care */
      add_cookie(r, r->err_headers_out, cookie, 0);
      note_challenge_auth_failure(r, r->user, message);
      ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server," invalid or expired. telling browser to delete cookie\n");
      return HTTP_UNAUTHORIZED;
    }
  } else {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server," No cookie found.  Trying RADIUS authentication.\n");
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
  if (!(check_pw(r, scr, r->user, sent_pw, state, message, errstr))) {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server, "RADIUS authentication for user=%s password=%s failed\n",
	    r->user, sent_pw);
    if (!(rec->authoritative)) {
      ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server, "We're not authoritative.  Never mind.\n");
      return DECLINED;		/* never mind */
    }
    note_challenge_auth_failure(r, r->user, message);
    ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server, "Sending failure message to user=%s\n", r->user);
    return HTTP_UNAUTHORIZED;
  }

  min = scr->timeout;		/* the server config is authoritative */
  if (scr->timeout == 0) {	/* except that zero means forever */
    min = 24*30*60;		/* expire in one month (that's forever!) */
  }

  if ((rec->timeout != 0) && /* if we don't let the server choose */
      (rec->timeout < min)) { /* and we're more restrictive than the server */
    min = rec->timeout;		/* use the directory config */
  }

  expires = time(NULL) + (min * 60);
  cookie = make_cookie(r, expires, sent_pw, NULL);

  ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server," RADIUS Authentication for user=%s password=%s OK.  Cookie expiry in %d minutes\n",
	  r->user, sent_pw, min);
  ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server," Adding cookie %s\n", cookie);
  add_cookie(r, r->headers_out, cookie, expires);
  return OK;
}

/* Apache 2.1+ */
static authn_status
authenticate_basic_user_newargs(request_rec *r,
                                const char *user,
                                const char *password)
{
  int normalreturnvalue = authenticate_basic_user_common(r, user, password);

  if (normalreturnvalue == OK)
    return AUTH_GRANTED;
  else if (normalreturnvalue == HTTP_UNAUTHORIZED)
    return AUTH_DENIED;
  else
    return AUTH_GENERAL_ERROR;
  /* AUTH_USER_NOT_FOUND would be nice, but the typical RADIUS server
     never gives any such information, it just sends an Access-Reject
     packet, no reasons given
   */
}

/* Apache 2.0 */
static int
authenticate_basic_user(request_rec *r)
{
  int res;
  const char *sent_pw;
  
  /* this used to say just if ((res=...)), which relied on the fact that
     OK is defined as 0, and the other states are non-0, which is then
     used in a typical C fashion... but it's a bad idea, really, we should
     explicitly check if it's not OK, whatever that may be -joy
   */
  res = ap_get_basic_auth_pw(r, &sent_pw);
  if (res != OK)
    return res;

  return authenticate_basic_user_common(r, r->user, sent_pw);
}

/* Apache 2.1+ */
static const authn_provider authn_radius_provider = {
    &authenticate_basic_user_newargs,
    NULL
};

static void register_hooks(apr_pool_t *p)
{
/* Apache 2.1+ */
    static const char * const aszPost[]={ "mod_authz_user.c", NULL };
    ap_register_provider(p, AUTHN_PROVIDER_GROUP, "radius", "0", &authn_radius_provider);
    ap_hook_check_user_id(authenticate_basic_user,NULL,aszPost,APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA radius_auth_module =
{
    STANDARD20_MODULE_STUFF,
    create_radius_dir_config,	/* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    create_radius_server_config,/* server config */
    NULL,                       /* merge server config */
    auth_cmds,                	/* command apr_table_t */
    register_hooks              /* register hooks */
};
