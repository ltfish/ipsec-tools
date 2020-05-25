/* A Bison parser, made by GNU Bison 3.5.1.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2020 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Undocumented macros, especially those whose name start with YY_,
   are private implementation details.  Do not rely on them.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "3.5.1"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1




/* First part of user prologue.  */
#line 5 "cfparse.y"

/*
 * Copyright (C) 1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002 and 2003 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include PATH_IPSEC_H

#ifdef ENABLE_HYBRID
#include <arpa/inet.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>

#include "var.h"
#include "misc.h"
#include "vmbuf.h"
#include "plog.h"
#include "sockmisc.h"
#include "str2val.h"
#include "genlist.h"
#include "debug.h"

#include "admin.h"
#include "privsep.h"
#include "cfparse_proto.h"
#include "cftoken_proto.h"
#include "algorithm.h"
#include "localconf.h"
#include "policy.h"
#include "sainfo.h"
#include "oakley.h"
#include "pfkey.h"
#include "remoteconf.h"
#include "grabmyaddr.h"
#include "isakmp_var.h"
#include "handler.h"
#include "isakmp.h"
#include "nattraversal.h"
#include "isakmp_frag.h"
#ifdef ENABLE_HYBRID
#include "resolv.h"
#include "isakmp_unity.h"
#include "isakmp_xauth.h"
#include "isakmp_cfg.h"
#endif
#include "ipsec_doi.h"
#include "strnames.h"
#include "gcmalloc.h"
#ifdef HAVE_GSSAPI
#include "gssapi.h"
#endif
#include "vendorid.h"
#include "rsalist.h"
#include "crypto_openssl.h"

struct secprotospec {
	int prop_no;
	int trns_no;
	int strength;		/* for isakmp/ipsec */
	int encklen;		/* for isakmp/ipsec */
	time_t lifetime;	/* for isakmp */
	int lifebyte;		/* for isakmp */
	int proto_id;		/* for ipsec (isakmp?) */
	int ipsec_level;	/* for ipsec */
	int encmode;		/* for ipsec */
	int vendorid;		/* for isakmp */
	char *gssid;
	struct sockaddr *remote;
	int algclass[MAXALGCLASS];

	struct secprotospec *next;	/* the tail is the most prefiered. */
	struct secprotospec *prev;
};

static int num2dhgroup[] = {
	0,
	OAKLEY_ATTR_GRP_DESC_MODP768,
	OAKLEY_ATTR_GRP_DESC_MODP1024,
	OAKLEY_ATTR_GRP_DESC_EC2N155,
	OAKLEY_ATTR_GRP_DESC_EC2N185,
	OAKLEY_ATTR_GRP_DESC_MODP1536,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	OAKLEY_ATTR_GRP_DESC_MODP2048,
	OAKLEY_ATTR_GRP_DESC_MODP3072,
	OAKLEY_ATTR_GRP_DESC_MODP4096,
	OAKLEY_ATTR_GRP_DESC_MODP6144,
	OAKLEY_ATTR_GRP_DESC_MODP8192
};

static struct remoteconf *cur_rmconf;
static int tmpalgtype[MAXALGCLASS];
static struct sainfo *cur_sainfo;
static int cur_algclass;
static int oldloglevel = LLV_BASE;

static struct secprotospec *newspspec __P((void));
static void insspspec __P((struct remoteconf *, struct secprotospec *));
void dupspspec_list __P((struct remoteconf *dst, struct remoteconf *src));
void flushspspec __P((struct remoteconf *));
static void adminsock_conf __P((vchar_t *, vchar_t *, vchar_t *, int));

static int set_isakmp_proposal __P((struct remoteconf *));
static void clean_tmpalgtype __P((void));
static int expand_isakmpspec __P((int, int, int *,
	int, int, time_t, int, int, int, char *, struct remoteconf *));

void freeetypes (struct etypes **etypes);

static int load_x509(const char *file, char **filenameptr,
		     vchar_t **certptr)
{
	char path[PATH_MAX];

	getpathname(path, sizeof(path), LC_PATHTYPE_CERT, file);
	*certptr = eay_get_x509cert(path);
	if (*certptr == NULL)
		return -1;

	*filenameptr = racoon_strdup(file);
	STRDUP_FATAL(*filenameptr);

	return 0;
}

static int process_rmconf()
{

	/* check a exchange mode */
	if (cur_rmconf->etypes == NULL) {
		yyerror("no exchange mode specified.\n");
		return -1;
	}

	if (cur_rmconf->idvtype == IDTYPE_UNDEFINED)
		cur_rmconf->idvtype = IDTYPE_ADDRESS;

	if (cur_rmconf->idvtype == IDTYPE_ASN1DN) {
		if (cur_rmconf->mycertfile) {
			if (cur_rmconf->idv)
				yywarn("Both CERT and ASN1 ID "
				       "are set. Hope this is OK.\n");
			/* TODO: Preparse the DN here */
		} else if (cur_rmconf->idv) {
			/* OK, using asn1dn without X.509. */
		} else {
			yyerror("ASN1 ID not specified "
				"and no CERT defined!\n");
			return -1;
		}
	}

	if (duprmconf_finish(cur_rmconf))
		return -1;

	if (set_isakmp_proposal(cur_rmconf) != 0)
		return -1;

	/* DH group settting if aggressive mode is there. */
	if (check_etypeok(cur_rmconf, (void*) ISAKMP_ETYPE_AGG)) {
		struct isakmpsa *p;
		int b = 0;

		/* DH group */
		for (p = cur_rmconf->proposal; p; p = p->next) {
			if (b == 0 || (b && b == p->dh_group)) {
				b = p->dh_group;
				continue;
			}
			yyerror("DH group must be equal "
				"in all proposals "
				"when aggressive mode is "
				"used.\n");
			return -1;
		}
		cur_rmconf->dh_group = b;

		if (cur_rmconf->dh_group == 0) {
			yyerror("DH group must be set in the proposal.\n");
			return -1;
		}

		/* DH group settting if PFS is required. */
		if (oakley_setdhgroup(cur_rmconf->dh_group,
				&cur_rmconf->dhgrp) < 0) {
			yyerror("failed to set DH value.\n");
			return -1;
		}
	}

	insrmconf(cur_rmconf);

	return 0;
}


#line 312 "cfparse.c"

# ifndef YY_CAST
#  ifdef __cplusplus
#   define YY_CAST(Type, Val) static_cast<Type> (Val)
#   define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type> (Val)
#  else
#   define YY_CAST(Type, Val) ((Type) (Val))
#   define YY_REINTERPRET_CAST(Type, Val) ((Type) (Val))
#  endif
# endif
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* Use api.header.include to #include this header
   instead of duplicating it here.  */
#ifndef YY_YY_Y_TAB_H_INCLUDED
# define YY_YY_Y_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    PRIVSEP = 258,
    USER = 259,
    GROUP = 260,
    CHROOT = 261,
    PATH = 262,
    PATHTYPE = 263,
    INCLUDE = 264,
    PFKEY_BUFFER = 265,
    LOGGING = 266,
    LOGLEV = 267,
    PADDING = 268,
    PAD_RANDOMIZE = 269,
    PAD_RANDOMIZELEN = 270,
    PAD_MAXLEN = 271,
    PAD_STRICT = 272,
    PAD_EXCLTAIL = 273,
    LISTEN = 274,
    X_ISAKMP = 275,
    X_ISAKMP_NATT = 276,
    X_ADMIN = 277,
    STRICT_ADDRESS = 278,
    ADMINSOCK = 279,
    DISABLED = 280,
    LDAPCFG = 281,
    LDAP_HOST = 282,
    LDAP_PORT = 283,
    LDAP_PVER = 284,
    LDAP_BASE = 285,
    LDAP_BIND_DN = 286,
    LDAP_BIND_PW = 287,
    LDAP_SUBTREE = 288,
    LDAP_ATTR_USER = 289,
    LDAP_ATTR_ADDR = 290,
    LDAP_ATTR_MASK = 291,
    LDAP_ATTR_GROUP = 292,
    LDAP_ATTR_MEMBER = 293,
    RADCFG = 294,
    RAD_AUTH = 295,
    RAD_ACCT = 296,
    RAD_TIMEOUT = 297,
    RAD_RETRIES = 298,
    MODECFG = 299,
    CFG_NET4 = 300,
    CFG_MASK4 = 301,
    CFG_DNS4 = 302,
    CFG_NBNS4 = 303,
    CFG_DEFAULT_DOMAIN = 304,
    CFG_AUTH_SOURCE = 305,
    CFG_AUTH_GROUPS = 306,
    CFG_SYSTEM = 307,
    CFG_RADIUS = 308,
    CFG_PAM = 309,
    CFG_LDAP = 310,
    CFG_LOCAL = 311,
    CFG_NONE = 312,
    CFG_GROUP_SOURCE = 313,
    CFG_ACCOUNTING = 314,
    CFG_CONF_SOURCE = 315,
    CFG_MOTD = 316,
    CFG_POOL_SIZE = 317,
    CFG_AUTH_THROTTLE = 318,
    CFG_SPLIT_NETWORK = 319,
    CFG_SPLIT_LOCAL = 320,
    CFG_SPLIT_INCLUDE = 321,
    CFG_SPLIT_DNS = 322,
    CFG_PFS_GROUP = 323,
    CFG_SAVE_PASSWD = 324,
    RETRY = 325,
    RETRY_COUNTER = 326,
    RETRY_INTERVAL = 327,
    RETRY_PERSEND = 328,
    RETRY_PHASE1 = 329,
    RETRY_PHASE2 = 330,
    NATT_KA = 331,
    ALGORITHM_CLASS = 332,
    ALGORITHMTYPE = 333,
    STRENGTHTYPE = 334,
    SAINFO = 335,
    FROM = 336,
    REMOTE = 337,
    ANONYMOUS = 338,
    CLIENTADDR = 339,
    INHERIT = 340,
    REMOTE_ADDRESS = 341,
    EXCHANGE_MODE = 342,
    EXCHANGETYPE = 343,
    DOI = 344,
    DOITYPE = 345,
    SITUATION = 346,
    SITUATIONTYPE = 347,
    CERTIFICATE_TYPE = 348,
    CERTTYPE = 349,
    PEERS_CERTFILE = 350,
    CA_TYPE = 351,
    VERIFY_CERT = 352,
    SEND_CERT = 353,
    SEND_CR = 354,
    MATCH_EMPTY_CR = 355,
    IDENTIFIERTYPE = 356,
    IDENTIFIERQUAL = 357,
    MY_IDENTIFIER = 358,
    PEERS_IDENTIFIER = 359,
    VERIFY_IDENTIFIER = 360,
    DNSSEC = 361,
    CERT_X509 = 362,
    CERT_PLAINRSA = 363,
    NONCE_SIZE = 364,
    DH_GROUP = 365,
    KEEPALIVE = 366,
    PASSIVE = 367,
    INITIAL_CONTACT = 368,
    NAT_TRAVERSAL = 369,
    REMOTE_FORCE_LEVEL = 370,
    PROPOSAL_CHECK = 371,
    PROPOSAL_CHECK_LEVEL = 372,
    GENERATE_POLICY = 373,
    GENERATE_LEVEL = 374,
    SUPPORT_PROXY = 375,
    PROPOSAL = 376,
    EXEC_PATH = 377,
    EXEC_COMMAND = 378,
    EXEC_SUCCESS = 379,
    EXEC_FAILURE = 380,
    GSS_ID = 381,
    GSS_ID_ENC = 382,
    GSS_ID_ENCTYPE = 383,
    COMPLEX_BUNDLE = 384,
    DPD = 385,
    DPD_DELAY = 386,
    DPD_RETRY = 387,
    DPD_MAXFAIL = 388,
    PH1ID = 389,
    XAUTH_LOGIN = 390,
    WEAK_PHASE1_CHECK = 391,
    REKEY = 392,
    PREFIX = 393,
    PORT = 394,
    PORTANY = 395,
    UL_PROTO = 396,
    ANY = 397,
    IKE_FRAG = 398,
    ESP_FRAG = 399,
    MODE_CFG = 400,
    PFS_GROUP = 401,
    LIFETIME = 402,
    LIFETYPE_TIME = 403,
    LIFETYPE_BYTE = 404,
    STRENGTH = 405,
    REMOTEID = 406,
    SCRIPT = 407,
    PHASE1_UP = 408,
    PHASE1_DOWN = 409,
    PHASE1_DEAD = 410,
    NUMBER = 411,
    SWITCH = 412,
    BOOLEAN = 413,
    HEXSTRING = 414,
    QUOTEDSTRING = 415,
    ADDRSTRING = 416,
    ADDRRANGE = 417,
    UNITTYPE_BYTE = 418,
    UNITTYPE_KBYTES = 419,
    UNITTYPE_MBYTES = 420,
    UNITTYPE_TBYTES = 421,
    UNITTYPE_SEC = 422,
    UNITTYPE_MIN = 423,
    UNITTYPE_HOUR = 424,
    EOS = 425,
    BOC = 426,
    EOC = 427,
    COMMA = 428
  };
#endif
/* Tokens.  */
#define PRIVSEP 258
#define USER 259
#define GROUP 260
#define CHROOT 261
#define PATH 262
#define PATHTYPE 263
#define INCLUDE 264
#define PFKEY_BUFFER 265
#define LOGGING 266
#define LOGLEV 267
#define PADDING 268
#define PAD_RANDOMIZE 269
#define PAD_RANDOMIZELEN 270
#define PAD_MAXLEN 271
#define PAD_STRICT 272
#define PAD_EXCLTAIL 273
#define LISTEN 274
#define X_ISAKMP 275
#define X_ISAKMP_NATT 276
#define X_ADMIN 277
#define STRICT_ADDRESS 278
#define ADMINSOCK 279
#define DISABLED 280
#define LDAPCFG 281
#define LDAP_HOST 282
#define LDAP_PORT 283
#define LDAP_PVER 284
#define LDAP_BASE 285
#define LDAP_BIND_DN 286
#define LDAP_BIND_PW 287
#define LDAP_SUBTREE 288
#define LDAP_ATTR_USER 289
#define LDAP_ATTR_ADDR 290
#define LDAP_ATTR_MASK 291
#define LDAP_ATTR_GROUP 292
#define LDAP_ATTR_MEMBER 293
#define RADCFG 294
#define RAD_AUTH 295
#define RAD_ACCT 296
#define RAD_TIMEOUT 297
#define RAD_RETRIES 298
#define MODECFG 299
#define CFG_NET4 300
#define CFG_MASK4 301
#define CFG_DNS4 302
#define CFG_NBNS4 303
#define CFG_DEFAULT_DOMAIN 304
#define CFG_AUTH_SOURCE 305
#define CFG_AUTH_GROUPS 306
#define CFG_SYSTEM 307
#define CFG_RADIUS 308
#define CFG_PAM 309
#define CFG_LDAP 310
#define CFG_LOCAL 311
#define CFG_NONE 312
#define CFG_GROUP_SOURCE 313
#define CFG_ACCOUNTING 314
#define CFG_CONF_SOURCE 315
#define CFG_MOTD 316
#define CFG_POOL_SIZE 317
#define CFG_AUTH_THROTTLE 318
#define CFG_SPLIT_NETWORK 319
#define CFG_SPLIT_LOCAL 320
#define CFG_SPLIT_INCLUDE 321
#define CFG_SPLIT_DNS 322
#define CFG_PFS_GROUP 323
#define CFG_SAVE_PASSWD 324
#define RETRY 325
#define RETRY_COUNTER 326
#define RETRY_INTERVAL 327
#define RETRY_PERSEND 328
#define RETRY_PHASE1 329
#define RETRY_PHASE2 330
#define NATT_KA 331
#define ALGORITHM_CLASS 332
#define ALGORITHMTYPE 333
#define STRENGTHTYPE 334
#define SAINFO 335
#define FROM 336
#define REMOTE 337
#define ANONYMOUS 338
#define CLIENTADDR 339
#define INHERIT 340
#define REMOTE_ADDRESS 341
#define EXCHANGE_MODE 342
#define EXCHANGETYPE 343
#define DOI 344
#define DOITYPE 345
#define SITUATION 346
#define SITUATIONTYPE 347
#define CERTIFICATE_TYPE 348
#define CERTTYPE 349
#define PEERS_CERTFILE 350
#define CA_TYPE 351
#define VERIFY_CERT 352
#define SEND_CERT 353
#define SEND_CR 354
#define MATCH_EMPTY_CR 355
#define IDENTIFIERTYPE 356
#define IDENTIFIERQUAL 357
#define MY_IDENTIFIER 358
#define PEERS_IDENTIFIER 359
#define VERIFY_IDENTIFIER 360
#define DNSSEC 361
#define CERT_X509 362
#define CERT_PLAINRSA 363
#define NONCE_SIZE 364
#define DH_GROUP 365
#define KEEPALIVE 366
#define PASSIVE 367
#define INITIAL_CONTACT 368
#define NAT_TRAVERSAL 369
#define REMOTE_FORCE_LEVEL 370
#define PROPOSAL_CHECK 371
#define PROPOSAL_CHECK_LEVEL 372
#define GENERATE_POLICY 373
#define GENERATE_LEVEL 374
#define SUPPORT_PROXY 375
#define PROPOSAL 376
#define EXEC_PATH 377
#define EXEC_COMMAND 378
#define EXEC_SUCCESS 379
#define EXEC_FAILURE 380
#define GSS_ID 381
#define GSS_ID_ENC 382
#define GSS_ID_ENCTYPE 383
#define COMPLEX_BUNDLE 384
#define DPD 385
#define DPD_DELAY 386
#define DPD_RETRY 387
#define DPD_MAXFAIL 388
#define PH1ID 389
#define XAUTH_LOGIN 390
#define WEAK_PHASE1_CHECK 391
#define REKEY 392
#define PREFIX 393
#define PORT 394
#define PORTANY 395
#define UL_PROTO 396
#define ANY 397
#define IKE_FRAG 398
#define ESP_FRAG 399
#define MODE_CFG 400
#define PFS_GROUP 401
#define LIFETIME 402
#define LIFETYPE_TIME 403
#define LIFETYPE_BYTE 404
#define STRENGTH 405
#define REMOTEID 406
#define SCRIPT 407
#define PHASE1_UP 408
#define PHASE1_DOWN 409
#define PHASE1_DEAD 410
#define NUMBER 411
#define SWITCH 412
#define BOOLEAN 413
#define HEXSTRING 414
#define QUOTEDSTRING 415
#define ADDRSTRING 416
#define ADDRRANGE 417
#define UNITTYPE_BYTE 418
#define UNITTYPE_KBYTES 419
#define UNITTYPE_MBYTES 420
#define UNITTYPE_TBYTES 421
#define UNITTYPE_SEC 422
#define UNITTYPE_MIN 423
#define UNITTYPE_HOUR 424
#define EOS 425
#define BOC 426
#define EOC 427
#define COMMA 428

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 247 "cfparse.y"

	unsigned long num;
	vchar_t *val;
	struct remoteconf *rmconf;
	struct sockaddr *saddr;
	struct sainfoalg *alg;

#line 718 "cfparse.c"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;

int yyparse (void);

#endif /* !YY_YY_Y_TAB_H_INCLUDED  */



#ifdef short
# undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
# include <limits.h> /* INFRINGES ON USER NAME SPACE */
# if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#  define YY_STDINT_H
# endif
#endif

/* Narrow types that promote to a signed type and that can represent a
   signed or unsigned integer of at least N bits.  In tables they can
   save space and decrease cache pressure.  Promoting to a signed type
   helps avoid bugs in integer arithmetic.  */

#ifdef __INT_LEAST8_MAX__
typedef __INT_LEAST8_TYPE__ yytype_int8;
#elif defined YY_STDINT_H
typedef int_least8_t yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef __INT_LEAST16_MAX__
typedef __INT_LEAST16_TYPE__ yytype_int16;
#elif defined YY_STDINT_H
typedef int_least16_t yytype_int16;
#else
typedef short yytype_int16;
#endif

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
# if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#  define YYPTRDIFF_T __PTRDIFF_TYPE__
#  define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
# elif defined PTRDIFF_MAX
#  ifndef ptrdiff_t
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYPTRDIFF_T ptrdiff_t
#  define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
# else
#  define YYPTRDIFF_T long
#  define YYPTRDIFF_MAXIMUM LONG_MAX
# endif
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM                                  \
  YY_CAST (YYPTRDIFF_T,                                 \
           (YYPTRDIFF_MAXIMUM < YY_CAST (YYSIZE_T, -1)  \
            ? YYPTRDIFF_MAXIMUM                         \
            : YY_CAST (YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST (YYPTRDIFF_T, sizeof (X))

/* Stored state numbers (used for stacks). */
typedef yytype_int16 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif

#ifndef YY_ATTRIBUTE_PURE
# if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define YY_ATTRIBUTE_PURE
# endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# else
#  define YY_ATTRIBUTE_UNUSED
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && ! defined __ICC && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                            \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END      \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

#if defined __cplusplus && defined __GNUC__ && ! defined __ICC && 6 <= __GNUC__
# define YY_IGNORE_USELESS_CAST_BEGIN                          \
    _Pragma ("GCC diagnostic push")                            \
    _Pragma ("GCC diagnostic ignored \"-Wuseless-cast\"")
# define YY_IGNORE_USELESS_CAST_END            \
    _Pragma ("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_END
#endif


#define YY_ASSERT(E) ((void) (0 && (E)))

#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYPTRDIFF_T yynewbytes;                                         \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * YYSIZEOF (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF (*yyptr);                        \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, YY_CAST (YYSIZE_T, (Count)) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYPTRDIFF_T yyi;                      \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  2
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   534

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  174
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  204
/* YYNRULES -- Number of rules.  */
#define YYNRULES  381
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  691

#define YYUNDEFTOK  2
#define YYMAXUTOK   428


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79,    80,    81,    82,    83,    84,
      85,    86,    87,    88,    89,    90,    91,    92,    93,    94,
      95,    96,    97,    98,    99,   100,   101,   102,   103,   104,
     105,   106,   107,   108,   109,   110,   111,   112,   113,   114,
     115,   116,   117,   118,   119,   120,   121,   122,   123,   124,
     125,   126,   127,   128,   129,   130,   131,   132,   133,   134,
     135,   136,   137,   138,   139,   140,   141,   142,   143,   144,
     145,   146,   147,   148,   149,   150,   151,   152,   153,   154,
     155,   156,   157,   158,   159,   160,   161,   162,   163,   164,
     165,   166,   167,   168,   169,   170,   171,   172,   173
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   337,   337,   338,   341,   342,   343,   344,   345,   346,
     347,   348,   349,   350,   351,   352,   353,   354,   355,   360,
     363,   364,   368,   367,   378,   378,   380,   379,   390,   390,
     391,   391,   397,   396,   417,   417,   422,   436,   443,   455,
     458,   472,   475,   476,   479,   479,   480,   480,   481,   481,
     482,   482,   483,   483,   488,   491,   492,   496,   495,   502,
     501,   513,   512,   522,   521,   531,   530,   539,   539,   542,
     554,   555,   560,   560,   578,   579,   583,   582,   601,   600,
     619,   618,   637,   636,   655,   654,   664,   663,   676,   676,
     688,   689,   693,   692,   704,   703,   715,   714,   724,   723,
     735,   734,   744,   743,   755,   754,   766,   765,   777,   776,
     788,   787,   799,   798,   810,   809,   824,   827,   828,   832,
     831,   843,   842,   853,   855,   858,   857,   867,   866,   876,
     875,   883,   882,   895,   894,   904,   903,   917,   916,   930,
     929,   943,   942,   950,   949,   959,   958,   972,   971,   981,
     980,   990,   989,  1003,  1002,  1016,  1015,  1026,  1025,  1035,
    1034,  1044,  1043,  1053,  1052,  1062,  1061,  1075,  1074,  1088,
    1087,  1101,  1102,  1105,  1122,  1123,  1126,  1143,  1144,  1147,
    1170,  1171,  1174,  1208,  1209,  1212,  1249,  1252,  1253,  1257,
    1256,  1262,  1261,  1267,  1266,  1272,  1271,  1277,  1276,  1282,
    1281,  1298,  1306,  1297,  1345,  1350,  1355,  1360,  1365,  1370,
    1377,  1426,  1491,  1520,  1523,  1548,  1562,  1563,  1567,  1566,
    1572,  1571,  1577,  1576,  1582,  1581,  1593,  1593,  1600,  1605,
    1604,  1611,  1667,  1668,  1671,  1672,  1673,  1676,  1677,  1678,
    1681,  1682,  1688,  1687,  1718,  1717,  1738,  1737,  1761,  1760,
    1777,  1778,  1786,  1793,  1799,  1809,  1810,  1814,  1813,  1823,
    1822,  1827,  1827,  1828,  1828,  1829,  1831,  1830,  1851,  1850,
    1868,  1867,  1898,  1897,  1912,  1911,  1928,  1928,  1929,  1929,
    1930,  1930,  1931,  1931,  1933,  1932,  1942,  1941,  1951,  1950,
    1968,  1967,  1985,  1984,  2001,  2001,  2002,  2002,  2004,  2003,
    2009,  2009,  2010,  2010,  2011,  2011,  2012,  2012,  2022,  2022,
    2029,  2029,  2036,  2036,  2043,  2043,  2044,  2044,  2047,  2047,
    2048,  2048,  2049,  2049,  2050,  2050,  2052,  2051,  2063,  2062,
    2074,  2073,  2082,  2081,  2091,  2090,  2100,  2099,  2108,  2108,
    2109,  2109,  2111,  2110,  2116,  2115,  2120,  2120,  2122,  2121,
    2136,  2135,  2147,  2148,  2172,  2171,  2193,  2192,  2226,  2234,
    2246,  2247,  2248,  2251,  2252,  2256,  2255,  2261,  2260,  2273,
    2272,  2278,  2277,  2291,  2290,  2388,  2389,  2390,  2393,  2394,
    2395,  2396
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 0
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "PRIVSEP", "USER", "GROUP", "CHROOT",
  "PATH", "PATHTYPE", "INCLUDE", "PFKEY_BUFFER", "LOGGING", "LOGLEV",
  "PADDING", "PAD_RANDOMIZE", "PAD_RANDOMIZELEN", "PAD_MAXLEN",
  "PAD_STRICT", "PAD_EXCLTAIL", "LISTEN", "X_ISAKMP", "X_ISAKMP_NATT",
  "X_ADMIN", "STRICT_ADDRESS", "ADMINSOCK", "DISABLED", "LDAPCFG",
  "LDAP_HOST", "LDAP_PORT", "LDAP_PVER", "LDAP_BASE", "LDAP_BIND_DN",
  "LDAP_BIND_PW", "LDAP_SUBTREE", "LDAP_ATTR_USER", "LDAP_ATTR_ADDR",
  "LDAP_ATTR_MASK", "LDAP_ATTR_GROUP", "LDAP_ATTR_MEMBER", "RADCFG",
  "RAD_AUTH", "RAD_ACCT", "RAD_TIMEOUT", "RAD_RETRIES", "MODECFG",
  "CFG_NET4", "CFG_MASK4", "CFG_DNS4", "CFG_NBNS4", "CFG_DEFAULT_DOMAIN",
  "CFG_AUTH_SOURCE", "CFG_AUTH_GROUPS", "CFG_SYSTEM", "CFG_RADIUS",
  "CFG_PAM", "CFG_LDAP", "CFG_LOCAL", "CFG_NONE", "CFG_GROUP_SOURCE",
  "CFG_ACCOUNTING", "CFG_CONF_SOURCE", "CFG_MOTD", "CFG_POOL_SIZE",
  "CFG_AUTH_THROTTLE", "CFG_SPLIT_NETWORK", "CFG_SPLIT_LOCAL",
  "CFG_SPLIT_INCLUDE", "CFG_SPLIT_DNS", "CFG_PFS_GROUP", "CFG_SAVE_PASSWD",
  "RETRY", "RETRY_COUNTER", "RETRY_INTERVAL", "RETRY_PERSEND",
  "RETRY_PHASE1", "RETRY_PHASE2", "NATT_KA", "ALGORITHM_CLASS",
  "ALGORITHMTYPE", "STRENGTHTYPE", "SAINFO", "FROM", "REMOTE", "ANONYMOUS",
  "CLIENTADDR", "INHERIT", "REMOTE_ADDRESS", "EXCHANGE_MODE",
  "EXCHANGETYPE", "DOI", "DOITYPE", "SITUATION", "SITUATIONTYPE",
  "CERTIFICATE_TYPE", "CERTTYPE", "PEERS_CERTFILE", "CA_TYPE",
  "VERIFY_CERT", "SEND_CERT", "SEND_CR", "MATCH_EMPTY_CR",
  "IDENTIFIERTYPE", "IDENTIFIERQUAL", "MY_IDENTIFIER", "PEERS_IDENTIFIER",
  "VERIFY_IDENTIFIER", "DNSSEC", "CERT_X509", "CERT_PLAINRSA",
  "NONCE_SIZE", "DH_GROUP", "KEEPALIVE", "PASSIVE", "INITIAL_CONTACT",
  "NAT_TRAVERSAL", "REMOTE_FORCE_LEVEL", "PROPOSAL_CHECK",
  "PROPOSAL_CHECK_LEVEL", "GENERATE_POLICY", "GENERATE_LEVEL",
  "SUPPORT_PROXY", "PROPOSAL", "EXEC_PATH", "EXEC_COMMAND", "EXEC_SUCCESS",
  "EXEC_FAILURE", "GSS_ID", "GSS_ID_ENC", "GSS_ID_ENCTYPE",
  "COMPLEX_BUNDLE", "DPD", "DPD_DELAY", "DPD_RETRY", "DPD_MAXFAIL",
  "PH1ID", "XAUTH_LOGIN", "WEAK_PHASE1_CHECK", "REKEY", "PREFIX", "PORT",
  "PORTANY", "UL_PROTO", "ANY", "IKE_FRAG", "ESP_FRAG", "MODE_CFG",
  "PFS_GROUP", "LIFETIME", "LIFETYPE_TIME", "LIFETYPE_BYTE", "STRENGTH",
  "REMOTEID", "SCRIPT", "PHASE1_UP", "PHASE1_DOWN", "PHASE1_DEAD",
  "NUMBER", "SWITCH", "BOOLEAN", "HEXSTRING", "QUOTEDSTRING", "ADDRSTRING",
  "ADDRRANGE", "UNITTYPE_BYTE", "UNITTYPE_KBYTES", "UNITTYPE_MBYTES",
  "UNITTYPE_TBYTES", "UNITTYPE_SEC", "UNITTYPE_MIN", "UNITTYPE_HOUR",
  "EOS", "BOC", "EOC", "COMMA", "$accept", "statements", "statement",
  "privsep_statement", "privsep_stmts", "privsep_stmt", "$@1", "$@2",
  "$@3", "$@4", "$@5", "path_statement", "$@6", "special_statement", "$@7",
  "include_statement", "pfkey_statement", "gssenc_statement",
  "logging_statement", "log_level", "padding_statement", "padding_stmts",
  "padding_stmt", "$@8", "$@9", "$@10", "$@11", "$@12", "listen_statement",
  "listen_stmts", "listen_stmt", "$@13", "$@14", "$@15", "$@16", "$@17",
  "$@18", "ike_addrinfo_port", "ike_port", "radcfg_statement", "$@19",
  "radcfg_stmts", "radcfg_stmt", "$@20", "$@21", "$@22", "$@23", "$@24",
  "$@25", "ldapcfg_statement", "$@26", "ldapcfg_stmts", "ldapcfg_stmt",
  "$@27", "$@28", "$@29", "$@30", "$@31", "$@32", "$@33", "$@34", "$@35",
  "$@36", "$@37", "$@38", "modecfg_statement", "modecfg_stmts",
  "modecfg_stmt", "$@39", "$@40", "$@41", "$@42", "$@43", "$@44", "$@45",
  "$@46", "$@47", "$@48", "$@49", "$@50", "$@51", "$@52", "$@53", "$@54",
  "$@55", "$@56", "$@57", "$@58", "$@59", "$@60", "$@61", "$@62", "$@63",
  "addrdnslist", "addrdns", "addrwinslist", "addrwins", "splitnetlist",
  "splitnet", "authgrouplist", "authgroup", "splitdnslist", "splitdns",
  "timer_statement", "timer_stmts", "timer_stmt", "$@64", "$@65", "$@66",
  "$@67", "$@68", "$@69", "sainfo_statement", "$@70", "$@71",
  "sainfo_name", "sainfo_id", "sainfo_param", "sainfo_specs",
  "sainfo_spec", "$@72", "$@73", "$@74", "$@75", "$@76", "algorithms",
  "$@77", "algorithm", "prefix", "port", "ul_proto", "keylength",
  "remote_statement", "$@78", "$@79", "$@80", "$@81",
  "remote_specs_inherit_block", "remote_specs_block", "remote_index",
  "remote_specs", "remote_spec", "$@82", "$@83", "$@84", "$@85", "$@86",
  "$@87", "$@88", "$@89", "$@90", "$@91", "$@92", "$@93", "$@94", "$@95",
  "$@96", "$@97", "$@98", "$@99", "$@100", "$@101", "$@102", "$@103",
  "$@104", "$@105", "$@106", "$@107", "$@108", "$@109", "$@110", "$@111",
  "$@112", "$@113", "$@114", "$@115", "$@116", "$@117", "$@118", "$@119",
  "$@120", "$@121", "$@122", "$@123", "$@124", "$@125", "$@126", "$@127",
  "$@128", "exchange_types", "cert_spec", "$@129", "$@130", "dh_group_num",
  "identifierstring", "isakmpproposal_specs", "isakmpproposal_spec",
  "$@131", "$@132", "$@133", "$@134", "$@135", "unittype_time",
  "unittype_byte", YY_NULLPTR
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_int16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325,   326,   327,   328,   329,   330,   331,   332,   333,   334,
     335,   336,   337,   338,   339,   340,   341,   342,   343,   344,
     345,   346,   347,   348,   349,   350,   351,   352,   353,   354,
     355,   356,   357,   358,   359,   360,   361,   362,   363,   364,
     365,   366,   367,   368,   369,   370,   371,   372,   373,   374,
     375,   376,   377,   378,   379,   380,   381,   382,   383,   384,
     385,   386,   387,   388,   389,   390,   391,   392,   393,   394,
     395,   396,   397,   398,   399,   400,   401,   402,   403,   404,
     405,   406,   407,   408,   409,   410,   411,   412,   413,   414,
     415,   416,   417,   418,   419,   420,   421,   422,   423,   424,
     425,   426,   427,   428
};
# endif

#define YYPACT_NINF (-542)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-230)

#define yytable_value_is_error(Yyn) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
    -542,    42,  -542,  -124,    46,   -87,   -72,    82,   -63,   -39,
    -542,  -542,   -29,   -15,  -542,   -50,    34,     7,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,    12,    10,    21,  -542,    25,
    -542,  -542,    38,    40,  -542,  -542,    30,    66,    89,    66,
    -542,   143,    37,  -542,     3,  -542,  -542,  -542,  -542,    -4,
      -5,  -542,  -542,    29,    -9,    35,   -11,    36,    45,  -542,
    -542,    72,    63,  -542,   -45,    63,  -542,    71,   -53,   -13,
      76,  -542,  -542,    73,    85,    87,    90,    88,    99,  -542,
    -542,    94,    94,  -542,    -8,  -542,  -542,    -7,    -6,    96,
      97,   102,   104,   107,   106,   108,    54,    81,     4,   110,
     103,   115,   122,   112,   118,   109,  -542,  -542,   119,   120,
     121,   123,   124,   125,  -542,  -542,  -542,  -542,  -542,   -90,
     113,   177,   111,  -542,  -542,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,   114,  -542,   126,   127,   129,
     132,   130,   131,   133,   135,   134,   136,   137,   138,   139,
    -542,  -542,   140,   141,   146,   147,  -542,  -542,  -542,  -542,
    -542,   142,   144,  -542,   145,   148,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,   149,  -542,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,   150,   150,  -542,  -542,
     151,  -542,  -542,  -542,    14,  -542,    14,    14,    14,  -542,
     157,    50,  -542,    32,  -542,    27,   117,    27,   153,   155,
     156,   158,   159,   160,   161,   162,   163,   164,   165,   166,
    -542,   167,   154,   168,  -542,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,   -12,    -3,  -542,  -542,
     169,   170,  -542,   102,  -542,   104,   171,   173,   174,   175,
     176,   178,   108,   179,   180,   181,   182,   183,   184,   185,
     187,   188,   189,   190,   191,   172,   192,  -542,   192,   193,
     112,   194,   196,   197,  -542,  -542,  -542,  -542,   198,  -542,
    -542,  -542,    50,  -542,  -542,    -1,  -542,  -542,  -542,   -21,
    -542,  -542,  -542,    94,  -542,   214,   213,    92,   -37,   199,
     152,   205,   212,   215,   206,   207,   216,   218,  -542,   219,
     220,   -57,   201,   -75,   221,  -542,   222,   224,   225,   226,
     227,    32,   228,   -30,   -20,   230,   231,    70,   210,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,   233,  -542,   217,   223,   229,
     232,   234,   235,   236,   237,   238,   239,   240,   241,   211,
    -542,   243,  -542,   242,   244,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,   150,
     245,   246,  -542,  -542,  -542,  -542,  -542,   247,  -542,   248,
     249,   250,    -1,  -542,  -542,  -542,  -542,  -542,   -38,    75,
     257,   203,  -542,  -542,  -542,  -542,  -542,   261,   262,  -542,
    -542,   263,   264,  -542,   265,  -542,  -542,  -542,  -542,   -59,
     -56,  -542,  -542,   -38,  -542,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,   255,  -542,  -542,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,   271,   272,    31,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,   259,  -542,   260,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,   269,  -542,  -542,  -542,
     275,   276,  -542,  -542,   266,   -49,   267,   268,   273,  -542,
     270,  -542,  -542,   274,  -542,   277,   278,   279,   280,    32,
    -542,    32,  -542,   281,   282,   283,   284,   285,   286,   287,
     288,   289,   290,   291,  -542,   292,   294,   295,   296,   297,
     298,   299,   300,   301,   302,   303,   304,   305,    14,    13,
    -542,  -542,  -542,   306,   307,  -542,   308,  -542,   323,   310,
     309,   311,    14,    13,   313,  -542,  -542,  -542,  -542,  -542,
    -542,   314,  -542,   315,   316,  -542,   317,  -542,  -542,  -542,
    -542,  -542,   318,  -542,   319,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,   -27,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,   320,   321,   322,  -542,
    -542,  -542,  -542,  -542,  -542,   324,  -542,  -542,  -542,  -542,
     325,  -542,  -542,  -542,  -542,   326,  -542,   328,  -542,   312,
     -38,   333,    91,  -542,  -542,   329,   330,  -542,  -542,  -542,
     269,   331,   332,  -542,  -542,  -542,   323,  -542,  -542,   338,
     347,  -542,  -542,  -542,  -542,  -542,  -542,   334,   335,    14,
      13,   336,  -542,  -542,  -542,  -542,  -542,   337,   339,  -542,
    -542
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_int16 yydefact[] =
{
       2,     0,     1,     0,     0,     0,     0,     0,     0,     0,
      88,    72,     0,     0,   201,     0,     0,     0,     3,     4,
       5,    18,     6,     7,     8,     9,    10,    11,    13,    12,
      14,    15,    16,    17,    20,     0,     0,     0,    40,     0,
      42,    55,     0,     0,   117,   187,     0,    70,   244,    70,
     254,   248,     0,    34,     0,    32,    36,    37,    39,     0,
       0,    90,    74,     0,     0,   204,     0,   213,     0,    71,
     253,     0,     0,    69,     0,     0,    38,     0,     0,     0,
       0,    19,    21,     0,     0,     0,     0,     0,     0,    41,
      43,     0,     0,    67,     0,    54,    56,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   116,   118,     0,     0,
       0,     0,     0,     0,   186,   188,   205,   206,   212,   232,
       0,     0,     0,   207,   208,   209,   242,   255,   245,   246,
     249,    35,    24,    22,    28,    26,    30,    33,    44,    46,
      48,    50,    52,    57,    59,     0,    65,    63,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      89,    91,     0,     0,     0,     0,    73,    75,   119,   121,
     173,     0,   171,   176,     0,   174,   131,   133,   135,   137,
     139,   182,   141,   180,   143,   145,   149,   151,   153,   147,
     165,   167,   163,   169,   155,   161,     0,     0,   185,   129,
     183,   157,   159,   189,     0,   193,     0,     0,     0,   233,
     232,   234,   215,   360,   216,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      68,     0,     0,     0,    94,    96,    92,    98,   102,   104,
     100,   106,   108,   110,   112,   114,     0,     0,    84,    86,
       0,     0,   123,     0,   124,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   125,   177,   127,     0,
       0,     0,     0,     0,   375,   376,   377,   191,     0,   195,
     197,   199,   234,   235,   236,     0,   362,   361,   214,   202,
     251,   243,   250,     0,   259,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   298,     0,
       0,     0,     0,     0,     0,   350,     0,     0,     0,     0,
       0,   360,     0,     0,     0,     0,     0,     0,     0,   252,
     256,   247,    25,    23,    29,    27,    31,    45,    47,    49,
      51,    53,    58,    60,    66,     0,    64,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      76,     0,    80,     0,     0,   120,   122,   172,   175,   132,
     134,   136,   138,   140,   142,   181,   144,   146,   150,   152,
     154,   148,   166,   168,   164,   170,   156,   162,   179,     0,
       0,     0,   130,   184,   158,   160,   190,     0,   194,     0,
       0,     0,     0,   238,   239,   237,   210,   226,     0,     0,
       0,     0,   217,   257,   352,   261,   263,     0,     0,   265,
     272,     0,     0,   266,     0,   276,   278,   280,   282,   360,
     360,   294,   296,     0,   300,   324,   328,   326,   346,   320,
     318,   322,     0,   330,   332,   334,   336,   342,   288,   316,
     340,   338,   304,   302,   306,   314,     0,     0,     0,    61,
      95,    97,    93,    99,   103,   105,   101,   107,   109,   111,
     113,   115,    78,     0,    82,     0,    85,    87,   178,   126,
     128,   192,   196,   198,   200,   211,     0,   358,   359,   218,
       0,     0,   220,   203,     0,     0,     0,     0,     0,   356,
       0,   268,   270,     0,   274,     0,     0,     0,     0,   360,
     284,   360,   290,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   363,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     308,   310,   312,     0,     0,    77,     0,    81,   240,     0,
     228,     0,     0,     0,     0,   258,   353,   260,   262,   264,
     354,     0,   273,     0,     0,   267,     0,   277,   279,   281,
     283,   286,     0,   292,     0,   295,   297,   299,   301,   325,
     329,   327,   347,   321,   319,   323,     0,   331,   333,   335,
     337,   343,   289,   317,   341,   339,   305,   303,   307,   315,
     344,   378,   379,   380,   381,   348,     0,     0,     0,    62,
      79,    83,   241,   231,   227,     0,   219,   222,   224,   221,
       0,   357,   269,   271,   275,     0,   285,     0,   291,     0,
       0,     0,     0,   351,   364,     0,     0,   309,   311,   313,
       0,     0,     0,   355,   287,   293,   240,   369,   371,     0,
       0,   345,   349,   230,   223,   225,   373,     0,     0,     0,
       0,     0,   370,   372,   365,   367,   374,     0,     0,   366,
     368
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,  -542,   -88,   342,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,    20,  -542,    48,  -542,   327,   -93,    47,
    -542,   105,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,    86,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,  -340,  -542,  -542,   293,    95,
     -95,  -282,  -542,  -542,  -542,  -542,  -542,   208,    98,   360,
    -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -542,  -448,  -335,  -542,  -542,  -542,  -542,  -542,
    -542,  -542,  -216,  -541
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,    18,    19,    54,    82,   229,   228,   231,   230,
     232,    20,    83,    21,    77,    22,    23,    24,    25,    39,
      26,    59,    90,   233,   234,   235,   236,   237,    27,    60,
      96,   238,   239,   563,   243,   241,   155,    50,    70,    28,
      43,    98,   177,   493,   564,   495,   566,   383,   384,    29,
      42,    97,   171,   369,   367,   368,   370,   373,   371,   372,
     374,   375,   376,   377,   378,    30,    63,   117,   260,   261,
     410,   411,   289,   266,   267,   268,   269,   270,   271,   273,
     274,   278,   275,   276,   277,   283,   291,   292,   284,   281,
     279,   280,   282,   181,   182,   184,   185,   286,   287,   192,
     193,   209,   210,    31,    64,   125,   293,   417,   298,   419,
     420,   421,    32,    46,   431,    67,    68,   132,   309,   432,
     571,   574,   661,   662,   506,   569,   635,   570,   221,   305,
     426,   633,    33,   225,    72,   227,    75,   311,   312,    51,
     226,   350,   514,   434,   516,   517,   523,   583,   584,   520,
     586,   525,   526,   527,   528,   592,   645,   550,   594,   647,
     533,   534,   453,   536,   555,   554,   556,   626,   627,   628,
     557,   551,   542,   541,   543,   537,   539,   538,   545,   546,
     547,   548,   553,   552,   549,   655,   540,   656,   462,   515,
     439,   640,   581,   509,   308,   606,   654,   687,   688,   677,
     678,   681,   297,   625
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
     299,   300,   301,   153,   154,   535,   468,    78,    79,    80,
      84,    85,    86,    87,    88,    91,    92,   156,    93,    94,
     158,   159,   160,   161,   162,   163,   164,   165,   166,   167,
     168,   169,   638,    47,   172,   173,   174,   175,    47,   576,
     507,   130,     2,   529,   459,     3,   531,    34,   219,     4,
     649,     5,     6,     7,    35,     8,   427,   200,   456,   201,
     202,     9,   118,   119,   120,   121,   122,   123,    10,   440,
     441,   442,   220,    36,    99,   100,   101,   102,   103,   104,
     105,    11,   460,   650,    37,   470,    12,   106,   107,   108,
     109,   110,   111,   112,    38,   472,   113,   114,   115,   651,
     457,   306,   307,   142,   306,   307,   194,   143,    40,   195,
      48,    49,    13,    65,   530,   532,    49,   131,   508,   126,
     652,   577,    14,   443,    15,   428,   429,   471,   133,   134,
     430,    66,    41,   196,   197,   198,    66,   473,   199,   685,
     423,   424,    44,   144,   379,   653,    66,   145,   380,   128,
     129,   127,   157,   381,   135,   425,    45,   382,   187,   188,
     189,   190,    52,   124,    53,   170,   176,    95,    89,    16,
     138,    17,    55,   140,    71,    81,   621,   622,   623,   624,
      56,   294,   295,   296,   560,   561,   562,   206,   207,   303,
     304,    57,   306,   307,   591,    58,   593,   310,   137,   437,
     438,   116,   667,   313,   314,    69,   315,    76,   316,    61,
     317,    62,   318,   319,   320,   321,   322,   323,   476,   477,
     324,   325,   326,   510,   511,   433,   327,   328,    74,   329,
     330,   331,   136,   332,   137,   333,   146,   334,   335,   669,
     670,   141,   148,   147,   149,   151,   150,   336,   337,   338,
     339,   340,   341,   342,   343,    49,   152,   178,   179,   204,
     344,   345,   346,   180,   347,   183,   212,   186,   191,   348,
     203,   205,   208,   222,   211,   213,   214,   215,   223,   216,
     217,   218,   224,   387,   240,   245,   242,   244,   246,   349,
     247,   248,   250,   249,   251,   219,   252,   253,   254,   255,
     256,   257,   258,   259,   435,   436,   444,   449,   450,   445,
     408,   285,   262,   388,   365,   264,   498,   263,   458,   395,
     673,   265,   272,   352,   290,   353,   354,   505,   355,   356,
     357,   358,   359,   360,   361,   362,   363,   364,   366,   385,
     386,   389,   620,   390,   391,   392,   393,   568,   394,   396,
     397,   398,   399,   400,   401,   402,   637,   403,   404,   405,
     406,   407,   446,   412,   414,   409,   415,   416,   418,   447,
     478,   492,   448,   451,   452,   513,   454,   455,   461,   463,
     464,   465,   466,   467,   676,   469,   474,   480,   475,   479,
     666,    73,     0,   481,     0,   413,     0,   422,     0,   482,
       0,     0,   483,   494,   484,   485,   486,   487,   488,   489,
     490,   491,   496,   512,   497,   499,   500,   501,   502,   503,
     504,   518,   519,   521,   522,   524,   544,   558,   559,   565,
     567,   572,   573,   580,   139,   351,   575,   578,   579,     0,
     582,     0,     0,     0,   585,     0,     0,   587,   588,   589,
     590,   595,   596,   597,   598,   599,   600,   601,   602,   603,
     604,   605,   607,   684,   608,   609,   610,   611,   612,   613,
     614,   615,   616,   617,   618,   619,   629,   630,   631,   632,
     634,   636,  -229,   639,   641,   642,   643,   644,   646,   648,
     657,   658,   659,   668,   679,   663,   664,   660,   665,   671,
     672,   674,   675,   680,   682,   683,   686,   689,     0,   690,
       0,     0,     0,   302,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   288
};

static const yytype_int16 yycheck[] =
{
     216,   217,   218,    91,    92,   453,   341,     4,     5,     6,
      14,    15,    16,    17,    18,    20,    21,    25,    23,    24,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,   573,    83,    40,    41,    42,    43,    83,    88,
      78,     5,     0,   102,   119,     3,   102,   171,   138,     7,
      77,     9,    10,    11,     8,    13,    77,    53,   115,    55,
      56,    19,    71,    72,    73,    74,    75,    76,    26,   106,
     107,   108,   162,   160,    45,    46,    47,    48,    49,    50,
      51,    39,   157,   110,   156,   115,    44,    58,    59,    60,
      61,    62,    63,    64,    12,   115,    67,    68,    69,   126,
     157,   160,   161,   156,   160,   161,    52,   160,   171,    55,
     160,   161,    70,    83,   449,   450,   161,    81,   156,    84,
     147,   170,    80,   160,    82,   146,   147,   157,    83,    84,
     151,   101,   171,    52,    53,    54,   101,   157,    57,   680,
     141,   142,   171,   156,   156,   172,   101,   160,   160,   160,
     161,    65,   160,   156,    68,   156,   171,   160,    52,    53,
      54,    55,   128,   172,   157,   172,   172,   172,   172,   127,
      72,   129,   160,    75,    85,   172,   163,   164,   165,   166,
     170,   167,   168,   169,   153,   154,   155,    65,    66,   139,
     140,   170,   160,   161,   529,   170,   531,   170,   171,   107,
     108,   172,   650,    86,    87,   139,    89,   170,    91,   171,
      93,   171,    95,    96,    97,    98,    99,   100,   148,   149,
     103,   104,   105,   148,   149,   313,   109,   110,    85,   112,
     113,   114,   160,   116,   171,   118,   160,   120,   121,   148,
     149,   170,   157,   170,   157,   157,   156,   130,   131,   132,
     133,   134,   135,   136,   137,   161,   157,   161,   161,   156,
     143,   144,   145,   161,   147,   161,   157,   160,   160,   152,
     160,   156,   160,   160,   156,   156,   156,   156,   101,   156,
     156,   156,   171,   263,   170,   156,   160,   160,   156,   172,
     160,   160,   157,   160,   160,   138,   160,   160,   160,   160,
     160,   160,   156,   156,    90,    92,   107,   101,   101,   157,
     138,   161,   170,   265,   160,   170,   409,   173,   117,   272,
     660,   173,   173,   170,   173,   170,   170,   422,   170,   170,
     170,   170,   170,   170,   170,   170,   170,   170,   170,   170,
     170,   170,   558,   170,   170,   170,   170,    78,   170,   170,
     170,   170,   170,   170,   170,   170,   572,   170,   170,   170,
     170,   170,   157,   170,   170,   173,   170,   170,   170,   157,
     160,   160,   157,   157,   156,   172,   157,   157,   157,   157,
     156,   156,   156,   156,   666,   157,   156,   170,   157,   156,
      78,    49,    -1,   170,    -1,   290,    -1,   302,    -1,   170,
      -1,    -1,   170,   160,   170,   170,   170,   170,   170,   170,
     170,   170,   170,   156,   170,   170,   170,   170,   170,   170,
     170,   160,   160,   160,   160,   160,   171,   156,   156,   170,
     170,   156,   156,   160,    74,   227,   170,   170,   170,    -1,
     170,    -1,    -1,    -1,   170,    -1,    -1,   170,   170,   170,
     170,   170,   170,   170,   170,   170,   170,   170,   170,   170,
     170,   170,   170,   679,   170,   170,   170,   170,   170,   170,
     170,   170,   170,   170,   170,   170,   170,   170,   170,   156,
     170,   170,   173,   170,   170,   170,   170,   170,   170,   170,
     170,   170,   170,   160,   156,   170,   170,   173,   170,   170,
     170,   170,   170,   156,   170,   170,   170,   170,    -1,   170,
      -1,    -1,    -1,   220,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   207
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_int16 yystos[] =
{
       0,   175,     0,     3,     7,     9,    10,    11,    13,    19,
      26,    39,    44,    70,    80,    82,   127,   129,   176,   177,
     185,   187,   189,   190,   191,   192,   194,   202,   213,   223,
     239,   277,   286,   306,   171,     8,   160,   156,    12,   193,
     171,   171,   224,   214,   171,   171,   287,    83,   160,   161,
     211,   313,   128,   157,   178,   160,   170,   170,   170,   195,
     203,   171,   171,   240,   278,    83,   101,   289,   290,   139,
     212,    85,   308,   212,    85,   310,   170,   188,     4,     5,
       6,   172,   179,   186,    14,    15,    16,    17,    18,   172,
     196,    20,    21,    23,    24,   172,   204,   225,   215,    45,
      46,    47,    48,    49,    50,    51,    58,    59,    60,    61,
      62,    63,    64,    67,    68,    69,   172,   241,    71,    72,
      73,    74,    75,    76,   172,   279,    84,   290,   160,   161,
       5,    81,   291,    83,    84,   290,   160,   171,   312,   313,
     312,   170,   156,   160,   156,   160,   160,   170,   157,   157,
     156,   157,   157,   211,   211,   210,    25,   160,    27,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
     172,   226,    40,    41,    42,    43,   172,   216,   161,   161,
     161,   267,   268,   161,   269,   270,   160,    52,    53,    54,
      55,   160,   273,   274,    52,    55,    52,    53,    54,    57,
      53,    55,    56,   160,   156,   156,    65,    66,   160,   275,
     276,   156,   157,   156,   156,   156,   156,   156,   156,   138,
     162,   302,   160,   101,   171,   307,   314,   309,   181,   180,
     183,   182,   184,   197,   198,   199,   200,   201,   205,   206,
     170,   209,   160,   208,   160,   156,   156,   160,   160,   160,
     157,   160,   160,   160,   160,   160,   160,   160,   156,   156,
     242,   243,   170,   173,   170,   173,   247,   248,   249,   250,
     251,   252,   173,   253,   254,   256,   257,   258,   255,   264,
     265,   263,   266,   259,   262,   161,   271,   272,   271,   246,
     173,   260,   261,   280,   167,   168,   169,   376,   282,   376,
     376,   376,   302,   139,   140,   303,   160,   161,   368,   292,
     170,   311,   312,    86,    87,    89,    91,    93,    95,    96,
      97,    98,    99,   100,   103,   104,   105,   109,   110,   112,
     113,   114,   116,   118,   120,   121,   130,   131,   132,   133,
     134,   135,   136,   137,   143,   144,   145,   147,   152,   172,
     315,   311,   170,   170,   170,   170,   170,   170,   170,   170,
     170,   170,   170,   170,   170,   160,   170,   228,   229,   227,
     230,   232,   233,   231,   234,   235,   236,   237,   238,   156,
     160,   156,   160,   221,   222,   170,   170,   267,   269,   170,
     170,   170,   170,   170,   170,   273,   170,   170,   170,   170,
     170,   170,   170,   170,   170,   170,   170,   170,   138,   173,
     244,   245,   170,   275,   170,   170,   170,   281,   170,   283,
     284,   285,   303,   141,   142,   156,   304,    77,   146,   147,
     151,   288,   293,   211,   317,    90,    92,   107,   108,   364,
     106,   107,   108,   160,   107,   157,   157,   157,   157,   101,
     101,   157,   156,   336,   157,   157,   115,   157,   117,   119,
     157,   157,   362,   157,   156,   156,   156,   156,   368,   157,
     115,   157,   115,   157,   156,   157,   148,   149,   160,   156,
     170,   170,   170,   170,   170,   170,   170,   170,   170,   170,
     170,   170,   160,   217,   160,   219,   170,   170,   272,   170,
     170,   170,   170,   170,   170,   304,   298,    78,   156,   367,
     148,   149,   156,   172,   316,   363,   318,   319,   160,   160,
     323,   160,   160,   320,   160,   325,   326,   327,   328,   102,
     368,   102,   368,   334,   335,   367,   337,   349,   351,   350,
     360,   347,   346,   348,   171,   352,   353,   354,   355,   358,
     331,   345,   357,   356,   339,   338,   340,   344,   156,   156,
     153,   154,   155,   207,   218,   170,   220,   170,    78,   299,
     301,   294,   156,   156,   295,   170,    88,   170,   170,   170,
     160,   366,   170,   321,   322,   170,   324,   170,   170,   170,
     170,   368,   329,   368,   332,   170,   170,   170,   170,   170,
     170,   170,   170,   170,   170,   170,   369,   170,   170,   170,
     170,   170,   170,   170,   170,   170,   170,   170,   170,   170,
     376,   163,   164,   165,   166,   377,   341,   342,   343,   170,
     170,   170,   156,   305,   170,   300,   170,   376,   377,   170,
     365,   170,   170,   170,   170,   330,   170,   333,   170,    77,
     110,   126,   147,   172,   370,   359,   361,   170,   170,   170,
     173,   296,   297,   170,   170,   170,    78,   367,   160,   148,
     149,   170,   170,   299,   170,   170,   305,   373,   374,   156,
     156,   375,   170,   170,   376,   377,   170,   371,   372,   170,
     170
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_int16 yyr1[] =
{
       0,   174,   175,   175,   176,   176,   176,   176,   176,   176,
     176,   176,   176,   176,   176,   176,   176,   176,   176,   177,
     178,   178,   180,   179,   181,   179,   182,   179,   183,   179,
     184,   179,   186,   185,   188,   187,   189,   190,   191,   192,
     193,   194,   195,   195,   197,   196,   198,   196,   199,   196,
     200,   196,   201,   196,   202,   203,   203,   205,   204,   206,
     204,   207,   204,   208,   204,   209,   204,   210,   204,   211,
     212,   212,   214,   213,   215,   215,   217,   216,   218,   216,
     219,   216,   220,   216,   221,   216,   222,   216,   224,   223,
     225,   225,   227,   226,   228,   226,   229,   226,   230,   226,
     231,   226,   232,   226,   233,   226,   234,   226,   235,   226,
     236,   226,   237,   226,   238,   226,   239,   240,   240,   242,
     241,   243,   241,   241,   241,   244,   241,   245,   241,   246,
     241,   247,   241,   248,   241,   249,   241,   250,   241,   251,
     241,   252,   241,   253,   241,   254,   241,   255,   241,   256,
     241,   257,   241,   258,   241,   259,   241,   260,   241,   261,
     241,   262,   241,   263,   241,   264,   241,   265,   241,   266,
     241,   267,   267,   268,   269,   269,   270,   271,   271,   272,
     273,   273,   274,   275,   275,   276,   277,   278,   278,   280,
     279,   281,   279,   282,   279,   283,   279,   284,   279,   285,
     279,   287,   288,   286,   289,   289,   289,   289,   289,   289,
     290,   290,   290,   291,   291,   291,   292,   292,   294,   293,
     295,   293,   296,   293,   297,   293,   298,   293,   299,   300,
     299,   301,   302,   302,   303,   303,   303,   304,   304,   304,
     305,   305,   307,   306,   308,   306,   309,   306,   310,   306,
     311,   311,   312,   313,   313,   314,   314,   316,   315,   317,
     315,   318,   315,   319,   315,   315,   320,   315,   321,   315,
     322,   315,   323,   315,   324,   315,   325,   315,   326,   315,
     327,   315,   328,   315,   329,   315,   330,   315,   331,   315,
     332,   315,   333,   315,   334,   315,   335,   315,   336,   315,
     337,   315,   338,   315,   339,   315,   340,   315,   341,   315,
     342,   315,   343,   315,   344,   315,   345,   315,   346,   315,
     347,   315,   348,   315,   349,   315,   350,   315,   351,   315,
     352,   315,   353,   315,   354,   315,   355,   315,   356,   315,
     357,   315,   358,   315,   359,   315,   360,   315,   361,   315,
     362,   315,   363,   363,   365,   364,   366,   364,   367,   367,
     368,   368,   368,   369,   369,   371,   370,   372,   370,   373,
     370,   374,   370,   375,   370,   376,   376,   376,   377,   377,
     377,   377
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     0,     2,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     4,
       0,     2,     0,     4,     0,     4,     0,     4,     0,     4,
       0,     4,     0,     5,     0,     4,     3,     3,     3,     3,
       1,     4,     0,     2,     0,     4,     0,     4,     0,     4,
       0,     4,     0,     4,     4,     0,     2,     0,     4,     0,
       4,     0,     7,     0,     4,     0,     4,     0,     3,     2,
       0,     1,     0,     5,     0,     2,     0,     5,     0,     6,
       0,     5,     0,     6,     0,     4,     0,     4,     0,     5,
       0,     2,     0,     4,     0,     4,     0,     4,     0,     4,
       0,     4,     0,     4,     0,     4,     0,     4,     0,     4,
       0,     4,     0,     4,     0,     4,     4,     0,     2,     0,
       4,     0,     4,     3,     3,     0,     5,     0,     5,     0,
       4,     0,     4,     0,     4,     0,     4,     0,     4,     0,
       4,     0,     4,     0,     4,     0,     4,     0,     4,     0,
       4,     0,     4,     0,     4,     0,     4,     0,     4,     0,
       4,     0,     4,     0,     4,     0,     4,     0,     4,     0,
       4,     1,     3,     1,     1,     3,     1,     1,     3,     2,
       1,     3,     1,     1,     3,     1,     4,     0,     2,     0,
       4,     0,     5,     0,     4,     0,     5,     0,     5,     0,
       5,     0,     0,     8,     1,     2,     2,     2,     2,     2,
       5,     6,     2,     0,     3,     2,     0,     2,     0,     4,
       0,     4,     0,     6,     0,     6,     0,     4,     1,     0,
       4,     2,     0,     1,     0,     1,     1,     1,     1,     1,
       0,     1,     0,     6,     0,     4,     0,     6,     0,     4,
       1,     1,     3,     2,     1,     0,     2,     0,     4,     0,
       4,     0,     4,     0,     4,     2,     0,     4,     0,     5,
       0,     5,     0,     4,     0,     5,     0,     4,     0,     4,
       0,     4,     0,     4,     0,     5,     0,     6,     0,     4,
       0,     5,     0,     6,     0,     4,     0,     4,     0,     4,
       0,     4,     0,     4,     0,     4,     0,     4,     0,     5,
       0,     5,     0,     5,     0,     4,     0,     4,     0,     4,
       0,     4,     0,     4,     0,     4,     0,     4,     0,     4,
       0,     4,     0,     4,     0,     4,     0,     4,     0,     4,
       0,     4,     0,     4,     0,     6,     0,     4,     0,     6,
       0,     5,     0,     2,     0,     5,     0,     4,     1,     1,
       0,     1,     1,     0,     2,     0,     6,     0,     6,     0,
       4,     0,     4,     0,     5,     1,     1,     1,     1,     1,
       1,     1
};


#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == YYEMPTY)                                        \
      {                                                           \
        yychar = (Token);                                         \
        yylval = (Value);                                         \
        YYPOPSTACK (yylen);                                       \
        yystate = *yyssp;                                         \
        goto yybackup;                                            \
      }                                                           \
    else                                                          \
      {                                                           \
        yyerror (YY_("syntax error: cannot back up")); \
        YYERROR;                                                  \
      }                                                           \
  while (0)

/* Error token number */
#define YYTERROR        1
#define YYERRCODE       256



/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)

/* This macro is provided for backward compatibility. */
#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


# define YY_SYMBOL_PRINT(Title, Type, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Type, Value); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo, int yytype, YYSTYPE const * const yyvaluep)
{
  FILE *yyoutput = yyo;
  YYUSE (yyoutput);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyo, yytoknum[yytype], *yyvaluep);
# endif
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo, int yytype, YYSTYPE const * const yyvaluep)
{
  YYFPRINTF (yyo, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  yy_symbol_value_print (yyo, yytype, yyvaluep);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yy_state_t *yybottom, yy_state_t *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp, int yyrule)
{
  int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %d):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       yystos[+yyssp[yyi + 1 - yynrhs]],
                       &yyvsp[(yyi + 1) - (yynrhs)]
                                              );
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen(S) (YY_CAST (YYPTRDIFF_T, strlen (S)))
#  else
/* Return the length of YYSTR.  */
static YYPTRDIFF_T
yystrlen (const char *yystr)
{
  YYPTRDIFF_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYPTRDIFF_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYPTRDIFF_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            else
              goto append;

          append:
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (yyres)
    return yystpcpy (yyres, yystr) - yyres;
  else
    return yystrlen (yystr);
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYPTRDIFF_T *yymsg_alloc, char **yymsg,
                yy_state_t *yyssp, int yytoken)
{
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat: reported tokens (one for the "unexpected",
     one per "expected"). */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Actual size of YYARG. */
  int yycount = 0;
  /* Cumulated lengths of YYARG.  */
  YYPTRDIFF_T yysize = 0;

  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[+*yyssp];
      YYPTRDIFF_T yysize0 = yytnamerr (YY_NULLPTR, yytname[yytoken]);
      yysize = yysize0;
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYPTRDIFF_T yysize1
                    = yysize + yytnamerr (YY_NULLPTR, yytname[yyx]);
                  if (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM)
                    yysize = yysize1;
                  else
                    return 2;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
    default: /* Avoid compiler warnings. */
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    /* Don't count the "%s"s in the final size, but reserve room for
       the terminator.  */
    YYPTRDIFF_T yysize1 = yysize + (yystrlen (yyformat) - 2 * yycount) + 1;
    if (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM)
      yysize = yysize1;
    else
      return 2;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          ++yyp;
          ++yyformat;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep)
{
  YYUSE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}




/* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;
/* Number of syntax errors so far.  */
int yynerrs;


/*----------.
| yyparse.  |
`----------*/

int
yyparse (void)
{
    yy_state_fast_t yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss;
    yy_state_t *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYPTRDIFF_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYPTRDIFF_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */
  goto yysetstate;


/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;


/*--------------------------------------------------------------------.
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  YYDPRINTF ((stderr, "Entering state %d\n", yystate));
  YY_ASSERT (0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST (yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    goto yyexhaustedlab;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYPTRDIFF_T yysize = yyssp - yyss + 1;

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        yy_state_t *yyss1 = yyss;
        YYSTYPE *yyvs1 = yyvs;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
# undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YY_IGNORE_USELESS_CAST_BEGIN
      YYDPRINTF ((stderr, "Stack size increased to %ld\n",
                  YY_CAST (long, yystacksize)));
      YY_IGNORE_USELESS_CAST_END

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:
  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);
  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  /* Discard the shifted token.  */
  yychar = YYEMPTY;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
  case 22:
#line 368 "cfparse.y"
                {
			struct passwd *pw;

			if ((pw = getpwnam((yyvsp[0].val)->v)) == NULL) {
				yyerror("unknown user \"%s\"", (yyvsp[0].val)->v);
				return -1;
			}
			lcconf->uid = pw->pw_uid;
		}
#line 2458 "cfparse.c"
    break;

  case 24:
#line 378 "cfparse.y"
                            { lcconf->uid = (yyvsp[0].num); }
#line 2464 "cfparse.c"
    break;

  case 26:
#line 380 "cfparse.y"
                {
			struct group *gr;

			if ((gr = getgrnam((yyvsp[0].val)->v)) == NULL) {
				yyerror("unknown group \"%s\"", (yyvsp[0].val)->v);
				return -1;
			}
			lcconf->gid = gr->gr_gid;
		}
#line 2478 "cfparse.c"
    break;

  case 28:
#line 390 "cfparse.y"
                             { lcconf->gid = (yyvsp[0].num); }
#line 2484 "cfparse.c"
    break;

  case 30:
#line 391 "cfparse.y"
                                    { lcconf->chroot = (yyvsp[0].val)->v; }
#line 2490 "cfparse.c"
    break;

  case 32:
#line 397 "cfparse.y"
                {
			if ((yyvsp[-1].num) >= LC_PATHTYPE_MAX) {
				yyerror("invalid path type %d", (yyvsp[-1].num));
				return -1;
			}

			/* free old pathinfo */
			if (lcconf->pathinfo[(yyvsp[-1].num)])
				racoon_free(lcconf->pathinfo[(yyvsp[-1].num)]);

			/* set new pathinfo */
			lcconf->pathinfo[(yyvsp[-1].num)] = racoon_strdup((yyvsp[0].val)->v);
			STRDUP_FATAL(lcconf->pathinfo[(yyvsp[-1].num)]);
			vfree((yyvsp[0].val));
		}
#line 2510 "cfparse.c"
    break;

  case 34:
#line 417 "cfparse.y"
                                      { lcconf->complex_bundle = (yyvsp[0].num); }
#line 2516 "cfparse.c"
    break;

  case 36:
#line 423 "cfparse.y"
                {
			char path[MAXPATHLEN];

			getpathname(path, sizeof(path),
				LC_PATHTYPE_INCLUDE, (yyvsp[-1].val)->v);
			vfree((yyvsp[-1].val));
			if (yycf_switch_buffer(path) != 0)
				return -1;
		}
#line 2530 "cfparse.c"
    break;

  case 37:
#line 437 "cfparse.y"
        {
			lcconf->pfkey_buffer_size = (yyvsp[-1].num);
        }
#line 2538 "cfparse.c"
    break;

  case 38:
#line 444 "cfparse.y"
                {
			if ((yyvsp[-1].num) >= LC_GSSENC_MAX) {
				yyerror("invalid GSS ID encoding %d", (yyvsp[-1].num));
				return -1;
			}
			lcconf->gss_id_enc = (yyvsp[-1].num);
		}
#line 2550 "cfparse.c"
    break;

  case 40:
#line 459 "cfparse.y"
                {
			/*
			 * set the loglevel to the value specified
			 * in the configuration file plus the number
			 * of -d options specified on the command line
			 */
			loglevel += (yyvsp[0].num) - oldloglevel;
			oldloglevel = (yyvsp[0].num);
		}
#line 2564 "cfparse.c"
    break;

  case 44:
#line 479 "cfparse.y"
                                     { lcconf->pad_random = (yyvsp[0].num); }
#line 2570 "cfparse.c"
    break;

  case 46:
#line 480 "cfparse.y"
                                        { lcconf->pad_randomlen = (yyvsp[0].num); }
#line 2576 "cfparse.c"
    break;

  case 48:
#line 481 "cfparse.y"
                                  { lcconf->pad_maxsize = (yyvsp[0].num); }
#line 2582 "cfparse.c"
    break;

  case 50:
#line 482 "cfparse.y"
                                  { lcconf->pad_strict = (yyvsp[0].num); }
#line 2588 "cfparse.c"
    break;

  case 52:
#line 483 "cfparse.y"
                                    { lcconf->pad_excltail = (yyvsp[0].num); }
#line 2594 "cfparse.c"
    break;

  case 57:
#line 496 "cfparse.y"
                {
			myaddr_listen((yyvsp[0].saddr), FALSE);
			racoon_free((yyvsp[0].saddr));
		}
#line 2603 "cfparse.c"
    break;

  case 59:
#line 502 "cfparse.y"
                {
#ifdef ENABLE_NATT
			myaddr_listen((yyvsp[0].saddr), TRUE);
			racoon_free((yyvsp[0].saddr));
#else
			racoon_free((yyvsp[0].saddr));
			yyerror("NAT-T support not compiled in.");
#endif
		}
#line 2617 "cfparse.c"
    break;

  case 61:
#line 513 "cfparse.y"
                {
#ifdef ENABLE_ADMINPORT
			adminsock_conf((yyvsp[-3].val), (yyvsp[-2].val), (yyvsp[-1].val), (yyvsp[0].num));
#else
			yywarn("admin port support not compiled in");
#endif
		}
#line 2629 "cfparse.c"
    break;

  case 63:
#line 522 "cfparse.y"
                {
#ifdef ENABLE_ADMINPORT
			adminsock_conf((yyvsp[0].val), NULL, NULL, -1);
#else
			yywarn("admin port support not compiled in");
#endif
		}
#line 2641 "cfparse.c"
    break;

  case 65:
#line 531 "cfparse.y"
                {
#ifdef ENABLE_ADMINPORT
			adminsock_path = NULL;
#else
			yywarn("admin port support not compiled in");
#endif
		}
#line 2653 "cfparse.c"
    break;

  case 67:
#line 539 "cfparse.y"
                               { lcconf->strict_address = TRUE; }
#line 2659 "cfparse.c"
    break;

  case 69:
#line 543 "cfparse.y"
                {
			char portbuf[10];

			snprintf(portbuf, sizeof(portbuf), "%ld", (yyvsp[0].num));
			(yyval.saddr) = str2saddr((yyvsp[-1].val)->v, portbuf);
			vfree((yyvsp[-1].val));
			if (!(yyval.saddr))
				return -1;
		}
#line 2673 "cfparse.c"
    break;

  case 70:
#line 554 "cfparse.y"
                                { (yyval.num) = PORT_ISAKMP; }
#line 2679 "cfparse.c"
    break;

  case 71:
#line 555 "cfparse.y"
                                { (yyval.num) = (yyvsp[0].num); }
#line 2685 "cfparse.c"
    break;

  case 72:
#line 560 "cfparse.y"
                       {
#ifndef ENABLE_HYBRID
			yyerror("racoon not configured with --enable-hybrid");
			return -1;
#endif
#ifndef HAVE_LIBRADIUS
			yyerror("racoon not configured with --with-libradius");
			return -1;
#endif
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBRADIUS
			xauth_rad_config.timeout = 3;
			xauth_rad_config.retries = 3;
#endif
#endif
		}
#line 2706 "cfparse.c"
    break;

  case 76:
#line 583 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBRADIUS
			int i = xauth_rad_config.auth_server_count;
			if (i == RADIUS_MAX_SERVERS) {
				yyerror("maximum radius auth servers exceeded");
				return -1;
			}

			xauth_rad_config.auth_server_list[i].host = vdup((yyvsp[-1].val));
			xauth_rad_config.auth_server_list[i].secret = vdup((yyvsp[0].val));
			xauth_rad_config.auth_server_list[i].port = 0; // default port
			xauth_rad_config.auth_server_count++;
#endif
#endif
		}
#line 2727 "cfparse.c"
    break;

  case 78:
#line 601 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBRADIUS
			int i = xauth_rad_config.auth_server_count;
			if (i == RADIUS_MAX_SERVERS) {
				yyerror("maximum radius auth servers exceeded");
				return -1;
			}

			xauth_rad_config.auth_server_list[i].host = vdup((yyvsp[-2].val));
			xauth_rad_config.auth_server_list[i].secret = vdup((yyvsp[0].val));
			xauth_rad_config.auth_server_list[i].port = (yyvsp[-1].num);
			xauth_rad_config.auth_server_count++;
#endif
#endif
		}
#line 2748 "cfparse.c"
    break;

  case 80:
#line 619 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBRADIUS
			int i = xauth_rad_config.acct_server_count;
			if (i == RADIUS_MAX_SERVERS) {
				yyerror("maximum radius account servers exceeded");
				return -1;
			}

			xauth_rad_config.acct_server_list[i].host = vdup((yyvsp[-1].val));
			xauth_rad_config.acct_server_list[i].secret = vdup((yyvsp[0].val));
			xauth_rad_config.acct_server_list[i].port = 0; // default port
			xauth_rad_config.acct_server_count++;
#endif
#endif
		}
#line 2769 "cfparse.c"
    break;

  case 82:
#line 637 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBRADIUS
			int i = xauth_rad_config.acct_server_count;
			if (i == RADIUS_MAX_SERVERS) {
				yyerror("maximum radius account servers exceeded");
				return -1;
			}

			xauth_rad_config.acct_server_list[i].host = vdup((yyvsp[-2].val));
			xauth_rad_config.acct_server_list[i].secret = vdup((yyvsp[0].val));
			xauth_rad_config.acct_server_list[i].port = (yyvsp[-1].num);
			xauth_rad_config.acct_server_count++;
#endif
#endif
		}
#line 2790 "cfparse.c"
    break;

  case 84:
#line 655 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBRADIUS
			xauth_rad_config.timeout = (yyvsp[0].num);
#endif
#endif
		}
#line 2802 "cfparse.c"
    break;

  case 86:
#line 664 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBRADIUS
			xauth_rad_config.retries = (yyvsp[0].num);
#endif
#endif
		}
#line 2814 "cfparse.c"
    break;

  case 88:
#line 676 "cfparse.y"
                        {
#ifndef ENABLE_HYBRID
			yyerror("racoon not configured with --enable-hybrid");
			return -1;
#endif
#ifndef HAVE_LIBLDAP
			yyerror("racoon not configured with --with-libldap");
			return -1;
#endif
		}
#line 2829 "cfparse.c"
    break;

  case 92:
#line 693 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBLDAP
			if (((yyvsp[0].num)<2)||((yyvsp[0].num)>3))
				yyerror("invalid ldap protocol version (2|3)");
			xauth_ldap_config.pver = (yyvsp[0].num);
#endif
#endif
		}
#line 2843 "cfparse.c"
    break;

  case 94:
#line 704 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBLDAP
			if (xauth_ldap_config.host != NULL)
				vfree(xauth_ldap_config.host);
			xauth_ldap_config.host = vdup((yyvsp[0].val));
#endif
#endif
		}
#line 2857 "cfparse.c"
    break;

  case 96:
#line 715 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBLDAP
			xauth_ldap_config.port = (yyvsp[0].num);
#endif
#endif
		}
#line 2869 "cfparse.c"
    break;

  case 98:
#line 724 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBLDAP
			if (xauth_ldap_config.base != NULL)
				vfree(xauth_ldap_config.base);
			xauth_ldap_config.base = vdup((yyvsp[0].val));
#endif
#endif
		}
#line 2883 "cfparse.c"
    break;

  case 100:
#line 735 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBLDAP
			xauth_ldap_config.subtree = (yyvsp[0].num);
#endif
#endif
		}
#line 2895 "cfparse.c"
    break;

  case 102:
#line 744 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBLDAP
			if (xauth_ldap_config.bind_dn != NULL)
				vfree(xauth_ldap_config.bind_dn);
			xauth_ldap_config.bind_dn = vdup((yyvsp[0].val));
#endif
#endif
		}
#line 2909 "cfparse.c"
    break;

  case 104:
#line 755 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBLDAP
			if (xauth_ldap_config.bind_pw != NULL)
				vfree(xauth_ldap_config.bind_pw);
			xauth_ldap_config.bind_pw = vdup((yyvsp[0].val));
#endif
#endif
		}
#line 2923 "cfparse.c"
    break;

  case 106:
#line 766 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBLDAP
			if (xauth_ldap_config.attr_user != NULL)
				vfree(xauth_ldap_config.attr_user);
			xauth_ldap_config.attr_user = vdup((yyvsp[0].val));
#endif
#endif
		}
#line 2937 "cfparse.c"
    break;

  case 108:
#line 777 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBLDAP
			if (xauth_ldap_config.attr_addr != NULL)
				vfree(xauth_ldap_config.attr_addr);
			xauth_ldap_config.attr_addr = vdup((yyvsp[0].val));
#endif
#endif
		}
#line 2951 "cfparse.c"
    break;

  case 110:
#line 788 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBLDAP
			if (xauth_ldap_config.attr_mask != NULL)
				vfree(xauth_ldap_config.attr_mask);
			xauth_ldap_config.attr_mask = vdup((yyvsp[0].val));
#endif
#endif
		}
#line 2965 "cfparse.c"
    break;

  case 112:
#line 799 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBLDAP
			if (xauth_ldap_config.attr_group != NULL)
				vfree(xauth_ldap_config.attr_group);
			xauth_ldap_config.attr_group = vdup((yyvsp[0].val));
#endif
#endif
		}
#line 2979 "cfparse.c"
    break;

  case 114:
#line 810 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBLDAP
			if (xauth_ldap_config.attr_member != NULL)
				vfree(xauth_ldap_config.attr_member);
			xauth_ldap_config.attr_member = vdup((yyvsp[0].val));
#endif
#endif
		}
#line 2993 "cfparse.c"
    break;

  case 119:
#line 832 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
			if (inet_pton(AF_INET, (yyvsp[0].val)->v,
			     &isakmp_cfg_config.network4) != 1)
				yyerror("bad IPv4 network address.");
#else
			yyerror("racoon not configured with --enable-hybrid");
#endif
		}
#line 3007 "cfparse.c"
    break;

  case 121:
#line 843 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
			if (inet_pton(AF_INET, (yyvsp[0].val)->v,
			    &isakmp_cfg_config.netmask4) != 1)
				yyerror("bad IPv4 netmask address.");
#else
			yyerror("racoon not configured with --enable-hybrid");
#endif
		}
#line 3021 "cfparse.c"
    break;

  case 125:
#line 858 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
			isakmp_cfg_config.splitnet_type = UNITY_LOCAL_LAN;
#else
			yyerror("racoon not configured with --enable-hybrid");
#endif
		}
#line 3033 "cfparse.c"
    break;

  case 127:
#line 867 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
			isakmp_cfg_config.splitnet_type = UNITY_SPLIT_INCLUDE;
#else
			yyerror("racoon not configured with --enable-hybrid");
#endif
		}
#line 3045 "cfparse.c"
    break;

  case 129:
#line 876 "cfparse.y"
                {
#ifndef ENABLE_HYBRID
			yyerror("racoon not configured with --enable-hybrid");
#endif
		}
#line 3055 "cfparse.c"
    break;

  case 131:
#line 883 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
			strncpy(&isakmp_cfg_config.default_domain[0], 
			    (yyvsp[0].val)->v, MAXPATHLEN);
			isakmp_cfg_config.default_domain[MAXPATHLEN] = '\0';
			vfree((yyvsp[0].val));
#else
			yyerror("racoon not configured with --enable-hybrid");
#endif
		}
#line 3070 "cfparse.c"
    break;

  case 133:
#line 895 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
			isakmp_cfg_config.authsource = ISAKMP_CFG_AUTH_SYSTEM;
#else
			yyerror("racoon not configured with --enable-hybrid");
#endif
		}
#line 3082 "cfparse.c"
    break;

  case 135:
#line 904 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBRADIUS
			isakmp_cfg_config.authsource = ISAKMP_CFG_AUTH_RADIUS;
#else /* HAVE_LIBRADIUS */
			yyerror("racoon not configured with --with-libradius");
#endif /* HAVE_LIBRADIUS */
#else /* ENABLE_HYBRID */
			yyerror("racoon not configured with --enable-hybrid");
#endif /* ENABLE_HYBRID */
		}
#line 3098 "cfparse.c"
    break;

  case 137:
#line 917 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBPAM
			isakmp_cfg_config.authsource = ISAKMP_CFG_AUTH_PAM;
#else /* HAVE_LIBPAM */
			yyerror("racoon not configured with --with-libpam");
#endif /* HAVE_LIBPAM */
#else /* ENABLE_HYBRID */
			yyerror("racoon not configured with --enable-hybrid");
#endif /* ENABLE_HYBRID */
		}
#line 3114 "cfparse.c"
    break;

  case 139:
#line 930 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBLDAP
			isakmp_cfg_config.authsource = ISAKMP_CFG_AUTH_LDAP;
#else /* HAVE_LIBLDAP */
			yyerror("racoon not configured with --with-libldap");
#endif /* HAVE_LIBLDAP */
#else /* ENABLE_HYBRID */
			yyerror("racoon not configured with --enable-hybrid");
#endif /* ENABLE_HYBRID */
		}
#line 3130 "cfparse.c"
    break;

  case 141:
#line 943 "cfparse.y"
                {
#ifndef ENABLE_HYBRID
			yyerror("racoon not configured with --enable-hybrid");
#endif
		}
#line 3140 "cfparse.c"
    break;

  case 143:
#line 950 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
			isakmp_cfg_config.groupsource = ISAKMP_CFG_GROUP_SYSTEM;
#else
			yyerror("racoon not configured with --enable-hybrid");
#endif
		}
#line 3152 "cfparse.c"
    break;

  case 145:
#line 959 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBLDAP
			isakmp_cfg_config.groupsource = ISAKMP_CFG_GROUP_LDAP;
#else /* HAVE_LIBLDAP */
			yyerror("racoon not configured with --with-libldap");
#endif /* HAVE_LIBLDAP */
#else /* ENABLE_HYBRID */
			yyerror("racoon not configured with --enable-hybrid");
#endif /* ENABLE_HYBRID */
		}
#line 3168 "cfparse.c"
    break;

  case 147:
#line 972 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
			isakmp_cfg_config.accounting = ISAKMP_CFG_ACCT_NONE;
#else
			yyerror("racoon not configured with --enable-hybrid");
#endif
		}
#line 3180 "cfparse.c"
    break;

  case 149:
#line 981 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
			isakmp_cfg_config.accounting = ISAKMP_CFG_ACCT_SYSTEM;
#else
			yyerror("racoon not configured with --enable-hybrid");
#endif
		}
#line 3192 "cfparse.c"
    break;

  case 151:
#line 990 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBRADIUS
			isakmp_cfg_config.accounting = ISAKMP_CFG_ACCT_RADIUS;
#else /* HAVE_LIBRADIUS */
			yyerror("racoon not configured with --with-libradius");
#endif /* HAVE_LIBRADIUS */
#else /* ENABLE_HYBRID */
			yyerror("racoon not configured with --enable-hybrid");
#endif /* ENABLE_HYBRID */
		}
#line 3208 "cfparse.c"
    break;

  case 153:
#line 1003 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBPAM
			isakmp_cfg_config.accounting = ISAKMP_CFG_ACCT_PAM;
#else /* HAVE_LIBPAM */
			yyerror("racoon not configured with --with-libpam");
#endif /* HAVE_LIBPAM */
#else /* ENABLE_HYBRID */
			yyerror("racoon not configured with --enable-hybrid");
#endif /* ENABLE_HYBRID */
		}
#line 3224 "cfparse.c"
    break;

  case 155:
#line 1016 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
			if (isakmp_cfg_resize_pool((yyvsp[0].num)) != 0)
				yyerror("cannot allocate memory for pool");
#else /* ENABLE_HYBRID */
			yyerror("racoon not configured with --enable-hybrid");
#endif /* ENABLE_HYBRID */
		}
#line 3237 "cfparse.c"
    break;

  case 157:
#line 1026 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
			isakmp_cfg_config.pfs_group = (yyvsp[0].num);
#else /* ENABLE_HYBRID */
			yyerror("racoon not configured with --enable-hybrid");
#endif /* ENABLE_HYBRID */
		}
#line 3249 "cfparse.c"
    break;

  case 159:
#line 1035 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
			isakmp_cfg_config.save_passwd = (yyvsp[0].num);
#else /* ENABLE_HYBRID */
			yyerror("racoon not configured with --enable-hybrid");
#endif /* ENABLE_HYBRID */
		}
#line 3261 "cfparse.c"
    break;

  case 161:
#line 1044 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
			isakmp_cfg_config.auth_throttle = (yyvsp[0].num);
#else /* ENABLE_HYBRID */
			yyerror("racoon not configured with --enable-hybrid");
#endif /* ENABLE_HYBRID */
		}
#line 3273 "cfparse.c"
    break;

  case 163:
#line 1053 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
			isakmp_cfg_config.confsource = ISAKMP_CFG_CONF_LOCAL;
#else /* ENABLE_HYBRID */
			yyerror("racoon not configured with --enable-hybrid");
#endif /* ENABLE_HYBRID */
		}
#line 3285 "cfparse.c"
    break;

  case 165:
#line 1062 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBRADIUS
			isakmp_cfg_config.confsource = ISAKMP_CFG_CONF_RADIUS;
#else /* HAVE_LIBRADIUS */
			yyerror("racoon not configured with --with-libradius");
#endif /* HAVE_LIBRADIUS */
#else /* ENABLE_HYBRID */
			yyerror("racoon not configured with --enable-hybrid");
#endif /* ENABLE_HYBRID */
		}
#line 3301 "cfparse.c"
    break;

  case 167:
#line 1075 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
#ifdef HAVE_LIBLDAP
			isakmp_cfg_config.confsource = ISAKMP_CFG_CONF_LDAP;
#else /* HAVE_LIBLDAP */
			yyerror("racoon not configured with --with-libldap");
#endif /* HAVE_LIBLDAP */
#else /* ENABLE_HYBRID */
			yyerror("racoon not configured with --enable-hybrid");
#endif /* ENABLE_HYBRID */
		}
#line 3317 "cfparse.c"
    break;

  case 169:
#line 1088 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
			strncpy(&isakmp_cfg_config.motd[0], (yyvsp[0].val)->v, MAXPATHLEN);
			isakmp_cfg_config.motd[MAXPATHLEN] = '\0';
			vfree((yyvsp[0].val));
#else
			yyerror("racoon not configured with --enable-hybrid");
#endif
		}
#line 3331 "cfparse.c"
    break;

  case 173:
#line 1106 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
			struct isakmp_cfg_config *icc = &isakmp_cfg_config;

			if (icc->dns4_index > MAXNS)
				yyerror("No more than %d DNS", MAXNS);
			if (inet_pton(AF_INET, (yyvsp[0].val)->v,
			    &icc->dns4[icc->dns4_index++]) != 1)
				yyerror("bad IPv4 DNS address.");
#else
			yyerror("racoon not configured with --enable-hybrid");
#endif
		}
#line 3349 "cfparse.c"
    break;

  case 176:
#line 1127 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
			struct isakmp_cfg_config *icc = &isakmp_cfg_config;

			if (icc->nbns4_index > MAXWINS)
				yyerror("No more than %d WINS", MAXWINS);
			if (inet_pton(AF_INET, (yyvsp[0].val)->v,
			    &icc->nbns4[icc->nbns4_index++]) != 1)
				yyerror("bad IPv4 WINS address.");
#else
			yyerror("racoon not configured with --enable-hybrid");
#endif
		}
#line 3367 "cfparse.c"
    break;

  case 179:
#line 1148 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
			struct isakmp_cfg_config *icc = &isakmp_cfg_config;
			struct unity_network network;
			memset(&network,0,sizeof(network));

			if (inet_pton(AF_INET, (yyvsp[-1].val)->v, &network.addr4) != 1)
				yyerror("bad IPv4 SPLIT address.");

			/* Turn $2 (the prefix) into a subnet mask */
			network.mask4.s_addr = ((yyvsp[0].num)) ? htonl(~((1 << (32 - (yyvsp[0].num))) - 1)) : 0;

			/* add the network to our list */ 
			if (splitnet_list_add(&icc->splitnet_list, &network,&icc->splitnet_count))
				yyerror("Unable to allocate split network");
#else
			yyerror("racoon not configured with --enable-hybrid");
#endif
		}
#line 3391 "cfparse.c"
    break;

  case 182:
#line 1175 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
			char * groupname = NULL;
			char ** grouplist = NULL;
			struct isakmp_cfg_config *icc = &isakmp_cfg_config;

			grouplist = racoon_realloc(icc->grouplist,
					sizeof(char**)*(icc->groupcount+1));
			if (grouplist == NULL) {
				yyerror("unable to allocate auth group list");
				return -1;
			}

			groupname = racoon_malloc((yyvsp[0].val)->l+1);
			if (groupname == NULL) {
				yyerror("unable to allocate auth group name");
				return -1;
			}

			memcpy(groupname,(yyvsp[0].val)->v,(yyvsp[0].val)->l);
			groupname[(yyvsp[0].val)->l]=0;
			grouplist[icc->groupcount]=groupname;
			icc->grouplist = grouplist;
			icc->groupcount++;

			vfree((yyvsp[0].val));
#else
			yyerror("racoon not configured with --enable-hybrid");
#endif
		}
#line 3426 "cfparse.c"
    break;

  case 185:
#line 1213 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
			struct isakmp_cfg_config *icc = &isakmp_cfg_config;

			if (!icc->splitdns_len)
			{
				icc->splitdns_list = racoon_malloc((yyvsp[0].val)->l);
				if(icc->splitdns_list == NULL) {
					yyerror("error allocating splitdns list buffer");
					return -1;
				}
				memcpy(icc->splitdns_list,(yyvsp[0].val)->v,(yyvsp[0].val)->l);
				icc->splitdns_len = (yyvsp[0].val)->l;
			}
			else
			{
				int len = icc->splitdns_len + (yyvsp[0].val)->l + 1;
				icc->splitdns_list = racoon_realloc(icc->splitdns_list,len);
				if(icc->splitdns_list == NULL) {
					yyerror("error allocating splitdns list buffer");
					return -1;
				}
				icc->splitdns_list[icc->splitdns_len] = ',';
				memcpy(icc->splitdns_list + icc->splitdns_len + 1, (yyvsp[0].val)->v, (yyvsp[0].val)->l);
				icc->splitdns_len = len;
			}
			vfree((yyvsp[0].val));
#else
			yyerror("racoon not configured with --enable-hybrid");
#endif
		}
#line 3462 "cfparse.c"
    break;

  case 189:
#line 1257 "cfparse.y"
                {
			lcconf->retry_counter = (yyvsp[0].num);
		}
#line 3470 "cfparse.c"
    break;

  case 191:
#line 1262 "cfparse.y"
                {
			lcconf->retry_interval = (yyvsp[-1].num) * (yyvsp[0].num);
		}
#line 3478 "cfparse.c"
    break;

  case 193:
#line 1267 "cfparse.y"
                {
			lcconf->count_persend = (yyvsp[0].num);
		}
#line 3486 "cfparse.c"
    break;

  case 195:
#line 1272 "cfparse.y"
                {
			lcconf->retry_checkph1 = (yyvsp[-1].num) * (yyvsp[0].num);
		}
#line 3494 "cfparse.c"
    break;

  case 197:
#line 1277 "cfparse.y"
                {
			lcconf->wait_ph2complete = (yyvsp[-1].num) * (yyvsp[0].num);
		}
#line 3502 "cfparse.c"
    break;

  case 199:
#line 1282 "cfparse.y"
                {
#ifdef ENABLE_NATT
        		if (libipsec_opt & LIBIPSEC_OPT_NATT)
				lcconf->natt_ka_interval = (yyvsp[-1].num) * (yyvsp[0].num);
			else
                		yyerror("libipsec lacks NAT-T support");
#else
			yyerror("NAT-T support not compiled in.");
#endif
		}
#line 3517 "cfparse.c"
    break;

  case 201:
#line 1298 "cfparse.y"
                {
			cur_sainfo = newsainfo();
			if (cur_sainfo == NULL) {
				yyerror("failed to allocate sainfo");
				return -1;
			}
		}
#line 3529 "cfparse.c"
    break;

  case 202:
#line 1306 "cfparse.y"
                {
			struct sainfo *check;

			/* default */
			if (cur_sainfo->algs[algclass_ipsec_enc] == 0) {
				yyerror("no encryption algorithm at %s",
					sainfo2str(cur_sainfo));
				return -1;
			}
			if (cur_sainfo->algs[algclass_ipsec_auth] == 0) {
				yyerror("no authentication algorithm at %s",
					sainfo2str(cur_sainfo));
				return -1;
			}
			if (cur_sainfo->algs[algclass_ipsec_comp] == 0) {
				yyerror("no compression algorithm at %s",
					sainfo2str(cur_sainfo));
				return -1;
			}

			/* duplicate check */
			check = getsainfo(cur_sainfo->idsrc,
					  cur_sainfo->iddst,
					  cur_sainfo->id_i,
					  NULL,
					  cur_sainfo->remoteid);

			if (check && ((check->idsrc != SAINFO_ANONYMOUS) &&
				      (cur_sainfo->idsrc != SAINFO_ANONYMOUS))) {
				yyerror("duplicated sainfo: %s",
					sainfo2str(cur_sainfo));
				return -1;
			}

			inssainfo(cur_sainfo);
		}
#line 3570 "cfparse.c"
    break;

  case 204:
#line 1346 "cfparse.y"
                {
			cur_sainfo->idsrc = SAINFO_ANONYMOUS;
			cur_sainfo->iddst = SAINFO_ANONYMOUS;
		}
#line 3579 "cfparse.c"
    break;

  case 205:
#line 1351 "cfparse.y"
                {
			cur_sainfo->idsrc = SAINFO_ANONYMOUS;
			cur_sainfo->iddst = SAINFO_CLIENTADDR;
		}
#line 3588 "cfparse.c"
    break;

  case 206:
#line 1356 "cfparse.y"
                {
			cur_sainfo->idsrc = SAINFO_ANONYMOUS;
			cur_sainfo->iddst = (yyvsp[0].val);
		}
#line 3597 "cfparse.c"
    break;

  case 207:
#line 1361 "cfparse.y"
                {
			cur_sainfo->idsrc = (yyvsp[-1].val);
			cur_sainfo->iddst = SAINFO_ANONYMOUS;
		}
#line 3606 "cfparse.c"
    break;

  case 208:
#line 1366 "cfparse.y"
                {
			cur_sainfo->idsrc = (yyvsp[-1].val);
			cur_sainfo->iddst = SAINFO_CLIENTADDR;
		}
#line 3615 "cfparse.c"
    break;

  case 209:
#line 1371 "cfparse.y"
                {
			cur_sainfo->idsrc = (yyvsp[-1].val);
			cur_sainfo->iddst = (yyvsp[0].val);
		}
#line 3624 "cfparse.c"
    break;

  case 210:
#line 1378 "cfparse.y"
                {
			char portbuf[10];
			struct sockaddr *saddr;

			if (((yyvsp[0].num) == IPPROTO_ICMP || (yyvsp[0].num) == IPPROTO_ICMPV6)
			 && ((yyvsp[-1].num) != IPSEC_PORT_ANY || (yyvsp[-1].num) != IPSEC_PORT_ANY)) {
				yyerror("port number must be \"any\".");
				return -1;
			}

			snprintf(portbuf, sizeof(portbuf), "%lu", (yyvsp[-1].num));
			saddr = str2saddr((yyvsp[-3].val)->v, portbuf);
			vfree((yyvsp[-3].val));
			if (saddr == NULL)
				return -1;

			switch (saddr->sa_family) {
			case AF_INET:
				if ((yyvsp[0].num) == IPPROTO_ICMPV6) {
					yyerror("upper layer protocol mismatched.\n");
					racoon_free(saddr);
					return -1;
				}
				(yyval.val) = ipsecdoi_sockaddr2id(saddr,
										  (yyvsp[-2].num) == ~0 ? (sizeof(struct in_addr) << 3): (yyvsp[-2].num),
										  (yyvsp[0].num));
				break;
#ifdef INET6
			case AF_INET6:
				if ((yyvsp[0].num) == IPPROTO_ICMP) {
					yyerror("upper layer protocol mismatched.\n");
					racoon_free(saddr);
					return -1;
				}
				(yyval.val) = ipsecdoi_sockaddr2id(saddr, 
										  (yyvsp[-2].num) == ~0 ? (sizeof(struct in6_addr) << 3): (yyvsp[-2].num),
										  (yyvsp[0].num));
				break;
#endif
			default:
				yyerror("invalid family: %d", saddr->sa_family);
				(yyval.val) = NULL;
				break;
			}
			racoon_free(saddr);
			if ((yyval.val) == NULL)
				return -1;
		}
#line 3677 "cfparse.c"
    break;

  case 211:
#line 1427 "cfparse.y"
                {
			char portbuf[10];
			struct sockaddr *laddr = NULL, *haddr = NULL;
			char *cur = NULL;

			if (((yyvsp[0].num) == IPPROTO_ICMP || (yyvsp[0].num) == IPPROTO_ICMPV6)
			 && ((yyvsp[-1].num) != IPSEC_PORT_ANY || (yyvsp[-1].num) != IPSEC_PORT_ANY)) {
				yyerror("port number must be \"any\".");
				return -1;
			}

			snprintf(portbuf, sizeof(portbuf), "%lu", (yyvsp[-1].num));
			
			laddr = str2saddr((yyvsp[-4].val)->v, portbuf);
			if (laddr == NULL) {
			    return -1;
			}
			vfree((yyvsp[-4].val));
			haddr = str2saddr((yyvsp[-3].val)->v, portbuf);
			if (haddr == NULL) {
			    racoon_free(laddr);
			    return -1;
			}
			vfree((yyvsp[-3].val));

			switch (laddr->sa_family) {
			case AF_INET:
				if ((yyvsp[0].num) == IPPROTO_ICMPV6) {
				    yyerror("upper layer protocol mismatched.\n");
				    if (laddr)
					racoon_free(laddr);
				    if (haddr)
					racoon_free(haddr);
				    return -1;
				}
                                (yyval.val) = ipsecdoi_sockrange2id(laddr, haddr, 
							   (yyvsp[0].num));
				break;
#ifdef INET6
			case AF_INET6:
				if ((yyvsp[0].num) == IPPROTO_ICMP) {
					yyerror("upper layer protocol mismatched.\n");
					if (laddr)
					    racoon_free(laddr);
					if (haddr)
					    racoon_free(haddr);
					return -1;
				}
				(yyval.val) = ipsecdoi_sockrange2id(laddr, haddr, 
							       (yyvsp[0].num));
				break;
#endif
			default:
				yyerror("invalid family: %d", laddr->sa_family);
				(yyval.val) = NULL;
				break;
			}
			if (laddr)
			    racoon_free(laddr);
			if (haddr)
			    racoon_free(haddr);
			if ((yyval.val) == NULL)
				return -1;
		}
#line 3746 "cfparse.c"
    break;

  case 212:
#line 1492 "cfparse.y"
                {
			struct ipsecdoi_id_b *id_b;

			if ((yyvsp[-1].num) == IDTYPE_ASN1DN) {
				yyerror("id type forbidden: %d", (yyvsp[-1].num));
				(yyval.val) = NULL;
				return -1;
			}

			(yyvsp[0].val)->l--;

			(yyval.val) = vmalloc(sizeof(*id_b) + (yyvsp[0].val)->l);
			if ((yyval.val) == NULL) {
				yyerror("failed to allocate identifier");
				return -1;
			}

			id_b = (struct ipsecdoi_id_b *)(yyval.val)->v;
			id_b->type = idtype2doi((yyvsp[-1].num));

			id_b->proto_id = 0;
			id_b->port = 0;

			memcpy((yyval.val)->v + sizeof(*id_b), (yyvsp[0].val)->v, (yyvsp[0].val)->l);
		}
#line 3776 "cfparse.c"
    break;

  case 213:
#line 1520 "cfparse.y"
                {
			cur_sainfo->id_i = NULL;
		}
#line 3784 "cfparse.c"
    break;

  case 214:
#line 1524 "cfparse.y"
                {
			struct ipsecdoi_id_b *id_b;
			vchar_t *idv;

			if (set_identifier(&idv, (yyvsp[-1].num), (yyvsp[0].val)) != 0) {
				yyerror("failed to set identifer.\n");
				return -1;
			}
			cur_sainfo->id_i = vmalloc(sizeof(*id_b) + idv->l);
			if (cur_sainfo->id_i == NULL) {
				yyerror("failed to allocate identifier");
				return -1;
			}

			id_b = (struct ipsecdoi_id_b *)cur_sainfo->id_i->v;
			id_b->type = idtype2doi((yyvsp[-1].num));

			id_b->proto_id = 0;
			id_b->port = 0;

			memcpy(cur_sainfo->id_i->v + sizeof(*id_b),
			       idv->v, idv->l);
			vfree(idv);
		}
#line 3813 "cfparse.c"
    break;

  case 215:
#line 1549 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
			if ((cur_sainfo->group = vdup((yyvsp[0].val))) == NULL) {
				yyerror("failed to set sainfo xauth group.\n");
				return -1;
			}
#else
			yyerror("racoon not configured with --enable-hybrid");
			return -1;
#endif
 		}
#line 3829 "cfparse.c"
    break;

  case 218:
#line 1567 "cfparse.y"
                {
			cur_sainfo->pfs_group = (yyvsp[0].num);
		}
#line 3837 "cfparse.c"
    break;

  case 220:
#line 1572 "cfparse.y"
                {
			cur_sainfo->remoteid = (yyvsp[0].num);
		}
#line 3845 "cfparse.c"
    break;

  case 222:
#line 1577 "cfparse.y"
                {
			cur_sainfo->lifetime = (yyvsp[-1].num) * (yyvsp[0].num);
		}
#line 3853 "cfparse.c"
    break;

  case 224:
#line 1582 "cfparse.y"
                {
#if 1
			yyerror("byte lifetime support is deprecated");
			return -1;
#else
			cur_sainfo->lifebyte = fix_lifebyte((yyvsp[-1].num) * (yyvsp[0].num));
			if (cur_sainfo->lifebyte == 0)
				return -1;
#endif
		}
#line 3868 "cfparse.c"
    break;

  case 226:
#line 1593 "cfparse.y"
                                {
			cur_algclass = (yyvsp[0].num);
		}
#line 3876 "cfparse.c"
    break;

  case 228:
#line 1601 "cfparse.y"
                {
			inssainfoalg(&cur_sainfo->algs[cur_algclass], (yyvsp[0].alg));
		}
#line 3884 "cfparse.c"
    break;

  case 229:
#line 1605 "cfparse.y"
                {
			inssainfoalg(&cur_sainfo->algs[cur_algclass], (yyvsp[0].alg));
		}
#line 3892 "cfparse.c"
    break;

  case 231:
#line 1612 "cfparse.y"
                {
			int defklen;

			(yyval.alg) = newsainfoalg();
			if ((yyval.alg) == NULL) {
				yyerror("failed to get algorithm allocation");
				return -1;
			}

			(yyval.alg)->alg = algtype2doi(cur_algclass, (yyvsp[-1].num));
			if ((yyval.alg)->alg == -1) {
				yyerror("algorithm mismatched");
				racoon_free((yyval.alg));
				(yyval.alg) = NULL;
				return -1;
			}

			defklen = default_keylen(cur_algclass, (yyvsp[-1].num));
			if (defklen == 0) {
				if ((yyvsp[0].num)) {
					yyerror("keylen not allowed");
					racoon_free((yyval.alg));
					(yyval.alg) = NULL;
					return -1;
				}
			} else {
				if ((yyvsp[0].num) && check_keylen(cur_algclass, (yyvsp[-1].num), (yyvsp[0].num)) < 0) {
					yyerror("invalid keylen %d", (yyvsp[0].num));
					racoon_free((yyval.alg));
					(yyval.alg) = NULL;
					return -1;
				}
			}

			if ((yyvsp[0].num))
				(yyval.alg)->encklen = (yyvsp[0].num);
			else
				(yyval.alg)->encklen = defklen;

			/* check if it's supported algorithm by kernel */
			if (!(cur_algclass == algclass_ipsec_auth && (yyvsp[-1].num) == algtype_non_auth)
			 && pk_checkalg(cur_algclass, (yyvsp[-1].num), (yyval.alg)->encklen)) {
				int a = algclass2doi(cur_algclass);
				int b = algtype2doi(cur_algclass, (yyvsp[-1].num));
				if (a == IPSECDOI_ATTR_AUTH)
					a = IPSECDOI_PROTO_IPSEC_AH;
				yyerror("algorithm %s not supported by the kernel (missing module?)",
					s_ipsecdoi_trns(a, b));
				racoon_free((yyval.alg));
				(yyval.alg) = NULL;
				return -1;
			}
		}
#line 3950 "cfparse.c"
    break;

  case 232:
#line 1667 "cfparse.y"
                              { (yyval.num) = ~0; }
#line 3956 "cfparse.c"
    break;

  case 233:
#line 1668 "cfparse.y"
                       { (yyval.num) = (yyvsp[0].num); }
#line 3962 "cfparse.c"
    break;

  case 234:
#line 1671 "cfparse.y"
                              { (yyval.num) = IPSEC_PORT_ANY; }
#line 3968 "cfparse.c"
    break;

  case 235:
#line 1672 "cfparse.y"
                     { (yyval.num) = (yyvsp[0].num); }
#line 3974 "cfparse.c"
    break;

  case 236:
#line 1673 "cfparse.y"
                        { (yyval.num) = IPSEC_PORT_ANY; }
#line 3980 "cfparse.c"
    break;

  case 237:
#line 1676 "cfparse.y"
                       { (yyval.num) = (yyvsp[0].num); }
#line 3986 "cfparse.c"
    break;

  case 238:
#line 1677 "cfparse.y"
                         { (yyval.num) = (yyvsp[0].num); }
#line 3992 "cfparse.c"
    break;

  case 239:
#line 1678 "cfparse.y"
                    { (yyval.num) = IPSEC_ULPROTO_ANY; }
#line 3998 "cfparse.c"
    break;

  case 240:
#line 1681 "cfparse.y"
                              { (yyval.num) = 0; }
#line 4004 "cfparse.c"
    break;

  case 241:
#line 1682 "cfparse.y"
                       { (yyval.num) = (yyvsp[0].num); }
#line 4010 "cfparse.c"
    break;

  case 242:
#line 1688 "cfparse.y"
                {
			struct remoteconf *from, *new;

			if (getrmconf_by_name((yyvsp[-2].val)->v) != NULL) {
				yyerror("named remoteconf \"%s\" already exists.");
				return -1;
			}

			from = getrmconf_by_name((yyvsp[0].val)->v);
			if (from == NULL) {
				yyerror("named parent remoteconf \"%s\" does not exist.",
					(yyvsp[0].val)->v);
				return -1;
			}

			new = duprmconf_shallow(from);
			if (new == NULL) {
				yyerror("failed to duplicate remoteconf from \"%s\".",
					(yyvsp[0].val)->v);
				return -1;
			}

			new->name = racoon_strdup((yyvsp[-2].val)->v);
			cur_rmconf = new;

			vfree((yyvsp[-2].val));
			vfree((yyvsp[0].val));
		}
#line 4043 "cfparse.c"
    break;

  case 244:
#line 1718 "cfparse.y"
                {
			struct remoteconf *new;

			if (getrmconf_by_name((yyvsp[0].val)->v) != NULL) {
				yyerror("Named remoteconf \"%s\" already exists.");
				return -1;
			}

			new = newrmconf();
			if (new == NULL) {
				yyerror("failed to get new remoteconf.");
				return -1;
			}
			new->name = racoon_strdup((yyvsp[0].val)->v);
			cur_rmconf = new;

			vfree((yyvsp[0].val));
		}
#line 4066 "cfparse.c"
    break;

  case 246:
#line 1738 "cfparse.y"
                {
			struct remoteconf *from, *new;

			from = getrmconf((yyvsp[0].saddr), GETRMCONF_F_NO_ANONYMOUS);
			if (from == NULL) {
				yyerror("failed to get remoteconf for %s.",
					saddr2str((yyvsp[0].saddr)));
				return -1;
			}

			new = duprmconf_shallow(from);
			if (new == NULL) {
				yyerror("failed to duplicate remoteconf from %s.",
					saddr2str((yyvsp[0].saddr)));
				return -1;
			}

			racoon_free((yyvsp[0].saddr));
			new->remote = (yyvsp[-2].saddr);
			cur_rmconf = new;
		}
#line 4092 "cfparse.c"
    break;

  case 248:
#line 1761 "cfparse.y"
                {
			struct remoteconf *new;

			new = newrmconf();
			if (new == NULL) {
				yyerror("failed to get new remoteconf.");
				return -1;
			}

			new->remote = (yyvsp[0].saddr);
			cur_rmconf = new;
		}
#line 4109 "cfparse.c"
    break;

  case 251:
#line 1779 "cfparse.y"
                {
			if (process_rmconf() != 0)
				return -1;
		}
#line 4118 "cfparse.c"
    break;

  case 252:
#line 1787 "cfparse.y"
                {
			if (process_rmconf() != 0)
				return -1;
		}
#line 4127 "cfparse.c"
    break;

  case 253:
#line 1794 "cfparse.y"
                {
			(yyval.saddr) = newsaddr(sizeof(struct sockaddr));
			(yyval.saddr)->sa_family = AF_UNSPEC;
			((struct sockaddr_in *)(yyval.saddr))->sin_port = htons((yyvsp[0].num));
		}
#line 4137 "cfparse.c"
    break;

  case 254:
#line 1800 "cfparse.y"
                {
			(yyval.saddr) = (yyvsp[0].saddr);
			if ((yyval.saddr) == NULL) {
				yyerror("failed to allocate sockaddr");
				return -1;
			}
		}
#line 4149 "cfparse.c"
    break;

  case 257:
#line 1814 "cfparse.y"
                {
			if (cur_rmconf->remote != NULL) {
				yyerror("remote_address already specified");
				return -1;
			}
			cur_rmconf->remote = (yyvsp[0].saddr);
		}
#line 4161 "cfparse.c"
    break;

  case 259:
#line 1823 "cfparse.y"
                {
			cur_rmconf->etypes = NULL;
		}
#line 4169 "cfparse.c"
    break;

  case 261:
#line 1827 "cfparse.y"
                            { cur_rmconf->doitype = (yyvsp[0].num); }
#line 4175 "cfparse.c"
    break;

  case 263:
#line 1828 "cfparse.y"
                                        { cur_rmconf->sittype = (yyvsp[0].num); }
#line 4181 "cfparse.c"
    break;

  case 266:
#line 1831 "cfparse.y"
                {
			yywarn("This directive without certtype will be removed!\n");
			yywarn("Please use 'peers_certfile x509 \"%s\";' instead\n", (yyvsp[0].val)->v);

			if (cur_rmconf->peerscert != NULL) {
				yyerror("peers_certfile already defined\n");
				return -1;
			}

			if (load_x509((yyvsp[0].val)->v, &cur_rmconf->peerscertfile,
				      &cur_rmconf->peerscert)) {
				yyerror("failed to load certificate \"%s\"\n",
					(yyvsp[0].val)->v);
				return -1;
			}

			vfree((yyvsp[0].val));
		}
#line 4204 "cfparse.c"
    break;

  case 268:
#line 1851 "cfparse.y"
                {
			if (cur_rmconf->peerscert != NULL) {
				yyerror("peers_certfile already defined\n");
				return -1;
			}

			if (load_x509((yyvsp[0].val)->v, &cur_rmconf->peerscertfile,
				      &cur_rmconf->peerscert)) {
				yyerror("failed to load certificate \"%s\"\n",
					(yyvsp[0].val)->v);
				return -1;
			}

			vfree((yyvsp[0].val));
		}
#line 4224 "cfparse.c"
    break;

  case 270:
#line 1868 "cfparse.y"
                {
			char path[MAXPATHLEN];
			int ret = 0;

			if (cur_rmconf->peerscert != NULL) {
				yyerror("peers_certfile already defined\n");
				return -1;
			}

			cur_rmconf->peerscert = vmalloc(1);
			if (cur_rmconf->peerscert == NULL) {
				yyerror("failed to allocate peerscert");
				return -1;
			}
			cur_rmconf->peerscert->v[0] = ISAKMP_CERT_PLAINRSA;

			getpathname(path, sizeof(path),
				    LC_PATHTYPE_CERT, (yyvsp[0].val)->v);
			if (rsa_parse_file(cur_rmconf->rsa_public, path,
					   RSA_TYPE_PUBLIC)) {
				yyerror("Couldn't parse keyfile.\n", path);
				return -1;
			}
			plog(LLV_DEBUG, LOCATION, NULL,
			     "Public PlainRSA keyfile parsed: %s\n", path);

			vfree((yyvsp[0].val));
		}
#line 4257 "cfparse.c"
    break;

  case 272:
#line 1898 "cfparse.y"
                {
			if (cur_rmconf->peerscert != NULL) {
				yyerror("peers_certfile already defined\n");
				return -1;
			}
			cur_rmconf->peerscert = vmalloc(1);
			if (cur_rmconf->peerscert == NULL) {
				yyerror("failed to allocate peerscert");
				return -1;
			}
			cur_rmconf->peerscert->v[0] = ISAKMP_CERT_DNS;
		}
#line 4274 "cfparse.c"
    break;

  case 274:
#line 1912 "cfparse.y"
                {
			if (cur_rmconf->cacert != NULL) {
				yyerror("ca_type already defined\n");
				return -1;
			}

			if (load_x509((yyvsp[0].val)->v, &cur_rmconf->cacertfile,
				      &cur_rmconf->cacert)) {
				yyerror("failed to load certificate \"%s\"\n",
					(yyvsp[0].val)->v);
				return -1;
			}

			vfree((yyvsp[0].val));
		}
#line 4294 "cfparse.c"
    break;

  case 276:
#line 1928 "cfparse.y"
                                   { cur_rmconf->verify_cert = (yyvsp[0].num); }
#line 4300 "cfparse.c"
    break;

  case 278:
#line 1929 "cfparse.y"
                                 { cur_rmconf->send_cert = (yyvsp[0].num); }
#line 4306 "cfparse.c"
    break;

  case 280:
#line 1930 "cfparse.y"
                               { cur_rmconf->send_cr = (yyvsp[0].num); }
#line 4312 "cfparse.c"
    break;

  case 282:
#line 1931 "cfparse.y"
                                      { cur_rmconf->match_empty_cr = (yyvsp[0].num); }
#line 4318 "cfparse.c"
    break;

  case 284:
#line 1933 "cfparse.y"
                {
			if (set_identifier(&cur_rmconf->idv, (yyvsp[-1].num), (yyvsp[0].val)) != 0) {
				yyerror("failed to set identifer.\n");
				return -1;
			}
			cur_rmconf->idvtype = (yyvsp[-1].num);
		}
#line 4330 "cfparse.c"
    break;

  case 286:
#line 1942 "cfparse.y"
                {
			if (set_identifier_qual(&cur_rmconf->idv, (yyvsp[-2].num), (yyvsp[0].val), (yyvsp[-1].num)) != 0) {
				yyerror("failed to set identifer.\n");
				return -1;
			}
			cur_rmconf->idvtype = (yyvsp[-2].num);
		}
#line 4342 "cfparse.c"
    break;

  case 288:
#line 1951 "cfparse.y"
                {
#ifdef ENABLE_HYBRID
			/* formerly identifier type login */
			if (xauth_rmconf_used(&cur_rmconf->xauth) == -1) {
				yyerror("failed to allocate xauth state\n");
				return -1;
			}
			if ((cur_rmconf->xauth->login = vdup((yyvsp[0].val))) == NULL) {
				yyerror("failed to set identifer.\n");
				return -1;
			}
#else
			yyerror("racoon not configured with --enable-hybrid");
#endif
		}
#line 4362 "cfparse.c"
    break;

  case 290:
#line 1968 "cfparse.y"
                {
			struct idspec  *id;
			id = newidspec();
			if (id == NULL) {
				yyerror("failed to allocate idspec");
				return -1;
			}
			if (set_identifier(&id->id, (yyvsp[-1].num), (yyvsp[0].val)) != 0) {
				yyerror("failed to set identifer.\n");
				racoon_free(id);
				return -1;
			}
			id->idtype = (yyvsp[-1].num);
			genlist_append (cur_rmconf->idvl_p, id);
		}
#line 4382 "cfparse.c"
    break;

  case 292:
#line 1985 "cfparse.y"
                {
			struct idspec  *id;
			id = newidspec();
			if (id == NULL) {
				yyerror("failed to allocate idspec");
				return -1;
			}
			if (set_identifier_qual(&id->id, (yyvsp[-2].num), (yyvsp[0].val), (yyvsp[-1].num)) != 0) {
				yyerror("failed to set identifer.\n");
				racoon_free(id);
				return -1;
			}
			id->idtype = (yyvsp[-2].num);
			genlist_append (cur_rmconf->idvl_p, id);
		}
#line 4402 "cfparse.c"
    break;

  case 294:
#line 2001 "cfparse.y"
                                         { cur_rmconf->verify_identifier = (yyvsp[0].num); }
#line 4408 "cfparse.c"
    break;

  case 296:
#line 2002 "cfparse.y"
                                  { cur_rmconf->nonce_size = (yyvsp[0].num); }
#line 4414 "cfparse.c"
    break;

  case 298:
#line 2004 "cfparse.y"
                {
			yyerror("dh_group cannot be defined here.");
			return -1;
		}
#line 4423 "cfparse.c"
    break;

  case 300:
#line 2009 "cfparse.y"
                               { cur_rmconf->passive = (yyvsp[0].num); }
#line 4429 "cfparse.c"
    break;

  case 302:
#line 2010 "cfparse.y"
                                { cur_rmconf->ike_frag = (yyvsp[0].num); }
#line 4435 "cfparse.c"
    break;

  case 304:
#line 2011 "cfparse.y"
                                            { cur_rmconf->ike_frag = ISAKMP_FRAG_FORCE; }
#line 4441 "cfparse.c"
    break;

  case 306:
#line 2012 "cfparse.y"
                                { 
#ifdef SADB_X_EXT_NAT_T_FRAG
        		if (libipsec_opt & LIBIPSEC_OPT_FRAG)
				cur_rmconf->esp_frag = (yyvsp[0].num); 
			else
                		yywarn("libipsec lacks IKE frag support");
#else
			yywarn("Your kernel does not support esp_frag");
#endif
		}
#line 4456 "cfparse.c"
    break;

  case 308:
#line 2022 "cfparse.y"
                                              { 
			if (cur_rmconf->script[SCRIPT_PHASE1_UP] != NULL)
				vfree(cur_rmconf->script[SCRIPT_PHASE1_UP]);

			cur_rmconf->script[SCRIPT_PHASE1_UP] = 
			    script_path_add(vdup((yyvsp[-1].val)));
		}
#line 4468 "cfparse.c"
    break;

  case 310:
#line 2029 "cfparse.y"
                                                { 
			if (cur_rmconf->script[SCRIPT_PHASE1_DOWN] != NULL)
				vfree(cur_rmconf->script[SCRIPT_PHASE1_DOWN]);

			cur_rmconf->script[SCRIPT_PHASE1_DOWN] = 
			    script_path_add(vdup((yyvsp[-1].val)));
		}
#line 4480 "cfparse.c"
    break;

  case 312:
#line 2036 "cfparse.y"
                                                { 
			if (cur_rmconf->script[SCRIPT_PHASE1_DEAD] != NULL)
				vfree(cur_rmconf->script[SCRIPT_PHASE1_DEAD]);

			cur_rmconf->script[SCRIPT_PHASE1_DEAD] = 
			    script_path_add(vdup((yyvsp[-1].val)));
		}
#line 4492 "cfparse.c"
    break;

  case 314:
#line 2043 "cfparse.y"
                                { cur_rmconf->mode_cfg = (yyvsp[0].num); }
#line 4498 "cfparse.c"
    break;

  case 316:
#line 2044 "cfparse.y"
                                         {
			cur_rmconf->weak_phase1_check = (yyvsp[0].num);
		}
#line 4506 "cfparse.c"
    break;

  case 318:
#line 2047 "cfparse.y"
                                       { cur_rmconf->gen_policy = (yyvsp[0].num); }
#line 4512 "cfparse.c"
    break;

  case 320:
#line 2048 "cfparse.y"
                                               { cur_rmconf->gen_policy = (yyvsp[0].num); }
#line 4518 "cfparse.c"
    break;

  case 322:
#line 2049 "cfparse.y"
                                     { cur_rmconf->support_proxy = (yyvsp[0].num); }
#line 4524 "cfparse.c"
    break;

  case 324:
#line 2050 "cfparse.y"
                                       { cur_rmconf->ini_contact = (yyvsp[0].num); }
#line 4530 "cfparse.c"
    break;

  case 326:
#line 2052 "cfparse.y"
                {
#ifdef ENABLE_NATT
        		if (libipsec_opt & LIBIPSEC_OPT_NATT)
				cur_rmconf->nat_traversal = (yyvsp[0].num);
			else
                		yyerror("libipsec lacks NAT-T support");
#else
			yyerror("NAT-T support not compiled in.");
#endif
		}
#line 4545 "cfparse.c"
    break;

  case 328:
#line 2063 "cfparse.y"
                {
#ifdef ENABLE_NATT
			if (libipsec_opt & LIBIPSEC_OPT_NATT)
				cur_rmconf->nat_traversal = NATT_FORCE;
			else
                		yyerror("libipsec lacks NAT-T support");
#else
			yyerror("NAT-T support not compiled in.");
#endif
		}
#line 4560 "cfparse.c"
    break;

  case 330:
#line 2074 "cfparse.y"
                {
#ifdef ENABLE_DPD
			cur_rmconf->dpd = (yyvsp[0].num);
#else
			yyerror("DPD support not compiled in.");
#endif
		}
#line 4572 "cfparse.c"
    break;

  case 332:
#line 2082 "cfparse.y"
                {
#ifdef ENABLE_DPD
			cur_rmconf->dpd_interval = (yyvsp[0].num);
#else
			yyerror("DPD support not compiled in.");
#endif
		}
#line 4584 "cfparse.c"
    break;

  case 334:
#line 2091 "cfparse.y"
                {
#ifdef ENABLE_DPD
			cur_rmconf->dpd_retry = (yyvsp[0].num);
#else
			yyerror("DPD support not compiled in.");
#endif
		}
#line 4596 "cfparse.c"
    break;

  case 336:
#line 2100 "cfparse.y"
                {
#ifdef ENABLE_DPD
			cur_rmconf->dpd_maxfails = (yyvsp[0].num);
#else
			yyerror("DPD support not compiled in.");
#endif
		}
#line 4608 "cfparse.c"
    break;

  case 338:
#line 2108 "cfparse.y"
                             { cur_rmconf->rekey = (yyvsp[0].num); }
#line 4614 "cfparse.c"
    break;

  case 340:
#line 2109 "cfparse.y"
                                         { cur_rmconf->rekey = REKEY_FORCE; }
#line 4620 "cfparse.c"
    break;

  case 342:
#line 2111 "cfparse.y"
                {
			cur_rmconf->ph1id = (yyvsp[0].num);
		}
#line 4628 "cfparse.c"
    break;

  case 344:
#line 2116 "cfparse.y"
                {
			cur_rmconf->lifetime = (yyvsp[-1].num) * (yyvsp[0].num);
		}
#line 4636 "cfparse.c"
    break;

  case 346:
#line 2120 "cfparse.y"
                                                    { cur_rmconf->pcheck_level = (yyvsp[0].num); }
#line 4642 "cfparse.c"
    break;

  case 348:
#line 2122 "cfparse.y"
                {
#if 1
			yyerror("byte lifetime support is deprecated in Phase1");
			return -1;
#else
			yywarn("the lifetime of bytes in phase 1 "
				"will be ignored at the moment.");
			cur_rmconf->lifebyte = fix_lifebyte((yyvsp[-1].num) * (yyvsp[0].num));
			if (cur_rmconf->lifebyte == 0)
				return -1;
#endif
		}
#line 4659 "cfparse.c"
    break;

  case 350:
#line 2136 "cfparse.y"
                {
			struct secprotospec *spspec;

			spspec = newspspec();
			if (spspec == NULL)
				return -1;
			insspspec(cur_rmconf, spspec);
		}
#line 4672 "cfparse.c"
    break;

  case 353:
#line 2149 "cfparse.y"
                {
			struct etypes *new;
			new = racoon_malloc(sizeof(struct etypes));
			if (new == NULL) {
				yyerror("failed to allocate etypes");
				return -1;
			}
			new->type = (yyvsp[0].num);
			new->next = NULL;
			if (cur_rmconf->etypes == NULL)
				cur_rmconf->etypes = new;
			else {
				struct etypes *p;
				for (p = cur_rmconf->etypes;
				     p->next != NULL;
				     p = p->next)
					;
				p->next = new;
			}
		}
#line 4697 "cfparse.c"
    break;

  case 354:
#line 2172 "cfparse.y"
                {
			if (cur_rmconf->mycert != NULL) {
				yyerror("certificate_type already defined\n");
				return -1;
			}

			if (load_x509((yyvsp[-1].val)->v, &cur_rmconf->mycertfile,
				      &cur_rmconf->mycert)) {
				yyerror("failed to load certificate \"%s\"\n",
					(yyvsp[-1].val)->v);
				return -1;
			}

			cur_rmconf->myprivfile = racoon_strdup((yyvsp[0].val)->v);
			STRDUP_FATAL(cur_rmconf->myprivfile);

			vfree((yyvsp[-1].val));
			vfree((yyvsp[0].val));
		}
#line 4721 "cfparse.c"
    break;

  case 356:
#line 2193 "cfparse.y"
                {
			char path[MAXPATHLEN];
			int ret = 0;

			if (cur_rmconf->mycert != NULL) {
				yyerror("certificate_type already defined\n");
				return -1;
			}

			cur_rmconf->mycert = vmalloc(1);
			if (cur_rmconf->mycert == NULL) {
				yyerror("failed to allocate mycert");
				return -1;
			}
			cur_rmconf->mycert->v[0] = ISAKMP_CERT_PLAINRSA;

			getpathname(path, sizeof(path),
				    LC_PATHTYPE_CERT, (yyvsp[0].val)->v);
			cur_rmconf->send_cr = FALSE;
			cur_rmconf->send_cert = FALSE;
			cur_rmconf->verify_cert = FALSE;
			if (rsa_parse_file(cur_rmconf->rsa_private, path,
					   RSA_TYPE_PRIVATE)) {
				yyerror("Couldn't parse keyfile.\n", path);
				return -1;
			}
			plog(LLV_DEBUG, LOCATION, NULL,
			     "Private PlainRSA keyfile parsed: %s\n", path);
			vfree((yyvsp[0].val));
		}
#line 4756 "cfparse.c"
    break;

  case 358:
#line 2227 "cfparse.y"
                {
			(yyval.num) = algtype2doi(algclass_isakmp_dh, (yyvsp[0].num));
			if ((yyval.num) == -1) {
				yyerror("must be DH group");
				return -1;
			}
		}
#line 4768 "cfparse.c"
    break;

  case 359:
#line 2235 "cfparse.y"
                {
			if (ARRAYLEN(num2dhgroup) > (yyvsp[0].num) && num2dhgroup[(yyvsp[0].num)] != 0) {
				(yyval.num) = num2dhgroup[(yyvsp[0].num)];
			} else {
				yyerror("must be DH group");
				(yyval.num) = 0;
				return -1;
			}
		}
#line 4782 "cfparse.c"
    break;

  case 360:
#line 2246 "cfparse.y"
                              { (yyval.val) = NULL; }
#line 4788 "cfparse.c"
    break;

  case 361:
#line 2247 "cfparse.y"
                           { (yyval.val) = (yyvsp[0].val); }
#line 4794 "cfparse.c"
    break;

  case 362:
#line 2248 "cfparse.y"
                             { (yyval.val) = (yyvsp[0].val); }
#line 4800 "cfparse.c"
    break;

  case 365:
#line 2256 "cfparse.y"
                {
			cur_rmconf->spspec->lifetime = (yyvsp[-1].num) * (yyvsp[0].num);
		}
#line 4808 "cfparse.c"
    break;

  case 367:
#line 2261 "cfparse.y"
                {
#if 1
			yyerror("byte lifetime support is deprecated");
			return -1;
#else
			cur_rmconf->spspec->lifebyte = fix_lifebyte((yyvsp[-1].num) * (yyvsp[0].num));
			if (cur_rmconf->spspec->lifebyte == 0)
				return -1;
#endif
		}
#line 4823 "cfparse.c"
    break;

  case 369:
#line 2273 "cfparse.y"
                {
			cur_rmconf->spspec->algclass[algclass_isakmp_dh] = (yyvsp[0].num);
		}
#line 4831 "cfparse.c"
    break;

  case 371:
#line 2278 "cfparse.y"
                {
			if (cur_rmconf->spspec->vendorid != VENDORID_GSSAPI) {
				yyerror("wrong Vendor ID for gssapi_id");
				return -1;
			}
			if (cur_rmconf->spspec->gssid != NULL)
				racoon_free(cur_rmconf->spspec->gssid);
			cur_rmconf->spspec->gssid =
			    racoon_strdup((yyvsp[0].val)->v);
			STRDUP_FATAL(cur_rmconf->spspec->gssid);
		}
#line 4847 "cfparse.c"
    break;

  case 373:
#line 2291 "cfparse.y"
                {
			int doi;
			int defklen;

			doi = algtype2doi((yyvsp[-2].num), (yyvsp[-1].num));
			if (doi == -1) {
				yyerror("algorithm mismatched 1");
				return -1;
			}

			switch ((yyvsp[-2].num)) {
			case algclass_isakmp_enc:
			/* reject suppressed algorithms */
#ifndef HAVE_OPENSSL_RC5_H
				if ((yyvsp[-1].num) == algtype_rc5) {
					yyerror("algorithm %s not supported",
					    s_attr_isakmp_enc(doi));
					return -1;
				}
#endif
#ifndef HAVE_OPENSSL_IDEA_H
				if ((yyvsp[-1].num) == algtype_idea) {
					yyerror("algorithm %s not supported",
					    s_attr_isakmp_enc(doi));
					return -1;
				}
#endif

				cur_rmconf->spspec->algclass[algclass_isakmp_enc] = doi;
				defklen = default_keylen((yyvsp[-2].num), (yyvsp[-1].num));
				if (defklen == 0) {
					if ((yyvsp[0].num)) {
						yyerror("keylen not allowed");
						return -1;
					}
				} else {
					if ((yyvsp[0].num) && check_keylen((yyvsp[-2].num), (yyvsp[-1].num), (yyvsp[0].num)) < 0) {
						yyerror("invalid keylen %d", (yyvsp[0].num));
						return -1;
					}
				}
				if ((yyvsp[0].num))
					cur_rmconf->spspec->encklen = (yyvsp[0].num);
				else
					cur_rmconf->spspec->encklen = defklen;
				break;
			case algclass_isakmp_hash:
				cur_rmconf->spspec->algclass[algclass_isakmp_hash] = doi;
				break;
			case algclass_isakmp_ameth:
				cur_rmconf->spspec->algclass[algclass_isakmp_ameth] = doi;
				/*
				 * We may have to set the Vendor ID for the
				 * authentication method we're using.
				 */
				switch ((yyvsp[-1].num)) {
				case algtype_gssapikrb:
					if (cur_rmconf->spspec->vendorid !=
					    VENDORID_UNKNOWN) {
						yyerror("Vendor ID mismatch "
						    "for auth method");
						return -1;
					}
					/*
					 * For interoperability with Win2k,
					 * we set the Vendor ID to "GSSAPI".
					 */
					cur_rmconf->spspec->vendorid =
					    VENDORID_GSSAPI;
					break;
				case algtype_rsasig:
					if (oakley_get_certtype(cur_rmconf->peerscert) == ISAKMP_CERT_PLAINRSA) {
						if (rsa_list_count(cur_rmconf->rsa_private) == 0) {
							yyerror ("Private PlainRSA key not set. "
								 "Use directive 'certificate_type plainrsa ...'\n");
							return -1;
						}
						if (rsa_list_count(cur_rmconf->rsa_public) == 0) {
							yyerror ("Public PlainRSA keys not set. "
								 "Use directive 'peers_certfile plainrsa ...'\n");
							return -1;
						}
					}
					break;
				default:
					break;
				}
				break;
			default:
				yyerror("algorithm mismatched 2");
				return -1;
			}
		}
#line 4945 "cfparse.c"
    break;

  case 375:
#line 2388 "cfparse.y"
                                { (yyval.num) = 1; }
#line 4951 "cfparse.c"
    break;

  case 376:
#line 2389 "cfparse.y"
                                { (yyval.num) = 60; }
#line 4957 "cfparse.c"
    break;

  case 377:
#line 2390 "cfparse.y"
                                { (yyval.num) = (60 * 60); }
#line 4963 "cfparse.c"
    break;

  case 378:
#line 2393 "cfparse.y"
                                { (yyval.num) = 1; }
#line 4969 "cfparse.c"
    break;

  case 379:
#line 2394 "cfparse.y"
                                { (yyval.num) = 1024; }
#line 4975 "cfparse.c"
    break;

  case 380:
#line 2395 "cfparse.y"
                                { (yyval.num) = (1024 * 1024); }
#line 4981 "cfparse.c"
    break;

  case 381:
#line 2396 "cfparse.y"
                                { (yyval.num) = (1024 * 1024 * 1024); }
#line 4987 "cfparse.c"
    break;


#line 4991 "cfparse.c"

      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
               ? yytable[yyi]
               : yydefgoto[yylhs]);
  }

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = YY_CAST (char *, YYSTACK_ALLOC (YY_CAST (YYSIZE_T, yymsg_alloc)));
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYTERROR;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  yystos[yystate], yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;


#if !defined yyoverflow || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif


/*-----------------------------------------------------.
| yyreturn -- parsing is finished, return the result.  |
`-----------------------------------------------------*/
yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  yystos[+*yyssp], yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  return yyresult;
}
#line 2398 "cfparse.y"


static struct secprotospec *
newspspec()
{
	struct secprotospec *new;

	new = racoon_calloc(1, sizeof(*new));
	if (new == NULL) {
		yyerror("failed to allocate spproto");
		return NULL;
	}

	new->encklen = 0;	/*XXX*/

	/*
	 * Default to "uknown" vendor -- we will override this
	 * as necessary.  When we send a Vendor ID payload, an
	 * "unknown" will be translated to a KAME/racoon ID.
	 */
	new->vendorid = VENDORID_UNKNOWN;

	return new;
}

/*
 * insert into head of list.
 */
static void
insspspec(rmconf, spspec)
	struct remoteconf *rmconf;
	struct secprotospec *spspec;
{
	if (rmconf->spspec != NULL)
		rmconf->spspec->prev = spspec;
	spspec->next = rmconf->spspec;
	rmconf->spspec = spspec;
}

static struct secprotospec *
dupspspec(spspec)
	struct secprotospec *spspec;
{
	struct secprotospec *new;

	new = newspspec();
	if (new == NULL) {
		plog(LLV_ERROR, LOCATION, NULL, 
		    "dupspspec: malloc failed\n");
		return NULL;
	}
	memcpy(new, spspec, sizeof(*new));

	if (spspec->gssid) {
		new->gssid = racoon_strdup(spspec->gssid);
		STRDUP_FATAL(new->gssid);
	}
	if (spspec->remote) {
		new->remote = racoon_malloc(sizeof(*new->remote));
		if (new->remote == NULL) {
			plog(LLV_ERROR, LOCATION, NULL, 
			    "dupspspec: malloc failed (remote)\n");
			return NULL;
		}
		memcpy(new->remote, spspec->remote, sizeof(*new->remote));
	}

	return new;
}

/*
 * copy the whole list
 */
void
dupspspec_list(dst, src)
	struct remoteconf *dst, *src;
{
	struct secprotospec *p, *new, *last;

	for(p = src->spspec, last = NULL; p; p = p->next, last = new) {
		new = dupspspec(p);
		if (new == NULL)
			exit(1);

		new->prev = last;
		new->next = NULL; /* not necessary but clean */

		if (last)
			last->next = new;
		else /* first element */
			dst->spspec = new;

	}
}

/*
 * delete the whole list
 */
void
flushspspec(rmconf)
	struct remoteconf *rmconf;
{
	struct secprotospec *p;

	while(rmconf->spspec != NULL) {
		p = rmconf->spspec;
		rmconf->spspec = p->next;
		if (p->next != NULL)
			p->next->prev = NULL; /* not necessary but clean */

		if (p->gssid)
			racoon_free(p->gssid);
		if (p->remote)
			racoon_free(p->remote);
		racoon_free(p);
	}
	rmconf->spspec = NULL;
}

/* set final acceptable proposal */
static int
set_isakmp_proposal(rmconf)
	struct remoteconf *rmconf;
{
	struct secprotospec *s;
	int prop_no = 1; 
	int trns_no = 1;
	int32_t types[MAXALGCLASS];

	/* mandatory check */
	if (rmconf->spspec == NULL) {
		yyerror("no remote specification found: %s.\n",
			saddr2str(rmconf->remote));
		return -1;
	}
	for (s = rmconf->spspec; s != NULL; s = s->next) {
		/* XXX need more to check */
		if (s->algclass[algclass_isakmp_enc] == 0) {
			yyerror("encryption algorithm required.");
			return -1;
		}
		if (s->algclass[algclass_isakmp_hash] == 0) {
			yyerror("hash algorithm required.");
			return -1;
		}
		if (s->algclass[algclass_isakmp_dh] == 0) {
			yyerror("DH group required.");
			return -1;
		}
		if (s->algclass[algclass_isakmp_ameth] == 0) {
			yyerror("authentication method required.");
			return -1;
		}
	}

	/* skip to last part */
	for (s = rmconf->spspec; s->next != NULL; s = s->next)
		;

	while (s != NULL) {
		plog(LLV_DEBUG2, LOCATION, NULL,
			"lifetime = %ld\n", (long)
			(s->lifetime ? s->lifetime : rmconf->lifetime));
		plog(LLV_DEBUG2, LOCATION, NULL,
			"lifebyte = %d\n",
			s->lifebyte ? s->lifebyte : rmconf->lifebyte);
		plog(LLV_DEBUG2, LOCATION, NULL,
			"encklen=%d\n", s->encklen);

		memset(types, 0, ARRAYLEN(types) * sizeof(int32_t));
		types[algclass_isakmp_enc] = s->algclass[algclass_isakmp_enc];
		types[algclass_isakmp_hash] = s->algclass[algclass_isakmp_hash];
		types[algclass_isakmp_dh] = s->algclass[algclass_isakmp_dh];
		types[algclass_isakmp_ameth] =
		    s->algclass[algclass_isakmp_ameth];

		/* expanding spspec */
		clean_tmpalgtype();
		trns_no = expand_isakmpspec(prop_no, trns_no, types,
				algclass_isakmp_enc, algclass_isakmp_ameth + 1,
				s->lifetime ? s->lifetime : rmconf->lifetime,
				s->lifebyte ? s->lifebyte : rmconf->lifebyte,
				s->encklen, s->vendorid, s->gssid,
				rmconf);
		if (trns_no == -1) {
			plog(LLV_ERROR, LOCATION, NULL,
				"failed to expand isakmp proposal.\n");
			return -1;
		}

		s = s->prev;
	}

	if (rmconf->proposal == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"no proposal found.\n");
		return -1;
	}

	return 0;
}

static void
clean_tmpalgtype()
{
	int i;
	for (i = 0; i < MAXALGCLASS; i++)
		tmpalgtype[i] = 0;	/* means algorithm undefined. */
}

static int
expand_isakmpspec(prop_no, trns_no, types,
		class, last, lifetime, lifebyte, encklen, vendorid, gssid,
		rmconf)
	int prop_no, trns_no;
	int *types, class, last;
	time_t lifetime;
	int lifebyte;
	int encklen;
	int vendorid;
	char *gssid;
	struct remoteconf *rmconf;
{
	struct isakmpsa *new;

	/* debugging */
    {
	int j;
	char tb[10];
	plog(LLV_DEBUG2, LOCATION, NULL,
		"p:%d t:%d\n", prop_no, trns_no);
	for (j = class; j < MAXALGCLASS; j++) {
		snprintf(tb, sizeof(tb), "%d", types[j]);
		plog(LLV_DEBUG2, LOCATION, NULL,
			"%s%s%s%s\n",
			s_algtype(j, types[j]),
			types[j] ? "(" : "",
			tb[0] == '0' ? "" : tb,
			types[j] ? ")" : "");
	}
	plog(LLV_DEBUG2, LOCATION, NULL, "\n");
    }

#define TMPALGTYPE2STR(n) \
	s_algtype(algclass_isakmp_##n, types[algclass_isakmp_##n])
		/* check mandatory values */
		if (types[algclass_isakmp_enc] == 0
		 || types[algclass_isakmp_ameth] == 0
		 || types[algclass_isakmp_hash] == 0
		 || types[algclass_isakmp_dh] == 0) {
			yyerror("few definition of algorithm "
				"enc=%s ameth=%s hash=%s dhgroup=%s.\n",
				TMPALGTYPE2STR(enc),
				TMPALGTYPE2STR(ameth),
				TMPALGTYPE2STR(hash),
				TMPALGTYPE2STR(dh));
			return -1;
		}
#undef TMPALGTYPE2STR

	/* set new sa */
	new = newisakmpsa();
	if (new == NULL) {
		yyerror("failed to allocate isakmp sa");
		return -1;
	}
	new->prop_no = prop_no;
	new->trns_no = trns_no++;
	new->lifetime = lifetime;
	new->lifebyte = lifebyte;
	new->enctype = types[algclass_isakmp_enc];
	new->encklen = encklen;
	new->authmethod = types[algclass_isakmp_ameth];
	new->hashtype = types[algclass_isakmp_hash];
	new->dh_group = types[algclass_isakmp_dh];
	new->vendorid = vendorid;
#ifdef HAVE_GSSAPI
	if (new->authmethod == OAKLEY_ATTR_AUTH_METHOD_GSSAPI_KRB) {
		if (gssid != NULL) {
			if ((new->gssid = vmalloc(strlen(gssid))) == NULL) {
				racoon_free(new);
				yyerror("failed to allocate gssid");
				return -1;
			}
			memcpy(new->gssid->v, gssid, new->gssid->l);
			racoon_free(gssid);
		} else {
			/*
			 * Allocate the default ID so that it gets put
			 * into a GSS ID attribute during the Phase 1
			 * exchange.
			 */
			new->gssid = gssapi_get_default_gss_id();
		}
	}
#endif
	insisakmpsa(new, rmconf);

	return trns_no;
}

#if 0
/*
 * fix lifebyte.
 * Must be more than 1024B because its unit is kilobytes.
 * That is defined RFC2407.
 */
static int
fix_lifebyte(t)
	unsigned long t;
{
	if (t < 1024) {
		yyerror("byte size should be more than 1024B.");
		return 0;
	}

	return(t / 1024);
}
#endif

int
cfparse()
{
	int error;

	yyerrorcount = 0;
	yycf_init_buffer();

	if (yycf_switch_buffer(lcconf->racoon_conf) != 0) {
		plog(LLV_ERROR, LOCATION, NULL, 
		    "could not read configuration file \"%s\"\n", 
		    lcconf->racoon_conf);
		return -1;
	}

	error = yyparse();
	if (error != 0) {
		if (yyerrorcount) {
			plog(LLV_ERROR, LOCATION, NULL,
				"fatal parse failure (%d errors)\n",
				yyerrorcount);
		} else {
			plog(LLV_ERROR, LOCATION, NULL,
				"fatal parse failure.\n");
		}
		return -1;
	}

	if (error == 0 && yyerrorcount) {
		plog(LLV_ERROR, LOCATION, NULL,
			"parse error is nothing, but yyerrorcount is %d.\n",
				yyerrorcount);
		exit(1);
	}

	yycf_clean_buffer();

	plog(LLV_DEBUG2, LOCATION, NULL, "parse successed.\n");

	return 0;
}

int
cfreparse()
{
	flushph2();
	flushph1();
	flushrmconf();
	flushsainfo();
	clean_tmpalgtype();
	return(cfparse());
}

#ifdef ENABLE_ADMINPORT
static void
adminsock_conf(path, owner, group, mode_dec)
	vchar_t *path;
	vchar_t *owner;
	vchar_t *group;
	int mode_dec;
{
	struct passwd *pw = NULL;
	struct group *gr = NULL;
	mode_t mode = 0;
	uid_t uid;
	gid_t gid;
	int isnum;

	adminsock_path = path->v;

	if (owner == NULL)
		return;

	errno = 0;
	uid = atoi(owner->v);
	isnum = !errno;
	if (((pw = getpwnam(owner->v)) == NULL) && !isnum)
		yyerror("User \"%s\" does not exist", owner->v);

	if (pw)
		adminsock_owner = pw->pw_uid;
	else
		adminsock_owner = uid;

	if (group == NULL)
		return;

	errno = 0;
	gid = atoi(group->v);
	isnum = !errno;
	if (((gr = getgrnam(group->v)) == NULL) && !isnum)
		yyerror("Group \"%s\" does not exist", group->v);

	if (gr)
		adminsock_group = gr->gr_gid;
	else
		adminsock_group = gid;

	if (mode_dec == -1)
		return;

	if (mode_dec > 777)
		yyerror("Mode 0%03o is invalid", mode_dec);
	if (mode_dec >= 400) { mode += 0400; mode_dec -= 400; }
	if (mode_dec >= 200) { mode += 0200; mode_dec -= 200; }
	if (mode_dec >= 100) { mode += 0200; mode_dec -= 100; }

	if (mode_dec > 77)
		yyerror("Mode 0%03o is invalid", mode_dec);
	if (mode_dec >= 40) { mode += 040; mode_dec -= 40; }
	if (mode_dec >= 20) { mode += 020; mode_dec -= 20; }
	if (mode_dec >= 10) { mode += 020; mode_dec -= 10; }

	if (mode_dec > 7)
		yyerror("Mode 0%03o is invalid", mode_dec);
	if (mode_dec >= 4) { mode += 04; mode_dec -= 4; }
	if (mode_dec >= 2) { mode += 02; mode_dec -= 2; }
	if (mode_dec >= 1) { mode += 02; mode_dec -= 1; }
	
	adminsock_mode = mode;

	return;
}
#endif
