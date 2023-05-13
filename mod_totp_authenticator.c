/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright 2011 Bradley K. Goodman
 * brad at bradgoodman dot com
 *
 * Portions Copyright 2010 Google Inc.
 * By Markus Gutschke
 *
 * This source code has been fixed for compiling error and other bugs by
 * Nicola Asuni - Fubra.com - 2011-12-07
 * This source code has been modified to be able to use an additional static password
 * joehil                   - 2017-06-30
 */

#include "apr_strings.h"
#include "apr_lib.h"		/* for apr_isalnum */
#include "apr_md5.h"		/* for APR_MD5_DIGESTSIZE */

#include "ap_config.h"
#include "ap_provider.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "apr_sha1.h"

#include "mod_auth.h"
#include "base32.h"
#include "hmac.h"
#include "sha1.h"

#include "apu.h"
#include "apr_general.h"
#include "apr_base64.h"

#include <stdbool.h>		/* for bool */

#define DEBUG_TOTP_AUTH

/* Helper functions */
#define max(a,b)             \
({                           \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a > _b ? _a : _b;       \
})

#define min(a,b)             \
({                           \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a < _b ? _a : _b;       \
})


static unsigned int
get_timestamp()
{
	apr_time_t      apr_time = apr_time_now();
	apr_time /= 1000000;
	apr_time /= 30;

	return (apr_time);
}

static unsigned char *
decode_shared_secret(request_rec *r, const char *buf, int *len)
{
	// Decode secret key
	int             base32Len = strlen(buf);
	unsigned char  *secret = apr_palloc(r->pool, base32Len + 1);
	memcpy(secret, buf, base32Len);
	secret[base32Len] = '\000';

	/* *len = (base32Len * 5 + 7) / 8; */
	if ((*len = base32_decode(secret, secret, base32Len)) < 1) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			      "Could not find a valid BASE32 encoded secret");
		memset(secret, 0, base32Len);

		return NULL;
	}
	memset(secret + *len, 0, base32Len + 1 - *len);
	return secret;
}

static char    *
hex_encode(apr_pool_t *p, uint8_t *data, int len)
{
	const char     *hex = "0123456789abcdef";
	char           *result = apr_palloc(p, (APR_MD5_DIGESTSIZE * 2) + 1);
	int             idx;
	char           *h = result;

	for (idx = 0; idx < APR_MD5_DIGESTSIZE; idx++) {
		*h++ = hex[data[idx] >> 4];
		*h++ = hex[data[idx] & 0xF];
	}
	*h = (char) 0;

	return result;
}

/* Module configuration */

typedef struct {
	char           *tokenDir;
	char           *stateDir;
	char            tolerance;
} totp_auth_config_rec;

static void    *
create_authn_totp_config(apr_pool_t *p, char *d)
{
	totp_auth_config_rec *conf = apr_palloc(p, sizeof(*conf));
	conf->tokenDir = NULL;
	conf->stateDir = NULL;
	conf->tolerance = 1;

	return conf;
}

static const char *
set_totp_auth_config_path(cmd_parms *cmd, void *offset, const char *path)
{
	return ap_set_file_slot(cmd, offset, path);
}

static const char *
set_totp_auth_config_int(cmd_parms *cmd, void *offset, const char *value)
{
	return ap_set_int_slot(cmd, offset, value);
}

static const command_rec authn_totp_cmds[] = {
	AP_INIT_TAKE1("TOTPAuthTokenDir", set_totp_auth_config_path,
		      (void *) APR_OFFSETOF(totp_auth_config_rec, tokenDir),
		      OR_AUTHCFG,
		      "Directory containing Google Authenticator credential files"),
	AP_INIT_TAKE1("TOTPAuthStateDir", set_totp_auth_config_path,
		      (void *) APR_OFFSETOF(totp_auth_config_rec, stateDir),
		      OR_AUTHCFG,
		      "Directory that contains TOTP key state information"),
	AP_INIT_TAKE1("TOTPAuthTolerance", set_totp_auth_config_int,
		      (void *) APR_OFFSETOF(totp_auth_config_rec, tolerance),
		      OR_AUTHCFG,
		      "Clock Tolerance (in number of past and future OTP that are accepted)"),
	{NULL}
};

module AP_MODULE_DECLARE_DATA authn_totp_module;

/* Authentication Helpers */

typedef struct {
	char           *shared_key;
	unsigned int    shared_key_len;
	bool            disallow_reuse;
	unsigned char   window_size;
	int             rate_limit_count;
	int             rate_limit_seconds;
	unsigned int    scratch_codes[10];
	unsigned int    scratch_codes_count;
} totp_user_config;

/**
  * \brief get_user_totp_config Based on the given username, get the users TOTP configuration
  * \param r Request
  * \param username Username
  * \param len Length of the secret key (out). Must be allocated by the caller.
  * \return Pointer to structure containing TOTP configuration for given user on success, NULL otherwise
 **/
static totp_user_config *
get_user_totp_config(request_rec *r, totp_auth_config_rec *conf,
		     const char *username)
{
	const char       *tmp;
	const char       *psep = "=";
	char             *config_filename;
	char             *token, *last;
	char              line[MAX_STRING_LEN];
	unsigned int      line_len = 0;
	int               count = 0;
	apr_status_t      status;
	ap_configfile_t  *config_file;
	totp_user_config *user_config = NULL;

	/* validate user name */
	for (tmp = username; *tmp; ++tmp) {
		if (!apr_isalnum(*tmp)) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
				      "get_user_totp_config: username '%s' contains invalid character %c",
				      username, *tmp);
			return NULL;
		}
	}

	config_filename = apr_psprintf(r->pool, "%s/%s", conf->tokenDir, username);

	status = ap_pcfg_openfile(&config_file, r->pool, config_filename);

	if (status != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
			      "get_user_totp_config: could not open user configuration file: %s",
			      config_filename);
		return NULL;
	}

	user_config = apr_palloc(r->pool, sizeof(*user_config));
	memset(user_config, 0, sizeof(*user_config));

	while (!(ap_cfg_getline(line, MAX_STRING_LEN, config_file))) {
		/* Skip blank lines. */
		if (!line[0])
			continue;
		/* Parse authentication settings. */
		if (line[0] == '"') {
			token = apr_strtok(&line[2], psep, &last);
			if (token != NULL) {
				if (0 == apr_strnatcmp(token, "DISALLOW_REUSE")) {
					user_config->disallow_reuse = true;
				} else if (0 == apr_strnatcmp(token, "WINDOW_SIZE")) {
					token = apr_strtok(NULL, psep, &last);
					for (tmp = token; *tmp; ++tmp) {
						if (!apr_isdigit(*tmp)) {
							ap_log_rerror(APLOG_MARK,
								      APLOG_ERR,
								      status, r,
								      "get_user_totp_config: window size '%s' contains invalid character %c",
								      token, *tmp);
							token = NULL;
						}
					}
					if (token)
						user_config->window_size =
						    max(0,
							min(apr_atoi64(token), 32));
					else
						ap_log_rerror(APLOG_MARK, APLOG_ERR,
							      status, r,
							      "get_user_totp_config: invalid WINDOW_SIZE directive: missing value. See line: %s",
							      line);
				} else if (0 == apr_strnatcmp(token, "RATE_LIMIT")) {
					token = apr_strtok(NULL, psep, &last);
					for (tmp = token; *tmp; ++tmp) {
						if (!apr_isdigit(*tmp)) {
							ap_log_rerror(APLOG_MARK,
								      APLOG_ERR,
								      status, r,
								      "get_user_totp_config: rate limit count '%s' contains invalid character %c",
								      token, *tmp);
							token = NULL;
						}
					}
					if (token)
						user_config->rate_limit_count =
						    max(0,
							min(apr_atoi64(token), 5));
					else
						ap_log_rerror(APLOG_MARK, APLOG_ERR,
							      status, r,
							      "get_user_totp_config: invalid RATE_LIMIT directive: missing value. See line: %s",
							      line);
					token = apr_strtok(NULL, psep, &last);
					for (tmp = token; *tmp; ++tmp) {
						if (!apr_isdigit(*tmp)) {
							ap_log_rerror(APLOG_MARK,
								      APLOG_ERR,
								      status, r,
								      "get_user_totp_config: rate limit seconds '%s' contains invalid character %c",
								      token, *tmp);
							token = NULL;
						}
					}
					if (token)
						user_config->rate_limit_seconds =
						    max(30,
							min(apr_atoi64(token), 300));
					else {
						user_config->rate_limit_count = 0;
						ap_log_rerror(APLOG_MARK, APLOG_ERR,
							      status, r,
							      "get_user_totp_config: invalid RATE_LIMIT directive: missing value. See line: %s",
							      line);
					}
				}
			}
		}
		/* Shared key is on the first valid line */
		else if (!user_config->shared_key) {
			token = apr_pstrdup(r->pool, line);
			line_len = strlen(token);

			user_config->shared_key = apr_palloc(r->pool, line_len + 1);
			memset(user_config->shared_key, 0, line_len);

			count =
			    base32_decode(token, user_config->shared_key, line_len);
			if (count < 0) {
				memset(user_config->shared_key, 0, line_len);
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					      "get_user_totp_config: could not find a valid BASE32 encoded secret");
				return NULL;
			} else {
				memset(user_config->shared_key + count, 0,
				       line_len + 1 - count);
				user_config->shared_key_len = count;
			}
		}
		/* Handle scratch codes */
		else {
			token = apr_pstrdup(r->pool, line);
			line_len = strlen(token);

			/* validate scratch code */
			for (tmp = token; *tmp; ++tmp) {
				if (!apr_isdigit(*tmp)) {
					ap_log_rerror(APLOG_MARK, APLOG_ERR, status,
						      r,
						      "get_user_totp_config: scratch code '%s' contains invalid character %c",
						      line, *tmp);
					token = NULL;
				}
			}
			if (token)
				user_config->scratch_codes[user_config->
							   scratch_codes_count++] =
				    apr_atoi64(token);
		}
	}

	ap_cfg_closefile(config_file);

	return user_config;
}

static unsigned int
generate_totp_code(unsigned int timestamp, unsigned char *secret, int len)
{
	unsigned char   hash[SHA1_DIGEST_LENGTH];
	unsigned long   chlg = timestamp;
	unsigned char   challenge[8];
	unsigned int    totp_code = 0;
	int             j;
	int             offset;

	for (j = 8; j--; chlg >>= 8)
		challenge[j] = chlg;

	hmac_sha1(secret, len, challenge, 8, hash, SHA1_DIGEST_LENGTH);
	offset = hash[SHA1_DIGEST_LENGTH - 1] & 0xF;
	for (j = 0; j < 4; ++j) {
		totp_code <<= 8;
		totp_code |= hash[offset + j];
	}
	memset(hash, 0, sizeof(hash));
	totp_code &= 0x7FFFFFFF;
	totp_code %= 1000000;

	return totp_code;
}

/* Mark a file with the last used time  - do disallow reuse */
//static void markLastUsed(request_rec *r,char *user) {}

/* Authentication Functions */

static          authn_status
authn_totp_check_password(request_rec *r, const char *user, const char *password)
{
	totp_auth_config_rec *conf =
	    ap_get_module_config(r->per_dir_config, &authn_totp_module);
	totp_user_config *totp_config = NULL;
	unsigned int    totp_code = 0;
	unsigned int    timestamp;
	unsigned int    code;
	int             i;

#ifdef DEBUG_TOTP_AUTH
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		      "**** TOTP BASIC AUTH at  T=%lu  user  \"%s\"",
		      apr_time_now() / 1000000, user);
#endif

	totp_config = get_user_totp_config(r, conf, user);
	if (!totp_config) {
#ifdef DEBUG_TOTP_AUTH
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			      "could not find TOTP configuration for user \"%s\"",
			      user);
#endif
		return AUTH_DENIED;
	}
#ifdef DEBUG_TOTP_AUTH
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		      "secret key is \"%s\", secret length: %d",
		      totp_config->shared_key, totp_config->shared_key_len);
#endif

	/***
	 *** Perform TOTP Authentication
	 ***/
	timestamp = get_timestamp();
	code = (unsigned int) apr_atoi64(password);
	for (i = -(conf->tolerance); i <= (conf->tolerance); ++i) {
		totp_code =
		    generate_totp_code(timestamp + i, totp_config->shared_key,
				       totp_config->shared_key_len);

#ifdef DEBUG_TOTP_AUTH
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			      "validating code @ T=%d expected=\"%6.6u\" vs. input=\"%6.6u\"",
			      timestamp, totp_code, code);
#endif

		if (totp_code == code) {
#ifdef DEBUG_TOTP_AUTH
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				      "access granted for user \"%s\" based on code \"%6.6u\"",
				      user, code);
#endif
			return AUTH_GRANTED;
		}

	}

#ifdef DEBUG_TOTP_AUTH
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		      "access denied for user \"%s\" based on code \"%6.6u\"",
		      user, code);
#endif

	return AUTH_DENIED;
}

/* This handles Digest Authentication. Returns a has of the 
   User, Realm and (Required) Password. Caller (Digest module)
	 determines if the entered password was actually valid
*/
static          authn_status
authn_totp_get_realm_hash(request_rec *r, const char *user, const char *realm,
			  char **rethash)
{
	totp_auth_config_rec *conf =
	    ap_get_module_config(r->per_dir_config, &authn_totp_module);

	totp_user_config *totp_config = NULL;
	unsigned int    totp_code;
	char           *hashstr;
	char           *pwstr;
	unsigned char  *hash;

#ifdef DEBUG_TOTP_AUTH
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		      "**** TOTP DIGEST AUTH at  T=%lu  user  \"%s\"",
		      apr_time_now() / 1000000, user);
#endif

	totp_config = get_user_totp_config(r, conf, user);
	if (!totp_config) {
#ifdef DEBUG_TOTP_AUTH
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			      "could not find TOTP configuration for user \"%s\"",
			      user);
#endif
		return AUTH_USER_NOT_FOUND;
	}
#ifdef DEBUG_TOTP_AUTH
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		      "secret key is \"%s\", secret length: %d",
		      totp_config->shared_key, totp_config->shared_key_len);
#endif

	hash = apr_palloc(r->pool, APR_MD5_DIGESTSIZE);

	totp_code =
	    generate_totp_code(get_timestamp(), totp_config->shared_key,
			       totp_config->shared_key_len);

	pwstr = apr_psprintf(r->pool, "%6.6u", totp_code);
	hashstr = apr_psprintf(r->pool, "%s:%s:%s", user, realm, pwstr);

#ifdef DEBUG_TOTP_AUTH
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		      "user \"%s\", password \"%s\" at modulus %lu", user, pwstr,
		      (apr_time_now() / 1000000) % 30);
#endif

	apr_md5(hash, hashstr, strlen(hashstr));
	*rethash = hex_encode(r->pool, hash, APR_MD5_DIGESTSIZE);

	return AUTH_USER_FOUND;
}

/* Module Declaration */

static const authn_provider authn_totp_provider =
    { &authn_totp_check_password, &authn_totp_get_realm_hash };

static void
register_hooks(apr_pool_t *p)
{
	ap_register_auth_provider(p, AUTHN_PROVIDER_GROUP, "totp",
				  AUTHN_PROVIDER_VERSION, &authn_totp_provider,
				  AP_AUTH_INTERNAL_PER_CONF);
}

AP_DECLARE_MODULE(authn_totp) =
{
    STANDARD20_MODULE_STUFF,
    create_authn_totp_config,	    /* dir config creater */
    NULL,							/* dir merger --- default is to override */
    NULL,							/* server config */
    NULL,							/* merge server config */
    authn_totp_cmds,				/* command apr_table_t */
    register_hooks					/* register hooks */
};
