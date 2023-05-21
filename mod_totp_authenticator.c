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
 * Repurpose this module as a general TOTP authenticator by
 * Oleksandr Ostrenko
 */

#include "httpd.h"
#include "http_log.h"
#include "http_request.h"

#include "mod_auth.h"

#include "apr_general.h"
#include "apr_strings.h"
#include "apr_pools.h"      /* for apr_pool_t */
#include "apr_md5.h"        /* for APR_MD5_DIGESTSIZE */
#include "apr_sha1.h"       /* for APR_SHA1_DIGESTSIZE */

#include <stdbool.h>        /* for bool */

#include "hmac.h"
/*#include "sha1.h"*/

#include "utils.h"

#define DEBUG_TOTP_AUTH

/* Helper functions */

/**
  * \brief get_timestamp Get number of complete 30-second intervals since 00:00:00 January 1, 1970 UTC
  * \param ts number of microseconds since since 00:00:00 January 1, 1970 UTC
  * \return number of complete 30-second intervals since 00:00:00 January 1, 1970 UTC
 **/
static apr_time_t
to_totp_timestamp(apr_time_t ts)
{
	ts /= 1000000; /* convert to seconds */
	ts /= 30;      /* count number of 30-second intervals that have passed */

	return ts;
}

static char    *
hex_encode(apr_pool_t *p, uint8_t *data, apr_size_t len)
{
	const char     *hex = "0123456789abcdef";
	char           *result = apr_palloc(p, (len * 2) + 1);
	int             idx;
	char           *h = result;

	for (idx = 0; idx < len; idx++) {
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
} totp_auth_config_rec;

static void    *
create_authn_totp_config(apr_pool_t *p, char *d)
{
	totp_auth_config_rec *conf = apr_palloc(p, sizeof(*conf));
	conf->tokenDir = NULL;
	conf->stateDir = NULL;

	return conf;
}

static const char *
set_totp_auth_config_path(cmd_parms *cmd, void *offset, const char *path)
{
	return ap_set_file_slot(cmd, offset, path);
}
/*
static const char *
set_totp_auth_config_int(cmd_parms *cmd, void *offset, const char *value)
{
	return ap_set_int_slot(cmd, offset, value);
}
*/
static const command_rec authn_totp_cmds[] = {
	AP_INIT_TAKE1("TOTPAuthTokenDir", set_totp_auth_config_path,
		      (void *) APR_OFFSETOF(totp_auth_config_rec, tokenDir),
		      OR_AUTHCFG,
		      "Directory containing Google Authenticator credential files"),
	AP_INIT_TAKE1("TOTPAuthStateDir", set_totp_auth_config_path,
		      (void *) APR_OFFSETOF(totp_auth_config_rec, stateDir),
		      OR_AUTHCFG,
		      "Directory that contains TOTP key state information"),
	{NULL}
};

module AP_MODULE_DECLARE_DATA authn_totp_module;

/* Authentication Helpers */

/**
  * \brief get_user_totp_config Based on the given username, get the users TOTP configuration
  * \param r Request
  * \param user User name
  * \return Pointer to structure containing TOTP configuration for given user on success, NULL otherwise
 **/
static totp_user_config *
get_user_totp_config(request_rec *r, const char *user)
{
	totp_auth_config_rec *conf =
	    ap_get_module_config(r->per_dir_config, &authn_totp_module);

	if (!conf->tokenDir) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			      "get_user_totp_config: TOTPAuthTokenDir is not defined");
		return NULL;
	}

	return totp_read_user_config(r, user, conf->tokenDir);
}

/**
  * \brief generate_totp_code Generate a one time password using shared secret and timestamp
  * \param timestamp Unix timestamp
  * \param secret Shared secret key.
  * \param secret_len Length of the secret key.
  * \return TOTP code
 **/
static unsigned int
generate_totp_code(apr_time_t timestamp, const char *secret, apr_size_t secret_len)
{
	unsigned char   hash[APR_SHA1_DIGESTSIZE];
	const size_t    challenge_size = sizeof(apr_time_t);
	unsigned char   challenge_data[sizeof(apr_time_t)];
	unsigned int    totp_code = 0;
	int             j, offset;

	for (j = challenge_size; j--; timestamp >>= 8)
		challenge_data[j] = timestamp;

	hmac_sha1(secret, secret_len, challenge_data, challenge_size, hash, APR_SHA1_DIGESTSIZE);
	offset = hash[APR_SHA1_DIGESTSIZE - 1] & 0xF;
	for (j = 0; j < 4; ++j) {
		totp_code <<= 8;
		totp_code |= hash[offset + j];
	}
	memset(hash, 0, sizeof(hash));
	totp_code &= 0x7FFFFFFF;
	totp_code %= 1000000;

	return totp_code;
}

/* Authentication Helpers: Disallow TOTP Code Reuse */

typedef struct {
    apr_time_t   timestamp;
    unsigned int totp_code;
} totp_login_rec;

bool cb_check_code(const void *new, const void *old, totp_file_helper_cb_data *data)
{
	if (old) {
		static const apr_time_t timedelta = 3600000000; /* one hour */
		/* check for an existing login entry with new TOTP code */
		totp_login_rec *pNew = (totp_login_rec *)new;
		totp_login_rec *pOld = (totp_login_rec *)old;

		/* check if entry time is within time tolerance */
		if((pNew->timestamp - pOld->timestamp) <= timedelta) {
			/* check if entry code matches current one */
			if((pNew->totp_code == pOld->totp_code)&&data->conf->disallow_reuse)
				data->res++;
			return true;
		}
		return false;
	} else {
		/* should new entry be appended to the file? */
		return true;
	}
}

/**
  * \brief mark_code_invalid Mark a TOTP code invalid
  * \param r Request
  * \param timestamp Timestamp for login event
  * \param user Authenticating user name
  * \param totp_config Pointer to user's TOTP authentication settings
  * \param totp_code Authenticating TOTP code
  * \return true upon success, false otherwise
 **/
static bool
mark_code_invalid(request_rec *r, apr_time_t timestamp,
          const char *user, totp_user_config *totp_config, 
          unsigned int totp_code)
{
	totp_auth_config_rec *conf =
	    ap_get_module_config(r->per_dir_config, &authn_totp_module);
	char                     *code_filepath;
    totp_login_rec            login_data;
	apr_status_t              status;
	totp_file_helper_cb_data  cb_data;

	if (!conf->stateDir) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
			      "mark_code_invalid: TOTPAuthStateDir is not defined");
		return false;
	}

	/* set code file path */
	code_filepath =
	    apr_psprintf(r->pool, "%s/%s.codes", conf->stateDir, user);

	/* initialize callback data */
	cb_data.conf = totp_config;
	cb_data.res = 0;

	/* current login entry */
    login_data.timestamp = timestamp;
    login_data.totp_code = totp_code;
	
    status = totp_check_n_update_file_helper(r, code_filepath,
            &login_data, sizeof(totp_login_rec), cb_check_code, &cb_data);
	if (APR_SUCCESS != status) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
			      "mark_code_invalid: could not update codes file \"%s\"",
			      code_filepath);
		return false;
	}

	return (cb_data.res == 0);
}

/* Authentication Helpers: Rate Limiting User Logins */

bool cb_rate_limit(const void *new, const void *old, totp_file_helper_cb_data *data)
{
	if (old) {
		apr_time_t curr = *((apr_time_t *)new);
		apr_time_t prev = *((apr_time_t *)old);

		if(curr > prev) {
			/* check if entry time is within time tolerance */
			if((curr - prev) <= data->conf->rate_limit_seconds * 1000000) {
				data->res++;
				return true;
			}
		} else {
			return false;
		}
	} else {
		return true;
	}
}

/**
  * \brief check_rate_limit Check if a user's login attempt is still within the rate limit
  * \param r Request
  * \param timestamp Timestamp for login event
  * \param user Authenticating user name
  * \param totp_config Pointer to user's TOTP authentication settings
  * \param totp_code Authenticating TOTP code
  * \return true upon success, false otherwise
 **/
static bool
check_rate_limit(request_rec *r, apr_time_t timestamp,
          const char *user, totp_user_config *totp_config)
{
	totp_auth_config_rec *conf =
	    ap_get_module_config(r->per_dir_config, &authn_totp_module);
	apr_status_t              status;
	char                     *login_filepath;
	totp_file_helper_cb_data  cb_data;

	/* return immediately if no rate limit is defined */
	if(totp_config->rate_limit_count == 0)
		return true;

	if (!conf->stateDir) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
			      "check_rate_limit: TOTPAuthStateDir is not defined");
		return false;
	}

	/* set code file path */
	login_filepath =
	    apr_psprintf(r->pool, "%s/%s.logins", conf->stateDir, user);

	/* initialize callback data */
	cb_data.conf = totp_config;
	cb_data.res = 0;
	
    status = totp_check_n_update_file_helper(r, login_filepath,
            &timestamp, sizeof(apr_time_t), cb_rate_limit, &cb_data);
	if (APR_SUCCESS != status) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
			      "check_rate_limit: could not update logins file \"%s\"",
			      login_filepath);
		return false;
	}

	return (cb_data.res <= totp_config->rate_limit_count);
}

/* Authentication Functions */

static          authn_status
authn_totp_check_password(request_rec *r, const char *user, const char *password)
{
	totp_auth_config_rec *conf =
	    ap_get_module_config(r->per_dir_config, &authn_totp_module);
	totp_user_config *totp_config = NULL;
	unsigned int      password_len = strlen(password);
	apr_time_t        timestamp = apr_time_now(), totp_timestamp = to_totp_timestamp(timestamp);
	unsigned int      totp_code = 0;
	unsigned int      user_code;
	int               i;

#ifdef DEBUG_TOTP_AUTH
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		      "TOTP BASIC AUTH at timestamp=%" APR_TIME_T_FMT " totp_timestamp=%" APR_TIME_T_FMT
		      timestamp, totp_timestamp);
#endif

	/* validate user name */
	if (!is_alnum_str(user)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			      "user name contains invalid character");
		return AUTH_DENIED;
	}

	/* validate password */
	if ((password_len == 6) || (password_len == 8)) {
		if (!is_digit_str(password)) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				      "password contains invalid character");
			return AUTH_DENIED;
		}
	} else {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			      "password is not recognized as TOTP (6 digits) or scratch code (8 digits)");
		return AUTH_DENIED;
	}

	totp_config = get_user_totp_config(r, user);
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
		      "secret key is \"%s\", secret length: %ld",
		      totp_config->shared_key, totp_config->shared_key_len);
#endif

	/* check if user login count is within the rate limit */
	if (!check_rate_limit(r, timestamp, user, totp_config)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		      "login attemp for user \"%s\" exceeds rate limit",
		      user);
		return AUTH_DENIED;
	}

	/***
	 *** Perform TOTP Authentication
	 ***/
	user_code = (unsigned int) apr_atoi64(password);
	/* TOTP codes */
	if (password_len == 6) {
		for (i = -(totp_config->window_size);
		     i <= (totp_config->window_size); ++i) {
			totp_code =
			    generate_totp_code(totp_timestamp + i,
					       totp_config->shared_key,
					       totp_config->shared_key_len);

#ifdef DEBUG_TOTP_AUTH
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				      "validating code @ T=%" APR_TIME_T_FMT " expected=\"%6.6u\" vs. input=\"%6.6u\"",
				      timestamp, totp_code, user_code);
#endif

			if (totp_code == user_code) {
				if (mark_code_invalid(r, timestamp, user, totp_config, totp_code)) {
#ifdef DEBUG_TOTP_AUTH
					ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
						      "access granted for user \"%s\" based on code \"%6.6u\"",
						      user, user_code);
#endif
					return AUTH_GRANTED;
				} else
					/* fail authentication attempt */
					break;
			}

		}
	}
	/* Scratch codes */
	else {
		for (i = 0; i < totp_config->scratch_codes_count; ++i) {
#ifdef DEBUG_TOTP_AUTH
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				      "validating scratch code expected=\"%8.8u\" vs. input=\"%8.8u\"",
				      totp_config->scratch_codes[i], user_code);
#endif
			if (totp_config->scratch_codes[i] == user_code) {
				if (mark_code_invalid(r, timestamp, user, totp_config, totp_config->scratch_codes[i])) {
#ifdef DEBUG_TOTP_AUTH
					ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
						      "access granted for user \"%s\" based on scratch code \"%8.8u\"",
						      user, user_code);
#endif
					return AUTH_GRANTED;
				} else
					/* fail authentication attempt */
					break;
			}
		}
	}

#ifdef DEBUG_TOTP_AUTH
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		      "access denied for user \"%s\" based on password \"%s\"",
		      user, password);
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
	apr_time_t      timestamp = apr_time_now(), totp_timestamp = to_totp_timestamp(timestamp);
	unsigned int    totp_code;
	char           *hashstr;
	char           *pwstr;
	char            err_char;
	unsigned char  *hash;

#ifdef DEBUG_TOTP_AUTH
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		      "TOTP DIGEST AUTH at timestamp=%" APR_TIME_T_FMT " user=\"%s\" realm=\"%s\"",
		      timestamp, user, realm);
#endif

	/* validate user name */
	err_char = is_alnum_str(user);
	if (err_char) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			      "user \"%s\" contains invalid character '%c'",
			      user, err_char);
		return AUTH_USER_NOT_FOUND;
	}

	totp_config = get_user_totp_config(r, user);
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
		      "secret key is \"%s\", secret length: %ld",
		      totp_config->shared_key, totp_config->shared_key_len);
#endif

	hash = apr_palloc(r->pool, APR_MD5_DIGESTSIZE);

	totp_code =
	    generate_totp_code(totp_timestamp, totp_config->shared_key,
			       totp_config->shared_key_len);

	pwstr = apr_psprintf(r->pool, "%6.6u", totp_code);
	hashstr = apr_psprintf(r->pool, "%s:%s:%s", user, realm, pwstr);

#ifdef DEBUG_TOTP_AUTH
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		      "T=%" APR_TIME_T_FMT ", user \"%s\", password \"%s\"",
              timestamp, user, pwstr);
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
