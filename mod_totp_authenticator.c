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

#include "ap_config.h"
#include "ap_provider.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "mod_auth.h"

#include "apu.h"

#include "apr_general.h"
#include "apr_strings.h"
#include "apr_file_io.h"    /* file IO routines */
#include "apr_lib.h"		/* for apr_isalnum */
#include "apr_md5.h"		/* for APR_MD5_DIGESTSIZE */
#include "apr_sha1.h"
#include "apr_mmap.h"
#include "apr_base64.h"     /* for apr_pdecode_base32 */

#include <stdbool.h>		/* for bool */

/*#include "base32.h"*/
#include "hmac.h"
/*#include "sha1.h"*/

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

/**
  * \brief get_timestamp Get number of 30-second intervals since 00:00:00 January 1, 1970 UTC
 **/
static apr_time_t
get_timestamp()
{
	/* get number of microseconds since since 00:00:00 January 1, 1970 UTC */
	apr_time_t epoch_30sec = apr_time_now();
	epoch_30sec /= 1000000; /* convert to seconds */
	epoch_30sec /= 30;      /* count number of 30-second intervals that have passed */

	return epoch_30sec;
}

static char    *
hex_encode(apr_pool_t *p, uint8_t *data, unsigned int len)
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

static char
is_digit_str(const char *val)
{
	const char     *tmp = val;
	for (; *tmp; ++tmp)
		if (!apr_isdigit(*tmp))
			return *tmp;
	return NULL;
}

static char
is_alnum_str(const char *val)
{
	const char     *tmp = val;
	for (; *tmp; ++tmp)
		if (!apr_isalnum(*tmp))
			return *tmp;
	return NULL;
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

typedef struct {
	char           *shared_key;
	unsigned int    shared_key_len;
	bool            disallow_reuse;
	unsigned char   window_size;
	int             rate_limit_count;
	int             rate_limit_seconds;
	unsigned int    scratch_codes[10];
	unsigned char   scratch_codes_count;
} totp_user_config;

static apr_status_t
totp_update_file_helper(request_rec *r, apr_time_t timestamp,
			apr_interval_time_t timedelta, apr_size_t entry_size,
			const char *filepath, const char *tmppath)
{
	apr_status_t    status;
	apr_file_t     *tmp_file;
	apr_file_t     *target_file;
    apr_finfo_t     target_finfo;
    apr_mmap_t     *target_mmap;

	status = apr_file_open(&tmp_file,    /* temporary file handle */
			       tmppath,              /* file name */
			       APR_FOPEN_CREATE |	 /* create file if it does
							              * not exist */
			       APR_FOPEN_EXCL   |    /* return an error if file exists */
			       APR_FOPEN_WRITE  |    /* open file for writing */
			       APR_FOPEN_TRUNCATE,	 /* truncate file to 0 length */
			       APR_UREAD|APR_UWRITE, /* set read/write permissions 
				                          * only for owner */
			       r->pool	             /* memory pool to use */
	    );

	if (APR_SUCCESS != status) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
			      "totp_update_file_helper: could not create temporary file \"%s\"",
			      tmppath);
		return status;
	}

	status = apr_file_open(&target_file, /* target file handle */
			       filepath,	         /* file name */
			       APR_FOPEN_READ,       /* open file for reading */
			       APR_FPROT_OS_DEFAULT, /* permissions */
			       r->pool	             /* memory pool to use */
	    );

	if ((APR_SUCCESS != status) && (APR_ENOENT != status)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
			      "totp_update_file_helper: could not open target file \"%s\"",
			      filepath);
		apr_file_close(tmp_file);
		return status;
	}

	if (APR_ENOENT != status) {
		/* Read current target file contents into a memory map */
		if ((status = apr_file_info_get(&target_finfo, APR_FINFO_SIZE, target_file)) != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
					"totp_update_file_helper: could not get target file \"%s\" size",
					filepath);
			apr_file_close(tmp_file);
			return status;
		}
		if ((status = apr_mmap_create(&target_mmap, target_file, 0, target_finfo.size, APR_MMAP_READ, r->pool)) != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
					"totp_update_file_helper: could not load target file \"%s\" into memory",
					filepath);
			apr_file_close(tmp_file);
			return status;
		}

		/* close the target file once contents have been loaded into memory */
		apr_file_close(target_file);

		/* process the file contents */

		/* delete the memory map */
		apr_mmap_delete(target_mmap);
	}

	apr_file_close(tmp_file);

	status = apr_file_rename(tmppath, filepath, r->pool);

	if (APR_SUCCESS != status) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
			      "totp_update_file_helper: unable to move file \"%s\" to \"\"",
			      tmppath, filepath);
		return status;
	}

	return APR_SUCCESS;
}

/**
  * \brief get_user_totp_config Based on the given username, get the users TOTP configuration
  * \param r Request
  * \param conf Pointer to TOTP authentication configuration record
  * \param username Username
  * \return Pointer to structure containing TOTP configuration for given user on success, NULL otherwise
 **/
static totp_user_config *
get_user_totp_config(request_rec *r, totp_auth_config_rec *conf,
		     const char *username)
{
	const char       *psep = " ";
	char             *config_filename;
	char             *token, *last;
	char              line[MAX_STRING_LEN];
	char              err_char;
	unsigned int      line_len = 0, line_no = 0;
	apr_status_t      status;
	ap_configfile_t  *config_file;
	totp_user_config *user_config = NULL;

	if (!conf->tokenDir) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			      "get_user_totp_config: TOTPAuthTokenDir is not defined");
		return NULL;
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
		/* Bump line number counter */
		line_no++;
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

					err_char = is_digit_str(token);
					if (err_char)
						ap_log_rerror(APLOG_MARK,
							      APLOG_ERR,
							      0, r,
							      "get_user_totp_config: window size value '%s' contains invalid character %c at line %d",
							      token, err_char,
							      line_no);
					else
						user_config->window_size =
						    max(0,
							min(apr_atoi64(token), 32));
				} else if (0 == apr_strnatcmp(token, "RATE_LIMIT")) {
					token = apr_strtok(NULL, psep, &last);

					err_char = is_digit_str(token);
					if (err_char)
						ap_log_rerror(APLOG_MARK,
							      APLOG_ERR,
							      0, r,
							      "get_user_totp_config: rate limit count value '%s' contains invalid character %c at line %d",
							      token, err_char,
							      line_no);
					else
						user_config->rate_limit_count =
						    max(0,
							min(apr_atoi64(token), 5));

					token = apr_strtok(NULL, psep, &last);

					err_char = is_digit_str(token);
					if (err_char) {
						user_config->rate_limit_count = 0;
						ap_log_rerror(APLOG_MARK,
							      APLOG_ERR,
							      0, r,
							      "get_user_totp_config: rate limit seconds value '%s' contains invalid character %c at line %d",
							      token, err_char,
							      line_no);
					} else
						user_config->rate_limit_seconds =
						    max(30,
							min(apr_atoi64(token), 300));
				} else
					ap_log_rerror(APLOG_MARK, APLOG_DEBUG,
						      0, r,
						      "get_user_totp_config: unrecognized directive \"%s\" at line %d",
						      line, line_no);

			} else
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG,
					      0, r,
					      "get_user_totp_config: skipping comment line \"%s\" at line %d",
					      line, line_no);
		}
		/* Shared key is on the first valid line */
		else if (!user_config->shared_key) {
			token = apr_pstrdup(r->pool, line);
			line_len = strlen(token);

			user_config->shared_key = apr_pdecode_base32(r->pool, token, line_len, APR_ENCODE_NONE, &user_config->shared_key_len);

			if(!user_config->shared_key) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					      "get_user_totp_config: could not find a valid BASE32 encoded secret at line %d",
						  line_no);
				return NULL;
			}
		}
		/* Handle scratch codes */
		else {
			token = apr_pstrdup(r->pool, line);
			line_len = strlen(token);

			/* validate scratch code */
			err_char = is_digit_str(token);
			if (err_char)
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0,
					      r,
					      "get_user_totp_config: scratch code '%s' contains invalid character %c at line %d",
					      line, err_char, line_no);
			else if (user_config->scratch_codes_count < 10)
				user_config->
				    scratch_codes[user_config->scratch_codes_count++]
				    = apr_atoi64(token);
			else
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0,
					      r,
					      "get_user_totp_config: scratch code '%s' at line %d was skipped, only 10 scratch codes per user are supported",
					      line, line_no);
		}
	}

	ap_cfg_closefile(config_file);

	return user_config;
}

/**
  * \brief generate_totp_code Generate a one time password using shared secret and timestamp
  * \param timestamp Unix timestamp
  * \param secret Shared secret key.
  * \param secret_len Length of the secret key.
  * \return TOTP code
 **/
static unsigned int
generate_totp_code(unsigned long challenge, const char *secret, apr_size_t secret_len)
{
	unsigned char   hash[SHA1_DIGEST_LENGTH];
	unsigned char   challenge_data[8];
	unsigned int    totp_code = 0;
	int             j, offset;

	for (j = 8; j--; challenge >>= 8)
		challenge_data[j] = challenge;

	hmac_sha1(secret, secret_len, challenge_data, 8, hash, SHA1_DIGEST_LENGTH);
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

/**
  * \brief mark_code_invalid Mark a code invalid
  * \param r Request
  * \param conf Pointer to TOTP authentication configuration record
  * \param username Username
  * \param password Password
  * \return true upon success, false otherwise
 **/
static bool
mark_code_invalid(request_rec *r, totp_auth_config_rec *conf, const char *user,
		  const char *password)
{
	char           *code_filepath;
	apr_file_t     *code_file;
	apr_status_t    status;

	if (!conf->stateDir) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
			      "mark_code_invalid: TOTPAuthStateDir is not defined");
		return false;
	}

	code_filepath =
	    apr_psprintf(r->pool, "%s/%s-c%s", conf->stateDir, user, password);

	status = apr_file_open(&code_file,	 /* new file handle */
			       code_filepath,	     /* file name */
			       APR_FOPEN_CREATE   |  /* create file if it does not exist */
			       APR_FOPEN_EXCL     |	 /* return an error if file exists */
				   APR_FOPEN_WRITE    |  /* open file for writing */
			       APR_FOPEN_TRUNCATE |	 /* truncate file to 0 length */
			       APR_FOPEN_XTHREAD,	 /* allow multiple threads to 
							             /* use the file */
			       APR_FPROT_OS_DEFAULT, /* permissions */
			       r->pool	             /* memory pool to use */
	    );

	if (APR_SUCCESS != status) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
			      "mark_code_invalid: could not create file \"%s\"",
			      code_filepath);
		return false;
	}

	apr_file_close(code_file);

	return true;
}

/* Authentication Functions */

static          authn_status
authn_totp_check_password(request_rec *r, const char *user, const char *password)
{
	totp_auth_config_rec *conf =
	    ap_get_module_config(r->per_dir_config, &authn_totp_module);
	totp_user_config *totp_config = NULL;
	unsigned int    password_len = strlen(password);
	apr_time_t      timestamp = get_timestamp();
	unsigned int    totp_code = 0;
	unsigned int    user_code;
	char            err_char;
	const char     *tmp;
	int             i;

#ifdef DEBUG_TOTP_AUTH
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		      "TOTP BASIC AUTH at timestamp=%lu user=\"%s\" password=\"%s\"",
		      timestamp, user, password);
#endif

	/* validate user name */
	err_char = is_alnum_str(user);
	if (err_char) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			      "user '%s' contains invalid character %c",
			      user, err_char);
		return AUTH_DENIED;
	}

	/* validate password */
	if ((password_len == 6) || (password_len == 8)) {
		err_char = is_digit_str(password);
		if (err_char) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				      "password '%s' contains invalid character %c",
				      password, err_char);
			return AUTH_DENIED;
		}
	} else {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			      "password '%s' is not recognized as TOTP (6 digits) or scratch code (8 digits)",
			      password);
		return AUTH_DENIED;
	}

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
	user_code = (unsigned int) apr_atoi64(password);
	/* TOTP codes */
	if (password_len == 6) {
		for (i = -(totp_config->window_size);
		     i <= (totp_config->window_size); ++i) {
			totp_code =
			    generate_totp_code(timestamp + i,
					       totp_config->shared_key,
					       totp_config->shared_key_len);

#ifdef DEBUG_TOTP_AUTH
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				      "validating code @ T=%lu expected=\"%6.6u\" vs. input=\"%6.6u\"",
				      timestamp, totp_code, user_code);
#endif

			if (totp_code == user_code) {
				if (mark_code_invalid(r, conf, user, password)) {
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
				if (mark_code_invalid(r, conf, user, password)) {
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
	apr_time_t      timestamp = get_timestamp();
	unsigned int    totp_code;
	char           *hashstr;
	char           *pwstr;
	char            err_char;
	unsigned char  *hash;

#ifdef DEBUG_TOTP_AUTH
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		      "TOTP DIGEST AUTH at timestamp=%lu user=\"%s\" realm=\"%s\"",
		      timestamp, user, realm);
#endif

	/* validate user name */
	err_char = is_alnum_str(user);
	if (err_char) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			      "user '%s' contains invalid character %c",
			      user, err_char);
		return AUTH_USER_NOT_FOUND;
	}

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
	    generate_totp_code(timestamp, totp_config->shared_key,
			       totp_config->shared_key_len);

	pwstr = apr_psprintf(r->pool, "%6.6u", totp_code);
	hashstr = apr_psprintf(r->pool, "%s:%s:%s", user, realm, pwstr);

#ifdef DEBUG_TOTP_AUTH
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		      "user \"%s\", password \"%s\" at modulus %lu", user, pwstr,
		      timestamp);
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
