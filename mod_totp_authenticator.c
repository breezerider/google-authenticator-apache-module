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
#include "apr_encode.h"     /* for apr_pdecode_base32 */

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
  * \brief get_timestamp Get number of complete 30-second intervals since 00:00:00 January 1, 1970 UTC
  * \param ts number of microseconds since since 00:00:00 January 1, 1970 UTC
  * \return number of complete 30-second intervals since 00:00:00 January 1, 1970 UTC
 **/
static apr_time_t
to_totp_timestamp(apr_time_t ts)
{
	/* get  */
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

static char
is_digit_str(const char *val)
{
	const char     *tmp = val;
	for (; *tmp; ++tmp)
		if (!apr_isdigit(*tmp))
			return *tmp;
	return 0;
}

static char
is_alnum_str(const char *val)
{
	const char     *tmp = val;
	for (; *tmp; ++tmp)
		if (!apr_isalnum(*tmp))
			return *tmp;
	return 0;
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
	apr_size_t      shared_key_len;
	bool            disallow_reuse;
	unsigned char   window_size;
	int             rate_limit_count;
	int             rate_limit_seconds;
	unsigned int    scratch_codes[10];
	unsigned char   scratch_codes_count;
} totp_user_config;

typedef struct {
	totp_user_config  *conf;
	unsigned int       res;
} totp_file_helper_cb_data;

/**
 * \brief totp_file_helper_cb Callback function used by totp_check_n_update_file_helper
 * \param new Pointer to new data entry
 * \param old Pointer to an existing data entry
 * \param data Pointert to callback function data
 * \return if old if not NULL then retunr true if existing entry should be kept, false otherwise. 
 * When old is NULL, return if true if new entry should be appended to the file, false otherwise.
**/
typedef bool (*totp_file_helper_cb) (const void *new, const void *old, totp_file_helper_cb_data *data);

/**
  * \brief totp_check_n_update_file_helper Update file entries and apend new entry
  * \param r Request
  * \param filepath Path to target file
  * \param entry Pointer to new data entry
  * \param entry_size Size of the entry data structure in bytes
  * \param cb_check Pointer to callback function that is called on each entry
  * \param cb_data Pointert to callback function data
  * \return Pointer to structure containing TOTP configuration for given user on success, NULL otherwise
 **/
static apr_status_t
totp_check_n_update_file_helper(request_rec *r, const char *filepath,
            const void *entry, apr_size_t entry_size,
			totp_file_helper_cb cb_check,
			totp_file_helper_cb_data *cb_data)
{
	apr_status_t    status;
    const char     *tmp_filepath;
	apr_file_t     *tmp_file;
	apr_file_t     *target_file;
    apr_finfo_t     target_finfo;
    apr_mmap_t     *target_mmap;
    apr_size_t      bytes_written;
    apr_time_t      timestamp = *((apr_time_t *)entry);
    apr_size_t      entry_pos;
    apr_time_t      entry_time;
    const char     *file_data;

    tmp_filepath = apr_psprintf(r->pool, "%s.%" APR_TIME_T_FMT, filepath, timestamp);

	status = apr_file_open(&tmp_file,    /* temporary file handle */
			       tmp_filepath,         /* file name */
			       APR_FOPEN_EXCL     |  /* return an error if file exists */
			       APR_FOPEN_WRITE    |  /* open file for writing */
			       APR_FOPEN_CREATE   |  /* create file if it does
							              * not exist */
                   APR_FOPEN_BUFFERED |  /* buffered file IO */
			       APR_FOPEN_TRUNCATE,	 /* truncate file to 0 length */
			       APR_UREAD|APR_UWRITE, /* set read/write permissions 
				                          * only for owner */
			       r->pool	             /* memory pool to use */
	    );
	if (APR_SUCCESS != status) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
			      "totp_update_file_helper: could not create temporary file \"%s\"",
			      tmp_filepath);
		return status;
	}

	status = apr_file_open(&target_file, /* target file handle */
			       filepath,	         /* file name */
			       APR_FOPEN_READ,       /* open file for reading */
			       APR_FPROT_OS_DEFAULT, /* default permissions */
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
		file_data = target_mmap->mm;
		for(entry_pos = 0; entry_pos < target_mmap->size;
            entry_pos += entry_size, file_data += entry_size) {
			entry_time = *((apr_time_t*)file_data);

			if(timestamp >= entry_time) {
				/* check if entry time is within time tolerance */
				if((*cb_check) (entry, file_data, cb_data)) {
					/* keep the entry */
					ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
							"totp_update_file_helper: entry %ld is kept, cb_data->res = %u",
							entry_time, cb_data->res);
						
                    bytes_written = entry_size;
					if (((status = apr_file_write(tmp_file, file_data, &bytes_written)) != APR_SUCCESS) ||
                        (bytes_written != entry_size)) {
						ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
								"totp_update_file_helper: could not write to temporary file \"%s\"",
								tmp_filepath);
                        apr_mmap_delete(target_mmap);
						apr_file_close(tmp_file);
						return status;
					}
				} else {
					ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
							"totp_update_file_helper: entry %ld is NOT kept, cb_data->res = %u",
							entry_time, cb_data->res);
				}
			} else {
				/* entry is in the future */
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
						"totp_update_file_helper: entry %ld is in the future and will be dropped",
						entry_time);
			}
		}

		/* delete the memory map */
		apr_mmap_delete(target_mmap);
	}

    /* add current entry to file */
	if((*cb_check) (entry, NULL, cb_data)) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
				"totp_update_file_helper: adding new entry %ld, cb_data->res = %u",
				timestamp, cb_data->res);
		bytes_written = entry_size;
		if (((status = apr_file_write(tmp_file, entry, &bytes_written)) != APR_SUCCESS) ||
			(bytes_written != entry_size)) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
					"totp_update_file_helper: could not write to temporary file \"%s\"",
					tmp_filepath);
			apr_file_close(tmp_file);
			return status;
		}
	} else {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
				"totp_update_file_helper: NOT adding new entry %ld, cb_data->res = %u",
				timestamp, cb_data->res);
	}

	apr_file_close(tmp_file);

	status = apr_file_rename(tmp_filepath, filepath, r->pool);
	if (APR_SUCCESS != status) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
			      "totp_update_file_helper: unable to move file \"%s\" to \"%s\"",
			      tmp_filepath, filepath);
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
						    max(0,
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
generate_totp_code(apr_time_t timestamp, const char *secret, apr_size_t secret_len)
{
	unsigned char   hash[APR_SHA1_DIGESTSIZE];
	unsigned char   challenge_data[sizeof(apr_time_t)], challenge_size = sizeof(apr_time_t);
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
		/* check for an existing login entry with new TOTP code */
		totp_login_rec *pNew = (totp_login_rec *)new;
		totp_login_rec *pOld = (totp_login_rec *)old;

		/* check if entry time is within time tolerance */
		if((pNew->timestamp - pOld->timestamp) <= 3600) {
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
  * \brief mark_code_invalid Mark a code invalid
  * \param r Request
  * \param conf Pointer to TOTP authentication configuration record
  * \param timestamp Timestamp for login event
  * \param username Authenticating user name
  * \param totp_code Authenticating TOTP code
  * \return true upon success, false otherwise
 **/
static bool
mark_code_invalid(request_rec *r, totp_auth_config_rec *conf,
          apr_time_t timestamp, const char *user, 
          totp_user_config *totp_config, 
          unsigned int totp_code)
{
	char           *code_filepath;
	apr_file_t     *code_file;
    totp_login_rec  login_data;
	apr_status_t    status;
	totp_file_helper_cb_data cb_data;

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

/* TODO Authentication Helpers: Rate Limiting User Logins */

bool cb_rate_limit(const void *new, const void *old, totp_file_helper_cb_data *data)
{
	if (old) {
		apr_time_t curr = *((apr_time_t *)new);
		apr_time_t prev = *((apr_time_t *)old);

		if(curr > prev) {
			/* check if entry time is within time tolerance */
			if((curr - prev) <= data->conf->rate_limit_seconds) {
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

/* Authentication Functions */

static          authn_status
authn_totp_check_password(request_rec *r, const char *user, const char *password)
{
	totp_auth_config_rec *conf =
	    ap_get_module_config(r->per_dir_config, &authn_totp_module);
	totp_user_config *totp_config = NULL;
	unsigned int    password_len = strlen(password);
	apr_time_t      timestamp = apr_time_now(), totp_timestamp = to_totp_timestamp(timestamp);
	unsigned int    totp_code = 0;
	unsigned int    user_code;
	char            err_char;
	const char     *tmp;
	int             i;

#ifdef DEBUG_TOTP_AUTH
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		      "TOTP BASIC AUTH at timestamp=%" APR_TIME_T_FMT " user=\"%s\" password=\"%s\"",
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
			    generate_totp_code(totp_timestamp + i,
					       totp_config->shared_key,
					       totp_config->shared_key_len);

#ifdef DEBUG_TOTP_AUTH
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				      "validating code @ T=%" APR_TIME_T_FMT " expected=\"%6.6u\" vs. input=\"%6.6u\"",
				      timestamp, totp_code, user_code);
#endif

			if (totp_code == user_code) {
				if (mark_code_invalid(r, conf, timestamp, user, totp_config, totp_code)) {
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
				if (mark_code_invalid(r, conf, timestamp, user, totp_config, totp_config->scratch_codes[i])) {
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
