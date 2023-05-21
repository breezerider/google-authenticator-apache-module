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

#ifndef MOD_TOTP_AUTHN_UTIL_H
#define MOD_TOTP_AUTHN_UTIL_H


#include "http_request.h"

#include "apr_general.h"
#include "apr_time.h"       /* for apr_time_t */
#include "apr_lib.h"        /* for apr_isalnum, apr_isdigit */

#include <stdbool.h>		/* for bool */

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

static bool
is_digit_str(const char *val)
{
	const char     *tmp = val;
	for (; *tmp; ++tmp)
		if (!apr_isdigit(*tmp))
			return false;
	return true;
}

static bool
is_alnum_str(const char *val)
{
	const char     *tmp = val;
	for (; *tmp; ++tmp)
		if (!apr_isalnum(*tmp))
			return false;
	return true;
}

/* Authentication Helpers */
typedef struct {
	const char     *shared_key;
	apr_size_t      shared_key_len;
	bool            disallow_reuse;
	unsigned char   window_size;
	unsigned int    rate_limit_count;
	apr_time_t      rate_limit_seconds;
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
  * \brief read_user_totp_config Read a user's TOTP configuration from configuration file
  * \param user User name
  * \param token_dir Directory contianing TOTP configuration
  * \param pool The pool which we are logging for
  * \return Pointer to structure containing TOTP configuration for given user on success, NULL otherwise
 **/
totp_user_config *
totp_read_user_config(request_rec *r, const char *user, const char *token_dir);

/**
  * \brief totp_check_n_update_file_helper Update file entries and apend new entry
  * \param r Request
  * \param filepath Path to target file
  * \param entry Pointer to new data entry
  * \param entry_size Size of the entry data structure in bytes
  * \param cb_check Pointer to callback function that is called on each entry
  * \param cb_data Pointert to callback function data
  * \param pool APR pool 
  * \return Pointer to structure containing TOTP configuration for given user on success, NULL otherwise
 **/
apr_status_t
totp_check_n_update_file_helper(request_rec *r, const char *filepath, const void *entry, 
            apr_size_t entry_size, totp_file_helper_cb cb_check,
            totp_file_helper_cb_data *cb_data);

#endif /* MOD_TOTP_AUTHN_UTIL_H */
