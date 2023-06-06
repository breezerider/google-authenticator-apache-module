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

#include <stdbool.h>            /* for bool */

#include "httpd.h"
#include "http_log.h"
#include "http_core.h"          /* for ap_auth_name */
#include "http_request.h"

#include "apr_general.h"
#include "apr_time.h"           /* for apr_time_t */
#include "apr_lib.h"            /* for apr_isalnum, apr_isdigit */
#include "apr_strings.h"        /* string manipulation routines */
#include "apr_file_io.h"        /* file IO routines */
#include "apr_mmap.h"           /* for apr_mmap_t */
#include "apr_encode.h"         /* for apr_pdecode_base32 */
#include "apr_pools.h"          /* for apr_pool_t */
#include "apr_md5.h"            /* for APR_MD5_DIGESTSIZE */
#include "apr_sha1.h"           /* for APR_SHA1_DIGESTSIZE */

#include "mod_auth.h"
#include "mod_session.h"

static APR_OPTIONAL_FN_TYPE(ap_session_load) *ap_session_load_fn = NULL;
static APR_OPTIONAL_FN_TYPE(ap_session_get)  *ap_session_get_fn = NULL;
static APR_OPTIONAL_FN_TYPE(ap_session_set)  *ap_session_set_fn = NULL;

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

/**
  * \brief get_timestamp Get number of complete 30-second intervals since 00:00:00 January 1, 1970 UTC
  * \param ts number of microseconds since since 00:00:00 January 1, 1970 UTC
  * \return number of complete 30-second intervals since 00:00:00 January 1, 1970 UTC
 **/
static          apr_time_t
to_totp_timestamp(apr_time_t ts)
{
    /* count number of 30-second intervals */
    return apr_time_sec(ts) / 30;
}

/**
  * \brief hmac_sha1 HMAC SHA1 implementation (adapted from code by Markus Gutschke)
 **/
static void
hmac_sha1(const unsigned char *key, unsigned int keyLength,
          const unsigned char *data, unsigned int dataLength,
          char unsigned *result, unsigned int resultLength)
{
    int             i;
    apr_sha1_ctx_t  ctx;

    unsigned char   sha[APR_SHA1_DIGESTSIZE];
    unsigned char   tmp_key[64];
    unsigned char   hashed_key[APR_SHA1_DIGESTSIZE];

    if (keyLength > 64) {
        // The key can be no bigger than 64 bytes. If it is, we'll hash it down to
        // 20 bytes.
        apr_sha1_init(&ctx);
        apr_sha1_update(&ctx, key, keyLength);
        apr_sha1_final(hashed_key, &ctx);
        key = hashed_key;
        keyLength = APR_SHA1_DIGESTSIZE;
    }

    // The key for the inner digest is derived from our key, by padding the key
    // the full length of 64 bytes, and then XOR'ing each byte with 0x36.
    for (i = 0; i < keyLength; ++i) {
        tmp_key[i] = key[i] ^ 0x36;
    }
    memset(tmp_key + keyLength, 0x36, 64 - keyLength);

    // Compute inner digest
    apr_sha1_init(&ctx);
    apr_sha1_update(&ctx, tmp_key, 64);
    apr_sha1_update(&ctx, data, dataLength);
    apr_sha1_final(sha, &ctx);

    // The key for the outer digest is derived from our key, by padding the key
    // the full length of 64 bytes, and then XOR'ing each byte with 0x5C.
    for (i = 0; i < keyLength; ++i) {
        tmp_key[i] = key[i] ^ 0x5C;
    }
    memset(tmp_key + keyLength, 0x5C, 64 - keyLength);

    // Compute outer digest
    apr_sha1_init(&ctx);
    apr_sha1_update(&ctx, tmp_key, 64);
    apr_sha1_update(&ctx, sha, APR_SHA1_DIGESTSIZE);
    apr_sha1_final(sha, &ctx);

    // Copy result to output buffer and truncate or pad as necessary
    memset(result, 0, resultLength);
    if (resultLength > APR_SHA1_DIGESTSIZE) {
        resultLength = APR_SHA1_DIGESTSIZE;
    }
    memcpy(result, sha, resultLength);

    // Zero out all internal data structures
    memset(hashed_key, 0, sizeof(hashed_key));
    memset(sha, 0, sizeof(sha));
    memset(tmp_key, 0, sizeof(tmp_key));
}

/* Module configuration */

typedef struct {
    char           *tokenDir;
    char           *stateDir;
    apr_time_t      expires;
} totp_auth_config_rec;

static void    *
create_authn_totp_config(apr_pool_t *p, char *d)
{
    totp_auth_config_rec *conf = apr_palloc(p, sizeof(*conf));
    conf->tokenDir = NULL;
    conf->stateDir = NULL;
    conf->expires  = 3600; /* one hour */

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
    AP_INIT_TAKE1("TOTPExpires", set_totp_auth_config_int,
                  (void *) APR_OFFSETOF(totp_auth_config_rec, expires),
                  OR_AUTHCFG,
                  "Expiry time (in seconds) for TOTP authentication token"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA authn_totp_module;

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
    totp_user_config *conf;
    apr_time_t      exp;
    unsigned int    res;
} totp_file_helper_cb_data;

/**
 * \brief totp_file_helper_cb Callback function used by check_n_update_file_helper
 * \param new Pointer to new data entry
 * \param old Pointer to an existing data entry
 * \param data Pointert to callback function data
 * \return if old if not NULL then retunr true if existing entry should be kept, false otherwise.
 * When old is NULL, return if true if new entry should be appended to the file, false otherwise.
**/
typedef bool    (*totp_file_helper_cb)(const void *new, const void *old,
                                       totp_file_helper_cb_data * data);

/**
  * \brief read_user_config Read a user's TOTP configuration from configuration file
  * \param user User name
  * \param token_dir Directory contianing TOTP configuration
  * \param pool The pool which we are logging for
  * \return Pointer to structure containing TOTP configuration for given user on success, NULL otherwise
 **/
static totp_user_config *
read_user_config(request_rec *r, const char *user, const char *token_dir)
{
    const char     *psep = " ";
    char           *config_filename;
    char           *token, *last;
    char            line[MAX_STRING_LEN];
    char            err_char;
    unsigned int    line_len = 0, line_no = 0;
    apr_status_t    status;
    ap_configfile_t *config_file;
    totp_user_config *user_config = NULL;

    config_filename = apr_psprintf(r->pool, "%s/%s", token_dir, user);

    status = ap_pcfg_openfile(&config_file, r->pool, config_filename);

    if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                      "read_user_config: could not open user configuration file \"%s\"",
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

                    if (!is_digit_str(token))
                        ap_log_rerror(APLOG_MARK,
                                      APLOG_ERR,
                                      0, r,
                                      "read_user_config: window size value \"%s\" contains invalid characters at line %d",
                                      token, line_no);
                    else
                        user_config->window_size =
                            max(0, min(apr_atoi64(token), 32));
                } else if (0 == apr_strnatcmp(token, "RATE_LIMIT")) {
                    token = apr_strtok(NULL, psep, &last);

                    if (!is_digit_str(token))
                        ap_log_rerror(APLOG_MARK,
                                      APLOG_ERR,
                                      0, r,
                                      "read_user_config: rate limit count value \"%s\" contains invalid characters at line %d",
                                      token, line_no);
                    else
                        user_config->rate_limit_count =
                            max(0, min(apr_atoi64(token), 5));

                    token = apr_strtok(NULL, psep, &last);

                    if (!is_digit_str(token)) {
                        user_config->rate_limit_count = 0;
                        ap_log_rerror(APLOG_MARK,
                                      APLOG_ERR,
                                      0, r,
                                      "read_user_config: rate limit seconds value \"%s\" contains invalid characters at line %d",
                                      token, line_no);
                    } else
                        user_config->rate_limit_seconds =
                            max(0, min(apr_atoi64(token), 300));
                } else
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG,
                                  0, r,
                                  "read_user_config: unrecognized directive \"%s\" at line %d",
                                  line, line_no);

            } else
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG,
                              0, r,
                              "read_user_config: skipping comment line \"%s\" at line %d",
                              line, line_no);
        }
        /* Shared key is on the first valid line */
        else if (!user_config->shared_key) {
            token = apr_pstrdup(r->pool, line);
            line_len = strlen(token);

            user_config->shared_key =
                apr_pdecode_base32(r->pool, token, line_len, APR_ENCODE_NONE,
                                   &user_config->shared_key_len);

            if (!user_config->shared_key) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "read_user_config: could not find a valid BASE32 encoded secret at line %d",
                              line_no);
                return NULL;
            }
        }
        /* Handle scratch codes */
        else {
            token = apr_pstrdup(r->pool, line);
            line_len = strlen(token);

            /* validate scratch code */
            if (!is_digit_str(token))
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "read_user_config: scratch code \"%s\" contains invalid characters and was skipped at line %d",
                              line, line_no);
            else if (user_config->scratch_codes_count < 10)
                user_config->scratch_codes[user_config->scratch_codes_count++]
                    = apr_atoi64(token);
            else
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "read_user_config: scratch code \"%s\" at line %d was skipped, only 10 scratch codes per user are supported",
                              line, line_no);
        }
    }

    ap_cfg_closefile(config_file);

    return user_config;
}

/**
  * \brief get_user_config Based on the given username, get the users TOTP configuration
  * \param r Request
  * \param user User name
  * \return Pointer to structure containing TOTP configuration for given user on success, NULL otherwise
 **/
static totp_user_config *
get_user_config(request_rec *r, const char *user)
{
    totp_auth_config_rec *conf =
        ap_get_module_config(r->per_dir_config, &authn_totp_module);

    if (!conf->tokenDir) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "get_user_config: TOTPAuthTokenDir is not defined");
        return NULL;
    }

    return read_user_config(r, user, conf->tokenDir);
}

/**
  * \brief generate_totp_code Generate a one time password using shared secret and timestamp
  * \param timestamp Unix timestamp
  * \param totp_config Pointer to structure containing TOTP configuration
  * \param hash_out Either NULL or a pointer to memory location to store the SHA1 hash digest
  * \return TOTP code as an unsigned integer
 **/
static unsigned int
generate_totp_code(apr_time_t timestamp, const totp_user_config *totp_config)
{
    unsigned char   hash[APR_SHA1_DIGESTSIZE];
    const size_t    challenge_size = sizeof(apr_time_t);
    unsigned char   challenge_data[sizeof(apr_time_t)];
    unsigned int    totp_code = 0;
    int             j, offset;

    for (j = challenge_size; j--; timestamp >>= 8)
        challenge_data[j] = timestamp;

    hmac_sha1(totp_config->shared_key,
              totp_config->shared_key_len,
              challenge_data, challenge_size, hash, APR_SHA1_DIGESTSIZE);
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

/**
  * \brief check_n_update_file_helper Update file entries and apend new entry
  * \param r Request
  * \param filepath Path to target file
  * \param entry Pointer to new data entry
  * \param entry_size Size of the entry data structure in bytes
  * \param cb_check Pointer to callback function that is called on each entry
  * \param cb_data Pointert to callback function data
  * \param pool APR pool
  * \return Pointer to structure containing TOTP configuration for given user on success, NULL otherwise
 **/
static          apr_status_t
check_n_update_file_helper(request_rec *r, const char *filepath,
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
    apr_time_t      timestamp = *((apr_time_t *) entry);
    apr_size_t      entry_pos;
    apr_time_t      entry_time;
    const char     *file_data;

    tmp_filepath = apr_psprintf(r->pool, "%s.%" APR_TIME_T_FMT, filepath, timestamp);

    status = apr_file_open(&tmp_file,   /* temporary file handle */
                           tmp_filepath,        /* file name */
                           APR_FOPEN_EXCL |     /* return an error if file exists */
                           APR_FOPEN_WRITE |    /* open file for writing */
                           APR_FOPEN_CREATE |   /* create file if it does * not
                                                 * exist */
                           APR_FOPEN_BUFFERED | /* buffered file IO */
                           APR_FOPEN_TRUNCATE,  /* truncate file to 0 length */
                           APR_UREAD | APR_UWRITE,      /* set read/write
                                                         * permissions * only for
                                                         * owner */
                           r->pool      /* memory pool to use */
        );
    if (APR_SUCCESS != status) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                      "totp_update_file_helper: could not create temporary file \"%s\"",
                      tmp_filepath);
        return status;
    }

    status = apr_file_open(&target_file,        /* target file handle */
                           filepath,    /* file name */
                           APR_FOPEN_READ,      /* open file for reading */
                           APR_FPROT_OS_DEFAULT,        /* default permissions */
                           r->pool      /* memory pool to use */
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
        if ((status =
             apr_file_info_get(&target_finfo, APR_FINFO_SIZE,
                               target_file)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                          "totp_update_file_helper: could not get target file \"%s\" size",
                          filepath);
            apr_file_close(tmp_file);
            return status;
        }
        if ((status =
             apr_mmap_create(&target_mmap, target_file, 0, target_finfo.size,
                             APR_MMAP_READ, r->pool)) != APR_SUCCESS) {
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
        for (entry_pos = 0; entry_pos < target_mmap->size;
             entry_pos += entry_size, file_data += entry_size) {
            entry_time = *((apr_time_t *) file_data);

            if (timestamp >= entry_time) {
                /* check if entry time is within time tolerance */
                if ((*cb_check) (entry, file_data, cb_data)) {
                    /* keep the entry */
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                                  "totp_update_file_helper: entry %ld is kept, cb_data->res = %u",
                                  entry_time, cb_data->res);
                    bytes_written = entry_size;
                    if (((status =
                          apr_file_write(tmp_file, file_data,
                                         &bytes_written)) != APR_SUCCESS)
                        || (bytes_written != entry_size)) {
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
    if ((*cb_check) (entry, NULL, cb_data)) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "totp_update_file_helper: adding new entry %ld, cb_data->res = %u",
                      timestamp, cb_data->res);
        bytes_written = entry_size;
        if (((status =
              apr_file_write(tmp_file, entry, &bytes_written)) != APR_SUCCESS)
            || (bytes_written != entry_size)) {
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

/* Authentication Helpers: Toekn Authentication */

/**
  * \brief generate_token_hash Generate token hash from TOTP password and timestamp
  * \param timestamp Unix timestamp
  * \param totp_code TOTP code
  * \param totp_config Pointer to structure containing TOTP configuration
  * \return Pointer to memory location that contains the SHA1 hash digest
 **/
static unsigned char *
generate_token_hash(apr_pool_t *pool, apr_time_t timestamp, unsigned int totp_code,
                    const totp_user_config *totp_config)
{
    const apr_size_t challenge_len = sizeof(apr_time_t) + sizeof(unsigned int);
    unsigned char   challenge_data[challenge_len];
    unsigned char  *hash = apr_palloc(pool, APR_SHA1_DIGESTSIZE);

    memcpy(challenge_data, &totp_code, sizeof(unsigned int));
    memcpy(challenge_data + sizeof(unsigned int), &timestamp, sizeof(apr_time_t));

    hmac_sha1(totp_config->shared_key,
              totp_config->shared_key_len,
              challenge_data, challenge_len, hash, APR_SHA1_DIGESTSIZE);

    return hash;
}

/**
  * \brief generate_authn_token Generate an authentication token
  * \param r Request
  * \param timestamp Unix timestamp
  * \param totp_code TOTP code
  * \return Pointer to string containing the authentication token on success, NULL otherwise
 **/
static const char *
generate_authn_token(request_rec *r, apr_time_t timestamp, unsigned int totp_code,
                     const totp_user_config *totp_config)
{
    const char     *challenge;
    const char     *token;
    const char     *hash;

    hash = generate_token_hash(r->pool, timestamp, totp_code, totp_config);

    token =
        apr_pencode_base64_binary(r->pool, hash, APR_SHA1_DIGESTSIZE,
                                  APR_ENCODE_NONE, NULL);
    challenge =
        apr_pencode_base64_binary(r->pool, (unsigned char *) &timestamp,
                                  sizeof(apr_time_t), APR_ENCODE_NONE, NULL);

    token = apr_pstrcat(r->pool, challenge, ".", token, NULL);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "generate_authn_token: time %" APR_TIME_T_FMT
                  ", TOTP code \"%6.6u\" -> token \"%s\"",
                  timestamp, totp_code, token);

    return token;
}

/**
  * \brief parse_authn_token Parse an authentication token
  * \param r Request
  * \param token Pointer to string containing the authentication token
  * \param timestamp Either NULL or pointer to memory location to store the Unix timestamp
  * \param hash Either NULL or pointer to memory location that can hold the corresponding SHA1 hash digest
  * \return true on success, false otherwise
 **/
static bool
parse_authn_token(request_rec *r, const char *token,
                  apr_time_t *timestamp, unsigned char **hash)
{
    char           *input = apr_pmemdup(r->pool, token, strlen(token) + 1);
    char           *value, *last;
    const char     *psep = ".";
    const char     *tmp;
    apr_size_t      len = 0;
    apr_status_t    status;


    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "parse_authn_token: parsing token \"%s\"", token);

    value = apr_strtok(input, psep, &last);
    if (value != NULL) {
        if (timestamp) {
            status =
                apr_decode_base64_binary(NULL, value, APR_ENCODE_STRING,
                                         APR_ENCODE_NONE, &len);
            if (len == sizeof(apr_time_t))
                status =
                    apr_decode_base64_binary((unsigned char *) timestamp, value,
                                             APR_ENCODE_STRING, APR_ENCODE_NONE,
                                             &len);

            if ((status != APR_SUCCESS) || (len != sizeof(apr_time_t))) {
                ap_log_rerror(APLOG_MARK,
                              APLOG_ERR,
                              status, r,
                              "parse_authn_token: failed to decode the timestamp");
                return false;
            }
        }

        value = apr_strtok(NULL, psep, &last);
        if (!value) {
            ap_log_rerror(APLOG_MARK,
                          APLOG_ERR,
                          0, r, "parse_authn_token: hash string is absent");
            return false;
        } else if (hash) {
            status =
                apr_decode_base64_binary(NULL, value, APR_ENCODE_STRING,
                                         APR_ENCODE_NONE, &len);
            if (len == APR_SHA1_DIGESTSIZE)
                status =
                    apr_decode_base64_binary(*hash, value, APR_ENCODE_STRING,
                                             APR_ENCODE_NONE, &len);

            if ((status != APR_SUCCESS) || (len != APR_SHA1_DIGESTSIZE)) {
                ap_log_rerror(APLOG_MARK,
                              APLOG_ERR,
                              status, r,
                              "parse_authn_token: failed to decode the hash");
                return false;
            }
        }
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "parse_authn_token: token \"%s\" could not be split", token);
        return false;
    }

    tmp =
        apr_pencode_base16_binary(r->pool, *hash, APR_SHA1_DIGESTSIZE,
                                  APR_ENCODE_COLON, NULL);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "parse_authn_token: token \"%s\" -> time %" APR_TIME_T_FMT
                  ", hash \"%s\"", token, timestamp ? *timestamp : 0L,
                  hash ? tmp : "<NULL>");

    return true;
}

/* Session cookie support */

/**
  * \brief is_session_cookie_available Check if session cookie is available
  * \return true if all required function have been found, false otherwise
 **/
static bool
is_session_cookie_available()
{
    return ap_session_load_fn && ap_session_get_fn && ap_session_set_fn;
}

/**
  * \brief set_session_auth Store username, TOTP password and authentication token to the session cookie
  * \param r Request
  * \param user Pointer to string containing the username
  * \param password Pointer to string containing the password
  * \param token Pointer to string containing the authentication token
 **/
static void
set_session_auth(request_rec *r, const char *user, const char *password,
                 const char *token)
{
    const char     *authname = ap_auth_name(r);
    session_rec    *z = NULL;

    ap_session_load_fn(r, &z);
    ap_session_set_fn(r, z,
                      apr_pstrcat(r->pool, authname, "-" MOD_SESSION_USER, NULL),
                      user);
    ap_session_set_fn(r, z,
                      apr_pstrcat(r->pool, authname, "-" MOD_SESSION_PW, NULL),
                      password);
    ap_session_set_fn(r, z, apr_pstrcat(r->pool, authname, "-totp-token", NULL),
                      token);
}

/**
  * \brief set_session_auth Get username, TOTP password and authentication token from the session cookie
  * \param r Request
  * \param user If not NULL, function returns pointer to a string containing the username
  * \param password If not NULL, function returns pointer to string containing the password
  * \param token If not NULL, function returns pointer to string containing the authentication token
 **/
static void
get_session_auth(request_rec *r, const char **user, const char **password,
                 const char **token)
{
    const char     *authname = ap_auth_name(r);
    session_rec    *z = NULL;

    ap_session_load_fn(r, &z);

    if (user) {
        ap_session_get_fn(r, z,
                          apr_pstrcat(r->pool, authname, "-" MOD_SESSION_USER, NULL),
                          user);
    }
    if (password) {
        ap_session_get_fn(r, z,
                          apr_pstrcat(r->pool, authname, "-" MOD_SESSION_PW, NULL),
                          password);
    }
    if (token) {
        ap_session_get_fn(r, z, apr_pstrcat(r->pool, authname, "-totp-token", NULL),
                          token);
    }

    /* set the user, even though the user is unauthenticated at this point */
    if (user && *user) {
        r->user = (char *) *user;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "get_session_auth: " MOD_SESSION_USER " \"%s\", "
                  MOD_SESSION_PW " \"%s\", token \"%s\"", user ? *user : "<null>",
                  password ? *password : "<null>", token ? *token : "<null>");
}

/* Authentication Helpers: Disallow TOTP Code Reuse */

typedef struct {
    apr_time_t      timestamp;
    unsigned int    totp_code;
} totp_login_rec;

bool
cb_check_code(const void *new, const void *old, totp_file_helper_cb_data *data)
{
    if (old) {
        const apr_time_t timedelta = apr_time_from_sec(data->exp);
        /* check for an existing login entry with new TOTP code */
        totp_login_rec *pNew = (totp_login_rec *) new;
        totp_login_rec *pOld = (totp_login_rec *) old;

        /* check if entry time is within time tolerance */
        if ((pNew->timestamp - pOld->timestamp) <= timedelta) {
            /* check if entry code matches current one */
            if ((pNew->totp_code == pOld->totp_code) && data->conf->disallow_reuse)
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
    char           *code_filepath;
    totp_login_rec  login_data;
    apr_status_t    status;
    totp_file_helper_cb_data cb_data;

    if (!conf->stateDir) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                      "mark_code_invalid: TOTPAuthStateDir is not defined");
        return false;
    }

    /* set code file path */
    code_filepath = apr_psprintf(r->pool, "%s/%s.codes", conf->stateDir, user);

    /* initialize callback data */
    cb_data.conf = totp_config;
    cb_data.exp = conf->expires;
    cb_data.res = 0;

    /* current login entry */
    login_data.timestamp = timestamp;
    login_data.totp_code = totp_code;

    status = check_n_update_file_helper(r, code_filepath,
                                        &login_data, sizeof(totp_login_rec),
                                        cb_check_code, &cb_data);
    if (APR_SUCCESS != status) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                      "mark_code_invalid: could not update codes file \"%s\"",
                      code_filepath);
        return false;
    }

    return (cb_data.res == 0);
}

/* Authentication Helpers: Validate TOTP login */

bool
cb_verify_code(const void *new, const void *old, totp_file_helper_cb_data *data)
{
    if (old) {
        const apr_time_t timedelta = apr_time_from_sec(data->exp);
        /* check for an existing login entry with new TOTP code */
        totp_login_rec *pNew = (totp_login_rec *) new;
        totp_login_rec *pOld = (totp_login_rec *) old;

        /* check if entry time is within time tolerance */
        if ((pNew->timestamp - pOld->timestamp) <= timedelta) {
            /* check if entry code matches current one */
            if ((pOld->timestamp == pNew->timestamp) &&
                (pOld->totp_code == pNew->totp_code))
                data->res++;
            return true;
        }
        return false;
    } else {
        /* should new entry be appended to the file? */
        return false;
    }
}

/**
  * \brief verify_totp_code Verify TOTP login data
  * \param r Request
  * \param timestamp Timestamp for login event
  * \param user Authenticating user name
  * \param totp_config Pointer to user's TOTP authentication settings
  * \param totp_code Authenticating TOTP code
  * \return true upon success, false otherwise
 **/
static bool
verify_totp_code(request_rec *r, apr_time_t timestamp,
                  const char *user, totp_user_config *totp_config,
                  unsigned int totp_code)
{
    totp_auth_config_rec *conf =
        ap_get_module_config(r->per_dir_config, &authn_totp_module);
    char           *code_filepath;
    totp_login_rec  login_data;
    apr_status_t    status;
    totp_file_helper_cb_data cb_data;

    if (!conf->stateDir) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                      "verify_totp_code: TOTPAuthStateDir is not defined");
        return false;
    }

    /* set code file path */
    code_filepath = apr_psprintf(r->pool, "%s/%s.codes", conf->stateDir, user);

    /* initialize callback data */
    cb_data.conf = totp_config;
    cb_data.exp = conf->expires;
    cb_data.res = 0;

    /* current login entry */
    login_data.timestamp = timestamp;
    login_data.totp_code = totp_code;

    status = check_n_update_file_helper(r, code_filepath,
                                        &login_data, sizeof(totp_login_rec),
                                        cb_verify_code, &cb_data);
    if (APR_SUCCESS != status) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                      "verify_totp_code: could not update codes file \"%s\"",
                      code_filepath);
        return false;
    }

    return (cb_data.res == 1);
}

/* Authentication Helpers: Rate Limiting User Logins */

bool
cb_rate_limit(const void *new, const void *old, totp_file_helper_cb_data *data)
{
    if (old) {
        apr_time_t      curr = *((apr_time_t *) new);
        apr_time_t      prev = *((apr_time_t *) old);

        if (curr > prev) {
            /* check if entry time is within time tolerance */
            if ((curr - prev) <= apr_time_from_sec(data->conf->rate_limit_seconds)) {
                data->res++;
                return true;
            }
        }
        return false;
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
    apr_status_t    status;
    char           *login_filepath;
    totp_file_helper_cb_data cb_data;

    /* return immediately if no rate limit is defined */
    if (totp_config->rate_limit_count == 0)
        return true;

    if (!conf->stateDir) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                      "check_rate_limit: TOTPAuthStateDir is not defined");
        return false;
    }

    /* set code file path */
    login_filepath = apr_psprintf(r->pool, "%s/%s.logins", conf->stateDir, user);

    /* initialize callback data */
    cb_data.conf = totp_config;
    cb_data.res = 0;

    status = check_n_update_file_helper(r, login_filepath,
                                        &timestamp, sizeof(apr_time_t),
                                        cb_rate_limit, &cb_data);
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
    unsigned int    password_len = strlen(password);
    apr_time_t      timestamp = apr_time_now();
    apr_time_t      totp_timestamp = to_totp_timestamp(timestamp);
    const char     *token, *tmp;
    unsigned int    totp_code = 0, user_code = 0;
    int             i;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "TOTP BASIC AUTH at timestamp=%" APR_TIME_T_FMT " totp_timestamp=%"
                  APR_TIME_T_FMT, timestamp, totp_timestamp);

    /* validate user name */
    if (!is_alnum_str(user)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "user name contains non-alphanumeric characters");
        return AUTH_USER_NOT_FOUND;
    }

    /* validate password */
    if ((password_len == 6) || (password_len == 8)) {
        if (!is_digit_str(password)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "password contains non-digit characters");
            return AUTH_DENIED;
        }
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "password is not recognized as a TOTP (6 digits) or a scratch code (8 digits)");
        return AUTH_DENIED;
    }

    totp_config = get_user_config(r, user);
    if (!totp_config) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "could not find TOTP configuration for user \"%s\"", user);
        return AUTH_USER_NOT_FOUND;
    }
#ifdef DEBUG_TOTP_AUTH
    tmp =
        apr_pencode_base16_binary(r->pool, totp_config->shared_key,
                                  totp_config->shared_key_len,
                                  APR_ENCODE_COLON, NULL);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "secret key is \"%s\", secret length: %ld",
                  tmp, totp_config->shared_key_len);
#endif

    /* check if user login count is within the rate limit */
/*    if (!check_rate_limit(r, timestamp, user, totp_config)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "login attemp for user \"%s\" exceeds rate limit", user);
        return AUTH_DENIED;
    }
*/
    /* TOTP Authentication */
    user_code = (unsigned int) apr_atoi64(password);
    /* TOTP codes */
    if (password_len == 6) {
        for (i = -(totp_config->window_size); i <= (totp_config->window_size); ++i) {
            totp_code = generate_totp_code(totp_timestamp + i, totp_config);

            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "validating code timestamp=%" APR_TIME_T_FMT
                          ", expected=\"%6.6u\", input=\"%6.6u\"", timestamp,
                          totp_code, user_code);

            if (totp_code == user_code) {
                if (mark_code_invalid(r, timestamp, user, totp_config, user_code)) {
                    if (is_session_cookie_available()) {
                        token =
                            generate_authn_token(r, timestamp, user_code,
                                                 totp_config);
                        tmp = apr_psprintf(r->pool, "%6.6u", user_code);
                        if (token && tmp)
                            set_session_auth(r, user, tmp, token);
                    }

                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                                  "access granted for user \"%s\" based on code \"%6.6u\"",
                                  user, user_code);
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

            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "validating scratch code expected=\"%8.8u\", input=\"%8.8u\"",
                          totp_config->scratch_codes[i], user_code);

            if (totp_config->scratch_codes[i] == user_code) {
                if (mark_code_invalid(r, timestamp, user, totp_config, user_code)) {
                    if (is_session_cookie_available()) {
                        token =
                            generate_authn_token(r, timestamp, user_code,
                                                 totp_config);
                        tmp = apr_psprintf(r->pool, "%8.8u", user_code);
                        if (token && tmp)
                            set_session_auth(r, user, tmp, token);
                    }

                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                                  "access granted for user \"%s\" based on scratch code \"%8.8u\"",
                                  user, user_code);
                    return AUTH_GRANTED;
                } else
                    /* fail authentication attempt */
                    break;
            }
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "access denied for user \"%s\" based on password \"%s\"",
                  user, password);

    return AUTH_DENIED;
}

/**
 * Check user's TOTP authentication token
 */
static int
authn_totp_check_authn(request_rec *r)
{
    totp_auth_config_rec *conf =
        ap_get_module_config(r->per_dir_config, &authn_totp_module);

    totp_user_config *totp_config = NULL;
    const char     *sent_user = NULL, *sent_password = NULL,
                   *sent_token = NULL, *tmp;
    unsigned char  *hash, *sent_hash;
    unsigned int    sent_totp_code;
    unsigned int    password_len;
    apr_time_t      sent_timestamp;

    /* check if session cookie support is available */
    if (!is_session_cookie_available())
        return DECLINED;

    /* check if authentication realm is set */
    if (!ap_auth_name(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "authn_totp_check_authn: AuthName is not set");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* get data from session cookie */
    get_session_auth(r, &sent_user, &sent_password, &sent_token);

    if (sent_user && sent_password && sent_token) {
        sent_hash = apr_palloc(r->pool, APR_SHA1_DIGESTSIZE);
        if (parse_authn_token(r, sent_token, &sent_timestamp, &sent_hash)) {

            /* validate username */
            if (!is_alnum_str(sent_user)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "authn_totp_check_authn: username contains non-alphanumeric characters");
                return DECLINED;
            }

            /* validate password */
            password_len = strlen(sent_password);
            if ((password_len == 6) || (password_len == 8)) {
                if (!is_digit_str(sent_password)) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                  "authn_totp_check_authn: password contains non-digit characters");
                    return DECLINED;
                }
            } else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "authn_totp_check_authn: password is not recognized as a TOTP (6 digits) or a scratch code (8 digits)");
                return DECLINED;
            }

            /* get the TOTP code sent by user */
            totp_config = get_user_config(r, sent_user);
            if (!totp_config) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "authn_totp_check_authn: could not find TOTP configuration for user \"%s\"",
                              sent_user);
                return DECLINED;
            }
#ifdef DEBUG_TOTP_AUTH
            tmp =
                apr_pencode_base16_binary(r->pool, totp_config->shared_key,
                                          totp_config->shared_key_len,
                                          APR_ENCODE_COLON, NULL);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "authn_totp_check_authn: secret key is \"%s\", secret length: %ld",
                          tmp, totp_config->shared_key_len);
#endif

            /* get the TOTP code sent by user */
            sent_totp_code = (unsigned int) apr_atoi64(sent_password);

            /* generate expected TOTP code */
            hash =
                generate_token_hash(r->pool, sent_timestamp, sent_totp_code,
                                    totp_config);

            if (0 == memcmp(hash, sent_hash, APR_SHA1_DIGESTSIZE)) {
                if(verify_totp_code(r, sent_timestamp, sent_user, totp_config, sent_totp_code)) {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                                "authn_totp_check_authn: access granted to user \"%s\"",
                                sent_user);
                    return OK;
                }
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                              "authn_totp_check_authn: TOTP verification failed user \"%s\"",
                              sent_user);
            } else {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                              "authn_totp_check_authn: hash mismatch for user \"%s\"",
                              sent_user);
            }
        }
    }

    /* pass on */
    return DECLINED;
}

static int
authn_totp_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                       apr_pool_t *ptemp, server_rec *s)
{

    if (!is_session_cookie_available()) {
        ap_session_load_fn = APR_RETRIEVE_OPTIONAL_FN(ap_session_load);
        ap_session_get_fn = APR_RETRIEVE_OPTIONAL_FN(ap_session_get);
        ap_session_set_fn = APR_RETRIEVE_OPTIONAL_FN(ap_session_set);

        if (!is_session_cookie_available()) {
            ap_log_error(APLOG_MARK, APLOG_WARNING,
                         0, NULL,
                         "Failed to load mod_session: TOTP authentication will not be persistent");
        }
    }

    return OK;
}

/* Module Declaration */

static const authn_provider authn_totp_provider =
    { &authn_totp_check_password, NULL };

static void
register_hooks(apr_pool_t *p)
{
    ap_hook_check_authn(authn_totp_check_authn, NULL, NULL, APR_HOOK_FIRST,
                        AP_AUTH_INTERNAL_PER_CONF);

    ap_hook_post_config(authn_totp_post_config, NULL, NULL, APR_HOOK_MIDDLE);

    ap_register_auth_provider(p, AUTHN_PROVIDER_GROUP, "totp",
                              AUTHN_PROVIDER_VERSION, &authn_totp_provider,
                              AP_AUTH_INTERNAL_PER_CONF);
}

AP_DECLARE_MODULE(authn_totp) = {
    STANDARD20_MODULE_STUFF,
    create_authn_totp_config,   /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    authn_totp_cmds,            /* command apr_table_t */
    register_hooks              /* register hooks */
};
