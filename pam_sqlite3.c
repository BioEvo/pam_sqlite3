/*
 *  * PAM authentication module for SQLite
 *  *
 *  * pam_sqlite3: zhangjun <18238896@qq.com>
 *  *
 *  * This work is a dirivative of pam_sqlite3 
 *  * (https://github.com/HormyAJP/pam_sqlite3).
 *  *
 *  pam_sqlite3
 *
 *  This work is Copyright (C) zhangjun
 *  GNU GPL v3
 *  This work is a dirivative of pam_sqlite3, Copyright (C) HormyAJP
 *  pam_sqlite3 is a dirivative of pam_sqlite3.
 *
 *  Different portions of this program are Copyright to the respective
 *  authors of those peices of code; but are all under the terms
 *  of of the GNU General Pulblic License.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.
 *
 *  */

/* $Id: pam_sqlite.c,  2019/04/28 22:30:07 $ */
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <ctype.h>
#include <unistd.h>
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <time.h>
#include <sqlite3.h>

#ifdef HAVE_OPENSSL_MD5_H
#include <openssl/md5.h>
#endif
#ifdef HAVE_OPENSSL_SHA_H
#include <openssl/sha.h>
#endif

#include <sys/cdefs.h>

#define PAM_OPT_USE_FIRST_PASS      0x04
#define PAM_OPT_TRY_FIRST_PASS      0x08
#define PAM_OPT_ECHO_PASS       0x20

#include <security/pam_modules.h>
#include <security/pam_appl.h>

#define PAM_MODULE_NAME  "pam_sqlite3"

#define SYSLOG(x...)  do {                                          \
                          openlog("pam_sqlite3", LOG_PID, LOG_AUTH); \
                          syslog(LOG_INFO, ##x);                    \
                          closelog();                               \
                      } while(0)
#define SYSLOGERR(x...) SYSLOG("Error: " x)

static const char* UNKNOWN_SERVICE = "<Unknown Service>";

typedef enum {
    PW_CLEAR = 0,
    PW_MD5 = 1,
    PW_SHA = 2
} pw_scheme;

/* Options */
struct module_options {
    char *db;
    char *table;
    char *user;
    char *passwd;
    char *active;
    char *expire;
    pw_scheme pw_type;
};

#define FAIL(MSG)       \
    {                   \
        SYSLOGERR(MSG); \
        free(buf);      \
        return NULL;    \
    }

#define GROW(x)     if (x > buflen - dest - 1) {            \
    char *grow;                                             \
    buflen += 256 + x;                                      \
    grow = realloc(buf, buflen + 256 + x);                  \
    if (grow == NULL) FAIL("Out of memory building query"); \
    buf = grow;                                             \
}

#define APPEND(str, len)    GROW(len); memcpy(buf + dest, str, len); dest += len
#define APPENDS(str)    len = strlen(str); APPEND(str, len)

#define MAX_ZSQL -1

/*
 * * Being very defensive here. The current logic in the rest of the code should prevent this from
 * * happening. But lets protect against future code changes which could cause a NULL ptr to creep
 * * in.
 * */
#define CHECK_STRING(str)                                                       \
    if (!str)                                                                   \
        FAIL("Internal error in format_query: string ptr " #str " was NULL");

static void *xcalloc(size_t nmemb, size_t size)
{
    void *retval;
    double v = ((double)size) * (int)(nmemb & (((size_t)-1) >> 1));

    if (v != nmemb * size) {
        return NULL;
    }

    retval = calloc(nmemb, size);

    return retval;
}

#ifdef HAVE_OPENSSL_MD5_H
#define HAVE_PAM_MD5_DATA
/* pam_md5_data */
static char *pam_md5_data(const char *d, unsigned int sz, char *md)
{
    size_t i, j;
    unsigned char buf[16];

    if (md == NULL) {
        if ((md = xcalloc(32 + 1, sizeof(char))) == NULL) {
            return NULL;
        }
    }

    MD5((unsigned char*)d, (unsigned long)sz, buf);

    for (i = 0, j = 0; i < 16; i++, j += 2) {
        md[j + 0] = "0123456789abcdef"[(int)(buf[i] >> 4)];
        md[j + 1] = "0123456789abcdef"[(int)(buf[i] & 0x0f)];
    }
    md[j] = '\0';

    return md;
}
#endif

#ifdef HAVE_OPENSSL_SHA_H
#define HAVE_PAM_SHA_DATA
/* pam_sha_data */
static char *pam_sha_data(const char *d, unsigned int sz, char *md)
{
    size_t i, j;
    unsigned char buf[SHA_DIGEST_LENGTH];

    if (md == NULL) {
        if ((md = xcalloc(SHA_DIGEST_LENGTH*2 + 1, sizeof(char))) == NULL) {
            return NULL;
        }
    }

    SHA1((unsigned char*)d, (unsigned long)sz, buf);

    for (i = 0, j = 0; i < SHA_DIGEST_LENGTH; i++, j += 2) {
        md[j + 0] = "0123456789abcdef"[(int)(buf[i] >> 4)];
        md[j + 1] = "0123456789abcdef"[(int)(buf[i] & 0x0f)];
    }
    md[j] = '\0';

    return md;
}
#endif

static char *format_query(const char *template, struct module_options *options,
    const char *user, const char *passwd)
{
    char *buf = malloc(256);
    if (!buf)
        return NULL;

    int buflen = 256;
    int dest = 0, len;
    const char *src = template;
    char *pct;
    char *tmp;

    while (*src) {
        pct = strchr(src, '%');

        if (pct) {
            /* copy from current position to % char into buffer */
            if (pct != src) {
                len = pct - src;
                APPEND(src, len);
            }

            /* decode the escape */
            switch(pct[1]) {
                case 'U':   /* username */
                    if (user) {
                        tmp = sqlite3_mprintf("%q", user);
                        if (!tmp)
                            FAIL("sqlite3_mprintf out of memory");
                        len = strlen(tmp);
                        APPEND(tmp, len);
                        sqlite3_free(tmp);
                    }
                    break;
                case 'P':   /* password */
                    if (passwd) {
                        tmp = sqlite3_mprintf("%q", passwd);
                        if (!tmp)
                            FAIL("sqlite3_mprintf out of memory");
                        len = strlen(tmp);
                        APPEND(tmp, len);
                        sqlite3_free(tmp);
                    }
                    break;
                case 'O':   /* option value */
                    pct++;
                    switch (pct[1]) {
                        case 'p':   /* passwd */
                            CHECK_STRING(options->passwd);
                            APPENDS(options->passwd);
                            break;
                        case 'u':   /* username */
                            CHECK_STRING(options->user);
                            APPENDS(options->user);
                            break;
                        case 't':   /* table */
                            CHECK_STRING(options->table);
                            APPENDS(options->table);
                            break;
                        case 'e':  /* expire */
                            CHECK_STRING(options->expire);
                            APPENDS(options->expire);
                            break;
                    }
                    break;

                case '%':   /* quoted % sign */
                    APPEND(pct, 1);
                    break;

                default:    /* unknown */
                    APPEND(pct, 2);
                    break;
            }
            src = pct + 2;
        } else {
            /* copy rest of string into buffer and we're done */
            len = strlen(src);
            APPEND(src, len);
            break;
        }
    }

    buf[dest] = '\0';
    return buf;
}

/*
 *  * safe_assign protects against duplicate config options causing a memory leak.
 *  */
static void inline
safe_assign(char **asignee, const char *val)
{
    if(*asignee)
        free(*asignee);
    *asignee = strdup(val);
}

static int
pam_conv_pass(pam_handle_t *pamh, int options)
{
    int retval;
    const void *item;
    const struct pam_conv *conv;
    struct pam_message msg;
    const struct pam_message *msgs[1];
    struct pam_response *resp;

    if ((retval = pam_get_item(pamh, PAM_CONV, &item)) != PAM_SUCCESS)
        return retval;
    conv = (const struct pam_conv *)item;
    msg.msg_style = options & PAM_OPT_ECHO_PASS ? PAM_PROMPT_ECHO_ON : PAM_PROMPT_ECHO_OFF;
    msg.msg = "";
    msgs[0] = &msg;
    if ((retval = conv->conv(1, msgs, &resp, conv->appdata_ptr)) != PAM_SUCCESS)
        return retval;
    if ((retval = pam_set_item(pamh, PAM_AUTHTOK, resp[0].resp)) != PAM_SUCCESS)
        return retval;
    memset(resp[0].resp, 0, strlen(resp[0].resp));
    free(resp[0].resp);
    free(resp);
    return PAM_SUCCESS;
}

int
pam_get_pass(pam_handle_t *pamh, const char **passp, int options)
{
    int retval;
    const void *item = NULL;

    /*
     * Grab the already-entered password if we might want to use it.
     */
    if (options & (PAM_OPT_TRY_FIRST_PASS | PAM_OPT_USE_FIRST_PASS)) {
        if ((retval = pam_get_item(pamh, PAM_AUTHTOK, &item)) != PAM_SUCCESS)
            return retval;
    }

    if (item == NULL) {
        /* The user hasn't entered a password yet. */
        if (options & PAM_OPT_USE_FIRST_PASS)
            return PAM_AUTH_ERR;
        /* Use the conversation function to get a password. */
        if ((retval = pam_conv_pass(pamh, options)) != PAM_SUCCESS ||
            (retval = pam_get_item(pamh, PAM_AUTHTOK, &item)) != PAM_SUCCESS)
            return retval;
    }
    *passp = (const char *)item;
    return PAM_SUCCESS;
}

const char* pam_get_service(pam_handle_t *pamh, const char **service)
{
    if (pam_get_item(pamh, PAM_SERVICE, (const void**)service) != PAM_SUCCESS)
        *service = UNKNOWN_SERVICE;
    return *service;
}

/* private: parse and set the specified string option */
static void
set_module_option(const char *option, struct module_options *options)
{
    char *buf, *eq;
    char *val, *end;

    if(!option || !*option)
        return;

    buf = strdup(option);
    if(!buf)
        return;

    if((eq = strchr(buf, '='))) {
        end = eq - 1;
        val = eq + 1;
        if(end <= buf || !*val)
        {
            free(buf);
            return;
        }
        while(end > buf && isspace(*end))
            end--;
        end++;
        *end = '\0';
        while(*val && isspace(*val))
            val++;
    } else {
        val = NULL;
    }

    // SYSLOG("setting option: %s=>%s\n", buf, val);

    if(!strcmp(buf, "db")) {
        safe_assign(&options->db, val);
    } else if(!strcmp(buf, "table")) {
        safe_assign(&options->table, val);
    } else if(!strcmp(buf, "user")) {
        safe_assign(&options->user, val);
    } else if(!strcmp(buf, "passwd")) {
        safe_assign(&options->passwd, val);
    } else if(!strcmp(buf, "active")) {
        safe_assign(&options->active, val);
    } else if(!strcmp(buf, "expire")) {
        safe_assign(&options->expire, val);
    } else if(!strcmp(buf, "crypt")) {
        if(!strcmp(val, "1")) {
            options->pw_type = PW_MD5;
        } else if(!strcmp(val, "2")) {
            options->pw_type = PW_SHA;
        } else {
            options->pw_type = PW_CLEAR;
        }
    } else {
        SYSLOG("ignored option: %s\n", buf);
    }

    free(buf);
}

/* private: read module options from file or commandline */
static int
get_module_options(int argc, const char **argv, struct module_options **options)
{
    int i, rc;
    struct module_options *opts;

    rc = 0;
    if (!(opts = (struct module_options *)malloc(sizeof *opts))){
        *options = NULL;
        return rc;
    }

    bzero(opts, sizeof(*opts));
    opts->pw_type = PW_CLEAR;

    for(i = 0; i < argc; i++) {
        set_module_option(argv[i], opts);
    }
    *options = opts;

    return rc;
}

/* private: free module options returned by get_module_options() */
static void
free_module_options(struct module_options *options)
{
    if (!options)
        return;

    if(options->db)
        free(options->db);
    if(options->table)
        free(options->table);
    if(options->user)
        free(options->user);
    if(options->passwd)
        free(options->passwd);
    if(options->active)
        free(options->active);
    if(options->expire)
        free(options->expire);

    bzero(options, sizeof(*options));
    free(options);
}

/* private: make sure required options are present (in cmdline or conf file) */
static int
options_valid(struct module_options *options)
{
    if(!options)
    {
        SYSLOGERR("failed to read options.");
        return -1;
    }

    if(options->db == 0 || options->table == 0 || options->user == 0)
    {
        SYSLOGERR("the database, table and user options are required.");
        return -1;
    }
    return 0;
}

/* private: open SQLite database */
static sqlite3 *pam_sqlite3_connect(struct module_options *options)
{
  const char *errtext = NULL;
  sqlite3 *sdb = NULL;

  if (sqlite3_open(options->db, &sdb) != SQLITE_OK) {
      errtext = sqlite3_errmsg(sdb);
      SYSLOG("Error opening SQLite database (%s)", errtext);
      /*
       * * N.B. sdb is usually non-NULL when errors occur, so we explicitly
       * * release the resource and return NULL to indicate failure to the caller.
       * */

      sqlite3_close(sdb);
      return NULL;
  }

  return sdb;
}


/* private: authenticate expire for acount  */
static int
auth_verify_expire(const char *user, struct module_options *options)
{
    int res;
    int rc = PAM_CRED_EXPIRED;
    sqlite3 *conn = NULL;
    sqlite3_stmt *vm = NULL;    
    const char *tail  = NULL;
    const char *errtext = NULL;
    char *query  = NULL;
    time_t timenow = {0}, endtime = {0};
    struct tm *timeinfo;

    if(!(conn = pam_sqlite3_connect(options))) {
        rc = PAM_AUTH_ERR;
        goto done;
    }

    if(!(query = format_query("SELECT %Oe FROM %Ot WHERE %Ou='%U'", options, user, NULL))) {
        SYSLOGERR("failed to construct sql query");
        rc = PAM_AUTH_ERR;
        goto done;
    }

    res = sqlite3_prepare(conn, query, MAX_ZSQL, &vm, &tail);

    free(query);

    if (res != SQLITE_OK) {
        errtext = sqlite3_errmsg(conn);
        SYSLOG("Error executing SQLite query (%s)", errtext);
        rc = PAM_AUTH_ERR;
        goto done;
    }

    if (SQLITE_ROW != sqlite3_step(vm)) {
        SYSLOG("no rows to retrieve");
        rc = PAM_AUTH_ERR;
        goto done;
    }
    
    const char *expire = (const char *) sqlite3_column_text(vm, 0);
    if (!expire) {
        SYSLOG("sqlite3 failed to return row data");
        rc = PAM_AUTH_ERR;
        goto done;
    }

    char year[5], mon[3], day[3], ym[8];

    char *dtmp = strrchr(expire, '-');
    strncpy(ym, expire, strlen(expire) - strlen(dtmp));
    char *mtmp = strrchr(ym, '-');
    strncpy(year, ym, strlen(ym) - strlen(mtmp));
    strcpy(day, ++dtmp);
    strcpy(mon, ++mtmp);

    timenow = time(NULL);
    timeinfo = localtime(&timenow);
    timeinfo->tm_year = atoi(year) - 1900;
    timeinfo->tm_mon = atoi(mon) - 1;
    timeinfo->tm_mday = atoi(day);
    endtime = mktime(timeinfo);

    if (difftime(endtime, timenow) > 0 ) {
        rc = PAM_SUCCESS;
    }

done:
    sqlite3_finalize(vm);
    sqlite3_close(conn);
    return rc;
}

/* private: authenticate user and passwd against database */
static int
auth_verify_password(const char *user, const char *passwd,
                     struct module_options *options)
{
    int res;
    sqlite3 *conn = NULL;
    sqlite3_stmt *vm = NULL;
    int rc = PAM_AUTH_ERR;
    const char *tail  = NULL;
    const char *errtext = NULL;
    char *encrypted_pw = NULL;
    char *query  = NULL;

    if(!(conn = pam_sqlite3_connect(options))) {
        rc = PAM_AUTH_ERR;
        goto done;
    }
        
    if(!(query = format_query("SELECT %Op FROM %Ot WHERE %Ou='%U'", options, user, NULL) )) {
        SYSLOGERR("failed to construct sql query");
        rc = PAM_AUTH_ERR;
        goto done;
    }

    // SYSLOG("query: %s", query);

    res = sqlite3_prepare(conn, query, MAX_ZSQL, &vm, &tail);

    free(query);

    if (res != SQLITE_OK) {
        errtext = sqlite3_errmsg(conn);
        SYSLOG("Error executing SQLite query (%s)", errtext);
        rc = PAM_AUTH_ERR;
        goto done;
    }

    if (SQLITE_ROW != sqlite3_step(vm)) {
        SYSLOG("no rows to retrieve");
        rc = PAM_USER_UNKNOWN;
        goto done;        
    }
    
    const char *stored_pw = (const char *) sqlite3_column_text(vm, 0);
    if (!stored_pw) {
        SYSLOG("sqlite3 failed to return row data");
        rc = PAM_AUTH_ERR;
        goto done;
    }
    
    switch(options->pw_type) {
    case PW_CLEAR:
        if(strcmp(passwd, stored_pw) == 0)
            rc = PAM_SUCCESS;
        break;
#ifdef HAVE_PAM_MD5_DATA
    case PW_MD5:
        encrypted_pw = pam_md5_data(passwd, strlen(passwd), encrypted_pw);
        if (!encrypted_pw) {
            SYSLOG("crypt failed when encrypting password");
            rc = PAM_AUTH_ERR;
            goto done;
        }

        if(strcmp(encrypted_pw, stored_pw) == 0)
            rc = PAM_SUCCESS;
        break;
#endif
#ifdef HAVE_PAM_SHA_DATA
    case PW_SHA:
        encrypted_pw = pam_sha_data(passwd, strlen(passwd), encrypted_pw);
        if (!encrypted_pw) {
            SYSLOG("crypt failed when encrypting password");
            rc = PAM_AUTH_ERR;
            goto done;
        }

        if(strcmp(encrypted_pw, stored_pw) == 0)
            rc = PAM_SUCCESS;
        break;
    }
#endif

done:
    sqlite3_finalize(vm);
    sqlite3_close(conn);
    return rc;
}

/* public: authenticate user */
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    struct module_options *options = NULL;
    const char *user = NULL, *password = NULL, *service = NULL;
    int rc, std_flags;

    std_flags = get_module_options(argc, argv, &options);
    if(options_valid(options) != 0) {
        rc = PAM_AUTH_ERR;
        goto done;
    }

    if((rc = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
        SYSLOG("failed to get username from pam");
        goto done;
    }

    SYSLOG("attempting to authenticate: '%s'", user);
        
    if((rc = pam_get_pass(pamh, &password, std_flags) != PAM_SUCCESS)) {
        goto done;
    }
        
    if((rc = auth_verify_password(user, password, options)) != PAM_SUCCESS)
        SYSLOG("(%s) user '%s' is not authenticated.", pam_get_service(pamh, &service), user);
    else
        SYSLOG("(%s) user '%s' is authenticated.", pam_get_service(pamh, &service), user);

done:
    free_module_options(options);
    return rc;
}

/* public: check if account has active */
PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    struct module_options *options = NULL;
    const char *user = NULL, *service = NULL;
    int rc = PAM_AUTH_ERR;
    sqlite3 *conn = NULL;
    sqlite3_stmt *vm = NULL;
    char *query = NULL;
    const char *tail = NULL;
    const char *errtext = NULL;
    int res;

    get_module_options(argc, argv, &options);
    if(options_valid(options) != 0) {
        rc = PAM_AUTH_ERR;
        goto done;
    }

    /* both not specified, just succeed. */
    if(options->active == NULL || atoi(options->active) == 0) {
        rc = PAM_ACCT_EXPIRED;
        SYSLOG("(%s) Default all users are not activated.", pam_get_service(pamh, &service));
        goto done;
    }    

    if((rc = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
        SYSLOGERR("could not retrieve user");
        rc = PAM_AUTH_ERR;
        goto done;
    }
    
    if(!(conn = pam_sqlite3_connect(options))) {
        SYSLOGERR("could not connect to database");
        rc = PAM_AUTH_ERR;
        goto done;
    }    

    /* if account has activated then active = '1' */
    if(atoi(options->active) == 1) {
        if(!(query = format_query("SELECT active from %Ot WHERE %Ou='%U'", options, user, NULL))) {
            SYSLOGERR("failed to construct sql query");
            rc = PAM_AUTH_ERR;
            goto done;
        }
        
        res = sqlite3_prepare(conn, query, MAX_ZSQL, &vm, &tail);
        free(query);

        if (res != SQLITE_OK) {
            errtext = sqlite3_errmsg(conn);
            SYSLOGERR("Error executing SQLite query (%s)", errtext);
            rc = PAM_AUTH_ERR;
            goto done;
        }

        res = sqlite3_step(vm);

        if(SQLITE_ROW != res) {
            SYSLOG("no rows to retrieve");
            rc = PAM_AUTH_ERR;            
            goto done;
        }
        
        const char *active = (const char *) sqlite3_column_text(vm, 0);
        if (atoi(active) == 1) {
            if((rc = auth_verify_expire(user, options)) != PAM_SUCCESS) {
                SYSLOG("(%s) user '%s' has expire.", pam_get_service(pamh, &service), user);
                rc = PAM_ACCT_EXPIRED;
                goto done;
            }
        } else {
            SYSLOG("(%s) user '%s' is not activated.", pam_get_service(pamh, &service), user);
            rc = PAM_ACCT_EXPIRED;
            goto done;
        }
        
        SYSLOG("(%s) user '%s' is activated.", pam_get_service(pamh, &service), user);
        rc = PAM_SUCCESS;
    }
    
done:
    /* Do all cleanup in one place. */
    sqlite3_finalize(vm);
    sqlite3_close(conn);
    free_module_options(options);
    return rc;
}

/* public: change password */
PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{       
    return PAM_SUCCESS;
}

/* public: just succeed. */
PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}
