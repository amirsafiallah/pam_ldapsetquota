#include "library.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <ldap.h>
#include <err.h>
#include <ctype.h>
#include <syslog.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>
#include <linux/quota.h>
#include <sys/quota.h>
#include <errno.h>
#include <string.h>
#include <mntent.h>
#include <pwd.h>

struct ldap_quota {
    char fs[BUFSIZ]; //File System
    u_int64_t quotaBhardlimit; //Blocks Hard Limit
    u_int64_t quotaBsoftlimit; //Blocks Soft Limit
    u_int64_t quotaIhardlimit; //INodes Hard Limit
    u_int64_t quotaIsoftlimit; //INodes Soft Limit
};

char *trim(char *str) {
    char *end;

    // Trim leading space
    while (isspace((unsigned char) *str)) str++;

    if (*str == 0)  // All spaces?
        return str;

    // Trim trailing space
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char) *end)) end--;

    // Write new null terminator
    *(end + 1) = 0;

    return str;
}

//return 1 if success
int read_ldap_quota(char *str, struct ldap_quota *a) {
    //read (FileSystem:BlocksSoft,BlocksHard,InodesSoft,InodesHard) from quota attribute
    //this format is used on quota.schema

    a->fs[0] = '\0';
    char *p = strchr(str, ':'); //find `:` character
    if (p == NULL) return 0;
    *(p) = '\0';
    strncpy(a->fs, trim(str), sizeof(a->fs)); //trim any whitespace before and after FS path

    int r = sscanf(p + 1,
                   " %lu , %lu , %lu , %lu ",
                   &a->quotaBsoftlimit,
                   &a->quotaBhardlimit,
                   &a->quotaIsoftlimit,
                   &a->quotaIhardlimit);
    return (r > 0);
}

/*return 1 if anything changed*/
void setquota(struct if_dqblk *pDqblk, const struct ldap_quota *pQuota) {
    pDqblk->dqb_bhardlimit = pQuota->quotaBhardlimit;
    pDqblk->dqb_bsoftlimit = pQuota->quotaBsoftlimit;
    pDqblk->dqb_ihardlimit = pQuota->quotaIhardlimit;
    pDqblk->dqb_isoftlimit = pQuota->quotaIsoftlimit;

    pDqblk->dqb_valid |= QIF_BLIMITS;
    pDqblk->dqb_valid |= QIF_ILIMITS;
}

int configure(pam_handle_t *pamh, const struct ldap_quota *pQuota, uid_t uid) {
    char mntdevice[BUFSIZ], mntpoint[BUFSIZ];
    const struct mntent *mnt;
    *mntpoint = *mntdevice = '\0';
    size_t match_size = 0;
    const struct passwd *pwd;
    FILE *fd;

    pwd = getpwuid(uid);

    if ((fd = setmntent("/etc/mtab", "r")) == NULL) {
        pam_syslog(pamh, LOG_ERR, "Unable to open /etc/mtab");
        return PAM_PERM_DENIED;
    }

    while ((mnt = getmntent(fd)) != NULL) {
        if (pQuota->fs == NULL) {
            size_t mnt_len = strlen(mnt->mnt_dir);
            /* If fs is not specified use filesystem with homedir as default
             * Checking the mnt_len-th character in pwd->pw_dir is safe because of the
             * strncmp(2) check before (whose success implies strlen(pwd->pw_dir) >=
             * mntlen)
             */
            if ((strncmp(pwd->pw_dir, mnt->mnt_dir, mnt_len) == 0) &&
                (mnt_len > match_size) &&
                (pwd->pw_dir[mnt_len] == '\0' || pwd->pw_dir[mnt_len] == '/')) {
                strncpy(mntpoint, mnt->mnt_dir, sizeof(mntpoint));
                strncpy(mntdevice, mnt->mnt_fsname, sizeof(mntdevice));
                match_size = mnt_len;
            }
        } else if ((strcmp(pQuota->fs, mnt->mnt_dir) == 0) ||
                   (strcmp(pQuota->fs, mnt->mnt_fsname) == 0)) {
            strncpy(mntdevice, mnt->mnt_fsname, sizeof(mntdevice));
        }
    }
    /*The endmntent() function closes the file system description file fd*/
    endmntent(fd);

    struct if_dqblk ndqblk;
    /* Get limits */
    if (quotactl(QCMD(Q_GETQUOTA, USRQUOTA), mntdevice, pwd->pw_uid,
                 (void *) &ndqblk) == -1) {
        pam_syslog(pamh, LOG_ERR, "%s", strerror(errno));
        return PAM_PERM_DENIED;
    }

    setquota(&ndqblk, pQuota);

    if (quotactl(QCMD(Q_SETQUOTA, USRQUOTA), mntdevice, pwd->pw_uid,
                 (void *) &ndqblk) == -1) {
        pam_syslog(pamh, LOG_ERR, "%s", strerror(errno));
        return PAM_PERM_DENIED;
    }
    return PAM_SUCCESS;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    int read = 0;
    int retval;
    const void *user;
    const struct passwd *pwd;
    struct ldap_quota ldapquota; //Quota information from ldap
    const char *url = URL;
    const char *dn = DN; //dn
    char filter[1024]; //person uid number
    char *attr[] = {"quota", NULL}; //attribute `quota` according to schema.
    LDAP *LDAP;
    int version = LDAPVERSION; //version of ldap
    struct timeval search_timeout;
    search_timeout.tv_sec = SEARCH_TIMEOUT_SECOND; //search timeout (seconds)
    search_timeout.tv_usec = SEARCH_TIMEOUT_MICROSECOND;//and search timeout (microseconds)
    int err;
    LDAPMessage *res;

    retval = pam_get_item(pamh, PAM_USER, &user);
    if (retval != PAM_SUCCESS || user == NULL || *(const char *) user == '\0') {
        pam_syslog(pamh, LOG_NOTICE, "user unknown");
        return PAM_USER_UNKNOWN;
    }

    pwd = getpwnam(user);
    if (pwd == NULL) {
        return PAM_CRED_INSUFFICIENT;
    }

    if (pwd->pw_uid < START_UID || pwd->pw_uid > END_UID)
        return PAM_SUCCESS;

    sprintf(filter, "uidNumber=%u", pwd->pw_uid);

    err = ldap_initialize(&LDAP, url);
    if (err != LDAP_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "ldap_initialize(): %s\n", ldap_err2string(err));
        return PAM_SESSION_ERR;
    }

    err = ldap_set_option(LDAP, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (err != LDAP_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "ldap_set_option(PROTOCOL_VERSION): %s\n", ldap_err2string(err));
        ldap_unbind_ext_s(LDAP, NULL, NULL);
        return PAM_SESSION_ERR;
    };


    err = ldap_search_ext_s(
            LDAP,                         // LDAP            * ld
            dn,        // char            * base
            LDAP_SCOPE_ONELEVEL,     // int               scope
            filter,    // char            * filter
            attr,     // char            * attrs[]
            0,                          // int               attrsonly
            NULL,                       // LDAPControl    ** serverctrls
            NULL,                       // LDAPControl    ** clientctrls
            &search_timeout,                        // struct timeval  * timeout
            1,        // int               sizelimit
            &res                        // LDAPMessage    ** res
    );

    if (err != LDAP_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "ldap_search_ext_s(): %s\n", ldap_err2string(err));
        ldap_msgfree(res);
        ldap_unbind_ext_s(LDAP, NULL, NULL);
        return PAM_SESSION_ERR;
    };

    // verify an entry was found
    if (!(ldap_count_entries(LDAP, res))) {
        pam_syslog(pamh, LOG_NOTICE, "0 entries found.\n");
        ldap_msgfree(res);
        ldap_unbind_ext_s(LDAP, NULL, NULL);
        return PAM_SESSION_ERR;
    };
    pam_syslog(pamh, LOG_NOTICE, "# %i entries found.\n", ldap_count_entries(LDAP, res));

    // loops through entries, attributes, and values
    LDAPMessage *entry = ldap_first_entry(LDAP, res);

    BerElement *ber;
    char *attribute = ldap_first_attribute(LDAP, entry, &ber);
    while ((attribute)) {
        struct berval **vals = ldap_get_values_len(LDAP, entry, attribute);
        for (int pos = 0; pos < ldap_count_values_len(vals); pos++)
            if (strcmp(attribute, "quota") == 0) {
                if (read_ldap_quota(vals[pos]->bv_val, &ldapquota))
                    read = 1;
            }
        ldap_value_free_len(vals);
        ldap_memfree(attribute);
        attribute = ldap_next_attribute(LDAP, entry, ber);
    };
    ber_free(ber, 0);

    ldap_msgfree(res);
    ldap_unbind_ext_s(LDAP, NULL, NULL);

    if (read) {
        pam_syslog(pamh, LOG_NOTICE, "Quotas (FileSystem:BlocksSoft,BlocksHard,InodesSoft,InodesHard)\n"
                                     "(%s,%lu,%lu,%lu,%lu)",
                   ldapquota.fs, ldapquota.quotaBsoftlimit, ldapquota.quotaBhardlimit, ldapquota.quotaIsoftlimit,
                   ldapquota.quotaIhardlimit);
        return configure(pamh, &ldapquota, pwd->pw_uid);
    } else {
        pam_syslog(pamh, LOG_NOTICE, "Quotas Not Found!");
    }
    return PAM_SESSION_ERR;
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                         const char **argv) {
    return PAM_SUCCESS;
}