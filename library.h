#ifndef PAM_LDAPSETQUOTA_LIBRARY_H
#define PAM_LDAPSETQUOTA_LIBRARY_H

#define PAM_SM_SESSION

#include <security/pam_modules.h>
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv);

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv);
#endif