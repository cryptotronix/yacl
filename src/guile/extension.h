/* -*- mode: c; c-file-style: "gnu" -*- */
#ifndef YACL_GUILE_EXT_H_
#define YACL_GUILE_EXT_H_

#include "../../yacl.h"
#include <libguile.h>

YACL_EXPORT
SCM
yacl_scm_sha256 (SCM bv);

/* --- ECC Functions --- */
YACL_EXPORT
SCM
yacl_scm_gen_p256_key_pair (void);

YACL_EXPORT
SCM
yacl_scm_p256_sign(SCM data, SCM d);

YACL_EXPORT
SCM
yacl_scm_p256_verify(SCM data, SCM q, SCM sig);

YACL_EXPORT
SCM
yacl_scm_get_random (SCM len);

YACL_EXPORT
SCM
yacl_scm_hexdump (SCM bv);

YACL_EXPORT
SCM
yacl_scm_hkdf_sha256 (SCM ikm, SCM salt, SCM info);

YACL_EXPORT
SCM
yacl_scm_b64url_encode (SCM bv);

YACL_EXPORT
SCM
yacl_scm_b64url_decode (SCM scmb64);

YACL_EXPORT
void
yacl_init_guile (void);

#endif
