/* -*- mode: c; c-file-style: "gnu" -*- */
#ifndef YACL_GUILE_EXT_H_
#define YACL_GUILE_EXT_H_

#include "../../yacl.h"
#include <libguile.h>

YACL_EXPORT
SCM
yacl_scm_sha256 (SCM bv);

YACL_EXPORT
void
yacl_init_guile (void);

#endif
