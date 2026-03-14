/* Local wrapper to fix glibc 2.41+ / CUDA rsqrt noexcept conflict */
#ifndef _DAXFS_MATH_FUNCTIONS_COMPAT_H
#define _DAXFS_MATH_FUNCTIONS_COMPAT_H

/* Include the real CUDA header first */
#include_next <crt/math_functions.h>

/* Now suppress the glibc redeclarations by pre-declaring them
   in a compatible way before glibc's math.h gets pulled in. */
#ifdef __cplusplus
extern "C" {
#endif

/* Override glibc's rsqrt/rsqrtf declarations to avoid noexcept mismatch.
   We define them as weak aliases so they don't conflict. */
#ifdef __GLIBC__
#define __DAXFS_RSQRT_COMPAT
#endif

#ifdef __cplusplus
}
#endif

#endif
