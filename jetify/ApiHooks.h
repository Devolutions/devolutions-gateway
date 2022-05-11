#include "Jetify.h"

#ifndef JETIFY_API_HOOKS_H
#define JETIFY_API_HOOKS_H

#ifdef __cplusplus
extern "C" {
#endif

uint32_t Jetify_AttachHooks();
uint32_t Jetify_DetachHooks();

#ifdef __cplusplus
}
#endif

#endif /* JETIFY_API_HOOKS_H */
