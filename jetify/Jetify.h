
#ifndef JETIFY_API_H
#define JETIFY_API_H

#ifdef _WIN32
#include <windows.h>
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#ifndef WCHAR
#define WCHAR uint16_t
#endif

#ifndef BOOL
#define BOOL unsigned char
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define JETIFY_MAX_PATH 1024

#ifdef _WIN32
#define JETIFY_API __stdcall
#else
#define JETIFY_API 
#endif

#ifdef _WIN32
#define JETIFY_EXPORT __declspec(dllexport)
#else
#define JETIFY_EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

JETIFY_EXPORT bool Jetify_Init();
JETIFY_EXPORT void Jetify_Uninit();

#ifdef __cplusplus
}
#endif

#endif /* JETIFY_API_H */
