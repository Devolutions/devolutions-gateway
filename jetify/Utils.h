#include "Jetify.h"

#ifndef JETIFY_UTILS_H
#define JETIFY_UTILS_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

// Unicode conversion

int Jetify_ConvertFromUnicode(UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar,
    LPSTR* lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar, LPBOOL lpUsedDefaultChar);

int Jetify_ConvertToUnicode(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte,
    LPWSTR* lpWideCharStr, int cchWideChar);

// String handling

bool Jetify_StringEquals(const char* str1, const char* str2);
bool Jetify_StringIEquals(const char* str1, const char* str2);
bool Jetify_StringEndsWith(const char* str, const char* val);
bool Jetify_IStringEndsWith(const char* str, const char* val);

// File handling

const char* Jetify_FileBase(const char* filename);

// Environment variables

bool Jetify_SetEnv(const char* name, const char* value);
char* Jetify_GetEnv(const char* name);
bool Jetify_EnvExists(const char* name);
bool Jetify_GetEnvBool(const char* name, bool defaultValue);
int Jetify_GetEnvInt(const char* name, int defaultValue);

#ifdef __cplusplus
}
#endif

#endif /* JETIFY_UTILS_H */
