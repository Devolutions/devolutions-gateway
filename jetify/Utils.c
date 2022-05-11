
#include "Utils.h"

#ifdef _WIN32
#include <UserEnv.h>
#endif

// Unicode conversion

int Jetify_ConvertFromUnicode(UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar,
    LPSTR* lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar, LPBOOL lpUsedDefaultChar)
{
    int status;
    BOOL allocate = FALSE;

    if (!lpWideCharStr)
        return 0;

    if (!lpMultiByteStr)
        return 0;

    if (cchWideChar == -1)
        cchWideChar = (int)(wcslen(lpWideCharStr) + 1);

    if (cbMultiByte == 0)
    {
        cbMultiByte =
            WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, NULL, 0, NULL, NULL);
        allocate = TRUE;
    }
    else if (!(*lpMultiByteStr))
        allocate = TRUE;

    if (cbMultiByte < 1)
        return 0;

    if (allocate)
    {
        *lpMultiByteStr = (LPSTR)calloc(1, cbMultiByte + 1);

        if (!(*lpMultiByteStr))
        {
            return 0;
        }
    }

    status = WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, *lpMultiByteStr,
        cbMultiByte, lpDefaultChar, lpUsedDefaultChar);

    if ((status != cbMultiByte) && allocate)
    {
        status = 0;
    }

    if ((status <= 0) && allocate)
    {
        free(*lpMultiByteStr);
        *lpMultiByteStr = NULL;
    }

    return status;
}

int Jetify_ConvertToUnicode(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte,
    LPWSTR* lpWideCharStr, int cchWideChar)
{
    int status;
    BOOL allocate = FALSE;

    if (!lpMultiByteStr)
        return 0;

    if (!lpWideCharStr)
        return 0;

    if (cbMultiByte == -1)
    {
        size_t len = strnlen(lpMultiByteStr, INT_MAX);
        if (len >= INT_MAX)
            return 0;
        cbMultiByte = (int)(len + 1);
    }

    if (cchWideChar == 0)
    {
        cchWideChar = MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, NULL, 0);
        allocate = TRUE;
    }
    else if (!(*lpWideCharStr))
        allocate = TRUE;

    if (cchWideChar < 1)
        return 0;

    if (allocate)
    {
        *lpWideCharStr = (LPWSTR)calloc(cchWideChar + 1, sizeof(WCHAR));

        if (!(*lpWideCharStr))
        {
            return 0;
        }
    }

    status = MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, *lpWideCharStr, cchWideChar);

    if (status != cchWideChar)
    {
        if (allocate)
        {
            free(*lpWideCharStr);
            *lpWideCharStr = NULL;
            status = 0;
        }
    }

    return status;
}

// String handling

bool Jetify_StringEquals(const char* str1, const char* str2)
{
    return strcmp(str1, str2) == 0;
}

bool Jetify_StringIEquals(const char* str1, const char* str2)
{
    return _stricmp(str1, str2) == 0;
}

bool Jetify_StringEndsWith(const char* str, const char* val)
{
    size_t strLen;
    size_t valLen;
    const char* p;

    if (!str || !val)
        return false;

    strLen = strlen(str);
    valLen = strlen(val);

    if ((strLen < 1) || (valLen < 1))
        return false;

    if (valLen > strLen)
        return false;

    p = &str[strLen - valLen];

    if (!strcmp(p, val))
        return true;

    return false;
}

bool Jetify_IStringEndsWith(const char* str, const char* val)
{
    int strLen;
    int valLen;
    const char* p;

    if (!str || !val)
        return false;

    strLen = (int) strlen(str);
    valLen = (int) strlen(val);

    if ((strLen < 1) || (valLen < 1))
        return false;

    if (valLen > strLen)
        return false;

    p = &str[strLen - valLen];

    if (!_stricmp(p, val))
        return true;

    return false;
}

// file handling

const char* Jetify_FileBase(const char* filename)
{
    size_t length;
    char* separator;

    if (!filename)
        return NULL;

    separator = strrchr(filename, '\\');

    if (!separator)
        separator = strrchr(filename, '/');

    if (!separator)
        return filename;

    length = strlen(filename);

    if ((length - (separator - filename)) > 1)
        return separator + 1;

    return filename;
}

// Environment variables

bool Jetify_SetEnv(const char* name, const char* value)
{
    return SetEnvironmentVariableA(name, value) ? true : false;
}

char* Jetify_GetEnv(const char* name)
{
    uint32_t size;
    char* env = NULL;

    size = GetEnvironmentVariableA(name, NULL, 0);

    if (!size)
        return NULL;

    env = (char*)malloc(size);

    if (!env)
        return NULL;

    if (GetEnvironmentVariableA(name, env, size) != size - 1)
    {
        free(env);
        return NULL;
    }

    return env;
}

bool Jetify_EnvExists(const char* name)
{
    if (!name)
        return false;

    return GetEnvironmentVariableA(name, NULL, 0) ? true : false;
}

bool Jetify_GetEnvBool(const char* name, bool defaultValue)
{
    char* env;
    bool value = defaultValue;

    env = Jetify_GetEnv(name);

    if (!env)
        return value;

    if ((strcmp(env, "1") == 0) || (_stricmp(env, "TRUE") == 0))
        value = true;
    else if ((strcmp(env, "0") == 0) || (_stricmp(env, "FALSE") == 0))
        value = false;

    free(env);

    return value;
}

int Jetify_GetEnvInt(const char* name, int defaultValue)
{
    char* env;
    int value = defaultValue;

    env = Jetify_GetEnv(name);

    if (!env)
        return value;

    value = atoi(env);

    free(env);

    return value;
}
