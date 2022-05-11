
#include "Logger.h"

#include "Utils.h"

#include <stdio.h>
#include <stdlib.h>

static bool g_LogInitialized = false;

static FILE* g_LogFile = NULL;
static bool g_LogEnabled = false;
static char g_LogFilePath[JETIFY_MAX_PATH] = { 0 };

static uint32_t g_LogLevel = JETIFY_LOG_DEBUG;

#define JETIFY_LOG_MAX_LINE    8192

bool Jetify_IsLogLevelActive(uint32_t logLevel)
{
    if (!g_LogEnabled)
        return false;

    if (g_LogLevel == JETIFY_LOG_OFF)
        return false;

    return logLevel >= g_LogLevel;
}

bool Jetify_LogVA(const char* format, va_list args)
{
    if (!g_LogFile)
        return true;

    char message[JETIFY_LOG_MAX_LINE];
    vsnprintf_s(message, JETIFY_LOG_MAX_LINE - 1, _TRUNCATE, format, args);
    strcat_s(message, JETIFY_LOG_MAX_LINE - 1, "\n");

    if (g_LogFile) {
        fprintf(g_LogFile, message);
        fflush(g_LogFile); // WARNING: performance drag
    }

    return true;
}

bool Jetify_Log(const char* format, ...)
{
	bool status;
	va_list args;
	va_start(args, format);
	status = Jetify_LogVA(format, args);
	va_end(args);
	return status;
}

void Jetify_LogHexDump(const uint8_t* data, size_t size)
{
    int i, ln, hn;
	const uint8_t* p = data;
    size_t width = 16;
    size_t offset = 0;
    size_t chunk = 0;
    char line[512];
    char* bin2hex = "0123456789ABCDEF";

    while (offset < size) {
        chunk = size - offset;

        if (chunk >= width)
            chunk = width;

        for (i = 0; i < chunk; i++)
        {
            ln = p[i] & 0xF;
            hn = (p[i] >> 4) & 0xF;

            line[i * 2] = bin2hex[hn];
            line[(i * 2) + 1] = bin2hex[ln];
        }

        line[chunk * 2] = ' ';

        for (i = (int) chunk; i < width; i++) {
            line[i * 2] = ' ';
            line[(i * 2) + 1] = ' ';
        }

        char* side = &line[(width * 2) + 1];

        for (i = 0; i < chunk; i++)
        {
            char c = ((p[i] >= 0x20) && (p[i] < 0x7F)) ? p[i] : '.';
            side[i] = c;
        }
        side[i] = '\n';
        side[i+1] = '\0';

        if (g_LogFile) {
            fwrite(line, 1, strlen(line), g_LogFile);
        }

        offset += chunk;
        p += chunk;
    }
}

void Jetify_LogEnvInit()
{
    char* envvar;

    if (g_LogInitialized)
        return;

    envvar = Jetify_GetEnv("JETIFY_LOG_LEVEL");

    if (envvar) {
        int ival = atoi(envvar);

        if ((ival >= 0) && (ival <= 6)) {
            Jetify_SetLogLevel((uint32_t) ival);
        }
        else {
            if (!strcmp(envvar, "TRACE")) {
                Jetify_SetLogLevel(JETIFY_LOG_TRACE);
            }
            else if (!strcmp(envvar, "DEBUG")) {
                Jetify_SetLogLevel(JETIFY_LOG_DEBUG);
            }
            else if (!strcmp(envvar, "INFO")) {
                Jetify_SetLogLevel(JETIFY_LOG_INFO);
            }
            else if (!strcmp(envvar, "WARN")) {
                Jetify_SetLogLevel(JETIFY_LOG_WARN);
            }
            else if (!strcmp(envvar, "ERROR")) {
                Jetify_SetLogLevel(JETIFY_LOG_ERROR);
            }
            else if (!strcmp(envvar, "FATAL")) {
                Jetify_SetLogLevel(JETIFY_LOG_FATAL);
            }
            else if (!strcmp(envvar, "OFF")) {
                Jetify_SetLogLevel(JETIFY_LOG_OFF);
            }
        }

        if (g_LogLevel != JETIFY_LOG_OFF) {
            g_LogEnabled = true;
        }
    }

    free(envvar);

    envvar = Jetify_GetEnv("JETIFY_LOG_FILE_PATH");

    if (envvar) {
        Jetify_SetLogFilePath(envvar);
    }

    free(envvar);

    g_LogInitialized = true;
}

void Jetify_LogOpen()
{
    Jetify_LogEnvInit();

    if (!g_LogEnabled)
        return;

    if (g_LogFilePath[0] == '\0') {
        ExpandEnvironmentStringsA("%TEMP%\\Jetify.log", g_LogFilePath, JETIFY_MAX_PATH);
    }

    g_LogFile = fopen(g_LogFilePath, "wb");
}

void Jetify_LogClose()
{
    if (g_LogFile) {
        fclose(g_LogFile);
        g_LogFile = NULL;
    }
}

void Jetify_SetLogEnabled(bool logEnabled)
{
    g_LogEnabled = logEnabled;
}

void Jetify_SetLogLevel(uint32_t logLevel)
{
    g_LogLevel = logLevel;
}

void Jetify_SetLogFilePath(const char* logFilePath)
{
    strcpy_s(g_LogFilePath, JETIFY_MAX_PATH, logFilePath);
}
