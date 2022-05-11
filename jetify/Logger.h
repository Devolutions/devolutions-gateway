#include "Jetify.h"

#ifndef JETIFY_LOGGER_H
#define JETIFY_LOGGER_H

#ifdef __cplusplus
extern "C" {
#endif

#define JETIFY_LOG_TRACE   0
#define JETIFY_LOG_DEBUG   1
#define JETIFY_LOG_INFO    2
#define JETIFY_LOG_WARN    3
#define JETIFY_LOG_ERROR   4
#define JETIFY_LOG_FATAL   5
#define JETIFY_LOG_OFF     6

bool Jetify_IsLogLevelActive(uint32_t logLevel);

#define Jetify_LogPrint(_log_level, ...)                                               \
	do                                                                                 \
	{                                                                                  \
		if (Jetify_IsLogLevelActive(JETIFY_LOG_ ## _log_level))                        \
		{                                                                              \
			Jetify_Log(__VA_ARGS__);                                                   \
		}                                                                              \
	} while (0)

#define Jetify_LogDump(_log_level, ...)                                                \
	do                                                                                 \
	{                                                                                  \
		if (Jetify_IsLogLevelActive(JETIFY_LOG_ ## _log_level))                        \
		{                                                                              \
			Jetify_LogHexDump(__VA_ARGS__);                                            \
		}                                                                              \
	} while (0)

bool Jetify_Log(const char* format, ...);
void Jetify_LogHexDump(const uint8_t* data, size_t size);

void Jetify_LogOpen();
void Jetify_LogClose();
void Jetify_SetLogEnabled(bool logEnabled);
void Jetify_SetLogLevel(uint32_t logLevel);
void Jetify_SetLogFilePath(const char* logFilePath);

#ifdef __cplusplus
}
#endif

#endif /* JETIFY_LOGGER_H */
