// A very simple logger.

#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define LOG_TIME                                                                                   \
    do {                                                                                           \
        static char buf[26];                                                                       \
        time_t now = time(NULL);                                                                   \
        struct tm* s_tm = localtime(&now);                                                         \
        strftime(buf, sizeof buf, "%F %T %z", s_tm);                                               \
        fprintf(stderr, "%s ", buf);                                                               \
    } while (0);

#define LOG_EXIT(format, ...)                                                                      \
    do {                                                                                           \
        LOG_TIME                                                                                   \
        fprintf(stderr, "[EXIT] file %s:%d: ", __FILE__, __LINE__);                                \
        fprintf(stderr, format, ##__VA_ARGS__);                                                    \
        fprintf(stderr, "\n");                                                                     \
        exit(EXIT_FAILURE);                                                                        \
    } while (0)

#define LOG_WARN(format, ...)                                                                      \
    do {                                                                                           \
        LOG_TIME                                                                                   \
        fprintf(stderr, "[WARN] file %s:%d: ", __FILE__, __LINE__);                                \
        fprintf(stderr, format, ##__VA_ARGS__);                                                    \
        fprintf(stderr, "\n");                                                                     \
    } while (0)

#define LOG_MSG(format, ...)                                                                       \
    do {                                                                                           \
        LOG_TIME                                                                                   \
        fprintf(stderr, "[MSG] file %s:%d: ", __FILE__, __LINE__);                                 \
        fprintf(stderr, format, ##__VA_ARGS__);                                                    \
        fprintf(stderr, "\n");                                                                     \
    } while (0)

#endif
