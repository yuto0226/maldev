#pragma once
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include "color.h"

// log levels
#define LOG_LEVEL_NONE   0
#define LOG_LEVEL_ERROR  1
#define LOG_LEVEL_WARN   2
#define LOG_LEVEL_INFO   3
#define LOG_LEVEL_DEBUG  4

#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_LEVEL_INFO
#endif

// log macros
#define LOG(_stream, _clr, _tag, fmt, ...) \
    fprintf((_stream), "%s%s%s " fmt "\n", (_clr), (_tag), ANSI_RESET, ##__VA_ARGS__)

#define panic(fmt, ...) \
    do { \
        fprintf(stderr, ANSI_RED "[x] [%s] " fmt " (errno=%d: %s) %s:%d\n" ANSI_RESET, \
                __func__, ##__VA_ARGS__, errno, strerror(errno), __FILE__, __LINE__); \
        exit(EXIT_FAILURE); \
    } while (0)

#if LOG_LEVEL >= LOG_LEVEL_ERROR
#define error(fmt, ...) LOG(stderr, ANSI_RED, "[-]", fmt, ##__VA_ARGS__)
#else
#define error(fmt, ...) ((void)0)
#endif

#if LOG_LEVEL >= LOG_LEVEL_WARN
#define warn(fmt, ...)  LOG(stderr, ANSI_YELLOW, "[!]", fmt, ##__VA_ARGS__)
#else
#define warn(fmt, ...) ((void)0)
#endif

#if LOG_LEVEL >= LOG_LEVEL_INFO
#define info(fmt, ...)  LOG(stdout, ANSI_BLUE, "[i]", fmt, ##__VA_ARGS__)
#define ok(fmt, ...)    LOG(stdout, ANSI_GREEN, "[+]", fmt, ##__VA_ARGS__)
#else
#define info(fmt, ...) ((void)0)
#define ok(fmd, ...) ((void)0)
#endif

#if LOG_LEVEL >= LOG_LEVEL_DEBUG
#define debug(fmt, ...) LOG(stdout, ANSI_CYAN, "[d]", fmt, ##__VA_ARGS__)
#else
#define debug(fmt, ...) ((void)0)
#endif

#ifdef __cplusplus
extern "C" {
#endif
    void hexdump(const void* buf, size_t size);
#ifdef __cplusplus
}
#endif