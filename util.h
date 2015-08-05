#ifndef __UTIL_H
#define __UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/elf.h>
#include <linux/types.h>
#include <assert.h>

#define	ALIGN	8

inline void debug_print(const char *str);
inline __u32 __align(__u32 size);

#endif	//util.h
