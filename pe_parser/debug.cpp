#include <stdio.h>

#include "color.h"
#include "debug.h"

void hexdump(const void *buf, size_t size)
{
    const unsigned char *p = static_cast<const unsigned char *>(buf);
    for (size_t off = 0; off < size; off += 16) {
        printf(ANSI_RED "%08zx  " ANSI_RESET, off);

        for (size_t i = 0; i < 16; ++i) {
            if (off + i < size) {
                if (!isprint(p[off + i]))
                    printf(ANSI_GRAY);
                else
                    printf(ANSI_BOLD);
                printf("%02x " ANSI_RESET, p[off + i]);
            } else
                printf("   ");

            if (i == 7)
                putchar(' ');
        }

        putchar(' ');
        putchar('|');

        for (size_t i = 0; i < 16 && off + i < size; ++i) {
            unsigned char c = p[off + i];
            if (!isprint(p[off + i]))
                printf(ANSI_GRAY);
            else
                printf(ANSI_BOLD);
            printf("%c" ANSI_RESET, (c >= 0x20 && c <= 0x7e) ? c : '.');
        }
        putchar('|');
        putchar('\n');
    }
}
