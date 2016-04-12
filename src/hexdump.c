/* -*- mode: c; c-file-style: "gnu" -*- */
#include "config.h"
#include "../yacl.h"
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <assert.h>
#ifdef HAVE_LIBGLIB
#include <glib.h>
#endif

#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#pragma GCC diagnostic push
#endif
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Winitializer-overrides"
#pragma GCC diagnostic ignored "-Woverride-init"
#pragma GCC diagnostic ignored "-Wcast-qual"


#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 8
#endif

void
yacl_hexdump(const uint8_t const *mem, size_t len)
{
  unsigned int i, j;

  if (NULL == mem)
    {
#ifdef HAVE_LIBGLIB
      g_error ("ERROR, NULL in hexdump");
#else
      assert (mem);
#endif
    }


  for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
    {
      /* print offset */
      if(i % HEXDUMP_COLS == 0)
        {
          printf("0x%06x: ", i);
        }

      /* print hex data */
      if(i < len)
        {
          printf("%02x ", 0xFF & ((char*)mem)[i]);
        }
      else /* end of block, just aligning for ASCII dump */
        {
          printf("   ");
        }

      /* print ASCII dump */
      if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
        {
          for(j = i - (HEXDUMP_COLS - 1); j <= i; j++)
            {
              if(j >= len) /* end of block, not really printing */
                {
                  assert ((int)' ' == putchar(' '));
                }
              else if(isprint(((char*)mem)[j])) /* printable char */
                {
                  unsigned char to_put = 0xFF & ((char*)mem)[j];
                  assert ((int) to_put == putchar(to_put));
                }
              else /* other char */
                {
                  assert ((int)'.' == putchar('.'));
                }
            }
          assert ((int)'\n' == putchar('\n'));
        }
    }
}

#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#pragma GCC diagnostic pop
#endif
