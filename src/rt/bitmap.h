//
//  Copyright (C) 2017  Nick Gasson
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

#ifndef _RT_BITMAP_H
#define _RT_BITMAP_H

#include "util.h"

#include <stdlib.h>
#include <string.h>

#define BITMAP_WORDS(s) (((s) + 63) >> 6)

typedef struct {
   size_t   size;
   uint64_t data[0];
} bitmap_t;

static inline bitmap_t *bitmap_new(size_t size)
{
   bitmap_t *b = xcalloc(sizeof(bitmap_t) + 8 * BITMAP_WORDS(size));
   b->size = size;
   return b;
}

static inline void bitmap_free(bitmap_t *b)
{
   free(b);
}

static inline void bitmap_zero(bitmap_t *b)
{
   const size_t nwords = BITMAP_WORDS(b->size);
   if (nwords == 1)
      b->data[0] = 0;
   else
      memset(b->data, '\0', 8 * nwords);
}

static inline void bitmap_set(bitmap_t *b, unsigned bit)
{
   b->data[bit >> 6] |= UINT64_C(1) << (bit & 63);
}

static inline void bitmap_clear(bitmap_t *b, unsigned bit)
{
   b->data[bit >> 6] &= ~(UINT64_C(1) << (bit & 63));
}

static inline bool bitmap_isset(const bitmap_t *b, unsigned bit)
{
   return !!(b->data[bit >> 6] & (UINT64_C(1) << (bit & 63)));
}

static inline void bitmap_or(bitmap_t *dst, const bitmap_t *src)
{
   for (size_t i = 0; i < BITMAP_WORDS(dst->size); i++)
      dst->data[i] |= src->data[i];
}

static inline void bitmap_move(bitmap_t *dst, bitmap_t *src)
{
   for (size_t i = 0; i < BITMAP_WORDS(dst->size); i++) {
      dst->data[i] |= src->data[i];
      src->data[i] = 0;
   };
}

static inline int bitmap_next_set(const bitmap_t *b, unsigned from)
{
   while (from < b->size) {
      const int word = from >> 6;
      const int bit = from & 63;
      const uint64_t masked = b->data[word] & ~((UINT64_C(1) << bit) - 1);

      if (masked != 0) {
         const int ctz = __builtin_ctzll(masked);
         return (from & ~63) + ctz;
      }

      from = (from + 64) & ~63;
   }

   return -1;
}

#endif  // _RT_BITMAP_H
