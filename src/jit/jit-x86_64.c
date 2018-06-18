//
//  Copyright (C) 2018  Nick Gasson
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

#include "jit.h"

#include <stdarg.h>
#include <udis86.h>
#include <string.h>
#include <inttypes.h>

#ifndef __MINGW32__
#include <sys/mman.h>
#endif

typedef struct {
   void    *code_base;
   uint8_t *code_wptr;
   size_t   code_len;
} jit_state_t;

static void jit_alloc_code(jit_state_t *state, size_t size)
{
   state->code_base = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_SHARED | MAP_ANON, -1, 0);
   if (state->code_base == MAP_FAILED)
      fatal_errno("mmap");

   state->code_wptr = state->code_base;
   state->code_len  = size;
}

static void jit_emit(jit_state_t *state, ...)
{
   va_list ap;
   va_start(ap, state);

   int op;
   while ((op = va_arg(ap, int)) != -1) {
      if (state->code_wptr == state->code_base + state->code_len)
         fatal_trace("JIT code buffer too small %d", (int)state->code_len);
      *(state->code_wptr++) = op;
   }

   va_end(ap);
}

#define __IMM32(x) (x) & 0xff, ((x) >> 8) & 0xff,      \
      ((x) >> 16) & 0xff, ((x) >> 24) & 0xff

#define __EAX 0
#define __EBX 3
#define __ECX 1
#define __EDX 2

#define __RET() jit_emit(&state, 0xc3, -1)
#define __MOVI(i, r) jit_emit(&state, 0xb8 + r, __IMM32(i), -1)

static void jit_dump(jit_state_t *state)
{
   ud_t u;
   ud_init(&u);
   ud_set_input_file(&u, stdin);
   ud_set_input_buffer(&u, state->code_base,
                       state->code_wptr - (uint8_t *)state->code_base);
   ud_set_mode(&u, 64);
   ud_set_syntax(&u, UD_SYN_INTEL);

   while (ud_disassemble(&u)) {
      const char *hex1 = ud_insn_hex(&u);
      const char *hex2 = hex1 + 16;
      printf("%-12" PRIx64 " ",
             (uintptr_t)state->code_base + ud_insn_off(&u));
      printf("%-16.16s %-24s", hex1, ud_insn_asm(&u));
      if (strlen(hex1) > 16) {
         printf("\n");
         printf("%15s -", "");
         printf("%-16s", hex2);
      }
      printf("\n");
   }
}

void *jit_vcode_unit(vcode_unit_t unit)
{
   jit_state_t state = {};
   jit_alloc_code(&state, 4096);

   __MOVI(0x2a, __EAX);
   __RET();

   jit_dump(&state);

   return state.code_base;
}
