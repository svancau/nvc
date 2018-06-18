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
#include <memory.h>
#include <stdlib.h>
#include <assert.h>

#ifndef __MINGW32__
#include <sys/mman.h>
#endif

typedef struct {
   int         name;
   vcode_reg_t usage;
   bool        callee_save;
   int         arg_index;
   const char *text;
} jit_reg_t;

typedef struct {
   void       *code_base;
   uint8_t    *code_wptr;
   size_t      code_len;
   jit_reg_t **reg_map;
} jit_state_t;

#define __IMM32(x) (x) & 0xff, ((x) >> 8) & 0xff,      \
      ((x) >> 16) & 0xff, ((x) >> 24) & 0xff

#define __EAX 0
#define __ECX 1
#define __EDX 2
#define __EBX 3
#define __ESP 4
#define __EBP 5
#define __ESI 6
#define __EDI 7

#define __(...) jit_emit(state, __VA_ARGS__, -1)

#define __MODRM(m, r, rm) (((m & 3) << 6) | (((r) & 7) << 3) | (rm & 7))

#define __RET() __(0xc3)
#define __MOVI(r, i) __(0xb8 + r, __IMM32(i))
#define __MOVR(r1, r2) if (r1 != r2) __(0x89, __MODRM(3, r2, r1))
#define __ADDI8(r, i) __(0x83, __MODRM(3, 0, r), i)
#define __ADDI32(r, i) __(0x81, __MODRM(3, 0, r), __IMM32(i))

#define TRACE(...) _jit_trace(__FUNCTION__, __VA_ARGS__)

static jit_reg_t x86_64_regs[] = {
   {
      .name = __EDI,
      .text = "EDI",
      .callee_save = false,
      .arg_index = 0
   },
   {
      .name = __ESI,
      .text = "ESI",
      .callee_save = false,
      .arg_index = 1
   },
   {
      .name = __EDX,
      .text = "EDX",
      .callee_save = false,
      .arg_index = 2
   },
   {
      .name = __ECX,
      .text = "ECX",
      .callee_save = false,
      .arg_index = 3
   },
   {
      .name = __EAX,
      .text = "EAX",
      .callee_save = false,
      .arg_index = -1
   },
   {
      .name = __EBX,
      .text = "EBX",
      .callee_save = true,
      .arg_index = -1
   },
};

static void _jit_trace(const char *function, const char *fmt, ...)
{
   va_list ap;
   va_start(ap, fmt);
   char *buf = xvasprintf(fmt, ap);
   va_end(ap);

   printf("[%s] %s\n", function, buf);
}

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

static jit_reg_t *jit_get_reg(jit_state_t *state, vcode_reg_t reg)
{
   assert(reg != VCODE_INVALID_REG);
   assert(state->reg_map[reg] != NULL);
   assert(state->reg_map[reg]->usage == reg);
   return state->reg_map[reg];
}

static jit_reg_t *jit_alloc_reg(jit_state_t *state, vcode_reg_t usage)
{
   for (int i = 0; i < ARRAY_LEN(x86_64_regs); i++) {
      jit_reg_t *r = &(x86_64_regs[i]);
      if (r->usage == usage)
         return r;
      else if (r->usage == VCODE_INVALID_REG) {
         r->usage = usage;
         state->reg_map[usage] = r;
         TRACE("vcode reg %d -> %s", usage, r->text);
         return r;
      }
   }

   fatal_trace("JIT no more free registers");
}

static void jit_op_const(jit_state_t *state, int op)
{
   jit_reg_t *reg = jit_alloc_reg(state, vcode_get_result(op));
   reg->usage = vcode_get_result(op);
   __MOVI(reg->name, vcode_get_value(op));
}

static void jit_op_ret(jit_state_t *state, int op)
{
   if (vcode_count_args(op) > 0) {
      jit_reg_t *result = jit_get_reg(state, vcode_get_arg(op, 0));
      __MOVR(__EAX, result->name);
   }

   __RET();
}

static void jit_op_addi(jit_state_t *state, int op)
{
   jit_reg_t *p0 = jit_get_reg(state, vcode_get_arg(op, 0));
   jit_reg_t *result = jit_alloc_reg(state, vcode_get_result(op));
   const int64_t value = vcode_get_value(op);

   __MOVR(result->name, p0->name);

   if (value >= -128 && value <= 127)
      __ADDI8(result->name, value);
   else
      __ADDI32(result->name, value);
}

static void jit_op(jit_state_t *state, int op)
{
   switch (vcode_get_op(op)) {
   case VCODE_OP_CONST:
      jit_op_const(state, op);
      break;
   case VCODE_OP_RETURN:
      jit_op_ret(state, op);
      break;
   case VCODE_OP_ADDI:
      jit_op_addi(state, op);
      break;
   default:
      vcode_dump_with_mark(op);
      fatal("cannot JIT code op %s", vcode_op_string(vcode_get_op(op)));
   }
}

void *jit_vcode_unit(vcode_unit_t unit)
{
   vcode_select_unit(unit);

   jit_state_t state = {};
   jit_alloc_code(&state, 4096);

   const int nregs = vcode_count_regs();
   state.reg_map = xmalloc(nregs * sizeof(jit_reg_t *));
   for (int i = 0; i < nregs; i++)
      state.reg_map[i] = NULL;

   for (int i = 0; i < ARRAY_LEN(x86_64_regs); i++)
      x86_64_regs[i].usage = VCODE_INVALID_REG;

   if (vcode_unit_kind() == VCODE_UNIT_FUNCTION) {
      const int nparams = vcode_count_params();
      for (int i = 0; i < nparams; i++) {
         bool have_reg = false;
         for (int j = 0; j < ARRAY_LEN(x86_64_regs); j++) {
            if (x86_64_regs[j].arg_index == i) {
               state.reg_map[i] = &(x86_64_regs[j]);
               x86_64_regs[j].usage = i;
               have_reg = true;
               break;
            }
         }

         if (!have_reg)
            fatal("cannot find register for parameter %d", i);
      }
   }

   vcode_select_block(0);

   const int nops = vcode_count_ops();
   for (int i = 0; i < nops; i++)
      jit_op(&state, i);

   jit_dump(&state);


   free(state.reg_map);
   return state.code_base;
}
