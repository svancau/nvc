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
#include "hash.h"

#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <memory.h>
#include <stdlib.h>
#include <assert.h>

#ifndef __MINGW32__
#include <sys/mman.h>
#endif

#if defined(HAVE_UCONTEXT_H)
#include <ucontext.h>
#elif defined(HAVE_SYS_UCONTEXT_H)
#include <sys/ucontext.h>
#endif

#ifdef HAVE_CAPSTONE
#include <capstone/capstone.h>
#endif

typedef enum {
   REG_F_CALLEE_SAVE = (1 << 0),
   REG_F_RESULT      = (1 << 1),
} jit_reg_flags_t;

typedef struct {
   int             name;
   vcode_reg_t     usage;
   jit_reg_flags_t flags;
   int             arg_index;
   const char     *text;
} jit_mach_reg_t;

typedef enum {
   JIT_UNDEFINED,
   JIT_CONST,
   JIT_STACK,
   JIT_REGISTER,
} jit_vcode_reg_state_t;

typedef enum {
   JIT_F_RETURNED    = (1 << 0),
   JIT_F_BLOCK_LOCAL = (1 << 1),
   JIT_F_PARAMETER   = (1 << 2),
} jit_vcode_reg_flags_t;

typedef struct {
   jit_vcode_reg_state_t state;
   jit_vcode_reg_flags_t flags;
   int                   lifetime;
   union {
      int64_t  value;
      unsigned stack_offset;
      unsigned reg_name;
   };
} jit_vcode_reg_t;

typedef struct {
   uint8_t      *code_wptr;
   unsigned      offset;
   vcode_block_t target;
} jit_patch_t;

typedef struct {
   void            *code_base;
   uint8_t         *code_wptr;
   size_t           code_len;
   jit_vcode_reg_t *vcode_regs;
   uint8_t        **block_ptrs;
   jit_patch_t     *patches;
   size_t           patch_wptr;
   unsigned         stack_size;
   unsigned         stack_wptr;
   vcode_unit_t     unit;
} jit_state_t;

#define __IMM32(x) (x) & 0xff, ((x) >> 8) & 0xff,       \
      ((x) >> 16) & 0xff, ((x) >> 24) & 0xff

typedef enum {
   __EAX = 0, __ECX, __EDX, __EBX, __ESP, __EBP, __ESI, __EDI
} x86_reg_t;

typedef enum {
   __RAX = 0x10, __RCX, __RDX, __RBX, __RSP, __RBP, __RSI, __RDI
} x86_64_reg_t;

#define __(...) jit_emit(state, __VA_ARGS__, -1)

#define __MODRM(m, r, rm) (((m & 3) << 6) | (((r) & 7) << 3) | (rm & 7))

#define __RET() __(0xc3)
#define __MOVI8(r, i) __(0xb0 + (r & 7), i)
#define __MOVI32(r, i) __(0xb8 + (r & 7), __IMM32(i))
#define __MOVR(r1, r2) __(0x89, __MODRM(3, r2, r1))
#define __MOVQR(r1, r2) __(0x48, 0x89, __MODRM(3, r2, r1))
#define __MOVMR(r1, r2, d) __(0x8b, __MODRM(1, r1, r2), d)
#define __MOVRM(r1, d, r2) __(0x89, __MODRM(1, r2, r1), d)
#define __MOVI32M(r, d, i) __(0xc7, __MODRM(1, 0, r), d, __IMM32(i))
#define __ADDI8(r, i) __(0x83, __MODRM(3, 0, r), i)
#define __ADDI32(r, i) __(0x81, __MODRM(3, 0, r), __IMM32(i))
#define __SUBQRI32(r, i) __(0x48, 0x81, __MODRM(3, 5, r), __IMM32(i))
#define __SUBQRI8(r, i) __(0x48, 0x83, __MODRM(3, 5, r), i)
#define __PUSH(r) __(0x50 + (r & 7))
#define __POP(r) __(0x58 + (r & 7))
#define __JMPR32(d) __(0xe9, __IMM32(d))
#define __JMPR8(d) __(0xeb, d)

static jit_mach_reg_t x86_64_regs[] = {
   {
      .name = __EDI,
      .text = "EDI",
      .flags = 0,
      .arg_index = 0
   },
   {
      .name = __ESI,
      .text = "ESI",
      .flags = 0,
      .arg_index = 1
   },
   {
      .name = __EDX,
      .text = "EDX",
      .flags = 0,
      .arg_index = 2
   },
   {
      .name = __ECX,
      .text = "ECX",
      .flags = 0,
      .arg_index = 3
   },
   {
      .name = __EAX,
      .text = "EAX",
      .flags = REG_F_RESULT,
      .arg_index = -1
   },
   {
      .name = __EBX,
      .text = "EBX",
      .flags = REG_F_CALLEE_SAVE,
      .arg_index = -1
   },
};

static hash_t *jit_cache = NULL;

#ifdef HAVE_CAPSTONE
static csh capstone;
#endif

static void jit_dump(jit_state_t *state, int mark_op);

static void jit_alloc_code(jit_state_t *state, size_t size)
{
   state->code_base = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_SHARED | MAP_ANON, -1, 0);
   if (state->code_base == MAP_FAILED)
      fatal_errno("mmap");

   state->code_wptr = state->code_base;
   state->code_len  = size;
}

__attribute__((noreturn))
static void jit_abort(jit_state_t *state, int mark_op, const char *fmt, ...)
{
   va_list ap;
   va_start(ap, fmt);
   char *msg LOCAL = xvasprintf(fmt, ap);
   va_end(ap);

   jit_dump(state, mark_op);
   fatal_trace("%s", msg);
}

static void jit_emit(jit_state_t *state, ...)
{
   va_list ap;
   va_start(ap, state);

   int op;
   while ((op = va_arg(ap, int)) != -1) {
      if (state->code_wptr == state->code_base + state->code_len)
         jit_abort(state, -1, "JIT code buffer too small %d",
                   (int)state->code_len);
      *(state->code_wptr++) = op;
   }

   va_end(ap);
}

#ifdef HAVE_CAPSTONE
static void jit_dump_callback(int op, void *arg)
{
   jit_state_t *state = (jit_state_t *)arg;

   uint8_t *base = (uint8_t *)state->code_base;
   if (op > 0 || vcode_active_block() > 0)
      base = (uint8_t *)vcode_get_jit_addr(op);

   uint8_t *limit = state->code_wptr;
   if (op + 1 == vcode_count_ops()) {
      vcode_block_t old_block = vcode_active_block();
      if (old_block + 1 < vcode_count_blocks()) {
         vcode_select_block(old_block + 1);
         if (vcode_count_ops() > 0)
            limit = (uint8_t *)vcode_get_jit_addr(0);
         vcode_select_block(old_block);
      }
   }
   else
      limit = (uint8_t *)vcode_get_jit_addr(op + 1);

   if (base == NULL || limit == NULL || base == limit)
      return;

   assert(base >= (uint8_t*)state->code_base);
   assert(base <= limit);
   assert(limit >= base);
   assert(limit <= (uint8_t*)state->code_base + state->code_len);

   cs_insn *insn;
   size_t count = cs_disasm(capstone, base, limit - base,
                            (unsigned long)state->code_base, 0, &insn);
   if (count > 0) {
      size_t j;
      for (j = 0; j < count; j++) {
         char hex1[33], *p = hex1;
         for (size_t k = 0; insn[k].size; k++)
            p += checked_sprintf(p, hex1 + sizeof(hex1) - p, "%02x",
                                 insn[j].bytes[k]);

         color_printf("$bold$$blue$");
         printf("%-12" PRIx64 " ", insn[j].address);
         printf("%-16.16s %s %s", hex1, insn[j].mnemonic, insn[j].op_str);
         if (strlen(hex1) > 16) {
            printf("\n");
            printf("%15s -", "");
            printf("%-16s", hex1 + 16);
         }
         color_printf("$$\n");
      }

      cs_free(insn, count);
   }
   else
      fatal_trace("disassembly of %p failed", base);
}
#endif  // HAVE_CAPSTONE

static void jit_dump(jit_state_t *state, int mark_op)
{
#ifdef HAVE_CAPSTONE
   if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone) != CS_ERR_OK)
      fatal_trace("failed to init capstone");

   vcode_dump_with_mark(mark_op, jit_dump_callback, state);

   cs_close(&capstone);
#else
   vcode_dump_with_mark(mark_op, NULL, NULL);
#endif
}

static unsigned jit_align_object(size_t size, unsigned ptr)
{
   const size_t align = size - ptr % size;
   return align == size ? 0 : align;
}

static size_t jit_size_of(vcode_type_t type)
{
   switch (vtype_kind(type)) {
   case VCODE_TYPE_INT:
      {
         const int64_t range = vtype_high(type) - vtype_low(type);
         if (range <= UINT8_MAX)
            return 1;
         else if (range <= UINT16_MAX)
            return 2;
         else if (range <= UINT32_MAX)
            return 4;
         else
            return 8;
      }

   default:
      assert(false);
   }
}

static inline bool jit_is_int8(int64_t value)
{
   return value >= INT8_MIN && value <= INT8_MAX;
}

static jit_mach_reg_t *jit_alloc_reg(jit_state_t *state, int op,
                                     vcode_reg_t usage)
{
   int nposs = 0;
   jit_mach_reg_t *possible[ARRAY_LEN(x86_64_regs)];
   for (int i = 0; i < ARRAY_LEN(x86_64_regs); i++) {
      if (x86_64_regs[i].flags & REG_F_CALLEE_SAVE)
         continue;  // TODO: later...
      else if (x86_64_regs[i].usage != VCODE_INVALID_REG) {
         // TODO
         continue;
      }
      else
         possible[nposs++] = &(x86_64_regs[i]);
   }

   jit_mach_reg_t *best = NULL;
   for (int i = 0; i < nposs; i++) {
      if (best == NULL)
         best = possible[i];
      else if (!!(state->vcode_regs[usage].flags & JIT_F_RETURNED)
               && !!(possible[i]->flags & REG_F_RESULT))
         best = possible[i];
   }

   if (best == NULL)
      jit_abort(state, op, "JIT no more free registers");

   best->usage = usage;
   return best;
}

static jit_vcode_reg_t *jit_get_vcode_reg(jit_state_t *state, vcode_reg_t reg)
{
   assert(reg != VCODE_INVALID_REG);
   return &(state->vcode_regs[reg]);
}

static void jit_prologue(jit_state_t *state)
{
   __PUSH(__RBP);
   __MOVQR(__RBP, __RSP);

   if (state->stack_size == 0)
      ;
   else if (state->stack_size < INT8_MAX)
      __SUBQRI8(__RSP, state->stack_size);
   else
      __SUBQRI32(__RSP, state->stack_size);
}

static void jit_epilogue(jit_state_t *state)
{
   __MOVQR(__RSP, __RBP);
   __POP(__RBP);
}

static void jit_op_const(jit_state_t *state, int op)
{
   jit_vcode_reg_t *r = jit_get_vcode_reg(state, vcode_get_result(op));
   r->state = JIT_CONST;
   r->value = vcode_get_value(op);
}

static void jit_op_return(jit_state_t *state, int op)
{
   if (vcode_count_args(op) > 0) {
      vcode_reg_t result_reg = vcode_get_arg(op, 0);
      jit_vcode_reg_t *r = jit_get_vcode_reg(state, result_reg);

      switch (r->state) {
      case JIT_REGISTER:
         if (r->reg_name != __EAX)
            __MOVR(__EAX, r->reg_name);
         break;
      case JIT_CONST:
         __MOVI32(__EAX, r->value);
         break;
      case JIT_UNDEFINED:
      case JIT_STACK:
         jit_abort(state, op, "cannot return r%d", result_reg);
      }
   }

   jit_epilogue(state);
   __RET();
}

static void jit_op_addi(jit_state_t *state, int op)
{
   jit_vcode_reg_t *p0 = jit_get_vcode_reg(state, vcode_get_arg(op, 0));
   jit_vcode_reg_t *result = jit_get_vcode_reg(state, vcode_get_result(op));

   assert(p0->state == JIT_REGISTER);

   unsigned reg_name;
   if (!!(p0->flags & JIT_F_BLOCK_LOCAL) && p0->lifetime <= op) {
      reg_name = p0->reg_name;
   }
   else {
      jit_mach_reg_t *mreg = jit_alloc_reg(state, op, vcode_get_result(op));
      __MOVR(mreg->name, p0->reg_name);
      reg_name = mreg->name;
   }

   const int64_t value = vcode_get_value(op);
   if (jit_is_int8(value))
      __ADDI8(reg_name, value);
   else
      __ADDI32(reg_name, value);

   result->state = JIT_REGISTER;
   result->reg_name = reg_name;
}

static void jit_op_alloca(jit_state_t *state, int op)
{
   const size_t size = jit_size_of(vcode_get_type(op));
   const unsigned align = jit_align_object(size, state->stack_wptr);
   const unsigned stack_offset = state->stack_wptr + align;

   state->stack_wptr += align + size;
   assert(state->stack_wptr <= state->stack_size);

   jit_vcode_reg_t *r = jit_get_vcode_reg(state, vcode_get_result(op));
   r->state = JIT_STACK;
   r->stack_offset = -stack_offset - size;
}

static void jit_op_store_indirect(jit_state_t *state, int op)
{
   jit_vcode_reg_t *dest = jit_get_vcode_reg(state, vcode_get_arg(op, 1));
   assert(dest->state == JIT_STACK);
   assert(dest->stack_offset >= INT8_MIN);

   jit_vcode_reg_t *src = jit_get_vcode_reg(state, vcode_get_arg(op, 0));
   switch (src->state) {
   case JIT_REGISTER:
      __MOVRM(__EBP, dest->stack_offset, src->reg_name);
      break;
   case JIT_CONST:
      __MOVI32M(__EBP, dest->stack_offset, src->value);
      break;
   default:
      jit_abort(state, op, "cannot store r%d", vcode_get_arg(op, 0));
   }

}

static void jit_op_load_indirect(jit_state_t *state, int op)
{
   jit_vcode_reg_t *src = jit_get_vcode_reg(state, vcode_get_arg(op, 0));
   assert(src->state == JIT_STACK);

   vcode_reg_t result_reg = vcode_get_result(op);
   jit_vcode_reg_t *dest = jit_get_vcode_reg(state, result_reg);
   jit_mach_reg_t *mreg = jit_alloc_reg(state, op, result_reg);

   assert(src->stack_offset >= INT8_MIN);
   __MOVMR(mreg->name, __EBP, src->stack_offset);

   dest->state = JIT_REGISTER;
   dest->reg_name = mreg->name;
}

static void jit_op_jump(jit_state_t *state, int op)
{
   vcode_block_t target = vcode_get_target(op, 0);
   if (state->block_ptrs[target] != NULL) {
      ptrdiff_t diff = state->block_ptrs[target] - state->code_wptr;
      if (jit_is_int8(diff))
         __JMPR8(diff);
      else
         __JMPR32(diff);
   }
   else {
      jit_patch_t *p = &(state->patches[state->patch_wptr++]);
      p->code_wptr = state->code_wptr;
      p->offset    = 1;
      p->target    = target;

      __JMPR32(0);
   }
}

static void jit_op_cmp(jit_state_t *state, int op)
{

}

static void jit_op_cond(jit_state_t *state, int op)
{

}

static void jit_op(jit_state_t *state, int op)
{
   vcode_set_jit_addr(op, (uintptr_t)state->code_wptr);

   switch (vcode_get_op(op)) {
   case VCODE_OP_CONST:
      jit_op_const(state, op);
      break;
   case VCODE_OP_RETURN:
      jit_op_return(state, op);
      break;
   case VCODE_OP_ADDI:
      jit_op_addi(state, op);
      break;
   case VCODE_OP_ALLOCA:
      jit_op_alloca(state, op);
      break;
   case VCODE_OP_STORE_INDIRECT:
      jit_op_store_indirect(state, op);
      break;
   case VCODE_OP_LOAD_INDIRECT:
      jit_op_load_indirect(state, op);
      break;
   case VCODE_OP_JUMP:
      jit_op_jump(state, op);
      break;
   case VCODE_OP_CMP:
      jit_op_cmp(state, op);
      break;
   case VCODE_OP_COND:
      jit_op_cond(state, op);
      break;
   case VCODE_OP_COMMENT:
      break;
   default:
      jit_abort(state, op, "cannot JIT op %s",
                vcode_op_string(vcode_get_op(op)));
   }
}

static void jit_stack_frame(jit_state_t *state)
{
   state->stack_size = 0;
   state->stack_wptr = 0;

   const int nblocks = vcode_count_blocks();
   for (int i = 0; i < nblocks; i++) {
      vcode_select_block(i);

      const int nops = vcode_count_ops();
      for (int j = 0; j < nops; j++) {
         switch (vcode_get_op(j)) {
         case VCODE_OP_ALLOCA:
            {
               assert(vcode_count_args(j) == 0);
               const size_t size = jit_size_of(vcode_get_type(j));
               state->stack_size +=
                  jit_align_object(size, state->stack_size) + size;
            }
            break;
         default:
            break;
         }
      }
   }
}

static void jit_analyse(jit_state_t *state)
{
   const int nregs = vcode_count_regs();
   vcode_block_t *defn_block LOCAL = xmalloc(nregs * sizeof(vcode_block_t));
   for (int i = 0; i < nregs; i++) {
      state->vcode_regs[i].flags |= JIT_F_BLOCK_LOCAL;
      if (state->vcode_regs[i].flags & JIT_F_PARAMETER)
         defn_block[i] = 0;
      else
         defn_block[i] = VCODE_INVALID_BLOCK;
   }

   const int nblocks = vcode_count_blocks();
   for (int i = 0; i < nblocks; i++) {
      vcode_select_block(i);

      const int nops = vcode_count_ops();
      for (int j = 0; j < nops; j++) {
         switch (vcode_get_op(j)) {
         case VCODE_OP_RETURN:
            if (vcode_count_args(j) > 0)
               state->vcode_regs[vcode_get_arg(j, 0)].flags |= JIT_F_RETURNED;
            break;

         case VCODE_OP_ADDI:
         case VCODE_OP_CONST:
         case VCODE_OP_ALLOCA:
         case VCODE_OP_LOAD_INDIRECT:
         case VCODE_OP_CMP:
            {
               vcode_reg_t result = vcode_get_result(j);
               assert(defn_block[result] == VCODE_INVALID_BLOCK);
               defn_block[result] = i;
            }
            break;

         case VCODE_OP_STORE_INDIRECT:
         case VCODE_OP_JUMP:
         case VCODE_OP_COND:
         case VCODE_OP_COMMENT:
            break;

         default:
            jit_abort(state, j, "cannot analyse op %s for JIT",
                      vcode_op_string(vcode_get_op(j)));
            break;
         }

         const int nargs = vcode_count_args(j);
         for (int k = 0; k < nargs; k++) {
            vcode_reg_t reg = vcode_get_arg(j, k);
            if (defn_block[reg] == VCODE_INVALID_BLOCK)
               jit_abort(state, j, "r%d has no definition", reg);
            else if (defn_block[reg] != i) {
               printf("r%d is not block local\n", reg);
               state->vcode_regs[reg].flags &= ~JIT_F_BLOCK_LOCAL;
            }
            else
               // Track last usage of this register
               state->vcode_regs[reg].lifetime = j;
         }
      }
   }
}

static void jit_fixup_jumps(jit_state_t *state)
{
   for (unsigned i = 0; i < state->patch_wptr; i++) {
      jit_patch_t *p = state->patches + i;
   }
}

void *jit_vcode_unit(vcode_unit_t unit)
{
   vcode_select_unit(unit);

   jit_state_t *state = xcalloc(sizeof(jit_state_t));
   state->unit = unit;
   jit_alloc_code(state, 4096);

   jit_stack_frame(state);
   printf("stack size %d\n", state->stack_size);

   const int nregs = vcode_count_regs();
   state->vcode_regs = xcalloc(nregs * sizeof(jit_vcode_reg_t));

   const int nblocks = vcode_count_blocks();
   state->block_ptrs = xcalloc(nblocks * sizeof(uint8_t *));

   state->patches = xcalloc(nblocks * 2 * sizeof(jit_patch_t));
   state->patch_wptr = 0;

   for (int i = 0; i < ARRAY_LEN(x86_64_regs); i++)
      x86_64_regs[i].usage = VCODE_INVALID_REG;

   if (vcode_unit_kind() == VCODE_UNIT_FUNCTION) {
      const int nparams = vcode_count_params();
      for (int i = 0; i < nparams; i++) {
         bool have_reg = false;
         for (int j = 0; j < ARRAY_LEN(x86_64_regs); j++) {
            if (x86_64_regs[j].arg_index == i) {
               x86_64_regs[j].usage = i;

               jit_vcode_reg_t *r = jit_get_vcode_reg(state, i);
               r->state = JIT_REGISTER;
               r->reg_name = x86_64_regs[j].name;
               r->flags |= JIT_F_PARAMETER;

               have_reg = true;
               break;
            }
         }

         if (!have_reg)
            jit_abort(state, -1, "cannot find register for parameter %d", i);
      }
   }

   jit_analyse(state);

   jit_prologue(state);

   vcode_select_block(0);

   for (int j = 0; j < nblocks; j++) {
      state->block_ptrs[j] = state->code_wptr;

      vcode_select_block(j);
      const int nops = vcode_count_ops();
      for (int i = 0; i < nops; i++)
         jit_op(state, i);
   }

   assert(state->patch_wptr <= nblocks * 2);

   jit_fixup_jumps(state);

   jit_dump(state, -1);

   free(state->vcode_regs);
   state->vcode_regs = NULL;

   free(state->block_ptrs);
   state->block_ptrs = NULL;

   if (jit_cache == NULL)
      jit_cache = hash_new(1024, true);

   hash_put(jit_cache, unit, state);
   vcode_unit_ref(unit);

   return state->code_base;
}

static jit_state_t *jit_find_in_cache(void *mem)
{
   if (jit_cache == NULL)
      return NULL;

   hash_iter_t it = HASH_BEGIN;
   jit_state_t *value = NULL;
   const void *key;
   while (hash_iter(jit_cache, &it, &key, (void **)&value)) {
      if ((uint8_t *)mem >= (uint8_t *)value->code_base
          && (uint8_t *)mem < (uint8_t *)value->code_base + value->code_len)
         return value;
   }

   return NULL;
}

void jit_free(void *mem)
{
   jit_state_t *value = jit_find_in_cache(mem);
   if (value == NULL)
      fatal_trace("%p not in JIT cache", mem);

   vcode_unit_unref(value->unit);
   hash_put(jit_cache, value->unit, NULL);
   // TODO: unmap memory
   free(value);
}

void jit_crash_handler(void *extra)
{
   ucontext_t *uc = (ucontext_t*)extra;
   uintptr_t rip = uc->uc_mcontext.gregs[REG_RIP];
   jit_state_t *jc = jit_find_in_cache((void *)rip);
   if (jc == NULL)
      return;

   vcode_select_unit(jc->unit);

   int mark_op = -1;
   const int nblocks = vcode_count_blocks();
   for (int i = 0; i < nblocks; i++) {
      vcode_select_block(i);

      const int nops = vcode_count_ops();
      for (int j = 0; j < nops; j++) {
         if (vcode_get_jit_addr(j) > rip) {
            if (j == 0) {
               vcode_select_block(i - 1);
               mark_op = vcode_count_ops() - 1;
            }
            else
               mark_op = j - 1;
            goto found_op;
         }
         else
            mark_op = j;
      }
   }
 found_op:
   jit_dump(jc, mark_op);

   color_printf("$red$Crashed while running JIT compiled code$$\n\n");

   printf("RAX %16llx    RSP %16llx\n",
          uc->uc_mcontext.gregs[REG_RAX], uc->uc_mcontext.gregs[REG_RSP]);
   printf("RBX %16llx    RBP %16llx\n",
          uc->uc_mcontext.gregs[REG_RBX], uc->uc_mcontext.gregs[REG_RBP]);
   printf("RCX %16llx    RSI %16llx\n",
          uc->uc_mcontext.gregs[REG_RCX], uc->uc_mcontext.gregs[REG_RSI]);
   printf("RDX %16llx    RDI %16llx\n",
          uc->uc_mcontext.gregs[REG_RDX], uc->uc_mcontext.gregs[REG_RDI]);
}
