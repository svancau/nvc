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
#include "jit-priv.h"
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

#ifdef HAVE_CAPSTONE
#include <capstone/capstone.h>
#endif

static hash_t *jit_cache = NULL;

#ifdef HAVE_CAPSTONE
static csh capstone;
#endif

extern jit_mach_reg_t mach_regs[];
extern const size_t num_mach_regs;

static void jit_alloc_code(jit_state_t *state, size_t size)
{
   state->code_base = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE | MAP_ANON, -1, 0);
   if (state->code_base == MAP_FAILED)
      fatal_errno("mmap");

   state->code_wptr = state->code_base;
   state->code_len  = size;
}

jit_vcode_reg_t *jit_get_vcode_reg(jit_state_t *state, vcode_reg_t reg)
{
   assert(reg != VCODE_INVALID_REG);
   return &(state->vcode_regs[reg]);
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
                            (unsigned long)base, 0, &insn);
   if (count > 0) {
      size_t j;
      for (j = 0; j < count; j++) {
         char hex1[33], *p = hex1;
         for (size_t k = 0; k < insn[j].size; k++)
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

void jit_dump(jit_state_t *state, int mark_op)
{
#ifdef HAVE_CAPSTONE
#if defined ARCH_X86_64
   if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone) != CS_ERR_OK)
      fatal_trace("failed to init capstone for x86_64");
#elif defined ARCH_ARM64
   if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &capstone) != CS_ERR_OK)
      fatal_trace("failed to init capstone for Arm64");
#else
#error Cannot configure capstone for this architecture
#endif

   vcode_dump_with_mark(mark_op, jit_dump_callback, state);

   cs_close(&capstone);
#else
   vcode_dump_with_mark(mark_op, NULL, NULL);
#endif
}

__attribute__((noreturn))
void jit_abort(jit_state_t *state, int mark_op, const char *fmt, ...)
{
   va_list ap;
   va_start(ap, fmt);
   char *msg LOCAL = xvasprintf(fmt, ap);
   va_end(ap);

   jit_dump(state, mark_op);
   fatal_trace("%s", msg);
}

void jit_emit(jit_state_t *state, const uint8_t *bytes, size_t len)
{
   if (state->code_wptr + len >= (uint8_t *)state->code_base + state->code_len)
      jit_abort(state, -1, "JIT code buffer too small %d",
                (int)state->code_len);

   for (size_t i = 0; i < len; i++)
      *(state->code_wptr++) = bytes[i];
}

jit_state_t *jit_find_in_cache(void *mem)
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

unsigned jit_align_object(size_t size, unsigned ptr)
{
   size = MIN(size, sizeof(void *));
   const size_t align = size - ptr % size;
   return align == size ? 0 : align;
}


static jit_mach_reg_t *__jit_alloc_reg(jit_state_t *state, int op,
                                       vcode_reg_t usage, vcode_reg_t hint)
{
   if (!(state->vcode_regs[usage].flags & JIT_F_BLOCK_LOCAL))
      return NULL;

   int nposs = 0;
   jit_mach_reg_t *possible[num_mach_regs];
   for (size_t i = 0; i < num_mach_regs; i++) {
      if (mach_regs[i].flags & REG_F_SCRATCH)
         continue;
      else if (mach_regs[i].usage != VCODE_INVALID_REG) {
         jit_vcode_reg_t *owner =
            jit_get_vcode_reg(state, mach_regs[i].usage);
         if (!!(owner->flags & JIT_F_BLOCK_LOCAL)
             && (owner->defn_block != vcode_active_block()
                 || owner->lifetime < op
                 || (hint == mach_regs[i].usage && owner->lifetime == op))) {
            // No longer in use
            possible[nposs++] = &(mach_regs[i]);
            mach_regs[i].usage = VCODE_INVALID_REG;
         }
      }
      else
         possible[nposs++] = &(mach_regs[i]);
   }

   jit_mach_reg_t *best = NULL;
   for (int i = 0; i < nposs; i++) {
      if (best == NULL)
         best = possible[i];
      else if (!!(state->vcode_regs[usage].flags & JIT_F_RETURNED)
               && !!(possible[i]->flags & REG_F_RESULT))
         best = possible[i];
      else if (possible[i]->usage == hint)
         best = possible[i];
   }

   if (best == NULL)
      return NULL;

   best->usage = usage;
   return best;
}

jit_mach_reg_t *jit_alloc_reg(jit_state_t *state, int op, vcode_reg_t usage)
{
   return __jit_alloc_reg(state, op, usage, VCODE_INVALID_REG);
}

jit_mach_reg_t *jit_reuse_reg(jit_state_t *state, int op, vcode_reg_t usage,
                              vcode_reg_t hint)
{
   return __jit_alloc_reg(state, op, usage, hint);
}

vcode_reg_t jit_reuse_hint(jit_vcode_reg_t *input)
{
   return input->state == JIT_REGISTER ? input->reg_name : VCODE_INVALID_REG;
}

bool jit_is_no_op(int op)
{
   const vcode_op_t kind = vcode_get_op(op);
   return kind == VCODE_OP_COMMENT || kind == VCODE_OP_DEBUG_INFO;
}

int jit_next_op(int op)
{
   // Skip over comment and debug info
   const int nops = vcode_count_ops();
   do {
      ++op;
   } while (op < nops && jit_is_no_op(op));
   return op;
}

int jit_previous_op(int op)
{
   // Skip over comment and debug info
   assert(op > 0);
   const int nops = vcode_count_ops();
   do {
      --op;
   } while (op < nops && jit_is_no_op(op));
   return op;
}

bool jit_is_ephemeral(jit_vcode_reg_t *r, int op)
{
   return !!(r->flags & JIT_F_BLOCK_LOCAL) && r->lifetime == jit_next_op(op);
}

size_t jit_size_of(vcode_type_t type)
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

   case VCODE_TYPE_UARRAY:
      return sizeof(uarray_t);

   case VCODE_TYPE_POINTER:
      return sizeof(void *);

   case VCODE_TYPE_OFFSET:
      return 4;

   default:
      fatal_trace("missing jit_size_of for type %d", vtype_kind(type));
   }
}

static void jit_stack_frame(jit_state_t *state)
{
   state->stack_size = 0;

   const int nvars = vcode_count_vars();
   for (int i = 0; i < nvars; i++) {
      vcode_var_t var = vcode_var_handle(i);
      const size_t size = jit_size_of(vcode_var_type(var));
      state->stack_size += jit_align_object(size, state->stack_size);
      state->var_offsets[i] = -state->stack_size - size;
      state->stack_size += size;
   }

   state->stack_wptr = state->stack_size;

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

static bool jit_must_store_result(int op)
{
   switch (vcode_get_op(op)) {
   case VCODE_OP_CONST:
   case VCODE_OP_LOAD:
   case VCODE_OP_UARRAY_DIR:
   case VCODE_OP_UARRAY_LEFT:
   case VCODE_OP_UARRAY_RIGHT:
      return false;

   default:
      return true;
   }
}

static void jit_analyse(jit_state_t *state)
{
   const int nregs = vcode_count_regs();
   for (int i = 0; i < nregs; i++) {
      state->vcode_regs[i].flags |= JIT_F_BLOCK_LOCAL;
      state->vcode_regs[i].size = jit_size_of(vcode_reg_type(i));
      state->vcode_regs[i].vcode_reg = i;
      if (state->vcode_regs[i].flags & JIT_F_PARAMETER)
         state->vcode_regs[i].defn_block = 0;
      else
         state->vcode_regs[i].defn_block = VCODE_INVALID_BLOCK;
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
         case VCODE_OP_LOAD:
         case VCODE_OP_CMP:
         case VCODE_OP_ADD:
         case VCODE_OP_SUB:
         case VCODE_OP_MUL:
         case VCODE_OP_UNWRAP:
         case VCODE_OP_UARRAY_DIR:
         case VCODE_OP_UARRAY_LEFT:
         case VCODE_OP_UARRAY_RIGHT:
         case VCODE_OP_UARRAY_LEN:
         case VCODE_OP_SELECT:
         case VCODE_OP_CAST:
         case VCODE_OP_RANGE_NULL:
            {
               vcode_reg_t result = vcode_get_result(j);
               assert(state->vcode_regs[result].defn_block
                      == VCODE_INVALID_BLOCK);
               state->vcode_regs[result].defn_block = i;

               if (jit_must_store_result(j)) {
                  state->stack_size += state->vcode_regs[result].size;
                  state->stack_size +=
                     jit_align_object(state->vcode_regs[result].size,
                                      state->stack_size);
               }
            }
            break;

         case VCODE_OP_COND:
            {
               vcode_reg_t input = vcode_get_arg(j, 0);
               if (state->vcode_regs[input].defn_block == i && j > 0
                   && vcode_get_op(jit_previous_op(j)) == VCODE_OP_CMP
                   && vcode_get_result(jit_previous_op(j)) == input)
                  state->vcode_regs[input].flags |= JIT_F_COND_INPUT;
            }
            break;

         case VCODE_OP_STORE_INDIRECT:
         case VCODE_OP_STORE:
         case VCODE_OP_JUMP:
         case VCODE_OP_COMMENT:
         case VCODE_OP_BOUNDS:
         case VCODE_OP_DEBUG_INFO:
         case VCODE_OP_DYNAMIC_BOUNDS:
            break;

         default:
            jit_abort(state, j, "cannot analyse op %s for JIT",
                      vcode_op_string(vcode_get_op(j)));
            break;
         }

         const int nargs = vcode_count_args(j);
         for (int k = 0; k < nargs; k++) {
            vcode_reg_t reg = vcode_get_arg(j, k);
            if (state->vcode_regs[reg].defn_block == VCODE_INVALID_BLOCK)
               jit_abort(state, j, "r%d has no definition", reg);
            else if (state->vcode_regs[reg].defn_block != i)
               state->vcode_regs[reg].flags &= ~JIT_F_BLOCK_LOCAL;
            else {
               // Track last usage of this register
               state->vcode_regs[reg].lifetime = j;
               state->vcode_regs[reg].use_count++;
            }
         }
      }
   }
}

 void jit_fixup_jumps(jit_state_t *state)
{
   for (unsigned i = 0; i < state->patch_wptr; i++) {
      jit_fixup_t *p = state->patches + i;
      jit_patch_jump(p->patch, state->block_ptrs[p->target]);
   }
}

void *jit_vcode_unit(vcode_unit_t unit)
{
   vcode_select_unit(unit);

   jit_state_t *state = xcalloc(sizeof(jit_state_t));
   state->unit = unit;
   jit_alloc_code(state, 4096);

   for (int i = 0; i < num_mach_regs; i++)
      mach_regs[i].usage = VCODE_INVALID_REG;

   const int nvars = vcode_count_vars();
   state->var_offsets = xmalloc(nvars * sizeof(unsigned));

   jit_stack_frame(state);

   const int nregs = vcode_count_regs();
   state->vcode_regs = xcalloc(nregs * sizeof(jit_vcode_reg_t));

   const int nblocks = vcode_count_blocks();
   state->block_ptrs = xcalloc(nblocks * sizeof(uint8_t *));

   state->patches = xcalloc(nblocks * 2 * sizeof(jit_patch_t));
   state->patch_wptr = 0;

   if (vcode_unit_kind() == VCODE_UNIT_FUNCTION)
      jit_bind_params(state);

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

   if (getenv("NVC_JIT_VERBOSE") != NULL)
      jit_dump(state, -1);

   free(state->vcode_regs);
   state->vcode_regs = NULL;

   free(state->block_ptrs);
   state->block_ptrs = NULL;

   free(state->patches);
   state->patches = NULL;

   free(state->var_offsets);
   state->var_offsets = NULL;

   if (jit_cache == NULL)
      jit_cache = hash_new(1024, true);

   hash_put(jit_cache, unit, state);
   vcode_unit_ref(unit);

   return state->code_base;
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
