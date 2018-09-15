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

#if defined(HAVE_UCONTEXT_H)
#include <ucontext.h>
#elif defined(HAVE_SYS_UCONTEXT_H)
#include <sys/ucontext.h>
#endif

#define __IMM32(x) (x) & 0xff, ((x) >> 8) & 0xff,       \
      ((x) >> 16) & 0xff, ((x) >> 24) & 0xff
#define __IMM16(x) (x) & 0xff, ((x) >> 8) & 0xff

typedef enum {
   __EAX = 0, __ECX, __EDX, __EBX, __ESP, __EBP, __ESI, __EDI,
   __RAX = 0x10, __RCX, __RDX, __RBX, __RSP, __RBP, __RSI, __RDI
} x86_reg_t;

typedef enum {
   X86_CMP_EQ = 0x04,
   X86_CMP_NE = 0x05,
   X86_CMP_GT = 0x0f,
} x86_cmp_t;

#define __(...) do {                                                    \
      const uint8_t __b[] = { __VA_ARGS__ };                            \
      jit_emit(state, __b, ARRAY_LEN(__b));                             \
   } while (0)

#define __MODRM(m, r, rm) (((m & 3) << 6) | (((r) & 7) << 3) | (rm & 7))

#define __MULR(r) __(0xf7, __MODRM(3, 4, r))
#define __SUBQRI32(r, i) __(0x48, 0x81, __MODRM(3, 5, r), __IMM32(i))
#define __SUBQRI8(r, i) __(0x48, 0x83, __MODRM(3, 5, r), i)
#define __PUSH(r) __(0x50 + (r & 7))
#define __POP(r) __(0x58 + (r & 7))

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
      .flags = REG_F_RESULT | REG_F_SCRATCH,
      .arg_index = -1
   },
   {
      .name = __EBX,
      .text = "EBX",
      .flags = REG_F_CALLEE_SAVE,
      .arg_index = -1
   },
};

void jit_patch_jump(jit_patch_t patch, uint8_t *target)
{
   ptrdiff_t diff = target - patch.pc - patch.offset - 4;
   patch.pc[patch.offset + 0] = diff & 0xff;
   patch.pc[patch.offset + 1] = (diff >> 8) & 0xff;
   patch.pc[patch.offset + 2] = (diff >> 24) & 0xff;
   patch.pc[patch.offset + 3] = (diff >> 28) & 0xff;
}

static inline bool jit_is_int8(int64_t value)
{
   return value >= INT8_MIN && value <= INT8_MAX;
}

static inline bool jit_is_int16(int64_t value)
{
   return value >= INT16_MIN && value <= INT16_MAX;
}

static jit_patch_t x86_jmp_rel(jit_state_t *state, ptrdiff_t disp)
{
   jit_patch_t patch = { state->code_wptr, 1 };

   if (jit_is_int8(disp - 2))
      __(0xeb, disp - 2);
   else
      __(0xe9, __IMM32(disp - 5));

   return patch;
}

static jit_patch_t x86_jcc_rel(jit_state_t *state, x86_cmp_t cmp,
                               ptrdiff_t disp)
{
   jit_patch_t patch = { state->code_wptr, 2 };
   __(0x0f, 0x80 + cmp, __IMM32(disp - 6));
   return patch;
}

static void x86_ret(jit_state_t *state)
{
   __(0xc3);
}

static void x86_int3(jit_state_t *state)
{
   __(0xcc);
}

static void x86_xor(jit_state_t *state, x86_reg_t lhs, x86_reg_t rhs)
{
   __(0x31, __MODRM(3, lhs, rhs));
}

static void x86_lea_scaled(jit_state_t *state, x86_reg_t dst, x86_reg_t base,
                           x86_reg_t offset, size_t size)
{
   int scale = 0;
   switch (size) {
   case 1: scale = 0; break;
   case 2: scale = 1; break;
   case 4: scale = 2; break;
   case 8: scale = 4; break;
   };

   __(0x48, 0x8d, __MODRM(1, dst, 4), __MODRM(scale, offset, base), 0);
}

static void x86_add_reg_imm(jit_state_t *state, x86_reg_t dst, int64_t imm,
                            size_t size)
{
   if (jit_is_int8(imm))
      __(0x83, __MODRM(3, 0, dst), (uint8_t)imm);
   else
      __(0x81, __MODRM(3, 0, dst), __IMM32(imm));
}

static void x86_add_reg_reg(jit_state_t *state, x86_reg_t dst, x86_reg_t src,
                            size_t size)
{
   if (size > 4)
      __(0x48);

   __(0x01, __MODRM(3, src, dst));
}

static void x86_add_reg_mem(jit_state_t *state, x86_reg_t dst, x86_reg_t addr,
                            int offset)
{
   assert(offset >= INT8_MIN);
   assert(offset <= INT8_MAX);

   __(0x03, __MODRM(1, dst, addr), offset);
}

static void x86_sub_reg_reg(jit_state_t *state, x86_reg_t dst, x86_reg_t src)
{
   __(0x29, __MODRM(3, src, dst));
}

static void x86_sub_reg_mem(jit_state_t *state, x86_reg_t dst, x86_reg_t addr,
                            int offset)
{
   assert(offset >= INT8_MIN);
   assert(offset <= INT8_MAX);

   __(0x2b, __MODRM(1, dst, addr), offset);
}

static void x86_cmov_reg_reg(jit_state_t *state, x86_reg_t dst, x86_reg_t src,
                             x86_cmp_t cmp)
{
   __(0x0f, 0x40 + cmp, __MODRM(3, dst, src));
}

static void x86_cmov_reg_mem(jit_state_t *state, x86_reg_t dst, x86_reg_t addr,
                             int offset, x86_cmp_t cmp)
{
   assert(offset >= INT8_MIN);
   assert(offset <= INT8_MAX);

   __(0x0f, 0x40 + cmp, __MODRM(1, dst, addr), offset);
}

static void x86_mov_reg_imm(jit_state_t *state, x86_reg_t dst, int64_t imm)
{
   __(0xb8 + (dst & 7), __IMM32(imm));
}

static void x86_mov_reg_reg(jit_state_t *state, x86_reg_t dst, x86_reg_t src)
{
   if (src == dst)
      return;

   if ((dst & 0x10) || (src & 0x10))
      __(0x48);

   __(0x8b, __MODRM(3, dst, src));
}

static void x86_movzbl(jit_state_t *state, x86_reg_t dst, x86_reg_t src)
{
   __(0x0f, 0xb6, __MODRM(3, dst, src));
}

static void x86_mov_reg_mem_relative(jit_state_t *state, x86_reg_t dst,
                                     x86_reg_t addr, int offset, size_t size)
{
   assert(offset >= INT8_MIN);
   assert(offset <= INT8_MAX);

   if (size > 4)
      __(0x48);

   __(0x8b, __MODRM(1, dst, addr), offset);
}

static void x86_mov_mem_imm(jit_state_t *state, x86_reg_t addr, int offset,
                            int64_t imm, size_t size)
{
   assert(offset >= INT8_MIN);
   assert(offset <= INT8_MAX);

   switch (size) {
   case 4:
      __(0xc7, __MODRM(1, 0, addr), offset, __IMM32(imm));
      break;
   default:
      jit_abort(state, -1, "cannot handle size %d in x86_mov_mem_imm", size);
   }
}

static void x86_mov_mem_reg_relative(jit_state_t *state, x86_reg_t addr,
                                     int offset, x86_reg_t src, size_t size)
{
   assert(offset >= INT8_MIN);
   assert(offset <= INT8_MAX);

   if (size > 4)
      __(0x48);

   __(0x89, __MODRM(1, src, addr), offset);
}

static void x86_mov_reg_mem_indirect(jit_state_t *state, x86_reg_t dst,
                                     x86_reg_t addr, size_t size)
{
   if (size > 4)
      __(0x48);

   __(0x8b, __MODRM(1, dst, addr), 0);
}

 __attribute__((unused))
static void x86_nop(jit_state_t *state)
{
   __(0x90);
}

#if 0
static void x86_test_mem_imm8(jit_state_t *state, x86_reg_t addr, int offset,
                              int8_t imm8)
{
   assert(offset >= INT8_MIN);
   assert(offset <= INT8_MAX);

   __(0x67, 0xf6, __MODRM(1, 0, addr), offset, (uint8_t)imm8);
}
#endif

static void x86_cmp_reg_reg(jit_state_t *state, x86_reg_t lhs, x86_reg_t rhs)
{
   __(0x39, __MODRM(3, rhs, lhs));
}

static void x86_cmp_reg_mem(jit_state_t *state, x86_reg_t reg, x86_reg_t addr,
                            int offset, size_t size)
{
   assert(offset >= INT8_MIN);
   assert(offset <= INT8_MAX);

   switch (size) {
   case 1:
      __(0x38, __MODRM(1, reg, addr), offset);
      break;
   case 4:
      __(0x39, __MODRM(1, reg, addr), offset);
      break;
   default:
      jit_abort(state, -1, "cannot handle size %d in x86_cmp_reg_mem", size);
   }
}

static void x86_cmp_mem_imm(jit_state_t *state, x86_reg_t addr,
                            int offset, int64_t imm, size_t size)
{
   assert(offset >= INT8_MIN);
   assert(offset <= INT8_MAX);

   switch (size) {
   case 1:
      __(0x80, __MODRM(1, 7, addr), offset, imm);
      break;
   case 4:
      __(0x83, __MODRM(1, 7, addr), offset, __IMM32(imm));
      break;
   default:
      jit_abort(state, -1, "cannot handle size %d in x86_cmp_mem_imm", size);
   }
}

static void x86_cmp_reg_imm(jit_state_t *state, x86_reg_t reg, int64_t imm)
{
   if (jit_is_int8(imm))
      __(0x83, __MODRM(3, 7, reg), imm);
   else
      __(0x81, __MODRM(3, 7, reg), __IMM32(imm));
}

static void x86_setbyte(jit_state_t *state, x86_reg_t reg, x86_cmp_t cmp)
{
   __(0x0f, 0x90 + cmp, __MODRM(3, 0, reg));
}

static jit_vcode_reg_t *jit_get_vcode_reg(jit_state_t *state, vcode_reg_t reg)
{
   assert(reg != VCODE_INVALID_REG);
   return &(state->vcode_regs[reg]);
}

static jit_mach_reg_t *__jit_alloc_reg(jit_state_t *state, int op,
                                       vcode_reg_t usage, bool can_clobber)
{
   int nposs = 0;
   jit_mach_reg_t *possible[ARRAY_LEN(x86_64_regs)];
   for (int i = 0; i < ARRAY_LEN(x86_64_regs); i++) {
      if (x86_64_regs[i].flags & REG_F_SCRATCH)
         continue;
      else if (x86_64_regs[i].usage != VCODE_INVALID_REG) {
         jit_vcode_reg_t *owner =
            jit_get_vcode_reg(state, x86_64_regs[i].usage);
         if (!!(owner->flags & JIT_F_BLOCK_LOCAL)
             && (owner->defn_block != vcode_active_block()
                 || owner->lifetime < op
                 || (can_clobber && owner->lifetime == op))) {
            // No longer in use
            possible[nposs++] = &(x86_64_regs[i]);
            x86_64_regs[i].usage = VCODE_INVALID_REG;
         }
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
      return NULL;

   best->usage = usage;
   return best;
}

static jit_mach_reg_t *jit_alloc_reg(jit_state_t *state, int op,
                                     vcode_reg_t usage)
{
   return __jit_alloc_reg(state, op, usage, false);
}

static jit_mach_reg_t *jit_alloc_reg_clobber(jit_state_t *state, int op,
                                             vcode_reg_t usage)
{
   return __jit_alloc_reg(state, op, usage, true);
}

static void jit_move_to_reg(jit_state_t *state, x86_reg_t dest,
                            jit_vcode_reg_t *src)
{
   switch (src->state) {
   case JIT_STACK:
      x86_mov_reg_mem_relative(state, dest, __EBP,
                               src->stack_offset, src->size);
      break;
   case JIT_REGISTER:
      x86_mov_reg_reg(state, dest, src->reg_name);
      break;
   case JIT_CONST:
      x86_mov_reg_imm(state, dest, src->value);
      break;
   default:
      jit_abort(state, -1, "cannot move r%d (state %d) to register",
                src->vcode_reg, src->state);
   }
}

void jit_prologue(jit_state_t *state)
{
   __PUSH(__RBP);
   __PUSH(__RBX);
   x86_mov_reg_reg(state, __RBP, __RSP);

   if (state->stack_size == 0)
      ;
   else if (state->stack_size < INT8_MAX)
      __SUBQRI8(__RSP, state->stack_size);
   else
      __SUBQRI32(__RSP, state->stack_size);
}

void jit_epilogue(jit_state_t *state)
{
   x86_mov_reg_reg(state, __RSP, __RBP);
   __POP(__RBX);
   __POP(__RBP);
}

static ptrdiff_t jit_jump_target(jit_state_t *state, vcode_block_t target)
{
   if (state->block_ptrs[target] != NULL)
      return state->block_ptrs[target] - state->code_wptr;
   else
      return PTRDIFF_MAX;
}

static void jit_fixup_jump_later(jit_state_t *state, jit_patch_t patch,
                                 vcode_block_t target)
{
   jit_fixup_t *p = &(state->patches[state->patch_wptr++]);
   p->patch  = patch;
   p->target = target;
}

static void jit_claim_mach_reg(jit_vcode_reg_t *reg)
{
   for (size_t i = 0; i < ARRAY_LEN(x86_64_regs); i++) {
      jit_mach_reg_t *mreg = &(x86_64_regs[i]);
      if (mreg->name == reg->reg_name) {
         mreg->usage = reg->vcode_reg;
         return;
      }
   }
}

static bool jit_can_reuse_reg(jit_vcode_reg_t *reg, int op)
{
   return reg->state == JIT_REGISTER
      && !!(reg->flags & JIT_F_BLOCK_LOCAL)
      && reg->lifetime <= op;
}

static void jit_spill(jit_state_t *state, jit_vcode_reg_t *reg)
{
   const unsigned align = jit_align_object(reg->size, state->stack_wptr);
   const signed stack_offset = state->stack_wptr + align;

   state->stack_wptr += align + reg->size;
   assert(state->stack_wptr <= state->stack_size);

   reg->state = JIT_STACK;
   reg->stack_offset = -stack_offset - reg->size;
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
         x86_mov_reg_reg(state, __EAX, r->reg_name);
         break;
      case JIT_CONST:
         x86_mov_reg_imm(state, __EAX, r->value);
         break;
      case JIT_STACK:
         x86_mov_reg_mem_relative(state, __EAX, __EBP,
                                  r->stack_offset, r->size);
         break;
      case JIT_UNDEFINED:
      case JIT_FLAGS:
         jit_abort(state, op, "cannot return r%d", result_reg);
      }
   }

   jit_epilogue(state);
   x86_ret(state);
}

static void jit_op_addi(jit_state_t *state, int op)
{
   jit_vcode_reg_t *p0 = jit_get_vcode_reg(state, vcode_get_arg(op, 0));
   jit_vcode_reg_t *result = jit_get_vcode_reg(state, vcode_get_result(op));

   unsigned reg_name;
   if (jit_can_reuse_reg(p0, op)) {
      result->state = JIT_REGISTER;
      result->reg_name = p0->reg_name;
      reg_name = result->reg_name;

      jit_claim_mach_reg(result);
   }
   else {
      jit_mach_reg_t *mreg = jit_alloc_reg(state, op, vcode_get_result(op));
      if (mreg != NULL) {
         result->state = JIT_REGISTER;
         reg_name = result->reg_name = mreg->name;
      }
      else {
         jit_spill(state, result);
         reg_name = __EAX;
      }
      jit_move_to_reg(state, reg_name, p0);
   }

   x86_add_reg_imm(state, reg_name, vcode_get_value(op), result->size);

   if (result->state == JIT_STACK)
      x86_mov_mem_reg_relative(state, __EBP, result->stack_offset, reg_name,
                               result->size);
}

static void jit_op_sub(jit_state_t *state, int op)
{
   jit_vcode_reg_t *p0 = jit_get_vcode_reg(state, vcode_get_arg(op, 0));
   jit_vcode_reg_t *p1 = jit_get_vcode_reg(state, vcode_get_arg(op, 1));
   jit_vcode_reg_t *result = jit_get_vcode_reg(state, vcode_get_result(op));

   unsigned reg_name;
   if (jit_can_reuse_reg(p0, op)) {
      result->state = JIT_REGISTER;
      reg_name = result->reg_name = p0->reg_name;

      jit_claim_mach_reg(result);
   }
   else {
      jit_mach_reg_t *mreg = jit_alloc_reg(state, op, vcode_get_result(op));
      if (mreg == NULL) {
         jit_spill(state, result);
         reg_name = __EAX;
      }
      else {
         result->state = JIT_REGISTER;
         reg_name = result->reg_name = mreg->name;
      }
      jit_move_to_reg(state, reg_name, p0);
   }

   switch (p1->state) {
   case JIT_REGISTER:
      x86_sub_reg_reg(state, reg_name, p1->reg_name);
      break;
   case JIT_STACK:
      x86_sub_reg_mem(state, reg_name, __EBP, p1->stack_offset);
      break;
   default:
      jit_abort(state, op, "cannot subtract these operands");
   }

   if (result->state == JIT_STACK)
      x86_mov_mem_reg_relative(state, __EBP, result->stack_offset, reg_name,
                               result->size);
}

static void jit_op_add(jit_state_t *state, int op)
{
   jit_vcode_reg_t *p0 = jit_get_vcode_reg(state, vcode_get_arg(op, 0));
   jit_vcode_reg_t *p1 = jit_get_vcode_reg(state, vcode_get_arg(op, 1));
   jit_vcode_reg_t *result = jit_get_vcode_reg(state, vcode_get_result(op));

   unsigned reg_name;
   const bool pointer = vcode_reg_kind(result->vcode_reg) == VCODE_TYPE_POINTER;

   jit_vcode_reg_t *operand = NULL;
   if (jit_can_reuse_reg(p0, op)) {
      result->state = JIT_REGISTER;
      reg_name = result->reg_name = p0->reg_name;
      operand = p1;
      jit_claim_mach_reg(result);
   }
   else if (!pointer && jit_can_reuse_reg(p1, op)) {
      result->state = JIT_REGISTER;
      reg_name = result->reg_name = p1->reg_name;
      operand = p0;
      jit_claim_mach_reg(result);
   }
   else {
      jit_mach_reg_t *mreg = jit_alloc_reg(state, op, vcode_get_result(op));
      if (mreg == NULL) {
         jit_spill(state, result);
         reg_name = __EAX;
      }
      else {
         result->state = JIT_REGISTER;
         reg_name = result->reg_name = mreg->name;
      }
      jit_move_to_reg(state, reg_name, p0);
      operand = p1;
   }

   if (pointer) {
      // Pointer arithmetic handled separately to regular arithmentic
      assert(operand == p1);
      assert(p0->state == JIT_REGISTER);
      assert(p1->state == JIT_REGISTER);

      x86_lea_scaled(state, reg_name, p0->reg_name, p1->reg_name, 4);
   }
   else {
      switch (operand->state) {
      case JIT_REGISTER:
         x86_add_reg_reg(state, reg_name, operand->reg_name, result->size);
         break;
      case JIT_STACK:
         x86_add_reg_mem(state, reg_name, __EBP, operand->stack_offset);
         break;
      default:
         jit_abort(state, op, "cannot add these operands");
      }
   }

   if (result->state == JIT_STACK)
      x86_mov_mem_reg_relative(state, __EBP, result->stack_offset, reg_name,
                               result->size);
}

static void jit_op_mul(jit_state_t *state, int op)
{
   jit_vcode_reg_t *p0 = jit_get_vcode_reg(state, vcode_get_arg(op, 0));
   jit_vcode_reg_t *p1 = jit_get_vcode_reg(state, vcode_get_arg(op, 1));
   jit_vcode_reg_t *result = jit_get_vcode_reg(state, vcode_get_result(op));

   assert(p0->state == JIT_REGISTER);
   assert(p1->state == JIT_REGISTER);

   if (p0->reg_name != __EAX)
      x86_mov_reg_reg(state, __EAX, p0->reg_name);

   __MULR(p1->reg_name);

   if (jit_is_ephemeral(result, op)) {
      result->state = JIT_REGISTER;
      result->reg_name = __EAX;
   }
   else {
      jit_mach_reg_t *mreg = jit_alloc_reg(state, op, vcode_get_result(op));
      x86_mov_reg_reg(state, mreg->name, __EAX);

      result->state = JIT_REGISTER;
      result->reg_name = mreg->name;
   }
}

static void jit_op_alloca(jit_state_t *state, int op)
{
   const size_t size = jit_size_of(vcode_get_type(op));
   const unsigned align = jit_align_object(size, state->stack_wptr);
   const signed stack_offset = state->stack_wptr + align;

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
      x86_mov_mem_reg_relative(state, __EBP, dest->stack_offset, src->reg_name,
                               src->size);
      break;
   case JIT_CONST:
      x86_mov_mem_imm(state, __EBP, dest->stack_offset, src->value, src->size);
      break;
   default:
      jit_abort(state, op, "cannot store r%d", vcode_get_arg(op, 0));
   }
}

static void jit_op_load_indirect(jit_state_t *state, int op)
{
   jit_vcode_reg_t *src = jit_get_vcode_reg(state, vcode_get_arg(op, 0));

   vcode_reg_t result_reg = vcode_get_result(op);
   jit_vcode_reg_t *dest = jit_get_vcode_reg(state, result_reg);
   jit_mach_reg_t *mreg = jit_alloc_reg(state, op, result_reg);

   switch (src->state) {
   case JIT_STACK:
      x86_mov_reg_mem_relative(state, mreg->name, __EBP,
                               src->stack_offset, dest->size);
      break;

   case JIT_REGISTER:
      x86_mov_reg_mem_indirect(state, mreg->name, src->reg_name, dest->size);
      break;

   default:
      jit_abort(state, op, "cannot load indirect r%d", vcode_get_arg(op, 0));
   }

   dest->state = JIT_REGISTER;
   dest->reg_name = mreg->name;
}

static void jit_op_jump(jit_state_t *state, int op)
{
   vcode_block_t target = vcode_get_target(op, 0);
   if (target == vcode_active_block() + 1)
      return;

   ptrdiff_t diff = jit_jump_target(state, target);
   jit_patch_t patch = x86_jmp_rel(state, diff);

   if (diff == PTRDIFF_MAX)
      jit_fixup_jump_later(state, patch, target);
}

static void jit_op_cmp(jit_state_t *state, int op)
{
   jit_vcode_reg_t *p0 = jit_get_vcode_reg(state, vcode_get_arg(op, 0));
   jit_vcode_reg_t *p1 = jit_get_vcode_reg(state, vcode_get_arg(op, 1));

   if (p0->state == JIT_REGISTER && p1->state == JIT_CONST) {
      x86_cmp_reg_imm(state, p0->reg_name, p1->value);
   }
   else if (p0->state == JIT_CONST && p1->state == JIT_REGISTER) {
      const vcode_cmp_t kind = vcode_get_cmp(op);
      if (kind == VCODE_CMP_EQ || kind == VCODE_CMP_NEQ) {
         x86_cmp_reg_imm(state, p1->reg_name, p0->value);
      }
      else {
         jit_mach_reg_t *mreg = jit_alloc_reg(state, op, VCODE_INVALID_REG);
         x86_mov_reg_imm(state, mreg->name, p0->value);
         x86_cmp_reg_reg(state, mreg->name, p1->reg_name);
      }
   }
   else if (p0->state == JIT_REGISTER && p1->state == JIT_REGISTER) {
      x86_cmp_reg_reg(state, p0->reg_name, p1->reg_name);
   }
   else if (p0->state == JIT_STACK && p1->state == JIT_STACK) {
      x86_mov_reg_mem_relative(state, __EAX, __EBP, p0->stack_offset,
                               p0->size);
      x86_cmp_reg_mem(state, __EAX, __EBP, p1->stack_offset, p1->size);
   }
   else if (p0->state == JIT_REGISTER && p1->state == JIT_STACK)
      x86_cmp_reg_mem(state, p0->reg_name, __EBP, p1->stack_offset, p1->size);
   else
      jit_abort(state, op, "cannot handle operand combination");

   jit_vcode_reg_t *r = jit_get_vcode_reg(state, vcode_get_result(op));

   if (!!(r->flags & JIT_F_COND_INPUT) && jit_is_ephemeral(r, op)) {
      // Can just leave the result in the flags bits
      r->state = JIT_FLAGS;
   }
   else {
      jit_mach_reg_t *mreg = jit_alloc_reg(state, op, vcode_get_result(op));
      x86_setbyte(state, __EAX, X86_CMP_EQ);
      x86_movzbl(state, mreg->name, __EAX);

      r->state = JIT_REGISTER;
      r->reg_name = mreg->name;
   }
}

static void jit_op_cond(jit_state_t *state, int op)
{
   vcode_block_t target = vcode_get_target(op, 0);
   ptrdiff_t diff = jit_jump_target(state, target);

   jit_patch_t patch;

   jit_vcode_reg_t *input = jit_get_vcode_reg(state, vcode_get_arg(op, 0));
   switch (input->state) {
   case JIT_REGISTER:
      assert(input->state == JIT_REGISTER);
      x86_cmp_reg_imm(state, input->reg_name, 0);
      patch = x86_jcc_rel(state, X86_CMP_NE, diff);
      break;

   case JIT_FLAGS:
      switch (vcode_get_cmp(jit_previous_op(op))) {
      case VCODE_CMP_EQ:
         patch = x86_jcc_rel(state, X86_CMP_EQ, diff);
         break;
      case VCODE_CMP_GT:
         patch = x86_jcc_rel(state, X86_CMP_GT, diff);
         break;
      default:
         jit_abort(state, op, "cannot handle comparison");
      }
      break;

   default:
      jit_abort(state, op, "cannot generate code for cond");
   }

   if (diff == PTRDIFF_MAX)
      jit_fixup_jump_later(state, patch, target);

   vcode_block_t alt_target = vcode_get_target(op, 1);
   if (alt_target == vcode_active_block() + 1)
      return;

   ptrdiff_t diff2 = jit_jump_target(state, alt_target);
   jit_patch_t patch2 = x86_jmp_rel(state, diff2);

   if (diff2 == PTRDIFF_MAX)
      jit_fixup_jump_later(state, patch2, alt_target);
}

static void jit_op_store(jit_state_t *state, int op)
{
   vcode_var_t dest = vcode_get_address(op);
   const signed stack_offset = state->var_offsets[vcode_var_index(dest)];

   jit_vcode_reg_t *src = jit_get_vcode_reg(state, vcode_get_arg(op, 0));
   switch (src->state) {
   case JIT_REGISTER:
      x86_mov_mem_reg_relative(state, __EBP, stack_offset, src->reg_name,
                               src->size);
      break;
   case JIT_CONST:
      x86_mov_mem_imm(state, __EBP, stack_offset, src->value, src->size);
      break;
   case JIT_STACK:
      x86_mov_reg_mem_relative(state, __EAX, __EBP, src->stack_offset,
                               src->size);
      x86_mov_mem_reg_relative(state, __EBP, stack_offset, __EAX, src->size);
      break;
   default:
      jit_abort(state, op, "cannot store r%d", vcode_get_arg(op, 0));
   }
}

static void jit_op_load(jit_state_t *state, int op)
{
   vcode_var_t src = vcode_get_address(op);
   const signed stack_offset = state->var_offsets[vcode_var_index(src)];

   vcode_reg_t result_reg = vcode_get_result(op);
   jit_vcode_reg_t *dest = jit_get_vcode_reg(state, result_reg);

   jit_mach_reg_t *mreg = jit_alloc_reg(state, op, result_reg);
   assert(mreg != NULL);  // TODO

   x86_mov_reg_mem_relative(state, mreg->name, __EBP, stack_offset, dest->size);

   dest->state = JIT_REGISTER;
   dest->reg_name = mreg->name;
}

static void jit_op_bounds(jit_state_t *state, int op)
{

}

static void jit_op_dynamic_bounds(jit_state_t *state, int op)
{

}

static void jit_op_unwrap(jit_state_t *state, int op)
{
   jit_vcode_reg_t *src = jit_get_vcode_reg(state, vcode_get_arg(op, 0));
   assert(src->state == JIT_STACK);

   vcode_reg_t result_reg = vcode_get_result(op);
   jit_vcode_reg_t *dest = jit_get_vcode_reg(state, result_reg);
   jit_mach_reg_t *mreg = jit_alloc_reg(state, op, result_reg);

   x86_mov_reg_mem_relative(state, mreg->name, __EBP,
                            src->stack_offset, sizeof(void *));

   dest->state = JIT_REGISTER;
   dest->reg_name = mreg->name;
}

static void jit_op_uarray_dir(jit_state_t *state, int op)
{
   jit_vcode_reg_t *src = jit_get_vcode_reg(state, vcode_get_arg(op, 0));
   assert(src->state == JIT_STACK);

   vcode_reg_t result_reg = vcode_get_result(op);
   jit_vcode_reg_t *dest = jit_get_vcode_reg(state, result_reg);

   int offset = src->stack_offset + offsetof(uarray_t, dims[0].dir);

   jit_mach_reg_t *mreg;
   if (dest->use_count >= 2 && (mreg = jit_alloc_reg(state, op, result_reg))) {
      dest->state = JIT_REGISTER;
      dest->reg_name = mreg->name;

      // TODO: use sign-extend load
      x86_cmp_mem_imm(state, __EBP, offset, 1, 1);
      x86_setbyte(state, __EAX, X86_CMP_EQ);
      x86_movzbl(state, mreg->name, __EAX);
   }
   else {
      dest->state = JIT_STACK;
      dest->stack_offset = offset;
   }
}

static void jit_op_uarray_left(jit_state_t *state, int op)
{
   jit_vcode_reg_t *src = jit_get_vcode_reg(state, vcode_get_arg(op, 0));
   assert(src->state == JIT_STACK);

   vcode_reg_t result_reg = vcode_get_result(op);
   jit_vcode_reg_t *dest = jit_get_vcode_reg(state, result_reg);

   dest->state = JIT_STACK;
   dest->stack_offset = src->stack_offset + offsetof(uarray_t, dims[0].left);
}

static void jit_op_uarray_right(jit_state_t *state, int op)
{
   jit_vcode_reg_t *src = jit_get_vcode_reg(state, vcode_get_arg(op, 0));
   assert(src->state == JIT_STACK);

   vcode_reg_t result_reg = vcode_get_result(op);
   jit_vcode_reg_t *dest = jit_get_vcode_reg(state, result_reg);

   dest->state = JIT_STACK;
   dest->stack_offset = src->stack_offset + offsetof(uarray_t, dims[0].right);
}

static void jit_op_select(jit_state_t *state, int op)
{
   jit_vcode_reg_t *src = jit_get_vcode_reg(state, vcode_get_arg(op, 0));
   switch (src->state) {
   case JIT_STACK:
      x86_cmp_mem_imm(state, __EBP, src->stack_offset, 0, src->size);
      break;
   case JIT_REGISTER:
      x86_cmp_reg_imm(state, src->reg_name, 0);
      break;
   default:
      jit_abort(state, op, "cannot select on r%d", vcode_get_arg(op, 0));
   }

   vcode_reg_t result_reg = vcode_get_result(op);
   jit_vcode_reg_t *dest = jit_get_vcode_reg(state, result_reg);

   x86_reg_t reg_name;
   jit_mach_reg_t *mreg = jit_alloc_reg(state, op, result_reg);
   if (mreg == NULL) {
      jit_spill(state, dest);
      reg_name = __EAX;
   }
   else {
      dest->state = JIT_REGISTER;
      dest->reg_name = reg_name = mreg->name;
   }

   jit_move_to_reg(state, reg_name,
                   jit_get_vcode_reg(state, vcode_get_arg(op, 1)));

   jit_vcode_reg_t *p2 = jit_get_vcode_reg(state, vcode_get_arg(op, 2));
   switch (p2->state) {
   case JIT_REGISTER:
      x86_cmov_reg_reg(state, reg_name, p2->reg_name, X86_CMP_EQ);
      break;

   case JIT_STACK:
      x86_cmov_reg_mem(state, reg_name, __EBP, p2->stack_offset, X86_CMP_EQ);
      break;

   case JIT_CONST:
      if (dest->state == JIT_STACK) {
         jit_patch_t patch = x86_jcc_rel(state, X86_CMP_NE, PTRDIFF_MAX);
         x86_mov_reg_imm(state, reg_name, p2->value);
         jit_patch_jump(patch, state->code_wptr);
      }
      else {
         x86_mov_reg_imm(state, __EAX, p2->value);
         x86_cmov_reg_reg(state, reg_name, __EAX, X86_CMP_EQ);
      }
      break;

   default:
      jit_abort(state, op, "cannot conditional move r%d (state %d)",
                p2->vcode_reg, p2->state);
   }

   if (dest->state == JIT_STACK)
      x86_mov_mem_reg_relative(state, __EBP, dest->stack_offset, reg_name,
                               dest->size);
}

static void jit_op_cast(jit_state_t *state, int op)
{
   vcode_reg_t src_reg = vcode_get_arg(op, 0);
   jit_vcode_reg_t *src = jit_get_vcode_reg(state, src_reg);

   vcode_reg_t dest_reg = vcode_get_result(op);
   jit_vcode_reg_t *dest = jit_get_vcode_reg(state, dest_reg);

   const vtype_kind_t to_kind = vtype_kind(vcode_get_type(op));
   const vtype_kind_t from_kind = vcode_reg_kind(src_reg);

   const bool integer_conversion =
      (to_kind == VCODE_TYPE_OFFSET || to_kind == VCODE_TYPE_INT)
      && (from_kind == VCODE_TYPE_OFFSET || from_kind == VCODE_TYPE_INT);

   if (integer_conversion) {
      if (src->state == JIT_STACK && dest->use_count <= 2) {
         // No need to allocate a register
         dest->state = JIT_STACK;
         dest->stack_offset = src->stack_offset;
         return;
      }
      else if (jit_can_reuse_reg(src, op)) {
         dest->state = JIT_REGISTER;
         dest->reg_name = src->reg_name;
         jit_claim_mach_reg(dest);
         return;
      }
   }

   x86_reg_t reg_name;
   jit_mach_reg_t *mreg = jit_alloc_reg(state, op, dest_reg);
   if (mreg == NULL) {
      jit_spill(state, dest);
      reg_name = __EAX;
   }
   else {
      dest->state = JIT_REGISTER;
      dest->reg_name = reg_name = mreg->name;
   }

   switch (vtype_kind(vcode_get_type(op))) {
   case VCODE_TYPE_INT:
   case VCODE_TYPE_OFFSET:
      switch (vcode_reg_kind(src_reg)) {
      case VCODE_TYPE_OFFSET:
      case VCODE_TYPE_INT:
         jit_move_to_reg(state, dest->reg_name, src);
         break;
      default:
         jit_abort(state, op, "cannot cast r%d to int", src_reg);
      }
      break;

   default:
      jit_abort(state, op, "cannot generate code for cast");
   }

   if (dest->state == JIT_STACK)
      x86_mov_mem_reg_relative(state, __EBP, dest->stack_offset, reg_name,
                               dest->size);
}

void jit_op(jit_state_t *state, int op)
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
   case VCODE_OP_ADD:
      jit_op_add(state, op);
      break;
   case VCODE_OP_MUL:
      jit_op_mul(state, op);
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
   case VCODE_OP_DEBUG_INFO:
      return;
   case VCODE_OP_STORE:
      jit_op_store(state, op);
      break;
   case VCODE_OP_LOAD:
      jit_op_load(state, op);
      break;
   case VCODE_OP_BOUNDS:
      jit_op_bounds(state, op);
      break;
   case VCODE_OP_DYNAMIC_BOUNDS:
      jit_op_dynamic_bounds(state, op);
      break;
   case VCODE_OP_UNWRAP:
      jit_op_unwrap(state, op);
      break;
   case VCODE_OP_UARRAY_DIR:
      jit_op_uarray_dir(state, op);
      break;
   case VCODE_OP_UARRAY_LEFT:
      jit_op_uarray_left(state, op);
      break;
   case VCODE_OP_UARRAY_RIGHT:
      jit_op_uarray_right(state, op);
      break;
   case VCODE_OP_SELECT:
      jit_op_select(state, op);
      break;
   case VCODE_OP_CAST:
      jit_op_cast(state, op);
      break;
   case VCODE_OP_SUB:
      jit_op_sub(state, op);
      break;
   default:
      jit_abort(state, op, "cannot JIT op %s",
                vcode_op_string(vcode_get_op(op)));
   }
}

void jit_bind_params(jit_state_t *state)
{
   const int nparams = vcode_count_params();
   for (int i = 0; i < nparams; i++) {
      jit_vcode_reg_t *r = jit_get_vcode_reg(state, vcode_param_reg(i));

      switch (vtype_kind(vcode_param_type(i))) {
      case VCODE_TYPE_INT:
         {
            bool have_reg = false;
            for (int j = 0; j < ARRAY_LEN(x86_64_regs); j++) {
               if (x86_64_regs[j].arg_index == i) {
                  x86_64_regs[j].usage = i;

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
         break;

      case VCODE_TYPE_UARRAY:
         r->state = JIT_STACK;
         r->stack_offset = state->params_size + 3 * sizeof(void *);
         r->flags |= JIT_F_PARAMETER;

         state->params_size += jit_size_of(vcode_param_type(i));
         break;

      default:
         jit_abort(state, -1, "cannot handle parameters with type %d",
                   vtype_kind(vcode_param_type(i)));
      }
   }
}

void jit_reset(jit_state_t *state)
{
   for (int i = 0; i < ARRAY_LEN(x86_64_regs); i++)
      x86_64_regs[i].usage = VCODE_INVALID_REG;
}

void jit_signal_handler(int signum, void *extra)
{
   ucontext_t *uc = (ucontext_t*)extra;
   uintptr_t rip = uc->uc_mcontext.gregs[REG_RIP];

   if (signum == SIGTRAP)
      rip--;

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

   if (signum == SIGTRAP)
      color_printf("$red$Hit JIT breakpoint$$\n\n");
   else
      color_printf("$red$Crashed while running JIT compiled code$$\n\n");

   printf("RAX %16llx    RSP %16llx    RIP %16llx\n",
          uc->uc_mcontext.gregs[REG_RAX], uc->uc_mcontext.gregs[REG_RSP],
          uc->uc_mcontext.gregs[REG_RIP]);
   printf("RBX %16llx    RBP %16llx    EFL %16llx\n",
          uc->uc_mcontext.gregs[REG_RBX], uc->uc_mcontext.gregs[REG_RBP],
          uc->uc_mcontext.gregs[REG_EFL]);
   printf("RCX %16llx    RSI %16llx\n",
          uc->uc_mcontext.gregs[REG_RCX], uc->uc_mcontext.gregs[REG_RSI]);
   printf("RDX %16llx    RDI %16llx\n",
          uc->uc_mcontext.gregs[REG_RDX], uc->uc_mcontext.gregs[REG_RDI]);

   printf("\n");

   const uint32_t *const stack_top =
      (uint32_t *)((uc->uc_mcontext.gregs[REG_RBP] + 3) & ~7);

   for (int i = (jc->stack_size + 15) / 16; i > 0; i--) {
      const uint32_t *p = stack_top - i * 4;
      printf("%p  RBP-0x%-2x  %08x %08x %08x %08x\n", p, i * 16,
             p[0], p[1], p[2], p[3]);
   }

   for (int i = 0; i <= (jc->params_size + 15) / 16; i++) {
      const uint32_t *p = stack_top + i * 4;
      printf("%p  RBP+0x%-2x  %08x %08x %08x %08x\n", p, i * 16,
             p[0], p[1], p[2], p[3]);
   }
}
