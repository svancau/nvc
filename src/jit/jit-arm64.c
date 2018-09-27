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

#include <assert.h>

typedef enum {
   __W0 = 0x00, __W1 = 0x01, __W2 = 0x02, __W3 = 0x03,
   __W30 = 0x1e, __WZR = 0x1f, __WSP = 0x1f,

   __X0 = 0x20, __X1 = 0x21, __X2 = 0x22, __X3 = 0x23,
   __X30 = 0x3e, __XZR = 0x3f, __SP = 0x3f
} arm64_reg_t;

typedef enum {
   ARM64_COND_EQ = 0x0,
   ARM64_COND_NE = 0x1,
   ARM64_COND_CS = 0x2,
   ARM64_COND_CC = 0x3,
   ARM64_COND_MI = 0x4,
   ARM64_COND_PL = 0x5,
   ARM64_COND_VS = 0x6,
   ARM64_COND_VC = 0x7,
   ARM64_COND_HI = 0x8,
   ARM64_COND_LS = 0x9,
   ARM64_COND_GE = 0xa,
   ARM64_COND_LT = 0xb,
   ARM64_COND_GT = 0xc,
   ARM64_COND_LE = 0xd,
   ARM64_COND_AL = 0xe,
} arm64_cond_t;

#define __SF(reg) (!!((reg) & 0x20) << 31)
#define __R(reg) ((reg) & 0x1f)
#define __IMM16(imm) ((imm) & 0xffff)
#define __IMM12(imm) ((imm) & 0xfff)

jit_mach_reg_t mach_regs[] = {
   {
      .name = __W0,
      .text = "W0",
      .flags = REG_F_RESULT,
      .arg_index = 0
   },
   {
      .name = __W1,
      .text = "W1",
      .flags = 0,
      .arg_index = 1
   },
   {
      .name = __W2,
      .text = "W2",
      .flags = 0,
      .arg_index = 2
   },
   {
      .name = __W3,
      .text = "W3",
      .flags = 0,
      .arg_index = 3
   },
};

const size_t num_mach_regs = ARRAY_LEN(mach_regs);

static void arm64_emit(jit_state_t *state, uint32_t opcode)
{
   const uint8_t bytes[] = {
      opcode & 0xff,
      (opcode >> 8) & 0xff,
      (opcode >> 16) & 0xff,
      (opcode >> 24) & 0xff
   };
   jit_emit(state, bytes, ARRAY_LEN(bytes));
}

static void __arm64_uncond_branch(jit_state_t *state, int opc, int op2,
                                  int op3, int rn, int op4)
{
   const uint32_t encoding =
      (0x6b << 25) | (opc << 21) | (op2 << 16) | (op3 << 10)
      | (__R(rn) << 5) | op4;
   arm64_emit(state, encoding);
}

static void arm64_ret(jit_state_t *state)
{
   __arm64_uncond_branch(state, 0x2, 0x1f, 0, __X30, 0);
}

static void arm64_add_imm(jit_state_t *state, arm64_reg_t dest,
                          arm64_reg_t operand, int64_t imm)
{
   assert(imm >= 0);
   assert(imm < 4096);

   const uint32_t encoding =
      __SF(dest)
      | (0x11 << 24)
      | (0x00 << 22)   // shift
      | (__IMM12(imm) << 10)
      | (__R(operand) << 5)
      | __R(dest);
   arm64_emit(state, encoding);
}

static void arm64_mov_reg_imm(jit_state_t *state, arm64_reg_t dest,
                              int64_t imm)
{
   const uint32_t encoding =
      __SF(dest)
      | (0x2 << 29)                // opc
      | (0x25 << 23)               // Move wide
      | (0 << 21)                  // hw
      | (__IMM16(imm) << 5)        // imm16
      | __R(dest);                 // Rd
   arm64_emit(state, encoding);
}

static void arm64_mov_reg_reg(jit_state_t *state, arm64_reg_t dest,
                              arm64_reg_t src)
{
   if (src == dest)
      return;

   const uint32_t encoding =
      __SF(dest)
      | (0x1 << 29)
      | (0xa << 24)
      | (0 << 22)   // shift
      | (0 << 21)   // N
      | (__R(src) << 16)
      | (0x1f << 5)  // Rn
      | __R(dest);
   arm64_emit(state, encoding);
}

void jit_prologue(jit_state_t *state)
{
}

void jit_epilogue(jit_state_t *state)
{
}

void jit_patch_jump(jit_patch_t patch, uint8_t *target)
{
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
         arm64_mov_reg_reg(state, __W0, r->reg_name);
         break;
      case JIT_CONST:
         arm64_mov_reg_imm(state, __W0, r->value);
         break;
         //case JIT_STACK:
         //x86_mov_reg_mem_relative(state, __EAX, __EBP,
         //                         r->stack_offset, r->size);
         //break;
      default:
         jit_abort(state, op, "cannot return r%d", result_reg);
      }
   }

   jit_epilogue(state);
   arm64_ret(state);
}

static void jit_op_addi(jit_state_t *state, int op)
{
   jit_vcode_reg_t *p0 = jit_get_vcode_reg(state, vcode_get_arg(op, 0));
   jit_vcode_reg_t *result = jit_get_vcode_reg(state, vcode_get_result(op));

   assert(p0->state == JIT_REGISTER);

   unsigned reg_name;
   jit_mach_reg_t *mreg = jit_reuse_reg(state, op, vcode_get_result(op),
                                        jit_reuse_hint(p0));
   if (mreg != NULL) {
      result->state = JIT_REGISTER;
      reg_name = result->reg_name = mreg->name;
   }
   else {
      assert(false);
      //jit_spill(state, result);
      //reg_name = __EAX;
   }

   arm64_add_imm(state, reg_name, p0->reg_name, vcode_get_value(op));

   if (result->state == JIT_STACK)
      assert(false);
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
#if 0
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
#endif
   case VCODE_OP_COMMENT:
   case VCODE_OP_DEBUG_INFO:
      return;
#if 0
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
   case VCODE_OP_RANGE_NULL:
      jit_op_range_null(state, op);
      break;
#endif
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
            for (int j = 0; j < ARRAY_LEN(mach_regs); j++) {
               if (mach_regs[j].arg_index == i) {
                  mach_regs[j].usage = i;

                  r->state = JIT_REGISTER;
                  r->reg_name = mach_regs[j].name;
                  r->flags |= JIT_F_PARAMETER;

                  have_reg = true;
                  break;
               }
            }

            if (!have_reg)
               jit_abort(state, -1, "cannot find register for parameter %d", i);
         }
         break;

      default:
         jit_abort(state, -1, "cannot handle parameters with type %d",
                   vtype_kind(vcode_param_type(i)));
      }
   }
}

void jit_signal_handler(int signum, void *extra)
{
#if 0
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
#endif
}
