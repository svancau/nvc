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

#ifndef _JIT_PRIV_H
#define _JIT_PRIV_H

#include "jit.h"
#include "vcode.h"

typedef struct {
   void    *ptr;
   struct {
      int32_t left;
      int32_t right;
      int8_t  dir;
   } dims[1];
} uarray_t;

typedef enum {
   REG_F_CALLEE_SAVE = (1 << 0),
   REG_F_RESULT      = (1 << 1),
   REG_F_SCRATCH     = (1 << 2),
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
   JIT_FLAGS,
} jit_vcode_reg_state_t;

typedef enum {
   JIT_F_RETURNED    = (1 << 0),
   JIT_F_BLOCK_LOCAL = (1 << 1),
   JIT_F_PARAMETER   = (1 << 2),
   JIT_F_COND_INPUT  = (1 << 3),
} jit_vcode_reg_flags_t;

typedef struct {
   vcode_reg_t           vcode_reg;
   jit_vcode_reg_state_t state;
   jit_vcode_reg_flags_t flags;
   vcode_block_t         defn_block;
   int                   lifetime;
   int                   use_count;
   unsigned              size;
   union {
      int64_t  value;
      signed   stack_offset;
      unsigned reg_name;
   };
} jit_vcode_reg_t;

typedef struct {
   uint8_t *pc;
   unsigned offset;
} jit_patch_t;

typedef struct {
   jit_patch_t   patch;
   vcode_block_t target;
} jit_fixup_t;

typedef struct {
   void            *code_base;
   uint8_t         *code_wptr;
   size_t           code_len;
   jit_vcode_reg_t *vcode_regs;
   uint8_t        **block_ptrs;
   unsigned        *var_offsets;
   jit_fixup_t     *patches;
   size_t           patch_wptr;
   unsigned         stack_size;
   unsigned         stack_wptr;
   unsigned         params_size;
   vcode_unit_t     unit;
} jit_state_t;

#define __(...) do {                                                    \
      const uint8_t __b[] = { __VA_ARGS__ };                            \
      jit_emit(state, __b, ARRAY_LEN(__b));                             \
   } while (0)

////////////////////////////////////////////////////////////
// Implemented by shared code

__attribute__((noreturn))
void jit_abort(jit_state_t *state, int mark_op, const char *fmt, ...);

jit_state_t *jit_find_in_cache(void *mem);
void jit_emit(jit_state_t *state, const uint8_t *bytes, size_t len);
void jit_dump(jit_state_t *state, int mark_op);
void jit_reset(jit_state_t *state);

unsigned jit_align_object(size_t size, unsigned ptr);
bool jit_is_no_op(int op);
int jit_next_op(int op);
int jit_previous_op(int op);
bool jit_is_ephemeral(jit_vcode_reg_t *r, int op);
size_t jit_size_of(vcode_type_t type);
jit_vcode_reg_t *jit_get_vcode_reg(jit_state_t *state, vcode_reg_t reg);

////////////////////////////////////////////////////////////
// Implemented by CPU-specific code

void jit_patch_jump(jit_patch_t patch, uint8_t *target);
void jit_bind_params(jit_state_t *state);
void jit_prologue(jit_state_t *state);
void jit_epilogue(jit_state_t *state);
void jit_op(jit_state_t *state, int op);

#endif  // _JIT_PRIV_H
