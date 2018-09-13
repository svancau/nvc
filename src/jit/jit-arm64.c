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
