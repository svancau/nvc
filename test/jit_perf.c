#include "lib.h"
#include "phase.h"
#include "common.h"
#include "vcode.h"
#include "jit/jit.h"

#include <assert.h>
#include <stdlib.h>
#include <time.h>

static void test_fact(void)
{
   extern int fact(int);

   vcode_unit_t unit = vcode_find_unit(ident_new("WORK.JITPERF.FACT(N)N"));
   assert(unit);

   uint32_t (*fn)(int) = jit_vcode_unit(unit);
   assert(fn);

   assert((*fn)(4) == 24);
   assert(fact(4) == 24);

   uint64_t cstart = get_timestamp_us();
   for (int i = 0; i < 100000000; i++)
      fact(i & 15);
   double ctime = (get_timestamp_us() - cstart) / 1000.0;

   uint64_t vstart = get_timestamp_us();
   for (int i = 0; i < 100000000; i++)
      (*fn)(i & 15);
   double vtime = (get_timestamp_us() - vstart) / 1000.0;

   printf("Factorial   C: %.1f ms; VHDL: %1.f ms\n", ctime, vtime);
}

int main(int argc, char **argv)
{
   term_init();
   register_trace_signal_handlers();

   const char *lib_dir = getenv("LIB_DIR");
   if (lib_dir)
      lib_add_search_path(lib_dir);

   opt_set_int("bootstrap", 0);
   opt_set_int("cover", 0);
   opt_set_int("unit-test", 0);
   opt_set_str("dump-vcode", NULL);
   opt_set_int("ignore-time", 0);
   opt_set_int("verbose", 0);
   intern_strings();

   lib_t test = lib_tmp("work");
   lib_set_work(test);

   set_standard(STD_93);
   set_relax_rules(0);

   input_from_file(TESTDIR "/perf/jitperf.vhd");

   tree_t pack = parse();
   if (pack == NULL)
      return 1;

   if (!sem_check(pack))
      return 1;

   simplify(pack, 0);
   bounds_check(pack);
   lower_unit(pack);

   tree_t body = parse();
   if (body == NULL)
      return 1;

   if (!sem_check(body))
      return 1;

   simplify(body, 0);
   bounds_check(body);
   lower_unit(body);

   test_fact();

   return 0;
}
