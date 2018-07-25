#include "lib.h"
#include "phase.h"
#include "common.h"
#include "vcode.h"
#include "jit/jit.h"

#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include <dlfcn.h>

void _bounds_fail(void)
{
   assert(false);
}

static void test_fact(void)
{
   extern int fact(int);

   vcode_unit_t unit =
      vcode_find_unit(ident_new("JITPERFLIB.JITPERF.FACT(N)N"));
   assert(unit);

   uint32_t (*fn)(int) = jit_vcode_unit(unit);
   assert(fn);

   uint32_t (*lfn)(int) = dlsym(NULL, "JITPERFLIB.JITPERF.FACT(N)N");
   assert(lfn);

   assert((*fn)(4) == 24);
   assert((*lfn)(4) == 24);
   assert(fact(4) == 24);

   uint64_t cstart = get_timestamp_us();
   for (int i = 0; i < 100000000; i++)
      fact(i & 15);
   double ctime = (get_timestamp_us() - cstart) / 1000.0;

   uint64_t vstart = get_timestamp_us();
   for (int i = 0; i < 100000000; i++)
      (*fn)(i & 15);
   double vtime = (get_timestamp_us() - vstart) / 1000.0;

   uint64_t lstart = get_timestamp_us();
   for (int i = 0; i < 100000000; i++)
      (*lfn)(i & 15);
   double ltime = (get_timestamp_us() - lstart) / 1000.0;

   printf("Factorial   C: %.1f ms; JIT: %.1f ms; LLVM: %.1f\n",
          ctime, vtime, ltime);
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
   opt_set_int("optimise", 2);
   opt_set_int("dump-llvm", 0);
   intern_strings();

   lib_t test = lib_new("JITPERFLIB", "jitperf");
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
   vcode_unit_t unit = lower_unit(body);
   cgen(body, unit);

   char sopath[PATH_MAX];
   lib_realpath(test, "_JITPERFLIB.JITPERF-body.so", sopath, sizeof(sopath));

   void *dlh = dlopen(sopath, RTLD_GLOBAL | RTLD_NOW);
   if (dlh == NULL) {
      fprintf(stderr, "%s: %s\n", sopath, dlerror());
      return 1;
   }

   test_fact();

   return 0;
}
