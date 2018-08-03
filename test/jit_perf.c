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
#include <string.h>

typedef struct {
   void    *ptr;
   struct {
      int32_t left;
      int32_t right;
      int8_t  dir;
   } dims[1];
} uarray_t;

void _bounds_fail(void)
{
   assert(false);
}

static void print_result(const char *name, uint64_t ctime,
                         uint64_t ltime, uint64_t jtime)
{
   const double cms = ctime / 1000.0;
   const double lms = ltime / 1000.0;
   const double jms = jtime / 1000.0;

   printf("%-10s C: %2.1f ms; LLVM: %.1f ms (%.1fx); JIT: %.1f ms (%.1fx)\n",
          name, cms, lms, lms / cms, jms, jms / cms);
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

   const int REPS = 10000000;

   uint64_t cstart = get_timestamp_us();
   for (int i = 0; i < REPS; i++)
      fact(i & 15);
   double ctime = get_timestamp_us() - cstart;

   uint64_t vstart = get_timestamp_us();
   for (int i = 0; i < REPS; i++)
      (*fn)(i & 15);
   double vtime = get_timestamp_us() - vstart;

   uint64_t lstart = get_timestamp_us();
   for (int i = 0; i < REPS; i++)
      (*lfn)(i & 15);
   double ltime = get_timestamp_us() - lstart;

   print_result("Factorial", ctime, ltime, vtime);
}

static void test_sum(void)
{
   extern int32_t sum(const int32_t*, int);

   const char *func_name =
      "JITPERFLIB.JITPERF.SUM(29JITPERFLIB.JITPERF.INT_VECTOR)I";

   vcode_unit_t unit = vcode_find_unit(ident_new(func_name));
   assert(unit);

   int32_t (*jfn)(uarray_t) = jit_vcode_unit(unit);
   assert(jfn);

   int32_t (*lfn)(uarray_t) = dlsym(NULL, func_name);
   assert(lfn);

   static const int N = 1024;
   static const int REPS = 500000;
   int32_t *data LOCAL = xmalloc(N * sizeof(int32_t));

   int expect = 0;
   for (int i = 0; i < N; i++)
      expect += (data[i] = random());

   uarray_t input = {
      .ptr = data,
      .dims = { { 0, N - 1, RANGE_TO } }
   };

   assert((*lfn)(input) == expect);
   assert((*sum)(data, N) == expect);

   uint64_t cstart = get_timestamp_us();
   for (int i = 0; i < REPS; i++)
      sum(data, N);
   uint64_t ctime = get_timestamp_us() - cstart;

   uint64_t lstart = get_timestamp_us();
   for (int i = 0; i < REPS; i++)
      (*lfn)(input);
   uint64_t ltime = get_timestamp_us() - lstart;

   uint64_t jstart = get_timestamp_us();
   for (int i = 0; i < REPS; i++)
      (*jfn)(input);
   uint64_t jtime = get_timestamp_us() - jstart;

   print_result("Sum", ctime, ltime, jtime);
}

int main(int argc, char **argv)
{
   term_init();
   register_trace_signal_handlers();

   const char *lib_dir = getenv("LIB_DIR");
   if (lib_dir)
      lib_add_search_path(lib_dir);

   srandom((unsigned)time(NULL));

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

   if (argc == 1 || strcmp(argv[1], "fact") == 0)
      test_fact();

   if (argc == 1 || strcmp(argv[1], "sum") == 0)
      test_sum();

   return 0;
}
