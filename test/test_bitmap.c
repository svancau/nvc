#include "util.h"
#include "test_util.h"
#include "rt/bitmap.h"

#include <check.h>

START_TEST(test_small)
{
   bitmap_t *b = bitmap_new(50);

   fail_if(bitmap_isset(b, 1));
   bitmap_set(b, 20);
   fail_if(bitmap_isset(b, 1));
   fail_unless(bitmap_isset(b, 20));
   bitmap_set(b, 33);
   fail_if(bitmap_isset(b, 1));
   fail_unless(bitmap_isset(b, 33));

   bitmap_free(b);
}
END_TEST

START_TEST(test_rand)
{
   bitmap_t *b = bitmap_new(1000);

   bool state[1000];
   for (int i = 0; i < 1000; i++) {
      if ((state[i] = (rand() % 2)))
         bitmap_set(b, i);
   }

   for (int i = 0; i < 1000; i++) {
      if (state[i])
         fail_unless(bitmap_isset(b, i));
      else
         fail_if(bitmap_isset(b, i));
   }

   bitmap_free(b);
}
END_TEST

int main(void)
{
   Suite *s = suite_create("bitmap");

   TCase *tc_core = nvc_unit_test();
   tcase_add_test(tc_core, test_small);
   tcase_add_test(tc_core, test_rand);
   suite_add_tcase(s, tc_core);

   return nvc_run_test(s);
}
