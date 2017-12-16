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

START_TEST(test_next_set)
{
   bitmap_t *b = bitmap_new(100);

   bitmap_set(b, 5);
   bitmap_set(b, 10);
   bitmap_set(b, 11);
   bitmap_set(b, 31);
   bitmap_set(b, 63);
   bitmap_set(b, 64);
   bitmap_set(b, 99);

   int search = -1;
   fail_unless((search = bitmap_next_set(b, search + 1)) == 5);
   fail_unless((search = bitmap_next_set(b, search + 1)) == 10);
   fail_unless((search = bitmap_next_set(b, search + 1)) == 11);
   fail_unless((search = bitmap_next_set(b, search + 1)) == 31);
   fail_unless((search = bitmap_next_set(b, search + 1)) == 63);
   fail_unless((search = bitmap_next_set(b, search + 1)) == 64);
   fail_unless((search = bitmap_next_set(b, search + 1)) == 99);
   fail_unless((search = bitmap_next_set(b, search + 1)) == -1);

   bitmap_zero(b);
   fail_unless(bitmap_next_set(b, 0) == -1);

   bitmap_set(b, 86);
   fail_unless(bitmap_next_set(b, 0) == 86);

   bitmap_zero(b);

   bitmap_set(b, 31);
   fail_unless(bitmap_next_set(b, 32) == -1);

   bitmap_free(b);

}
END_TEST

int main(void)
{
   Suite *s = suite_create("bitmap");

   TCase *tc_core = nvc_unit_test();
   tcase_add_test(tc_core, test_small);
   tcase_add_test(tc_core, test_rand);
   tcase_add_test(tc_core, test_next_set);
   suite_add_tcase(s, tc_core);

   return nvc_run_test(s);
}
