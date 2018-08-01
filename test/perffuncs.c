#include <stdint.h>
#include <stddef.h>

int fact(int x)
{
   int result = 1;
   for (int i = 2; i <= x; i++)
      result *= i;
   return result;
}

int32_t sum(const int32_t *data, int len)
{
   int32_t result = 0;
   for (int i = 0; i < len; i++)
      result += data[i];
   return result;
}
