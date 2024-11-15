#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "vlad_rusty_lib.h"

#ifdef __cplusplus
extern "C"
{
#endif

  // Boot function
  int main(void)
  {
    const char *result = get_ohai();
    printf ("%s\n", result);
    const char *result2 = say_hi("Vic");
    printf ("%s\n", result2);
    return 0;
  }

#ifdef __cplusplus
}
#endif