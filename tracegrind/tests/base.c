
#include <stdio.h>

volatile short a[7] = { 1,2,3,4,5,6,7 };
volatile static short b[7] = { 1,2,3,4,5,6,7 };

int main ( void )
{
  int i;
  short sum;
  for (i = 0; i < 7; i++) {
     sum += a[i] * b[i];
  }
  return 1 & ((unsigned int)sum / 1000000);
}
