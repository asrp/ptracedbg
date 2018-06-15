// gcc -fPIC sample1.c

#include <stdio.h>
#include <unistd.h>

int my_var;
typedef int (*func_ptr_t)(void);

void test_function(){
  printf("Called test_function! Probably from the debugger.\n");
  printf("my_var=%i\n", my_var);
}

int main(){
  printf("Starting main loop\n");
  my_var = 1;
  while (1){
    usleep(100000);
  }
}
