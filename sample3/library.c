// gcc -shared -x c -o library.so -fPIC library.c

#include <stdio.h>

int memory[1000];
int program_counter = 0;

void do_nothing() {}

void toggle(){
  memory[program_counter + 1] = 1 - memory[program_counter + 1];
}

void print_memory(){
  for (int i=0; i<60; i++){
    printf("%i", memory[i]);
  }
  printf("\n");
}

void (*primitives[])(void) = {do_nothing, toggle};
