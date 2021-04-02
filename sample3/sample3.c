// gcc -rdynamic -fPIC -gdwarf-2 sample3.c -ldl

#include <stdio.h>
#include <unistd.h>

// Needed for backtrace printing on segfault
#include <signal.h>
#include <execinfo.h>
#include <stdlib.h>

#include <dlfcn.h>

int foobar = 12;
int count = -1;
int pid;
void* dlrun_once;
void* dllibrary;
typedef int (*int_func_ptr_t)(void);
typedef void (*void_func_ptr_t)(void);

void bt_sighandler(int sig, struct sigcontext ctx) {
  // "obselete" way, but with fewer imports
  void *trace[16];
  char **messages = (char **)NULL;
  int i, trace_size = 0;
  if (sig == SIGSEGV)
    printf("Got signal %d, faulty address is %p, "
           "from %p\n", sig, ctx.cr2, ctx.rip);
  else
    printf("Got signal %d\n", sig);

  trace_size = backtrace(trace, 16);
  /* overwrite sigaction with caller's address */
  trace[1] = (void *)ctx.rip;
  messages = backtrace_symbols(trace, trace_size);
  /* skip first stack frame (points here) */
  printf("[bt] Execution path:\n");
  for (i=1; i<trace_size; ++i)
    printf("[bt] %s\n", messages[i]);
  exit(0);
}

void register_signals(){
  struct sigaction sa;

  sa.sa_handler = (void *)bt_sighandler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;

  sigaction(SIGSEGV, &sa, NULL);

  // Ignore SIGCHLD
  struct sigaction sa2;
  sa2.sa_handler = SIG_IGN;
  sigemptyset(&sa2.sa_mask);
  sa2.sa_flags = 0;
  sigaction(SIGCHLD, &sa2, 0);
}

void test_function(){
  printf("Called test_function! Probably from the debugger.\n");
  printf("count=%i\n", count);
}

void reload_run_once(){
  if (dlrun_once != NULL) dlclose(dlrun_once);
  dlrun_once = dlopen("./run_once.so", RTLD_NOW);
}

void reload_library(){
  if (dllibrary != NULL) dlclose(dllibrary);
  dllibrary = dlopen("./library.so", RTLD_NOW);
}

void make_fork(){
  pid = fork();
  if (pid == 0) {raise(SIGSTOP); }
}

int main(){
  register_signals();
  reload_library();
  printf("Starting main loop\n");
  count = 0;
  while (1){
    count += 1;
    //printf("%i: Sleep loop %i\n", pid, count);
    usleep(100000);
  }
}
