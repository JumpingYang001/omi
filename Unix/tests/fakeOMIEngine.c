#include <stdio.h>
#include <unistd.h>
int main(int argc, char *argv[], char **envp) {
  printf("Sub program started\n");
  system("env");
  printf("arguments:\n");
  int j;
  for (j = 0; j < argc; j++)
       printf("argv[%d]: %s\n", j, argv[j]);
  for (j = 0; j < sizeof(envp); j++)
       printf("envp[%d]: %s\n", j, envp[j]);
  printf("Sub program ended\n");
  return -1;
}