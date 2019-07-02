#include <gmp.h>
#include <stdlib.h>
#include "RSA.h"

int main(int argc, char* argv[]) {
  if (argc < 2)
    return 0;
  RSA_init();
  RSA_key private_key, public_key; 
  RSA_generate_keys(atoi(argv[1]), public_key, private_key);
  gmp_printf("Public:\t%Zx\nPrivate:\t%Zx\n", public_key, private_key);
  return 0;
}


