#include <gmp.h>


typedef mpz_t RSA_key; 

// Generate pair of RSA keys with e=65537. 
void RSA_generate_keys(int bits, RSA_key public_key, RSA_key private_key);

// Init constants needed for RSA encryption. Should be called at the beginning of the program.
void RSA_init();
