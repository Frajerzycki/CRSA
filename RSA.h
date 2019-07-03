#include <gmp.h>


typedef mpz_t RSA_key; 

// Generate pair of RSA keys with e=65537. 
void RSA_generate_keys(int bits, RSA_key public_key, RSA_key private_key);

// Init constants needed for RSA encryption. Should be called at the beginning of the program.
void RSA_init();
//
void RSA_encrypt(char* message, char* ciphertext, size_t bytes_to_encrypt, size_t *encrypted_bytes, RSA_key public_key);
//
void RSA_decrypt(char* ciphertext, char* message, size_t bytes_to_decrypt, size_t *decrypted_bytes, RSA_key public_key, RSA_key private_key);
//
size_t RSA_size(RSA_key public_key);

