#include <gmp.h>
#include <stdio.h>
#ifdef __linux__
#include <bsd/stdlib.h>
#else
#include <stdlib.h>
#endif
#include "RSA.h"
#include <string.h>

mpz_t e;

void random_number(size_t bytes, mpz_t destination) {
  char *buffer = malloc(bytes);
  arc4random_buf(buffer, bytes);
  mpz_import(destination, bytes, 1, sizeof(char), 0, 0, buffer);
  free(buffer);
}

void random_prime(int bits, mpz_t destination) {
  size_t bytes = bits >> 3;
  int lastbit_index = bits - 1;
  do {
    random_number(bytes, destination);
    mpz_setbit(destination, lastbit_index);
  } while (mpz_probab_prime_p(destination, 50) < 1);
}

void RSA_generate_keys(int bits, RSA_key public_key, RSA_key private_key) {
  int prime_size = bits >> 1; // Size in bits of p and q.

  mpz_t p; // Secret prime number.
  mpz_init(p);
  random_prime(prime_size, p);

  mpz_t q; // Secret prime number.
  mpz_init(q);
  random_prime(prime_size, q);

  mpz_mul(public_key, p, q);
  // Subtract one from primes, beacuse λ(n) = lcm(p − 1, q − 1);
  mpz_sub_ui(p, p, 1);
  mpz_sub_ui(q, q, 1);

  mpz_t ctf; // Carmichael's totient function λ(n).
  mpz_init(ctf);

  mpz_lcm(ctf, p, q);
  mpz_clears(p, q, NULL);

  mpz_t gcd; // Not used variable, just for storing result of Extended Euclidean
             // algorithm.
  mpz_inits(gcd, private_key, NULL);

  mpz_gcdext(gcd, private_key, NULL, e, ctf);
  mpz_clear(gcd);
  while (mpz_sgn(private_key) < 1)
    mpz_add(private_key, private_key, ctf);
  mpz_clear(ctf);
}

void RSA_init() {
  mpz_init(e);
  mpz_set_si(e, 65537);
}

size_t RSA_size(RSA_key public_key) { return mpz_sizeinbase(public_key, 256); }

void RSA_encrypt(char *message, char *ciphertext, size_t bytes_to_encrypt,
                 size_t *encrypted_bytes, RSA_key public_key) {
  mpz_t m; // Message turned into number.
  mpz_init(m);
  mpz_import(m, bytes_to_encrypt, 1, sizeof(char), 0, 0, message);
  mpz_t c; // Encrypted message.
  mpz_init(c);
  mpz_powm_sec(c, m, e, public_key);
  mpz_clear(m);
  mpz_export(ciphertext, encrypted_bytes, 1, sizeof(char), 0, 0, c);
  mpz_clear(c);
}

void RSA_decrypt(char *ciphertext, char *message, size_t bytes_to_decrypt,
                 size_t *decrypted_bytes, RSA_key public_key,
                 RSA_key private_key) {
  mpz_t c; // Encrypted message.
  mpz_init(c);
  mpz_import(c, bytes_to_decrypt, 1, sizeof(char), 0, 0, ciphertext);
  mpz_t m; // Message turned into number.
  mpz_init(m);
  mpz_powm_sec(m, c, private_key, public_key);
  mpz_clear(c);
  mpz_export(message, decrypted_bytes, 1, sizeof(char), 0, 0, m);
  mpz_clear(m);
}
