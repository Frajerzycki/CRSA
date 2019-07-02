#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include "headers/keys.h"

mpz_t e;

void random_number(size_t bytes, mpz_t destination) {
  char* buffer = malloc(bytes);
  arc4random_buf(buffer, bytes); 
  mpz_import(destination, bytes, 1, sizeof(char), 0, 0, buffer);
  free(buffer);
}

void random_prime(int bits, mpz_t destination) {
  size_t bytes = bits >> 3;
  int lastbit_index = bits-1;
  do {
    random_number(bytes, destination);
    mpz_setbit(destination, lastbit_index);
  } while(mpz_probab_prime_p(destination, 50) < 1); 
}

void generate_keys(int bits, RSA_key public_key, RSA_key private_key) {
  mpz_t p,q; // Secret prime numbers.
  mpz_t ctf; // Carmichael's totient function λ(n).
  mpz_t gcd;
  int prime_size = bits >> 1; // Size in bits of p and q.
  
  mpz_init(p);
  random_prime(prime_size, p);

  mpz_init(q);
  random_prime(prime_size, q);
  
  mpz_mul(public_key, p, q);
  // Subtract one from primes, beacuse λ(n) = lcm(p − 1, q − 1);
  mpz_sub_ui(p, p, 1);
  mpz_sub_ui(q, q, 1);

  mpz_init(ctf);
  mpz_lcm(ctf,p,q);
  mpz_clears(p, q, NULL); 

  mpz_inits(gcd, private_key, NULL);
  mpz_gcdext(gcd, private_key, NULL, e, ctf);
  mpz_clears(ctf,gcd,NULL);

  mpz_abs(private_key, private_key);
}

int main() {
  mpz_init(e);
  mpz_set_si(e, 65537);
  RSA_key private_key, public_key; 
  generate_keys(2048, public_key, private_key);
  gmp_printf("Public:\t%Zx\nPrivate:\t%Zx\n", public_key, private_key);
}
