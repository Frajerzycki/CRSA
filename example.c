#include "RSA.h"
#include "MGF1.h"
#include "SHA256.h"
#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
  if (argc < 2)
    return 0;
  /*RSA_init();
  RSA_key private_key, public_key;
  RSA_generate_keys(atoi(argv[1]), public_key, private_key);
  char* message = "Kot";
  char* ciphertext = malloc(RSA_size(public_key));
  size_t encrypted_bytes;
  RSA_encrypt(message, ciphertext, 4, &encrypted_bytes, public_key);
  char* decrypted_message = malloc(RSA_size(public_key));
  printf("%zu\n", encrypted_bytes);
  RSA_decrypt(ciphertext, decrypted_message, encrypted_bytes, &encrypted_bytes,
  public_key, private_key); printf("%s\n", decrypted_message);
  gmp_printf("Public:\t%Zx\nPrivate:\t%Zx\n", public_key, private_key);*/
  if (argc < 3)
    return 0;
  uint32_t size = atoi(argv[2]);
  uint8_t *mask = MGF1_SHA256(argv[1], strlen(argv[1]),size);
  for (int i = 0; i < size; i++)
    printf("%02x", mask[i]);
  printf("\n");
  free(mask);
  return 0;
}
