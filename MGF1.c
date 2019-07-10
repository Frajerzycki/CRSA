#include "SHA256.h"
#include <string.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>

uint8_t* MGF1_SHA256(void* data, size_t data_size, uint32_t l) {
  size_t concatenated_size = data_size + 4;
  char concatenated[concatenated_size];
  memcpy(concatenated, data, data_size);
  uint8_t *output = malloc(l), *hash;
  uint32_t counter = 0, counter32t = 0, reversed_counter;
  for (uint32_t max = l >> 5; counter < max; counter++, counter32t += 32) {
    reversed_counter = __builtin_bswap32(counter); 
    memcpy(concatenated + data_size, &reversed_counter, 4);
    hash = SHA256(concatenated, concatenated_size);
    memcpy(output + counter32t, hash, 32);
    free(hash);
  } 

  uint8_t rest = l & 31;
  if (rest > 0) {
    reversed_counter = __builtin_bswap32(counter); 
    memcpy(concatenated + data_size, &reversed_counter, 4);
    hash = SHA256(concatenated, concatenated_size);
    memcpy(output + counter32t, hash, rest);
    free(hash);
  }
    
  return output;
}
