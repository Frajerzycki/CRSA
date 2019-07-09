#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define RIGHTROTATE32(n, b) ((n >> b) | (n << (32 - b)))
#define BSWAP32(x) (((x & 0xff000000) >> 24) | ((x & 0x00ff0000) >> 8) | ((x & 0x0000ff00) << 8) | (x << 24))
const static uint32_t K[] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

uint8_t *SHA256(void *data, size_t size) {
  uint32_t *hash = malloc(32);
  hash[0] = 0x6a09e667;
  hash[1] = 0xbb67ae85;
  hash[2] = 0x3c6ef372;
  hash[3] = 0xa54ff53a;
  hash[4] = 0x510e527f;
  hash[5] = 0x9b05688c;
  hash[6] = 0x1f83d9ab;
  hash[7] = 0x5be0cd19;

  size_t bit_length = (size << 3) + 65;
  uint16_t k = (512 - (bit_length & 0x1FF)) & 0x1FF;
  bit_length += k;
  k -= 7;
  k >>= 3;

  size_t byte_length = bit_length >> 3;
  uint8_t *bytes = malloc(byte_length);
  memcpy(bytes, data, size);
  bytes += size;
  bytes[0] = 0x80;
  bytes++;
  memset(bytes, 0, k);
  bytes += k;
  size <<= 3;
  bytes[7] = size & 0xFF;
  bytes[6] = (size >> 8) & 0xFF;
  bytes[5] = (size >> 16) & 0xFF;
  bytes[4] = (size >> 24) & 0xFF;
  bytes[3] = (size >> 32) & 0xFF;
  bytes[2] = (size >> 40) & 0xFF;
  bytes[1] = (size >> 48) & 0xFF;
  bytes[0] = (size >> 56) & 0xFF;
  bytes -= byte_length - 8;
  size_t bytes_index = 0;

  while (bytes_index < byte_length) {
    uint32_t w[64];
    for (uint8_t i = 0; i < 16; i++, bytes_index += 4) {
      w[i] = (bytes[bytes_index] << 24) | (bytes[bytes_index + 1] << 16) |
             (bytes[bytes_index + 2] << 8) | bytes[bytes_index + 3];
    }
    for (uint8_t i = 16; i < 64; i++) {
      uint32_t wim15 = w[i - 15];
      uint32_t s0 =
          RIGHTROTATE32(wim15, 7) ^ RIGHTROTATE32(wim15, 18) ^ (wim15 >> 3);
      uint32_t wim2 = w[i - 2];
      uint32_t s1 =
          RIGHTROTATE32(wim2, 17) ^ RIGHTROTATE32(wim2, 19) ^ (wim2 >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = hash[0];
    uint32_t b = hash[1];
    uint32_t c = hash[2];
    uint32_t d = hash[3];
    uint32_t e = hash[4];
    uint32_t f = hash[5];
    uint32_t g = hash[6];
    uint32_t h = hash[7];
    for (size_t i = 0; i < 64; i++) {
      uint32_t s1 =
          RIGHTROTATE32(e, 6) ^ RIGHTROTATE32(e, 11) ^ RIGHTROTATE32(e, 25);
      uint32_t ch = (e & f) ^ (~e & g);
      uint32_t temp1 = h + s1 + ch + K[i] + w[i];
      uint32_t s0 =
          RIGHTROTATE32(a, 2) ^ RIGHTROTATE32(a, 13) ^ RIGHTROTATE32(a, 22);
      uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      uint32_t temp2 = s0 + maj;

      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }
    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
    hash[5] += f;
    hash[6] += g;
    hash[7] += h;
  }
  hash[0] = BSWAP32(hash[0]);
  hash[1] = BSWAP32(hash[1]);
  hash[2] = BSWAP32(hash[2]);
  hash[3] = BSWAP32(hash[3]);
  hash[4] = BSWAP32(hash[4]);
  hash[5] = BSWAP32(hash[5]);
  hash[6] = BSWAP32(hash[6]);
  hash[7] = BSWAP32(hash[7]);
  return (uint8_t *)hash;
}
