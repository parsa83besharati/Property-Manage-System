#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

#define SHA256_BLOCK_SIZE 32

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t hash[]);
void sha256_hash(const uint8_t *data, size_t len, uint8_t hash[]);
void sha256_to_hex(const uint8_t hash[SHA256_BLOCK_SIZE], char hex[SHA256_BLOCK_SIZE * 2 + 1]);
void generate_salt(char *salt, int length);
void hash_password(const char *password, const char *salt, char *output_hash);

#endif