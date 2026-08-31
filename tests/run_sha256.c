#include "unity.h"
#include "sha256.h"
#include "common.h"
#include <stdio.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

void test_sha256_hash_computation(void) {
    uint8_t hash[SHA256_DIGEST_LENGTH];
    const uint8_t data[] = "test_password";
    sha256_hash(data, strlen((const char*)data), hash);
    TEST_ASSERT_EQUAL_INT(32, SHA256_DIGEST_LENGTH);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        TEST_ASSERT_TRUE(hash[i] >= 0x00 && hash[i] <= 0xFF);
    }
}

void test_sha256_determinism(void) {
    uint8_t hash1[SHA256_DIGEST_LENGTH];
    uint8_t hash2[SHA256_DIGEST_LENGTH];
    const uint8_t data[] = "determinism_test";
    sha256_hash(data, strlen((const char*)data), hash1);
    sha256_hash(data, strlen((const char*)data), hash2);
    TEST_ASSERT_EQUAL_MEMORY(hash1, hash2, SHA256_DIGEST_LENGTH);
}

void test_sha256_uniqueness(void) {
    uint8_t hash_a[SHA256_DIGEST_LENGTH];
    uint8_t hash_b[SHA256_DIGEST_LENGTH];
    sha256_hash((uint8_t*)"input_A", strlen("input_A"), hash_a);
    sha256_hash((uint8_t*)"input_B", strlen("input_B"), hash_b);
    int different = 0;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        if (hash_a[i] != hash_b[i]) { different = 1; break; }
    }
    TEST_ASSERT_TRUE(different == 1);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_sha256_hash_computation);
    RUN_TEST(test_sha256_determinism);
    RUN_TEST(test_sha256_uniqueness);
    return UNITY_END();
}