#include "unity.h"
#include "common.h"
#include <stdio.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

// =============================================================================
// VALIDATE PHONE - Iranian format: 09xxxxxxxxx (11 digits, starts with 09)
// =============================================================================

void test_validate_phone_valid_standard(void) {
    TEST_ASSERT_TRUE(validate_phone("09123456789"));
    TEST_ASSERT_TRUE(validate_phone("09111111111"));
    TEST_ASSERT_TRUE(validate_phone("09999999999"));
}

void test_validate_phone_invalid_length_short(void) {
    TEST_ASSERT_FALSE(validate_phone("0912345678"));   // 10 digits
    TEST_ASSERT_FALSE(validate_phone("091234567"));    // 9 digits
    TEST_ASSERT_FALSE(validate_phone(""));             // empty
}

void test_validate_phone_invalid_length_long(void) {
    TEST_ASSERT_FALSE(validate_phone("091234567890")); // 12 digits
    TEST_ASSERT_FALSE(validate_phone("0912345678901")); // 13 digits
}

void test_validate_phone_invalid_prefix(void) {
    TEST_ASSERT_FALSE(validate_phone("08123456789"));  // starts with 08
    TEST_ASSERT_FALSE(validate_phone("07123456789"));  // starts with 07
    TEST_ASSERT_FALSE(validate_phone("00123456789"));  // starts with 00
    TEST_ASSERT_FALSE(validate_phone("99123456789"));  // missing leading 0
}

void test_validate_phone_invalid_chars(void) {
    TEST_ASSERT_FALSE(validate_phone("0912345678a"));  // letter at end
    TEST_ASSERT_FALSE(validate_phone("091234567-9"));  // dash
    TEST_ASSERT_FALSE(validate_phone("09 12345678"));  // space
    TEST_ASSERT_FALSE(validate_phone("0912345678!"));  // special char
}

void test_validate_phone_null(void) {
    // validate_phone dereferences the pointer, so we can't test NULL
    // This is a design limitation of the function
    TEST_ASSERT_FALSE(validate_phone(""));  // empty string instead
}

// =============================================================================
// VALIDATE EMAIL - Must have exactly one @, at least one ., non-empty segments
// =============================================================================

void test_validate_email_valid_standard(void) {
    TEST_ASSERT_TRUE(validate_email("user@example.com"));
    TEST_ASSERT_TRUE(validate_email("test.user@domain.org"));
    TEST_ASSERT_TRUE(validate_email("user123@test-domain.net"));
    TEST_ASSERT_TRUE(validate_email("a@b.co"));
}

void test_validate_email_invalid_no_at(void) {
    TEST_ASSERT_FALSE(validate_email("userexample.com"));
    TEST_ASSERT_FALSE(validate_email("user.example.com"));
    TEST_ASSERT_FALSE(validate_email("user@"));
    TEST_ASSERT_FALSE(validate_email("@example.com"));
}

void test_validate_email_invalid_multiple_at(void) {
    TEST_ASSERT_FALSE(validate_email("user@@example.com"));
    TEST_ASSERT_FALSE(validate_email("user@domain@com"));
    TEST_ASSERT_FALSE(validate_email("user@domain@com@org"));
}

void test_validate_email_invalid_no_dot(void) {
    TEST_ASSERT_FALSE(validate_email("user@examplecom"));
    TEST_ASSERT_FALSE(validate_email("user@localhost"));
}

void test_validate_email_invalid_empty_segments(void) {
    TEST_ASSERT_FALSE(validate_email(".user@example.com"));  // starts with dot
    TEST_ASSERT_FALSE(validate_email("user.@example.com"));  // ends with dot before @
    TEST_ASSERT_FALSE(validate_email("user@.example.com"));  // empty domain segment
    TEST_ASSERT_FALSE(validate_email("user@example..com"));  // double dot
    TEST_ASSERT_FALSE(validate_email("user@example."));      // ends with dot
}

void test_validate_email_edge_cases(void) {
    TEST_ASSERT_FALSE(validate_email(""));                    // empty
    TEST_ASSERT_FALSE(validate_email("@"));                   // just @
    TEST_ASSERT_FALSE(validate_email("."));                   // just .
    TEST_ASSERT_FALSE(validate_email("@."));                  // @ and .
    TEST_ASSERT_TRUE(validate_email("a@b.c"));                // minimal valid
}

// =============================================================================
// VALIDATE PASSWORD - Min 8 chars, must have upper, lower, digit
// =============================================================================

void test_validate_password_valid_standard(void) {
    TEST_ASSERT_TRUE(validate_password("Password1"));
    TEST_ASSERT_TRUE(validate_password("MyPass123"));
    TEST_ASSERT_TRUE(validate_password("Secure1Password"));
    TEST_ASSERT_TRUE(validate_password("Aa1aaaaaa"));  // exactly 8 chars
}

void test_validate_password_invalid_too_short(void) {
    TEST_ASSERT_FALSE(validate_password("Pass1"));      // 5 chars
    TEST_ASSERT_FALSE(validate_password("Pass12"));     // 6 chars
    TEST_ASSERT_FALSE(validate_password("Pass123"));    // 7 chars
    TEST_ASSERT_FALSE(validate_password(""));           // empty
}

void test_validate_password_invalid_no_upper(void) {
    TEST_ASSERT_FALSE(validate_password("password1"));
    TEST_ASSERT_FALSE(validate_password("mypass123"));
    TEST_ASSERT_FALSE(validate_password("aaaaaaaa1"));
}

void test_validate_password_invalid_no_lower(void) {
    TEST_ASSERT_FALSE(validate_password("PASSWORD1"));
    TEST_ASSERT_FALSE(validate_password("MYPASS123"));
    TEST_ASSERT_FALSE(validate_password("AAAAAAAA1"));
}

void test_validate_password_invalid_no_digit(void) {
    TEST_ASSERT_FALSE(validate_password("Password"));
    TEST_ASSERT_FALSE(validate_password("MyPass"));
    TEST_ASSERT_FALSE(validate_password("AaAaAaAa"));
}

void test_validate_password_special_chars_allowed(void) {
    // Special chars don't break validation as long as upper/lower/digit present
    TEST_ASSERT_TRUE(validate_password("Pass@word1"));
    TEST_ASSERT_TRUE(validate_password("P@ssw0rd!"));
    TEST_ASSERT_TRUE(validate_password("P#ssw0rd$"));
}

void test_validate_password_unicode(void) {
    // Non-ASCII behavior depends on locale; accept either result
    // On some locales, extended ASCII may pass isupper/islower/isdigit
    validate_password("Pässwörd1"); // Just verify it doesn't crash
}

// =============================================================================
// VALIDATE ID - Exactly 10 digits (Iranian national ID)
// =============================================================================

void test_validate_id_valid_standard(void) {
    TEST_ASSERT_TRUE(validate_id("1234567890"));
    TEST_ASSERT_TRUE(validate_id("0000000000"));
    TEST_ASSERT_TRUE(validate_id("9999999999"));
}

void test_validate_id_invalid_length(void) {
    TEST_ASSERT_FALSE(validate_id("123456789"));   // 9 digits
    TEST_ASSERT_FALSE(validate_id("12345678901")); // 11 digits
    TEST_ASSERT_FALSE(validate_id(""));            // empty
}

void test_validate_id_invalid_chars(void) {
    TEST_ASSERT_FALSE(validate_id("123456789a"));  // letter
    TEST_ASSERT_FALSE(validate_id("12345678 0"));  // space
    TEST_ASSERT_FALSE(validate_id("12345678-0"));  // dash
    TEST_ASSERT_FALSE(validate_id("12345678.0"));  // dot
}

// =============================================================================
// VALIDATE INT RANGE - String to int with bounds
// =============================================================================

void test_validate_int_range_valid(void) {
    int out;
    TEST_ASSERT_TRUE(validate_int_range("42", 0, 100, &out));
    TEST_ASSERT_EQUAL_INT(42, out);
    TEST_ASSERT_TRUE(validate_int_range("0", 0, 100, &out));
    TEST_ASSERT_EQUAL_INT(0, out);
    TEST_ASSERT_TRUE(validate_int_range("100", 0, 100, &out));
    TEST_ASSERT_EQUAL_INT(100, out);
    TEST_ASSERT_TRUE(validate_int_range("-5", -10, 10, &out));
    TEST_ASSERT_EQUAL_INT(-5, out);
}

void test_validate_int_range_invalid_not_number(void) {
    int out;
    TEST_ASSERT_FALSE(validate_int_range("abc", 0, 100, &out));
    TEST_ASSERT_FALSE(validate_int_range("42abc", 0, 100, &out));
    TEST_ASSERT_FALSE(validate_int_range("", 0, 100, &out));
    TEST_ASSERT_FALSE(validate_int_range("4.2", 0, 100, &out));
}

void test_validate_int_range_invalid_out_of_bounds(void) {
    int out;
    TEST_ASSERT_FALSE(validate_int_range("101", 0, 100, &out));
    TEST_ASSERT_FALSE(validate_int_range("-1", 0, 100, &out));
    TEST_ASSERT_FALSE(validate_int_range("1000", 0, 100, &out));
}

// =============================================================================
// VALIDATE DOUBLE RANGE - String to double with bounds
// =============================================================================

void test_validate_double_range_valid(void) {
    double out;
    TEST_ASSERT_TRUE(validate_double_range("3.14", 0.0, 10.0, &out));
    TEST_ASSERT_TRUE(out > 3.13 && out < 3.15);
    TEST_ASSERT_TRUE(validate_double_range("0", 0.0, 10.0, &out));
    TEST_ASSERT_TRUE(out == 0.0);
    TEST_ASSERT_TRUE(validate_double_range("10", 0.0, 10.0, &out));
    TEST_ASSERT_TRUE(out == 10.0);
    TEST_ASSERT_TRUE(validate_double_range("-5.5", -10.0, 10.0, &out));
    TEST_ASSERT_TRUE(out > -5.51 && out < -5.49);
}

void test_validate_double_range_invalid_not_number(void) {
    double out;
    TEST_ASSERT_FALSE(validate_double_range("abc", 0.0, 10.0, &out));
    TEST_ASSERT_FALSE(validate_double_range("3.14abc", 0.0, 10.0, &out));
    TEST_ASSERT_FALSE(validate_double_range("", 0.0, 10.0, &out));
}

void test_validate_double_range_invalid_out_of_bounds(void) {
    double out;
    TEST_ASSERT_FALSE(validate_double_range("10.1", 0.0, 10.0, &out));
    TEST_ASSERT_FALSE(validate_double_range("-0.1", 0.0, 10.0, &out));
    TEST_ASSERT_FALSE(validate_double_range("100", 0.0, 10.0, &out));
}

int main(void) {
    UNITY_BEGIN();
    // Phone
    RUN_TEST(test_validate_phone_valid_standard);
    RUN_TEST(test_validate_phone_invalid_length_short);
    RUN_TEST(test_validate_phone_invalid_length_long);
    RUN_TEST(test_validate_phone_invalid_prefix);
    RUN_TEST(test_validate_phone_invalid_chars);
    RUN_TEST(test_validate_phone_null);
    // Email
    RUN_TEST(test_validate_email_valid_standard);
    RUN_TEST(test_validate_email_invalid_no_at);
    RUN_TEST(test_validate_email_invalid_multiple_at);
    RUN_TEST(test_validate_email_invalid_no_dot);
    RUN_TEST(test_validate_email_invalid_empty_segments);
    RUN_TEST(test_validate_email_edge_cases);
    // Password
    RUN_TEST(test_validate_password_valid_standard);
    RUN_TEST(test_validate_password_invalid_too_short);
    RUN_TEST(test_validate_password_invalid_no_upper);
    RUN_TEST(test_validate_password_invalid_no_lower);
    RUN_TEST(test_validate_password_invalid_no_digit);
    RUN_TEST(test_validate_password_special_chars_allowed);
    RUN_TEST(test_validate_password_unicode);
    // ID
    RUN_TEST(test_validate_id_valid_standard);
    RUN_TEST(test_validate_id_invalid_length);
    RUN_TEST(test_validate_id_invalid_chars);
    // Int range
    RUN_TEST(test_validate_int_range_valid);
    RUN_TEST(test_validate_int_range_invalid_not_number);
    RUN_TEST(test_validate_int_range_invalid_out_of_bounds);
    // Double range
    RUN_TEST(test_validate_double_range_valid);
    RUN_TEST(test_validate_double_range_invalid_not_number);
    RUN_TEST(test_validate_double_range_invalid_out_of_bounds);
    return UNITY_END();
}