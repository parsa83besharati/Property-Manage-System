#include "common.h"
#include <windows.h>
#include <conio.h>

void safe_gets(char *buffer, int size) {
    if (fgets(buffer, size, stdin) != NULL) {
        trim_newline(buffer);
    } else {
        buffer[0] = '\0';
    }
}

void trim_newline(char *str) {
    size_t len = strlen(str);
    if (len > 0 && str[len - 1] == '\n') {
        str[len - 1] = '\0';
    }
}

void str_to_lower(char *str) {
    for (int i = 0; str[i]; i++) {
        str[i] = tolower((unsigned char)str[i]);
    }
}

void str_to_upper_first(char *str) {
    if (str[0]) {
        str[0] = toupper((unsigned char)str[0]);
    }
}

void capitalize_words(char *str) {
    bool new_word = true;
    for (int i = 0; str[i]; i++) {
        if (new_word && isalpha((unsigned char)str[i])) {
            str[i] = toupper((unsigned char)str[i]);
            new_word = false;
        } else if (str[i] == ' ') {
            new_word = true;
        } else {
            str[i] = tolower((unsigned char)str[i]);
        }
    }
}

int validate_int_range(const char *str, int min, int max, int *out) {
    char *endptr;
    errno = 0;
    long val = strtol(str, &endptr, 10);
    if (endptr == str || *endptr != '\0') return 0;
    if (errno == ERANGE) return 0;
    if (val < min || val > max) return 0;
    *out = (int)val;
    return 1;
}

int validate_double_range(const char *str, double min, double max, double *out) {
    char *endptr;
    double val = strtod(str, &endptr);
    if (endptr == str || *endptr != '\0') return 0;
    if (val < min || val > max) return 0;
    *out = val;
    return 1;
}

int validate_phone(const char *phone) {
    if (strlen(phone) != 11) return 0;
    if (strncmp(phone, "09", 2) != 0) return 0;
    for (int i = 0; i < 11; i++) {
        if (!isdigit((unsigned char)phone[i])) return 0;
    }
    return 1;
}

int validate_email(const char *email) {
    if (strlen(email) == 0) return 0;
    int at_count = 0, dot_count = 0;
    for (int i = 0; email[i]; i++) {
        if (email[i] == '@') at_count++;
        if (email[i] == '.') dot_count++;
    }
    if (at_count != 1 || dot_count == 0) return 0;
    
    int segment_len = 0;
    for (int i = 0; email[i]; i++) {
        if (email[i] == '.' || email[i] == '@') {
            if (segment_len == 0) return 0;
            segment_len = 0;
        } else {
            segment_len++;
        }
    }
    return segment_len > 0;
}

int validate_password(const char *password) {
    if (strlen(password) < 8) return 0;
    bool has_upper = false, has_lower = false, has_digit = false;
    for (int i = 0; password[i]; i++) {
        if (isupper((unsigned char)password[i])) has_upper = true;
        if (islower((unsigned char)password[i])) has_lower = true;
        if (isdigit((unsigned char)password[i])) has_digit = true;
    }
    return has_upper && has_lower && has_digit;
}

int validate_id(const char *id) {
    if (strlen(id) != 10) return 0;
    for (int i = 0; i < 10; i++) {
        if (!isdigit((unsigned char)id[i])) return 0;
    }
    return 1;
}

void get_current_date(char *buffer, int size) {
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    strftime(buffer, size, "%Y-%m-%d", tm_info);
}

void get_current_time(char *buffer, int size) {
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    strftime(buffer, size, "%H:%M:%S", tm_info);
}

void clear_screen(void) {
    system("cls");
}

void pause_screen(void) {
    printf("\nPress any key to continue...");
    _getch();
    printf("\n");
}

void print_header(const char *title) {
    char date[20], time_str[20];
    get_current_date(date, sizeof(date));
    get_current_time(time_str, sizeof(time_str));
    printf("=== %s ===\n", title);
    printf("Date: %s  Time: %s\n\n", date, time_str);
}