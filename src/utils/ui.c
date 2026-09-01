#include "ui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ioctl.h>
#endif

#ifdef _WIN32
static HANDLE console_handle = NULL;
static CONSOLE_SCREEN_BUFFER_INFO original_console_info;
static DWORD original_console_mode;
#else
static struct termios original_termios;
static int term_initialized = 0;
#endif

static bool ui_initialized = false;
static int spinner_state = 0;
#ifdef _WIN32
static DWORD spinner_thread_id = 0;
static HANDLE spinner_thread = NULL;
#else
static pthread_t spinner_thread;
#endif
static volatile bool spinner_running = false;
static char spinner_label[100] = {0};

static const char *spinner_frames[] = {"|", "/", "-", "\\", "|", "/", "-", "\\"};

#ifdef _WIN32
static DWORD WINAPI spinner_loop(LPVOID param) {
    (void)param;
#else
static void *spinner_loop(void *param) {
    (void)param;
#endif
    while (spinner_running) {
        ui_set_style(UI_STYLE_INFO);
        printf("\r%s %s", spinner_frames[spinner_state % 8], spinner_label);
        fflush(stdout);
        spinner_state++;
#ifdef _WIN32
        Sleep(80);
#else
        usleep(80000);
#endif
    }
    printf("\r%*s\r", (int)strlen(spinner_label) + 4, "");
    fflush(stdout);
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

void ui_init(void) {
    if (ui_initialized) return;
    
#ifdef _WIN32
    console_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    GetConsoleScreenBufferInfo(console_handle, &original_console_info);
    GetConsoleMode(console_handle, &original_console_mode);
    SetConsoleMode(console_handle, original_console_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#else
    if (!term_initialized) {
        tcgetattr(STDIN_FILENO, &original_termios);
        struct termios raw = original_termios;
        raw.c_lflag &= ~(ICANON | ECHO);
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
        term_initialized = 1;
    }
    printf("\033[?1049h"); // Enter alternate screen buffer
#endif
    
    ui_initialized = true;
}

void ui_cleanup(void) {
    if (!ui_initialized) return;
    
#ifdef _WIN32
    SetConsoleMode(console_handle, original_console_mode);
#else
    if (term_initialized) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_termios);
        term_initialized = 0;
    }
    printf("\033[?1049l"); // Exit alternate screen buffer
#endif
    ui_initialized = false;
}

void ui_clear(void) {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

void ui_reset_color(void) {
    printf("\033[0m");
}

void ui_set_color(UIColor fg, UIColor bg, UIColor attr) {
    printf("\033[%d;%d;%dm", attr, fg, bg);
}

void ui_set_style(UIStyle style) {
    ui_reset_color();
    switch (style) {
        case UI_STYLE_PRIMARY:
            ui_set_color(UI_FG_BRIGHT_CYAN, UI_BG_DEFAULT, UI_COLOR_BOLD);
            break;
        case UI_STYLE_SUCCESS:
            ui_set_color(UI_FG_BRIGHT_GREEN, UI_BG_DEFAULT, UI_COLOR_BOLD);
            break;
        case UI_STYLE_WARNING:
            ui_set_color(UI_FG_BRIGHT_YELLOW, UI_BG_DEFAULT, UI_COLOR_BOLD);
            break;
        case UI_STYLE_ERROR:
            ui_set_color(UI_FG_BRIGHT_RED, UI_BG_DEFAULT, UI_COLOR_BOLD);
            break;
        case UI_STYLE_INFO:
            ui_set_color(UI_FG_BRIGHT_BLUE, UI_BG_DEFAULT, 0);
            break;
        case UI_STYLE_MUTED:
            ui_set_color(UI_FG_BRIGHT_BLACK, UI_BG_DEFAULT, UI_COLOR_DIM);
            break;
        default:
            ui_reset_color();
            break;
    }
}

void ui_print(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    fflush(stdout);
}

void ui_println(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
    fflush(stdout);
}

void ui_print_styled(UIStyle style, const char *fmt, ...) {
    ui_set_style(style);
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    ui_reset_color();
    fflush(stdout);
}

void ui_box_top(int width) {
    ui_set_style(UI_STYLE_MUTED);
    printf("+");
    for (int i = 0; i < width - 2; i++) printf("-");
    printf("+\n");
    ui_reset_color();
}

void ui_box_middle(int width, const char *title) {
    ui_set_style(UI_STYLE_MUTED);
    printf("|");
    ui_reset_color();
    
    int title_len = strlen(title);
    int padding = (width - 2 - title_len) / 2;
    
    for (int i = 0; i < padding; i++) printf(" ");
    ui_set_style(UI_STYLE_PRIMARY);
    printf("%s", title);
    ui_reset_color();
    
    for (int i = 0; i < width - 2 - padding - title_len; i++) printf(" ");
    ui_set_style(UI_STYLE_MUTED);
    printf("|\n");
    ui_reset_color();
}

void ui_box_bottom(int width) {
    ui_set_style(UI_STYLE_MUTED);
    printf("+");
    for (int i = 0; i < width - 2; i++) printf("-");
    printf("+\n");
    ui_reset_color();
}

void ui_box_line(int width, const char *left, const char *content, const char *right) {
    ui_set_style(UI_STYLE_MUTED);
    printf("| ");
    ui_reset_color();
    
    if (left) {
        ui_set_style(UI_STYLE_MUTED);
        printf("%s", left);
        ui_reset_color();
    }
    
    if (content) printf("%s", content);
    
    int used = 2;
    if (left) used += strlen(left);
    if (content) used += strlen(content);
    if (right) used += strlen(right);
    
    for (int i = used; i < width - 1; i++) printf(" ");
    
    if (right) {
        ui_set_style(UI_STYLE_MUTED);
        printf("%s", right);
        ui_reset_color();
    }
    
    ui_set_style(UI_STYLE_MUTED);
    printf(" |\n");
    ui_reset_color();
}

void ui_draw_box(int width, const char *title, const char *lines[], int line_count) {
    ui_box_top(width);
    if (title) ui_box_middle(width, title);
    for (int i = 0; i < line_count; i++) {
        ui_box_line(width, NULL, lines[i], NULL);
    }
    ui_box_bottom(width);
}

void ui_header(const char *title, const char *subtitle) {
    ui_clear();
    ui_divider();
    ui_set_style(UI_STYLE_PRIMARY);
    printf("  %s\n", title);
    ui_reset_color();
    if (subtitle) {
        ui_set_style(UI_STYLE_MUTED);
        printf("  %s\n", subtitle);
        ui_reset_color();
    }
    ui_divider();
    printf("\n");
}

void ui_footer(const char *left, const char *right) {
    printf("\n");
    ui_divider();
    ui_set_style(UI_STYLE_MUTED);
    if (left) printf("%s", left);
    
    if (right) {
        int padding = UI_WIDTH - (left ? strlen(left) : 0) - strlen(right);
        if (padding > 0) printf("%*s", padding, "");
        printf("%s", right);
    }
    printf("\n");
    ui_reset_color();
}

void ui_divider(void) {
    ui_set_style(UI_STYLE_MUTED);
    for (int i = 0; i < UI_WIDTH; i++) printf("-");
    printf("\n");
    ui_reset_color();
}

void ui_spacer(int count) {
    for (int i = 0; i < count; i++) printf("\n");
}

void ui_menu_item(int num, const char *label, const char *desc, bool selected) {
    if (selected) {
        ui_set_style(UI_STYLE_PRIMARY);
        printf("  > %2d. %-25s", num, label);
        if (desc) {
            ui_set_style(UI_STYLE_MUTED);
            printf("  %s", desc);
        }
        ui_reset_color();
    } else {
        ui_set_style(UI_STYLE_DEFAULT);
        printf("    %2d. %-25s", num, label);
        if (desc) {
            ui_set_style(UI_STYLE_MUTED);
            printf("  %s", desc);
        }
        ui_reset_color();
    }
    printf("\n");
}

void ui_menu_start(const char *title) {
    ui_header(title, NULL);
}

int ui_menu_end(const char *prompt, int min, int max) {
    printf("\n");
    ui_set_style(UI_STYLE_INFO);
    printf("  %s [%d-%d]: ", prompt, min, max);
    ui_reset_color();
    
    char input[32];
    safe_gets(input, sizeof(input));
    int choice = atoi(input);
    
    if (choice >= min && choice <= max) return choice;
    return -1;
}

void ui_form_start(const char *title) {
    ui_header(title, "Fill in the fields below. Press Enter to confirm each field.");
    printf("\n");
}

int ui_form_field(const char *label, char *buffer, int maxlen, int (*validator)(const char *), const char *hint) {
    while (1) {
        ui_set_style(UI_STYLE_DEFAULT);
        printf("  %-20s ", label);
        ui_reset_color();
        
        ui_set_style(UI_STYLE_MUTED);
        if (hint) printf("(%s)", hint);
        printf(": ");
        ui_reset_color();
        
        safe_gets(buffer, maxlen);
        
        if (strlen(buffer) == 0) {
            ui_print_styled(UI_STYLE_WARNING, "  ! This field is required\n");
            continue;
        }
        
        if (validator && !validator(buffer)) {
            ui_print_styled(UI_STYLE_ERROR, "  ! Invalid input format\n");
            continue;
        }
        
        ui_print_styled(UI_STYLE_SUCCESS, "  + Valid\n");
        return 1;
    }
}

int ui_form_field_int(const char *label, int *out, int min, int max, const char *hint) {
    char buffer[64];
    char hint_str[128];
    snprintf(hint_str, sizeof(hint_str), "%s [%d-%d]", hint ? hint : "number", min, max);
    
    while (1) {
        if (!ui_form_field(label, buffer, sizeof(buffer), NULL, hint_str)) continue;
        
        char *endptr;
        long val = strtol(buffer, &endptr, 10);
        if (endptr == buffer || *endptr != '\0') {
            ui_print_styled(UI_STYLE_ERROR, "  ! Please enter a valid number\n");
            continue;
        }
        if (val < min || val > max) {
            ui_print_styled(UI_STYLE_ERROR, "  ! Value must be between %d and %d\n", min, max);
            continue;
        }
        *out = (int)val;
        return 1;
    }
}

int ui_form_field_double(const char *label, double *out, double min, double max, const char *hint) {
    char buffer[64];
    char hint_str[128];
    snprintf(hint_str, sizeof(hint_str), "%s [%.2f-%.2f]", hint ? hint : "amount", min, max);
    
    while (1) {
        if (!ui_form_field(label, buffer, sizeof(buffer), NULL, hint_str)) continue;
        
        char *endptr;
        double val = strtod(buffer, &endptr);
        if (endptr == buffer || *endptr != '\0') {
            ui_print_styled(UI_STYLE_ERROR, "  ! Please enter a valid number\n");
            continue;
        }
        if (val < min || val > max) {
            ui_print_styled(UI_STYLE_ERROR, "  ! Value must be between %.2f and %.2f\n", min, max);
            continue;
        }
        *out = val;
        return 1;
    }
}

int ui_form_field_enum(const char *label, const char *options[], int count, int *out, const char *hint) {
    while (1) {
        ui_set_style(UI_STYLE_DEFAULT);
        printf("  %-20s ", label);
        ui_reset_color();
        
        ui_set_style(UI_STYLE_MUTED);
        if (hint) printf("(%s)", hint);
        printf("\n");
        ui_reset_color();
        
        for (int i = 0; i < count; i++) {
            printf("      %d) %s\n", i + 1, options[i]);
        }
        
        printf("\n  Choice: ");
        char input[32];
        safe_gets(input, sizeof(input));
        int choice = atoi(input);
        
        if (choice >= 1 && choice <= count) {
            *out = choice - 1;
            ui_print_styled(UI_STYLE_SUCCESS, "  + Selected: %s\n", options[choice - 1]);
            return 1;
        }
        ui_print_styled(UI_STYLE_ERROR, "  ! Invalid choice. Enter 1-%d\n", count);
    }
}

#ifdef _WIN32
void get_password_hidden(char *buffer, int maxlen) {
    int i = 0;
    char ch;
    while (i < maxlen - 1) {
        ch = _getch();
        if (ch == '\r' || ch == '\n') break;
        if (ch == '\b' || ch == 127) {
            if (i > 0) {
                i--;
                printf("\b \b");
            }
        } else {
            buffer[i++] = ch;
            printf("*");
        }
    }
    buffer[i] = '\0';
    printf("\n");
}
#else
void get_password_hidden(char *buffer, int maxlen) {
    struct termios old, new;
    tcgetattr(STDIN_FILENO, &old);
    new = old;
    new.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &new);
    
    int i = 0;
    int ch;
    while (i < maxlen - 1 && (ch = getchar()) != EOF && ch != '\n') {
        if (ch == 127 || ch == '\b') {
            if (i > 0) {
                i--;
                printf("\b \b");
            }
        } else {
            buffer[i++] = ch;
            printf("*");
        }
    }
    buffer[i] = '\0';
    printf("\n");
    
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
}
#endif

int ui_form_field_password(const char *label, char *buffer, int maxlen, const char *hint) {
    while (1) {
        ui_set_style(UI_STYLE_DEFAULT);
        printf("  %-20s ", label);
        ui_reset_color();
        
        ui_set_style(UI_STYLE_MUTED);
        if (hint) printf("(%s)", hint);
        printf(": ");
        ui_reset_color();
        
        get_password_hidden(buffer, maxlen);
        
        if (strlen(buffer) == 0) {
            ui_print_styled(UI_STYLE_WARNING, "  ! This field is required\n");
            continue;
        }
        
        ui_print_styled(UI_STYLE_SUCCESS, "  + Entered\n");
        return 1;
    }
}

void ui_form_end(void) {
    ui_divider();
    ui_print_styled(UI_STYLE_SUCCESS, "  Form completed successfully!\n");
    printf("\n");
}

void ui_table_start(const char *headers[], int col_count, int widths[]) {
    ui_set_style(UI_STYLE_MUTED);
    printf("  ");
    for (int i = 0; i < col_count; i++) {
        printf("%-*s ", widths[i], headers[i]);
    }
    printf("\n");
    
    printf("  ");
    for (int i = 0; i < col_count; i++) {
        for (int j = 0; j < widths[i]; j++) printf("-");
        printf(" ");
    }
    printf("\n");
    ui_reset_color();
}

void ui_table_row(const char *cells[], int col_count) {
    printf("  ");
    for (int i = 0; i < col_count; i++) {
        printf("%-*s ", 20, cells[i] ? cells[i] : "");
    }
    printf("\n");
}

void ui_table_end(void) {
    ui_divider();
}

void ui_progress_start(const char *label, int total) {
    ui_set_style(UI_STYLE_INFO);
    printf("  %s\n", label);
    printf("  ");
    for (int i = 0; i < 50; i++) printf(".");
    printf(" 0%%");
    fflush(stdout);
    ui_reset_color();
}

void ui_progress_update(int current) {
    int percent = (current * 100) / 50;
    if (percent > 100) percent = 100;
    
    ui_set_style(UI_STYLE_PRIMARY);
    printf("\r  ");
    for (int i = 0; i < percent / 2; i++) printf("#");
    for (int i = percent / 2; i < 50; i++) printf(".");
    printf(" %3d%%", percent);
    fflush(stdout);
    ui_reset_color();
}

void ui_progress_end(void) {
    ui_set_style(UI_STYLE_SUCCESS);
    printf("\r  ");
    for (int i = 0; i < 50; i++) printf("#");
    printf(" 100%%\n");
    ui_reset_color();
}

void ui_spinner_start(const char *label) {
    if (spinner_running) return;
    strncpy(spinner_label, label, sizeof(spinner_label) - 1);
    spinner_label[sizeof(spinner_label) - 1] = '\0';
    spinner_running = true;
    spinner_state = 0;
#ifdef _WIN32
    spinner_thread = CreateThread(NULL, 0, spinner_loop, NULL, 0, &spinner_thread_id);
#else
    pthread_create(&spinner_thread, NULL, spinner_loop, NULL);
#endif
}

void ui_spinner_stop(void) {
    if (!spinner_running) return;
    spinner_running = false;
#ifdef _WIN32
    if (spinner_thread) {
        WaitForSingleObject(spinner_thread, 1000);
        CloseHandle(spinner_thread);
        spinner_thread = NULL;
    }
#else
    if (spinner_thread) {
        pthread_join(spinner_thread, NULL);
        spinner_thread = 0;
    }
#endif
}

void ui_alert(UIStyle style, const char *title, const char *message) {
    printf("\n");
    ui_set_style(style);
    printf("  +-- %s ", title);
    for (int i = 0; i < UI_WIDTH - 8 - (int)strlen(title); i++) printf("-");
    printf("+\n");
    
    printf("  | %s\n", message);
    
    printf("  +");
    for (int i = 0; i < UI_WIDTH - 4; i++) printf("-");
    printf("+\n");
    ui_reset_color();
    printf("\n");
    ui_pause(NULL);
}

void ui_confirm(const char *message, bool *out) {
    ui_alert(UI_STYLE_WARNING, "Confirm", message);
    ui_set_style(UI_STYLE_INFO);
    printf("  Continue? (y/n): ");
    ui_reset_color();
    
    char input[4];
    safe_gets(input, sizeof(input));
    *out = (input[0] == 'y' || input[0] == 'Y');
}

void ui_toast(UIStyle style, const char *message) {
    ui_set_style(style);
    printf("  > %s\n", message);
    ui_reset_color();
#ifdef _WIN32
    Sleep(1000);
#else
    sleep(1);
#endif
}

void ui_pause(const char *message) {
    ui_set_style(UI_STYLE_MUTED);
    if (message) printf("\n  %s", message);
    else printf("\n  Press Enter to continue...");
    ui_reset_color();
    
#ifdef _WIN32
    _getch();
#else
    getchar();
#endif
    printf("\n");
}

void ui_status_bar(const char *user, const char *mode, const char *time) {
    ui_set_style(UI_STYLE_MUTED);
    printf("\n");
    for (int i = 0; i < UI_WIDTH; i++) printf("-");
    printf("\n  User: %s  |  Mode: %s  |  %s\n", user, mode, time);
    for (int i = 0; i < UI_WIDTH; i++) printf("-");
    printf("\n");
    ui_reset_color();
}