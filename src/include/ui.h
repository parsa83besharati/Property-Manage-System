#ifndef UI_H
#define UI_H

#include "common.h"

#define UI_WIDTH 80
#define UI_PADDING 2

typedef enum {
    UI_COLOR_RESET = 0,
    UI_COLOR_BOLD = 1,
    UI_COLOR_DIM = 2,
    UI_COLOR_UNDERLINE = 4,
    UI_COLOR_BLINK = 5,
    UI_COLOR_REVERSE = 7,
    UI_COLOR_HIDDEN = 8,

    UI_FG_BLACK = 30,
    UI_FG_RED = 31,
    UI_FG_GREEN = 32,
    UI_FG_YELLOW = 33,
    UI_FG_BLUE = 34,
    UI_FG_MAGENTA = 35,
    UI_FG_CYAN = 36,
    UI_FG_WHITE = 37,
    UI_FG_DEFAULT = 39,

    UI_BG_BLACK = 40,
    UI_BG_RED = 41,
    UI_BG_GREEN = 42,
    UI_BG_YELLOW = 43,
    UI_BG_BLUE = 44,
    UI_BG_MAGENTA = 45,
    UI_BG_CYAN = 46,
    UI_BG_WHITE = 47,
    UI_BG_DEFAULT = 49,

    UI_FG_BRIGHT_BLACK = 90,
    UI_FG_BRIGHT_RED = 91,
    UI_FG_BRIGHT_GREEN = 92,
    UI_FG_BRIGHT_YELLOW = 93,
    UI_FG_BRIGHT_BLUE = 94,
    UI_FG_BRIGHT_MAGENTA = 95,
    UI_FG_BRIGHT_CYAN = 96,
    UI_FG_BRIGHT_WHITE = 97,

    UI_BG_BRIGHT_BLACK = 100,
    UI_BG_BRIGHT_RED = 101,
    UI_BG_BRIGHT_GREEN = 102,
    UI_BG_BRIGHT_YELLOW = 103,
    UI_BG_BRIGHT_BLUE = 104,
    UI_BG_BRIGHT_MAGENTA = 105,
    UI_BG_BRIGHT_CYAN = 106,
    UI_BG_BRIGHT_WHITE = 107,
} UIColor;

typedef enum {
    UI_STYLE_DEFAULT,
    UI_STYLE_PRIMARY,
    UI_STYLE_SUCCESS,
    UI_STYLE_WARNING,
    UI_STYLE_ERROR,
    UI_STYLE_INFO,
    UI_STYLE_MUTED,
} UIStyle;

void ui_init(void);
void ui_clear(void);
void ui_reset_color(void);
void ui_set_color(UIColor fg, UIColor bg, UIColor attr);
void ui_set_style(UIStyle style);
void ui_print(const char *fmt, ...);
void ui_println(const char *fmt, ...);
void ui_print_styled(UIStyle style, const char *fmt, ...);

void ui_box_top(int width);
void ui_box_middle(int width, const char *title);
void ui_box_bottom(int width);
void ui_box_line(int width, const char *left, const char *content, const char *right);
void ui_draw_box(int width, const char *title, const char *lines[], int line_count);

void ui_header(const char *title, const char *subtitle);
void ui_footer(const char *left, const char *right);
void ui_divider(void);
void ui_spacer(int count);

void ui_menu_item(int num, const char *label, const char *desc, bool selected);
void ui_menu_start(const char *title);
int ui_menu_end(const char *prompt, int min, int max);

void ui_form_start(const char *title);
int ui_form_field(const char *label, char *buffer, int maxlen, int (*validator)(const char *), const char *hint);
int ui_form_field_int(const char *label, int *out, int min, int max, const char *hint);
int ui_form_field_double(const char *label, double *out, double min, double max, const char *hint);
int ui_form_field_enum(const char *label, const char *options[], int count, int *out, const char *hint);
int ui_form_field_password(const char *label, char *buffer, int maxlen, const char *hint);
void ui_form_end(void);

void ui_table_start(const char *headers[], int col_count, int widths[]);
void ui_table_row(const char *cells[], int col_count);
void ui_table_end(void);

void ui_progress_start(const char *label, int total);
void ui_progress_update(int current);
void ui_progress_end(void);

void ui_spinner_start(const char *label);
void ui_spinner_stop(void);

void ui_alert(UIStyle style, const char *title, const char *message);
void ui_confirm(const char *message, bool *out);
void ui_toast(UIStyle style, const char *message);
void ui_pause(const char *message);

void ui_status_bar(const char *user, const char *mode, const char *time);

#endif