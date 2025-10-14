#pragma once

#define ANSI_RESET "\x1b[0m"
#define ANSI_RESET_FG "\x1b[39m"
#define ANSI_RESET_BG "\x1b[49m"

#define ANSI_BOLD "\x1b[1m"
#define ANSI_FAINT "\x1b[2m"
#define ANSI_ITALIC "\x1b[3m"
#define ANSI_UNDERLINE "\x1b[4m"
#define ANSI_BLINK "\x1b[5m"
#define ANSI_RAPID_BLINK "\x1b[6m"
#define ANSI_REVERSE "\x1b[7m"
#define ANSI_HIDDEN "\x1b[8m"
#define ANSI_STRIKE "\x1b[9m"
#define ANSI_DOUBLE_UNDERLINE "\x1b[21m"

#define ANSI_BOLD_OFF "\x1b[22m"
#define ANSI_FAINT_OFF "\x1b[22m"
#define ANSI_ITALIC_OFF "\x1b[23m"
#define ANSI_UNDERLINE_OFF "\x1b[24m"
#define ANSI_BLINK_OFF "\x1b[25m"
#define ANSI_REVERSE_OFF "\x1b[27m"
#define ANSI_HIDDEN_OFF "\x1b[28m"
#define ANSI_STRIKE_OFF "\x1b[29m"

#define ANSI_BLACK "\x1b[30m"
#define ANSI_RED "\x1b[31m"
#define ANSI_GREEN "\x1b[32m"
#define ANSI_YELLOW "\x1b[33m"
#define ANSI_BLUE "\x1b[34m"
#define ANSI_MAGENTA "\x1b[35m"
#define ANSI_CYAN "\x1b[36m"
#define ANSI_WHITE "\x1b[37m"
#define ANSI_DEFAULT_FG "\x1b[39m"

#define ANSI_BBLACK "\x1b[90m"
#define ANSI_GRAY "\x1b[90m"
#define ANSI_GREY "\x1b[90m"
#define ANSI_BRED "\x1b[91m"
#define ANSI_BGREEN "\x1b[92m"
#define ANSI_BYELLOW "\x1b[93m"
#define ANSI_BBLUE "\x1b[94m"
#define ANSI_BMAGENTA "\x1b[95m"
#define ANSI_BCYAN "\x1b[96m"
#define ANSI_BWHITE "\x1b[97m"

#define ANSI_BG_BLACK "\x1b[40m"
#define ANSI_BG_RED "\x1b[41m"
#define ANSI_BG_GREEN "\x1b[42m"
#define ANSI_BG_YELLOW "\x1b[43m"
#define ANSI_BG_BLUE "\x1b[44m"
#define ANSI_BG_MAGENTA "\x1b[45m"
#define ANSI_BG_CYAN "\x1b[46m"
#define ANSI_BG_WHITE "\x1b[47m"
#define ANSI_DEFAULT_BG "\x1b[49m"

#define ANSI_BG_BBLACK "\x1b[100m"
#define ANSI_BG_GRAY "\x1b[100m"
#define ANSI_BG_GREY "\x1b[100m"
#define ANSI_BG_BRED "\x1b[101m"
#define ANSI_BG_BGREEN "\x1b[102m"
#define ANSI_BG_BYELLOW "\x1b[103m"
#define ANSI_BG_BBLUE "\x1b[104m"
#define ANSI_BG_BMAGENTA "\x1b[105m"
#define ANSI_BG_BCYAN "\x1b[106m"
#define ANSI_BG_BWHITE "\x1b[107m"

#define ANSI__S(x) #x
#define ANSI__X(x) ANSI__S(x)

#define ANSI_FG_256(n) "\x1b[38;5;" ANSI__X(n) "m"
#define ANSI_BG_256(n) "\x1b[48;5;" ANSI__X(n) "m"

#define ANSI_FG_RGB(r, g, b) "\x1b[38;2;" ANSI__X(r) ";" ANSI__X(g) ";" ANSI__X(b) "m"
#define ANSI_BG_RGB(r, g, b) "\x1b[48;2;" ANSI__X(r) ";" ANSI__X(g) ";" ANSI__X(b) "m"

#define ANSI_WITH(style, text) style text ANSI_RESET
