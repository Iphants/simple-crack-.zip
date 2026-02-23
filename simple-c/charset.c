#include "charset.h"
#include <string.h>
#include <stdio.h>

static const char *lower = "abcdefghijklmnopqrstuvwxyz";
static const char *upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char *digit = "1234567890";
static const char *spec = "\"\\!@#$^&*()-_=+[]{}:;|?/><.,";

int build_charset_from_spec(char *out, const char *spec_str)
{
    out[0] = '\0';
    for (int i = 0; spec_str[i]; i++)
    {
        switch (spec_str[i])
        {
            case 'l':
                strcat(out, lower);
                break;
            case 'u':
                strcat(out, upper);
                break;
            case 'd':
                strcat(out, digit);
                break;
            case 's':
                strcat(out, spec);
                break;
            default:
                fprintf(stderr, "Invalid charset option: %c\n", spec_str[i]);
                fprintf(stderr, "Options: l=lower, u=upper, d=digits, s=special\n");
                return -1;
        }
    }
    return 0;
}
