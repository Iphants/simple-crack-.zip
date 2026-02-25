#ifndef PASSWORD_H
#define PASSWORD_H
#include <zip.h>

int try_password(struct zip *za, const char *pwd);
unsigned long long calculate_total_combinations(const char *charset, int min_len, int max_len);
void index_to_password(char *pwd, unsigned long long idx, const char *charset, int len);
#endif