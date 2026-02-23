#ifndef ATTACK_H
#define ATTACK_H

#include "config.h"

void dictionary_attack(const char *zip_path, const char *wordlist, int threads);
void brute_force(const char *zip_path, const char *charset, int min_len, int max_len, int threads);
void human_brute_force(const char *zip_path, int user_min, int user_max, int threads);

#endif
