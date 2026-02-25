#include "config.h"
#include "password.h"
#include <string.h>

int try_password(struct zip *za, const char *pwd)
{
    zip_int64_t n = zip_get_num_entries(za, 0);
    zip_uint64_t idx_encrypted = (zip_uint64_t)-1;

    // Find first encrtypted entry
    for (zip_int64_t i = 0; i < n; i++)
    {
        struct zip_stat st;
        zip_stat_init(&st);
        if (zip_stat_index(za, (zip_uint64_t)i, 0, &st) != 0)
            continue;
        if ((st.valid & ZIP_STAT_ENCRYPTION_METHOD) && st.encryption_method != 0)
        {
            idx_encrypted = (zip_uint64_t)i;
            break;
        }
    }

    if (idx_encrypted == (zip_uint64_t)-1)
        return 0;

    zip_file_t *zf = zip_fopen_index_encrypted(za, idx_encrypted, 0, pwd);
    if (!zf)
        return 0;

    char buf[4096];
    zip_int64_t r;
    zip_int64_t total_read = 0;
    while ((r = zip_fread(zf, buf, sizeof(buf))) > 0)
    {
        total_read += r;
    }
    zip_fclose(zf);
    return (total_read > 0) ? 1 : 0;
}

unsigned long long calculate_total_combinations(const char *charset, int min_len, int max_len)
{
    int clen = (int)strlen(charset);
    unsigned long long total = 0;
    for (int len = min_len; len <= max_len; len++)
    {
        unsigned long long comb = 1;
        for (int i = 0; i < len; i++)
            comb *= (unsigned long long)clen;
        total += comb;
    }
    return total;
}

void index_to_password(char *pwd, unsigned long long idx, const char *charset, int len)
{
    int clen = (int)strlen(charset);
    for (int i = len - 1; i >= 0; i--)
    {
        pwd[i] = charset[idx % clen];
        idx /= clen;
    }
    pwd[len] = '\0';
}
