#include "config.h"
#include "charset.h"
#include "password.h"
#include "attack.h"
#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <zip.h>
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>

/* Shared state for brute-force threads */
static atomic_int found = 0;
static char found_pwd[MAX_PWD];
static atomic_ullong total_attempts = 0;
static volatile sig_atomic_t stop_requested = 0;

typedef struct {
    const char *zip_path;
    const char *charset;
    int start;
    int step;
    int min_len;
    int max_len;
    int thread_id;
    unsigned long long attempts;
} thread_args;

static void sigint_handler (int sig)
{
    (void)sig;
    stop_requested = 1;
}

static void *brute_force_thread(void *arg)
{
    thread_args *targ = (thread_args *)arg;
    int err;
    struct zip *za = zip_open(targ->zip_path, ZIP_RDONLY, &err);
    if (!za)
    {
        zip_error_t ze;
        zip_error_init_with_code(&ze, err);

        fprintf(stderr,
            "[thread %d] error opening zip file: %s\n",
            targ->thread_id,
            zip_error_strerror(&ze)
        );

        zip_error_fini(&ze);
        return NULL;
    }

    const char *charset = targ->charset;
    int clen = (int)strlen(charset);
    int start = targ->start;
    int step = targ->step;
    int min_len = targ->min_len;
    int max_len = targ->max_len;
    char pwd[MAX_PWD];
    unsigned long long attempts = 0;
    unsigned long long progress = 0;

    for (int len = min_len; len <= max_len && atomic_load(&found) == 0 && !stop_requested; len++)
    {
        unsigned long long total_combinations = 1;
        for (int i = 0; i < len; i++)
            total_combinations *= (unsigned long long)clen;

        for (unsigned long long idx = start; idx < total_combinations && atomic_load(&found) == 0 && !stop_requested; idx += step)
        {
            attempts++;
            progress++;
            index_to_password(pwd, idx, charset, len);

            if ((attempts % ATTEMPT_CHUNK)==0)
            {
            atomic_fetch_add(&total_attempts, ATTEMPT_CHUNK);
            }
            if (try_password(za, pwd))
            {
                if (atomic_exchange(&found, 1) == 0)
                {
                    strncpy(found_pwd, pwd, MAX_PWD - 1);
                    found_pwd[MAX_PWD - 1] = '\0';
                }
                break;
            }
            if (progress % 10000 == 0)
            {
                printf("[thread %d] [%llu] %s\n", targ->thread_id, attempts, pwd);
                progress = 0;
            }
        }
    }

    unsigned long long remainder = attempts % ATTEMPT_CHUNK;
    if (remainder)
    {
        atomic_fetch_add(&total_attempts, remainder);
    }
    targ->attempts = attempts;
    zip_close(za);
    return NULL;
}

void dictionary_attack(const char *zip_path, const char *wordlist, int threads)
{
    int err;
    struct zip *za = zip_open(zip_path, ZIP_RDONLY, &err);
    if (!za)
    {
        fprintf(stderr, "Error opening zip file\n");
        return;
    }
    FILE *fp = fopen(wordlist, "r");
    if (!fp)
    {
        perror("Error opening wordlist");
        zip_close(za);
        return;
    }
    signal (SIGINT, sigint_handler);

    char pwd[MAX_PWD];
    unsigned long long attempts = 0;
    time_t start = time(NULL);

    printf("Dictionary attack (threads: %d)\n", threads);

    while (fgets(pwd, sizeof(pwd), fp) && !stop_requested)
    {
        pwd[strcspn(pwd, "\r\n")] = '\0';
        if (!pwd[0])
            continue;
        attempts++;

        if (attempts % PROGRESS_INTERVAL == 0)
            printf("[%llu] %s\n", attempts, pwd);

        if (try_password(za, pwd))
        {
            printf("\nPassword ketemu: %s\n", pwd);
            printf("Percobaan: %llu\n", attempts);
            printf("Waktu: %.2f detik\n", difftime(time(NULL), start));
            fclose(fp);
            zip_close(za);
            return;
        }
    }
    if (stop_requested)
    {
        printf("\nAttack stop requested by user\n");
    }
    printf("\nPassword not found in wordlist\n");
    fclose(fp);
    zip_close(za);
}

void brute_force(const char *zip_path, const char *charset, int min_len, int max_len, int threads)
{
    time_t start = time(NULL);
    unsigned long long total_combination = calculate_total_combinations(charset, min_len, max_len);

    printf("Multi-thread brute force started (%d threads)\n", threads);
    printf("File: %s\n", zip_path);
    printf("Charset length: %zu\n", strlen(charset));
    printf("Panjang: %d-%d\n", min_len, max_len);
    printf("Total kombinasi: %llu\n", total_combination);
    printf("Press ctrl+c to stop...\n\n");

    signal(SIGINT, sigint_handler);
    atomic_store(&found, 0);
    atomic_store(&total_attempts, 0);
    memset(found_pwd, 0, sizeof(found_pwd));

    platform_thread_t **thread_ids = malloc(sizeof(platform_thread_t*) * threads);
    thread_args *args = malloc(sizeof(thread_args) * threads);
    if (!thread_ids || !args)
    {
        fprintf (stderr, "Error allocating thread structures\n");
        free (thread_ids);
        free (args);
        return;
    }

    for (int i = 0; i < threads; i++)
    {
        args[i].zip_path = zip_path;
        args[i].charset = charset;
        args[i].start = i;
        args[i].step = threads;
        args[i].min_len = min_len;
        args[i].max_len = max_len;
        args[i].thread_id = i;
        args[i].attempts = 0;
        platform_thread_create(&thread_ids[i], (platform_thread_func_t)brute_force_thread, &args[i]);
    }

    for (int i = 0; i < threads; i++)
        platform_thread_join(thread_ids[i], NULL);
    double elapsed = difftime(time(NULL), start);

    if (atomic_load(&found))
        printf("Password ketemu: %s\n", found_pwd);
    else
        printf("Password tidak ketemu\n");

    printf("Total kombinasi: %llu\n", atomic_load(&total_attempts));
    printf("Waktu dibutuhkan: %.2f detik\n", elapsed);
    if (elapsed > 0)
        printf("Kecepatan: %.0f pwd/detik\n", atomic_load(&total_attempts) / elapsed);

    printf("Threads digunakan: %d\n", threads);
    printf("Statistik thread:\n");
    unsigned long long total_thread_attempt = 0;
    for (int i = 0; i < threads; i++)
    {
        total_thread_attempt += args[i].attempts;
    }
    if (total_thread_attempt != total_attempts)
        printf("Perbedaan: %lld percobaan\n", (long long)(total_attempts - total_thread_attempt));

    free(thread_ids);
    free(args);
}

void human_brute_force (const char *zip_path, int threads)
{
    time_t start = time(NULL);
    const struct 
    {
        const char *charset_spec;
        int min_len;
        int max_len;
        int priority;
        const char *description;
    }
    human_behavior[] = 
    {
        {"l", 6, 8, 1, "lowercase only (6-8)"},
        {"lu", 6, 8 , 2, "lowercase + uppercase (6-8)"},
        {"ld", 6, 8, 3, "lowercase + digit (6-8)"},
        {"lud", 6, 8, 4, "lowercase + uppercase + digit (6-8)"},
        {"ld", 8, 10, 5, "lowercase + digit (8-10)"},
        {"lud", 8, 10, 6, "lowercase + uppercase + digit (8-10)"},
        {"luds", 6, 9, 7, "lowercase +  uppercase + digit + special (6-9)"},
    };
    int num_strategies = sizeof(human_behavior)/sizeof(human_behavior[0]);

    printf("human patter brute-force attack\n");
    printf("File: %s\n\n", zip_path);
    atomic_store(&found, 0);
    atomic_store(&total_attempts, 0);
    memset (found_pwd, 0, sizeof(found_pwd));

    for (int s=0; s < num_strategies;s++)
    {
        char charset [256];
        if (build_charset_from_spec(charset, human_behavior[s].charset_spec) !=0)
            continue;

        printf("mimicry %d/%d: %s (charset: %s)\n", s+1, num_strategies, human_behavior[s].description, human_behavior[s].charset_spec);
        brute_force(zip_path, charset, human_behavior[s].min_len, human_behavior[s].max_len, threads);

        if (atomic_load(&found))
            break;
        printf("not found with this method\n\n");
    }

    double elapsed = difftime(time(NULL), start);
    if (atomic_load(&found))
    {
        printf("\npasswd found: %s\n", found_pwd);
        printf("total time: %.2f second\n", elapsed);
    }
    else
    {
        printf("\npasswd not found in any method\n");
        printf("total time: %.2f second\n", elapsed);
    }
}