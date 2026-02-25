#include "config.h"
#include "charset.h"
#include "attack.h"
#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog)
{
    printf(
        "Usage:\n"
        "  %s file.zip -w wordlist.txt [-t threads]\n"
        "  %s file.zip -b luds min max [-t threads]\n\n"
        "  %s file.zip -s [-t threads]\n\n"
        "Options:\n"
        "  -t <n>    total threads (default: auto / number of CPU cores)\n\n"
        "   -h       human behavior mode (try human-likely pattern first)\n\n"
        "Charset options:\n"
        "  l = lowercase (a-z)\n"
        "  u = uppercase (A-Z)\n"
        "  d = digits (0-9)\n"
        "  s = special characters (punctuation)\n\n"
        "Examples:\n"
        "  %s file.zip -w wordlist.txt\n"
        "  %s file.zip -b lud 4 6\n"
        "  %s file.zip -h\n",
        prog, prog, prog, prog, prog, prog
    );
}

static int get_default_threads(void)
{
    int n = platform_get_cpu_count();
    if (n < 1) return 1;
    return n;
}

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        usage(argv[0]);
        return 1;
    }
    int threads = get_default_threads();
    for (int i = 1; i < argc; i++) 
    {
        if (strcmp(argv[i], "-t") == 0) 
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "Error: -t <n> requires a number\n");
                return 1;
            }
            threads = atoi(argv[i + 1]);
            if (threads < 1) {
                fprintf(stderr, "Error: thread count must be at least 1\n");
                return 1;
            }
            i++;
        }
    }

    const char *zip_path = argv[1];
    const char *wordlist = NULL;
    const char *bf_charset_spec = NULL;
    int bf_min = 0, bf_max = 0;
    int human_behavior = 0;

    for (int i = 2; i < argc; i++)
    {
        if (strcmp(argv[i], "-w") == 0 && i+1 < argc)
        {
            wordlist = argv[i+1];
            i++;
        }
        else if (strcmp(argv[i], "-b") == 0)
        {
            if (i+3 >= argc)
            {
                fprintf(stderr, "Error: -b need charset, min, max\n");
                return 1;
            }
            bf_charset_spec = argv[i+1];
            bf_min = atoi(argv[i+2]);
            bf_max = atoi(argv[i+3]);
            i+=3;
        }
        else if (strcmp(argv[i], "-h") == 0)
        {
            human_behavior = 1;
        }
    }
    long cores = platform_get_cpu_count();

    if (wordlist)
    {
        printf("Threads used: %d (%d cores detected)\n", threads, cores);
        dictionary_attack(zip_path, wordlist, threads);
        return 0;
    }
    if (human_behavior)
    {
        printf("Thread used: %d (%d cores detected)\n", threads, cores);
        human_brute_force (zip_path, threads);
        return 0;
    }

    if (bf_charset_spec)
    {
        char charset[256];
        if (build_charset_from_spec(charset, bf_charset_spec) != 0)
            return 1;
        if (strlen(charset) == 0)
        {
            fprintf(stderr, "Charset kosong. Gunakan l, u, d, atau s.\n");
            return 1;
        }

        if (bf_min < 1 || bf_max > 10 || bf_min > bf_max)
        {
            fprintf(stderr, "Invalid length range: %d-%d (use 1-10, min <= max)\n", bf_min, bf_max);
            return 1;
        }

        printf("Threads used:%d (%d cores detected)\n", threads, cores);
        brute_force(zip_path, charset, bf_min, bf_max, threads);
        return 0;
    }

    fprintf(stderr, "Unknown or missing option (-w or -b)\n");
    usage(argv[0]);
    return 1;
}