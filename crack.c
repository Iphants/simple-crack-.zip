#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <zip.h>

#define max_pwd 64
#define progress_interval 100000

const char *lower = "abcdefghijklmnopqrstuvwxyz";
const char *upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const char *digit = "1234567890";
const char *spec = "!@#$^&*()-_=+[]{}:;|?/><.,";

//chek passwd
int try_password(const char *zip_path, const char *pwd)
{
    int err;
    struct  zip *za = zip_open(zip_path, ZIP_RDONLY, &err);
    if (!za) return 0;
    zip_set_default_password(za, pwd);
    zip_int64_t n = zip_get_num_entries (za, 0);
    for (zip_uint64_t i=0; i<n;i++)
    {    
        zip_file_t *zf = zip_fopen_index(za, i, 0);
        if (zf)
        {
            char buf[8];
            if (zip_fread(zf, buf, sizeof(buf))>0)
            {
                zip_fclose(zf);
                zip_close(za);
                return 1; //valid paswd
            }
            zip_fclose(zf);
        }
        
    }
    zip_close(za);
    return 0;
}

//dictionary method
void dictionary_attack(const char *zip_path, const char *wordlist)
{
    FILE *fp = fopen(wordlist, "r");
    if (!fp)
    {
        perror ("wordlist");
        return;
    }
    char pwd[max_pwd];
    unsigned long long attempt = 0;
    time_t start = time(NULL);
    while (fgets(pwd, sizeof(pwd), fp))
    {
        pwd[strcspn(pwd, "\r\n")] = 0;
        if (!pwd[0]) continue;
        attempt++;
        if (attempt % progress_interval == 0)
        printf("[%llu] %s\n", attempt, pwd);
        if (try_password(zip_path, pwd))
        {
            printf ("\n pasword ketemu: %s\n", pwd);
            printf ("Percobaan:%llu\n", attempt);
            printf ("Waktu %.2f detik\n", difftime(time(NULL), start));
            fclose(fp);
            return;
        }
    }
    printf("\n paswd ga ketemu\n");
    fclose(fp);
}

//brute force method
void brute_force(const char *zip_path, const char *charset, int min, int max)
{
    int clen = strlen(charset);
    char pwd[max_pwd];
    unsigned long long total = 0;
    time_t start = time(NULL);
    for (int len = min; len <= max; len++)
    {
        int *idx = calloc(len, sizeof(int));
        memset(pwd, charset[0], len);
        pwd[len] = 0;
        while (1)
        {
            total++;
            if (total % progress_interval == 0)
            printf("[%llu] %s\n", total, pwd);
            if (try_password(zip_path, pwd))
            {
                printf("\n paswd ketemu: %s\n", pwd);
                printf("Percobaan: %llu\n", total);
                printf("Waktu: %.2f detol\n", difftime(time(NULL), start));
                free(idx);
                return;
            }
            int p = len - 1;
            while(p>=0)
            {
                idx[p]++;
                if (idx[p]<clen)
                {
                    pwd[p] = charset[idx[p]];
                    break;
                }
                idx[p] = 0;
                pwd[p] = charset[0];
                p--;
            }
            if (p<0) break;
        }
        free(idx);
    }
    printf("\n Passwd gak ketemeu (bruteforce\n)");
}

//main
int main(int argc, char **argv)
{
    if (argc<3)
    {
        printf("Usage:\n");
        printf("%s file.zip -w wordlist.txt\n", argv[0]);
        printf("%s file.zip -b luds 1 6\n", argv[0]);
        return 1;
    }
    const char *zip_path = argv[1];
    if (!strcmp(argv[2], "-w"))
    {
        dictionary_attack(zip_path, argv[3]);
    }
    else if (!strcmp(argv[2], "-b"))
    {
        char charset[256] = "";
        for (int i = 0; argv[3][i]; i++)
        {
            if (argv[3][i]=='l')
            strcat(charset, lower);
            if (argv[3][1]=='u')
            strcat(charset, upper);
            if (argv[3][1]=='d')
            strcat(charset, digit);
            if (argv[3][1]=='s')
            strcat(charset, spec);
  
        }
        if (strlen(charset) == 0)
            {
                printf("Charset kosong\n");
                return 1;
            }
        brute_force(zip_path, charset, atoi(argv[4]), atoi(argv[5]));
    }
    return 0;
}
