#include "platform.h"
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>


typedef struct {
    pthread_t tid;
} posix_thread_t;
typedef struct {
    pthread_mutex_t mutex;
} posix_mutex_t;
int platform_thread_create(platform_thread_t **thread, platform_thread_func_t func, void *arg)
{
    posix_thread_t *pt = malloc(sizeof(posix_thread_t));
    if (!pt)
        return -1;

    int ret = pthread_create(&pt->tid, NULL, (void*(*)(void*))func, arg);
    if (ret != 0) {
        free(pt);
        return ret;
    }

    *thread = (platform_thread_t *)pt;
    return 0;
}
int platform_thread_join(platform_thread_t *thread, void **result)
{
    if (!thread)
        return -1;

    posix_thread_t *pt = (posix_thread_t *)thread;
    int ret = pthread_join(pt->tid, result);
    free(pt);
    return ret;
}
int platform_mutex_create(platform_mutex_t **mutex)
{
    posix_mutex_t *pm = malloc(sizeof(posix_mutex_t));
    if (!pm)
        return -1;

    int ret = pthread_mutex_init(&pm->mutex, NULL);
    if (ret != 0) {
        free(pm);
        return ret;
    }

    *mutex = (platform_mutex_t *)pm;
    return 0;
}
int platform_mutex_lock(platform_mutex_t *mutex)
{
    if (!mutex)
        return -1;

    posix_mutex_t *pm = (posix_mutex_t *)mutex;
    return pthread_mutex_lock(&pm->mutex);
}
int platform_mutex_unlock(platform_mutex_t *mutex)
{
    if (!mutex)
        return -1;

    posix_mutex_t *pm = (posix_mutex_t *)mutex;
    return pthread_mutex_unlock(&pm->mutex);
}
int platform_mutex_destroy(platform_mutex_t *mutex)
{
    if (!mutex)
        return -1;

    posix_mutex_t *pm = (posix_mutex_t *)mutex;
    int ret = pthread_mutex_destroy(&pm->mutex);
    free(pm);
    return ret;
}
int platform_get_cpu_count(void)
{
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n < 1)
        return 1;
    return (int)n;
}
