#include "platform.h"
#include <windows.h>
#include <stdlib.h>
#include <string.h>


typedef struct {
    HANDLE handle;
} win32_thread_t;

typedef struct {
    HANDLE mutex;
} win32_mutex_t;

int platform_thread_create(platform_thread_t **thread, platform_thread_func_t func, void *arg)
{
    win32_thread_t *wt = malloc(sizeof(win32_thread_t));
    if (!wt)
        return -1;

    HANDLE h = CreateThread (NULL, 0, (LPTHREAD_START_ROUTINE)func, arg, 0, NULL);
    if (h == NULL) {
        free(wt);
        return -1;
    }
    wt->handle = h;
    *thread = (platform_thread_t *)wt;
    return 0;
}

int platform_thread_join(platform_thread_t *thread, void **result)
{
    if (!thread)
        return -1;
    win32_thread_t *wt = (win32_thread_t *)thread;
    DWORD ret = WaitForSingleObject(wt->handle, INFINITE);
    CloseHandle(wt->handle);
    free(wt);

    if (ret == WAIT_OBJECT_0)
        return 0;
    return -1;
}

int platform_mutex_create(platform_mutex_t **mutex)
{
    win32_mutex_t *wm = malloc(sizeof(win32_mutex_t));
    if (!wm)
        return -1;

    HANDLE h = CreateMutex(NULL, FALSE, NULL);
    if (h == NULL) {
        free(wm);
        return -1;
    }
    wm->mutex = h;
    *mutex = (platform_mutex_t *)wm;
    return 0;
}
int platform_mutex_lock(platform_mutex_t *mutex)
{
    if (!mutex)
        return -1;
    win32_mutex_t *wm = (win32_mutex_t *)mutex;
    DWORD ret = WaitForSingleObject(wm->mutex, INFINITE);
    if (ret == WAIT_OBJECT_0)
        return 0;
    return -1;
}
int platform_mutex_unlock(platform_mutex_t *mutex)
{
    if (!mutex)
        return -1;

    win32_mutex_t *wm = (win32_mutex_t *)mutex;
    if (ReleaseMutex(wm->mutex))
        return 0;
    return -1;
}
int platform_mutex_destroy(platform_mutex_t *mutex)
{
    if (!mutex)
        return -1;

    win32_mutex_t *wm = (win32_mutex_t *)mutex;
    CloseHandle(wm->mutex);
    free(wm);
    return 0;
}
int platform_get_cpu_count(void)
{
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    int count = (int)sysinfo.dwNumberOfProcessors;
    if (count < 1)
        return 1;
    return count;
}