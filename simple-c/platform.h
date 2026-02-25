#ifndef PLATFORM_H
#define PLATFORM_H

typedef void* (*platform_thread_func_t)(void*);
typedef void platform_thread_t;
typedef void platform_mutex_t;
int platform_thread_create(platform_thread_t **thread, platform_thread_func_t func, void *arg);
int platform_thread_join(platform_thread_t *thread, void **result);
int platform_mutex_create(platform_mutex_t **mutex);
int platform_mutex_lock(platform_mutex_t *mutex);
int platform_mutex_unlock(platform_mutex_t *mutex);
int platform_mutex_destroy(platform_mutex_t *mutex);
int platform_get_cpu_count(void);
#endif 
 