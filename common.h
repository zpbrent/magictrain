#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>

#ifndef __common_h__
#define __common_h__

struct timespec tv2ts(struct timeval tv);
struct timespec double2ts(double d);
double ts2double(struct timespec t);
void ts_add(struct timespec *plhs, const struct timespec rhs);
void ts_sub(struct timespec *plhs, const struct timespec rhs);
double cal_mean(double *data, int len);
double cal_sd(double *data, int len);

#endif

