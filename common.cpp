
#include <strings.h>
#include <string.h>
#include <time.h>
#include<stdio.h>
#include "common.h"
#include "log.h"

extern Log* logger;

#define NS_PER_SEC		1000000000L /* nanoseconds per second */

/* convert a timeval structure to a timespec structure */
struct timespec tv2ts(struct timeval tv) 
{
   struct timespec ts;
   ts.tv_sec = (long int)tv.tv_sec;
   ts.tv_nsec = (long int)(tv.tv_usec*1000);
   return ts;
}

/* return the timespec structure from double */
struct timespec double2ts(double d) 
{
   struct timespec t;
   t.tv_sec = (long int)d;
   t.tv_nsec = (long int)((d - (double)t.tv_sec)*NS_PER_SEC);
   return t;
}

/* return the timestamp in double*/
double ts2double(struct timespec t) 
{
   return (double)t.tv_sec + ((double)t.tv_nsec/(double)NS_PER_SEC);
}

/* add the RHS to the LHS, answer in *plhs */
void ts_add(struct timespec *plhs, const struct timespec rhs) 
{
   plhs->tv_sec += rhs.tv_sec;
   plhs->tv_nsec += rhs.tv_nsec;
   if (plhs->tv_nsec >= NS_PER_SEC) 
   {
      plhs->tv_nsec -= NS_PER_SEC;
      plhs->tv_sec += 1;
   }
}

/* subtract the rhs from the lhs, result in plhs */
void ts_sub(struct timespec *plhs, const struct timespec rhs) 
{
   /* sanity check, lhs MUST BE more than rhs */
   if ((plhs->tv_sec < rhs.tv_sec) || (plhs->tv_sec == rhs.tv_sec && plhs->tv_nsec < rhs.tv_nsec)) 
   {
      plhs->tv_sec = plhs->tv_nsec = 0;
      return;
   }
   if (plhs->tv_nsec >= rhs.tv_nsec) 
   {
      plhs->tv_nsec -= rhs.tv_nsec;
   } 
   else if (plhs->tv_nsec < rhs.tv_nsec) 
   {
      plhs->tv_nsec += NS_PER_SEC - rhs.tv_nsec;
      plhs->tv_sec -= 1;
   }
   plhs->tv_sec -= rhs.tv_sec;
}

/* calculate a mean value of an array of data */
double cal_mean(double *data, int len)
{
   double sum = 0;
   for (int i=0; i<len; i++)
   {
      sum = sum + data[i];
   }
   return sum/len;
}

/* calculate a standard deviation of an array of data */
double cal_sd(double *data, int len)
{
   double mean;
   double sum = 0;

   mean = cal_mean(data, len);

   for (int i=0; i<len; i++)
   {
      sum = sum + pow(data[i] - mean, 2);
   }
   return sqrt(sum/len);
}

