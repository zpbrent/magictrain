/*
 * log.cpp
 * Used for printing out debug information
*/

#include <stdio.h> 
#include <stdarg.h> 
#include <time.h>
#include <sys/time.h>
#include "log.h"

/* Constructor */
Log::Log()
{
   isEnable_ = false;
}

/* Destructor */
Log::~Log()
{

}

/* enable PrintDebug */
void Log::set_debug()
{
   isEnable_ = true;
}

/* For printing out log information */
void Log::PrintLog(const char *format, ...)
{
   va_list ap;
   struct timeval t;

   va_start(ap, format);
   gettimeofday(&t, NULL);
   fprintf(stdout, "[%lu.%06lu] ", (long int)t.tv_sec, (long int)t.tv_usec);
   vfprintf(stdout, format, ap);
   va_end(ap);
   fflush(stdout);
}
   
/* For printing out debug information (used for debugging!) */
void Log::PrintDebug(const char *format, ...)
{
   va_list ap;
   struct timeval t;

   if (isEnable_)
   {
      va_start(ap, format);
      gettimeofday(&t, NULL);
      fprintf(stdout, "[Dbg][%lu.%06lu] ", (long int)t.tv_sec, (long int)t.tv_usec);
      vfprintf(stdout, format, ap);
      va_end(ap);
      fflush(stdout);
   }
}

/* For printing out error information */
void Log::PrintErr(const char *format, ...)
{
   va_list ap;
   struct timeval t;

   va_start(ap, format);
   gettimeofday(&t, NULL);
   fprintf(stderr, "[Err][%lu.%06lu] ", (long int)t.tv_sec, (long int)t.tv_usec);
   vfprintf(stderr, format, ap);
   va_end(ap);
   fflush(stderr);
}
   
