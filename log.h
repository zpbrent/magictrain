/*
 * log.h
 * Header file for log program
 * Last modified for release!
*/

#ifndef __log_h__
#define __log_hh__

class Log
{
   private:
      bool isEnable_;

   public:
      Log();
      ~Log();

      void set_debug();

      void PrintLog(const char *format, ...);
      void PrintDebug(const char *format, ...);
      void PrintErr(const char *format, ...);
};


#endif

