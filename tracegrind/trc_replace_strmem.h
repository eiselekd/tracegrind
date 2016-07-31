
#ifndef __TRACEGRIND_STR_H
#define __TRACEGRIND_STR_H


/* This file is for inclusion into client (your!) code.

   You can use these macros to manipulate and query memory permissions
   inside your own programs.

   See comment near the top of valgrind.h on how to use them.
*/

#include "valgrind.h"

/* !! ABIWARNING !! ABIWARNING !! ABIWARNING !! ABIWARNING !!
   This enum comprises an ABI exported by Valgrind to programs
   which use client requests.  DO NOT CHANGE THE ORDER OF THESE
   ENTRIES, NOR DELETE ANY -- add new ones at the end. */
typedef
   enum {
      VG_USERREQ__MAKE_MEM_NOACCESS = VG_USERREQ_TOOL_BASE('M','C'),

      /* This is just for tracegrind's internal use - don't use it */
      _VG_USERREQ__TRACEGRIND_RECORD_OVERLAP_ERROR
         = VG_USERREQ_TOOL_BASE('M','C') + 256
   } Vg_TracegrindClientRequest;

#endif
