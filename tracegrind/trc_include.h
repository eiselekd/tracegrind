#ifndef TRACEGRIND_INC_H_
#define TRACEGRIND_INC_H_

#include "tracegrind.h"

#define TRC_(str)    VGAPPEND(vgTracegrind_,str)

IRSB* TRC_(instrument)( VgCallbackClosure* closure,
                        IRSB* sb_in,
                        const VexGuestLayout* layout,
                        const VexGuestExtents* vge,
                        const VexArchInfo* archinfo_host,
                        IRType gWordTy, IRType hWordTy );

#endif
