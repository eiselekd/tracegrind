#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_gdbserver.h"

#include "pub_tool_vki.h"           // keeps libcproc.h happy, syscall nums
#include "pub_tool_aspacemgr.h"     // VG_(am_shadow_alloc)
#include "pub_tool_debuginfo.h"     // VG_(get_fnname_w_offset), VG_(get_fnname)
#include "pub_tool_hashtable.h"     // For tnt_include.h, VgHashtable
#include "pub_tool_libcassert.h"    // tl_assert
#include "pub_tool_libcbase.h"      // VG_STREQN
#include "pub_tool_libcprint.h"     // VG_(message)
#include "pub_tool_libcproc.h"      // VG_(getenv)
#include "pub_tool_replacemalloc.h" // VG_(replacement_malloc_process_cmd_line_option)
#include "pub_tool_machine.h"       // VG_(get_IP)
#include "pub_tool_mallocfree.h"    // VG_(out_of_memory_NORETURN)
#include "pub_tool_options.h"       // VG_STR/BHEX/BINT_CLO
#include "pub_tool_oset.h"          // OSet operations
#include "pub_tool_threadstate.h"   // VG_(get_running_tid)
#include "pub_tool_xarray.h"        // VG_(*XA)
#include "pub_tool_stacktrace.h"    // VG_(get_and_pp_StackTrace)
#include "pub_tool_libcfile.h"      // VG_(readlink)
#include "pub_tool_addrinfo.h"      // VG_(describe_addr)

#include "trc_include.h"
#include "trc_copy.h"
#include "trc_parser.h"

static void TRC_(post_clo_init)(void)
{
}

IRSB* TRC_(instrument)( VgCallbackClosure* closure,
                        IRSB* sb_in,
                        const VexGuestLayout* layout,
                        const VexGuestExtents* vge,
                        const VexArchInfo* archinfo_host,
                        IRType gWordTy, IRType hWordTy )
{
  Int i;
  IRSB*   sb_out;
  sb_out = deepCopyIRSBExceptStmts(sb_in);

  i = 0;
  while (i < sb_in->stmts_used ) {
    addStmtToIRSB( sb_out, sb_in->stmts[i] );
    i++;
  }

  return sb_out;
}

static void TRC_(fini)(Int exitcode)
{
}

static void trc_pre_clo_init(void)
{
  VG_(details_name)            ("Tracegrind");
  VG_(details_version)         ("0.1");
  VG_(details_description)     ("valgrind instruction tracer");
  VG_(details_copyright_author)("Copyright (C) nodo");
  VG_(details_bug_reports_to)  ("nodo@nodo.org");
  VG_(basic_tool_funcs)        (TRC_(post_clo_init),
                                TRC_(instrument),
                                TRC_(fini));

}

VG_DETERMINE_INTERFACE_VERSION(trc_pre_clo_init)
