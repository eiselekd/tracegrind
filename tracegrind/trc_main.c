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
#include "pub_tool_basics.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_machine.h"      // VG_(fnptr_to_fnentry)
#include "pub_tool_mallocfree.h"
#include "pub_tool_options.h"
#include "pub_tool_replacemalloc.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_wordfm.h"

#include "trc_include.h"
#include "trc_copy.h"
#include "trc_parser.h"

static ULong g_guest_instrs_executed = 0;

#define binop(_op, _arg1, _arg2) IRExpr_Binop((_op),(_arg1),(_arg2))
#define mkexpr(_tmp)             IRExpr_RdTmp((_tmp))
#define mkU32(_n)                IRExpr_Const(IRConst_U32(_n))
#define mkU64(_n)                IRExpr_Const(IRConst_U64(_n))
#define assign(_t, _e)           IRStmt_WrTmp((_t), (_e))

static VG_REGPARM(2)
void dh_handle_read ( Addr addr, UWord szB )
{
   Block* bk = find_Block_containing(addr);
   if (bk) {
      bk->n_reads += szB;
      if (bk->histoW)
         inc_histo_for_block(bk, addr, szB);
   }
}


void addMemEvent(IRSB* sbOut, Bool isWrite, Int szB, IRExpr* addr,
                 Int goff_sp)
{
   IRType   tyAddr   = Ity_INVALID;
   const HChar* hName= NULL;
   void*    hAddr    = NULL;
   IRExpr** argv     = NULL;
   IRDirty* di       = NULL;

   const Int THRESH = 4096 * 4; // somewhat arbitrary
   const Int rz_szB = VG_STACK_REDZONE_SZB;

   tyAddr = typeOfIRExpr( sbOut->tyenv, addr );
   tl_assert(tyAddr == Ity_I32 || tyAddr == Ity_I64);

   {
      hName = "dh_handle_read";
      hAddr = &dh_handle_read;
   }

   argv = mkIRExprVec_2( addr, mkIRExpr_HWord(szB) );

   /* Add the helper. */
   tl_assert(hName);
   tl_assert(hAddr);
   tl_assert(argv);
   di = unsafeIRDirty_0_N( 2/*regparms*/,
                           hName, VG_(fnptr_to_fnentry)( hAddr ),
                           argv );

   /* Generate the guard condition: "(addr - (SP - RZ)) >u N", for
      some arbitrary N.  If that fails then addr is in the range (SP -
      RZ .. SP + N - RZ).  If N is smallish (a page?) then we can say
      addr is within a page of SP and so can't possibly be a heap
      access, and so can be skipped. */
   IRTemp sp = newIRTemp(sbOut->tyenv, tyAddr);
   addStmtToIRSB( sbOut, assign(sp, IRExpr_Get(goff_sp, tyAddr)));

   IRTemp sp_minus_rz = newIRTemp(sbOut->tyenv, tyAddr);
   addStmtToIRSB(
      sbOut,
      assign(sp_minus_rz,
             tyAddr == Ity_I32
                ? binop(Iop_Sub32, mkexpr(sp), mkU32(rz_szB))
                : binop(Iop_Sub64, mkexpr(sp), mkU64(rz_szB)))
   );

   IRTemp diff = newIRTemp(sbOut->tyenv, tyAddr);
   addStmtToIRSB(
      sbOut,
      assign(diff,
             tyAddr == Ity_I32
                ? binop(Iop_Sub32, addr, mkexpr(sp_minus_rz))
                : binop(Iop_Sub64, addr, mkexpr(sp_minus_rz)))
   );

   IRTemp guard = newIRTemp(sbOut->tyenv, Ity_I1);
   addStmtToIRSB(
      sbOut,
      assign(guard,
             tyAddr == Ity_I32
                ? binop(Iop_CmpLT32U, mkU32(THRESH), mkexpr(diff))
                : binop(Iop_CmpLT64U, mkU64(THRESH), mkexpr(diff)))
   );
   di->guard = mkexpr(guard);

   addStmtToIRSB( sbOut, IRStmt_Dirty(di) );
}


static
void add_counter_update(IRSB* sbOut, Int n)
{
   #if defined(VG_BIGENDIAN)
   # define END Iend_BE
   #elif defined(VG_LITTLEENDIAN)
   # define END Iend_LE
   #else
   # error "Unknown endianness"
   #endif

   // Add code to increment 'g_guest_instrs_executed' by 'n', like this:
   //   WrTmp(t1, Load64(&g_guest_instrs_executed))
   //   WrTmp(t2, Add64(RdTmp(t1), Const(n)))
   //   Store(&g_guest_instrs_executed, t2)

   IRTemp t1 = newIRTemp(sbOut->tyenv, Ity_I64);
   IRTemp t2 = newIRTemp(sbOut->tyenv, Ity_I64);
   IRExpr* counter_addr = mkIRExpr_HWord( (HWord)&g_guest_instrs_executed );

   IRStmt* st1 = assign(t1, IRExpr_Load(END, Ity_I64, counter_addr));
   IRStmt* st2 = assign(t2, binop(Iop_Add64, mkexpr(t1), mkU64(n)));
   IRStmt* st3 = IRStmt_Store(END, counter_addr, mkexpr(t2));

   addStmtToIRSB( sbOut, st1 );
   addStmtToIRSB( sbOut, st2 );
   addStmtToIRSB( sbOut, st3 );
}

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
  Int i, n = 0;
  IRSB*   sb_out;
  sb_out = deepCopyIRSBExceptStmts(sb_in);

  i = 0; n = 0;
  while (i < sb_in->stmts_used ) {

    IRStmt* st = sb_in->stmts[i];
    switch (st->tag) {

    case Ist_IMark: {
      n++;
      break;
    }
    case Ist_Exit: {
      if (n > 0) {
	// Add an increment before the Exit statement, then reset 'n'.
	add_counter_update(sb_out, n);
	n = 0;
      }
      break;
    }
    default: break;
    }
    addStmtToIRSB( sb_out, sb_in->stmts[i] );
    i++;
  }

  if (n > 0) {
    // Add an increment before the SB end.
    add_counter_update(sb_out, n);
  }

  return sb_out;
}

static void TRC_(fini)(Int exitcode)
{
  // show results
   VG_(umsg)("======== SUMMARY STATISTICS ========\n");
   VG_(umsg)("\n");
   VG_(umsg)("guest_insns:  %'llu\n", g_guest_instrs_executed);
   VG_(umsg)("\n");

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
