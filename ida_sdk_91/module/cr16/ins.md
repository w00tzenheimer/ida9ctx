```cpp
/*
 *      National Semiconductor Corporation CR16 processor module for IDA.
 *      Copyright (c) 2002-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#ifndef __INSTRS_HPP
#define __INSTRS_HPP

// list of instructions
extern const instruc_t Instructions[];

enum nameNum ENUM_SIZE(uint16)
{
CR16_null = 0,           // Unknown Operation
CR16_addb,
CR16_addw,
CR16_addub,
CR16_adduw,
CR16_addcb,
CR16_addcw,
CR16_andb,
CR16_andw,
CR16_ashub,
CR16_ashuw,
// !!! don't change sequence !!!
CR16_beq,
CR16_bne,
CR16_bcs,
CR16_bcc,
CR16_bhi,
CR16_bls,
CR16_bgt,
CR16_ble,
CR16_bfs,
CR16_bfc,
CR16_blo,
CR16_bhs,
CR16_blt,
CR16_bge,
CR16_br,
//----------------------------
CR16_bal,
CR16_cmpb,
CR16_cmpw,
CR16_beq1b,
CR16_beq1w,
CR16_beq0b,
CR16_beq0w,
CR16_bne1b,
CR16_bne1w,
CR16_bne0b,
CR16_bne0w,
CR16_di,
CR16_ei,
CR16_excp,
// !!! don't change sequence !!!
CR16_jeq,
CR16_jne,
CR16_jcs,
CR16_jcc,
CR16_jhi,
CR16_jls,
CR16_jgt,
CR16_jle,
CR16_jfs,
CR16_jfc,
CR16_jlo,
CR16_jhs,
CR16_jlt,
CR16_jge,
CR16_jump,
//----------------------------
CR16_jal,
CR16_loadb,
CR16_loadw,
CR16_loadm,
CR16_lpr,
CR16_lshb,
CR16_lshw,
CR16_movb,
CR16_movw,
CR16_movxb,
CR16_movzb,
CR16_movd,
CR16_mulb,
CR16_mulw,
CR16_mulsb,
CR16_mulsw,
CR16_muluw,
CR16_nop,
CR16_orb,
CR16_orw,
CR16_push,
CR16_pop,
CR16_popret,
CR16_retx,
// !!! don't change sequence !!!
CR16_seq,
CR16_sne,
CR16_scs,
CR16_scc,
CR16_shi,
CR16_sls,
CR16_sgt,
CR16_sle,
CR16_sfs,
CR16_sfc,
CR16_slo,
CR16_shs,
CR16_slt,
CR16_sge,
//----------------------------
CR16_spr,
CR16_storb,
CR16_storw,
CR16_storm,
CR16_subb,
CR16_subw,
CR16_subcb,
CR16_subcw,
CR16_tbit,
CR16_tbitb,
CR16_tbitw,
CR16_sbitb,
CR16_sbitw,
CR16_cbitb,
CR16_cbitw,
CR16_wait,
CR16_eiwait,
CR16_xorb,
CR16_xorw,
CR16_last
};

#endif

```
