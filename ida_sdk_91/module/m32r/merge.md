```cpp
/*
        Interactive disassembler (IDA).
        Copyright (c) 2005-2025 Hex-Rays SA <support@hex-rays.com>
        ALL RIGHTS RESERVED.

        Merge functionality.

*/

#include "m32r.hpp"
#include <merge.hpp>
#include "../mergecmn.cpp"

//-------------------------------------------------------------------------
#define MERGE_IDPFLAGS(mask, name) \
  IDI_ALTENTRY(-1, atag, sizeof(m32r_t::idpflags), mask, nullptr, name)

static const idbattr_info_t idpopts_info[] =
{
  MERGE_IDPFLAGS(IDP_SYNTHETIC,   "analysis.synthetic_insns"),
  MERGE_IDPFLAGS(IDP_REG_ALIASES, "analysis.reg_aliases"    ),
  IDI_DEVICE_ENTRY,
};

DEFINE_SIMPLE_PROCMOD_HANDLER(idpopts_info)

```
