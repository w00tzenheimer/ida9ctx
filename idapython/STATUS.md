```text
Status of the IDC layer
-----------------------

The IDC emulation layer is complete and at par with IDA 5.1,
although it would benefit from more testing.


Status of IDA API wrappers
--------------------------

COMPLETE:   all possible functions wrapped, no SWIG ifdefs
INCOMPLETE: some wrapping or SWIG ifdefs still left
EXCLUDED:   will not be wrapped

allins.hpp    - COMPLETE
range.hpp     - COMPLETE (necessary SWIGdefs)
auto.hpp      - COMPLETE
bytes.hpp     - COMPLETE (some minor unwrapped)
compress.hpp  - EXCLUDED
dbg.hpp       - INCOMPLETE (SWIGs and lot of fixing to do)
demangle.hpp  - EXCLUDED
diskio.hpp    - INCOMPLETE (no SWIGs, some unwrapped)
entry.hpp     - COMPLETE
err.h         - EXCLUDED
exehdr.h      - EXCLUDED
expr.hpp      - COMPLETE (necessary SWIGs)
fixup.hpp     - COMPLETE
fpro.h        - EXCLUDED
frame.hpp     - COMPLETE
funcs.hpp     - COMPLETE (necessary SWIGs, minor FIXME)
gdl.hpp       - EXCLUDED
graph.hpp     - INCOMPLETE
help.h        - EXCLUDED
ida.hpp       - COMPLETE
idd.hpp       - COMPLETE (necessary SWIGs)
idp.hpp       - COMPLETE
ieee.h        - EXCLUDED
intel.hpp     - EXCLUDED
kernwin.hpp   - INCOMPLETE (SWIGs and lot of fixing to do)
lex.hpp       - EXCLUDED
lines.hpp     - INCOMPLETE (few FIXMEs)
llong.hpp     - EXCLUDED
loader.hpp    - INCOMPLETE (few FIXMEs)
md5.h         - EXCLUDED
moves.hpp     - COMPLETE (some needed SWIGs)
nalt.hpp      - INCOMPLETE (SWIGs and lot of fixing to do)
name.hpp      - INCOMPLETE (few FIXMEs)
netnode.hpp   - COMPLETE
offset.hpp    - COMPLETE
prodir.h      - EXCLUDED
pro.h         - COMPLETE (some needed SWIGs)
queue.hpp     - INCOMPLETE (one FIXME)
regex.h       - EXCLUDED
search.hpp    - COMPLETE
segment.hpp   - COMPLETE
sistack.hpp   - EXCLUDED
segregs.hpp   - INCOMPLETE (not wrapped at all)
strlist.hpp   - COMPLETE
typeinf.hpp   - INCOMPLETE (no SWIGs, lot of fixing to do)
ua.hpp        - INCOMPLETE (SWIGs and lot of fixing to do)
va.hpp        - EXCLUDED
vm.hpp        - EXCLUDED
xref.hpp      - COMPLETE

```
