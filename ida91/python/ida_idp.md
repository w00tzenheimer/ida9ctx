```python
"""Contains definition of the interface to IDP modules.

The interface consists of two structures:
* definition of target assembler: ::ash
* definition of current processor: ::ph


These structures contain information about target processor and assembler features.
It also defines two groups of kernel events:
* processor_t::event_t processor related events
* idb_event:event_code_t database related events


The processor related events are used to communicate with the processor module. The database related events are used to inform any interested parties, like plugins or processor modules, about the changes in the database. 
    """
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_idp
else:
    import _ida_idp
try:
    import builtins as __builtin__
except ImportError:
    import __builtin__


def _swig_repr(self):
    try:
        strthis = 'proxy of ' + self.this.__repr__()
    except __builtin__.Exception:
        strthis = ''
    return '<%s.%s; %s >' % (self.__class__.__module__, self.__class__.
        __name__, strthis)


def _swig_setattr_nondynamic_instance_variable(set):

    def set_instance_attr(self, name, value):
        if name == 'this':
            set(self, name, value)
        elif name == 'thisown':
            self.this.own(value)
        elif hasattr(self, name) and isinstance(getattr(type(self), name),
            property):
            set(self, name, value)
        else:
            raise AttributeError('You cannot add instance attributes to %s' %
                self)
    return set_instance_attr


def _swig_setattr_nondynamic_class_variable(set):

    def set_class_attr(cls, name, value):
        if hasattr(cls, name) and not isinstance(getattr(cls, name), property):
            set(cls, name, value)
        else:
            raise AttributeError('You cannot add class attributes to %s' % cls)
    return set_class_attr


def _swig_add_metaclass(metaclass):
    """Class decorator for adding a metaclass to a SWIG wrapped class - a slimmed down version of six.add_metaclass"""

    def wrapper(cls):
        return metaclass(cls.__name__, cls.__bases__, cls.__dict__.copy())
    return wrapper


class _SwigNonDynamicMeta(type):
    """Meta class to enforce nondynamic attributes (no new attributes) for a class"""
    __setattr__ = _swig_setattr_nondynamic_class_variable(type.__setattr__)


import weakref
SWIG_PYTHON_LEGACY_BOOL = _ida_idp.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi


class reg_access_vec_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_idp.reg_access_vec_t_swiginit(self, _ida_idp.
            new_reg_access_vec_t(*args))
    __swig_destroy__ = _ida_idp.delete_reg_access_vec_t

    def push_back(self, *args) ->'reg_access_t &':
        return _ida_idp.reg_access_vec_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_idp.reg_access_vec_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_idp.reg_access_vec_t_size(self)

    def empty(self) ->bool:
        return _ida_idp.reg_access_vec_t_empty(self)

    def at(self, _idx: 'size_t') ->'reg_access_t const &':
        return _ida_idp.reg_access_vec_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_idp.reg_access_vec_t_qclear(self)

    def clear(self) ->None:
        return _ida_idp.reg_access_vec_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_idp.reg_access_vec_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_idp.reg_access_vec_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_idp.reg_access_vec_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_idp.reg_access_vec_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_idp.reg_access_vec_t_truncate(self)

    def swap(self, r: 'reg_access_vec_t') ->None:
        return _ida_idp.reg_access_vec_t_swap(self, r)

    def extract(self) ->'reg_access_t *':
        return _ida_idp.reg_access_vec_t_extract(self)

    def inject(self, s: 'reg_access_t', len: 'size_t') ->None:
        return _ida_idp.reg_access_vec_t_inject(self, s, len)

    def __eq__(self, r: 'reg_access_vec_t') ->bool:
        return _ida_idp.reg_access_vec_t___eq__(self, r)

    def __ne__(self, r: 'reg_access_vec_t') ->bool:
        return _ida_idp.reg_access_vec_t___ne__(self, r)

    def begin(self, *args) ->'qvector< reg_access_t >::const_iterator':
        return _ida_idp.reg_access_vec_t_begin(self, *args)

    def end(self, *args) ->'qvector< reg_access_t >::const_iterator':
        return _ida_idp.reg_access_vec_t_end(self, *args)

    def insert(self, it: 'reg_access_t', x: 'reg_access_t'
        ) ->'qvector< reg_access_t >::iterator':
        return _ida_idp.reg_access_vec_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< reg_access_t >::iterator':
        return _ida_idp.reg_access_vec_t_erase(self, *args)

    def find(self, *args) ->'qvector< reg_access_t >::const_iterator':
        return _ida_idp.reg_access_vec_t_find(self, *args)

    def has(self, x: 'reg_access_t') ->bool:
        return _ida_idp.reg_access_vec_t_has(self, x)

    def add_unique(self, x: 'reg_access_t') ->bool:
        return _ida_idp.reg_access_vec_t_add_unique(self, x)

    def _del(self, x: 'reg_access_t') ->bool:
        return _ida_idp.reg_access_vec_t__del(self, x)

    def __len__(self) ->'size_t':
        return _ida_idp.reg_access_vec_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'reg_access_t const &':
        return _ida_idp.reg_access_vec_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'reg_access_t') ->None:
        return _ida_idp.reg_access_vec_t___setitem__(self, i, v)

    def append(self, x: 'reg_access_t') ->None:
        return _ida_idp.reg_access_vec_t_append(self, x)

    def extend(self, x: 'reg_access_vec_t') ->None:
        return _ida_idp.reg_access_vec_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_idp.reg_access_vec_t_swigregister(reg_access_vec_t)
IDP_INTERFACE_VERSION = _ida_idp.IDP_INTERFACE_VERSION
"""The interface version number. 
        """
CF_STOP = _ida_idp.CF_STOP
"""Instruction doesn't pass execution to the next instruction 
        """
CF_CALL = _ida_idp.CF_CALL
"""CALL instruction (should make a procedure here)
"""
CF_CHG1 = _ida_idp.CF_CHG1
"""The instruction modifies the first operand.
"""
CF_CHG2 = _ida_idp.CF_CHG2
"""The instruction modifies the second operand.
"""
CF_CHG3 = _ida_idp.CF_CHG3
"""The instruction modifies the third operand.
"""
CF_CHG4 = _ida_idp.CF_CHG4
"""The instruction modifies the fourth operand.
"""
CF_CHG5 = _ida_idp.CF_CHG5
"""The instruction modifies the fifth operand.
"""
CF_CHG6 = _ida_idp.CF_CHG6
"""The instruction modifies the sixth operand.
"""
CF_USE1 = _ida_idp.CF_USE1
"""The instruction uses value of the first operand.
"""
CF_USE2 = _ida_idp.CF_USE2
"""The instruction uses value of the second operand.
"""
CF_USE3 = _ida_idp.CF_USE3
"""The instruction uses value of the third operand.
"""
CF_USE4 = _ida_idp.CF_USE4
"""The instruction uses value of the fourth operand.
"""
CF_USE5 = _ida_idp.CF_USE5
"""The instruction uses value of the fifth operand.
"""
CF_USE6 = _ida_idp.CF_USE6
"""The instruction uses value of the sixth operand.
"""
CF_JUMP = _ida_idp.CF_JUMP
"""The instruction passes execution using indirect jump or call (thus needs additional analysis) 
        """
CF_SHFT = _ida_idp.CF_SHFT
"""Bit-shift instruction (shl,shr...)
"""
CF_HLL = _ida_idp.CF_HLL
"""Instruction may be present in a high level language function 
        """
CF_CHG7 = _ida_idp.CF_CHG7
"""The instruction modifies the seventh operand.
"""
CF_CHG8 = _ida_idp.CF_CHG8
"""The instruction modifies the eighth operand.
"""
CF_USE7 = _ida_idp.CF_USE7
"""The instruction uses value of the seventh operand.
"""
CF_USE8 = _ida_idp.CF_USE8
"""The instruction uses value of the eighth operand.
"""


def has_cf_chg(feature: int, opnum: 'uint') ->bool:
    """Does an instruction with the specified feature modify the i-th operand?
"""
    return _ida_idp.has_cf_chg(feature, opnum)


def has_cf_use(feature: int, opnum: 'uint') ->bool:
    """Does an instruction with the specified feature use a value of the i-th operand?
"""
    return _ida_idp.has_cf_use(feature, opnum)


def has_insn_feature(icode: 'uint16', bit: int) ->bool:
    """Does the specified instruction have the specified feature?
"""
    return _ida_idp.has_insn_feature(icode, bit)


def is_call_insn(insn: 'insn_t const &') ->bool:
    """Is the instruction a "call"?
"""
    return _ida_idp.is_call_insn(insn)


IRI_EXTENDED = _ida_idp.IRI_EXTENDED
"""Is the instruction a "return"?

include instructions like "leave" that begin the function epilog 
        """
IRI_RET_LITERALLY = _ida_idp.IRI_RET_LITERALLY
"""report only 'ret' instructions
"""
IRI_SKIP_RETTARGET = _ida_idp.IRI_SKIP_RETTARGET
"""exclude 'ret' instructions that have special targets (see set_ret_target in PC) 
        """
IRI_STRICT = _ida_idp.IRI_STRICT


def is_ret_insn(*args) ->bool:
    return _ida_idp.is_ret_insn(*args)


def is_indirect_jump_insn(insn: 'insn_t const &') ->bool:
    """Is the instruction an indirect jump?
"""
    return _ida_idp.is_indirect_jump_insn(insn)


def is_basic_block_end(insn: 'insn_t const &', call_insn_stops_block: bool
    ) ->bool:
    """Is the instruction the end of a basic block?
"""
    return _ida_idp.is_basic_block_end(insn, call_insn_stops_block)


class asm_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    flag: 'uint32' = property(_ida_idp.asm_t_flag_get, _ida_idp.asm_t_flag_set)
    """Assembler feature bits 
        """
    uflag: 'uint16' = property(_ida_idp.asm_t_uflag_get, _ida_idp.
        asm_t_uflag_set)
    """user defined flags (local only for IDP) you may define and use your own bits 
        """
    name: 'char const *' = property(_ida_idp.asm_t_name_get, _ida_idp.
        asm_t_name_set)
    """Assembler name (displayed in menus)
"""
    help: 'help_t' = property(_ida_idp.asm_t_help_get, _ida_idp.asm_t_help_set)
    """Help screen number, 0 - no help.
"""
    header: 'char const *const *' = property(_ida_idp.asm_t_header_get,
        _ida_idp.asm_t_header_set)
    """array of automatically generated header lines they appear at the start of disassembled text 
        """
    origin: 'char const *' = property(_ida_idp.asm_t_origin_get, _ida_idp.
        asm_t_origin_set)
    """org directive
"""
    end: 'char const *' = property(_ida_idp.asm_t_end_get, _ida_idp.
        asm_t_end_set)
    """end directive
"""
    cmnt: 'char const *' = property(_ida_idp.asm_t_cmnt_get, _ida_idp.
        asm_t_cmnt_set)
    """comment string (see also cmnt2)
"""
    ascsep: 'char' = property(_ida_idp.asm_t_ascsep_get, _ida_idp.
        asm_t_ascsep_set)
    """string literal delimiter
"""
    accsep: 'char' = property(_ida_idp.asm_t_accsep_get, _ida_idp.
        asm_t_accsep_set)
    """char constant delimiter
"""
    esccodes: 'char const *' = property(_ida_idp.asm_t_esccodes_get,
        _ida_idp.asm_t_esccodes_set)
    """special chars that cannot appear as is in string and char literals 
        """
    a_ascii: 'char const *' = property(_ida_idp.asm_t_a_ascii_get, _ida_idp
        .asm_t_a_ascii_set)
    """string literal directive
"""
    a_byte: 'char const *' = property(_ida_idp.asm_t_a_byte_get, _ida_idp.
        asm_t_a_byte_set)
    """byte directive
"""
    a_word: 'char const *' = property(_ida_idp.asm_t_a_word_get, _ida_idp.
        asm_t_a_word_set)
    """word directive
"""
    a_dword: 'char const *' = property(_ida_idp.asm_t_a_dword_get, _ida_idp
        .asm_t_a_dword_set)
    """nullptr if not allowed
"""
    a_qword: 'char const *' = property(_ida_idp.asm_t_a_qword_get, _ida_idp
        .asm_t_a_qword_set)
    """nullptr if not allowed
"""
    a_oword: 'char const *' = property(_ida_idp.asm_t_a_oword_get, _ida_idp
        .asm_t_a_oword_set)
    """nullptr if not allowed
"""
    a_float: 'char const *' = property(_ida_idp.asm_t_a_float_get, _ida_idp
        .asm_t_a_float_set)
    """float; 4bytes; nullptr if not allowed
"""
    a_double: 'char const *' = property(_ida_idp.asm_t_a_double_get,
        _ida_idp.asm_t_a_double_set)
    """double; 8bytes; nullptr if not allowed
"""
    a_tbyte: 'char const *' = property(_ida_idp.asm_t_a_tbyte_get, _ida_idp
        .asm_t_a_tbyte_set)
    """long double; nullptr if not allowed
"""
    a_packreal: 'char const *' = property(_ida_idp.asm_t_a_packreal_get,
        _ida_idp.asm_t_a_packreal_set)
    """packed decimal real nullptr if not allowed
"""
    a_dups: 'char const *' = property(_ida_idp.asm_t_a_dups_get, _ida_idp.
        asm_t_a_dups_set)
    """array keyword. the following sequences may appear:
* #h header
* #d size
* #v value
* #s(b,w,l,q,f,d,o) size specifiers for byte,word, dword,qword, float,double,oword 


        """
    a_bss: 'char const *' = property(_ida_idp.asm_t_a_bss_get, _ida_idp.
        asm_t_a_bss_set)
    """uninitialized data directive should include 's' for the size of data 
        """
    a_equ: 'char const *' = property(_ida_idp.asm_t_a_equ_get, _ida_idp.
        asm_t_a_equ_set)
    """'equ' Used if AS_UNEQU is set
"""
    a_seg: 'char const *' = property(_ida_idp.asm_t_a_seg_get, _ida_idp.
        asm_t_a_seg_set)
    """'seg ' prefix (example: push seg seg001)
"""
    a_curip: 'char const *' = property(_ida_idp.asm_t_a_curip_get, _ida_idp
        .asm_t_a_curip_set)
    """current IP (instruction pointer) symbol in assembler
"""
    a_public: 'char const *' = property(_ida_idp.asm_t_a_public_get,
        _ida_idp.asm_t_a_public_set)
    """"public" name keyword. nullptr-use default, ""-do not generate
"""
    a_weak: 'char const *' = property(_ida_idp.asm_t_a_weak_get, _ida_idp.
        asm_t_a_weak_set)
    """"weak" name keyword. nullptr-use default, ""-do not generate
"""
    a_extrn: 'char const *' = property(_ida_idp.asm_t_a_extrn_get, _ida_idp
        .asm_t_a_extrn_set)
    """"extern" name keyword
"""
    a_comdef: 'char const *' = property(_ida_idp.asm_t_a_comdef_get,
        _ida_idp.asm_t_a_comdef_set)
    """"comm" (communal variable)
"""
    a_align: 'char const *' = property(_ida_idp.asm_t_a_align_get, _ida_idp
        .asm_t_a_align_set)
    """"align" keyword
"""
    lbrace: 'char' = property(_ida_idp.asm_t_lbrace_get, _ida_idp.
        asm_t_lbrace_set)
    """left brace used in complex expressions
"""
    rbrace: 'char' = property(_ida_idp.asm_t_rbrace_get, _ida_idp.
        asm_t_rbrace_set)
    """right brace used in complex expressions
"""
    a_mod: 'char const *' = property(_ida_idp.asm_t_a_mod_get, _ida_idp.
        asm_t_a_mod_set)
    """% mod assembler time operation
"""
    a_band: 'char const *' = property(_ida_idp.asm_t_a_band_get, _ida_idp.
        asm_t_a_band_set)
    """& bit and assembler time operation
"""
    a_bor: 'char const *' = property(_ida_idp.asm_t_a_bor_get, _ida_idp.
        asm_t_a_bor_set)
    """| bit or assembler time operation
"""
    a_xor: 'char const *' = property(_ida_idp.asm_t_a_xor_get, _ida_idp.
        asm_t_a_xor_set)
    """^ bit xor assembler time operation
"""
    a_bnot: 'char const *' = property(_ida_idp.asm_t_a_bnot_get, _ida_idp.
        asm_t_a_bnot_set)
    """~ bit not assembler time operation
"""
    a_shl: 'char const *' = property(_ida_idp.asm_t_a_shl_get, _ida_idp.
        asm_t_a_shl_set)
    """<< shift left assembler time operation
"""
    a_shr: 'char const *' = property(_ida_idp.asm_t_a_shr_get, _ida_idp.
        asm_t_a_shr_set)
    """>> shift right assembler time operation
"""
    a_sizeof_fmt: 'char const *' = property(_ida_idp.asm_t_a_sizeof_fmt_get,
        _ida_idp.asm_t_a_sizeof_fmt_set)
    """size of type (format string)
"""
    flag2: 'uint32' = property(_ida_idp.asm_t_flag2_get, _ida_idp.
        asm_t_flag2_set)
    """Secondary assembler feature bits 
        """
    cmnt2: 'char const *' = property(_ida_idp.asm_t_cmnt2_get, _ida_idp.
        asm_t_cmnt2_set)
    """comment close string (usually nullptr) this is used to denote a string which closes comments, for example, if the comments are represented with (* ... *) then cmnt = "(*" and cmnt2 = "*)" 
        """
    low8: 'char const *' = property(_ida_idp.asm_t_low8_get, _ida_idp.
        asm_t_low8_set)
    """low8 operation, should contain s for the operand
"""
    high8: 'char const *' = property(_ida_idp.asm_t_high8_get, _ida_idp.
        asm_t_high8_set)
    """high8
"""
    low16: 'char const *' = property(_ida_idp.asm_t_low16_get, _ida_idp.
        asm_t_low16_set)
    """low16
"""
    high16: 'char const *' = property(_ida_idp.asm_t_high16_get, _ida_idp.
        asm_t_high16_set)
    """high16
"""
    a_include_fmt: 'char const *' = property(_ida_idp.
        asm_t_a_include_fmt_get, _ida_idp.asm_t_a_include_fmt_set)
    """the include directive (format string)
"""
    a_vstruc_fmt: 'char const *' = property(_ida_idp.asm_t_a_vstruc_fmt_get,
        _ida_idp.asm_t_a_vstruc_fmt_set)
    """if a named item is a structure and displayed in the verbose (multiline) form then display the name as printf(a_strucname_fmt, typename) (for asms with type checking, e.g. tasm ideal) 
        """
    a_rva: 'char const *' = property(_ida_idp.asm_t_a_rva_get, _ida_idp.
        asm_t_a_rva_set)
    """'rva' keyword for image based offsets (see REFINFO_RVAOFF) 
        """
    a_yword: 'char const *' = property(_ida_idp.asm_t_a_yword_get, _ida_idp
        .asm_t_a_yword_set)
    """32-byte (256-bit) data; nullptr if not allowed requires AS2_YWORD 
        """
    a_zword: 'char const *' = property(_ida_idp.asm_t_a_zword_get, _ida_idp
        .asm_t_a_zword_set)
    """64-byte (512-bit) data; nullptr if not allowed requires AS2_ZWORD 
        """

    def __init__(self):
        _ida_idp.asm_t_swiginit(self, _ida_idp.new_asm_t())
    __swig_destroy__ = _ida_idp.delete_asm_t


_ida_idp.asm_t_swigregister(asm_t)
AS_OFFST = _ida_idp.AS_OFFST
"""offsets are 'offset xxx' ?
"""
AS_COLON = _ida_idp.AS_COLON
"""create colons after data names ?
"""
AS_UDATA = _ida_idp.AS_UDATA
"""can use '?' in data directives
"""
AS_2CHRE = _ida_idp.AS_2CHRE
"""double char constants are: "xy
"""
AS_NCHRE = _ida_idp.AS_NCHRE
"""char constants are: 'x
"""
AS_N2CHR = _ida_idp.AS_N2CHR
"""can't have 2 byte char consts
"""
AS_1TEXT = _ida_idp.AS_1TEXT
"""1 text per line, no bytes
"""
AS_NHIAS = _ida_idp.AS_NHIAS
"""no characters with high bit
"""
AS_NCMAS = _ida_idp.AS_NCMAS
"""no commas in ascii directives
"""
AS_HEXFM = _ida_idp.AS_HEXFM
"""mask - hex number format
"""
ASH_HEXF0 = _ida_idp.ASH_HEXF0
"""34h
"""
ASH_HEXF1 = _ida_idp.ASH_HEXF1
"""h'34
"""
ASH_HEXF2 = _ida_idp.ASH_HEXF2
"""34
"""
ASH_HEXF3 = _ida_idp.ASH_HEXF3
"""0x34
"""
ASH_HEXF4 = _ida_idp.ASH_HEXF4
"""$34
"""
ASH_HEXF5 = _ida_idp.ASH_HEXF5
"""<^R > (radix)
"""
AS_DECFM = _ida_idp.AS_DECFM
"""mask - decimal number format
"""
ASD_DECF0 = _ida_idp.ASD_DECF0
"""34
"""
ASD_DECF1 = _ida_idp.ASD_DECF1
"""#34
"""
ASD_DECF2 = _ida_idp.ASD_DECF2
"""34.
"""
ASD_DECF3 = _ida_idp.ASD_DECF3
""".34
"""
AS_OCTFM = _ida_idp.AS_OCTFM
"""mask - octal number format
"""
ASO_OCTF0 = _ida_idp.ASO_OCTF0
"""123o
"""
ASO_OCTF1 = _ida_idp.ASO_OCTF1
"""0123
"""
ASO_OCTF2 = _ida_idp.ASO_OCTF2
"""123
"""
ASO_OCTF3 = _ida_idp.ASO_OCTF3
"""@123
"""
ASO_OCTF4 = _ida_idp.ASO_OCTF4
"""o'123
"""
ASO_OCTF5 = _ida_idp.ASO_OCTF5
"""123q
"""
ASO_OCTF6 = _ida_idp.ASO_OCTF6
"""~123
"""
ASO_OCTF7 = _ida_idp.ASO_OCTF7
"""q'123
"""
AS_BINFM = _ida_idp.AS_BINFM
"""mask - binary number format
"""
ASB_BINF0 = _ida_idp.ASB_BINF0
"""010101b
"""
ASB_BINF1 = _ida_idp.ASB_BINF1
"""^B010101
"""
ASB_BINF2 = _ida_idp.ASB_BINF2
"""%010101
"""
ASB_BINF3 = _ida_idp.ASB_BINF3
"""0b1010101
"""
ASB_BINF4 = _ida_idp.ASB_BINF4
"""b'1010101
"""
ASB_BINF5 = _ida_idp.ASB_BINF5
"""b'1010101'
"""
AS_UNEQU = _ida_idp.AS_UNEQU
"""replace undefined data items with EQU (for ANTA's A80)
"""
AS_ONEDUP = _ida_idp.AS_ONEDUP
"""One array definition per line.
"""
AS_NOXRF = _ida_idp.AS_NOXRF
"""Disable xrefs during the output file generation.
"""
AS_XTRNTYPE = _ida_idp.AS_XTRNTYPE
"""Assembler understands type of extern symbols as ":type" suffix.
"""
AS_RELSUP = _ida_idp.AS_RELSUP
"""Checkarg: 'and','or','xor' operations with addresses are possible.
"""
AS_LALIGN = _ida_idp.AS_LALIGN
"""Labels at "align" keyword are supported.
"""
AS_NOCODECLN = _ida_idp.AS_NOCODECLN
"""don't create colons after code names
"""
AS_NOSPACE = _ida_idp.AS_NOSPACE
"""No spaces in expressions.
"""
AS_ALIGN2 = _ida_idp.AS_ALIGN2
""".align directive expects an exponent rather than a power of 2 (.align 5 means to align at 32byte boundary) 
        """
AS_ASCIIC = _ida_idp.AS_ASCIIC
"""ascii directive accepts C-like escape sequences (\\n,\\x01 and similar) 
        """
AS_ASCIIZ = _ida_idp.AS_ASCIIZ
"""ascii directive inserts implicit zero byte at the end
"""
AS2_BRACE = _ida_idp.AS2_BRACE
"""Use braces for all expressions.
"""
AS2_STRINV = _ida_idp.AS2_STRINV
"""Invert meaning of idainfo::wide_high_byte_first for text strings (for processors with bytes bigger than 8 bits) 
        """
AS2_BYTE1CHAR = _ida_idp.AS2_BYTE1CHAR
"""One symbol per processor byte. Meaningful only for wide byte processors 
        """
AS2_IDEALDSCR = _ida_idp.AS2_IDEALDSCR
"""Description of struc/union is in the 'reverse' form (keyword before name), the same as in borland tasm ideal 
        """
AS2_TERSESTR = _ida_idp.AS2_TERSESTR
"""'terse' structure initialization form; NAME<fld,fld,...> is supported 
        """
AS2_COLONSUF = _ida_idp.AS2_COLONSUF
"""addresses may have ":xx" suffix; this suffix must be ignored when extracting the address under the cursor 
        """
AS2_YWORD = _ida_idp.AS2_YWORD
"""a_yword field is present and valid
"""
AS2_ZWORD = _ida_idp.AS2_ZWORD
"""a_zword field is present and valid
"""
HKCB_GLOBAL = _ida_idp.HKCB_GLOBAL
"""is global event listener? if true, the listener will survive database closing and opening. it will stay in the memory until explicitly unhooked. otherwise the kernel will delete it as soon as the owner is unloaded. should be used only with PLUGIN_FIX plugins. 
        """
PLFM_386 = _ida_idp.PLFM_386
"""Intel 80x86.
"""
PLFM_Z80 = _ida_idp.PLFM_Z80
"""8085, Z80
"""
PLFM_I860 = _ida_idp.PLFM_I860
"""Intel 860.
"""
PLFM_8051 = _ida_idp.PLFM_8051
"""8051
"""
PLFM_TMS = _ida_idp.PLFM_TMS
"""Texas Instruments TMS320C5x.
"""
PLFM_6502 = _ida_idp.PLFM_6502
"""6502
"""
PLFM_PDP = _ida_idp.PLFM_PDP
"""PDP11.
"""
PLFM_68K = _ida_idp.PLFM_68K
"""Motorola 680x0.
"""
PLFM_JAVA = _ida_idp.PLFM_JAVA
"""Java.
"""
PLFM_6800 = _ida_idp.PLFM_6800
"""Motorola 68xx.
"""
PLFM_ST7 = _ida_idp.PLFM_ST7
"""SGS-Thomson ST7.
"""
PLFM_MC6812 = _ida_idp.PLFM_MC6812
"""Motorola 68HC12.
"""
PLFM_MIPS = _ida_idp.PLFM_MIPS
"""MIPS.
"""
PLFM_ARM = _ida_idp.PLFM_ARM
"""Advanced RISC Machines.
"""
PLFM_TMSC6 = _ida_idp.PLFM_TMSC6
"""Texas Instruments TMS320C6x.
"""
PLFM_PPC = _ida_idp.PLFM_PPC
"""PowerPC.
"""
PLFM_80196 = _ida_idp.PLFM_80196
"""Intel 80196.
"""
PLFM_Z8 = _ida_idp.PLFM_Z8
"""Z8.
"""
PLFM_SH = _ida_idp.PLFM_SH
"""Renesas (formerly Hitachi) SuperH.
"""
PLFM_NET = _ida_idp.PLFM_NET
"""Microsoft Visual Studio.Net.
"""
PLFM_AVR = _ida_idp.PLFM_AVR
"""Atmel 8-bit RISC processor(s)
"""
PLFM_H8 = _ida_idp.PLFM_H8
"""Hitachi H8/300, H8/2000.
"""
PLFM_PIC = _ida_idp.PLFM_PIC
"""Microchip's PIC.
"""
PLFM_SPARC = _ida_idp.PLFM_SPARC
"""SPARC.
"""
PLFM_ALPHA = _ida_idp.PLFM_ALPHA
"""DEC Alpha.
"""
PLFM_HPPA = _ida_idp.PLFM_HPPA
"""Hewlett-Packard PA-RISC.
"""
PLFM_H8500 = _ida_idp.PLFM_H8500
"""Hitachi H8/500.
"""
PLFM_TRICORE = _ida_idp.PLFM_TRICORE
"""Tasking Tricore.
"""
PLFM_DSP56K = _ida_idp.PLFM_DSP56K
"""Motorola DSP5600x.
"""
PLFM_C166 = _ida_idp.PLFM_C166
"""Siemens C166 family.
"""
PLFM_ST20 = _ida_idp.PLFM_ST20
"""SGS-Thomson ST20.
"""
PLFM_IA64 = _ida_idp.PLFM_IA64
"""Intel Itanium IA64.
"""
PLFM_I960 = _ida_idp.PLFM_I960
"""Intel 960.
"""
PLFM_F2MC = _ida_idp.PLFM_F2MC
"""Fujistu F2MC-16.
"""
PLFM_TMS320C54 = _ida_idp.PLFM_TMS320C54
"""Texas Instruments TMS320C54xx.
"""
PLFM_TMS320C55 = _ida_idp.PLFM_TMS320C55
"""Texas Instruments TMS320C55xx.
"""
PLFM_TRIMEDIA = _ida_idp.PLFM_TRIMEDIA
"""Trimedia.
"""
PLFM_M32R = _ida_idp.PLFM_M32R
"""Mitsubishi 32bit RISC.
"""
PLFM_NEC_78K0 = _ida_idp.PLFM_NEC_78K0
"""NEC 78K0.
"""
PLFM_NEC_78K0S = _ida_idp.PLFM_NEC_78K0S
"""NEC 78K0S.
"""
PLFM_M740 = _ida_idp.PLFM_M740
"""Mitsubishi 8bit.
"""
PLFM_M7700 = _ida_idp.PLFM_M7700
"""Mitsubishi 16bit.
"""
PLFM_ST9 = _ida_idp.PLFM_ST9
"""ST9+.
"""
PLFM_FR = _ida_idp.PLFM_FR
"""Fujitsu FR Family.
"""
PLFM_MC6816 = _ida_idp.PLFM_MC6816
"""Motorola 68HC16.
"""
PLFM_M7900 = _ida_idp.PLFM_M7900
"""Mitsubishi 7900.
"""
PLFM_TMS320C3 = _ida_idp.PLFM_TMS320C3
"""Texas Instruments TMS320C3.
"""
PLFM_KR1878 = _ida_idp.PLFM_KR1878
"""Angstrem KR1878.
"""
PLFM_AD218X = _ida_idp.PLFM_AD218X
"""Analog Devices ADSP 218X.
"""
PLFM_OAKDSP = _ida_idp.PLFM_OAKDSP
"""Atmel OAK DSP.
"""
PLFM_TLCS900 = _ida_idp.PLFM_TLCS900
"""Toshiba TLCS-900.
"""
PLFM_C39 = _ida_idp.PLFM_C39
"""Rockwell C39.
"""
PLFM_CR16 = _ida_idp.PLFM_CR16
"""NSC CR16.
"""
PLFM_MN102L00 = _ida_idp.PLFM_MN102L00
"""Panasonic MN10200.
"""
PLFM_TMS320C1X = _ida_idp.PLFM_TMS320C1X
"""Texas Instruments TMS320C1x.
"""
PLFM_NEC_V850X = _ida_idp.PLFM_NEC_V850X
"""NEC V850 and V850ES/E1/E2.
"""
PLFM_SCR_ADPT = _ida_idp.PLFM_SCR_ADPT
"""Processor module adapter for processor modules written in scripting languages.
"""
PLFM_EBC = _ida_idp.PLFM_EBC
"""EFI Bytecode.
"""
PLFM_MSP430 = _ida_idp.PLFM_MSP430
"""Texas Instruments MSP430.
"""
PLFM_SPU = _ida_idp.PLFM_SPU
"""Cell Broadband Engine Synergistic Processor Unit.
"""
PLFM_DALVIK = _ida_idp.PLFM_DALVIK
"""Android Dalvik Virtual Machine.
"""
PLFM_65C816 = _ida_idp.PLFM_65C816
"""65802/65816
"""
PLFM_M16C = _ida_idp.PLFM_M16C
"""Renesas M16C.
"""
PLFM_ARC = _ida_idp.PLFM_ARC
"""Argonaut RISC Core.
"""
PLFM_UNSP = _ida_idp.PLFM_UNSP
"""SunPlus unSP.
"""
PLFM_TMS320C28 = _ida_idp.PLFM_TMS320C28
"""Texas Instruments TMS320C28x.
"""
PLFM_DSP96K = _ida_idp.PLFM_DSP96K
"""Motorola DSP96000.
"""
PLFM_SPC700 = _ida_idp.PLFM_SPC700
"""Sony SPC700.
"""
PLFM_AD2106X = _ida_idp.PLFM_AD2106X
"""Analog Devices ADSP 2106X.
"""
PLFM_PIC16 = _ida_idp.PLFM_PIC16
"""Microchip's 16-bit PIC.
"""
PLFM_S390 = _ida_idp.PLFM_S390
"""IBM's S390.
"""
PLFM_XTENSA = _ida_idp.PLFM_XTENSA
"""Tensilica Xtensa.
"""
PLFM_RISCV = _ida_idp.PLFM_RISCV
"""RISC-V.
"""
PLFM_RL78 = _ida_idp.PLFM_RL78
"""Renesas RL78.
"""
PLFM_RX = _ida_idp.PLFM_RX
"""Renesas RX.
"""
PLFM_WASM = _ida_idp.PLFM_WASM
"""WASM.
"""
PR_SEGS = _ida_idp.PR_SEGS
"""has segment registers?
"""
PR_USE32 = _ida_idp.PR_USE32
"""supports 32-bit addressing?
"""
PR_DEFSEG32 = _ida_idp.PR_DEFSEG32
"""segments are 32-bit by default
"""
PR_RNAMESOK = _ida_idp.PR_RNAMESOK
"""allow user register names for location names
"""
PR_ADJSEGS = _ida_idp.PR_ADJSEGS
"""IDA may adjust segments' starting/ending addresses.
"""
PR_DEFNUM = _ida_idp.PR_DEFNUM
"""mask - default number representation
"""
PRN_HEX = _ida_idp.PRN_HEX
"""hex
"""
PRN_OCT = _ida_idp.PRN_OCT
"""octal
"""
PRN_DEC = _ida_idp.PRN_DEC
"""decimal
"""
PRN_BIN = _ida_idp.PRN_BIN
"""binary
"""
PR_WORD_INS = _ida_idp.PR_WORD_INS
"""instruction codes are grouped 2bytes in binary line prefix
"""
PR_NOCHANGE = _ida_idp.PR_NOCHANGE
"""The user can't change segments and code/data attributes (display only) 
        """
PR_ASSEMBLE = _ida_idp.PR_ASSEMBLE
"""Module has a built-in assembler and will react to ev_assemble.
"""
PR_ALIGN = _ida_idp.PR_ALIGN
"""All data items should be aligned properly.
"""
PR_TYPEINFO = _ida_idp.PR_TYPEINFO
"""the processor module fully supports type information callbacks; without full support, function argument locations and other things will probably be wrong. 
        """
PR_USE64 = _ida_idp.PR_USE64
"""supports 64-bit addressing?
"""
PR_SGROTHER = _ida_idp.PR_SGROTHER
"""the segment registers don't contain the segment selectors.
"""
PR_STACK_UP = _ida_idp.PR_STACK_UP
"""the stack grows up
"""
PR_BINMEM = _ida_idp.PR_BINMEM
"""the processor module provides correct segmentation for binary files (i.e. it creates additional segments). The kernel will not ask the user to specify the RAM/ROM sizes 
        """
PR_SEGTRANS = _ida_idp.PR_SEGTRANS
"""the processor module supports the segment translation feature (meaning it calculates the code addresses using the map_code_ea() function) 
        """
PR_CHK_XREF = _ida_idp.PR_CHK_XREF
"""don't allow near xrefs between segments with different bases
"""
PR_NO_SEGMOVE = _ida_idp.PR_NO_SEGMOVE
"""the processor module doesn't support move_segm() (i.e. the user can't move segments) 
        """
PR_USE_ARG_TYPES = _ida_idp.PR_USE_ARG_TYPES
"""use processor_t::use_arg_types callback
"""
PR_SCALE_STKVARS = _ida_idp.PR_SCALE_STKVARS
"""use processor_t::get_stkvar_scale callback
"""
PR_DELAYED = _ida_idp.PR_DELAYED
"""has delayed jumps and calls. If this flag is set, processor_t::is_basic_block_end, processor_t::delay_slot_insn should be implemented 
        """
PR_ALIGN_INSN = _ida_idp.PR_ALIGN_INSN
"""allow ida to create alignment instructions arbitrarily. Since these instructions might lead to other wrong instructions and spoil the listing, IDA does not create them by default anymore 
        """
PR_PURGING = _ida_idp.PR_PURGING
"""there are calling conventions which may purge bytes from the stack
"""
PR_CNDINSNS = _ida_idp.PR_CNDINSNS
"""has conditional instructions
"""
PR_USE_TBYTE = _ida_idp.PR_USE_TBYTE
"""BTMT_SPECFLT means _TBYTE type
"""
PR_DEFSEG64 = _ida_idp.PR_DEFSEG64
"""segments are 64-bit by default
"""
PR_OUTER = _ida_idp.PR_OUTER
"""has outer operands (currently only mc68k)
"""
PR2_MAPPINGS = _ida_idp.PR2_MAPPINGS
"""the processor module uses memory mapping
"""
PR2_IDP_OPTS = _ida_idp.PR2_IDP_OPTS
"""the module has processor-specific configuration options
"""
PR2_CODE16_BIT = _ida_idp.PR2_CODE16_BIT
"""low bit of code addresses has special meaning e.g. ARM Thumb, MIPS16 
        """
PR2_MACRO = _ida_idp.PR2_MACRO
"""processor supports macro instructions
"""
PR2_USE_CALCREL = _ida_idp.PR2_USE_CALCREL
"""(Lumina) the module supports calcrel info
"""
PR2_REL_BITS = _ida_idp.PR2_REL_BITS
"""(Lumina) calcrel info has bits granularity, not bytes - construction flag only
"""
PR2_FORCE_16BIT = _ida_idp.PR2_FORCE_16BIT
"""use 16-bit basic types despite of 32-bit segments (used by c166)
"""
OP_FP_BASED = _ida_idp.OP_FP_BASED
"""operand is FP based
"""
OP_SP_BASED = _ida_idp.OP_SP_BASED
"""operand is SP based
"""
OP_SP_ADD = _ida_idp.OP_SP_ADD
"""operand value is added to the pointer
"""
OP_SP_SUB = _ida_idp.OP_SP_SUB
"""operand value is subtracted from the pointer
"""
CUSTOM_INSN_ITYPE = _ida_idp.CUSTOM_INSN_ITYPE
"""Custom instruction codes defined by processor extension plugins must be greater than or equal to this 
        """
REG_SPOIL = _ida_idp.REG_SPOIL
"""processor_t::use_regarg_type uses this bit in the return value to indicate that the register value has been spoiled 
        """


class _processor_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    version: 'int32' = property(_ida_idp._processor_t_version_get, _ida_idp
        ._processor_t_version_set)

    def has_idp_opts(self) ->bool:
        return _ida_idp._processor_t_has_idp_opts(self)

    def has_segregs(self) ->bool:
        return _ida_idp._processor_t_has_segregs(self)

    def use32(self) ->bool:
        return _ida_idp._processor_t_use32(self)

    def use64(self) ->bool:
        return _ida_idp._processor_t_use64(self)

    def ti(self) ->bool:
        return _ida_idp._processor_t_ti(self)

    def stkup(self) ->bool:
        return _ida_idp._processor_t_stkup(self)

    def use_tbyte(self) ->bool:
        return _ida_idp._processor_t_use_tbyte(self)

    def use_mappings(self) ->bool:
        return _ida_idp._processor_t_use_mappings(self)

    def has_code16_bit(self) ->bool:
        return _ida_idp._processor_t_has_code16_bit(self)

    def supports_macros(self) ->bool:
        return _ida_idp._processor_t_supports_macros(self)

    def supports_calcrel(self) ->bool:
        return _ida_idp._processor_t_supports_calcrel(self)

    def calcrel_in_bits(self) ->bool:
        return _ida_idp._processor_t_calcrel_in_bits(self)

    def get_default_segm_bitness(self, is_64bit_app: bool) ->int:
        return _ida_idp._processor_t_get_default_segm_bitness(self,
            is_64bit_app)

    def cbsize(self) ->int:
        return _ida_idp._processor_t_cbsize(self)

    def dbsize(self) ->int:
        return _ida_idp._processor_t_dbsize(self)

    def get_proc_index(self) ->int:
        return _ida_idp._processor_t_get_proc_index(self)
    ev_init = _ida_idp._processor_t_ev_init
    ev_term = _ida_idp._processor_t_ev_term
    ev_newprc = _ida_idp._processor_t_ev_newprc
    ev_newasm = _ida_idp._processor_t_ev_newasm
    ev_newfile = _ida_idp._processor_t_ev_newfile
    ev_oldfile = _ida_idp._processor_t_ev_oldfile
    ev_newbinary = _ida_idp._processor_t_ev_newbinary
    ev_endbinary = _ida_idp._processor_t_ev_endbinary
    ev_set_idp_options = _ida_idp._processor_t_ev_set_idp_options
    ev_set_proc_options = _ida_idp._processor_t_ev_set_proc_options
    ev_ana_insn = _ida_idp._processor_t_ev_ana_insn
    ev_emu_insn = _ida_idp._processor_t_ev_emu_insn
    ev_out_header = _ida_idp._processor_t_ev_out_header
    ev_out_footer = _ida_idp._processor_t_ev_out_footer
    ev_out_segstart = _ida_idp._processor_t_ev_out_segstart
    ev_out_segend = _ida_idp._processor_t_ev_out_segend
    ev_out_assumes = _ida_idp._processor_t_ev_out_assumes
    ev_out_insn = _ida_idp._processor_t_ev_out_insn
    ev_out_mnem = _ida_idp._processor_t_ev_out_mnem
    ev_out_operand = _ida_idp._processor_t_ev_out_operand
    ev_out_data = _ida_idp._processor_t_ev_out_data
    ev_out_label = _ida_idp._processor_t_ev_out_label
    ev_out_special_item = _ida_idp._processor_t_ev_out_special_item
    ev_gen_regvar_def = _ida_idp._processor_t_ev_gen_regvar_def
    ev_gen_src_file_lnnum = _ida_idp._processor_t_ev_gen_src_file_lnnum
    ev_creating_segm = _ida_idp._processor_t_ev_creating_segm
    ev_moving_segm = _ida_idp._processor_t_ev_moving_segm
    ev_coagulate = _ida_idp._processor_t_ev_coagulate
    ev_undefine = _ida_idp._processor_t_ev_undefine
    ev_treat_hindering_item = _ida_idp._processor_t_ev_treat_hindering_item
    ev_rename = _ida_idp._processor_t_ev_rename
    ev_is_far_jump = _ida_idp._processor_t_ev_is_far_jump
    ev_is_sane_insn = _ida_idp._processor_t_ev_is_sane_insn
    ev_is_cond_insn = _ida_idp._processor_t_ev_is_cond_insn
    ev_is_call_insn = _ida_idp._processor_t_ev_is_call_insn
    ev_is_ret_insn = _ida_idp._processor_t_ev_is_ret_insn
    ev_may_be_func = _ida_idp._processor_t_ev_may_be_func
    ev_is_basic_block_end = _ida_idp._processor_t_ev_is_basic_block_end
    ev_is_indirect_jump = _ida_idp._processor_t_ev_is_indirect_jump
    ev_is_insn_table_jump = _ida_idp._processor_t_ev_is_insn_table_jump
    ev_is_switch = _ida_idp._processor_t_ev_is_switch
    ev_calc_switch_cases = _ida_idp._processor_t_ev_calc_switch_cases
    ev_create_switch_xrefs = _ida_idp._processor_t_ev_create_switch_xrefs
    ev_is_align_insn = _ida_idp._processor_t_ev_is_align_insn
    ev_is_alloca_probe = _ida_idp._processor_t_ev_is_alloca_probe
    ev_delay_slot_insn = _ida_idp._processor_t_ev_delay_slot_insn
    ev_is_sp_based = _ida_idp._processor_t_ev_is_sp_based
    ev_can_have_type = _ida_idp._processor_t_ev_can_have_type
    ev_cmp_operands = _ida_idp._processor_t_ev_cmp_operands
    ev_adjust_refinfo = _ida_idp._processor_t_ev_adjust_refinfo
    ev_get_operand_string = _ida_idp._processor_t_ev_get_operand_string
    ev_get_reg_name = _ida_idp._processor_t_ev_get_reg_name
    ev_str2reg = _ida_idp._processor_t_ev_str2reg
    ev_get_autocmt = _ida_idp._processor_t_ev_get_autocmt
    ev_get_bg_color = _ida_idp._processor_t_ev_get_bg_color
    ev_is_jump_func = _ida_idp._processor_t_ev_is_jump_func
    ev_func_bounds = _ida_idp._processor_t_ev_func_bounds
    ev_verify_sp = _ida_idp._processor_t_ev_verify_sp
    ev_verify_noreturn = _ida_idp._processor_t_ev_verify_noreturn
    ev_create_func_frame = _ida_idp._processor_t_ev_create_func_frame
    ev_get_frame_retsize = _ida_idp._processor_t_ev_get_frame_retsize
    ev_get_stkvar_scale_factor = (_ida_idp.
        _processor_t_ev_get_stkvar_scale_factor)
    ev_demangle_name = _ida_idp._processor_t_ev_demangle_name
    ev_add_cref = _ida_idp._processor_t_ev_add_cref
    ev_add_dref = _ida_idp._processor_t_ev_add_dref
    ev_del_cref = _ida_idp._processor_t_ev_del_cref
    ev_del_dref = _ida_idp._processor_t_ev_del_dref
    ev_coagulate_dref = _ida_idp._processor_t_ev_coagulate_dref
    ev_may_show_sreg = _ida_idp._processor_t_ev_may_show_sreg
    ev_loader_elf_machine = _ida_idp._processor_t_ev_loader_elf_machine
    ev_auto_queue_empty = _ida_idp._processor_t_ev_auto_queue_empty
    ev_validate_flirt_func = _ida_idp._processor_t_ev_validate_flirt_func
    ev_adjust_libfunc_ea = _ida_idp._processor_t_ev_adjust_libfunc_ea
    ev_assemble = _ida_idp._processor_t_ev_assemble
    ev_extract_address = _ida_idp._processor_t_ev_extract_address
    ev_realcvt = _ida_idp._processor_t_ev_realcvt
    ev_gen_asm_or_lst = _ida_idp._processor_t_ev_gen_asm_or_lst
    ev_gen_map_file = _ida_idp._processor_t_ev_gen_map_file
    ev_create_flat_group = _ida_idp._processor_t_ev_create_flat_group
    ev_getreg = _ida_idp._processor_t_ev_getreg
    ev_analyze_prolog = _ida_idp._processor_t_ev_analyze_prolog
    ev_calc_spdelta = _ida_idp._processor_t_ev_calc_spdelta
    ev_calcrel = _ida_idp._processor_t_ev_calcrel
    ev_find_reg_value = _ida_idp._processor_t_ev_find_reg_value
    ev_find_op_value = _ida_idp._processor_t_ev_find_op_value
    ev_replaying_undo = _ida_idp._processor_t_ev_replaying_undo
    ev_ending_undo = _ida_idp._processor_t_ev_ending_undo
    ev_set_code16_mode = _ida_idp._processor_t_ev_set_code16_mode
    ev_get_code16_mode = _ida_idp._processor_t_ev_get_code16_mode
    ev_get_procmod = _ida_idp._processor_t_ev_get_procmod
    ev_asm_installed = _ida_idp._processor_t_ev_asm_installed
    ev_get_reg_accesses = _ida_idp._processor_t_ev_get_reg_accesses
    ev_is_control_flow_guard = _ida_idp._processor_t_ev_is_control_flow_guard
    ev_broadcast = _ida_idp._processor_t_ev_broadcast
    ev_create_merge_handlers = _ida_idp._processor_t_ev_create_merge_handlers
    ev_privrange_changed = _ida_idp._processor_t_ev_privrange_changed
    ev_cvt64_supval = _ida_idp._processor_t_ev_cvt64_supval
    ev_cvt64_hashval = _ida_idp._processor_t_ev_cvt64_hashval
    ev_get_regfinder = _ida_idp._processor_t_ev_get_regfinder
    ev_gen_stkvar_def = _ida_idp._processor_t_ev_gen_stkvar_def
    ev_last_cb_before_debugger = (_ida_idp.
        _processor_t_ev_last_cb_before_debugger)
    ev_next_exec_insn = _ida_idp._processor_t_ev_next_exec_insn
    ev_calc_step_over = _ida_idp._processor_t_ev_calc_step_over
    ev_calc_next_eas = _ida_idp._processor_t_ev_calc_next_eas
    ev_get_macro_insn_head = _ida_idp._processor_t_ev_get_macro_insn_head
    ev_get_dbr_opnum = _ida_idp._processor_t_ev_get_dbr_opnum
    ev_insn_reads_tbit = _ida_idp._processor_t_ev_insn_reads_tbit
    ev_clean_tbit = _ida_idp._processor_t_ev_clean_tbit
    ev_get_idd_opinfo = _ida_idp._processor_t_ev_get_idd_opinfo
    ev_get_reg_info = _ida_idp._processor_t_ev_get_reg_info
    ev_update_call_stack = _ida_idp._processor_t_ev_update_call_stack
    ev_last_cb_before_type_callbacks = (_ida_idp.
        _processor_t_ev_last_cb_before_type_callbacks)
    ev_setup_til = _ida_idp._processor_t_ev_setup_til
    ev_get_abi_info = _ida_idp._processor_t_ev_get_abi_info
    ev_max_ptr_size = _ida_idp._processor_t_ev_max_ptr_size
    ev_get_default_enum_size = _ida_idp._processor_t_ev_get_default_enum_size
    ev_get_cc_regs = _ida_idp._processor_t_ev_get_cc_regs
    ev_get_simd_types = _ida_idp._processor_t_ev_get_simd_types
    ev_calc_cdecl_purged_bytes = (_ida_idp.
        _processor_t_ev_calc_cdecl_purged_bytes)
    ev_calc_purged_bytes = _ida_idp._processor_t_ev_calc_purged_bytes
    ev_calc_retloc = _ida_idp._processor_t_ev_calc_retloc
    ev_calc_arglocs = _ida_idp._processor_t_ev_calc_arglocs
    ev_calc_varglocs = _ida_idp._processor_t_ev_calc_varglocs
    ev_adjust_argloc = _ida_idp._processor_t_ev_adjust_argloc
    ev_lower_func_type = _ida_idp._processor_t_ev_lower_func_type
    ev_equal_reglocs = _ida_idp._processor_t_ev_equal_reglocs
    ev_use_stkarg_type = _ida_idp._processor_t_ev_use_stkarg_type
    ev_use_regarg_type = _ida_idp._processor_t_ev_use_regarg_type
    ev_use_arg_types = _ida_idp._processor_t_ev_use_arg_types
    ev_arg_addrs_ready = _ida_idp._processor_t_ev_arg_addrs_ready
    ev_decorate_name = _ida_idp._processor_t_ev_decorate_name
    ev_arch_changed = _ida_idp._processor_t_ev_arch_changed
    ev_get_stkarg_area_info = _ida_idp._processor_t_ev_get_stkarg_area_info
    ev_last_cb_before_loader = _ida_idp._processor_t_ev_last_cb_before_loader
    ev_loader = _ida_idp._processor_t_ev_loader

    @staticmethod
    def notify(*args) ->'ssize_t':
        return _ida_idp._processor_t_notify(*args)

    @staticmethod
    def init(idp_modname: str) ->'ssize_t':
        return _ida_idp._processor_t_init(idp_modname)

    @staticmethod
    def term() ->'ssize_t':
        return _ida_idp._processor_t_term()

    @staticmethod
    def newprc(pnum: int, keep_cfg: bool) ->'ssize_t':
        return _ida_idp._processor_t_newprc(pnum, keep_cfg)

    @staticmethod
    def newasm(asmnum: int) ->'ssize_t':
        return _ida_idp._processor_t_newasm(asmnum)

    @staticmethod
    def asm_installed(asmnum: int) ->'ssize_t':
        return _ida_idp._processor_t_asm_installed(asmnum)

    @staticmethod
    def newfile(fname: str) ->'ssize_t':
        return _ida_idp._processor_t_newfile(fname)

    @staticmethod
    def oldfile(fname: str) ->'ssize_t':
        return _ida_idp._processor_t_oldfile(fname)

    @staticmethod
    def newbinary(filename: str, fileoff: 'qoff64_t', basepara:
        ida_idaapi.ea_t, binoff: ida_idaapi.ea_t, nbytes: 'uint64'
        ) ->'ssize_t':
        return _ida_idp._processor_t_newbinary(filename, fileoff, basepara,
            binoff, nbytes)

    @staticmethod
    def endbinary(ok: bool) ->'ssize_t':
        return _ida_idp._processor_t_endbinary(ok)

    @staticmethod
    def creating_segm(seg: 'segment_t *') ->'ssize_t':
        return _ida_idp._processor_t_creating_segm(seg)

    @staticmethod
    def assemble(_bin: 'uchar *', ea: ida_idaapi.ea_t, cs: ida_idaapi.ea_t,
        ip: ida_idaapi.ea_t, _use32: bool, line: str) ->'ssize_t':
        return _ida_idp._processor_t_assemble(_bin, ea, cs, ip, _use32, line)

    @staticmethod
    def ana_insn(out: 'insn_t *') ->'ssize_t':
        return _ida_idp._processor_t_ana_insn(out)

    @staticmethod
    def emu_insn(insn: 'insn_t const &') ->'ssize_t':
        return _ida_idp._processor_t_emu_insn(insn)

    @staticmethod
    def out_header(ctx: 'outctx_t &') ->'ssize_t':
        return _ida_idp._processor_t_out_header(ctx)

    @staticmethod
    def out_footer(ctx: 'outctx_t &') ->'ssize_t':
        return _ida_idp._processor_t_out_footer(ctx)

    @staticmethod
    def out_segstart(ctx: 'outctx_t &', seg: 'segment_t *') ->'ssize_t':
        return _ida_idp._processor_t_out_segstart(ctx, seg)

    @staticmethod
    def out_segend(ctx: 'outctx_t &', seg: 'segment_t *') ->'ssize_t':
        return _ida_idp._processor_t_out_segend(ctx, seg)

    @staticmethod
    def out_assumes(ctx: 'outctx_t &') ->'ssize_t':
        return _ida_idp._processor_t_out_assumes(ctx)

    @staticmethod
    def out_insn(ctx: 'outctx_t &') ->'ssize_t':
        return _ida_idp._processor_t_out_insn(ctx)

    @staticmethod
    def out_mnem(ctx: 'outctx_t &') ->'ssize_t':
        return _ida_idp._processor_t_out_mnem(ctx)

    @staticmethod
    def out_operand(ctx: 'outctx_t &', op: 'op_t const &') ->'ssize_t':
        return _ida_idp._processor_t_out_operand(ctx, op)

    @staticmethod
    def out_data(ctx: 'outctx_t &', analyze_only: bool) ->'ssize_t':
        return _ida_idp._processor_t_out_data(ctx, analyze_only)

    @staticmethod
    def out_label(ctx: 'outctx_t &', colored_name: str) ->'ssize_t':
        return _ida_idp._processor_t_out_label(ctx, colored_name)

    @staticmethod
    def out_special_item(ctx: 'outctx_t &', segtype: 'uchar') ->'ssize_t':
        return _ida_idp._processor_t_out_special_item(ctx, segtype)

    @staticmethod
    def gen_stkvar_def(ctx: 'outctx_t &', mptr: 'udm_t', v: int, tid: 'tid_t'
        ) ->'ssize_t':
        return _ida_idp._processor_t_gen_stkvar_def(ctx, mptr, v, tid)

    @staticmethod
    def gen_regvar_def(ctx: 'outctx_t &', v: 'regvar_t *') ->'ssize_t':
        return _ida_idp._processor_t_gen_regvar_def(ctx, v)

    @staticmethod
    def gen_src_file_lnnum(ctx: 'outctx_t &', file: str, lnnum: 'size_t'
        ) ->'ssize_t':
        return _ida_idp._processor_t_gen_src_file_lnnum(ctx, file, lnnum)

    @staticmethod
    def rename(ea: ida_idaapi.ea_t, new_name: str, flags: int) ->'ssize_t':
        return _ida_idp._processor_t_rename(ea, new_name, flags)

    @staticmethod
    def may_show_sreg(current_ea: ida_idaapi.ea_t) ->'ssize_t':
        return _ida_idp._processor_t_may_show_sreg(current_ea)

    @staticmethod
    def coagulate(start_ea: ida_idaapi.ea_t) ->'ssize_t':
        return _ida_idp._processor_t_coagulate(start_ea)

    @staticmethod
    def auto_queue_empty(type: int) ->None:
        return _ida_idp._processor_t_auto_queue_empty(type)

    @staticmethod
    def func_bounds(possible_return_code: 'int *', pfn: 'func_t *',
        max_func_end_ea: ida_idaapi.ea_t) ->'ssize_t':
        return _ida_idp._processor_t_func_bounds(possible_return_code, pfn,
            max_func_end_ea)

    @staticmethod
    def may_be_func(insn: 'insn_t const &', state: int) ->'ssize_t':
        return _ida_idp._processor_t_may_be_func(insn, state)

    @staticmethod
    def is_sane_insn(insn: 'insn_t const &', no_crefs: int) ->'ssize_t':
        return _ida_idp._processor_t_is_sane_insn(insn, no_crefs)

    @staticmethod
    def cmp_operands(op1: 'op_t const &', op2: 'op_t const &') ->'ssize_t':
        return _ida_idp._processor_t_cmp_operands(op1, op2)

    @staticmethod
    def is_jump_func(pfn: 'func_t *', jump_target: 'ea_t *', func_pointer:
        'ea_t *') ->'ssize_t':
        return _ida_idp._processor_t_is_jump_func(pfn, jump_target,
            func_pointer)

    @staticmethod
    def is_basic_block_end(insn: 'insn_t const &', call_insn_stops_block: bool
        ) ->'ssize_t':
        """Is the instruction the end of a basic block?
"""
        return _ida_idp._processor_t_is_basic_block_end(insn,
            call_insn_stops_block)

    @staticmethod
    def getreg(rv: 'uval_t *', regnum: int) ->'ssize_t':
        return _ida_idp._processor_t_getreg(rv, regnum)

    @staticmethod
    def undefine(ea: ida_idaapi.ea_t) ->'ssize_t':
        return _ida_idp._processor_t_undefine(ea)

    @staticmethod
    def moving_segm(seg: 'segment_t *', to: ida_idaapi.ea_t, flags: int
        ) ->'ssize_t':
        return _ida_idp._processor_t_moving_segm(seg, to, flags)

    @staticmethod
    def is_sp_based(insn: 'insn_t const &', x: 'op_t const &') ->'ssize_t':
        return _ida_idp._processor_t_is_sp_based(insn, x)

    @staticmethod
    def is_far_jump(icode: int) ->'ssize_t':
        return _ida_idp._processor_t_is_far_jump(icode)

    @staticmethod
    def is_call_insn(insn: 'insn_t const &') ->'ssize_t':
        """Is the instruction a "call"?
"""
        return _ida_idp._processor_t_is_call_insn(insn)

    @staticmethod
    def is_ret_insn(insn: 'insn_t const &', iri_flags: 'uchar') ->'ssize_t':
        return _ida_idp._processor_t_is_ret_insn(insn, iri_flags)

    @staticmethod
    def is_align_insn(ea: ida_idaapi.ea_t) ->'ssize_t':
        """If the instruction at 'ea' looks like an alignment instruction, return its length in bytes. Otherwise return 0. 
        """
        return _ida_idp._processor_t_is_align_insn(ea)

    @staticmethod
    def can_have_type(op: 'op_t const &') ->'ssize_t':
        return _ida_idp._processor_t_can_have_type(op)

    @staticmethod
    def get_stkvar_scale_factor() ->'ssize_t':
        return _ida_idp._processor_t_get_stkvar_scale_factor()

    @staticmethod
    def demangle_name(res: 'int32 *', name: str, disable_mask: int, demreq: int
        ) ->int:
        return _ida_idp._processor_t_demangle_name(res, name, disable_mask,
            demreq)

    @staticmethod
    def create_flat_group(image_base: ida_idaapi.ea_t, bitness: int,
        dataseg_sel: 'sel_t') ->'ssize_t':
        return _ida_idp._processor_t_create_flat_group(image_base, bitness,
            dataseg_sel)

    @staticmethod
    def is_alloca_probe(ea: ida_idaapi.ea_t) ->'ssize_t':
        return _ida_idp._processor_t_is_alloca_probe(ea)

    @staticmethod
    def get_reg_name(reg: int, width: 'size_t', reghi: int) ->str:
        """Get text representation of a register. For most processors this function will just return processor_t::reg_names[reg]. If the processor module has implemented processor_t::get_reg_name, it will be used instead 
        
@param reg: internal register number as defined in the processor module
@param width: register width in bytes
@param reghi: if specified, then this function will return the register pair
@returns length of register name in bytes or -1 if failure"""
        return _ida_idp._processor_t_get_reg_name(reg, width, reghi)

    @staticmethod
    def gen_asm_or_lst(starting: bool, fp: 'FILE *', is_asm: bool, flags:
        int, outline: 'void *') ->'ssize_t':
        return _ida_idp._processor_t_gen_asm_or_lst(starting, fp, is_asm,
            flags, outline)

    @staticmethod
    def gen_map_file(nlines: 'int *', fp: 'FILE *') ->'ssize_t':
        return _ida_idp._processor_t_gen_map_file(nlines, fp)

    @staticmethod
    def get_autocmt(insn: 'insn_t const &') ->str:
        return _ida_idp._processor_t_get_autocmt(insn)

    @staticmethod
    def loader_elf_machine(li: 'linput_t *', machine_type: int, p_procname:
        'char const **', p_pd: 'proc_def_t **', ldr: 'elf_loader_t *',
        reader: 'reader_t *') ->'ssize_t':
        return _ida_idp._processor_t_loader_elf_machine(li, machine_type,
            p_procname, p_pd, ldr, reader)

    @staticmethod
    def is_indirect_jump(insn: 'insn_t const &') ->'ssize_t':
        return _ida_idp._processor_t_is_indirect_jump(insn)

    @staticmethod
    def verify_noreturn(pfn: 'func_t *') ->'ssize_t':
        return _ida_idp._processor_t_verify_noreturn(pfn)

    @staticmethod
    def verify_sp(pfn: 'func_t *') ->'ssize_t':
        return _ida_idp._processor_t_verify_sp(pfn)

    @staticmethod
    def create_func_frame(pfn: 'func_t *') ->'ssize_t':
        return _ida_idp._processor_t_create_func_frame(pfn)

    @staticmethod
    def get_frame_retsize(retsize: 'int *', pfn: 'func_t const *') ->'ssize_t':
        return _ida_idp._processor_t_get_frame_retsize(retsize, pfn)

    @staticmethod
    def analyze_prolog(fct_ea: ida_idaapi.ea_t) ->'ssize_t':
        return _ida_idp._processor_t_analyze_prolog(fct_ea)

    @staticmethod
    def calc_spdelta(spdelta: 'sval_t *', ins: 'insn_t const &') ->'ssize_t':
        return _ida_idp._processor_t_calc_spdelta(spdelta, ins)

    @staticmethod
    def calcrel(ea: ida_idaapi.ea_t) ->'bytevec_t *, size_t *':
        return _ida_idp._processor_t_calcrel(ea)

    @staticmethod
    def get_reg_accesses(accvec: 'reg_accesses_t', insn: 'insn_t const &',
        flags: int) ->'ssize_t':
        return _ida_idp._processor_t_get_reg_accesses(accvec, insn, flags)

    @staticmethod
    def is_control_flow_guard(p_reg: 'int *', insn: 'insn_t const *'
        ) ->'ssize_t':
        return _ida_idp._processor_t_is_control_flow_guard(p_reg, insn)

    @staticmethod
    def find_reg_value(insn: 'insn_t const &', reg: int) ->'uint64 *':
        return _ida_idp._processor_t_find_reg_value(insn, reg)

    @staticmethod
    def find_op_value(insn: 'insn_t const &', op: int) ->'uint64 *':
        return _ida_idp._processor_t_find_op_value(insn, op)

    @staticmethod
    def treat_hindering_item(hindering_item_ea: ida_idaapi.ea_t,
        new_item_flags: 'flags64_t', new_item_ea: ida_idaapi.ea_t,
        new_item_length: 'asize_t') ->'ssize_t':
        return _ida_idp._processor_t_treat_hindering_item(hindering_item_ea,
            new_item_flags, new_item_ea, new_item_length)

    @staticmethod
    def extract_address(out_ea: 'ea_t *', screen_ea: ida_idaapi.ea_t,
        string: str, x: 'size_t') ->'ssize_t':
        return _ida_idp._processor_t_extract_address(out_ea, screen_ea,
            string, x)

    @staticmethod
    def str2reg(regname: str) ->'ssize_t':
        """Get any register number (-1 on error)
"""
        return _ida_idp._processor_t_str2reg(regname)

    @staticmethod
    def is_switch(si: 'switch_info_t', insn: 'insn_t const &') ->'ssize_t':
        return _ida_idp._processor_t_is_switch(si, insn)

    @staticmethod
    def create_switch_xrefs(jumpea: ida_idaapi.ea_t, si: 'switch_info_t'
        ) ->'ssize_t':
        return _ida_idp._processor_t_create_switch_xrefs(jumpea, si)

    @staticmethod
    def calc_switch_cases(casevec: 'void *', targets: 'eavec_t *', insn_ea:
        ida_idaapi.ea_t, si: 'switch_info_t') ->'ssize_t':
        return _ida_idp._processor_t_calc_switch_cases(casevec, targets,
            insn_ea, si)

    @staticmethod
    def get_bg_color(color: 'bgcolor_t *', ea: ida_idaapi.ea_t) ->'ssize_t':
        return _ida_idp._processor_t_get_bg_color(color, ea)

    @staticmethod
    def validate_flirt_func(start_ea: ida_idaapi.ea_t, funcname: str
        ) ->'ssize_t':
        return _ida_idp._processor_t_validate_flirt_func(start_ea, funcname)

    @staticmethod
    def get_operand_string(insn: 'insn_t const &', opnum: int) ->str:
        return _ida_idp._processor_t_get_operand_string(insn, opnum)

    @staticmethod
    def add_cref(_from: ida_idaapi.ea_t, to: ida_idaapi.ea_t, type: 'cref_t'
        ) ->'ssize_t':
        return _ida_idp._processor_t_add_cref(_from, to, type)

    @staticmethod
    def add_dref(_from: ida_idaapi.ea_t, to: ida_idaapi.ea_t, type: 'dref_t'
        ) ->'ssize_t':
        return _ida_idp._processor_t_add_dref(_from, to, type)

    @staticmethod
    def del_cref(_from: ida_idaapi.ea_t, to: ida_idaapi.ea_t, expand: bool
        ) ->'ssize_t':
        return _ida_idp._processor_t_del_cref(_from, to, expand)

    @staticmethod
    def del_dref(_from: ida_idaapi.ea_t, to: ida_idaapi.ea_t) ->'ssize_t':
        return _ida_idp._processor_t_del_dref(_from, to)

    @staticmethod
    def coagulate_dref(_from: ida_idaapi.ea_t, to: ida_idaapi.ea_t,
        may_define: bool, code_ea: 'ea_t *') ->'ssize_t':
        return _ida_idp._processor_t_coagulate_dref(_from, to, may_define,
            code_ea)

    @staticmethod
    def set_idp_options(keyword: str, vtype: int, value: 'void const *',
        idb_loaded: bool=True) ->str:
        return _ida_idp._processor_t_set_idp_options(keyword, vtype, value,
            idb_loaded)

    @staticmethod
    def set_proc_options(options: str, confidence: int) ->'ssize_t':
        return _ida_idp._processor_t_set_proc_options(options, confidence)

    @staticmethod
    def adjust_libfunc_ea(sig: 'idasgn_t const &', libfun:
        'libfunc_t const &', ea: 'ea_t *') ->'ssize_t':
        return _ida_idp._processor_t_adjust_libfunc_ea(sig, libfun, ea)

    @staticmethod
    def realcvt(m: 'void *', e: 'fpvalue_t *', swt: 'uint16'
        ) ->'fpvalue_error_t':
        return _ida_idp._processor_t_realcvt(m, e, swt)

    def delay_slot_insn(self, ea: 'ea_t *', bexec: 'bool *', fexec: 'bool *'
        ) ->bool:
        return _ida_idp._processor_t_delay_slot_insn(self, ea, bexec, fexec)

    @staticmethod
    def adjust_refinfo(ri: 'refinfo_t', ea: ida_idaapi.ea_t, n: int, fd:
        'fixup_data_t const &') ->'ssize_t':
        return _ida_idp._processor_t_adjust_refinfo(ri, ea, n, fd)

    @staticmethod
    def is_cond_insn(insn: 'insn_t const &') ->'ssize_t':
        return _ida_idp._processor_t_is_cond_insn(insn)

    @staticmethod
    def set_code16_mode(ea: ida_idaapi.ea_t, code16: bool=True) ->'ssize_t':
        return _ida_idp._processor_t_set_code16_mode(ea, code16)

    @staticmethod
    def get_code16_mode(ea: ida_idaapi.ea_t) ->bool:
        return _ida_idp._processor_t_get_code16_mode(ea)

    @staticmethod
    def next_exec_insn(target: 'ea_t *', ea: ida_idaapi.ea_t, tid: int,
        _getreg: 'processor_t::regval_getter_t *', regvalues: 'regval_t'
        ) ->'ssize_t':
        return _ida_idp._processor_t_next_exec_insn(target, ea, tid,
            _getreg, regvalues)

    @staticmethod
    def calc_step_over(target: 'ea_t *', ip: ida_idaapi.ea_t) ->'ssize_t':
        return _ida_idp._processor_t_calc_step_over(target, ip)

    @staticmethod
    def get_macro_insn_head(head: 'ea_t *', ip: ida_idaapi.ea_t) ->'ssize_t':
        return _ida_idp._processor_t_get_macro_insn_head(head, ip)

    @staticmethod
    def get_dbr_opnum(opnum: 'int *', insn: 'insn_t const &') ->'ssize_t':
        return _ida_idp._processor_t_get_dbr_opnum(opnum, insn)

    @staticmethod
    def insn_reads_tbit(insn: 'insn_t const &', _getreg:
        'processor_t::regval_getter_t *', regvalues: 'regval_t') ->'ssize_t':
        return _ida_idp._processor_t_insn_reads_tbit(insn, _getreg, regvalues)

    @staticmethod
    def get_idd_opinfo(opinf: 'idd_opinfo_t', ea: ida_idaapi.ea_t, n: int,
        thread_id: int, _getreg: 'processor_t::regval_getter_t *',
        regvalues: 'regval_t') ->'ssize_t':
        return _ida_idp._processor_t_get_idd_opinfo(opinf, ea, n, thread_id,
            _getreg, regvalues)

    @staticmethod
    def calc_next_eas(res: 'eavec_t *', insn: 'insn_t const &', over: bool
        ) ->'ssize_t':
        return _ida_idp._processor_t_calc_next_eas(res, insn, over)

    @staticmethod
    def clean_tbit(ea: ida_idaapi.ea_t, _getreg:
        'processor_t::regval_getter_t *', regvalues: 'regval_t') ->'ssize_t':
        return _ida_idp._processor_t_clean_tbit(ea, _getreg, regvalues)

    @staticmethod
    def get_reg_info(regname: str, bitrange: 'bitrange_t') ->str:
        return _ida_idp._processor_t_get_reg_info(regname, bitrange)

    @staticmethod
    def update_call_stack(stack: 'call_stack_t', tid: int, _getreg:
        'processor_t::regval_getter_t *', regvalues: 'regval_t') ->'ssize_t':
        return _ida_idp._processor_t_update_call_stack(stack, tid, _getreg,
            regvalues)

    @staticmethod
    def setup_til() ->'ssize_t':
        return _ida_idp._processor_t_setup_til()

    @staticmethod
    def max_ptr_size() ->'ssize_t':
        return _ida_idp._processor_t_max_ptr_size()

    @staticmethod
    def calc_cdecl_purged_bytes(ea: ida_idaapi.ea_t) ->'ssize_t':
        return _ida_idp._processor_t_calc_cdecl_purged_bytes(ea)

    @staticmethod
    def equal_reglocs(a1: 'argloc_t', a2: 'argloc_t') ->'ssize_t':
        return _ida_idp._processor_t_equal_reglocs(a1, a2)

    @staticmethod
    def decorate_name(outbuf: str, name: str, mangle: bool, cc: 'cm_t',
        type: 'tinfo_t') ->'ssize_t':
        return _ida_idp._processor_t_decorate_name(outbuf, name, mangle, cc,
            type)

    @staticmethod
    def calc_retloc(retloc: 'argloc_t', rettype: 'tinfo_t', cc: 'cm_t'
        ) ->'ssize_t':
        return _ida_idp._processor_t_calc_retloc(retloc, rettype, cc)

    @staticmethod
    def calc_varglocs(ftd: 'func_type_data_t', regs: 'regobjs_t', stkargs:
        'relobj_t', nfixed: int) ->'ssize_t':
        return _ida_idp._processor_t_calc_varglocs(ftd, regs, stkargs, nfixed)

    @staticmethod
    def calc_arglocs(fti: 'func_type_data_t') ->'ssize_t':
        return _ida_idp._processor_t_calc_arglocs(fti)

    @staticmethod
    def use_stkarg_type(ea: ida_idaapi.ea_t, arg: 'funcarg_t') ->'ssize_t':
        return _ida_idp._processor_t_use_stkarg_type(ea, arg)

    @staticmethod
    def use_regarg_type(idx: 'int *', ea: ida_idaapi.ea_t, rargs: 'void *'
        ) ->'ssize_t':
        return _ida_idp._processor_t_use_regarg_type(idx, ea, rargs)

    @staticmethod
    def use_arg_types(ea: ida_idaapi.ea_t, fti: 'func_type_data_t', rargs:
        'void *') ->'ssize_t':
        return _ida_idp._processor_t_use_arg_types(ea, fti, rargs)

    @staticmethod
    def calc_purged_bytes(p_purged_bytes: 'int *', fti: 'func_type_data_t'
        ) ->'ssize_t':
        return _ida_idp._processor_t_calc_purged_bytes(p_purged_bytes, fti)

    @staticmethod
    def get_stkarg_area_info(out: 'stkarg_area_info_t', cc: 'cm_t'
        ) ->'ssize_t':
        return _ida_idp._processor_t_get_stkarg_area_info(out, cc)

    @staticmethod
    def get_cc_regs(regs: 'callregs_t', cc: 'cm_t') ->'ssize_t':
        return _ida_idp._processor_t_get_cc_regs(regs, cc)

    @staticmethod
    def get_simd_types(out: 'void *', simd_attrs: 'simd_info_t', argloc:
        'argloc_t', create_tifs: bool) ->'ssize_t':
        return _ida_idp._processor_t_get_simd_types(out, simd_attrs, argloc,
            create_tifs)

    @staticmethod
    def arg_addrs_ready(caller: ida_idaapi.ea_t, n: int, tif: 'tinfo_t',
        addrs: 'ea_t *') ->'ssize_t':
        return _ida_idp._processor_t_arg_addrs_ready(caller, n, tif, addrs)

    @staticmethod
    def adjust_argloc(argloc: 'argloc_t', type: 'tinfo_t', size: int
        ) ->'ssize_t':
        return _ida_idp._processor_t_adjust_argloc(argloc, type, size)

    @staticmethod
    def lower_func_type(argnums: 'intvec_t *', fti: 'func_type_data_t'
        ) ->'ssize_t':
        return _ida_idp._processor_t_lower_func_type(argnums, fti)

    @staticmethod
    def get_abi_info(comp: 'comp_t') ->'qstrvec_t *, qstrvec_t *':
        return _ida_idp._processor_t_get_abi_info(comp)

    @staticmethod
    def arch_changed() ->'ssize_t':
        return _ida_idp._processor_t_arch_changed()

    @staticmethod
    def create_merge_handlers(md: 'merge_data_t *') ->'ssize_t':
        return _ida_idp._processor_t_create_merge_handlers(md)

    def privrange_changed(self, old_privrange: 'range_t', delta: 'adiff_t'
        ) ->'ssize_t':
        return _ida_idp._processor_t_privrange_changed(self, old_privrange,
            delta)

    def cvt64_supval(self, node: 'nodeidx_t', tag: 'uchar', idx:
        'nodeidx_t', data: 'uchar const *') ->'ssize_t':
        return _ida_idp._processor_t_cvt64_supval(self, node, tag, idx, data)

    def cvt64_hashval(self, node: 'nodeidx_t', tag: 'uchar', name: str,
        data: 'uchar const *') ->'ssize_t':
        return _ida_idp._processor_t_cvt64_hashval(self, node, tag, name, data)

    def get_stkvar_scale(self) ->int:
        return _ida_idp._processor_t_get_stkvar_scale(self)

    def get_canon_mnem(self, itype: 'uint16') ->str:
        return _ida_idp._processor_t_get_canon_mnem(self, itype)

    def get_canon_feature(self, itype: 'uint16') ->int:
        return _ida_idp._processor_t_get_canon_feature(self, itype)

    def sizeof_ldbl(self) ->'size_t':
        return _ida_idp._processor_t_sizeof_ldbl(self)

    def __init__(self):
        _ida_idp._processor_t_swiginit(self, _ida_idp.new__processor_t())
    __swig_destroy__ = _ida_idp.delete__processor_t


_ida_idp._processor_t_swigregister(_processor_t)


def get_ph() ->'processor_t *':
    return _ida_idp.get_ph()


def get_ash() ->'asm_t *':
    return _ida_idp.get_ash()


def str2reg(p: str) ->int:
    """Get any register number (-1 on error)
"""
    return _ida_idp.str2reg(p)


def is_align_insn(ea: ida_idaapi.ea_t) ->int:
    """If the instruction at 'ea' looks like an alignment instruction, return its length in bytes. Otherwise return 0. 
        """
    return _ida_idp.is_align_insn(ea)


def get_reg_name(reg: int, width: 'size_t', reghi: int=-1) ->str:
    """Get text representation of a register. For most processors this function will just return processor_t::reg_names[reg]. If the processor module has implemented processor_t::get_reg_name, it will be used instead 
        
@param reg: internal register number as defined in the processor module
@param width: register width in bytes
@param reghi: if specified, then this function will return the register pair
@returns length of register name in bytes or -1 if failure"""
    return _ida_idp.get_reg_name(reg, width, reghi)


class reg_info_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    reg: 'int' = property(_ida_idp.reg_info_t_reg_get, _ida_idp.
        reg_info_t_reg_set)
    """register number
"""
    size: 'int' = property(_ida_idp.reg_info_t_size_get, _ida_idp.
        reg_info_t_size_set)
    """register size
"""

    def __eq__(self, r: 'reg_info_t') ->bool:
        return _ida_idp.reg_info_t___eq__(self, r)

    def __ne__(self, r: 'reg_info_t') ->bool:
        return _ida_idp.reg_info_t___ne__(self, r)

    def __lt__(self, r: 'reg_info_t') ->bool:
        return _ida_idp.reg_info_t___lt__(self, r)

    def __gt__(self, r: 'reg_info_t') ->bool:
        return _ida_idp.reg_info_t___gt__(self, r)

    def __le__(self, r: 'reg_info_t') ->bool:
        return _ida_idp.reg_info_t___le__(self, r)

    def __ge__(self, r: 'reg_info_t') ->bool:
        return _ida_idp.reg_info_t___ge__(self, r)

    def compare(self, r: 'reg_info_t') ->int:
        return _ida_idp.reg_info_t_compare(self, r)

    def __init__(self):
        _ida_idp.reg_info_t_swiginit(self, _ida_idp.new_reg_info_t())
    __swig_destroy__ = _ida_idp.delete_reg_info_t


_ida_idp.reg_info_t_swigregister(reg_info_t)


def parse_reg_name(ri: 'reg_info_t', regname: str) ->bool:
    """Get register info by name. 
        
@param ri: result
@param regname: name of register
@returns success"""
    return _ida_idp.parse_reg_name(ri, regname)


NO_ACCESS = _ida_idp.NO_ACCESS
WRITE_ACCESS = _ida_idp.WRITE_ACCESS
READ_ACCESS = _ida_idp.READ_ACCESS
RW_ACCESS = _ida_idp.RW_ACCESS


class reg_access_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    regnum: 'int' = property(_ida_idp.reg_access_t_regnum_get, _ida_idp.
        reg_access_t_regnum_set)
    """register number (only entire registers)
"""
    range: 'bitrange_t' = property(_ida_idp.reg_access_t_range_get,
        _ida_idp.reg_access_t_range_set)
    """bitrange inside the register
"""
    access_type: 'access_type_t' = property(_ida_idp.
        reg_access_t_access_type_get, _ida_idp.reg_access_t_access_type_set)
    opnum: 'uchar' = property(_ida_idp.reg_access_t_opnum_get, _ida_idp.
        reg_access_t_opnum_set)
    """operand number
"""

    def have_common_bits(self, r: 'reg_access_t') ->bool:
        return _ida_idp.reg_access_t_have_common_bits(self, r)

    def __eq__(self, r: 'reg_access_t') ->bool:
        return _ida_idp.reg_access_t___eq__(self, r)

    def __ne__(self, r: 'reg_access_t') ->bool:
        return _ida_idp.reg_access_t___ne__(self, r)

    def __init__(self):
        _ida_idp.reg_access_t_swiginit(self, _ida_idp.new_reg_access_t())
    __swig_destroy__ = _ida_idp.delete_reg_access_t


_ida_idp.reg_access_t_swigregister(reg_access_t)


class reg_accesses_t(reg_access_vec_t):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_idp.reg_accesses_t_swiginit(self, _ida_idp.new_reg_accesses_t())
    __swig_destroy__ = _ida_idp.delete_reg_accesses_t


_ida_idp.reg_accesses_t_swigregister(reg_accesses_t)
SETPROC_IDB = _ida_idp.SETPROC_IDB
"""set processor type for old idb
"""
SETPROC_LOADER = _ida_idp.SETPROC_LOADER
"""set processor type for new idb; if the user has specified a compatible processor, return success without changing it. if failure, call loader_failure() 
          """
SETPROC_LOADER_NON_FATAL = _ida_idp.SETPROC_LOADER_NON_FATAL
"""the same as SETPROC_LOADER but non-fatal failures.
"""
SETPROC_USER = _ida_idp.SETPROC_USER
"""set user-specified processor used for -p and manual processor change at later time 
          """


def set_processor_type(procname: str, level: 'setproc_level_t') ->bool:
    """Set target processor type. Once a processor module is loaded, it cannot be replaced until we close the idb. 
        
@param procname: name of processor type (one of names present in processor_t::psnames)
@param level: SETPROC_
@returns success"""
    return _ida_idp.set_processor_type(procname, level)


def get_idp_name() ->str:
    """Get name of the current processor module. The name is derived from the file name. For example, for IBM PC the module is named "pc.w32" (windows version), then the module name is "PC" (uppercase). If no processor module is loaded, this function will return nullptr 
        """
    return _ida_idp.get_idp_name()


def set_target_assembler(asmnum: int) ->bool:
    """Set target assembler. 
        
@param asmnum: number of assembler in the current processor module
@returns success"""
    return _ida_idp.set_target_assembler(asmnum)


LTC_NONE = _ida_idp.LTC_NONE
"""no event (internal use)
"""
LTC_ADDED = _ida_idp.LTC_ADDED
"""added a local type
"""
LTC_DELETED = _ida_idp.LTC_DELETED
"""deleted a local type
"""
LTC_EDITED = _ida_idp.LTC_EDITED
"""edited a local type
"""
LTC_ALIASED = _ida_idp.LTC_ALIASED
"""added a type alias
"""
LTC_COMPILER = _ida_idp.LTC_COMPILER
"""changed the compiler and calling convention
"""
LTC_TIL_LOADED = _ida_idp.LTC_TIL_LOADED
"""loaded a til file
"""
LTC_TIL_UNLOADED = _ida_idp.LTC_TIL_UNLOADED
"""unloaded a til file
"""
LTC_TIL_COMPACTED = _ida_idp.LTC_TIL_COMPACTED
"""numbered types have been compacted compact_numbered_types()
"""
closebase = _ida_idp.closebase
savebase = _ida_idp.savebase
upgraded = _ida_idp.upgraded
auto_empty = _ida_idp.auto_empty
auto_empty_finally = _ida_idp.auto_empty_finally
determined_main = _ida_idp.determined_main
extlang_changed = _ida_idp.extlang_changed
idasgn_loaded = _ida_idp.idasgn_loaded
kernel_config_loaded = _ida_idp.kernel_config_loaded
loader_finished = _ida_idp.loader_finished
flow_chart_created = _ida_idp.flow_chart_created
compiler_changed = _ida_idp.compiler_changed
changing_ti = _ida_idp.changing_ti
ti_changed = _ida_idp.ti_changed
changing_op_ti = _ida_idp.changing_op_ti
op_ti_changed = _ida_idp.op_ti_changed
changing_op_type = _ida_idp.changing_op_type
op_type_changed = _ida_idp.op_type_changed
segm_added = _ida_idp.segm_added
deleting_segm = _ida_idp.deleting_segm
segm_deleted = _ida_idp.segm_deleted
changing_segm_start = _ida_idp.changing_segm_start
segm_start_changed = _ida_idp.segm_start_changed
changing_segm_end = _ida_idp.changing_segm_end
segm_end_changed = _ida_idp.segm_end_changed
changing_segm_name = _ida_idp.changing_segm_name
segm_name_changed = _ida_idp.segm_name_changed
changing_segm_class = _ida_idp.changing_segm_class
segm_class_changed = _ida_idp.segm_class_changed
segm_attrs_updated = _ida_idp.segm_attrs_updated
segm_moved = _ida_idp.segm_moved
allsegs_moved = _ida_idp.allsegs_moved
func_added = _ida_idp.func_added
func_updated = _ida_idp.func_updated
set_func_start = _ida_idp.set_func_start
set_func_end = _ida_idp.set_func_end
deleting_func = _ida_idp.deleting_func
frame_deleted = _ida_idp.frame_deleted
thunk_func_created = _ida_idp.thunk_func_created
func_tail_appended = _ida_idp.func_tail_appended
deleting_func_tail = _ida_idp.deleting_func_tail
func_tail_deleted = _ida_idp.func_tail_deleted
tail_owner_changed = _ida_idp.tail_owner_changed
func_noret_changed = _ida_idp.func_noret_changed
stkpnts_changed = _ida_idp.stkpnts_changed
updating_tryblks = _ida_idp.updating_tryblks
tryblks_updated = _ida_idp.tryblks_updated
deleting_tryblks = _ida_idp.deleting_tryblks
sgr_changed = _ida_idp.sgr_changed
make_code = _ida_idp.make_code
make_data = _ida_idp.make_data
destroyed_items = _ida_idp.destroyed_items
renamed = _ida_idp.renamed
byte_patched = _ida_idp.byte_patched
changing_cmt = _ida_idp.changing_cmt
cmt_changed = _ida_idp.cmt_changed
changing_range_cmt = _ida_idp.changing_range_cmt
range_cmt_changed = _ida_idp.range_cmt_changed
extra_cmt_changed = _ida_idp.extra_cmt_changed
item_color_changed = _ida_idp.item_color_changed
callee_addr_changed = _ida_idp.callee_addr_changed
bookmark_changed = _ida_idp.bookmark_changed
sgr_deleted = _ida_idp.sgr_deleted
adding_segm = _ida_idp.adding_segm
func_deleted = _ida_idp.func_deleted
dirtree_mkdir = _ida_idp.dirtree_mkdir
dirtree_rmdir = _ida_idp.dirtree_rmdir
dirtree_link = _ida_idp.dirtree_link
dirtree_move = _ida_idp.dirtree_move
dirtree_rank = _ida_idp.dirtree_rank
dirtree_rminode = _ida_idp.dirtree_rminode
dirtree_segm_moved = _ida_idp.dirtree_segm_moved
local_types_changed = _ida_idp.local_types_changed
lt_udm_created = _ida_idp.lt_udm_created
lt_udm_deleted = _ida_idp.lt_udm_deleted
lt_udm_renamed = _ida_idp.lt_udm_renamed
lt_udm_changed = _ida_idp.lt_udm_changed
lt_udt_expanded = _ida_idp.lt_udt_expanded
frame_created = _ida_idp.frame_created
frame_udm_created = _ida_idp.frame_udm_created
frame_udm_deleted = _ida_idp.frame_udm_deleted
frame_udm_renamed = _ida_idp.frame_udm_renamed
frame_udm_changed = _ida_idp.frame_udm_changed
frame_expanded = _ida_idp.frame_expanded
idasgn_matched_ea = _ida_idp.idasgn_matched_ea
lt_edm_created = _ida_idp.lt_edm_created
lt_edm_deleted = _ida_idp.lt_edm_deleted
lt_edm_renamed = _ida_idp.lt_edm_renamed
lt_edm_changed = _ida_idp.lt_edm_changed


def gen_idb_event(*args) ->None:
    """the kernel will use this function to generate idb_events
"""
    return _ida_idp.gen_idb_event(*args)


IDPOPT_CST = _ida_idp.IDPOPT_CST
IDPOPT_JVL = _ida_idp.IDPOPT_JVL
IDPOPT_PRI_DEFAULT = _ida_idp.IDPOPT_PRI_DEFAULT
IDPOPT_PRI_HIGH = _ida_idp.IDPOPT_PRI_HIGH
IDPOPT_NUM_INT = _ida_idp.IDPOPT_NUM_INT
IDPOPT_NUM_CHAR = _ida_idp.IDPOPT_NUM_CHAR
IDPOPT_NUM_SHORT = _ida_idp.IDPOPT_NUM_SHORT
IDPOPT_NUM_RANGE = _ida_idp.IDPOPT_NUM_RANGE
IDPOPT_NUM_UNS = _ida_idp.IDPOPT_NUM_UNS
IDPOPT_BIT_UINT = _ida_idp.IDPOPT_BIT_UINT
IDPOPT_BIT_UCHAR = _ida_idp.IDPOPT_BIT_UCHAR
IDPOPT_BIT_USHORT = _ida_idp.IDPOPT_BIT_USHORT
IDPOPT_BIT_BOOL = _ida_idp.IDPOPT_BIT_BOOL
IDPOPT_STR_QSTRING = _ida_idp.IDPOPT_STR_QSTRING
IDPOPT_STR_LONG = _ida_idp.IDPOPT_STR_LONG
IDPOPT_I64_RANGE = _ida_idp.IDPOPT_I64_RANGE
IDPOPT_I64_UNS = _ida_idp.IDPOPT_I64_UNS
IDPOPT_CST_PARAMS = _ida_idp.IDPOPT_CST_PARAMS
IDPOPT_MBROFF = _ida_idp.IDPOPT_MBROFF


class num_range_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, _min: 'int64', _max: 'int64'):
        _ida_idp.num_range_t_swiginit(self, _ida_idp.new_num_range_t(_min,
            _max))
    minval: 'int64' = property(_ida_idp.num_range_t_minval_get, _ida_idp.
        num_range_t_minval_set)
    maxval: 'int64' = property(_ida_idp.num_range_t_maxval_get, _ida_idp.
        num_range_t_maxval_set)
    __swig_destroy__ = _ida_idp.delete_num_range_t


_ida_idp.num_range_t_swigregister(num_range_t)


class params_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, _p1: 'int64', _p2: 'int64'):
        _ida_idp.params_t_swiginit(self, _ida_idp.new_params_t(_p1, _p2))
    p1: 'int64' = property(_ida_idp.params_t_p1_get, _ida_idp.params_t_p1_set)
    p2: 'int64' = property(_ida_idp.params_t_p2_get, _ida_idp.params_t_p2_set)
    __swig_destroy__ = _ida_idp.delete_params_t


_ida_idp.params_t_swigregister(params_t)
cik_string = _ida_idp.cik_string
cik_filename = _ida_idp.cik_filename
cik_path = _ida_idp.cik_path


def register_cfgopts(opts: 'cfgopt_t const []', nopts: 'size_t', cb:
    'config_changed_cb_t *'=None, obj: 'void *'=None) ->bool:
    return _ida_idp.register_cfgopts(opts, nopts, cb, obj)


def get_config_value(key: str) ->'jvalue_t *':
    return _ida_idp.get_config_value(key)


def cfg_get_cc_parm(compid: 'comp_t', name: str) ->str:
    return _ida_idp.cfg_get_cc_parm(compid, name)


def cfg_get_cc_header_path(compid: 'comp_t') ->str:
    return _ida_idp.cfg_get_cc_header_path(compid)


def cfg_get_cc_predefined_macros(compid: 'comp_t') ->str:
    return _ida_idp.cfg_get_cc_predefined_macros(compid)


def process_config_directive(directive: str, priority: int=2) ->None:
    return _ida_idp.process_config_directive(directive, priority)


def AssembleLine(ea, cs, ip, use32, line):
    """Assemble an instruction to a string (display a warning if an error is found)

@param ea: linear address of instruction
@param cs:  cs of instruction
@param ip:  ip of instruction
@param use32: is 32bit segment
@param line: line to assemble
@return:
    - None on failure
    - or a string containing the assembled instruction"""
    return _ida_idp.AssembleLine(ea, cs, ip, use32, line)


def assemble(ea, cs, ip, use32, line):
    """Assemble an instruction into the database (display a warning if an error is found)

@param ea: linear address of instruction
@param cs: cs of instruction
@param ip: ip of instruction
@param use32: is 32bit segment?
@param line: line to assemble

@return: Boolean. True on success."""
    return _ida_idp.assemble(ea, cs, ip, use32, line)


def ph_get_id():
    """Returns the 'ph.id' field"""
    return _ida_idp.ph_get_id()


def ph_get_version():
    """Returns the 'ph.version'"""
    return _ida_idp.ph_get_version()


def ph_get_flag():
    """Returns the 'ph.flag'"""
    return _ida_idp.ph_get_flag()


def ph_get_cnbits():
    """Returns the 'ph.cnbits'"""
    return _ida_idp.ph_get_cnbits()


def ph_get_dnbits():
    """Returns the 'ph.dnbits'"""
    return _ida_idp.ph_get_dnbits()


def ph_get_reg_first_sreg():
    """Returns the 'ph.reg_first_sreg'"""
    return _ida_idp.ph_get_reg_first_sreg()


def ph_get_reg_last_sreg():
    """Returns the 'ph.reg_last_sreg'"""
    return _ida_idp.ph_get_reg_last_sreg()


def ph_get_segreg_size():
    """Returns the 'ph.segreg_size'"""
    return _ida_idp.ph_get_segreg_size()


def ph_get_reg_code_sreg():
    """Returns the 'ph.reg_code_sreg'"""
    return _ida_idp.ph_get_reg_code_sreg()


def ph_get_reg_data_sreg():
    """Returns the 'ph.reg_data_sreg'"""
    return _ida_idp.ph_get_reg_data_sreg()


def ph_get_icode_return():
    """Returns the 'ph.icode_return'"""
    return _ida_idp.ph_get_icode_return()


def ph_get_instruc_start():
    """Returns the 'ph.instruc_start'"""
    return _ida_idp.ph_get_instruc_start()


def ph_get_instruc_end():
    """Returns the 'ph.instruc_end'"""
    return _ida_idp.ph_get_instruc_end()


def ph_get_tbyte_size():
    """Returns the 'ph.tbyte_size' field as defined in he processor module"""
    return _ida_idp.ph_get_tbyte_size()


def ph_get_instruc():
    """Returns a list of tuples (instruction_name, instruction_feature) containing the
instructions list as defined in he processor module"""
    return _ida_idp.ph_get_instruc()


def ph_get_regnames():
    """Returns the list of register names as defined in the processor module"""
    return _ida_idp.ph_get_regnames()


def ph_get_operand_info(ea: ida_idaapi.ea_t, n: int) ->Union[Tuple[int,
    ida_idaapi.ea_t, int, int, int], None]:
    """Returns the operand information given an ea and operand number.

@param ea: address
@param n: operand number

@return: Returns an idd_opinfo_t as a tuple: (modified, ea, reg_ival, regidx, value_size).
         Please refer to idd_opinfo_t structure in the SDK."""
    return _ida_idp.ph_get_operand_info(ea, n)


def ph_calcrel(ea: ida_idaapi.ea_t) ->'bytevec_t *, size_t *':
    return _ida_idp.ph_calcrel(ea)


def ph_find_reg_value(insn: 'insn_t const &', reg: int) ->'uint64 *':
    return _ida_idp.ph_find_reg_value(insn, reg)


def ph_find_op_value(insn: 'insn_t const &', op: int) ->'uint64 *':
    return _ida_idp.ph_find_op_value(insn, op)


def ph_get_reg_accesses(accvec: 'reg_accesses_t', insn: 'insn_t const &',
    flags: int) ->'ssize_t':
    return _ida_idp.ph_get_reg_accesses(accvec, insn, flags)


def ph_get_abi_info(comp: 'comp_t') ->'qstrvec_t *, qstrvec_t *':
    return _ida_idp.ph_get_abi_info(comp)


class IDP_Hooks(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, _flags: int=0, _hkcb_flags: int=1):
        if self.__class__ == IDP_Hooks:
            _self = None
        else:
            _self = self
        _ida_idp.IDP_Hooks_swiginit(self, _ida_idp.new_IDP_Hooks(_self,
            _flags, _hkcb_flags))

    def hook(self) ->bool:
        return _ida_idp.IDP_Hooks_hook(self)

    def unhook(self) ->bool:
        return _ida_idp.IDP_Hooks_unhook(self)

    def ev_init(self, idp_modname: str) ->int:
        """The IDP module is just loaded. 
          
@param idp_modname: (const char *) processor module name
@retval <0: on failure"""
        return _ida_idp.IDP_Hooks_ev_init(self, idp_modname)

    def ev_term(self) ->int:
        """The IDP module is being unloaded.
"""
        return _ida_idp.IDP_Hooks_ev_term(self)

    def ev_newprc(self, pnum: int, keep_cfg: bool) ->int:
        """Before changing processor type. 
          
@param pnum: (int) processor number in the array of processor names
@param keep_cfg: (bool) true: do not modify kernel configuration
@retval 1: ok
@retval <0: prohibit"""
        return _ida_idp.IDP_Hooks_ev_newprc(self, pnum, keep_cfg)

    def ev_newasm(self, asmnum: int) ->int:
        """Before setting a new assembler. 
          
@param asmnum: (int) See also ev_asm_installed"""
        return _ida_idp.IDP_Hooks_ev_newasm(self, asmnum)

    def ev_newfile(self, fname: 'char *') ->int:
        """A new file has been loaded. 
          
@param fname: (char *) input file name"""
        return _ida_idp.IDP_Hooks_ev_newfile(self, fname)

    def ev_oldfile(self, fname: 'char *') ->int:
        """An old file has been loaded. 
          
@param fname: (char *) input file name"""
        return _ida_idp.IDP_Hooks_ev_oldfile(self, fname)

    def ev_newbinary(self, filename: 'char *', fileoff: 'qoff64_t',
        basepara: ida_idaapi.ea_t, binoff: ida_idaapi.ea_t, nbytes: 'uint64'
        ) ->int:
        """IDA is about to load a binary file. 
          
@param filename: (char *) binary file name
@param fileoff: (qoff64_t) offset in the file
@param basepara: (::ea_t) base loading paragraph
@param binoff: (::ea_t) loader offset
@param nbytes: (::uint64) number of bytes to load"""
        return _ida_idp.IDP_Hooks_ev_newbinary(self, filename, fileoff,
            basepara, binoff, nbytes)

    def ev_endbinary(self, ok: bool) ->int:
        """IDA has loaded a binary file. 
          
@param ok: (bool) file loaded successfully?"""
        return _ida_idp.IDP_Hooks_ev_endbinary(self, ok)

    def ev_set_idp_options(self, keyword: str, value_type: int, value:
        'void const *', idb_loaded: bool) ->int:
        """Set IDP-specific configuration option Also see set_options_t in config.hpp 
          
@param keyword: (const char *)
@param value_type: (int)
@param value: (const void *)
@param idb_loaded: (bool) true if the ev_oldfile/ev_newfile events have been generated
@retval 1: ok
@retval 0: not implemented
@retval -1: error (and message in errbuf)"""
        return _ida_idp.IDP_Hooks_ev_set_idp_options(self, keyword,
            value_type, value, idb_loaded)

    def ev_set_proc_options(self, options: str, confidence: int) ->int:
        """Called if the user specified an option string in the command line: -p<processor name>:<options>. Can be used for setting a processor subtype. Also called if option string is passed to set_processor_type() and IDC's SetProcessorType(). 
          
@param options: (const char *)
@param confidence: (int) 0: loader's suggestion 1: user's decision
@retval <0: if bad option string"""
        return _ida_idp.IDP_Hooks_ev_set_proc_options(self, options, confidence
            )

    def ev_ana_insn(self, out: 'insn_t *') ->bool:
        """Analyze one instruction and fill 'out' structure. This function shouldn't change the database, flags or anything else. All these actions should be performed only by emu_insn() function. insn_t::ea contains address of instruction to analyze. 
          
@param out: (insn_t *)
@returns length of the instruction in bytes, 0 if instruction can't be decoded.
@retval 0: if instruction can't be decoded."""
        return _ida_idp.IDP_Hooks_ev_ana_insn(self, out)

    def ev_emu_insn(self, insn: 'insn_t const *') ->bool:
        """Emulate instruction, create cross-references, plan to analyze subsequent instructions, modify flags etc. Upon entrance to this function, all information about the instruction is in 'insn' structure. 
          
@param insn: (const insn_t *)
@retval 1: ok
@retval -1: the kernel will delete the instruction"""
        return _ida_idp.IDP_Hooks_ev_emu_insn(self, insn)

    def ev_out_header(self, outctx: 'outctx_t *') ->int:
        """Function to produce start of disassembled text 
          
@param outctx: (outctx_t *)
@retval void: """
        return _ida_idp.IDP_Hooks_ev_out_header(self, outctx)

    def ev_out_footer(self, outctx: 'outctx_t *') ->int:
        """Function to produce end of disassembled text 
          
@param outctx: (outctx_t *)
@retval void: """
        return _ida_idp.IDP_Hooks_ev_out_footer(self, outctx)

    def ev_out_segstart(self, outctx: 'outctx_t *', seg: 'segment_t *') ->int:
        """Function to produce start of segment 
          
@param outctx: (outctx_t *)
@param seg: (segment_t *)
@retval 1: ok
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_out_segstart(self, outctx, seg)

    def ev_out_segend(self, outctx: 'outctx_t *', seg: 'segment_t *') ->int:
        """Function to produce end of segment 
          
@param outctx: (outctx_t *)
@param seg: (segment_t *)
@retval 1: ok
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_out_segend(self, outctx, seg)

    def ev_out_assumes(self, outctx: 'outctx_t *') ->int:
        """Function to produce assume directives when segment register value changes. 
          
@param outctx: (outctx_t *)
@retval 1: ok
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_out_assumes(self, outctx)

    def ev_out_insn(self, outctx: 'outctx_t *') ->bool:
        """Generate text representation of an instruction in 'ctx.insn' outctx_t provides functions to output the generated text. This function shouldn't change the database, flags or anything else. All these actions should be performed only by emu_insn() function. 
          
@param outctx: (outctx_t *)
@retval void: """
        return _ida_idp.IDP_Hooks_ev_out_insn(self, outctx)

    def ev_out_mnem(self, outctx: 'outctx_t *') ->int:
        """Generate instruction mnemonics. This callback should append the colored mnemonics to ctx.outbuf Optional notification, if absent, out_mnem will be called. 
          
@param outctx: (outctx_t *)
@retval 1: if appended the mnemonics
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_out_mnem(self, outctx)

    def ev_out_operand(self, outctx: 'outctx_t *', op: 'op_t const *') ->bool:
        """Generate text representation of an instruction operand outctx_t provides functions to output the generated text. All these actions should be performed only by emu_insn() function. 
          
@param outctx: (outctx_t *)
@param op: (const op_t *)
@retval 1: ok
@retval -1: operand is hidden"""
        return _ida_idp.IDP_Hooks_ev_out_operand(self, outctx, op)

    def ev_out_data(self, outctx: 'outctx_t *', analyze_only: bool) ->int:
        """Generate text representation of data items This function may change the database and create cross-references if analyze_only is set 
          
@param outctx: (outctx_t *)
@param analyze_only: (bool)
@retval 1: ok
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_out_data(self, outctx, analyze_only)

    def ev_out_label(self, outctx: 'outctx_t *', colored_name: str) ->int:
        """The kernel is going to generate an instruction label line or a function header. 
          
@param outctx: (outctx_t *)
@param colored_name: (const char *)
@retval <0: if the kernel should not generate the label
@retval 0: not implemented or continue"""
        return _ida_idp.IDP_Hooks_ev_out_label(self, outctx, colored_name)

    def ev_out_special_item(self, outctx: 'outctx_t *', segtype: 'uchar'
        ) ->int:
        """Generate text representation of an item in a special segment i.e. absolute symbols, externs, communal definitions etc 
          
@param outctx: (outctx_t *)
@param segtype: (uchar)
@retval 1: ok
@retval 0: not implemented
@retval -1: overflow"""
        return _ida_idp.IDP_Hooks_ev_out_special_item(self, outctx, segtype)

    def ev_gen_regvar_def(self, outctx: 'outctx_t *', v: 'regvar_t *') ->int:
        """Generate register variable definition line. 
          
@param outctx: (outctx_t *)
@param v: (regvar_t *)
@retval >0: ok, generated the definition text
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_gen_regvar_def(self, outctx, v)

    def ev_gen_src_file_lnnum(self, outctx: 'outctx_t *', file: str, lnnum:
        'size_t') ->int:
        """Callback: generate analog of: 
     #line  123
    


          
@param outctx: (outctx_t *) output context
@param file: (const char *) source file (may be nullptr)
@param lnnum: (size_t) line number
@retval 1: directive has been generated
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_gen_src_file_lnnum(self, outctx, file,
            lnnum)

    def ev_creating_segm(self, seg: 'segment_t *') ->int:
        """A new segment is about to be created. 
          
@param seg: (segment_t *)
@retval 1: ok
@retval <0: segment should not be created"""
        return _ida_idp.IDP_Hooks_ev_creating_segm(self, seg)

    def ev_moving_segm(self, seg: 'segment_t *', to: ida_idaapi.ea_t, flags:
        int) ->int:
        """May the kernel move the segment? 
          
@param seg: (segment_t *) segment to move
@param to: (::ea_t) new segment start address
@param flags: (int) combination of Move segment flags
@retval 0: yes
@retval <0: the kernel should stop"""
        return _ida_idp.IDP_Hooks_ev_moving_segm(self, seg, to, flags)

    def ev_coagulate(self, start_ea: ida_idaapi.ea_t) ->int:
        """Try to define some unexplored bytes. This notification will be called if the kernel tried all possibilities and could not find anything more useful than to convert to array of bytes. The module can help the kernel and convert the bytes into something more useful. 
          
@param start_ea: (::ea_t)
@returns number of converted bytes"""
        return _ida_idp.IDP_Hooks_ev_coagulate(self, start_ea)

    def ev_undefine(self, ea: ida_idaapi.ea_t) ->int:
        """An item in the database (insn or data) is being deleted. 
          
@param ea: (ea_t)
@retval 1: do not delete srranges at the item end
@retval 0: srranges can be deleted"""
        return _ida_idp.IDP_Hooks_ev_undefine(self, ea)

    def ev_treat_hindering_item(self, hindering_item_ea: ida_idaapi.ea_t,
        new_item_flags: 'flags64_t', new_item_ea: ida_idaapi.ea_t,
        new_item_length: 'asize_t') ->int:
        """An item hinders creation of another item. 
          
@param hindering_item_ea: (::ea_t)
@param new_item_flags: (flags64_t) (0 for code)
@param new_item_ea: (::ea_t)
@param new_item_length: (::asize_t)
@retval 0: no reaction
@retval !=0: the kernel may delete the hindering item"""
        return _ida_idp.IDP_Hooks_ev_treat_hindering_item(self,
            hindering_item_ea, new_item_flags, new_item_ea, new_item_length)

    def ev_rename(self, ea: ida_idaapi.ea_t, new_name: str) ->int:
        """The kernel is going to rename a byte. 
          
@param ea: (::ea_t)
@param new_name: (const char *)
@retval <0: if the kernel should not rename it.
@retval 2: to inhibit the notification. I.e., the kernel should not rename, but 'set_name()' should return 'true'. also see renamed the return value is ignored when kernel is going to delete name"""
        return _ida_idp.IDP_Hooks_ev_rename(self, ea, new_name)

    def ev_is_far_jump(self, icode: int) ->int:
        """is indirect far jump or call instruction? meaningful only if the processor has 'near' and 'far' reference types 
          
@param icode: (int)
@retval 0: not implemented
@retval 1: yes
@retval -1: no"""
        return _ida_idp.IDP_Hooks_ev_is_far_jump(self, icode)

    def ev_is_sane_insn(self, insn: 'insn_t const *', no_crefs: int) ->int:
        """Is the instruction sane for the current file type?. 
          
@param insn: (const insn_t*) the instruction
@param no_crefs: (int) 1: the instruction has no code refs to it. ida just tries to convert unexplored bytes to an instruction (but there is no other reason to convert them into an instruction) 0: the instruction is created because of some coderef, user request or another weighty reason.
@retval >=0: ok
@retval <0: no, the instruction isn't likely to appear in the program"""
        return _ida_idp.IDP_Hooks_ev_is_sane_insn(self, insn, no_crefs)

    def ev_is_cond_insn(self, insn: 'insn_t const *') ->int:
        """Is conditional instruction? 
          
@param insn: (const insn_t *) instruction address
@retval 1: yes
@retval -1: no
@retval 0: not implemented or not instruction"""
        return _ida_idp.IDP_Hooks_ev_is_cond_insn(self, insn)

    def ev_is_call_insn(self, insn: 'insn_t const *') ->int:
        """Is the instruction a "call"? 
          
@param insn: (const insn_t *) instruction
@retval 0: unknown
@retval <0: no
@retval 1: yes"""
        return _ida_idp.IDP_Hooks_ev_is_call_insn(self, insn)

    def ev_is_ret_insn(self, insn: 'insn_t const *', flags: 'uchar') ->int:
        """Is the instruction a "return"? 
          
@param insn: (const insn_t *) instruction
@param flags: (uchar), combination of IRI_... flags (see above)
@retval 0: unknown
@retval <0: no
@retval 1: yes"""
        return _ida_idp.IDP_Hooks_ev_is_ret_insn(self, insn, flags)

    def ev_may_be_func(self, insn: 'insn_t const *', state: int) ->int:
        """Can a function start here? 
          
@param insn: (const insn_t*) the instruction
@param state: (int) autoanalysis phase 0: creating functions 1: creating chunks
@returns probability 1..100"""
        return _ida_idp.IDP_Hooks_ev_may_be_func(self, insn, state)

    def ev_is_basic_block_end(self, insn: 'insn_t const *',
        call_insn_stops_block: bool) ->int:
        """Is the current instruction end of a basic block?. This function should be defined for processors with delayed jump slots. 
          
@param insn: (const insn_t*) the instruction
@param call_insn_stops_block: (bool)
@retval 0: unknown
@retval <0: no
@retval 1: yes"""
        return _ida_idp.IDP_Hooks_ev_is_basic_block_end(self, insn,
            call_insn_stops_block)

    def ev_is_indirect_jump(self, insn: 'insn_t const *') ->int:
        """Determine if instruction is an indirect jump. If CF_JUMP bit cannot describe all jump types jumps, please define this callback. 
          
@param insn: (const insn_t*) the instruction
@retval 0: use CF_JUMP
@retval 1: no
@retval 2: yes"""
        return _ida_idp.IDP_Hooks_ev_is_indirect_jump(self, insn)

    def ev_is_insn_table_jump(self) ->int:
        """Reserved.
"""
        return _ida_idp.IDP_Hooks_ev_is_insn_table_jump(self)

    def ev_is_switch(self, si: 'switch_info_t', insn: 'insn_t const *') ->int:
        """Find 'switch' idiom or override processor module's decision. It will be called for instructions marked with CF_JUMP. 
          
@param si: (switch_info_t *), out
@param insn: (const insn_t *) instruction possibly belonging to a switch
@retval 1: switch is found, 'si' is filled. IDA will create the switch using the filled 'si'
@retval -1: no switch found. This value forbids switch creation by the processor module
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_is_switch(self, si, insn)

    def ev_calc_switch_cases(self, casevec: 'casevec_t *', targets:
        'eavec_t *', insn_ea: ida_idaapi.ea_t, si: 'switch_info_t') ->int:
        """Calculate case values and targets for a custom jump table. 
          
@param casevec: (::casevec_t *) vector of case values (may be nullptr)
@param targets: (eavec_t *) corresponding target addresses (my be nullptr)
@param insn_ea: (::ea_t) address of the 'indirect jump' instruction
@param si: (switch_info_t *) switch information
@retval 1: ok
@retval <=0: failed"""
        return _ida_idp.IDP_Hooks_ev_calc_switch_cases(self, casevec,
            targets, insn_ea, si)

    def ev_create_switch_xrefs(self, jumpea: ida_idaapi.ea_t, si:
        'switch_info_t') ->int:
        """Create xrefs for a custom jump table. 
          
@param jumpea: (::ea_t) address of the jump insn
@param si: (const switch_info_t *) switch information
@returns must return 1 Must be implemented if module uses custom jump tables, SWI_CUSTOM"""
        return _ida_idp.IDP_Hooks_ev_create_switch_xrefs(self, jumpea, si)

    def ev_is_align_insn(self, ea: ida_idaapi.ea_t) ->int:
        """Is the instruction created only for alignment purposes?. Do not directly call this function, use is_align_insn() 
          
@param ea: (ea_t) - instruction address
@retval number: of bytes in the instruction"""
        return _ida_idp.IDP_Hooks_ev_is_align_insn(self, ea)

    def ev_is_alloca_probe(self, ea: ida_idaapi.ea_t) ->int:
        """Does the function at 'ea' behave as __alloca_probe? 
          
@param ea: (::ea_t)
@retval 1: yes
@retval 0: no"""
        return _ida_idp.IDP_Hooks_ev_is_alloca_probe(self, ea)

    def ev_delay_slot_insn(self, ea: ida_idaapi.ea_t, bexec: bool, fexec: bool
        ) ->'PyObject *':
        """Get delay slot instruction 
          
@param ea: (::ea_t *) in: instruction address in question, out: (if the answer is positive) if the delay slot contains valid insn: the address of the delay slot insn else: BADADDR (invalid insn, e.g. a branch)
@param bexec: (bool *) execute slot if jumping, initially set to 'true'
@param fexec: (bool *) execute slot if not jumping, initally set to 'true'
@retval 1: positive answer
@retval <=0: ordinary insn"""
        return _ida_idp.IDP_Hooks_ev_delay_slot_insn(self, ea, bexec, fexec)

    def ev_is_sp_based(self, mode: 'int *', insn: 'insn_t const *', op:
        'op_t const *') ->int:
        """Check whether the operand is relative to stack pointer or frame pointer This event is used to determine how to output a stack variable If not implemented, then all operands are sp based by default. Implement this event only if some stack references use frame pointer instead of stack pointer. 
          
@param mode: (int *) out, combination of SP/FP operand flags
@param insn: (const insn_t *)
@param op: (const op_t *)
@retval 0: not implemented
@retval 1: ok"""
        return _ida_idp.IDP_Hooks_ev_is_sp_based(self, mode, insn, op)

    def ev_can_have_type(self, op: 'op_t const *') ->int:
        """Can the operand have a type as offset, segment, decimal, etc? (for example, a register AX can't have a type, meaning that the user can't change its representation. see bytes.hpp for information about types and flags) 
          
@param op: (const op_t *)
@retval 0: unknown
@retval <0: no
@retval 1: yes"""
        return _ida_idp.IDP_Hooks_ev_can_have_type(self, op)

    def ev_cmp_operands(self, op1: 'op_t const *', op2: 'op_t const *') ->int:
        """Compare instruction operands 
          
@param op1: (const op_t*)
@param op2: (const op_t*)
@retval 1: equal
@retval -1: not equal
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_cmp_operands(self, op1, op2)

    def ev_adjust_refinfo(self, ri: 'refinfo_t', ea: ida_idaapi.ea_t, n:
        int, fd: 'fixup_data_t const *') ->int:
        """Called from apply_fixup before converting operand to reference. Can be used for changing the reference info. (e.g. the PPC module adds REFINFO_NOBASE for some references) 
          
@param ri: (refinfo_t *)
@param ea: (::ea_t) instruction address
@param n: (int) operand number
@param fd: (const fixup_data_t *)
@retval <0: do not create an offset
@retval 0: not implemented or refinfo adjusted"""
        return _ida_idp.IDP_Hooks_ev_adjust_refinfo(self, ri, ea, n, fd)

    def ev_get_operand_string(self, insn: 'insn_t const *', opnum: int
        ) ->'PyObject *':
        """Request text string for operand (cli, java, ...). 
          
@param insn: (const insn_t*) the instruction
@param opnum: (int) operand number, -1 means any string operand
@retval 0: no string (or empty string)
@retval >0: original string length without terminating zero"""
        return _ida_idp.IDP_Hooks_ev_get_operand_string(self, insn, opnum)

    def ev_get_reg_name(self, reg: int, width: 'size_t', reghi: int
        ) ->'PyObject *':
        """Generate text representation of a register. Most processor modules do not need to implement this callback. It is useful only if processor_t::reg_names[reg] does not provide the correct register name. 
          
@param reg: (int) internal register number as defined in the processor module
@param width: (size_t) register width in bytes
@param reghi: (int) if not -1 then this function will return the register pair
@retval -1: if error
@retval strlen(buf): if success"""
        return _ida_idp.IDP_Hooks_ev_get_reg_name(self, reg, width, reghi)

    def ev_str2reg(self, regname: str) ->int:
        """Convert a register name to a register number. The register number is the register index in the processor_t::reg_names array Most processor modules do not need to implement this callback It is useful only if processor_t::reg_names[reg] does not provide the correct register names 
          
@param regname: (const char *)
@retval register: number + 1
@retval 0: not implemented or could not be decoded"""
        return _ida_idp.IDP_Hooks_ev_str2reg(self, regname)

    def ev_get_autocmt(self, insn: 'insn_t const *') ->'PyObject *':
        """Callback: get dynamic auto comment. Will be called if the autocomments are enabled and the comment retrieved from ida.int starts with '$!'. 'insn' contains valid info. 
          
@param insn: (const insn_t*) the instruction
@retval 1: new comment has been generated
@retval 0: callback has not been handled. the buffer must not be changed in this case"""
        return _ida_idp.IDP_Hooks_ev_get_autocmt(self, insn)

    def ev_get_bg_color(self, color: 'bgcolor_t *', ea: ida_idaapi.ea_t) ->int:
        """Get item background color. Plugins can hook this callback to color disassembly lines dynamically 
          
@param color: (bgcolor_t *), out
@param ea: (::ea_t)
@retval 0: not implemented
@retval 1: color set"""
        return _ida_idp.IDP_Hooks_ev_get_bg_color(self, color, ea)

    def ev_is_jump_func(self, pfn: 'func_t *', jump_target: 'ea_t *',
        func_pointer: 'ea_t *') ->int:
        """Is the function a trivial "jump" function?. 
          
@param pfn: (func_t *)
@param jump_target: (::ea_t *)
@param func_pointer: (::ea_t *)
@retval <0: no
@retval 0: don't know
@retval 1: yes, see 'jump_target' and 'func_pointer'"""
        return _ida_idp.IDP_Hooks_ev_is_jump_func(self, pfn, jump_target,
            func_pointer)

    def ev_func_bounds(self, possible_return_code: 'int *', pfn: 'func_t *',
        max_func_end_ea: ida_idaapi.ea_t) ->int:
        """find_func_bounds() finished its work. The module may fine tune the function bounds 
          
@param possible_return_code: (int *), in/out
@param pfn: (func_t *)
@param max_func_end_ea: (::ea_t) (from the kernel's point of view)
@retval void: """
        return _ida_idp.IDP_Hooks_ev_func_bounds(self, possible_return_code,
            pfn, max_func_end_ea)

    def ev_verify_sp(self, pfn: 'func_t *') ->int:
        """All function instructions have been analyzed. Now the processor module can analyze the stack pointer for the whole function 
          
@param pfn: (func_t *)
@retval 0: ok
@retval <0: bad stack pointer"""
        return _ida_idp.IDP_Hooks_ev_verify_sp(self, pfn)

    def ev_verify_noreturn(self, pfn: 'func_t *') ->int:
        """The kernel wants to set 'noreturn' flags for a function. 
          
@param pfn: (func_t *)
@retval 0: ok. any other value: do not set 'noreturn' flag"""
        return _ida_idp.IDP_Hooks_ev_verify_noreturn(self, pfn)

    def ev_create_func_frame(self, pfn: 'func_t *') ->int:
        """Create a function frame for a newly created function Set up frame size, its attributes etc 
          
@param pfn: (func_t *)
@retval 1: ok
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_create_func_frame(self, pfn)

    def ev_get_frame_retsize(self, frsize: 'int *', pfn: 'func_t const *'
        ) ->int:
        """Get size of function return address in bytes If this event is not implemented, the kernel will assume
* 8 bytes for 64-bit function
* 4 bytes for 32-bit function
* 2 bytes otherwise



@param frsize: (int *) frame size (out)
@param pfn: (const func_t *), can't be nullptr
@retval 1: ok
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_get_frame_retsize(self, frsize, pfn)

    def ev_get_stkvar_scale_factor(self) ->int:
        """Should stack variable references be multiplied by a coefficient before being used in the stack frame?. Currently used by TMS320C55 because the references into the stack should be multiplied by 2 
          
@returns scaling factor
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_get_stkvar_scale_factor(self)

    def ev_demangle_name(self, name: str, disable_mask: int, demreq: int
        ) ->'PyObject *':
        """Demangle a C++ (or another language) name into a user-readable string. This event is called by demangle_name() 
          
@param name: (const char *) mangled name
@param disable_mask: (uint32) flags to inhibit parts of output or compiler info/other (see MNG_)
@param demreq: (demreq_type_t) operation to perform
@retval 1: if success
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_demangle_name(self, name, disable_mask,
            demreq)

    def ev_add_cref(self, _from: ida_idaapi.ea_t, to: ida_idaapi.ea_t, type:
        'cref_t') ->int:
        """A code reference is being created. 
          
@param to: (::ea_t)
@param type: (cref_t)
@retval <0: cancel cref creation
@retval 0: not implemented or continue"""
        return _ida_idp.IDP_Hooks_ev_add_cref(self, _from, to, type)

    def ev_add_dref(self, _from: ida_idaapi.ea_t, to: ida_idaapi.ea_t, type:
        'dref_t') ->int:
        """A data reference is being created. 
          
@param to: (::ea_t)
@param type: (dref_t)
@retval <0: cancel dref creation
@retval 0: not implemented or continue"""
        return _ida_idp.IDP_Hooks_ev_add_dref(self, _from, to, type)

    def ev_del_cref(self, _from: ida_idaapi.ea_t, to: ida_idaapi.ea_t,
        expand: bool) ->int:
        """A code reference is being deleted. 
          
@param to: (::ea_t)
@param expand: (bool)
@retval <0: cancel cref deletion
@retval 0: not implemented or continue"""
        return _ida_idp.IDP_Hooks_ev_del_cref(self, _from, to, expand)

    def ev_del_dref(self, _from: ida_idaapi.ea_t, to: ida_idaapi.ea_t) ->int:
        """A data reference is being deleted. 
          
@param to: (::ea_t)
@retval <0: cancel dref deletion
@retval 0: not implemented or continue"""
        return _ida_idp.IDP_Hooks_ev_del_dref(self, _from, to)

    def ev_coagulate_dref(self, _from: ida_idaapi.ea_t, to: ida_idaapi.ea_t,
        may_define: bool, code_ea: 'ea_t *') ->int:
        """Data reference is being analyzed. plugin may correct 'code_ea' (e.g. for thumb mode refs, we clear the last bit) 
          
@param to: (::ea_t)
@param may_define: (bool)
@param code_ea: (::ea_t *)
@retval <0: failed dref analysis, >0 done dref analysis
@retval 0: not implemented or continue"""
        return _ida_idp.IDP_Hooks_ev_coagulate_dref(self, _from, to,
            may_define, code_ea)

    def ev_may_show_sreg(self, current_ea: ida_idaapi.ea_t) ->int:
        """The kernel wants to display the segment registers in the messages window. 
          
@param current_ea: (::ea_t)
@retval <0: if the kernel should not show the segment registers. (assuming that the module has done it)
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_may_show_sreg(self, current_ea)

    def ev_auto_queue_empty(self, type: 'atype_t') ->int:
        """One analysis queue is empty. 
          
@param type: (atype_t)
@retval void: see also idb_event::auto_empty_finally"""
        return _ida_idp.IDP_Hooks_ev_auto_queue_empty(self, type)

    def ev_validate_flirt_func(self, start_ea: ida_idaapi.ea_t, funcname: str
        ) ->int:
        """Flirt has recognized a library function. This callback can be used by a plugin or proc module to intercept it and validate such a function. 
          
@param start_ea: (::ea_t)
@param funcname: (const char *)
@retval -1: do not create a function,
@retval 0: function is validated"""
        return _ida_idp.IDP_Hooks_ev_validate_flirt_func(self, start_ea,
            funcname)

    def ev_adjust_libfunc_ea(self, sig: 'idasgn_t const *', libfun:
        'libfunc_t const *', ea: 'ea_t *') ->int:
        """Called when a signature module has been matched against bytes in the database. This is used to compute the offset at which a particular module's libfunc should be applied. 
          
@param sig: (const idasgn_t *)
@param libfun: (const libfunc_t *)
@param ea: (::ea_t *)
@retval 1: the ea_t pointed to by the third argument was modified.
@retval <=0: not modified. use default algorithm."""
        return _ida_idp.IDP_Hooks_ev_adjust_libfunc_ea(self, sig, libfun, ea)

    def ev_assemble(self, ea: ida_idaapi.ea_t, cs: ida_idaapi.ea_t, ip:
        ida_idaapi.ea_t, use32: bool, line: str) ->'PyObject *':
        """Assemble an instruction. (display a warning if an error is found). 
          
@param ea: (::ea_t) linear address of instruction
@param cs: (::ea_t) cs of instruction
@param ip: (::ea_t) ip of instruction
@param use32: (bool) is 32bit segment?
@param line: (const char *) line to assemble
@returns size of the instruction in bytes"""
        return _ida_idp.IDP_Hooks_ev_assemble(self, ea, cs, ip, use32, line)

    def ev_extract_address(self, out_ea: 'ea_t *', screen_ea:
        ida_idaapi.ea_t, string: str, position: 'size_t') ->int:
        """Extract address from a string. 
          
@param out_ea: (ea_t *), out
@param screen_ea: (ea_t)
@param string: (const char *)
@param position: (size_t)
@retval 1: ok
@retval 0: kernel should use the standard algorithm
@retval -1: error"""
        return _ida_idp.IDP_Hooks_ev_extract_address(self, out_ea,
            screen_ea, string, position)

    def ev_realcvt(self, m: 'void *', e: 'fpvalue_t *', swt: 'uint16') ->int:
        """Floating point -> IEEE conversion 
          
@param m: (void *) ptr to processor-specific floating point value
@param e: (fpvalue_t *) IDA representation of a floating point value
@param swt: (uint16) operation (see realcvt() in ieee.h)
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_realcvt(self, m, e, swt)

    def ev_gen_asm_or_lst(self, starting: bool, fp: 'FILE *', is_asm: bool,
        flags: int, outline: 'html_line_cb_t **') ->int:
        """Callback: generating asm or lst file. The kernel calls this callback twice, at the beginning and at the end of listing generation. The processor module can intercept this event and adjust its output 
          
@param starting: (bool) beginning listing generation
@param fp: (FILE *) output file
@param is_asm: (bool) true:assembler, false:listing
@param flags: (int) flags passed to gen_file()
@param outline: (html_line_cb_t **) ptr to ptr to outline callback. if this callback is defined for this code, it will be used by the kernel to output the generated lines
@retval void: """
        return _ida_idp.IDP_Hooks_ev_gen_asm_or_lst(self, starting, fp,
            is_asm, flags, outline)

    def ev_gen_map_file(self, nlines: 'int *', fp: 'FILE *') ->int:
        """Generate map file. If not implemented the kernel itself will create the map file. 
          
@param nlines: (int *) number of lines in map file (-1 means write error)
@param fp: (FILE *) output file
@retval 0: not implemented
@retval 1: ok
@retval -1: write error"""
        return _ida_idp.IDP_Hooks_ev_gen_map_file(self, nlines, fp)

    def ev_create_flat_group(self, image_base: ida_idaapi.ea_t, bitness:
        int, dataseg_sel: 'sel_t') ->int:
        """Create special segment representing the flat group. 
          
@param image_base: (::ea_t)
@param bitness: (int)
@param dataseg_sel: (::sel_t) return value is ignored"""
        return _ida_idp.IDP_Hooks_ev_create_flat_group(self, image_base,
            bitness, dataseg_sel)

    def ev_getreg(self, regval: 'uval_t *', regnum: int) ->int:
        """IBM PC only internal request, should never be used for other purpose Get register value by internal index 
          
@param regval: (uval_t *), out
@param regnum: (int)
@retval 1: ok
@retval 0: not implemented
@retval -1: failed (undefined value or bad regnum)"""
        return _ida_idp.IDP_Hooks_ev_getreg(self, regval, regnum)

    def ev_analyze_prolog(self, ea: ida_idaapi.ea_t) ->int:
        """Analyzes function prolog, epilog, and updates purge, and function attributes 
          
@param ea: (::ea_t) start of function
@retval 1: ok
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_analyze_prolog(self, ea)

    def ev_calc_spdelta(self, spdelta: 'sval_t *', insn: 'insn_t const *'
        ) ->int:
        """Calculate amount of change to sp for the given insn. This event is required to decompile code snippets. 
          
@param spdelta: (sval_t *)
@param insn: (const insn_t *)
@retval 1: ok
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_calc_spdelta(self, spdelta, insn)

    def ev_calcrel(self) ->int:
        """Reserved.
"""
        return _ida_idp.IDP_Hooks_ev_calcrel(self)

    def ev_find_reg_value(self, pinsn: 'insn_t const *', reg: int
        ) ->'PyObject *':
        """Find register value via a register tracker. The returned value in 'out' is valid before executing the instruction. 
          
@param pinsn: (const insn_t *) instruction
@param reg: (int) register index
@retval 1: if implemented, and value was found
@retval 0: not implemented, -1 decoding failed, or no value found"""
        return _ida_idp.IDP_Hooks_ev_find_reg_value(self, pinsn, reg)

    def ev_find_op_value(self, pinsn: 'insn_t const *', opn: int
        ) ->'PyObject *':
        """Find operand value via a register tracker. The returned value in 'out' is valid before executing the instruction. 
          
@param pinsn: (const insn_t *) instruction
@param opn: (int) operand index
@retval 1: if implemented, and value was found
@retval 0: not implemented, -1 decoding failed, or no value found"""
        return _ida_idp.IDP_Hooks_ev_find_op_value(self, pinsn, opn)

    def ev_replaying_undo(self, action_name: str, vec:
        'undo_records_t const *', is_undo: bool) ->int:
        """Replaying an undo/redo buffer 
          
@param action_name: (const char *) action that we perform undo/redo for. may be nullptr for intermediary buffers.
@param vec: (const undo_records_t *)
@param is_undo: (bool) true if performing undo, false if performing redo This event may be generated multiple times per undo/redo"""
        return _ida_idp.IDP_Hooks_ev_replaying_undo(self, action_name, vec,
            is_undo)

    def ev_ending_undo(self, action_name: str, is_undo: bool) ->int:
        """Ended undoing/redoing an action 
          
@param action_name: (const char *) action that we finished undoing/redoing. is not nullptr.
@param is_undo: (bool) true if performing undo, false if performing redo"""
        return _ida_idp.IDP_Hooks_ev_ending_undo(self, action_name, is_undo)

    def ev_set_code16_mode(self, ea: ida_idaapi.ea_t, code16: bool) ->int:
        """Some processors have ISA 16-bit mode e.g. ARM Thumb mode, PPC VLE, MIPS16 Set ISA 16-bit mode 
          
@param ea: (ea_t) address to set new ISA mode
@param code16: (bool) true for 16-bit mode, false for 32-bit mode"""
        return _ida_idp.IDP_Hooks_ev_set_code16_mode(self, ea, code16)

    def ev_get_code16_mode(self, ea: ida_idaapi.ea_t) ->int:
        """Get ISA 16-bit mode 
          
@param ea: (ea_t) address to get the ISA mode
@retval 1: 16-bit mode
@retval 0: not implemented or 32-bit mode"""
        return _ida_idp.IDP_Hooks_ev_get_code16_mode(self, ea)

    def ev_get_procmod(self) ->int:
        """Get pointer to the processor module object. All processor modules must implement this. The pointer is returned as size_t. 
          """
        return _ida_idp.IDP_Hooks_ev_get_procmod(self)

    def ev_asm_installed(self, asmnum: int) ->int:
        """After setting a new assembler 
          
@param asmnum: (int) See also ev_newasm"""
        return _ida_idp.IDP_Hooks_ev_asm_installed(self, asmnum)

    def ev_get_reg_accesses(self, accvec: 'reg_accesses_t', insn:
        'insn_t const *', flags: int) ->int:
        """Get info about the registers that are used/changed by an instruction. 
          
@param accvec: (reg_accesses_t*) out: info about accessed registers
@param insn: (const insn_t *) instruction in question
@param flags: (int) reserved, must be 0
@retval -1: if accvec is nullptr
@retval 1: found the requested access (and filled accvec)
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_get_reg_accesses(self, accvec, insn, flags
            )

    def ev_is_control_flow_guard(self, p_reg: 'int *', insn: 'insn_t const *'
        ) ->int:
        """Detect if an instruction is a "thunk call" to a flow guard function (equivalent to call reg/return/nop) 
          
@param p_reg: (int *) indirect register number, may be -1
@param insn: (const insn_t *) call/jump instruction
@retval -1: no thunk detected
@retval 1: indirect call
@retval 2: security check routine call (NOP)
@retval 3: return thunk
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_is_control_flow_guard(self, p_reg, insn)

    def ev_create_merge_handlers(self, md: 'merge_data_t *') ->int:
        """Create merge handlers, if needed 
          
@param md: (merge_data_t *) This event is generated immediately after opening idbs.
@returns must be 0"""
        return _ida_idp.IDP_Hooks_ev_create_merge_handlers(self, md)

    def ev_privrange_changed(self, old_privrange: 'range_t', delta: 'adiff_t'
        ) ->int:
        """Privrange interval has been moved to a new location. Most common actions to be done by module in this case: fix indices of netnodes used by module 
          
@param old_privrange: (const range_t *) - old privrange interval
@param delta: (::adiff_t)
@retval 0: Ok
@retval -1: error (and message in errbuf)"""
        return _ida_idp.IDP_Hooks_ev_privrange_changed(self, old_privrange,
            delta)

    def ev_cvt64_supval(self, node: 'nodeidx_t', tag: 'uchar', idx:
        'nodeidx_t', data: 'uchar const *') ->int:
        """perform 32-64 conversion for a netnode array element 
          
@param node: (::nodeidx_t)
@param tag: (uchar)
@param idx: (::nodeidx_t)
@param data: (const uchar *)
@retval 0: nothing was done
@retval 1: converted successfully
@retval -1: error (and message in errbuf)"""
        return _ida_idp.IDP_Hooks_ev_cvt64_supval(self, node, tag, idx, data)

    def ev_cvt64_hashval(self, node: 'nodeidx_t', tag: 'uchar', name: str,
        data: 'uchar const *') ->int:
        """perform 32-64 conversion for a hash value 
          
@param node: (::nodeidx_t)
@param tag: (uchar)
@param name: (const ::char *)
@param data: (const uchar *)
@retval 0: nothing was done
@retval 1: converted successfully
@retval -1: error (and message in errbuf)"""
        return _ida_idp.IDP_Hooks_ev_cvt64_hashval(self, node, tag, name, data)

    def ev_gen_stkvar_def(self, outctx: 'outctx_t *', stkvar: 'udm_t', v:
        int, tid: 'tid_t') ->int:
        """Generate stack variable definition line Default line is varname = type ptr value, where 'type' is one of byte,word,dword,qword,tbyte 
          
@param outctx: (outctx_t *)
@param stkvar: (const udm_t *)
@param v: (sval_t)
@param tid: (tid_t) stkvar TID
@retval 1: ok
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_gen_stkvar_def(self, outctx, stkvar, v,
            tid)

    def ev_next_exec_insn(self, target: 'ea_t *', ea: ida_idaapi.ea_t, tid:
        int, getreg: 'processor_t::regval_getter_t *', regvalues: 'regval_t'
        ) ->int:
        """Get next address to be executed This function must return the next address to be executed. If the instruction following the current one is executed, then it must return BADADDR Usually the instructions to consider are: jumps, branches, calls, returns. This function is essential if the 'single step' is not supported in hardware. 
          
@param target: (::ea_t *), out: pointer to the answer
@param ea: (::ea_t) instruction address
@param tid: (int) current therad id
@param getreg: (::processor_t::regval_getter_t *) function to get register values
@param regvalues: (const regval_t *) register values array
@retval 0: unimplemented
@retval 1: implemented"""
        return _ida_idp.IDP_Hooks_ev_next_exec_insn(self, target, ea, tid,
            getreg, regvalues)

    def ev_calc_step_over(self, target: 'ea_t *', ip: ida_idaapi.ea_t) ->int:
        """Calculate the address of the instruction which will be executed after "step over". The kernel will put a breakpoint there. If the step over is equal to step into or we cannot calculate the address, return BADADDR. 
          
@param target: (::ea_t *) pointer to the answer
@param ip: (::ea_t) instruction address
@retval 0: unimplemented
@retval 1: implemented"""
        return _ida_idp.IDP_Hooks_ev_calc_step_over(self, target, ip)

    def ev_calc_next_eas(self, res: 'eavec_t *', insn: 'insn_t const *',
        over: bool) ->int:
        """Calculate list of addresses the instruction in 'insn' may pass control to. This callback is required for source level debugging. 
          
@param res: (eavec_t *), out: array for the results.
@param insn: (const insn_t*) the instruction
@param over: (bool) calculate for step over (ignore call targets)
@retval <0: incalculable (indirect jumps, for example)
@retval >=0: number of addresses of called functions in the array. They must be put at the beginning of the array (0 if over=true)"""
        return _ida_idp.IDP_Hooks_ev_calc_next_eas(self, res, insn, over)

    def ev_get_macro_insn_head(self, head: 'ea_t *', ip: ida_idaapi.ea_t
        ) ->int:
        """Calculate the start of a macro instruction. This notification is called if IP points to the middle of an instruction 
          
@param head: (::ea_t *), out: answer, BADADDR means normal instruction
@param ip: (::ea_t) instruction address
@retval 0: unimplemented
@retval 1: implemented"""
        return _ida_idp.IDP_Hooks_ev_get_macro_insn_head(self, head, ip)

    def ev_get_dbr_opnum(self, opnum: 'int *', insn: 'insn_t const *') ->int:
        """Get the number of the operand to be displayed in the debugger reference view (text mode). 
          
@param opnum: (int *) operand number (out, -1 means no such operand)
@param insn: (const insn_t*) the instruction
@retval 0: unimplemented
@retval 1: implemented"""
        return _ida_idp.IDP_Hooks_ev_get_dbr_opnum(self, opnum, insn)

    def ev_insn_reads_tbit(self, insn: 'insn_t const *', getreg:
        'processor_t::regval_getter_t *', regvalues: 'regval_t') ->int:
        """Check if insn will read the TF bit. 
          
@param insn: (const insn_t*) the instruction
@param getreg: (::processor_t::regval_getter_t *) function to get register values
@param regvalues: (const regval_t *) register values array
@retval 2: yes, will generate 'step' exception
@retval 1: yes, will store the TF bit in memory
@retval 0: no"""
        return _ida_idp.IDP_Hooks_ev_insn_reads_tbit(self, insn, getreg,
            regvalues)

    def ev_clean_tbit(self, ea: ida_idaapi.ea_t, getreg:
        'processor_t::regval_getter_t *', regvalues: 'regval_t') ->int:
        """Clear the TF bit after an insn like pushf stored it in memory. 
          
@param ea: (::ea_t) instruction address
@param getreg: (::processor_t::regval_getter_t *) function to get register values
@param regvalues: (const regval_t *) register values array
@retval 1: ok
@retval 0: failed"""
        return _ida_idp.IDP_Hooks_ev_clean_tbit(self, ea, getreg, regvalues)

    def ev_get_reg_info(self, main_regname: 'char const **', bitrange:
        'bitrange_t', regname: str) ->int:
        """Get register information by its name. example: "ah" returns:
* main_regname="eax"
* bitrange_t = { offset==8, nbits==8 }


This callback may be unimplemented if the register names are all present in processor_t::reg_names and they all have the same size 
          
@param main_regname: (const char **), out
@param bitrange: (bitrange_t *), out: position and size of the value within 'main_regname' (empty bitrange == whole register)
@param regname: (const char *)
@retval 1: ok
@retval -1: failed (not found)
@retval 0: unimplemented"""
        return _ida_idp.IDP_Hooks_ev_get_reg_info(self, main_regname,
            bitrange, regname)

    def ev_update_call_stack(self, stack: 'call_stack_t', tid: int, getreg:
        'processor_t::regval_getter_t *', regvalues: 'regval_t') ->int:
        """Calculate the call stack trace for the given thread. This callback is invoked when the process is suspended and should fill the 'trace' object with the information about the current call stack. Note that this callback is NOT invoked if the current debugger backend implements stack tracing via debugger_t::event_t::ev_update_call_stack. The debugger-specific algorithm takes priority. Implementing this callback in the processor module is useful when multiple debugging platforms follow similar patterns, and thus the same processor-specific algorithm can be used for different platforms. 
          
@param stack: (call_stack_t *) result
@param tid: (int) thread id
@param getreg: (::processor_t::regval_getter_t *) function to get register values
@param regvalues: (const regval_t *) register values array
@retval 1: ok
@retval -1: failed
@retval 0: unimplemented"""
        return _ida_idp.IDP_Hooks_ev_update_call_stack(self, stack, tid,
            getreg, regvalues)

    def ev_setup_til(self) ->int:
        """Setup default type libraries. (called after loading a new file into the database). The processor module may load tils, setup memory model and perform other actions required to set up the type system. This is an optional callback. 
          
@retval void: """
        return _ida_idp.IDP_Hooks_ev_setup_til(self)

    def ev_get_abi_info(self, comp: 'comp_t') ->int:
        """Get all possible ABI names and optional extensions for given compiler abiname/option is a string entirely consisting of letters, digits and underscore 
          
@param comp: (comp_t) - compiler ID
@retval 0: not implemented
@retval 1: ok"""
        return _ida_idp.IDP_Hooks_ev_get_abi_info(self, comp)

    def ev_max_ptr_size(self) ->int:
        """Get maximal size of a pointer in bytes. 
          
@returns max possible size of a pointer"""
        return _ida_idp.IDP_Hooks_ev_max_ptr_size(self)

    def ev_get_default_enum_size(self) ->int:
        """Get default enum size. Not generated anymore. inf_get_cc_size_e() is used instead 
          """
        return _ida_idp.IDP_Hooks_ev_get_default_enum_size(self)

    def ev_get_cc_regs(self, regs: 'callregs_t', cc: 'cm_t') ->int:
        """Get register allocation convention for given calling convention 
          
@param regs: (callregs_t *), out
@param cc: (cm_t)
@retval 1: 
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_get_cc_regs(self, regs, cc)

    def ev_get_simd_types(self, out: 'simd_info_vec_t *', simd_attrs:
        'simd_info_t', argloc: 'argloc_t', create_tifs: bool) ->int:
        """Get SIMD-related types according to given attributes ant/or argument location 
          
@param out: (::simd_info_vec_t *)
@param simd_attrs: (const simd_info_t *), may be nullptr
@param argloc: (const argloc_t *), may be nullptr
@param create_tifs: (bool) return valid tinfo_t objects, create if neccessary
@retval number: of found types
@retval -1: error If name==nullptr, initialize all SIMD types"""
        return _ida_idp.IDP_Hooks_ev_get_simd_types(self, out, simd_attrs,
            argloc, create_tifs)

    def ev_calc_cdecl_purged_bytes(self, ea: ida_idaapi.ea_t) ->int:
        """Calculate number of purged bytes after call. 
          
@param ea: (::ea_t) address of the call instruction
@returns number of purged bytes (usually add sp, N)"""
        return _ida_idp.IDP_Hooks_ev_calc_cdecl_purged_bytes(self, ea)

    def ev_calc_purged_bytes(self, p_purged_bytes: 'int *', fti:
        'func_type_data_t') ->int:
        """Calculate number of purged bytes by the given function type. 
          
@param p_purged_bytes: (int *) ptr to output
@param fti: (const func_type_data_t *) func type details
@retval 1: 
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_calc_purged_bytes(self, p_purged_bytes,
            fti)

    def ev_calc_retloc(self, retloc: 'argloc_t', rettype: 'tinfo_t', cc: 'cm_t'
        ) ->int:
        """Calculate return value location. 
          
@param retloc: (argloc_t *)
@param rettype: (const tinfo_t *)
@param cc: (cm_t)
@retval 0: not implemented
@retval 1: ok,
@retval -1: error"""
        return _ida_idp.IDP_Hooks_ev_calc_retloc(self, retloc, rettype, cc)

    def ev_calc_arglocs(self, fti: 'func_type_data_t') ->int:
        """Calculate function argument locations. This callback should fill retloc, all arglocs, and stkargs. This callback is never called for CM_CC_SPECIAL functions. 
          
@param fti: (func_type_data_t *) points to the func type info
@retval 0: not implemented
@retval 1: ok
@retval -1: error"""
        return _ida_idp.IDP_Hooks_ev_calc_arglocs(self, fti)

    def ev_calc_varglocs(self, ftd: 'func_type_data_t', aux_regs:
        'regobjs_t', aux_stkargs: 'relobj_t', nfixed: int) ->int:
        """Calculate locations of the arguments that correspond to '...'. 
          
@param ftd: (func_type_data_t *), inout: info about all arguments (including varargs)
@param aux_regs: (regobjs_t *) buffer for hidden register arguments, may be nullptr
@param aux_stkargs: (relobj_t *) buffer for hidden stack arguments, may be nullptr
@param nfixed: (int) number of fixed arguments
@retval 0: not implemented
@retval 1: ok
@retval -1: error On some platforms variadic calls require passing additional information: for example, number of floating variadic arguments must be passed in rax on gcc-x64. The locations and values that constitute this additional information are returned in the buffers pointed by aux_regs and aux_stkargs"""
        return _ida_idp.IDP_Hooks_ev_calc_varglocs(self, ftd, aux_regs,
            aux_stkargs, nfixed)

    def ev_adjust_argloc(self, argloc: 'argloc_t', optional_type: 'tinfo_t',
        size: int) ->int:
        """Adjust argloc according to its type/size and platform endianess 
          
@param argloc: (argloc_t *), inout
@param size: (int) 'size' makes no sense if type != nullptr (type->get_size() should be used instead)
@retval 0: not implemented
@retval 1: ok
@retval -1: error"""
        return _ida_idp.IDP_Hooks_ev_adjust_argloc(self, argloc,
            optional_type, size)

    def ev_lower_func_type(self, argnums: 'intvec_t *', fti: 'func_type_data_t'
        ) ->int:
        """Get function arguments which should be converted to pointers when lowering function prototype. The processor module can also modify 'fti' in order to make non-standard conversion of some arguments. 
          
@param argnums: (intvec_t *), out - numbers of arguments to be converted to pointers in acsending order
@param fti: (func_type_data_t *), inout func type details
@retval 0: not implemented
@retval 1: argnums was filled
@retval 2: argnums was filled and made substantial changes to fti argnums[0] can contain a special negative value indicating that the return value should be passed as a hidden 'retstr' argument: -1 this argument is passed as the first one and the function returns a pointer to the argument, -2 this argument is passed as the last one and the function returns a pointer to the argument, -3 this argument is passed as the first one and the function returns 'void'."""
        return _ida_idp.IDP_Hooks_ev_lower_func_type(self, argnums, fti)

    def ev_equal_reglocs(self, a1: 'argloc_t', a2: 'argloc_t') ->int:
        """Are 2 register arglocs the same?. We need this callback for the pc module. 
          
@param a1: (argloc_t *)
@param a2: (argloc_t *)
@retval 1: yes
@retval -1: no
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_equal_reglocs(self, a1, a2)

    def ev_use_stkarg_type(self, ea: ida_idaapi.ea_t, arg: 'funcarg_t') ->int:
        """Use information about a stack argument. 
          
@param ea: (::ea_t) address of the push instruction which pushes the function argument into the stack
@param arg: (const funcarg_t *) argument info
@retval 1: ok
@retval <=0: failed, the kernel will create a comment with the argument name or type for the instruction"""
        return _ida_idp.IDP_Hooks_ev_use_stkarg_type(self, ea, arg)

    def ev_use_regarg_type(self, ea: ida_idaapi.ea_t, rargs:
        'funcargvec_t const *') ->'PyObject *':
        """Use information about register argument. 
          
@param ea: (::ea_t) address of the instruction
@param rargs: (const funcargvec_t *) vector of register arguments (including regs extracted from scattered arguments)
@retval 1: 
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_use_regarg_type(self, ea, rargs)

    def ev_use_arg_types(self, ea: ida_idaapi.ea_t, fti: 'func_type_data_t',
        rargs: 'funcargvec_t *') ->int:
        """Use information about callee arguments. 
          
@param ea: (::ea_t) address of the call instruction
@param fti: (func_type_data_t *) info about function type
@param rargs: (funcargvec_t *) array of register arguments
@retval 1: (and removes handled arguments from fti and rargs)
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_use_arg_types(self, ea, fti, rargs)

    def ev_arg_addrs_ready(self, caller: ida_idaapi.ea_t, n: int, tif:
        'tinfo_t', addrs: 'ea_t *') ->int:
        """Argument address info is ready. 
          
@param caller: (::ea_t)
@param n: (int) number of formal arguments
@param tif: (tinfo_t *) call prototype
@param addrs: (::ea_t *) argument intilization addresses
@retval <0: do not save into idb; other values mean "ok to save\""""
        return _ida_idp.IDP_Hooks_ev_arg_addrs_ready(self, caller, n, tif,
            addrs)

    def ev_decorate_name(self, name: str, mangle: bool, cc: int,
        optional_type: 'tinfo_t') ->'PyObject *':
        """Decorate/undecorate a C symbol name. 
          
@param name: (const char *) name of symbol
@param mangle: (bool) true-mangle, false-unmangle
@param cc: (cm_t) calling convention
@retval 1: if success
@retval 0: not implemented or failed"""
        return _ida_idp.IDP_Hooks_ev_decorate_name(self, name, mangle, cc,
            optional_type)

    def ev_arch_changed(self) ->int:
        """The loader is done parsing arch-related information, which the processor module might want to use to finish its initialization. 
          
@retval 1: if success
@retval 0: not implemented or failed"""
        return _ida_idp.IDP_Hooks_ev_arch_changed(self)

    def ev_get_stkarg_area_info(self, out: 'stkarg_area_info_t', cc: 'cm_t'
        ) ->int:
        """Get some metrics of the stack argument area. 
          
@param out: (stkarg_area_info_t *) ptr to stkarg_area_info_t
@param cc: (cm_t) calling convention
@retval 1: if success
@retval 0: not implemented"""
        return _ida_idp.IDP_Hooks_ev_get_stkarg_area_info(self, out, cc)

    def ev_last_cb_before_loader(self) ->int:
        return _ida_idp.IDP_Hooks_ev_last_cb_before_loader(self)

    def ev_loader(self) ->int:
        """This code and higher ones are reserved for the loaders. The arguments and the return values are defined by the loaders 
          """
        return _ida_idp.IDP_Hooks_ev_loader(self)
    __swig_destroy__ = _ida_idp.delete_IDP_Hooks

    def __disown__(self):
        self.this.disown()
        _ida_idp.disown_IDP_Hooks(self)
        return weakref.proxy(self)


_ida_idp.IDP_Hooks_swigregister(IDP_Hooks)


def get_idp_notifier_addr(arg1: 'PyObject *') ->'PyObject *':
    return _ida_idp.get_idp_notifier_addr(arg1)


def get_idp_notifier_ud_addr(hooks: 'IDP_Hooks') ->'PyObject *':
    return _ida_idp.get_idp_notifier_ud_addr(hooks)


def delay_slot_insn(ea: 'ea_t *', bexec: 'bool *', fexec: 'bool *') ->bool:
    return _ida_idp.delay_slot_insn(ea, bexec, fexec)


def get_reg_info(regname: str, bitrange: 'bitrange_t') ->str:
    return _ida_idp.get_reg_info(regname, bitrange)


def sizeof_ldbl() ->'size_t':
    return _ida_idp.sizeof_ldbl()


REAL_ERROR_FORMAT = -1
REAL_ERROR_RANGE = -2
REAL_ERROR_BADDATA = -3
IDPOPT_STR = 1
IDPOPT_NUM = 2
IDPOPT_BIT = 3
IDPOPT_FLT = 4
IDPOPT_I64 = 5
IDPOPT_OK = 0
IDPOPT_BADKEY = 1
IDPOPT_BADTYPE = 2
IDPOPT_BADVALUE = 3
import ida_pro
import ida_funcs
import ida_segment
import ida_ua


class processor_t(IDP_Hooks):
    __idc_cvt_id__ = ida_idaapi.PY_ICID_OPAQUE
    """
    Base class for all processor module scripts

    A processor_t instance is both an ida_idp.IDP_Hooks, and an
    ida_idp.IDB_Hooks at the same time: any method of those two classes
    can be overridden in your processor_t subclass (with the exception of
    'ida_idp.IDP_Hooks.ev_init' (replaced with processor_t.__init__),
    and 'ida_idp.IDP_Hooks.ev_term' (replaced with processor_t.__del__)).
    """

    def __init__(self):
        IDP_Hooks.__init__(self, ida_idaapi.HBF_CALL_WITH_NEW_EXEC)
        self.idb_hooks = _processor_t_Trampoline_IDB_Hooks(self)

    def get_idpdesc(self):
        """
        This function must be present and should return the list of
        short processor names similar to the one in ph.psnames.
        This method can be overridden to return to the kernel a different IDP description.
        """
        return '\x01'.join(map(lambda t: '\x01'.join(t), zip(self.plnames,
            self.psnames)))

    def get_auxpref(self, insn):
        """This function returns insn.auxpref value"""
        return insn.auxpref

    def _get_idp_notifier_addr(self):
        return _ida_idp.get_idp_notifier_addr(self)

    def _get_idp_notifier_ud_addr(self):
        return _ida_idp.get_idp_notifier_ud_addr(self)

    def _get_idb_notifier_addr(self):
        return _ida_idp.get_idb_notifier_addr(self)

    def _get_idb_notifier_ud_addr(self):
        return _ida_idp.get_idb_notifier_ud_addr(self.idb_hooks)

    def _make_forced_value_wrapper(self, val, meth=None):

        def f(*args):
            if meth:
                meth(*args)
            return val
        return f

    def _make_int_returning_wrapper(self, meth, intval=0):

        def f(*args):
            val = meth(*args)
            if val is None:
                val = intval
            return val
        return f

    def _get_notify(self, what, unimp_val=0, imp_forced_val=None,
        add_prefix=True, mandatory_impl=None):
        """
        This helper is used to implement backward-compatibility
        of pre IDA 7.3 processor_t interfaces.
        """
        if add_prefix:
            what = 'notify_%s' % what
        meth = getattr(self, what, None)
        if meth is None:
            if mandatory_impl:
                raise Exception('processor_t.%s() must be implemented' %
                    mandatory_impl)
            meth = self._make_forced_value_wrapper(unimp_val)
        elif imp_forced_val is not None:
            meth = self._make_forced_value_wrapper(imp_forced_val, meth)
        else:
            meth = self._make_int_returning_wrapper(meth)
        return meth

    def ev_newprc(self, *args):
        return self._get_notify('newprc')(*args)

    def ev_newfile(self, *args):
        return self._get_notify('newfile')(*args)

    def ev_oldfile(self, *args):
        return self._get_notify('oldfile')(*args)

    def ev_newbinary(self, *args):
        return self._get_notify('newbinary')(*args)

    def ev_endbinary(self, *args):
        return self._get_notify('endbinary')(*args)

    def ev_set_idp_options(self, keyword, value_type, value, idb_loaded):
        res = self._get_notify('set_idp_options', unimp_val=None)(keyword,
            value_type, value)
        if res is None:
            return 0
        return 1 if res == IDPOPT_OK else -1

    def ev_set_proc_options(self, *args):
        return self._get_notify('set_proc_options')(*args)

    def ev_ana_insn(self, *args):
        rc = self._get_notify('ana', mandatory_impl='ev_ana_insn')(*args)
        return rc > 0

    def ev_emu_insn(self, *args):
        rc = self._get_notify('emu', mandatory_impl='ev_emu_insn')(*args)
        return rc > 0

    def ev_out_header(self, *args):
        return self._get_notify('out_header', imp_forced_val=1)(*args)

    def ev_out_footer(self, *args):
        return self._get_notify('out_footer', imp_forced_val=1)(*args)

    def ev_out_segstart(self, ctx, s):
        return self._get_notify('out_segstart', imp_forced_val=1)(ctx, s.
            start_ea)

    def ev_out_segend(self, ctx, s):
        return self._get_notify('out_segend', imp_forced_val=1)(ctx, s.end_ea)

    def ev_out_assumes(self, *args):
        return self._get_notify('out_assumes', imp_forced_val=1)(*args)

    def ev_out_insn(self, *args):
        return self._get_notify('out_insn', mandatory_impl='ev_out_insn',
            imp_forced_val=True)(*args)

    def ev_out_mnem(self, *args):
        return self._get_notify('out_mnem', add_prefix=False, imp_forced_val=1
            )(*args)

    def ev_out_operand(self, *args):
        rc = self._get_notify('out_operand', mandatory_impl=
            'ev_out_operand', imp_forced_val=1)(*args)
        return rc > 0

    def ev_out_data(self, *args):
        return self._get_notify('out_data', imp_forced_val=1)(*args)

    def ev_out_label(self, *args):
        return self._get_notify('out_label')(*args)

    def ev_out_special_item(self, *args):
        return self._get_notify('out_special_item')(*args)

    def ev_gen_regvar_def(self, ctx, v):
        return self._get_notify('gen_regvar_def')(ctx, v.canon, v.user, v.cmt)

    def ev_gen_src_file_lnnum(self, *args):
        return self._get_notify('gen_src_file_lnnum')(*args)

    def ev_creating_segm(self, s):
        sname = ida_segment.get_visible_segm_name(s)
        sclass = ida_segment.get_segm_class(s)
        return self._get_notify('creating_segm')(s.start_ea, sname, sclass)

    def ev_moving_segm(self, s, to_ea, flags):
        sname = ida_segment.get_visible_segm_name(s)
        sclass = ida_segment.get_segm_class(s)
        return self._get_notify('moving_segm')(s.start_ea, sname, sclass,
            to_ea, flags)

    def ev_coagulate(self, *args):
        return self._get_notify('coagulate')(*args)

    def ev_undefine(self, *args):
        return self._get_notify('undefine')(*args)

    def ev_treat_hindering_item(self, *args):
        return self._get_notify('treat_hindering_item')(*args)

    def ev_rename(self, *args):
        return self._get_notify('rename')(*args)

    def ev_is_far_jump(self, *args):
        rc = self._get_notify('is_far_jump', unimp_val=False)(*args)
        return 1 if rc else -1

    def ev_is_sane_insn(self, *args):
        return self._get_notify('is_sane_insn')(*args)

    def ev_is_call_insn(self, *args):
        return self._get_notify('is_call_insn')(*args)

    def ev_is_ret_insn(self, *args):
        return self._get_notify('is_ret_insn')(*args)

    def ev_may_be_func(self, *args):
        return self._get_notify('may_be_func')(*args)

    def ev_is_basic_block_end(self, *args):
        return self._get_notify('is_basic_block_end')(*args)

    def ev_is_indirect_jump(self, *args):
        return self._get_notify('is_indirect_jump')(*args)

    def ev_is_insn_table_jump(self, *args):
        return self._get_notify('is_insn_table_jump')(*args)

    def ev_is_switch(self, *args):
        rc = self._get_notify('is_switch')(*args)
        return 1 if rc else 0

    def ev_create_switch_xrefs(self, *args):
        return self._get_notify('create_switch_xrefs', imp_forced_val=1)(*args)

    def ev_is_align_insn(self, *args):
        return self._get_notify('is_align_insn')(*args)

    def ev_is_alloca_probe(self, *args):
        return self._get_notify('is_alloca_probe')(*args)

    def ev_is_sp_based(self, mode, insn, op):
        rc = self._get_notify('is_sp_based', unimp_val=None)(insn, op)
        if type(rc) == int:
            ida_pro.int_pointer.frompointer(mode).assign(rc)
            return 1
        return 0

    def ev_can_have_type(self, *args):
        rc = self._get_notify('can_have_type')(*args)
        if rc is True:
            return 1
        elif rc is False:
            return -1
        else:
            return 0

    def ev_cmp_operands(self, *args):
        rc = self._get_notify('cmp_operands')(*args)
        if rc is True:
            return 1
        elif rc is False:
            return -1
        else:
            return 0

    def ev_get_operand_string(self, buf, insn, opnum):
        rc = self._get_notify('get_operand_string')(insn, opnum)
        if rc:
            return 1
        return 0

    def ev_str2reg(self, *args):
        rc = self._get_notify('notify_str2reg', unimp_val=-1)(*args)
        return 0 if rc < 0 else rc + 1

    def ev_get_autocmt(self, *args):
        return self._get_notify('get_autocmt')(*args)

    def ev_func_bounds(self, _possible_return_code, pfn, max_func_end_ea):
        possible_return_code = ida_pro.int_pointer.frompointer(
            _possible_return_code)
        rc = self._get_notify('func_bounds', unimp_val=None)(
            possible_return_code.value(), pfn.start_ea, max_func_end_ea)
        if type(rc) == int:
            possible_return_code.assign(rc)
        return 0

    def ev_verify_sp(self, pfn):
        return self._get_notify('verify_sp')(pfn.start_ea)

    def ev_verify_noreturn(self, pfn):
        return self._get_notify('verify_noreturn')(pfn.start_ea)

    def ev_create_func_frame(self, pfn):
        rc = self._get_notify('create_func_frame', imp_forced_val=1)(pfn.
            start_ea)
        if rc is True:
            return 1
        elif rc is False:
            return -1
        else:
            return rc

    def ev_get_frame_retsize(self, frsize, pfn):
        rc = self._get_notify('get_frame_retsize', unimp_val=None)(pfn.start_ea
            )
        if type(rc) == int:
            ida_pro.int_pointer.frompointer(frsize).assign(rc)
            return 1
        return 0

    def ev_coagulate_dref(self, from_ea, to_ea, may_define, _code_ea):
        code_ea = ida_pro.ea_pointer.frompointer(_code_ea)
        rc = self._get_notify('coagulate_dref')(from_ea, to_ea, may_define,
            code_ea.value())
        if rc == -1:
            return -1
        if rc != 0:
            code_ea.assign(rc)
        return 0

    def ev_may_show_sreg(self, *args):
        return self._get_notify('may_show_sreg')(*args)

    def ev_auto_queue_empty(self, *args):
        return self._get_notify('auto_queue_empty')(*args)

    def ev_validate_flirt_func(self, *args):
        return self._get_notify('validate_flirt_func')(*args)

    def ev_assemble(self, *args):
        return self._get_notify('assemble')(*args)

    def ev_gen_map_file(self, nlines, fp):
        import ida_fpro
        qfile = ida_fpro.qfile_t_from_fp(fp)
        rc = self._get_notify('gen_map_file')(qfile)
        if rc > 0:
            ida_pro.int_pointer.frompointer(nlines).assign(rc)
            return 1
        else:
            return 0

    def ev_calc_step_over(self, target, ip):
        rc = self._get_notify('calc_step_over', unimp_val=None)(ip)
        if rc is not None and rc != ida_idaapi.BADADDR:
            ida_pro.ea_pointer.frompointer(target).assign(rc)
            return 1
        return 0

    def closebase(self, *args):
        self._get_notify('closebase')(*args)

    def savebase(self, *args):
        self._get_notify('savebase')(*args)

    def auto_empty(self, *args):
        self._get_notify('auto_empty')(*args)

    def auto_empty_finally(self, *args):
        self._get_notify('auto_empty_finally')(*args)

    def determined_main(self, *args):
        self._get_notify('determined_main')(*args)

    def idasgn_loaded(self, *args):
        self._get_notify('load_idasgn')(*args)

    def kernel_config_loaded(self, *args):
        self._get_notify('kernel_config_loaded')(*args)

    def compiler_changed(self, *args):
        self._get_notify('set_compiler')(*args)

    def segm_moved(self, from_ea, to_ea, size, changed_netmap):
        s = ida_segment.getseg(to_ea)
        sname = ida_segment.get_visible_segm_name(s)
        sclass = ida_segment.get_segm_class(s)
        self._get_notify('move_segm')(from_ea, to_ea, sname, sclass,
            changed_netmap)

    def func_added(self, pfn):
        self._get_notify('add_func')(pfn.start_ea)

    def set_func_start(self, *args):
        self._get_notify('set_func_start')(*args)

    def set_func_end(self, *args):
        self._get_notify('set_func_end')(*args)

    def deleting_func(self, pfn):
        self._get_notify('del_func')(pfn.start_ea)

    def sgr_changed(self, *args):
        self._get_notify('setsgr')(*args)

    def make_code(self, *args):
        self._get_notify('make_code')(*args)

    def make_data(self, *args):
        self._get_notify('make_data')(*args)

    def renamed(self, *args):
        self._get_notify('renamed')(*args)


class __ph(object):
    id = property(lambda self: ph_get_id())
    cnbits = property(lambda self: ph_get_cnbits())
    dnbits = property(lambda self: ph_get_dnbits())
    flag = property(lambda self: ph_get_flag())
    icode_return = property(lambda self: ph_get_icode_return())
    instruc = property(lambda self: ph_get_instruc())
    instruc_end = property(lambda self: ph_get_instruc_end())
    instruc_start = property(lambda self: ph_get_instruc_start())
    reg_code_sreg = property(lambda self: ph_get_reg_code_sreg())
    reg_data_sreg = property(lambda self: ph_get_reg_data_sreg())
    reg_first_sreg = property(lambda self: ph_get_reg_first_sreg())
    reg_last_sreg = property(lambda self: ph_get_reg_last_sreg())
    regnames = property(lambda self: ph_get_regnames())
    segreg_size = property(lambda self: ph_get_segreg_size())
    tbyte_size = property(lambda self: ph_get_tbyte_size())
    version = property(lambda self: ph_get_version())


def str2sreg(name: str):
    """get segment register number from its name or -1"""
    rn = ph_get_regnames()
    for i in range(ph_get_reg_first_sreg(), ph_get_reg_last_sreg() + 1):
        if name.lower() == rn[i].lower():
            return i
    return -1


ph = __ph()


class IDB_Hooks(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, _flags: int=0, _hkcb_flags: int=1):
        if self.__class__ == IDB_Hooks:
            _self = None
        else:
            _self = self
        _ida_idp.IDB_Hooks_swiginit(self, _ida_idp.new_IDB_Hooks(_self,
            _flags, _hkcb_flags))

    def hook(self) ->bool:
        return _ida_idp.IDB_Hooks_hook(self)

    def unhook(self) ->bool:
        return _ida_idp.IDB_Hooks_unhook(self)

    def closebase(self) ->None:
        """The database will be closed now.
"""
        return _ida_idp.IDB_Hooks_closebase(self)

    def savebase(self) ->None:
        """The database is being saved.
"""
        return _ida_idp.IDB_Hooks_savebase(self)

    def upgraded(self, _from: int) ->None:
        """The database has been upgraded and the receiver can upgrade its info as well 
          """
        return _ida_idp.IDB_Hooks_upgraded(self, _from)

    def auto_empty(self) ->None:
        """Info: all analysis queues are empty. This callback is called once when the initial analysis is finished. If the queue is not empty upon the return from this callback, it will be called later again. 
          """
        return _ida_idp.IDB_Hooks_auto_empty(self)

    def auto_empty_finally(self) ->None:
        """Info: all analysis queues are empty definitively. This callback is called only once. 
          """
        return _ida_idp.IDB_Hooks_auto_empty_finally(self)

    def determined_main(self, main: ida_idaapi.ea_t) ->None:
        """The main() function has been determined. 
          
@param main: (::ea_t) address of the main() function"""
        return _ida_idp.IDB_Hooks_determined_main(self, main)

    def extlang_changed(self, kind: int, el: 'extlang_t *', idx: int) ->None:
        """The list of extlangs or the default extlang was changed. 
          
@param kind: (int) 0: extlang installed 1: extlang removed 2: default extlang changed
@param el: (extlang_t *) pointer to the extlang affected
@param idx: (int) extlang index"""
        return _ida_idp.IDB_Hooks_extlang_changed(self, kind, el, idx)

    def idasgn_loaded(self, short_sig_name: str) ->None:
        """FLIRT signature has been loaded for normal processing (not for recognition of startup sequences). 
          
@param short_sig_name: (const char *)"""
        return _ida_idp.IDB_Hooks_idasgn_loaded(self, short_sig_name)

    def kernel_config_loaded(self, pass_number: int) ->None:
        """This event is issued when ida.cfg is parsed. 
          
@param pass_number: (int)"""
        return _ida_idp.IDB_Hooks_kernel_config_loaded(self, pass_number)

    def loader_finished(self, li: 'linput_t *', neflags: 'uint16',
        filetypename: str) ->None:
        """External file loader finished its work. Use this event to augment the existing loader functionality. 
          
@param li: (linput_t *)
@param neflags: (uint16) Load file flags
@param filetypename: (const char *)"""
        return _ida_idp.IDB_Hooks_loader_finished(self, li, neflags,
            filetypename)

    def flow_chart_created(self, fc: 'qflow_chart_t') ->None:
        """Gui has retrieved a function flow chart. Plugins may modify the flow chart in this callback. 
          
@param fc: (qflow_chart_t *)"""
        return _ida_idp.IDB_Hooks_flow_chart_created(self, fc)

    def compiler_changed(self, adjust_inf_fields: bool) ->None:
        """The kernel has changed the compiler information. ( idainfo::cc structure; get_abi_name) 
          
@param adjust_inf_fields: (::bool) may change inf fields?"""
        return _ida_idp.IDB_Hooks_compiler_changed(self, adjust_inf_fields)

    def changing_ti(self, ea: ida_idaapi.ea_t, new_type: 'type_t const *',
        new_fnames: 'p_list const *') ->None:
        """An item typestring (c/c++ prototype) is to be changed. 
          
@param ea: (::ea_t)
@param new_type: (const type_t *)
@param new_fnames: (const p_list *)"""
        return _ida_idp.IDB_Hooks_changing_ti(self, ea, new_type, new_fnames)

    def ti_changed(self, ea: ida_idaapi.ea_t, type: 'type_t const *',
        fnames: 'p_list const *') ->None:
        """An item typestring (c/c++ prototype) has been changed. 
          
@param ea: (::ea_t)
@param type: (const type_t *)
@param fnames: (const p_list *)"""
        return _ida_idp.IDB_Hooks_ti_changed(self, ea, type, fnames)

    def changing_op_ti(self, ea: ida_idaapi.ea_t, n: int, new_type:
        'type_t const *', new_fnames: 'p_list const *') ->None:
        """An operand typestring (c/c++ prototype) is to be changed. 
          
@param ea: (::ea_t)
@param n: (int)
@param new_type: (const type_t *)
@param new_fnames: (const p_list *)"""
        return _ida_idp.IDB_Hooks_changing_op_ti(self, ea, n, new_type,
            new_fnames)

    def op_ti_changed(self, ea: ida_idaapi.ea_t, n: int, type:
        'type_t const *', fnames: 'p_list const *') ->None:
        """An operand typestring (c/c++ prototype) has been changed. 
          
@param ea: (::ea_t)
@param n: (int)
@param type: (const type_t *)
@param fnames: (const p_list *)"""
        return _ida_idp.IDB_Hooks_op_ti_changed(self, ea, n, type, fnames)

    def changing_op_type(self, ea: ida_idaapi.ea_t, n: int, opinfo: 'opinfo_t'
        ) ->None:
        """An operand type (offset, hex, etc...) is to be changed. 
          
@param ea: (::ea_t)
@param n: (int) eventually or'ed with OPND_OUTER or OPND_ALL
@param opinfo: (const opinfo_t *) additional operand info"""
        return _ida_idp.IDB_Hooks_changing_op_type(self, ea, n, opinfo)

    def op_type_changed(self, ea: ida_idaapi.ea_t, n: int) ->None:
        """An operand type (offset, hex, etc...) has been set or deleted. 
          
@param ea: (::ea_t)
@param n: (int) eventually or'ed with OPND_OUTER or OPND_ALL"""
        return _ida_idp.IDB_Hooks_op_type_changed(self, ea, n)

    def segm_added(self, s: 'segment_t *') ->None:
        """A new segment has been created. 
          
@param s: (segment_t *) See also adding_segm"""
        return _ida_idp.IDB_Hooks_segm_added(self, s)

    def deleting_segm(self, start_ea: ida_idaapi.ea_t) ->None:
        """A segment is to be deleted. 
          
@param start_ea: (::ea_t)"""
        return _ida_idp.IDB_Hooks_deleting_segm(self, start_ea)

    def segm_deleted(self, start_ea: ida_idaapi.ea_t, end_ea:
        ida_idaapi.ea_t, flags: int) ->None:
        """A segment has been deleted. 
          
@param start_ea: (::ea_t)
@param end_ea: (::ea_t)
@param flags: (int)"""
        return _ida_idp.IDB_Hooks_segm_deleted(self, start_ea, end_ea, flags)

    def changing_segm_start(self, s: 'segment_t *', new_start:
        ida_idaapi.ea_t, segmod_flags: int) ->None:
        """Segment start address is to be changed. 
          
@param s: (segment_t *)
@param new_start: (::ea_t)
@param segmod_flags: (int)"""
        return _ida_idp.IDB_Hooks_changing_segm_start(self, s, new_start,
            segmod_flags)

    def segm_start_changed(self, s: 'segment_t *', oldstart: ida_idaapi.ea_t
        ) ->None:
        """Segment start address has been changed. 
          
@param s: (segment_t *)
@param oldstart: (::ea_t)"""
        return _ida_idp.IDB_Hooks_segm_start_changed(self, s, oldstart)

    def changing_segm_end(self, s: 'segment_t *', new_end: ida_idaapi.ea_t,
        segmod_flags: int) ->None:
        """Segment end address is to be changed. 
          
@param s: (segment_t *)
@param new_end: (::ea_t)
@param segmod_flags: (int)"""
        return _ida_idp.IDB_Hooks_changing_segm_end(self, s, new_end,
            segmod_flags)

    def segm_end_changed(self, s: 'segment_t *', oldend: ida_idaapi.ea_t
        ) ->None:
        """Segment end address has been changed. 
          
@param s: (segment_t *)
@param oldend: (::ea_t)"""
        return _ida_idp.IDB_Hooks_segm_end_changed(self, s, oldend)

    def changing_segm_name(self, s: 'segment_t *', oldname: str) ->None:
        """Segment name is being changed. 
          
@param s: (segment_t *)
@param oldname: (const char *)"""
        return _ida_idp.IDB_Hooks_changing_segm_name(self, s, oldname)

    def segm_name_changed(self, s: 'segment_t *', name: str) ->None:
        """Segment name has been changed. 
          
@param s: (segment_t *)
@param name: (const char *)"""
        return _ida_idp.IDB_Hooks_segm_name_changed(self, s, name)

    def changing_segm_class(self, s: 'segment_t *') ->None:
        """Segment class is being changed. 
          
@param s: (segment_t *)"""
        return _ida_idp.IDB_Hooks_changing_segm_class(self, s)

    def segm_class_changed(self, s: 'segment_t *', sclass: str) ->None:
        """Segment class has been changed. 
          
@param s: (segment_t *)
@param sclass: (const char *)"""
        return _ida_idp.IDB_Hooks_segm_class_changed(self, s, sclass)

    def segm_attrs_updated(self, s: 'segment_t *') ->None:
        """Segment attributes has been changed. 
          
@param s: (segment_t *) This event is generated for secondary segment attributes (examples: color, permissions, etc)"""
        return _ida_idp.IDB_Hooks_segm_attrs_updated(self, s)

    def segm_moved(self, _from: ida_idaapi.ea_t, to: ida_idaapi.ea_t, size:
        'asize_t', changed_netmap: bool) ->None:
        """Segment has been moved. 
          
@param to: (::ea_t)
@param size: (::asize_t)
@param changed_netmap: (bool) See also idb_event::allsegs_moved"""
        return _ida_idp.IDB_Hooks_segm_moved(self, _from, to, size,
            changed_netmap)

    def allsegs_moved(self, info: 'segm_move_infos_t *') ->None:
        """Program rebasing is complete. This event is generated after series of segm_moved events 
          
@param info: (segm_move_infos_t *)"""
        return _ida_idp.IDB_Hooks_allsegs_moved(self, info)

    def func_added(self, pfn: 'func_t *') ->None:
        """The kernel has added a function. 
          
@param pfn: (func_t *)"""
        return _ida_idp.IDB_Hooks_func_added(self, pfn)

    def func_updated(self, pfn: 'func_t *') ->None:
        """The kernel has updated a function. 
          
@param pfn: (func_t *)"""
        return _ida_idp.IDB_Hooks_func_updated(self, pfn)

    def set_func_start(self, pfn: 'func_t *', new_start: ida_idaapi.ea_t
        ) ->None:
        """Function chunk start address will be changed. 
          
@param pfn: (func_t *)
@param new_start: (::ea_t)"""
        return _ida_idp.IDB_Hooks_set_func_start(self, pfn, new_start)

    def set_func_end(self, pfn: 'func_t *', new_end: ida_idaapi.ea_t) ->None:
        """Function chunk end address will be changed. 
          
@param pfn: (func_t *)
@param new_end: (::ea_t)"""
        return _ida_idp.IDB_Hooks_set_func_end(self, pfn, new_end)

    def deleting_func(self, pfn: 'func_t *') ->None:
        """The kernel is about to delete a function. 
          
@param pfn: (func_t *)"""
        return _ida_idp.IDB_Hooks_deleting_func(self, pfn)

    def frame_deleted(self, pfn: 'func_t *') ->None:
        """The kernel has deleted a function frame. 
          
@param pfn: (func_t *) idb_event::frame_created"""
        return _ida_idp.IDB_Hooks_frame_deleted(self, pfn)

    def thunk_func_created(self, pfn: 'func_t *') ->None:
        """A thunk bit has been set for a function. 
          
@param pfn: (func_t *)"""
        return _ida_idp.IDB_Hooks_thunk_func_created(self, pfn)

    def func_tail_appended(self, pfn: 'func_t *', tail: 'func_t *') ->None:
        """A function tail chunk has been appended. 
          
@param pfn: (func_t *)
@param tail: (func_t *)"""
        return _ida_idp.IDB_Hooks_func_tail_appended(self, pfn, tail)

    def deleting_func_tail(self, pfn: 'func_t *', tail: 'range_t') ->None:
        """A function tail chunk is to be removed. 
          
@param pfn: (func_t *)
@param tail: (const range_t *)"""
        return _ida_idp.IDB_Hooks_deleting_func_tail(self, pfn, tail)

    def func_tail_deleted(self, pfn: 'func_t *', tail_ea: ida_idaapi.ea_t
        ) ->None:
        """A function tail chunk has been removed. 
          
@param pfn: (func_t *)
@param tail_ea: (::ea_t)"""
        return _ida_idp.IDB_Hooks_func_tail_deleted(self, pfn, tail_ea)

    def tail_owner_changed(self, tail: 'func_t *', owner_func:
        ida_idaapi.ea_t, old_owner: ida_idaapi.ea_t) ->None:
        """A tail chunk owner has been changed. 
          
@param tail: (func_t *)
@param owner_func: (::ea_t)
@param old_owner: (::ea_t)"""
        return _ida_idp.IDB_Hooks_tail_owner_changed(self, tail, owner_func,
            old_owner)

    def func_noret_changed(self, pfn: 'func_t *') ->None:
        """FUNC_NORET bit has been changed. 
          
@param pfn: (func_t *)"""
        return _ida_idp.IDB_Hooks_func_noret_changed(self, pfn)

    def stkpnts_changed(self, pfn: 'func_t *') ->None:
        """Stack change points have been modified. 
          
@param pfn: (func_t *)"""
        return _ida_idp.IDB_Hooks_stkpnts_changed(self, pfn)

    def updating_tryblks(self, tbv: 'tryblks_t const *') ->None:
        """About to update tryblk information 
          
@param tbv: (const ::tryblks_t *)"""
        return _ida_idp.IDB_Hooks_updating_tryblks(self, tbv)

    def tryblks_updated(self, tbv: 'tryblks_t const *') ->None:
        """Updated tryblk information 
          
@param tbv: (const ::tryblks_t *)"""
        return _ida_idp.IDB_Hooks_tryblks_updated(self, tbv)

    def deleting_tryblks(self, range: 'range_t') ->None:
        """About to delete tryblk information in given range 
          
@param range: (const range_t *)"""
        return _ida_idp.IDB_Hooks_deleting_tryblks(self, range)

    def sgr_changed(self, start_ea: ida_idaapi.ea_t, end_ea:
        ida_idaapi.ea_t, regnum: int, value: 'sel_t', old_value: 'sel_t',
        tag: 'uchar') ->None:
        """The kernel has changed a segment register value. 
          
@param start_ea: (::ea_t)
@param end_ea: (::ea_t)
@param regnum: (int)
@param value: (::sel_t)
@param old_value: (::sel_t)
@param tag: (uchar) Segment register range tags"""
        return _ida_idp.IDB_Hooks_sgr_changed(self, start_ea, end_ea,
            regnum, value, old_value, tag)

    def make_code(self, insn: 'insn_t const *') ->None:
        """An instruction is being created. 
          
@param insn: (const insn_t*)"""
        return _ida_idp.IDB_Hooks_make_code(self, insn)

    def make_data(self, ea: ida_idaapi.ea_t, flags: 'flags64_t', tid:
        'tid_t', len: 'asize_t') ->None:
        """A data item is being created. 
          
@param ea: (::ea_t)
@param flags: (flags64_t)
@param tid: (tid_t)
@param len: (::asize_t)"""
        return _ida_idp.IDB_Hooks_make_data(self, ea, flags, tid, len)

    def destroyed_items(self, ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t,
        will_disable_range: bool) ->None:
        """Instructions/data have been destroyed in [ea1,ea2). 
          
@param ea1: (::ea_t)
@param ea2: (::ea_t)
@param will_disable_range: (bool)"""
        return _ida_idp.IDB_Hooks_destroyed_items(self, ea1, ea2,
            will_disable_range)

    def renamed(self, ea: ida_idaapi.ea_t, new_name: str, local_name: bool,
        old_name: str) ->None:
        """The kernel has renamed a byte. See also the rename event 
          
@param ea: (::ea_t)
@param new_name: (const char *) can be nullptr
@param local_name: (bool)
@param old_name: (const char *) can be nullptr"""
        return _ida_idp.IDB_Hooks_renamed(self, ea, new_name, local_name,
            old_name)

    def byte_patched(self, ea: ida_idaapi.ea_t, old_value: int) ->None:
        """A byte has been patched. 
          
@param ea: (::ea_t)
@param old_value: (uint32)"""
        return _ida_idp.IDB_Hooks_byte_patched(self, ea, old_value)

    def changing_cmt(self, ea: ida_idaapi.ea_t, repeatable_cmt: bool,
        newcmt: str) ->None:
        """An item comment is to be changed. 
          
@param ea: (::ea_t)
@param repeatable_cmt: (bool)
@param newcmt: (const char *)"""
        return _ida_idp.IDB_Hooks_changing_cmt(self, ea, repeatable_cmt, newcmt
            )

    def cmt_changed(self, ea: ida_idaapi.ea_t, repeatable_cmt: bool) ->None:
        """An item comment has been changed. 
          
@param ea: (::ea_t)
@param repeatable_cmt: (bool)"""
        return _ida_idp.IDB_Hooks_cmt_changed(self, ea, repeatable_cmt)

    def changing_range_cmt(self, kind: 'range_kind_t', a: 'range_t', cmt:
        str, repeatable: bool) ->None:
        """Range comment is to be changed. 
          
@param kind: (range_kind_t)
@param a: (const range_t *)
@param cmt: (const char *)
@param repeatable: (bool)"""
        return _ida_idp.IDB_Hooks_changing_range_cmt(self, kind, a, cmt,
            repeatable)

    def range_cmt_changed(self, kind: 'range_kind_t', a: 'range_t', cmt:
        str, repeatable: bool) ->None:
        """Range comment has been changed. 
          
@param kind: (range_kind_t)
@param a: (const range_t *)
@param cmt: (const char *)
@param repeatable: (bool)"""
        return _ida_idp.IDB_Hooks_range_cmt_changed(self, kind, a, cmt,
            repeatable)

    def extra_cmt_changed(self, ea: ida_idaapi.ea_t, line_idx: int, cmt: str
        ) ->None:
        """An extra comment has been changed. 
          
@param ea: (::ea_t)
@param line_idx: (int)
@param cmt: (const char *)"""
        return _ida_idp.IDB_Hooks_extra_cmt_changed(self, ea, line_idx, cmt)

    def item_color_changed(self, ea: ida_idaapi.ea_t, color: 'bgcolor_t'
        ) ->None:
        """An item color has been changed. 
          
@param ea: (::ea_t)
@param color: (bgcolor_t) if color==DEFCOLOR, the the color is deleted."""
        return _ida_idp.IDB_Hooks_item_color_changed(self, ea, color)

    def callee_addr_changed(self, ea: ida_idaapi.ea_t, callee: ida_idaapi.ea_t
        ) ->None:
        """Callee address has been updated by the user. 
          
@param ea: (::ea_t)
@param callee: (::ea_t)"""
        return _ida_idp.IDB_Hooks_callee_addr_changed(self, ea, callee)

    def bookmark_changed(self, index: int, pos: 'lochist_entry_t const *',
        desc: str, operation: int) ->None:
        """Boomarked position changed. 
          
@param index: (uint32)
@param pos: (::const lochist_entry_t *)
@param desc: (::const char *)
@param operation: (int) 0-added, 1-updated, 2-deleted if desc==nullptr, then the bookmark was deleted."""
        return _ida_idp.IDB_Hooks_bookmark_changed(self, index, pos, desc,
            operation)

    def sgr_deleted(self, start_ea: ida_idaapi.ea_t, end_ea:
        ida_idaapi.ea_t, regnum: int) ->None:
        """The kernel has deleted a segment register value. 
          
@param start_ea: (::ea_t)
@param end_ea: (::ea_t)
@param regnum: (int)"""
        return _ida_idp.IDB_Hooks_sgr_deleted(self, start_ea, end_ea, regnum)

    def adding_segm(self, s: 'segment_t *') ->None:
        """A segment is being created. 
          
@param s: (segment_t *)"""
        return _ida_idp.IDB_Hooks_adding_segm(self, s)

    def func_deleted(self, func_ea: ida_idaapi.ea_t) ->None:
        """A function has been deleted. 
          
@param func_ea: (::ea_t)"""
        return _ida_idp.IDB_Hooks_func_deleted(self, func_ea)

    def dirtree_mkdir(self, dt: 'dirtree_t *', path: str) ->None:
        """Dirtree: a directory has been created. 
          
@param dt: (dirtree_t *)
@param path: (::const char *)"""
        return _ida_idp.IDB_Hooks_dirtree_mkdir(self, dt, path)

    def dirtree_rmdir(self, dt: 'dirtree_t *', path: str) ->None:
        """Dirtree: a directory has been deleted. 
          
@param dt: (dirtree_t *)
@param path: (::const char *)"""
        return _ida_idp.IDB_Hooks_dirtree_rmdir(self, dt, path)

    def dirtree_link(self, dt: 'dirtree_t *', path: str, link: bool) ->None:
        """Dirtree: an item has been linked/unlinked. 
          
@param dt: (dirtree_t *)
@param path: (::const char *)
@param link: (::bool)"""
        return _ida_idp.IDB_Hooks_dirtree_link(self, dt, path, link)

    def dirtree_move(self, dt: 'dirtree_t *', _from: str, to: str) ->None:
        """Dirtree: a directory or item has been moved. 
          
@param dt: (dirtree_t *)
@param to: (::const char *)"""
        return _ida_idp.IDB_Hooks_dirtree_move(self, dt, _from, to)

    def dirtree_rank(self, dt: 'dirtree_t *', path: str, rank: 'size_t'
        ) ->None:
        """Dirtree: a directory or item rank has been changed. 
          
@param dt: (dirtree_t *)
@param path: (::const char *)
@param rank: (::size_t)"""
        return _ida_idp.IDB_Hooks_dirtree_rank(self, dt, path, rank)

    def dirtree_rminode(self, dt: 'dirtree_t *', inode: 'inode_t') ->None:
        """Dirtree: an inode became unavailable. 
          
@param dt: (dirtree_t *)
@param inode: (inode_t)"""
        return _ida_idp.IDB_Hooks_dirtree_rminode(self, dt, inode)

    def dirtree_segm_moved(self, dt: 'dirtree_t *') ->None:
        """Dirtree: inodes were changed due to a segment movement or a program rebasing 
          
@param dt: (dirtree_t *)"""
        return _ida_idp.IDB_Hooks_dirtree_segm_moved(self, dt)

    def local_types_changed(self, ltc: 'local_type_change_t', ordinal: int,
        name: str) ->None:
        """Local types have been changed 
          
@param ltc: (local_type_change_t)
@param ordinal: (uint32) 0 means ordinal is unknown
@param name: (const char *) nullptr means name is unknown"""
        return _ida_idp.IDB_Hooks_local_types_changed(self, ltc, ordinal, name)

    def lt_udm_created(self, udtname: str, udm: 'udm_t') ->None:
        """local type udt member has been added 
          
@param udtname: (::const char *)
@param udm: (::const udm_t *)"""
        return _ida_idp.IDB_Hooks_lt_udm_created(self, udtname, udm)

    def lt_udm_deleted(self, udtname: str, udm_tid: 'tid_t', udm: 'udm_t'
        ) ->None:
        """local type udt member has been deleted 
          
@param udtname: (::const char *)
@param udm_tid: (tid_t)
@param udm: (::const udm_t *)"""
        return _ida_idp.IDB_Hooks_lt_udm_deleted(self, udtname, udm_tid, udm)

    def lt_udm_renamed(self, udtname: str, udm: 'udm_t', oldname: str) ->None:
        """local type udt member has been renamed 
          
@param udtname: (::const char *)
@param udm: (::const udm_t *)
@param oldname: (::const char *)"""
        return _ida_idp.IDB_Hooks_lt_udm_renamed(self, udtname, udm, oldname)

    def lt_udm_changed(self, udtname: str, udm_tid: 'tid_t', udmold:
        'udm_t', udmnew: 'udm_t') ->None:
        """local type udt member has been changed 
          
@param udtname: (::const char *)
@param udm_tid: (tid_t)
@param udmold: (::const udm_t *)
@param udmnew: (::const udm_t *)"""
        return _ida_idp.IDB_Hooks_lt_udm_changed(self, udtname, udm_tid,
            udmold, udmnew)

    def lt_udt_expanded(self, udtname: str, udm_tid: 'tid_t', delta: 'adiff_t'
        ) ->None:
        """A structure type has been expanded/shrank. 
          
@param udtname: (::const char *)
@param udm_tid: (tid_t) the gap was added/removed before this member
@param delta: (::adiff_t) number of added/removed bytes"""
        return _ida_idp.IDB_Hooks_lt_udt_expanded(self, udtname, udm_tid, delta
            )

    def frame_created(self, func_ea: ida_idaapi.ea_t) ->None:
        """A function frame has been created. 
          
@param func_ea: (::ea_t) idb_event::frame_deleted"""
        return _ida_idp.IDB_Hooks_frame_created(self, func_ea)

    def frame_udm_created(self, func_ea: ida_idaapi.ea_t, udm: 'udm_t') ->None:
        """Frame member has been added. 
          
@param func_ea: (::ea_t)
@param udm: (::const udm_t *)"""
        return _ida_idp.IDB_Hooks_frame_udm_created(self, func_ea, udm)

    def frame_udm_deleted(self, func_ea: ida_idaapi.ea_t, udm_tid: 'tid_t',
        udm: 'udm_t') ->None:
        """Frame member has been deleted. 
          
@param func_ea: (::ea_t)
@param udm_tid: (tid_t)
@param udm: (::const udm_t *)"""
        return _ida_idp.IDB_Hooks_frame_udm_deleted(self, func_ea, udm_tid, udm
            )

    def frame_udm_renamed(self, func_ea: ida_idaapi.ea_t, udm: 'udm_t',
        oldname: str) ->None:
        """Frame member has been renamed. 
          
@param func_ea: (::ea_t)
@param udm: (::const udm_t *)
@param oldname: (::const char *)"""
        return _ida_idp.IDB_Hooks_frame_udm_renamed(self, func_ea, udm, oldname
            )

    def frame_udm_changed(self, func_ea: ida_idaapi.ea_t, udm_tid: 'tid_t',
        udmold: 'udm_t', udmnew: 'udm_t') ->None:
        """Frame member has been changed. 
          
@param func_ea: (::ea_t)
@param udm_tid: (tid_t)
@param udmold: (::const udm_t *)
@param udmnew: (::const udm_t *)"""
        return _ida_idp.IDB_Hooks_frame_udm_changed(self, func_ea, udm_tid,
            udmold, udmnew)

    def frame_expanded(self, func_ea: ida_idaapi.ea_t, udm_tid: 'tid_t',
        delta: 'adiff_t') ->None:
        """A frame type has been expanded/shrank. 
          
@param func_ea: (::ea_t)
@param udm_tid: (tid_t) the gap was added/removed before this member
@param delta: (::adiff_t) number of added/removed bytes"""
        return _ida_idp.IDB_Hooks_frame_expanded(self, func_ea, udm_tid, delta)

    def idasgn_matched_ea(self, ea: ida_idaapi.ea_t, name: str, lib_name: str
        ) ->None:
        """A FLIRT match has been found 
          
@param ea: (::ea_t) the matching address
@param name: (::const char *) the matched name
@param lib_name: (::const char *) library name extracted from signature file"""
        return _ida_idp.IDB_Hooks_idasgn_matched_ea(self, ea, name, lib_name)

    def lt_edm_created(self, enumname: str, edm: 'edm_t') ->None:
        """local type enum member has been added 
          
@param enumname: (::const char *)
@param edm: (::const edm_t *)"""
        return _ida_idp.IDB_Hooks_lt_edm_created(self, enumname, edm)

    def lt_edm_deleted(self, enumname: str, edm_tid: 'tid_t', edm: 'edm_t'
        ) ->None:
        """local type enum member has been deleted 
          
@param enumname: (::const char *)
@param edm_tid: (tid_t)
@param edm: (::const edm_t *)"""
        return _ida_idp.IDB_Hooks_lt_edm_deleted(self, enumname, edm_tid, edm)

    def lt_edm_renamed(self, enumname: str, edm: 'edm_t', oldname: str) ->None:
        """local type enum member has been renamed 
          
@param enumname: (::const char *)
@param edm: (::const edm_t *)
@param oldname: (::const char *)"""
        return _ida_idp.IDB_Hooks_lt_edm_renamed(self, enumname, edm, oldname)

    def lt_edm_changed(self, enumname: str, edm_tid: 'tid_t', edmold:
        'edm_t', edmnew: 'edm_t') ->None:
        """local type enum member has been changed 
          
@param enumname: (::const char *)
@param edm_tid: (tid_t)
@param edmold: (::const edm_t *)
@param edmnew: (::const edm_t *)"""
        return _ida_idp.IDB_Hooks_lt_edm_changed(self, enumname, edm_tid,
            edmold, edmnew)
    __swig_destroy__ = _ida_idp.delete_IDB_Hooks

    def __disown__(self):
        self.this.disown()
        _ida_idp.disown_IDB_Hooks(self)
        return weakref.proxy(self)


_ida_idp.IDB_Hooks_swigregister(IDB_Hooks)


def get_idb_notifier_addr(arg1: 'PyObject *') ->'PyObject *':
    return _ida_idp.get_idb_notifier_addr(arg1)


def get_idb_notifier_ud_addr(hooks: 'IDB_Hooks') ->'PyObject *':
    return _ida_idp.get_idb_notifier_ud_addr(hooks)


class _processor_t_Trampoline_IDB_Hooks(IDB_Hooks):

    def __init__(self, proc):
        IDB_Hooks.__init__(self, ida_idaapi.HBF_CALL_WITH_NEW_EXEC |
            ida_idaapi.HBF_VOLATILE_METHOD_SET)
        import weakref
        self.proc = weakref.ref(proc)
        for key in dir(self):
            if not key.startswith('_') and not key in ['proc']:
                thing = getattr(self, key)
                if hasattr(thing, '__call__'):
                    setattr(self, key, self.__make_parent_caller(key))

    def __dummy(self, *args):
        return 0

    def __make_parent_caller(self, key):

        def call_parent(*args):
            return getattr(self.proc(), key, self.__dummy)(*args)
        return call_parent


import weakref


class _notify_when_dispatcher_t:


    class _callback_t:

        def __init__(self, fun):
            self.fun = fun
            self.slots = 0


    class _IDP_Hooks(IDP_Hooks):

        def __init__(self, dispatcher):
            IDP_Hooks.__init__(self)
            self.dispatcher = weakref.ref(dispatcher)

        def ev_newfile(self, name):
            return self.dispatcher().dispatch(ida_idaapi.NW_OPENIDB, 0)

        def ev_oldfile(self, name):
            return self.dispatcher().dispatch(ida_idaapi.NW_OPENIDB, 1)


    class _IDB_Hooks(IDB_Hooks):

        def __init__(self, dispatcher):
            IDB_Hooks.__init__(self)
            self.dispatcher = weakref.ref(dispatcher)

        def closebase(self):
            return self.dispatcher().dispatch(ida_idaapi.NW_CLOSEIDB)

    def __init__(self):
        self.idp_hooks = self._IDP_Hooks(self)
        self.idp_hooks.hook()
        self.idb_hooks = self._IDB_Hooks(self)
        self.idb_hooks.hook()
        self.callbacks = []

    def _find(self, fun):
        for idx, cb in enumerate(self.callbacks):
            if cb.fun == fun:
                return idx, cb
        return None, None

    def dispatch(self, slot, *args):
        for cb in self.callbacks[:]:
            if cb.slots & slot != 0:
                cb.fun(slot, *args)
        return 0

    def notify_when(self, when, fun):
        _, cb = self._find(fun)
        if cb is None:
            cb = self._callback_t(fun)
            self.callbacks.append(cb)
        if when & ida_idaapi.NW_REMOVE != 0:
            cb.slots &= ~(when & ~ida_idaapi.NW_REMOVE)
        else:
            cb.slots |= when
        if cb.slots == 0:
            idx, cb = self._find(cb.fun)
            del self.callbacks[idx]
        return True

```
