```python
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_regfinder
else:
    import _ida_regfinder
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
SWIG_PYTHON_LEGACY_BOOL = _ida_regfinder.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi


class reg_value_def_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    val: 'uval_t' = property(_ida_regfinder.reg_value_def_t_val_get,
        _ida_regfinder.reg_value_def_t_val_set)
    """the value
"""
    def_ea: 'ea_t' = property(_ida_regfinder.reg_value_def_t_def_ea_get,
        _ida_regfinder.reg_value_def_t_def_ea_set)
    """the instruction address
"""
    def_itype: 'uint16' = property(_ida_regfinder.
        reg_value_def_t_def_itype_get, _ida_regfinder.
        reg_value_def_t_def_itype_set)
    """the instruction code (processor specific)
"""
    flags: 'uint16' = property(_ida_regfinder.reg_value_def_t_flags_get,
        _ida_regfinder.reg_value_def_t_flags_set)
    """additional info about the value
"""
    SHORT_INSN = property(_ida_regfinder.reg_value_def_t_SHORT_INSN_get)
    """like 'addi reg, imm'
"""
    PC_BASED = property(_ida_regfinder.reg_value_def_t_PC_BASED_get)
    """the value depends on DEF_EA only for numbers 
        """
    LIKE_GOT = property(_ida_regfinder.reg_value_def_t_LIKE_GOT_get)
    """the value is like GOT only for numbers 
        """

    def __init__(self, *args):
        _ida_regfinder.reg_value_def_t_swiginit(self, _ida_regfinder.
            new_reg_value_def_t(*args))

    def is_short_insn(self, *args) ->bool:
        """This function has the following signatures:

    0. is_short_insn() -> bool
    1. is_short_insn(insn: const insn_t &) -> bool

# 0: is_short_insn() -> bool


# 1: is_short_insn(insn: const insn_t &) -> bool

"""
        return _ida_regfinder.reg_value_def_t_is_short_insn(self, *args)

    def is_pc_based(self) ->bool:
        return _ida_regfinder.reg_value_def_t_is_pc_based(self)

    def is_like_got(self) ->bool:
        return _ida_regfinder.reg_value_def_t_is_like_got(self)

    def __eq__(self, r: 'reg_value_def_t') ->bool:
        return _ida_regfinder.reg_value_def_t___eq__(self, r)

    def __lt__(self, r: 'reg_value_def_t') ->bool:
        return _ida_regfinder.reg_value_def_t___lt__(self, r)
    NOVAL = _ida_regfinder.reg_value_def_t_NOVAL
    """without a value
"""
    UVAL = _ida_regfinder.reg_value_def_t_UVAL
    """as a number
"""
    SPVAL = _ida_regfinder.reg_value_def_t_SPVAL
    """as a SP delta
"""

    def dstr(self, how: 'reg_value_def_t::dstr_val_t', pm: 'procmod_t'=None
        ) ->str:
        """Return the string representation.
"""
        return _ida_regfinder.reg_value_def_t_dstr(self, how, pm)
    __swig_destroy__ = _ida_regfinder.delete_reg_value_def_t


_ida_regfinder.reg_value_def_t_swigregister(reg_value_def_t)
cvar = _ida_regfinder.cvar


class reg_value_info_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_regfinder.reg_value_info_t_swiginit(self, _ida_regfinder.
            new_reg_value_info_t())

    def clear(self) ->None:
        """Undefine the value.
"""
        return _ida_regfinder.reg_value_info_t_clear(self)

    def empty(self) ->bool:
        """Return 'true' if we know nothing about a value.
"""
        return _ida_regfinder.reg_value_info_t_empty(self)

    def swap(self, r: 'reg_value_info_t') ->None:
        return _ida_regfinder.reg_value_info_t_swap(self, r)

    @staticmethod
    def make_dead_end(dead_end_ea: ida_idaapi.ea_t) ->'reg_value_info_t':
        """Return the undefined value because of a dead end. 
        """
        return _ida_regfinder.reg_value_info_t_make_dead_end(dead_end_ea)

    @staticmethod
    def make_aborted(bblk_ea: ida_idaapi.ea_t) ->'reg_value_info_t':
        """Return the value after aborting. 
        """
        return _ida_regfinder.reg_value_info_t_make_aborted(bblk_ea)

    @staticmethod
    def make_badinsn(insn_ea: ida_idaapi.ea_t) ->'reg_value_info_t':
        """Return the unknown value after a bad insn. 
        """
        return _ida_regfinder.reg_value_info_t_make_badinsn(insn_ea)

    @staticmethod
    def make_unkinsn(insn: 'insn_t const &') ->'reg_value_info_t':
        """Return the unknown value after executing the insn. 
        """
        return _ida_regfinder.reg_value_info_t_make_unkinsn(insn)

    @staticmethod
    def make_unkfunc(func_ea: ida_idaapi.ea_t) ->'reg_value_info_t':
        """Return the unknown value from the function start. 
        """
        return _ida_regfinder.reg_value_info_t_make_unkfunc(func_ea)

    @staticmethod
    def make_unkloop(bblk_ea: ida_idaapi.ea_t) ->'reg_value_info_t':
        """Return the unknown value if it changes in a loop. 
        """
        return _ida_regfinder.reg_value_info_t_make_unkloop(bblk_ea)

    @staticmethod
    def make_unkmult(bblk_ea: ida_idaapi.ea_t) ->'reg_value_info_t':
        """Return the unknown value if the register has incompatible values. 
        """
        return _ida_regfinder.reg_value_info_t_make_unkmult(bblk_ea)

    @staticmethod
    def make_unkxref(bblk_ea: ida_idaapi.ea_t) ->'reg_value_info_t':
        """Return the unknown value if there are too many xrefs. 
        """
        return _ida_regfinder.reg_value_info_t_make_unkxref(bblk_ea)

    @staticmethod
    def make_unkvals(bblk_ea: ida_idaapi.ea_t) ->'reg_value_info_t':
        """Return the unknown value if the register has too many values. 
        """
        return _ida_regfinder.reg_value_info_t_make_unkvals(bblk_ea)

    @staticmethod
    def make_num(*args) ->'reg_value_info_t':
        """This function has the following signatures:

    0. make_num(rval: int, insn: const insn_t &, val_flags: uint16=0) -> reg_value_info_t
    1. make_num(rval: int, val_ea: ida_idaapi.ea_t, val_flags: uint16=0) -> reg_value_info_t

# 0: make_num(rval: int, insn: const insn_t &, val_flags: uint16=0) -> reg_value_info_t

Return the value that is the RVAL number. 
        

# 1: make_num(rval: int, val_ea: ida_idaapi.ea_t, val_flags: uint16=0) -> reg_value_info_t

Return the value that is the RVAL number. 
        
"""
        return _ida_regfinder.reg_value_info_t_make_num(*args)

    @staticmethod
    def make_initial_sp(func_ea: ida_idaapi.ea_t) ->'reg_value_info_t':
        """Return the value that is the initial stack pointer. 
        """
        return _ida_regfinder.reg_value_info_t_make_initial_sp(func_ea)

    def is_dead_end(self) ->bool:
        """Return 'true' if the value is undefined because of a dead end.
"""
        return _ida_regfinder.reg_value_info_t_is_dead_end(self)

    def aborted(self) ->bool:
        """Return 'true' if the tracking process was aborted.
"""
        return _ida_regfinder.reg_value_info_t_aborted(self)

    def is_special(self) ->bool:
        """Return 'true' if the value requires special handling.
"""
        return _ida_regfinder.reg_value_info_t_is_special(self)

    def is_badinsn(self) ->bool:
        """Return 'true' if the value is unknown because of a bad insn.
"""
        return _ida_regfinder.reg_value_info_t_is_badinsn(self)

    def is_unkinsn(self) ->bool:
        """Return 'true' if the value is unknown after executing the insn.
"""
        return _ida_regfinder.reg_value_info_t_is_unkinsn(self)

    def is_unkfunc(self) ->bool:
        """Return 'true' if the value is unknown from the function start.
"""
        return _ida_regfinder.reg_value_info_t_is_unkfunc(self)

    def is_unkloop(self) ->bool:
        """Return 'true' if the value is unknown because it changes in a loop.
"""
        return _ida_regfinder.reg_value_info_t_is_unkloop(self)

    def is_unkmult(self) ->bool:
        """Return 'true' if the value is unknown because the register has incompatible values (a number and SP delta). 
        """
        return _ida_regfinder.reg_value_info_t_is_unkmult(self)

    def is_unkxref(self) ->bool:
        """Return 'true' if the value is unknown because there are too many xrefs.
"""
        return _ida_regfinder.reg_value_info_t_is_unkxref(self)

    def is_unkvals(self) ->bool:
        """Return 'true' if the value is unknown because the register has too many values. 
        """
        return _ida_regfinder.reg_value_info_t_is_unkvals(self)

    def is_unknown(self) ->bool:
        """Return 'true' if the value is unknown.
"""
        return _ida_regfinder.reg_value_info_t_is_unknown(self)

    def is_num(self) ->bool:
        """Return 'true' if the value is a constant.
"""
        return _ida_regfinder.reg_value_info_t_is_num(self)

    def is_spd(self) ->bool:
        """Return 'true' if the value depends on the stack pointer.
"""
        return _ida_regfinder.reg_value_info_t_is_spd(self)

    def is_known(self) ->bool:
        """Return 'true' if the value is known (i.e. it is a number or SP delta).
"""
        return _ida_regfinder.reg_value_info_t_is_known(self)

    def get_num(self) ->bool:
        """Return the number if the value is a constant. 
        """
        return _ida_regfinder.reg_value_info_t_get_num(self)

    def get_spd(self) ->bool:
        """Return the SP delta if the value depends on the stack pointer. 
        """
        return _ida_regfinder.reg_value_info_t_get_spd(self)

    def get_def_ea(self) ->ida_idaapi.ea_t:
        """Return the defining address.
"""
        return _ida_regfinder.reg_value_info_t_get_def_ea(self)

    def get_def_itype(self) ->'uint16':
        """Return the defining instruction code (processor specific).
"""
        return _ida_regfinder.reg_value_info_t_get_def_itype(self)

    def is_value_unique(self) ->bool:
        """Check that the value is unique.
"""
        return _ida_regfinder.reg_value_info_t_is_value_unique(self)

    def have_all_vals_flag(self, val_flags: 'uint16') ->bool:
        """Check the given flag for each value.
"""
        return _ida_regfinder.reg_value_info_t_have_all_vals_flag(self,
            val_flags)

    def has_any_vals_flag(self, val_flags: 'uint16') ->bool:
        return _ida_regfinder.reg_value_info_t_has_any_vals_flag(self,
            val_flags)

    def is_all_vals_pc_based(self) ->bool:
        return _ida_regfinder.reg_value_info_t_is_all_vals_pc_based(self)

    def is_any_vals_pc_based(self) ->bool:
        return _ida_regfinder.reg_value_info_t_is_any_vals_pc_based(self)

    def is_all_vals_like_got(self) ->bool:
        return _ida_regfinder.reg_value_info_t_is_all_vals_like_got(self)

    def is_any_vals_like_got(self) ->bool:
        return _ida_regfinder.reg_value_info_t_is_any_vals_like_got(self)

    def set_all_vals_flag(self, val_flags: 'uint16') ->None:
        """Set the given flag for each value.
"""
        return _ida_regfinder.reg_value_info_t_set_all_vals_flag(self,
            val_flags)

    def set_all_vals_pc_based(self) ->None:
        return _ida_regfinder.reg_value_info_t_set_all_vals_pc_based(self)

    def set_all_vals_got_based(self) ->None:
        return _ida_regfinder.reg_value_info_t_set_all_vals_got_based(self)

    def set_dead_end(self, dead_end_ea: ida_idaapi.ea_t) ->None:
        """Set the value to be undefined because of a dead end. 
        """
        return _ida_regfinder.reg_value_info_t_set_dead_end(self, dead_end_ea)

    def set_badinsn(self, insn_ea: ida_idaapi.ea_t) ->None:
        """Set the value to be unknown after a bad insn. 
        """
        return _ida_regfinder.reg_value_info_t_set_badinsn(self, insn_ea)

    def set_unkinsn(self, insn: 'insn_t const &') ->None:
        """Set the value to be unknown after executing the insn. 
        """
        return _ida_regfinder.reg_value_info_t_set_unkinsn(self, insn)

    def set_unkfunc(self, func_ea: ida_idaapi.ea_t) ->None:
        """Set the value to be unknown from the function start. 
        """
        return _ida_regfinder.reg_value_info_t_set_unkfunc(self, func_ea)

    def set_unkloop(self, bblk_ea: ida_idaapi.ea_t) ->None:
        """Set the value to be unknown because it changes in a loop. 
        """
        return _ida_regfinder.reg_value_info_t_set_unkloop(self, bblk_ea)

    def set_unkmult(self, bblk_ea: ida_idaapi.ea_t) ->None:
        """Set the value to be unknown because the register has incompatible values. 
        """
        return _ida_regfinder.reg_value_info_t_set_unkmult(self, bblk_ea)

    def set_unkxref(self, bblk_ea: ida_idaapi.ea_t) ->None:
        """Set the value to be unknown because there are too many xrefs. 
        """
        return _ida_regfinder.reg_value_info_t_set_unkxref(self, bblk_ea)

    def set_unkvals(self, bblk_ea: ida_idaapi.ea_t) ->None:
        """Set the value to be unknown because the register has too many values. 
        """
        return _ida_regfinder.reg_value_info_t_set_unkvals(self, bblk_ea)

    def set_aborted(self, bblk_ea: ida_idaapi.ea_t) ->None:
        """Set the value after aborting. 
        """
        return _ida_regfinder.reg_value_info_t_set_aborted(self, bblk_ea)

    def set_num(self, *args) ->None:
        """This function has the following signatures:

    0. set_num(rval: int, insn: const insn_t &, val_flags: uint16=0) -> None
    1. set_num(rvals: uvalvec_t *, insn: const insn_t &) -> None
    2. set_num(rval: int, val_ea: ida_idaapi.ea_t, val_flags: uint16=0) -> None

# 0: set_num(rval: int, insn: const insn_t &, val_flags: uint16=0) -> None

Set the value to be a number after executing an insn. 
        

# 1: set_num(rvals: uvalvec_t *, insn: const insn_t &) -> None

Set the value to be numbers after executing an insn. 
        

# 2: set_num(rval: int, val_ea: ida_idaapi.ea_t, val_flags: uint16=0) -> None

Set the value to be a number before an address. 
        
"""
        return _ida_regfinder.reg_value_info_t_set_num(self, *args)
    EQUAL = _ida_regfinder.reg_value_info_t_EQUAL
    """L==R.
"""
    CONTAINS = _ida_regfinder.reg_value_info_t_CONTAINS
    """L contains R (i.e. R\\L is empty)
"""
    CONTAINED = _ida_regfinder.reg_value_info_t_CONTAINED
    """L is contained in R (i.e. L\\R is empty)
"""
    NOT_COMPARABLE = _ida_regfinder.reg_value_info_t_NOT_COMPARABLE
    """L\\R is not empty and R\\L is not empty.
"""

    def vals_union(self, r: 'reg_value_info_t'
        ) ->'reg_value_info_t::set_compare_res_t':
        """Add values from R into THIS ignoring duplicates. 
        
@retval EQUAL: THIS is not changed
@retval CONTAINS: THIS is not changed
@retval CONTAINED: THIS is a copy of R
@retval NOT_COMPARABLE: values from R are added to THIS"""
        return _ida_regfinder.reg_value_info_t_vals_union(self, r)

    def extend(self, pm: 'procmod_t', width: int, is_signed: bool) ->None:
        """Sign-, or zero-extend the number or SP delta value to full size. The initial value is considered to be of size WIDTH. 
        """
        return _ida_regfinder.reg_value_info_t_extend(self, pm, width,
            is_signed)

    def trunc_uval(self, pm: 'procmod_t') ->None:
        """Truncate the number to the application bitness. 
        """
        return _ida_regfinder.reg_value_info_t_trunc_uval(self, pm)
    ADD = _ida_regfinder.reg_value_info_t_ADD
    SUB = _ida_regfinder.reg_value_info_t_SUB
    OR = _ida_regfinder.reg_value_info_t_OR
    AND = _ida_regfinder.reg_value_info_t_AND
    XOR = _ida_regfinder.reg_value_info_t_XOR
    AND_NOT = _ida_regfinder.reg_value_info_t_AND_NOT
    SLL = _ida_regfinder.reg_value_info_t_SLL
    SLR = _ida_regfinder.reg_value_info_t_SLR
    MOVT = _ida_regfinder.reg_value_info_t_MOVT
    NEG = _ida_regfinder.reg_value_info_t_NEG
    NOT = _ida_regfinder.reg_value_info_t_NOT

    def add(self, r: 'reg_value_info_t', insn: 'insn_t const &') ->None:
        """Add R to the value, save INSN as a defining instruction. 
        """
        return _ida_regfinder.reg_value_info_t_add(self, r, insn)

    def sub(self, r: 'reg_value_info_t', insn: 'insn_t const &') ->None:
        """Subtract R from the value, save INSN as a defining instruction. 
        """
        return _ida_regfinder.reg_value_info_t_sub(self, r, insn)

    def bor(self, r: 'reg_value_info_t', insn: 'insn_t const &') ->None:
        """Make bitwise OR of R to the value, save INSN as a defining instruction. 
        """
        return _ida_regfinder.reg_value_info_t_bor(self, r, insn)

    def band(self, r: 'reg_value_info_t', insn: 'insn_t const &') ->None:
        """Make bitwise AND of R to the value, save INSN as a defining instruction. 
        """
        return _ida_regfinder.reg_value_info_t_band(self, r, insn)

    def bxor(self, r: 'reg_value_info_t', insn: 'insn_t const &') ->None:
        """Make bitwise eXclusive OR of R to the value, save INSN as a defining instruction. 
        """
        return _ida_regfinder.reg_value_info_t_bxor(self, r, insn)

    def bandnot(self, r: 'reg_value_info_t', insn: 'insn_t const &') ->None:
        """Make bitwise AND of the inverse of R to the value, save INSN as a defining instruction. 
        """
        return _ida_regfinder.reg_value_info_t_bandnot(self, r, insn)

    def sll(self, r: 'reg_value_info_t', insn: 'insn_t const &') ->None:
        """Shift the value left by R, save INSN as a defining instruction. 
        """
        return _ida_regfinder.reg_value_info_t_sll(self, r, insn)

    def slr(self, r: 'reg_value_info_t', insn: 'insn_t const &') ->None:
        """Shift the value right by R, save INSN as a defining instruction. 
        """
        return _ida_regfinder.reg_value_info_t_slr(self, r, insn)

    def movt(self, r: 'reg_value_info_t', insn: 'insn_t const &') ->None:
        """Replace the top 16 bits with bottom 16 bits of R, leaving the bottom 16 bits untouched, save INSN as a defining instruction. 
        """
        return _ida_regfinder.reg_value_info_t_movt(self, r, insn)

    def neg(self, insn: 'insn_t const &') ->None:
        """Negate the value, save INSN as a defining instruction.
"""
        return _ida_regfinder.reg_value_info_t_neg(self, insn)

    def bnot(self, insn: 'insn_t const &') ->None:
        """Make bitwise inverse of the value, save INSN as a defining instruction. 
        """
        return _ida_regfinder.reg_value_info_t_bnot(self, insn)

    def add_num(self, *args) ->None:
        """This function has the following signatures:

    0. add_num(r: int, insn: const insn_t &) -> None
    1. add_num(r: int) -> None

# 0: add_num(r: int, insn: const insn_t &) -> None

Add R to the value, save INSN as a defining instruction. 
        

# 1: add_num(r: int) -> None

Add R to the value, do not change the defining instructions. 
        
"""
        return _ida_regfinder.reg_value_info_t_add_num(self, *args)

    def shift_left(self, r: int) ->None:
        """Shift the value left by R, do not change the defining instructions. 
        """
        return _ida_regfinder.reg_value_info_t_shift_left(self, r)

    def shift_right(self, r: int) ->None:
        """Shift the value right by R, do not change the defining instructions. 
        """
        return _ida_regfinder.reg_value_info_t_shift_right(self, r)

    def __str__(self) ->str:
        return _ida_regfinder.reg_value_info_t___str__(self)

    def __len__(self) ->'size_t':
        return _ida_regfinder.reg_value_info_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'reg_value_def_t const &':
        return _ida_regfinder.reg_value_info_t___getitem__(self, i)
    __swig_destroy__ = _ida_regfinder.delete_reg_value_info_t


_ida_regfinder.reg_value_info_t_swigregister(reg_value_info_t)


def find_reg_value(ea: ida_idaapi.ea_t, reg: int) ->'uint64 *':
    """Find register value using the register tracker. 
        
@param ea: the address to find a value at
@param reg: the register to find
@retval 0: no value (the value is varying or the find depth is not enough to find a value)
@retval 1: the found value is in VAL
@retval -1: the processor module does not support a register tracker"""
    return _ida_regfinder.find_reg_value(ea, reg)


def find_sp_value(ea: ida_idaapi.ea_t, reg: int=-1) ->'int64 *':
    """Find a value of the SP based register using the register tracker. 
        
@param ea: the address to find a value at
@param reg: the register to find. by default the SP register is used.
@retval 0: no value (the value is varying or the find depth is not enough to find a value)
@retval 1: the found value is in VAL
@retval -1: the processor module does not support a register tracker"""
    return _ida_regfinder.find_sp_value(ea, reg)


def find_reg_value_info(rvi: 'reg_value_info_t', ea: ida_idaapi.ea_t, reg:
    int, max_depth: int=0) ->bool:
    """Find register value using the register tracker. 
        
@param rvi: the found value with additional attributes
@param ea: the address to find a value at
@param reg: the register to find
@param max_depth: the number of basic blocks to look before aborting the search and returning the unknown value. 0 means the value of REGTRACK_MAX_DEPTH from ida.cfg for ordinal registers or REGTRACK_FUNC_MAX_DEPTH for the function-wide registers, -1 means the value of REGTRACK_FUNC_MAX_DEPTH from ida.cfg.
@retval 'false': the processor module does not support a register tracker
@retval 'true': the found value is in RVI"""
    return _ida_regfinder.find_reg_value_info(rvi, ea, reg, max_depth)


def find_nearest_rvi(rvi: 'reg_value_info_t', ea: ida_idaapi.ea_t, reg:
    'int const [2]') ->int:
    """Find the value of any of the two registers using the register tracker. First, this function tries to find the registers in the basic block of EA, and if it could not do this, then it tries to find in the entire function. 
        
@param rvi: the found value with additional attributes
@param ea: the address to find a value at
@param reg: the registers to find
@returns the index of the found register or -1"""
    return _ida_regfinder.find_nearest_rvi(rvi, ea, reg)


def invalidate_regfinder_cache(*args) ->None:
    """The control flow from FROM to TO has changed. Remove from the register tracker cache all values at TO and all dependent values. if TO == BADADDR then clear the entire cache. 
        """
    return _ida_regfinder.invalidate_regfinder_cache(*args)

```
