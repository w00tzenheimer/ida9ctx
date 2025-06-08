```python
"""Routines to manipulate function stack frames, stack variables, register variables and local labels.

The frame is represented as a structure: 
  +------------------------------------------------+
  | function arguments                             |
  +------------------------------------------------+
  | return address (isn't stored in func_t)        |
  +------------------------------------------------+
  | saved registers (SI, DI, etc - func_t::frregs) |
  +------------------------------------------------+ <- typical BP
  |                                                |  |
  |                                                |  | func_t::fpd
  |                                                |  |
  |                                                | <- real BP
  | local variables (func_t::frsize)               |
  |                                                |
  |                                                |
  +------------------------------------------------+ <- SP

To access the structure of a function frame and stack variables, use:
* tinfo_t::get_func_frame(const func_t *pfn) (the preferred way)
* get_func_frame(tinfo_t *out, const func_t *pfn)
* tinfo_t::get_udt_details() gives info about stack variables: their type, names, offset, etc 


    """
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_frame
else:
    import _ida_frame
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
SWIG_PYTHON_LEGACY_BOOL = _ida_frame.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi
import ida_range


class xreflist_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_frame.xreflist_t_swiginit(self, _ida_frame.new_xreflist_t(*args))
    __swig_destroy__ = _ida_frame.delete_xreflist_t

    def push_back(self, *args) ->'xreflist_entry_t &':
        return _ida_frame.xreflist_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_frame.xreflist_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_frame.xreflist_t_size(self)

    def empty(self) ->bool:
        return _ida_frame.xreflist_t_empty(self)

    def at(self, _idx: 'size_t') ->'xreflist_entry_t const &':
        return _ida_frame.xreflist_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_frame.xreflist_t_qclear(self)

    def clear(self) ->None:
        return _ida_frame.xreflist_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_frame.xreflist_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_frame.xreflist_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_frame.xreflist_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_frame.xreflist_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_frame.xreflist_t_truncate(self)

    def swap(self, r: 'xreflist_t') ->None:
        return _ida_frame.xreflist_t_swap(self, r)

    def extract(self) ->'xreflist_entry_t *':
        return _ida_frame.xreflist_t_extract(self)

    def inject(self, s: 'xreflist_entry_t', len: 'size_t') ->None:
        return _ida_frame.xreflist_t_inject(self, s, len)

    def __eq__(self, r: 'xreflist_t') ->bool:
        return _ida_frame.xreflist_t___eq__(self, r)

    def __ne__(self, r: 'xreflist_t') ->bool:
        return _ida_frame.xreflist_t___ne__(self, r)

    def begin(self, *args) ->'qvector< xreflist_entry_t >::const_iterator':
        return _ida_frame.xreflist_t_begin(self, *args)

    def end(self, *args) ->'qvector< xreflist_entry_t >::const_iterator':
        return _ida_frame.xreflist_t_end(self, *args)

    def insert(self, it: 'xreflist_entry_t', x: 'xreflist_entry_t'
        ) ->'qvector< xreflist_entry_t >::iterator':
        return _ida_frame.xreflist_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< xreflist_entry_t >::iterator':
        return _ida_frame.xreflist_t_erase(self, *args)

    def find(self, *args) ->'qvector< xreflist_entry_t >::const_iterator':
        return _ida_frame.xreflist_t_find(self, *args)

    def has(self, x: 'xreflist_entry_t') ->bool:
        return _ida_frame.xreflist_t_has(self, x)

    def add_unique(self, x: 'xreflist_entry_t') ->bool:
        return _ida_frame.xreflist_t_add_unique(self, x)

    def _del(self, x: 'xreflist_entry_t') ->bool:
        return _ida_frame.xreflist_t__del(self, x)

    def __len__(self) ->'size_t':
        return _ida_frame.xreflist_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'xreflist_entry_t const &':
        return _ida_frame.xreflist_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'xreflist_entry_t') ->None:
        return _ida_frame.xreflist_t___setitem__(self, i, v)

    def append(self, x: 'xreflist_entry_t') ->None:
        return _ida_frame.xreflist_t_append(self, x)

    def extend(self, x: 'xreflist_t') ->None:
        return _ida_frame.xreflist_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_frame.xreflist_t_swigregister(xreflist_t)


def is_funcarg_off(pfn: 'func_t const *', frameoff: int) ->bool:
    return _ida_frame.is_funcarg_off(pfn, frameoff)


def lvar_off(pfn: 'func_t const *', frameoff: int) ->int:
    return _ida_frame.lvar_off(pfn, frameoff)


FRAME_UDM_NAME_R = _ida_frame.FRAME_UDM_NAME_R
FRAME_UDM_NAME_S = _ida_frame.FRAME_UDM_NAME_S


class stkpnt_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    ea: 'ea_t' = property(_ida_frame.stkpnt_t_ea_get, _ida_frame.
        stkpnt_t_ea_set)
    spd: 'sval_t' = property(_ida_frame.stkpnt_t_spd_get, _ida_frame.
        stkpnt_t_spd_set)

    def __eq__(self, r: 'stkpnt_t') ->bool:
        return _ida_frame.stkpnt_t___eq__(self, r)

    def __ne__(self, r: 'stkpnt_t') ->bool:
        return _ida_frame.stkpnt_t___ne__(self, r)

    def __lt__(self, r: 'stkpnt_t') ->bool:
        return _ida_frame.stkpnt_t___lt__(self, r)

    def __gt__(self, r: 'stkpnt_t') ->bool:
        return _ida_frame.stkpnt_t___gt__(self, r)

    def __le__(self, r: 'stkpnt_t') ->bool:
        return _ida_frame.stkpnt_t___le__(self, r)

    def __ge__(self, r: 'stkpnt_t') ->bool:
        return _ida_frame.stkpnt_t___ge__(self, r)

    def compare(self, r: 'stkpnt_t') ->int:
        return _ida_frame.stkpnt_t_compare(self, r)

    def __init__(self):
        _ida_frame.stkpnt_t_swiginit(self, _ida_frame.new_stkpnt_t())
    __swig_destroy__ = _ida_frame.delete_stkpnt_t


_ida_frame.stkpnt_t_swigregister(stkpnt_t)


class stkpnts_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __eq__(self, r: 'stkpnts_t') ->bool:
        return _ida_frame.stkpnts_t___eq__(self, r)

    def __ne__(self, r: 'stkpnts_t') ->bool:
        return _ida_frame.stkpnts_t___ne__(self, r)

    def __lt__(self, r: 'stkpnts_t') ->bool:
        return _ida_frame.stkpnts_t___lt__(self, r)

    def __gt__(self, r: 'stkpnts_t') ->bool:
        return _ida_frame.stkpnts_t___gt__(self, r)

    def __le__(self, r: 'stkpnts_t') ->bool:
        return _ida_frame.stkpnts_t___le__(self, r)

    def __ge__(self, r: 'stkpnts_t') ->bool:
        return _ida_frame.stkpnts_t___ge__(self, r)

    def compare(self, r: 'stkpnts_t') ->int:
        return _ida_frame.stkpnts_t_compare(self, r)

    def __init__(self):
        _ida_frame.stkpnts_t_swiginit(self, _ida_frame.new_stkpnts_t())
    __swig_destroy__ = _ida_frame.delete_stkpnts_t


_ida_frame.stkpnts_t_swigregister(stkpnts_t)


def add_frame(pfn: 'func_t *', frsize: int, frregs: 'ushort', argsize:
    'asize_t') ->bool:
    """Add function frame. 
        
@param pfn: pointer to function structure
@param frsize: size of function local variables
@param frregs: size of saved registers
@param argsize: size of function arguments range which will be purged upon return. this parameter is used for __stdcall and __pascal calling conventions. for other calling conventions please pass 0.
@retval 1: ok
@retval 0: failed (no function, frame already exists)"""
    return _ida_frame.add_frame(pfn, frsize, frregs, argsize)


def del_frame(pfn: 'func_t *') ->bool:
    """Delete a function frame. 
        
@param pfn: pointer to function structure
@returns success"""
    return _ida_frame.del_frame(pfn)


def set_frame_size(pfn: 'func_t *', frsize: 'asize_t', frregs: 'ushort',
    argsize: 'asize_t') ->bool:
    """Set size of function frame. Note: The returned size may not include all stack arguments. It does so only for __stdcall and __fastcall calling conventions. To get the entire frame size for all cases use frame.get_func_frame(pfn).get_size() 
        
@param pfn: pointer to function structure
@param frsize: size of function local variables
@param frregs: size of saved registers
@param argsize: size of function arguments that will be purged from the stack upon return
@returns success"""
    return _ida_frame.set_frame_size(pfn, frsize, frregs, argsize)


def get_frame_size(pfn: 'func_t const *') ->'asize_t':
    """Get full size of a function frame. This function takes into account size of local variables + size of saved registers + size of return address + number of purged bytes. The purged bytes correspond to the arguments of the functions with __stdcall and __fastcall calling conventions. 
        
@param pfn: pointer to function structure, may be nullptr
@returns size of frame in bytes or zero"""
    return _ida_frame.get_frame_size(pfn)


def get_frame_retsize(pfn: 'func_t const *') ->int:
    """Get size of function return address. 
        
@param pfn: pointer to function structure, can't be nullptr"""
    return _ida_frame.get_frame_retsize(pfn)


FPC_ARGS = _ida_frame.FPC_ARGS
FPC_RETADDR = _ida_frame.FPC_RETADDR
FPC_SAVREGS = _ida_frame.FPC_SAVREGS
FPC_LVARS = _ida_frame.FPC_LVARS


def get_frame_part(range: 'range_t', pfn: 'func_t const *', part:
    'frame_part_t') ->None:
    """Get offsets of the frame part in the frame. 
        
@param range: pointer to the output buffer with the frame part start/end(exclusive) offsets, can't be nullptr
@param pfn: pointer to function structure, can't be nullptr
@param part: frame part"""
    return _ida_frame.get_frame_part(range, pfn, part)


def frame_off_args(pfn: 'func_t const *') ->ida_idaapi.ea_t:
    """Get starting address of arguments section.
"""
    return _ida_frame.frame_off_args(pfn)


def frame_off_retaddr(pfn: 'func_t const *') ->ida_idaapi.ea_t:
    """Get starting address of return address section.
"""
    return _ida_frame.frame_off_retaddr(pfn)


def frame_off_savregs(pfn: 'func_t const *') ->ida_idaapi.ea_t:
    """Get starting address of saved registers section.
"""
    return _ida_frame.frame_off_savregs(pfn)


def frame_off_lvars(pfn: 'func_t const *') ->ida_idaapi.ea_t:
    """Get start address of local variables section.
"""
    return _ida_frame.frame_off_lvars(pfn)


def get_func_frame(out: 'tinfo_t', pfn: 'func_t const *') ->bool:
    """Get type of function frame 
        
@param out: type info
@param pfn: pointer to function structure
@returns success"""
    return _ida_frame.get_func_frame(out, pfn)


def soff_to_fpoff(pfn: 'func_t *', soff: int) ->int:
    """Convert struct offsets into fp-relative offsets. This function converts the offsets inside the udt_type_data_t object into the frame pointer offsets (for example, EBP-relative). 
        """
    return _ida_frame.soff_to_fpoff(pfn, soff)


def update_fpd(pfn: 'func_t *', fpd: 'asize_t') ->bool:
    """Update frame pointer delta. 
        
@param pfn: pointer to function structure
@param fpd: new fpd value. cannot be bigger than the local variable range size.
@returns success"""
    return _ida_frame.update_fpd(pfn, fpd)


def set_purged(ea: ida_idaapi.ea_t, nbytes: int, override_old_value: bool
    ) ->bool:
    """Set the number of purged bytes for a function or data item (funcptr). This function will update the database and plan to reanalyze items referencing the specified address. It works only for processors with PR_PURGING bit in 16 and 32 bit modes. 
        
@param ea: address of the function of item
@param nbytes: number of purged bytes
@param override_old_value: may overwrite old information about purged bytes
@returns success"""
    return _ida_frame.set_purged(ea, nbytes, override_old_value)


STKVAR_VALID_SIZE = _ida_frame.STKVAR_VALID_SIZE
"""x.dtyp contains correct variable type (for insns like 'lea' this bit must be off). In general, dr_O references do not allow to determine the variable size 
        """


def define_stkvar(pfn: 'func_t *', name: str, off: int, tif: 'tinfo_t',
    repr: 'value_repr_t'=None) ->bool:
    """Define/redefine a stack variable. 
        
@param pfn: pointer to function
@param name: variable name, nullptr means autogenerate a name
@param off: offset of the stack variable in the frame. negative values denote local variables, positive - function arguments.
@param tif: variable type
@param repr: variable representation
@returns success"""
    return _ida_frame.define_stkvar(pfn, name, off, tif, repr)


def add_frame_member(pfn: 'func_t const *', name: str, offset: int, tif:
    'tinfo_t', repr: 'value_repr_t'=None, etf_flags: 'uint'=0) ->bool:
    """Add member to the frame type 
        
@param pfn: pointer to function
@param name: variable name, nullptr means autogenerate a name
@param offset: member offset in the frame structure, in bytes
@param tif: variable type
@param repr: variable representation
@returns success"""
    return _ida_frame.add_frame_member(pfn, name, offset, tif, repr, etf_flags)


def is_anonymous_member_name(name: str) ->bool:
    """Is member name prefixed with "anonymous"?
"""
    return _ida_frame.is_anonymous_member_name(name)


def is_dummy_member_name(name: str) ->bool:
    """Is member name an auto-generated name?
"""
    return _ida_frame.is_dummy_member_name(name)


def is_special_frame_member(tid: 'tid_t') ->bool:
    """Is stkvar with TID the return address slot or the saved registers slot ? 
        
@param tid: frame member type id return address or saved registers member?"""
    return _ida_frame.is_special_frame_member(tid)


def set_frame_member_type(pfn: 'func_t const *', offset: int, tif:
    'tinfo_t', repr: 'value_repr_t'=None, etf_flags: 'uint'=0) ->bool:
    """Change type of the frame member 
        
@param pfn: pointer to function
@param offset: member offset in the frame structure, in bytes
@param tif: variable type
@param repr: variable representation
@returns success"""
    return _ida_frame.set_frame_member_type(pfn, offset, tif, repr, etf_flags)


def delete_frame_members(pfn: 'func_t const *', start_offset: int,
    end_offset: int) ->bool:
    """Delete frame members 
        
@param pfn: pointer to function
@param start_offset: member offset to start deletion from, in bytes
@param end_offset: member offset which not included in the deletion, in bytes
@returns success"""
    return _ida_frame.delete_frame_members(pfn, start_offset, end_offset)


def build_stkvar_name(pfn: 'func_t const *', v: int) ->str:
    """Build automatic stack variable name. 
        
@param pfn: pointer to function (can't be nullptr!)
@param v: value of variable offset
@returns length of stack variable name or -1"""
    return _ida_frame.build_stkvar_name(pfn, v)


def calc_stkvar_struc_offset(pfn: 'func_t *', insn: 'insn_t const &', n: int
    ) ->ida_idaapi.ea_t:
    """Calculate offset of stack variable in the frame structure. 
        
@param pfn: pointer to function (cannot be nullptr)
@param insn: the instruction
@param n: 0..UA_MAXOP-1 operand number -1 if error, return BADADDR
@returns BADADDR if some error (issue a warning if stack frame is bad)"""
    return _ida_frame.calc_stkvar_struc_offset(pfn, insn, n)


def calc_frame_offset(pfn: 'func_t *', off: int, insn: 'insn_t const *'=
    None, op: 'op_t const *'=None) ->int:
    """Calculate the offset of stack variable in the frame. 
        
@param pfn: pointer to function (cannot be nullptr)
@param off: the offset relative to stack pointer or frame pointer
@param insn: the instruction
@param op: the operand
@returns the offset in the frame"""
    return _ida_frame.calc_frame_offset(pfn, off, insn, op)


def free_regvar(v: 'regvar_t') ->None:
    return _ida_frame.free_regvar(v)


class regvar_t(ida_range.range_t):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    canon: 'char *' = property(_ida_frame.regvar_t_canon_get, _ida_frame.
        regvar_t_canon_set)
    """canonical register name (case-insensitive)
"""
    user: 'char *' = property(_ida_frame.regvar_t_user_get, _ida_frame.
        regvar_t_user_set)
    """user-defined register name
"""
    cmt: 'char *' = property(_ida_frame.regvar_t_cmt_get, _ida_frame.
        regvar_t_cmt_set)
    """comment to appear near definition
"""

    def __init__(self, *args):
        _ida_frame.regvar_t_swiginit(self, _ida_frame.new_regvar_t(*args))
    __swig_destroy__ = _ida_frame.delete_regvar_t

    def swap(self, r: 'regvar_t') ->None:
        return _ida_frame.regvar_t_swap(self, r)


_ida_frame.regvar_t_swigregister(regvar_t)


def add_regvar(pfn: 'func_t *', ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t,
    canon: str, user: str, cmt: str) ->int:
    """Define a register variable. 
        
@param pfn: function in which the definition will be created
@param ea1: range of addresses within the function where the definition will be used
@param ea2: range of addresses within the function where the definition will be used
@param canon: name of a general register
@param user: user-defined name for the register
@param cmt: comment for the definition
@returns Register variable error codes"""
    return _ida_frame.add_regvar(pfn, ea1, ea2, canon, user, cmt)


REGVAR_ERROR_OK = _ida_frame.REGVAR_ERROR_OK
"""all ok
"""
REGVAR_ERROR_ARG = _ida_frame.REGVAR_ERROR_ARG
"""function arguments are bad
"""
REGVAR_ERROR_RANGE = _ida_frame.REGVAR_ERROR_RANGE
"""the definition range is bad
"""
REGVAR_ERROR_NAME = _ida_frame.REGVAR_ERROR_NAME
"""the provided name(s) can't be accepted
"""


def find_regvar(*args) ->'regvar_t *':
    """This function has the following signatures:

    0. find_regvar(pfn: func_t *, ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t, canon: str, user: str) -> regvar_t *
    1. find_regvar(pfn: func_t *, ea: ida_idaapi.ea_t, canon: str) -> regvar_t *

# 0: find_regvar(pfn: func_t *, ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t, canon: str, user: str) -> regvar_t *

Find a register variable definition (powerful version). One of 'canon' and 'user' should be nullptr. If both 'canon' and 'user' are nullptr it returns the first regvar definition in the range. 
        
@returns nullptr-not found, otherwise ptr to regvar_t

# 1: find_regvar(pfn: func_t *, ea: ida_idaapi.ea_t, canon: str) -> regvar_t *

Find a register variable definition. 
        
@returns nullptr-not found, otherwise ptr to regvar_t
"""
    return _ida_frame.find_regvar(*args)


def has_regvar(pfn: 'func_t *', ea: ida_idaapi.ea_t) ->bool:
    """Is there a register variable definition? 
        
@param pfn: function in question
@param ea: current address"""
    return _ida_frame.has_regvar(pfn, ea)


def rename_regvar(pfn: 'func_t *', v: 'regvar_t', user: str) ->int:
    """Rename a register variable. 
        
@param pfn: function in question
@param v: variable to rename
@param user: new user-defined name for the register
@returns Register variable error codes"""
    return _ida_frame.rename_regvar(pfn, v, user)


def set_regvar_cmt(pfn: 'func_t *', v: 'regvar_t', cmt: str) ->int:
    """Set comment for a register variable. 
        
@param pfn: function in question
@param v: variable to rename
@param cmt: new comment
@returns Register variable error codes"""
    return _ida_frame.set_regvar_cmt(pfn, v, cmt)


def del_regvar(pfn: 'func_t *', ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t,
    canon: str) ->int:
    """Delete a register variable definition. 
        
@param pfn: function in question
@param ea1: range of addresses within the function where the definition holds
@param ea2: range of addresses within the function where the definition holds
@param canon: name of a general register
@returns Register variable error codes"""
    return _ida_frame.del_regvar(pfn, ea1, ea2, canon)


def add_auto_stkpnt(pfn: 'func_t *', ea: ida_idaapi.ea_t, delta: int) ->bool:
    """Add automatic SP register change point. 
        
@param pfn: pointer to the function. may be nullptr.
@param ea: linear address where SP changes. usually this is the end of the instruction which modifies the stack pointer ( insn_t::ea+ insn_t::size)
@param delta: difference between old and new values of SP
@returns success"""
    return _ida_frame.add_auto_stkpnt(pfn, ea, delta)


def add_user_stkpnt(ea: ida_idaapi.ea_t, delta: int) ->bool:
    """Add user-defined SP register change point. 
        
@param ea: linear address where SP changes
@param delta: difference between old and new values of SP
@returns success"""
    return _ida_frame.add_user_stkpnt(ea, delta)


def del_stkpnt(pfn: 'func_t *', ea: ida_idaapi.ea_t) ->bool:
    """Delete SP register change point. 
        
@param pfn: pointer to the function. may be nullptr.
@param ea: linear address
@returns success"""
    return _ida_frame.del_stkpnt(pfn, ea)


def get_spd(pfn: 'func_t *', ea: ida_idaapi.ea_t) ->int:
    """Get difference between the initial and current values of ESP. 
        
@param pfn: pointer to the function. may be nullptr.
@param ea: linear address of the instruction
@returns 0 or the difference, usually a negative number. returns the sp-diff before executing the instruction."""
    return _ida_frame.get_spd(pfn, ea)


def get_effective_spd(pfn: 'func_t *', ea: ida_idaapi.ea_t) ->int:
    """Get effective difference between the initial and current values of ESP. This function returns the sp-diff used by the instruction. The difference between get_spd() and get_effective_spd() is present only for instructions like "pop [esp+N]": they modify sp and use the modified value. 
        
@param pfn: pointer to the function. may be nullptr.
@param ea: linear address
@returns 0 or the difference, usually a negative number"""
    return _ida_frame.get_effective_spd(pfn, ea)


def get_sp_delta(pfn: 'func_t *', ea: ida_idaapi.ea_t) ->int:
    """Get modification of SP made at the specified location 
        
@param pfn: pointer to the function. may be nullptr.
@param ea: linear address
@returns 0 if the specified location doesn't contain a SP change point. otherwise return delta of SP modification."""
    return _ida_frame.get_sp_delta(pfn, ea)


def set_auto_spd(pfn: 'func_t *', ea: ida_idaapi.ea_t, new_spd: int) ->bool:
    """Add such an automatic SP register change point so that at EA the new cumulative SP delta (that is, the difference between the initial and current values of SP) would be equal to NEW_SPD. 
        
@param pfn: pointer to the function. may be nullptr.
@param ea: linear address of the instruction
@param new_spd: new value of the cumulative SP delta
@returns success"""
    return _ida_frame.set_auto_spd(pfn, ea, new_spd)


def recalc_spd(cur_ea: ida_idaapi.ea_t) ->bool:
    """Recalculate SP delta for an instruction that stops execution. The next instruction is not reached from the current instruction. We need to recalculate SP for the next instruction.
This function will create a new automatic SP register change point if necessary. It should be called from the emulator (emu.cpp) when auto_state == AU_USED if the current instruction doesn't pass the execution flow to the next instruction. 
        
@param cur_ea: linear address of the current instruction
@retval 1: new stkpnt is added
@retval 0: nothing is changed"""
    return _ida_frame.recalc_spd(cur_ea)


def recalc_spd_for_basic_block(pfn: 'func_t *', cur_ea: ida_idaapi.ea_t
    ) ->bool:
    """Recalculate SP delta for the current instruction. The typical code snippet to calculate SP delta in a proc module is:

if ( may_trace_sp() && pfn != nullptr )
  if ( !recalc_spd_for_basic_block(pfn, insn.ea) )
    trace_sp(pfn, insn);

where trace_sp() is a typical name for a function that emulates the SP change of an instruction.

@param pfn: pointer to the function
@param cur_ea: linear address of the current instruction
@retval true: the cumulative SP delta is set
@retval false: the instruction at CUR_EA passes flow to the next instruction. SP delta must be set as a result of emulating the current instruction."""
    return _ida_frame.recalc_spd_for_basic_block(pfn, cur_ea)


class xreflist_entry_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    ea: 'ea_t' = property(_ida_frame.xreflist_entry_t_ea_get, _ida_frame.
        xreflist_entry_t_ea_set)
    """Location of the insn referencing the stack frame member.
"""
    opnum: 'uchar' = property(_ida_frame.xreflist_entry_t_opnum_get,
        _ida_frame.xreflist_entry_t_opnum_set)
    """Number of the operand of that instruction.
"""
    type: 'uchar' = property(_ida_frame.xreflist_entry_t_type_get,
        _ida_frame.xreflist_entry_t_type_set)
    """The type of xref (cref_t & dref_t)
"""

    def __eq__(self, r: 'xreflist_entry_t') ->bool:
        return _ida_frame.xreflist_entry_t___eq__(self, r)

    def __ne__(self, r: 'xreflist_entry_t') ->bool:
        return _ida_frame.xreflist_entry_t___ne__(self, r)

    def __lt__(self, r: 'xreflist_entry_t') ->bool:
        return _ida_frame.xreflist_entry_t___lt__(self, r)

    def __gt__(self, r: 'xreflist_entry_t') ->bool:
        return _ida_frame.xreflist_entry_t___gt__(self, r)

    def __le__(self, r: 'xreflist_entry_t') ->bool:
        return _ida_frame.xreflist_entry_t___le__(self, r)

    def __ge__(self, r: 'xreflist_entry_t') ->bool:
        return _ida_frame.xreflist_entry_t___ge__(self, r)

    def compare(self, r: 'xreflist_entry_t') ->int:
        return _ida_frame.xreflist_entry_t_compare(self, r)

    def __init__(self):
        _ida_frame.xreflist_entry_t_swiginit(self, _ida_frame.
            new_xreflist_entry_t())
    __swig_destroy__ = _ida_frame.delete_xreflist_entry_t


_ida_frame.xreflist_entry_t_swigregister(xreflist_entry_t)


def build_stkvar_xrefs(out: 'xreflist_t', pfn: 'func_t *', start_offset:
    int, end_offset: int) ->None:
    """Fill 'out' with a list of all the xrefs made from function 'pfn' to specified range of the pfn's stack frame. 
        
@param out: the list of xrefs to fill.
@param pfn: the function to scan.
@param start_offset: start frame structure offset, in bytes
@param end_offset: end frame structure offset, in bytes"""
    return _ida_frame.build_stkvar_xrefs(out, pfn, start_offset, end_offset)

```
