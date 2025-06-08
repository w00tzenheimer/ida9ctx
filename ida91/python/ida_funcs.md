```python
"""Routines for working with functions within the disassembled program.

This file also contains routines for working with library signatures (e.g. FLIRT).
Each function consists of function chunks. At least one function chunk must be present in the function definition - the function entry chunk. Other chunks are called function tails. There may be several of them for a function.
A function tail is a continuous range of addresses. It can be used in the definition of one or more functions. One function using the tail is singled out and called the tail owner. This function is considered as 'possessing' the tail. get_func() on a tail address will return the function possessing the tail. You can enumerate the functions using the tail by using func_parent_iterator_t.
Each function chunk in the disassembly is represented as an "range" (a range of addresses, see range.hpp for details) with characteristics.
A function entry must start with an instruction (code) byte. 
    """
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_funcs
else:
    import _ida_funcs
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
SWIG_PYTHON_LEGACY_BOOL = _ida_funcs.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi
import ida_range


class dyn_stkpnt_array(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    data: 'stkpnt_t *' = property(_ida_funcs.dyn_stkpnt_array_data_get)
    count: 'size_t' = property(_ida_funcs.dyn_stkpnt_array_count_get)

    def __init__(self, _data: 'stkpnt_t *', _count: 'size_t'):
        _ida_funcs.dyn_stkpnt_array_swiginit(self, _ida_funcs.
            new_dyn_stkpnt_array(_data, _count))

    def __len__(self) ->'size_t':
        return _ida_funcs.dyn_stkpnt_array___len__(self)

    def __getitem__(self, i: 'size_t') ->'stkpnt_t const &':
        return _ida_funcs.dyn_stkpnt_array___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'stkpnt_t const &') ->None:
        return _ida_funcs.dyn_stkpnt_array___setitem__(self, i, v)
    __iter__ = ida_idaapi._bounded_getitem_iterator
    __swig_destroy__ = _ida_funcs.delete_dyn_stkpnt_array


_ida_funcs.dyn_stkpnt_array_swigregister(dyn_stkpnt_array)


class dyn_regvar_array(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    data: 'regvar_t *' = property(_ida_funcs.dyn_regvar_array_data_get)
    count: 'size_t' = property(_ida_funcs.dyn_regvar_array_count_get)

    def __init__(self, _data: 'regvar_t *', _count: 'size_t'):
        _ida_funcs.dyn_regvar_array_swiginit(self, _ida_funcs.
            new_dyn_regvar_array(_data, _count))

    def __len__(self) ->'size_t':
        return _ida_funcs.dyn_regvar_array___len__(self)

    def __getitem__(self, i: 'size_t') ->'regvar_t const &':
        return _ida_funcs.dyn_regvar_array___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'regvar_t const &') ->None:
        return _ida_funcs.dyn_regvar_array___setitem__(self, i, v)
    __iter__ = ida_idaapi._bounded_getitem_iterator
    __swig_destroy__ = _ida_funcs.delete_dyn_regvar_array


_ida_funcs.dyn_regvar_array_swigregister(dyn_regvar_array)


class dyn_range_array(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    data: 'range_t *' = property(_ida_funcs.dyn_range_array_data_get)
    count: 'size_t' = property(_ida_funcs.dyn_range_array_count_get)

    def __init__(self, _data: 'range_t', _count: 'size_t'):
        _ida_funcs.dyn_range_array_swiginit(self, _ida_funcs.
            new_dyn_range_array(_data, _count))

    def __len__(self) ->'size_t':
        return _ida_funcs.dyn_range_array___len__(self)

    def __getitem__(self, i: 'size_t') ->'range_t const &':
        return _ida_funcs.dyn_range_array___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'range_t') ->None:
        return _ida_funcs.dyn_range_array___setitem__(self, i, v)
    __iter__ = ida_idaapi._bounded_getitem_iterator
    __swig_destroy__ = _ida_funcs.delete_dyn_range_array


_ida_funcs.dyn_range_array_swigregister(dyn_range_array)


class dyn_ea_array(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    data: 'unsigned long long *' = property(_ida_funcs.dyn_ea_array_data_get)
    count: 'size_t' = property(_ida_funcs.dyn_ea_array_count_get)

    def __init__(self, _data: 'unsigned long long *', _count: 'size_t'):
        _ida_funcs.dyn_ea_array_swiginit(self, _ida_funcs.new_dyn_ea_array(
            _data, _count))

    def __len__(self) ->'size_t':
        return _ida_funcs.dyn_ea_array___len__(self)

    def __getitem__(self, i: 'size_t') ->'unsigned long long const &':
        return _ida_funcs.dyn_ea_array___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'unsigned long long const &') ->None:
        return _ida_funcs.dyn_ea_array___setitem__(self, i, v)
    __iter__ = ida_idaapi._bounded_getitem_iterator
    __swig_destroy__ = _ida_funcs.delete_dyn_ea_array


_ida_funcs.dyn_ea_array_swigregister(dyn_ea_array)


class dyn_regarg_array(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    data: 'regarg_t *' = property(_ida_funcs.dyn_regarg_array_data_get)
    count: 'size_t' = property(_ida_funcs.dyn_regarg_array_count_get)

    def __init__(self, _data: 'regarg_t', _count: 'size_t'):
        _ida_funcs.dyn_regarg_array_swiginit(self, _ida_funcs.
            new_dyn_regarg_array(_data, _count))

    def __len__(self) ->'size_t':
        return _ida_funcs.dyn_regarg_array___len__(self)

    def __getitem__(self, i: 'size_t') ->'regarg_t const &':
        return _ida_funcs.dyn_regarg_array___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'regarg_t') ->None:
        return _ida_funcs.dyn_regarg_array___setitem__(self, i, v)
    __iter__ = ida_idaapi._bounded_getitem_iterator
    __swig_destroy__ = _ida_funcs.delete_dyn_regarg_array


_ida_funcs.dyn_regarg_array_swigregister(dyn_regarg_array)


def free_regarg(v: 'regarg_t') ->None:
    return _ida_funcs.free_regarg(v)


class regarg_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    reg: 'int' = property(_ida_funcs.regarg_t_reg_get, _ida_funcs.
        regarg_t_reg_set)
    type: 'type_t *' = property(_ida_funcs.regarg_t_type_get, _ida_funcs.
        regarg_t_type_set)
    name: 'char *' = property(_ida_funcs.regarg_t_name_get, _ida_funcs.
        regarg_t_name_set)

    def __init__(self, *args):
        _ida_funcs.regarg_t_swiginit(self, _ida_funcs.new_regarg_t(*args))
    __swig_destroy__ = _ida_funcs.delete_regarg_t

    def swap(self, r: 'regarg_t') ->None:
        return _ida_funcs.regarg_t_swap(self, r)


_ida_funcs.regarg_t_swigregister(regarg_t)


class func_t(ida_range.range_t):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    flags: 'uint64' = property(_ida_funcs.func_t_flags_get, _ida_funcs.
        func_t_flags_set)
    """Function flags 
        """

    def is_far(self) ->bool:
        """Is a far function?
"""
        return _ida_funcs.func_t_is_far(self)

    def does_return(self) ->bool:
        """Does function return?
"""
        return _ida_funcs.func_t_does_return(self)

    def analyzed_sp(self) ->bool:
        """Has SP-analysis been performed?
"""
        return _ida_funcs.func_t_analyzed_sp(self)

    def need_prolog_analysis(self) ->bool:
        """Needs prolog analysis?
"""
        return _ida_funcs.func_t_need_prolog_analysis(self)
    frame: 'uval_t' = property(_ida_funcs.func_t_frame_get, _ida_funcs.
        func_t_frame_set)
    """netnode id of frame structure - see frame.hpp
"""
    frsize: 'asize_t' = property(_ida_funcs.func_t_frsize_get, _ida_funcs.
        func_t_frsize_set)
    """size of local variables part of frame in bytes. If FUNC_FRAME is set and fpd==0, the frame pointer (EBP) is assumed to point to the top of the local variables range. 
        """
    frregs: 'ushort' = property(_ida_funcs.func_t_frregs_get, _ida_funcs.
        func_t_frregs_set)
    """size of saved registers in frame. This range is immediately above the local variables range. 
        """
    argsize: 'asize_t' = property(_ida_funcs.func_t_argsize_get, _ida_funcs
        .func_t_argsize_set)
    """number of bytes purged from the stack upon returning 
        """
    fpd: 'asize_t' = property(_ida_funcs.func_t_fpd_get, _ida_funcs.
        func_t_fpd_set)
    """frame pointer delta. (usually 0, i.e. realBP==typicalBP) use update_fpd() to modify it. 
        """
    color: 'bgcolor_t' = property(_ida_funcs.func_t_color_get, _ida_funcs.
        func_t_color_set)
    """user defined function color
"""
    pntqty: 'uint32' = property(_ida_funcs.func_t_pntqty_get, _ida_funcs.
        func_t_pntqty_set)
    """number of SP change points
"""
    points: 'stkpnt_t *' = property(_ida_funcs.func_t_points_get,
        _ida_funcs.func_t_points_set)
    """array of SP change points. use ...stkpnt...() functions to access this array. 
        """
    regvarqty: 'int' = property(_ida_funcs.func_t_regvarqty_get, _ida_funcs
        .func_t_regvarqty_set)
    """number of register variables (-1-not read in yet) use find_regvar() to read register variables 
        """
    regvars: 'regvar_t *' = property(_ida_funcs.func_t_regvars_get,
        _ida_funcs.func_t_regvars_set)
    """array of register variables. this array is sorted by: start_ea. use ...regvar...() functions to access this array. 
        """
    regargqty: 'int' = property(_ida_funcs.func_t_regargqty_get, _ida_funcs
        .func_t_regargqty_set)
    """number of register arguments. During analysis IDA tries to guess the register arguments. It stores store the guessing outcome in this field. As soon as it determines the final function prototype, regargqty is set to zero. 
        """
    regargs: 'regarg_t *' = property(_ida_funcs.func_t_regargs_get,
        _ida_funcs.func_t_regargs_set)
    """unsorted array of register arguments. use ...regarg...() functions to access this array. regargs are destroyed when the full function type is determined. 
        """
    tailqty: 'int' = property(_ida_funcs.func_t_tailqty_get, _ida_funcs.
        func_t_tailqty_set)
    """number of function tails
"""
    tails: 'range_t *' = property(_ida_funcs.func_t_tails_get, _ida_funcs.
        func_t_tails_set)
    """array of tails, sorted by ea. use func_tail_iterator_t to access function tails. 
        """
    owner: 'ea_t' = property(_ida_funcs.func_t_owner_get, _ida_funcs.
        func_t_owner_set)
    """the address of the main function possessing this tail
"""
    refqty: 'int' = property(_ida_funcs.func_t_refqty_get, _ida_funcs.
        func_t_refqty_set)
    """number of referers
"""
    referers: 'ea_t *' = property(_ida_funcs.func_t_referers_get,
        _ida_funcs.func_t_referers_set)
    """array of referers (function start addresses). use func_parent_iterator_t to access the referers. 
        """

    def __init__(self, start: ida_idaapi.ea_t=0, end: ida_idaapi.ea_t=0, f:
        'flags64_t'=0):
        _ida_funcs.func_t_swiginit(self, _ida_funcs.new_func_t(start, end, f))

    def __get_points__(self) ->'dynamic_wrapped_array_t< stkpnt_t >':
        return _ida_funcs.func_t___get_points__(self)

    def __get_regvars__(self) ->'dynamic_wrapped_array_t< regvar_t >':
        return _ida_funcs.func_t___get_regvars__(self)

    def __get_tails__(self) ->'dynamic_wrapped_array_t< range_t >':
        return _ida_funcs.func_t___get_tails__(self)

    def __get_referers__(self) ->'dynamic_wrapped_array_t< ea_t >':
        return _ida_funcs.func_t___get_referers__(self)

    def __get_regargs__(self) ->'dynamic_wrapped_array_t< regarg_t >':
        return _ida_funcs.func_t___get_regargs__(self)
    points = property(__get_points__)
    """array of SP change points. use ...stkpnt...() functions to access this array. 
        """
    regvars = property(__get_regvars__)
    """array of register variables. this array is sorted by: start_ea. use ...regvar...() functions to access this array. 
        """
    tails = property(__get_tails__)
    """array of tails, sorted by ea. use func_tail_iterator_t to access function tails. 
        """
    referers = property(__get_referers__)
    """array of referers (function start addresses). use func_parent_iterator_t to access the referers. 
        """
    regargs = property(__get_regargs__)
    """unsorted array of register arguments. use ...regarg...() functions to access this array. regargs are destroyed when the full function type is determined. 
        """

    def addresses(self):
        """
        Alias for func_item_iterator_t(self).addresses()
        """
        yield from func_item_iterator_t(self).addresses()

    def code_items(self):
        """
        Alias for func_item_iterator_t(self).code_items()
        """
        yield from func_item_iterator_t(self).code_items()

    def data_items(self):
        """
        Alias for func_item_iterator_t(self).data_items()
        """
        yield from func_item_iterator_t(self).data_items()

    def head_items(self):
        """
        Alias for func_item_iterator_t(self).head_items()
        """
        yield from func_item_iterator_t(self).head_items()

    def not_tails(self):
        """
        Alias for func_item_iterator_t(self).not_tails()
        """
        yield from func_item_iterator_t(self).not_tails()

    def get_frame_object(self):
        """Retrieve the function frame, in the form of a structure
where frame offsets that are accessed by the program, as well
as areas for "saved registers" and "return address", are
represented by structure members.

If the function has no associated frame, return None

@return a ida_typeinf.tinfo_t object representing the frame, or None"""
        val = _ida_funcs.func_t_get_frame_object(self)
        if val.empty():
            val = None
        return val

    def get_name(self):
        """Get the function name

@return the function name"""
        return _ida_funcs.func_t_get_name(self)

    def get_prototype(self):
        """Retrieve the function prototype.

Once you have obtained the prototype, you can:

* retrieve the return type through ida_typeinf.tinfo_t.get_rettype()
* iterate on the arguments using ida_typeinf.tinfo_t.iter_func()

If the function has no associated prototype, return None

@return a ida_typeinf.tinfo_t object representing the prototype, or None"""
        val = _ida_funcs.func_t_get_prototype(self)
        if val.empty():
            val = None
        return val

    def __iter__(self):
        """
        Alias for func_item_iterator_t(self).__iter__()
        """
        return func_item_iterator_t(self).__iter__()
    frame_object = property(get_frame_object)
    name = property(get_name)
    prototype = property(get_prototype)
    __swig_destroy__ = _ida_funcs.delete_func_t


_ida_funcs.func_t_swigregister(func_t)
FUNC_NORET = _ida_funcs.FUNC_NORET
"""Function doesn't return.
"""
FUNC_FAR = _ida_funcs.FUNC_FAR
"""Far function.
"""
FUNC_LIB = _ida_funcs.FUNC_LIB
"""Library function.
"""
FUNC_STATICDEF = _ida_funcs.FUNC_STATICDEF
"""Static function.
"""
FUNC_FRAME = _ida_funcs.FUNC_FRAME
"""Function uses frame pointer (BP)
"""
FUNC_USERFAR = _ida_funcs.FUNC_USERFAR
"""User has specified far-ness of the function 
        """
FUNC_HIDDEN = _ida_funcs.FUNC_HIDDEN
"""A hidden function chunk.
"""
FUNC_THUNK = _ida_funcs.FUNC_THUNK
"""Thunk (jump) function.
"""
FUNC_BOTTOMBP = _ida_funcs.FUNC_BOTTOMBP
"""BP points to the bottom of the stack frame.
"""
FUNC_NORET_PENDING = _ida_funcs.FUNC_NORET_PENDING
"""Function 'non-return' analysis must be performed. This flag is verified upon func_does_return() 
        """
FUNC_SP_READY = _ida_funcs.FUNC_SP_READY
"""SP-analysis has been performed. If this flag is on, the stack change points should not be not modified anymore. Currently this analysis is performed only for PC 
        """
FUNC_FUZZY_SP = _ida_funcs.FUNC_FUZZY_SP
"""Function changes SP in untraceable way, for example: and esp, 0FFFFFFF0h 
        """
FUNC_PROLOG_OK = _ida_funcs.FUNC_PROLOG_OK
"""Prolog analysis has been performed by last SP-analysis 
        """
FUNC_PURGED_OK = _ida_funcs.FUNC_PURGED_OK
"""'argsize' field has been validated. If this bit is clear and 'argsize' is 0, then we do not known the real number of bytes removed from the stack. This bit is handled by the processor module. 
        """
FUNC_TAIL = _ida_funcs.FUNC_TAIL
"""This is a function tail. Other bits must be clear (except FUNC_HIDDEN). 
        """
FUNC_LUMINA = _ida_funcs.FUNC_LUMINA
"""Function info is provided by Lumina.
"""
FUNC_OUTLINE = _ida_funcs.FUNC_OUTLINE
"""Outlined code, not a real function.
"""
FUNC_REANALYZE = _ida_funcs.FUNC_REANALYZE
"""Function frame changed, request to reanalyze the function after the last insn is analyzed. 
        """
FUNC_UNWIND = _ida_funcs.FUNC_UNWIND
"""function is an exception unwind handler
"""
FUNC_CATCH = _ida_funcs.FUNC_CATCH
"""function is an exception catch handler
"""


def is_func_entry(pfn: 'func_t') ->bool:
    """Does function describe a function entry chunk?
"""
    return _ida_funcs.is_func_entry(pfn)


def is_func_tail(pfn: 'func_t') ->bool:
    """Does function describe a function tail chunk?
"""
    return _ida_funcs.is_func_tail(pfn)


def lock_func_range(pfn: 'func_t', lock: bool) ->None:
    """Lock function pointer Locked pointers are guaranteed to remain valid until they are unlocked. Ranges with locked pointers cannot be deleted or moved. 
        """
    return _ida_funcs.lock_func_range(pfn, lock)


class lock_func(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, _pfn: 'func_t'):
        _ida_funcs.lock_func_swiginit(self, _ida_funcs.new_lock_func(_pfn))
    __swig_destroy__ = _ida_funcs.delete_lock_func


_ida_funcs.lock_func_swigregister(lock_func)


class lock_func_with_tails_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, pfn: 'func_t'):
        _ida_funcs.lock_func_with_tails_t_swiginit(self, _ida_funcs.
            new_lock_func_with_tails_t(pfn))
    __swig_destroy__ = _ida_funcs.delete_lock_func_with_tails_t


_ida_funcs.lock_func_with_tails_t_swigregister(lock_func_with_tails_t)


def is_func_locked(pfn: 'func_t') ->bool:
    """Is the function pointer locked?
"""
    return _ida_funcs.is_func_locked(pfn)


def get_func(ea: ida_idaapi.ea_t) ->'func_t *':
    """Get pointer to function structure by address. 
        
@param ea: any address in a function
@returns ptr to a function or nullptr. This function returns a function entry chunk."""
    return _ida_funcs.get_func(ea)


def get_func_chunknum(pfn: 'func_t', ea: ida_idaapi.ea_t) ->int:
    """Get the containing tail chunk of 'ea'. 
        
@retval -1: means 'does not contain ea'
@retval 0: means the 'pfn' itself contains ea
@retval >0: the number of the containing function tail chunk"""
    return _ida_funcs.get_func_chunknum(pfn, ea)


def func_contains(pfn: 'func_t', ea: ida_idaapi.ea_t) ->bool:
    """Does the given function contain the given address?
"""
    return _ida_funcs.func_contains(pfn, ea)


def is_same_func(ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t) ->bool:
    """Do two addresses belong to the same function?
"""
    return _ida_funcs.is_same_func(ea1, ea2)


def getn_func(n: 'size_t') ->'func_t *':
    """Get pointer to function structure by number. 
        
@param n: number of function, is in range 0..get_func_qty()-1
@returns ptr to a function or nullptr. This function returns a function entry chunk."""
    return _ida_funcs.getn_func(n)


def get_func_qty() ->'size_t':
    """Get total number of functions in the program.
"""
    return _ida_funcs.get_func_qty()


def get_func_num(ea: ida_idaapi.ea_t) ->int:
    """Get ordinal number of a function. 
        
@param ea: any address in the function
@returns number of function (0..get_func_qty()-1). -1 means 'no function at the specified address'."""
    return _ida_funcs.get_func_num(ea)


def get_prev_func(ea: ida_idaapi.ea_t) ->'func_t *':
    """Get pointer to the previous function. 
        
@param ea: any address in the program
@returns ptr to function or nullptr if previous function doesn't exist"""
    return _ida_funcs.get_prev_func(ea)


def get_next_func(ea: ida_idaapi.ea_t) ->'func_t *':
    """Get pointer to the next function. 
        
@param ea: any address in the program
@returns ptr to function or nullptr if next function doesn't exist"""
    return _ida_funcs.get_next_func(ea)


def get_func_ranges(ranges: 'rangeset_t', pfn: 'func_t') ->ida_idaapi.ea_t:
    """Get function ranges. 
        
@param ranges: buffer to receive the range info
@param pfn: ptr to function structure
@returns end address of the last function range (BADADDR-error)"""
    return _ida_funcs.get_func_ranges(ranges, pfn)


def get_func_cmt(pfn: 'func_t', repeatable: bool) ->str:
    """Get function comment. 
        
@param pfn: ptr to function structure
@param repeatable: get repeatable comment?
@returns size of comment or -1 In fact this function works with function chunks too."""
    return _ida_funcs.get_func_cmt(pfn, repeatable)


def set_func_cmt(pfn: 'func_t', cmt: str, repeatable: bool) ->bool:
    """Set function comment. This function works with function chunks too. 
        
@param pfn: ptr to function structure
@param cmt: comment string, may be multiline (with '
'). Use empty str ("") to delete comment
@param repeatable: set repeatable comment?"""
    return _ida_funcs.set_func_cmt(pfn, cmt, repeatable)


def update_func(pfn: 'func_t') ->bool:
    """Update information about a function in the database (func_t). You must not change the function start and end addresses using this function. Use set_func_start() and set_func_end() for it. 
        
@param pfn: ptr to function structure
@returns success"""
    return _ida_funcs.update_func(pfn)


def add_func_ex(pfn: 'func_t') ->bool:
    """Add a new function. If the fn->end_ea is BADADDR, then IDA will try to determine the function bounds by calling find_func_bounds(..., FIND_FUNC_DEFINE). 
        
@param pfn: ptr to filled function structure
@returns success"""
    return _ida_funcs.add_func_ex(pfn)


def add_func(*args) ->bool:
    """Add a new function. If the function end address is BADADDR, then IDA will try to determine the function bounds by calling find_func_bounds(..., FIND_FUNC_DEFINE). 
        
@param ea1: start address
@param ea2: end address
@returns success"""
    return _ida_funcs.add_func(*args)


def del_func(ea: ida_idaapi.ea_t) ->bool:
    """Delete a function. 
        
@param ea: any address in the function entry chunk
@returns success"""
    return _ida_funcs.del_func(ea)


def set_func_start(ea: ida_idaapi.ea_t, newstart: ida_idaapi.ea_t) ->int:
    """Move function chunk start address. 
        
@param ea: any address in the function
@param newstart: new end address of the function
@returns Function move result codes"""
    return _ida_funcs.set_func_start(ea, newstart)


MOVE_FUNC_OK = _ida_funcs.MOVE_FUNC_OK
"""ok
"""
MOVE_FUNC_NOCODE = _ida_funcs.MOVE_FUNC_NOCODE
"""no instruction at 'newstart'
"""
MOVE_FUNC_BADSTART = _ida_funcs.MOVE_FUNC_BADSTART
"""bad new start address
"""
MOVE_FUNC_NOFUNC = _ida_funcs.MOVE_FUNC_NOFUNC
"""no function at 'ea'
"""
MOVE_FUNC_REFUSED = _ida_funcs.MOVE_FUNC_REFUSED
"""a plugin refused the action
"""


def set_func_end(ea: ida_idaapi.ea_t, newend: ida_idaapi.ea_t) ->bool:
    """Move function chunk end address. 
        
@param ea: any address in the function
@param newend: new end address of the function
@returns success"""
    return _ida_funcs.set_func_end(ea, newend)


def reanalyze_function(*args) ->None:
    """Reanalyze a function. This function plans to analyzes all chunks of the given function. Optional parameters (ea1, ea2) may be used to narrow the analyzed range. 
        
@param pfn: pointer to a function
@param ea1: start of the range to analyze
@param ea2: end of range to analyze
@param analyze_parents: meaningful only if pfn points to a function tail. if true, all tail parents will be reanalyzed. if false, only the given tail will be reanalyzed."""
    return _ida_funcs.reanalyze_function(*args)


def find_func_bounds(nfn: 'func_t', flags: int) ->int:
    """Determine the boundaries of a new function. This function tries to find the start and end addresses of a new function. It calls the module with processor_t::func_bounds in order to fine tune the function boundaries. 
        
@param nfn: structure to fill with information \\ nfn->start_ea points to the start address of the new function.
@param flags: Find function bounds flags
@returns Find function bounds result codes"""
    return _ida_funcs.find_func_bounds(nfn, flags)


FIND_FUNC_NORMAL = _ida_funcs.FIND_FUNC_NORMAL
"""stop processing if undefined byte is encountered
"""
FIND_FUNC_DEFINE = _ida_funcs.FIND_FUNC_DEFINE
"""create instruction if undefined byte is encountered
"""
FIND_FUNC_IGNOREFN = _ida_funcs.FIND_FUNC_IGNOREFN
"""ignore existing function boundaries. by default the function returns function boundaries if ea belongs to a function. 
        """
FIND_FUNC_KEEPBD = _ida_funcs.FIND_FUNC_KEEPBD
"""do not modify incoming function boundaries, just create instructions inside the boundaries. 
        """
FIND_FUNC_UNDEF = _ida_funcs.FIND_FUNC_UNDEF
"""function has instructions that pass execution flow to unexplored bytes. nfn->end_ea will have the address of the unexplored byte. 
        """
FIND_FUNC_OK = _ida_funcs.FIND_FUNC_OK
"""ok, 'nfn' is ready for add_func()
"""
FIND_FUNC_EXIST = _ida_funcs.FIND_FUNC_EXIST
"""function exists already. its bounds are returned in 'nfn'. 
        """


def get_func_name(ea: ida_idaapi.ea_t) ->str:
    """Get function name. 
        
@param ea: any address in the function
@returns length of the function name"""
    return _ida_funcs.get_func_name(ea)


def calc_func_size(pfn: 'func_t') ->'asize_t':
    """Calculate function size. This function takes into account all fragments of the function. 
        
@param pfn: ptr to function structure"""
    return _ida_funcs.calc_func_size(pfn)


def get_func_bitness(pfn: 'func_t') ->int:
    """Get function bitness (which is equal to the function segment bitness). pfn==nullptr => returns 0 
        
@retval 0: 16
@retval 1: 32
@retval 2: 64"""
    return _ida_funcs.get_func_bitness(pfn)


def get_func_bits(pfn: 'func_t') ->int:
    """Get number of bits in the function addressing.
"""
    return _ida_funcs.get_func_bits(pfn)


def get_func_bytes(pfn: 'func_t') ->int:
    """Get number of bytes in the function addressing.
"""
    return _ida_funcs.get_func_bytes(pfn)


def is_visible_func(pfn: 'func_t') ->bool:
    """Is the function visible (not hidden)?
"""
    return _ida_funcs.is_visible_func(pfn)


def is_finally_visible_func(pfn: 'func_t') ->bool:
    """Is the function visible (event after considering SCF_SHHID_FUNC)?
"""
    return _ida_funcs.is_finally_visible_func(pfn)


def set_visible_func(pfn: 'func_t', visible: bool) ->None:
    """Set visibility of function.
"""
    return _ida_funcs.set_visible_func(pfn, visible)


def set_func_name_if_jumpfunc(pfn: 'func_t', oldname: str) ->int:
    """Give a meaningful name to function if it consists of only 'jump' instruction. 
        
@param pfn: pointer to function (may be nullptr)
@param oldname: old name of function. if old name was in "j_..." form, then we may discard it and set a new name. if oldname is not known, you may pass nullptr.
@returns success"""
    return _ida_funcs.set_func_name_if_jumpfunc(pfn, oldname)


def calc_thunk_func_target(pfn: 'func_t') ->'ea_t *':
    """Calculate target of a thunk function. 
        
@param pfn: pointer to function (may not be nullptr)
@returns the target function or BADADDR"""
    return _ida_funcs.calc_thunk_func_target(pfn)


def func_does_return(callee: ida_idaapi.ea_t) ->bool:
    """Does the function return?. To calculate the answer, FUNC_NORET flag and is_noret() are consulted The latter is required for imported functions in the .idata section. Since in .idata we have only function pointers but not functions, we have to introduce a special flag for them. 
        """
    return _ida_funcs.func_does_return(callee)


def reanalyze_noret_flag(ea: ida_idaapi.ea_t) ->bool:
    """Plan to reanalyze noret flag. This function does not remove FUNC_NORET if it is already present. It just plans to reanalysis. 
        """
    return _ida_funcs.reanalyze_noret_flag(ea)


def set_noret_insn(insn_ea: ida_idaapi.ea_t, noret: bool) ->bool:
    """Signal a non-returning instruction. This function can be used by the processor module to tell the kernel about non-returning instructions (like call exit). The kernel will perform the global function analysis and find out if the function returns at all. This analysis will be done at the first call to func_does_return() 
        
@returns true if the instruction 'noret' flag has been changed"""
    return _ida_funcs.set_noret_insn(insn_ea, noret)


def get_fchunk(ea: ida_idaapi.ea_t) ->'func_t *':
    """Get pointer to function chunk structure by address. 
        
@param ea: any address in a function chunk
@returns ptr to a function chunk or nullptr. This function may return a function entry as well as a function tail."""
    return _ida_funcs.get_fchunk(ea)


def getn_fchunk(n: int) ->'func_t *':
    """Get pointer to function chunk structure by number. 
        
@param n: number of function chunk, is in range 0..get_fchunk_qty()-1
@returns ptr to a function chunk or nullptr. This function may return a function entry as well as a function tail."""
    return _ida_funcs.getn_fchunk(n)


def get_fchunk_qty() ->'size_t':
    """Get total number of function chunks in the program.
"""
    return _ida_funcs.get_fchunk_qty()


def get_fchunk_num(ea: ida_idaapi.ea_t) ->int:
    """Get ordinal number of a function chunk in the global list of function chunks. 
        
@param ea: any address in the function chunk
@returns number of function chunk (0..get_fchunk_qty()-1). -1 means 'no function chunk at the specified address'."""
    return _ida_funcs.get_fchunk_num(ea)


def get_prev_fchunk(ea: ida_idaapi.ea_t) ->'func_t *':
    """Get pointer to the previous function chunk in the global list. 
        
@param ea: any address in the program
@returns ptr to function chunk or nullptr if previous function chunk doesn't exist"""
    return _ida_funcs.get_prev_fchunk(ea)


def get_next_fchunk(ea: ida_idaapi.ea_t) ->'func_t *':
    """Get pointer to the next function chunk in the global list. 
        
@param ea: any address in the program
@returns ptr to function chunk or nullptr if next function chunk doesn't exist"""
    return _ida_funcs.get_next_fchunk(ea)


def append_func_tail(pfn: 'func_t', ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t
    ) ->bool:
    """Append a new tail chunk to the function definition. If the tail already exists, then it will simply be added to the function tail list Otherwise a new tail will be created and its owner will be set to be our function If a new tail cannot be created, then this function will fail. 
        
@param pfn: pointer to the function
@param ea1: start of the tail. If a tail already exists at the specified address it must start at 'ea1'
@param ea2: end of the tail. If a tail already exists at the specified address it must end at 'ea2'. If specified as BADADDR, IDA will determine the end address itself."""
    return _ida_funcs.append_func_tail(pfn, ea1, ea2)


def remove_func_tail(pfn: 'func_t', tail_ea: ida_idaapi.ea_t) ->bool:
    """Remove a function tail. If the tail belongs only to one function, it will be completely removed. Otherwise if the function was the tail owner, the first function using this tail becomes the owner of the tail. 
        
@param pfn: pointer to the function
@param tail_ea: any address inside the tail to remove"""
    return _ida_funcs.remove_func_tail(pfn, tail_ea)


def set_tail_owner(fnt: 'func_t', new_owner: ida_idaapi.ea_t) ->bool:
    """Set a new owner of a function tail. The new owner function must be already referring to the tail (after append_func_tail). 
        
@param fnt: pointer to the function tail
@param new_owner: the entry point of the new owner function"""
    return _ida_funcs.set_tail_owner(fnt, new_owner)


def func_tail_iterator_set(fti: 'func_tail_iterator_t', pfn: 'func_t', ea:
    ida_idaapi.ea_t) ->bool:
    return _ida_funcs.func_tail_iterator_set(fti, pfn, ea)


def func_tail_iterator_set_ea(fti: 'func_tail_iterator_t', ea: ida_idaapi.ea_t
    ) ->bool:
    return _ida_funcs.func_tail_iterator_set_ea(fti, ea)


def func_parent_iterator_set(fpi: 'func_parent_iterator_t', pfn: 'func_t'
    ) ->bool:
    return _ida_funcs.func_parent_iterator_set(fpi, pfn)


def f_any(arg1: 'flags64_t', arg2: 'void *') ->bool:
    """Helper function to accept any address.
"""
    return _ida_funcs.f_any(arg1, arg2)


class func_tail_iterator_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_funcs.func_tail_iterator_t_swiginit(self, _ida_funcs.
            new_func_tail_iterator_t(*args))
    __swig_destroy__ = _ida_funcs.delete_func_tail_iterator_t

    def set(self, *args) ->bool:
        return _ida_funcs.func_tail_iterator_t_set(self, *args)

    def set_ea(self, ea: ida_idaapi.ea_t) ->bool:
        return _ida_funcs.func_tail_iterator_t_set_ea(self, ea)

    def set_range(self, ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t) ->bool:
        return _ida_funcs.func_tail_iterator_t_set_range(self, ea1, ea2)

    def chunk(self) ->'range_t const &':
        return _ida_funcs.func_tail_iterator_t_chunk(self)

    def first(self) ->bool:
        return _ida_funcs.func_tail_iterator_t_first(self)

    def last(self) ->bool:
        return _ida_funcs.func_tail_iterator_t_last(self)

    def __next__(self) ->bool:
        return _ida_funcs.func_tail_iterator_t___next__(self)

    def prev(self) ->bool:
        return _ida_funcs.func_tail_iterator_t_prev(self)

    def main(self) ->bool:
        return _ida_funcs.func_tail_iterator_t_main(self)

    def __iter__(self):
        """
        Provide an iterator on function tails
        """
        ok = self.main()
        while ok:
            yield self.chunk()
            ok = self.next()
    next = __next__


_ida_funcs.func_tail_iterator_t_swigregister(func_tail_iterator_t)


class func_item_iterator_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_funcs.func_item_iterator_t_swiginit(self, _ida_funcs.
            new_func_item_iterator_t(*args))

    def set(self, *args) ->bool:
        """Set a function range. if pfn == nullptr then a segment range will be set.
"""
        return _ida_funcs.func_item_iterator_t_set(self, *args)

    def set_range(self, ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t) ->bool:
        """Set an arbitrary range.
"""
        return _ida_funcs.func_item_iterator_t_set_range(self, ea1, ea2)

    def first(self) ->bool:
        return _ida_funcs.func_item_iterator_t_first(self)

    def last(self) ->bool:
        return _ida_funcs.func_item_iterator_t_last(self)

    def current(self) ->ida_idaapi.ea_t:
        return _ida_funcs.func_item_iterator_t_current(self)

    def set_ea(self, _ea: ida_idaapi.ea_t) ->bool:
        return _ida_funcs.func_item_iterator_t_set_ea(self, _ea)

    def chunk(self) ->'range_t const &':
        return _ida_funcs.func_item_iterator_t_chunk(self)

    def __next__(self, func: 'testf_t *') ->bool:
        return _ida_funcs.func_item_iterator_t___next__(self, func)

    def prev(self, func: 'testf_t *') ->bool:
        return _ida_funcs.func_item_iterator_t_prev(self, func)

    def next_addr(self) ->bool:
        return _ida_funcs.func_item_iterator_t_next_addr(self)

    def next_head(self) ->bool:
        return _ida_funcs.func_item_iterator_t_next_head(self)

    def next_code(self) ->bool:
        return _ida_funcs.func_item_iterator_t_next_code(self)

    def next_data(self) ->bool:
        return _ida_funcs.func_item_iterator_t_next_data(self)

    def next_not_tail(self) ->bool:
        return _ida_funcs.func_item_iterator_t_next_not_tail(self)

    def prev_addr(self) ->bool:
        return _ida_funcs.func_item_iterator_t_prev_addr(self)

    def prev_head(self) ->bool:
        return _ida_funcs.func_item_iterator_t_prev_head(self)

    def prev_code(self) ->bool:
        return _ida_funcs.func_item_iterator_t_prev_code(self)

    def prev_data(self) ->bool:
        return _ida_funcs.func_item_iterator_t_prev_data(self)

    def prev_not_tail(self) ->bool:
        return _ida_funcs.func_item_iterator_t_prev_not_tail(self)

    def decode_prev_insn(self, out: 'insn_t *') ->bool:
        return _ida_funcs.func_item_iterator_t_decode_prev_insn(self, out)

    def decode_preceding_insn(self, visited: 'eavec_t *', p_farref:
        'bool *', out: 'insn_t *') ->bool:
        return _ida_funcs.func_item_iterator_t_decode_preceding_insn(self,
            visited, p_farref, out)

    def succ(self, func: 'testf_t *') ->bool:
        """Similar to next(), but succ() iterates the chunks from low to high addresses, while next() iterates through chunks starting at the function entry chunk 
        """
        return _ida_funcs.func_item_iterator_t_succ(self, func)

    def succ_code(self) ->bool:
        return _ida_funcs.func_item_iterator_t_succ_code(self)

    def __iter__(self):
        """
        Provide an iterator on code items
        """
        ok = self.first()
        while ok:
            yield self.current()
            ok = self.next_code()
    next = __next__

    def addresses(self):
        """
        Provide an iterator on addresses contained within the function
        """
        ok = self.first()
        while ok:
            yield self.current()
            ok = self.next_addr()

    def code_items(self):
        """
        Provide an iterator on code items contained within the function
        """
        ok = self.first()
        while ok:
            yield self.current()
            ok = self.next_code()

    def data_items(self):
        """
        Provide an iterator on data items contained within the function
        """
        ok = self.first()
        while ok:
            yield self.current()
            ok = self.next_data()

    def head_items(self):
        """
        Provide an iterator on item heads contained within the function
        """
        ok = self.first()
        while ok:
            yield self.current()
            ok = self.next_head()

    def not_tails(self):
        """
        Provide an iterator on non-tail addresses contained within the function
        """
        ok = self.first()
        while ok:
            yield self.current()
            ok = self.next_not_tail()
    __swig_destroy__ = _ida_funcs.delete_func_item_iterator_t


_ida_funcs.func_item_iterator_t_swigregister(func_item_iterator_t)


class func_parent_iterator_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_funcs.func_parent_iterator_t_swiginit(self, _ida_funcs.
            new_func_parent_iterator_t(*args))
    __swig_destroy__ = _ida_funcs.delete_func_parent_iterator_t

    def set(self, _fnt: 'func_t') ->bool:
        return _ida_funcs.func_parent_iterator_t_set(self, _fnt)

    def parent(self) ->ida_idaapi.ea_t:
        return _ida_funcs.func_parent_iterator_t_parent(self)

    def first(self) ->bool:
        return _ida_funcs.func_parent_iterator_t_first(self)

    def last(self) ->bool:
        return _ida_funcs.func_parent_iterator_t_last(self)

    def __next__(self) ->bool:
        return _ida_funcs.func_parent_iterator_t___next__(self)

    def prev(self) ->bool:
        return _ida_funcs.func_parent_iterator_t_prev(self)

    def reset_fnt(self, _fnt: 'func_t') ->None:
        return _ida_funcs.func_parent_iterator_t_reset_fnt(self, _fnt)

    def __iter__(self):
        """
        Provide an iterator on function parents
        """
        ok = self.first()
        while ok:
            yield self.parent()
            ok = self.next()
    next = __next__


_ida_funcs.func_parent_iterator_t_swigregister(func_parent_iterator_t)


def get_prev_func_addr(pfn: 'func_t', ea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
    return _ida_funcs.get_prev_func_addr(pfn, ea)


def get_next_func_addr(pfn: 'func_t', ea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
    return _ida_funcs.get_next_func_addr(pfn, ea)


def read_regargs(pfn: 'func_t') ->None:
    return _ida_funcs.read_regargs(pfn)


def add_regarg(pfn: 'func_t', reg: int, tif: 'tinfo_t', name: str) ->None:
    return _ida_funcs.add_regarg(pfn, reg, tif, name)


IDASGN_OK = _ida_funcs.IDASGN_OK
"""ok
"""
IDASGN_BADARG = _ida_funcs.IDASGN_BADARG
"""bad number of signature
"""
IDASGN_APPLIED = _ida_funcs.IDASGN_APPLIED
"""signature is already applied
"""
IDASGN_CURRENT = _ida_funcs.IDASGN_CURRENT
"""signature is currently being applied
"""
IDASGN_PLANNED = _ida_funcs.IDASGN_PLANNED
"""signature is planned to be applied
"""


def plan_to_apply_idasgn(fname: str) ->int:
    """Add a signature file to the list of planned signature files. 
        
@param fname: file name. should not contain directory part.
@returns 0 if failed, otherwise number of planned (and applied) signatures"""
    return _ida_funcs.plan_to_apply_idasgn(fname)


def apply_idasgn_to(signame: str, ea: ida_idaapi.ea_t, is_startup: bool) ->int:
    """Apply a signature file to the specified address. 
        
@param signame: short name of signature file (the file name without path)
@param ea: address to apply the signature
@param is_startup: if set, then the signature is treated as a startup one for startup signature ida doesn't rename the first function of the applied module.
@returns Library function codes"""
    return _ida_funcs.apply_idasgn_to(signame, ea, is_startup)


def get_idasgn_qty() ->int:
    """Get number of signatures in the list of planned and applied signatures. 
        
@returns 0..n"""
    return _ida_funcs.get_idasgn_qty()


def get_current_idasgn() ->int:
    """Get number of the the current signature. 
        
@returns 0..n-1"""
    return _ida_funcs.get_current_idasgn()


def calc_idasgn_state(n: int) ->int:
    """Get state of a signature in the list of planned signatures 
        
@param n: number of signature in the list (0..get_idasgn_qty()-1)
@returns state of signature or IDASGN_BADARG"""
    return _ida_funcs.calc_idasgn_state(n)


def del_idasgn(n: int) ->int:
    """Remove signature from the list of planned signatures. 
        
@param n: number of signature in the list (0..get_idasgn_qty()-1)
@returns IDASGN_OK, IDASGN_BADARG, IDASGN_APPLIED"""
    return _ida_funcs.del_idasgn(n)


def get_idasgn_title(name: str) ->str:
    """Get full description of the signature by its short name. 
        
@param name: short name of a signature
@returns size of signature description or -1"""
    return _ida_funcs.get_idasgn_title(name)


def apply_startup_sig(ea: ida_idaapi.ea_t, startup: str) ->bool:
    """Apply a startup signature file to the specified address. 
        
@param ea: address to apply the signature to; usually idainfo::start_ea
@param startup: the name of the signature file without path and extension
@returns true if successfully applied the signature"""
    return _ida_funcs.apply_startup_sig(ea, startup)


def try_to_add_libfunc(ea: ida_idaapi.ea_t) ->int:
    """Apply the currently loaded signature file to the specified address. If a library function is found, then create a function and name it accordingly. 
        
@param ea: any address in the program
@returns Library function codes"""
    return _ida_funcs.try_to_add_libfunc(ea)


LIBFUNC_FOUND = _ida_funcs.LIBFUNC_FOUND
"""ok, library function is found
"""
LIBFUNC_NONE = _ida_funcs.LIBFUNC_NONE
"""no, this is not a library function
"""
LIBFUNC_DELAY = _ida_funcs.LIBFUNC_DELAY
"""no decision because of lack of information
"""


def get_fchunk_referer(ea: int, idx):
    return _ida_funcs.get_fchunk_referer(ea, idx)


def get_idasgn_desc(n):
    """Get information about a signature in the list.
It returns: (name of signature, names of optional libraries)

See also: get_idasgn_desc_with_matches

@param n: number of signature in the list (0..get_idasgn_qty()-1)
@return: None on failure or tuple(signame, optlibs)"""
    return _ida_funcs.get_idasgn_desc(n)


def get_idasgn_desc_with_matches(n):
    """Get information about a signature in the list.
It returns: (name of signature, names of optional libraries, number of matches)

@param n: number of signature in the list (0..get_idasgn_qty()-1)
@return: None on failure or tuple(signame, optlibs, nmatches)"""
    return _ida_funcs.get_idasgn_desc_with_matches(n)


def func_t__from_ptrval__(ptrval: 'size_t') ->'func_t *':
    return _ida_funcs.func_t__from_ptrval__(ptrval)


import ida_idaapi


@ida_idaapi.replfun
def calc_thunk_func_target(*args):
    """Calculate target of a thunk function. 
        
@param pfn: pointer to function (may not be nullptr)
@param fptr: out: will hold address of a function pointer (if indirect jump)
@returns the target function or BADADDR"""
    if len(args) == 2:
        pfn, rawptr = args
        target, fptr = calc_thunk_func_target.__dict__['orig'](pfn)
        import ida_pro
        ida_pro.ea_pointer.frompointer(rawptr).assign(fptr)
        return target
    else:
        return calc_thunk_func_target.__dict__['orig'](*args)

```
