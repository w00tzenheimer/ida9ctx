```python
"""Functions that deal with fixup information.

A loader should setup fixup information using set_fixup(). 
    """
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_fixup
else:
    import _ida_fixup
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
SWIG_PYTHON_LEGACY_BOOL = _ida_fixup.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi
FIXUP_OFF8 = _ida_fixup.FIXUP_OFF8
"""8-bit offset
"""
FIXUP_OFF16 = _ida_fixup.FIXUP_OFF16
"""16-bit offset
"""
FIXUP_SEG16 = _ida_fixup.FIXUP_SEG16
"""16-bit base-logical segment base (selector)
"""
FIXUP_PTR16 = _ida_fixup.FIXUP_PTR16
"""32-bit long pointer (16-bit base:16-bit offset) 
        """
FIXUP_OFF32 = _ida_fixup.FIXUP_OFF32
"""32-bit offset
"""
FIXUP_PTR32 = _ida_fixup.FIXUP_PTR32
"""48-bit pointer (16-bit base:32-bit offset)
"""
FIXUP_HI8 = _ida_fixup.FIXUP_HI8
"""high 8 bits of 16bit offset
"""
FIXUP_HI16 = _ida_fixup.FIXUP_HI16
"""high 16 bits of 32bit offset
"""
FIXUP_LOW8 = _ida_fixup.FIXUP_LOW8
"""low 8 bits of 16bit offset
"""
FIXUP_LOW16 = _ida_fixup.FIXUP_LOW16
"""low 16 bits of 32bit offset
"""
V695_FIXUP_VHIGH = _ida_fixup.V695_FIXUP_VHIGH
"""obsolete
"""
V695_FIXUP_VLOW = _ida_fixup.V695_FIXUP_VLOW
"""obsolete
"""
FIXUP_OFF64 = _ida_fixup.FIXUP_OFF64
"""64-bit offset
"""
FIXUP_OFF8S = _ida_fixup.FIXUP_OFF8S
"""8-bit signed offset
"""
FIXUP_OFF16S = _ida_fixup.FIXUP_OFF16S
"""16-bit signed offset
"""
FIXUP_OFF32S = _ida_fixup.FIXUP_OFF32S
"""32-bit signed offset
"""
FIXUP_CUSTOM = _ida_fixup.FIXUP_CUSTOM
"""start of the custom types range
"""


def is_fixup_custom(type: 'fixup_type_t') ->bool:
    """Is fixup processed by processor module?
"""
    return _ida_fixup.is_fixup_custom(type)


FIXUPF_REL = _ida_fixup.FIXUPF_REL
"""fixup is relative to the linear address `base`. Otherwise fixup is relative to the start of the segment with `sel` selector. 
        """
FIXUPF_EXTDEF = _ida_fixup.FIXUPF_EXTDEF
"""target is a location (otherwise - segment). Use this bit if the target is a symbol rather than an offset from the beginning of a segment. 
        """
FIXUPF_UNUSED = _ida_fixup.FIXUPF_UNUSED
"""fixup is ignored by IDA
* disallows the kernel to convert operands
* this fixup is not used during output 


        """
FIXUPF_CREATED = _ida_fixup.FIXUPF_CREATED
"""fixup was not present in the input file
"""
FIXUPF_LOADER_MASK = _ida_fixup.FIXUPF_LOADER_MASK
"""additional flags. The bits from this mask are not stored in the database and can be used by the loader at its discretion. 
        """


class fixup_data_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    sel: 'sel_t' = property(_ida_fixup.fixup_data_t_sel_get, _ida_fixup.
        fixup_data_t_sel_set)
    """selector of the target segment. BADSEL means an absolute (zero based) target. 
        """
    off: 'ea_t' = property(_ida_fixup.fixup_data_t_off_get, _ida_fixup.
        fixup_data_t_off_set)
    """target offset 
        """
    displacement: 'adiff_t' = property(_ida_fixup.
        fixup_data_t_displacement_get, _ida_fixup.fixup_data_t_displacement_set
        )
    """displacement (offset from the target)
"""

    def __init__(self, *args):
        _ida_fixup.fixup_data_t_swiginit(self, _ida_fixup.new_fixup_data_t(
            *args))

    def get_type(self) ->'fixup_type_t':
        """Fixup type Types of fixups.
"""
        return _ida_fixup.fixup_data_t_get_type(self)

    def set_type(self, type_: 'fixup_type_t') ->None:
        return _ida_fixup.fixup_data_t_set_type(self, type_)

    def set_type_and_flags(self, type_: 'fixup_type_t', flags_: int=0) ->None:
        return _ida_fixup.fixup_data_t_set_type_and_flags(self, type_, flags_)

    def is_custom(self) ->bool:
        """is_fixup_custom()
"""
        return _ida_fixup.fixup_data_t_is_custom(self)

    def get_flags(self) ->int:
        """Fixup flags Fixup flags.
"""
        return _ida_fixup.fixup_data_t_get_flags(self)

    def is_extdef(self) ->bool:
        return _ida_fixup.fixup_data_t_is_extdef(self)

    def set_extdef(self) ->None:
        return _ida_fixup.fixup_data_t_set_extdef(self)

    def clr_extdef(self) ->None:
        return _ida_fixup.fixup_data_t_clr_extdef(self)

    def is_unused(self) ->bool:
        return _ida_fixup.fixup_data_t_is_unused(self)

    def set_unused(self) ->None:
        return _ida_fixup.fixup_data_t_set_unused(self)

    def clr_unused(self) ->None:
        return _ida_fixup.fixup_data_t_clr_unused(self)

    def has_base(self) ->bool:
        """Is fixup relative?
"""
        return _ida_fixup.fixup_data_t_has_base(self)

    def was_created(self) ->bool:
        """Is fixup artificial?
"""
        return _ida_fixup.fixup_data_t_was_created(self)

    def get_base(self) ->ida_idaapi.ea_t:
        """Get base of fixup. 
        """
        return _ida_fixup.fixup_data_t_get_base(self)

    def set_base(self, new_base: ida_idaapi.ea_t) ->None:
        """Set base of fixup. The target should be set before a call of this function. 
        """
        return _ida_fixup.fixup_data_t_set_base(self, new_base)

    def set_sel(self, seg: 'segment_t const *') ->None:
        return _ida_fixup.fixup_data_t_set_sel(self, seg)

    def set_target_sel(self) ->None:
        """Set selector of fixup to the target. The target should be set before a call of this function. 
        """
        return _ida_fixup.fixup_data_t_set_target_sel(self)

    def set(self, source: ida_idaapi.ea_t) ->None:
        """set_fixup()
"""
        return _ida_fixup.fixup_data_t_set(self, source)

    def get(self, source: ida_idaapi.ea_t) ->bool:
        """get_fixup()
"""
        return _ida_fixup.fixup_data_t_get(self, source)

    def get_handler(self) ->'fixup_handler_t const *':
        """get_fixup_handler()
"""
        return _ida_fixup.fixup_data_t_get_handler(self)

    def get_desc(self, source: ida_idaapi.ea_t) ->str:
        """get_fixup_desc()
"""
        return _ida_fixup.fixup_data_t_get_desc(self, source)

    def calc_size(self) ->int:
        """calc_fixup_size()
"""
        return _ida_fixup.fixup_data_t_calc_size(self)

    def get_value(self, ea: ida_idaapi.ea_t) ->int:
        """get_fixup_value()
"""
        return _ida_fixup.fixup_data_t_get_value(self, ea)

    def patch_value(self, ea: ida_idaapi.ea_t) ->bool:
        """patch_fixup_value()
"""
        return _ida_fixup.fixup_data_t_patch_value(self, ea)
    __swig_destroy__ = _ida_fixup.delete_fixup_data_t


_ida_fixup.fixup_data_t_swigregister(fixup_data_t)


def get_fixup(fd: 'fixup_data_t', source: ida_idaapi.ea_t) ->bool:
    """Get fixup information.
"""
    return _ida_fixup.get_fixup(fd, source)


def exists_fixup(source: ida_idaapi.ea_t) ->bool:
    """Check that a fixup exists at the given address.
"""
    return _ida_fixup.exists_fixup(source)


def set_fixup(source: ida_idaapi.ea_t, fd: 'fixup_data_t') ->None:
    """Set fixup information. You should fill fixup_data_t and call this function and the kernel will remember information in the database. 
        
@param source: the fixup source address, i.e. the address modified by the fixup
@param fd: fixup data"""
    return _ida_fixup.set_fixup(source, fd)


def del_fixup(source: ida_idaapi.ea_t) ->None:
    """Delete fixup information.
"""
    return _ida_fixup.del_fixup(source)


def get_first_fixup_ea() ->ida_idaapi.ea_t:
    return _ida_fixup.get_first_fixup_ea()


def get_next_fixup_ea(ea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
    return _ida_fixup.get_next_fixup_ea(ea)


def get_prev_fixup_ea(ea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
    return _ida_fixup.get_prev_fixup_ea(ea)


def get_fixup_handler(type: 'fixup_type_t') ->'fixup_handler_t const *':
    """Get handler of standard or custom fixup.
"""
    return _ida_fixup.get_fixup_handler(type)


def get_fixup_value(ea: ida_idaapi.ea_t, type: 'fixup_type_t') ->int:
    """Get the operand value. This function get fixup bytes from data or an instruction at `ea` and convert them to the operand value (maybe partially). It is opposite in meaning to the `patch_fixup_value()`. For example, FIXUP_HI8 read a byte at `ea` and shifts it left by 8 bits, or AArch64's custom fixup BRANCH26 get low 26 bits of the insn at `ea` and shifts it left by 2 bits. This function is mainly used to get a relocation addend. 
        
@param ea: address to get fixup bytes from, the size of the fixup bytes depends on the fixup type.
@param type: fixup type
@retval operand: value"""
    return _ida_fixup.get_fixup_value(ea, type)


def patch_fixup_value(ea: ida_idaapi.ea_t, fd: 'fixup_data_t') ->bool:
    """Patch the fixup bytes. This function updates data or an instruction at `ea` to the fixup bytes. For example, FIXUP_HI8 updates a byte at `ea` to the high byte of `fd->off`, or AArch64's custom fixup BRANCH26 updates low 26 bits of the insn at `ea` to the value of `fd->off` shifted right by 2. 
        
@param ea: address where data are changed, the size of the changed data depends on the fixup type.
@param fd: fixup data
@retval false: the fixup bytes do not fit (e.g. `fd->off` is greater than 0xFFFFFFC for BRANCH26). The database is changed even in this case."""
    return _ida_fixup.patch_fixup_value(ea, fd)


def get_fixup_desc(source: ida_idaapi.ea_t, fd: 'fixup_data_t') ->str:
    """Get FIXUP description comment.
"""
    return _ida_fixup.get_fixup_desc(source, fd)


def calc_fixup_size(type: 'fixup_type_t') ->int:
    """Calculate size of fixup in bytes (the number of bytes the fixup patches) 
        
@retval -1: means error"""
    return _ida_fixup.calc_fixup_size(type)


def find_custom_fixup(name: str) ->'fixup_type_t':
    return _ida_fixup.find_custom_fixup(name)


class fixup_info_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    ea: 'ea_t' = property(_ida_fixup.fixup_info_t_ea_get, _ida_fixup.
        fixup_info_t_ea_set)
    fd: 'fixup_data_t' = property(_ida_fixup.fixup_info_t_fd_get,
        _ida_fixup.fixup_info_t_fd_set)

    def __init__(self):
        _ida_fixup.fixup_info_t_swiginit(self, _ida_fixup.new_fixup_info_t())
    __swig_destroy__ = _ida_fixup.delete_fixup_info_t


_ida_fixup.fixup_info_t_swigregister(fixup_info_t)


def get_fixups(out: 'fixups_t *', ea: ida_idaapi.ea_t, size: 'asize_t') ->bool:
    return _ida_fixup.get_fixups(out, ea, size)


def contains_fixups(ea: ida_idaapi.ea_t, size: 'asize_t') ->bool:
    """Does the specified address range contain any fixup information?
"""
    return _ida_fixup.contains_fixups(ea, size)


def gen_fix_fixups(_from: ida_idaapi.ea_t, to: ida_idaapi.ea_t, size: 'asize_t'
    ) ->None:
    """Relocate the bytes with fixup information once more (generic function). This function may be called from loader_t::move_segm() if it suits the goal. If loader_t::move_segm is not defined then this function will be called automatically when moving segments or rebasing the entire program. Special parameter values (from = BADADDR, size = 0, to = delta) are used when the function is called from rebase_program(delta). 
        """
    return _ida_fixup.gen_fix_fixups(_from, to, size)


def handle_fixups_in_macro(ri: 'refinfo_t', ea: ida_idaapi.ea_t, other:
    'fixup_type_t', macro_reft_and_flags: int) ->bool:
    """Handle two fixups in a macro. We often combine two instruction that load parts of a value into one macro instruction. For example: 
       ADRP  X0, #var@PAGE
           ADD   X0, X0, #var@PAGEOFF  --> ADRL X0, var
      lui   $v0, %hi(var)
           addiu $v0, $v0, %lo(var)    --> la   $v0, var


        
@returns success ('false' means that RI was not changed)"""
    return _ida_fixup.handle_fixups_in_macro(ri, ea, other,
        macro_reft_and_flags)

```
