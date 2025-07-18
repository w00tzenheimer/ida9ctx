```python
"""Functions that deal with the segment registers.

If your processor doesn't use segment registers, then these functions are of no use for you. However, you should define two virtual segment registers - CS and DS (for code segment and data segment) and specify their internal numbers in the LPH structure (processor_t::reg_code_sreg and processor_t::reg_data_sreg). 
    """
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_segregs
else:
    import _ida_segregs
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
SWIG_PYTHON_LEGACY_BOOL = _ida_segregs.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi
import ida_range
R_es = _ida_segregs.R_es
R_cs = _ida_segregs.R_cs
R_ss = _ida_segregs.R_ss
R_ds = _ida_segregs.R_ds
R_fs = _ida_segregs.R_fs
R_gs = _ida_segregs.R_gs


class sreg_range_t(ida_range.range_t):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    val: 'sel_t' = property(_ida_segregs.sreg_range_t_val_get, _ida_segregs
        .sreg_range_t_val_set)
    """segment register value
"""
    tag: 'uchar' = property(_ida_segregs.sreg_range_t_tag_get, _ida_segregs
        .sreg_range_t_tag_set)
    """Segment register range tags
"""

    def __init__(self):
        _ida_segregs.sreg_range_t_swiginit(self, _ida_segregs.
            new_sreg_range_t())
    __swig_destroy__ = _ida_segregs.delete_sreg_range_t


_ida_segregs.sreg_range_t_swigregister(sreg_range_t)
SR_inherit = _ida_segregs.SR_inherit
"""the value is inherited from the previous range
"""
SR_user = _ida_segregs.SR_user
"""the value is specified by the user
"""
SR_auto = _ida_segregs.SR_auto
"""the value is determined by IDA
"""
SR_autostart = _ida_segregs.SR_autostart
"""used as SR_auto for segment starting address
"""


def get_sreg(ea: ida_idaapi.ea_t, rg: int) ->'sel_t':
    """Get value of a segment register. This function uses segment register range and default segment register values stored in the segment structure. 
        
@param ea: linear address in the program
@param rg: number of the segment register
@returns value of the segment register, BADSEL if value is unknown or rg is not a segment register."""
    return _ida_segregs.get_sreg(ea, rg)


def split_sreg_range(ea: ida_idaapi.ea_t, rg: int, v: 'sel_t', tag: 'uchar',
    silent: bool=False) ->bool:
    """Create a new segment register range. This function is used when the IDP emulator detects that a segment register changes its value. 
        
@param ea: linear address where the segment register will have a new value. if ea==BADADDR, nothing to do.
@param rg: the number of the segment register
@param v: the new value of the segment register. If the value is unknown, you should specify BADSEL.
@param tag: the register info tag. see Segment register range tags
@param silent: if false, display a warning() in the case of failure
@returns success"""
    return _ida_segregs.split_sreg_range(ea, rg, v, tag, silent)


def set_default_sreg_value(sg: 'segment_t *', rg: int, value: 'sel_t') ->bool:
    """Set default value of a segment register for a segment. 
        
@param sg: pointer to segment structure if nullptr, then set the register for all segments
@param rg: number of segment register
@param value: its default value. this value will be used by get_sreg() if value of the register is unknown at the specified address.
@returns success"""
    return _ida_segregs.set_default_sreg_value(sg, rg, value)


def set_sreg_at_next_code(ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t, rg:
    int, value: 'sel_t') ->None:
    """Set the segment register value at the next instruction. This function is designed to be called from idb_event::sgr_changed handler in order to contain the effect of changing a segment register value only until the next instruction.
It is useful, for example, in the ARM module: the modification of the T register does not affect existing instructions later in the code. 
        
@param ea1: address to start to search for an instruction
@param ea2: the maximal address
@param rg: the segment register number
@param value: the segment register value"""
    return _ida_segregs.set_sreg_at_next_code(ea1, ea2, rg, value)


def get_sreg_range(out: 'sreg_range_t', ea: ida_idaapi.ea_t, rg: int) ->bool:
    """Get segment register range by linear address. 
        
@param out: segment register range
@param ea: any linear address in the program
@param rg: the segment register number
@returns success"""
    return _ida_segregs.get_sreg_range(out, ea, rg)


def get_prev_sreg_range(out: 'sreg_range_t', ea: ida_idaapi.ea_t, rg: int
    ) ->bool:
    """Get segment register range previous to one with address. 
        
@param out: segment register range
@param ea: any linear address in the program
@param rg: the segment register number
@returns success"""
    return _ida_segregs.get_prev_sreg_range(out, ea, rg)


def set_default_dataseg(ds_sel: 'sel_t') ->None:
    """Set default value of DS register for all segments.
"""
    return _ida_segregs.set_default_dataseg(ds_sel)


def get_sreg_ranges_qty(rg: int) ->'size_t':
    """Get number of segment register ranges. 
        
@param rg: the segment register number"""
    return _ida_segregs.get_sreg_ranges_qty(rg)


def getn_sreg_range(out: 'sreg_range_t', rg: int, n: int) ->bool:
    """Get segment register range by its number. 
        
@param out: segment register range
@param rg: the segment register number
@param n: number of range (0..qty()-1)
@returns success"""
    return _ida_segregs.getn_sreg_range(out, rg, n)


def get_sreg_range_num(ea: ida_idaapi.ea_t, rg: int) ->int:
    """Get number of segment register range by address. 
        
@param ea: any address in the range
@param rg: the segment register number
@returns -1 if no range occupies the specified address. otherwise returns number of the specified range (0..get_srranges_qty()-1)"""
    return _ida_segregs.get_sreg_range_num(ea, rg)


def del_sreg_range(ea: ida_idaapi.ea_t, rg: int) ->bool:
    """Delete segment register range started at ea. When a segment register range is deleted, the previous range is extended to cover the empty space. The segment register range at the beginning of a segment cannot be deleted. 
        
@param ea: start_ea of the deleted range
@param rg: the segment register number
@returns success"""
    return _ida_segregs.del_sreg_range(ea, rg)


def copy_sreg_ranges(dst_rg: int, src_rg: int, map_selector: bool=False
    ) ->None:
    """Duplicate segment register ranges. 
        
@param dst_rg: number of destination segment register
@param src_rg: copy ranges from
@param map_selector: map selectors to linear addresses using sel2ea()"""
    return _ida_segregs.copy_sreg_ranges(dst_rg, src_rg, map_selector)

```
