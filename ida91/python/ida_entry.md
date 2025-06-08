```python
"""Functions that deal with entry points.

Exported functions are considered as entry points as well.
IDA maintains list of entry points to the program. Each entry point:
* has an address
* has a name
* may have an ordinal number 


    """
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_entry
else:
    import _ida_entry
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
SWIG_PYTHON_LEGACY_BOOL = _ida_entry.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi


def get_entry_qty() ->'size_t':
    """Get number of entry points.
"""
    return _ida_entry.get_entry_qty()


AEF_UTF8 = _ida_entry.AEF_UTF8
"""the name is given in UTF-8 (default)
"""
AEF_IDBENC = _ida_entry.AEF_IDBENC
"""the name is given in the IDB encoding; non-ASCII bytes will be decoded accordingly. Specifying AEF_IDBENC also implies AEF_NODUMMY 
        """
AEF_NODUMMY = _ida_entry.AEF_NODUMMY
"""automatically prepend the name with '_' if it begins with a dummy suffix. See also AEF_IDBENC 
        """


def add_entry(ord: int, ea: ida_idaapi.ea_t, name: str, makecode: bool,
    flags: int=0) ->bool:
    """Add an entry point to the list of entry points. 
        
@param ord: ordinal number if ordinal number is equal to 'ea' then ordinal is not used
@param ea: linear address
@param name: name of entry point. If the specified location already has a name, the old name will be appended to the regular comment. If name == nullptr, then the old name will be retained.
@param makecode: should the kernel convert bytes at the entry point to instruction(s)
@param flags: See AEF_*
@returns success (currently always true)"""
    return _ida_entry.add_entry(ord, ea, name, makecode, flags)


def get_entry_ordinal(idx: 'size_t') ->int:
    """Get ordinal number of an entry point. 
        
@param idx: internal number of entry point. Should be in the range 0..get_entry_qty()-1
@returns ordinal number or 0."""
    return _ida_entry.get_entry_ordinal(idx)


def get_entry(ord: int) ->ida_idaapi.ea_t:
    """Get entry point address by its ordinal 
        
@param ord: ordinal number of entry point
@returns address or BADADDR"""
    return _ida_entry.get_entry(ord)


def get_entry_name(ord: int) ->str:
    """Get name of the entry point by its ordinal. 
        
@param ord: ordinal number of entry point
@returns size of entry name or -1"""
    return _ida_entry.get_entry_name(ord)


def rename_entry(ord: int, name: str, flags: int=0) ->bool:
    """Rename entry point. 
        
@param ord: ordinal number of the entry point
@param name: name of entry point. If the specified location already has a name, the old name will be appended to a repeatable comment.
@param flags: See AEF_*
@returns success"""
    return _ida_entry.rename_entry(ord, name, flags)


def set_entry_forwarder(ord: int, name: str, flags: int=0) ->bool:
    """Set forwarder name for ordinal. 
        
@param ord: ordinal number of the entry point
@param name: forwarder name for entry point.
@param flags: See AEF_*
@returns success"""
    return _ida_entry.set_entry_forwarder(ord, name, flags)


def get_entry_forwarder(ord: int) ->str:
    """Get forwarder name for the entry point by its ordinal. 
        
@param ord: ordinal number of entry point
@returns size of entry forwarder name or -1"""
    return _ida_entry.get_entry_forwarder(ord)

```
