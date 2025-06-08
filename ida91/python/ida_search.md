```python
"""Middle-level search functions.

They all are controlled by Search flags 
    """
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_search
else:
    import _ida_search
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
SWIG_PYTHON_LEGACY_BOOL = _ida_search.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi
SEARCH_UP = _ida_search.SEARCH_UP
"""search towards lower addresses
"""
SEARCH_DOWN = _ida_search.SEARCH_DOWN
"""search towards higher addresses
"""
SEARCH_NEXT = _ida_search.SEARCH_NEXT
"""skip the starting address when searching. this bit is useful only for search(), bin_search(), find_reg_access(). find_.. functions skip the starting address automatically. 
        """
SEARCH_CASE = _ida_search.SEARCH_CASE
"""case-sensitive search (case-insensitive otherwise)
"""
SEARCH_REGEX = _ida_search.SEARCH_REGEX
"""regular expressions in search string (supported only for the text search)
"""
SEARCH_NOBRK = _ida_search.SEARCH_NOBRK
"""do not test if the user clicked cancel to interrupt the search
"""
SEARCH_NOSHOW = _ida_search.SEARCH_NOSHOW
"""do not display the search progress/refresh screen
"""
SEARCH_IDENT = _ida_search.SEARCH_IDENT
"""search for an identifier (text search). it means that the characters before and after the match cannot be is_visible_char(). 
        """
SEARCH_BRK = _ida_search.SEARCH_BRK
"""return BADADDR if the search was cancelled.
"""
SEARCH_USE = _ida_search.SEARCH_USE
"""find_reg_access: search for a use (read access)
"""
SEARCH_DEF = _ida_search.SEARCH_DEF
"""find_reg_access: search for a definition (write access)
"""
SEARCH_USESEL = _ida_search.SEARCH_USESEL
"""query the UI for a possible current selection to limit the search to 
        """


def search_down(sflag: int) ->bool:
    """Is the SEARCH_DOWN bit set?
"""
    return _ida_search.search_down(sflag)


def find_error(ea: ida_idaapi.ea_t, sflag: int) ->'int *':
    return _ida_search.find_error(ea, sflag)


def find_notype(ea: ida_idaapi.ea_t, sflag: int) ->'int *':
    return _ida_search.find_notype(ea, sflag)


def find_unknown(ea: ida_idaapi.ea_t, sflag: int) ->ida_idaapi.ea_t:
    return _ida_search.find_unknown(ea, sflag)


def find_defined(ea: ida_idaapi.ea_t, sflag: int) ->ida_idaapi.ea_t:
    return _ida_search.find_defined(ea, sflag)


def find_suspop(ea: ida_idaapi.ea_t, sflag: int) ->'int *':
    return _ida_search.find_suspop(ea, sflag)


def find_data(ea: ida_idaapi.ea_t, sflag: int) ->ida_idaapi.ea_t:
    return _ida_search.find_data(ea, sflag)


def find_code(ea: ida_idaapi.ea_t, sflag: int) ->ida_idaapi.ea_t:
    return _ida_search.find_code(ea, sflag)


def find_not_func(ea: ida_idaapi.ea_t, sflag: int) ->ida_idaapi.ea_t:
    return _ida_search.find_not_func(ea, sflag)


def find_imm(ea: ida_idaapi.ea_t, sflag: int, search_value: int) ->'int *':
    return _ida_search.find_imm(ea, sflag, search_value)


def find_text(start_ea: ida_idaapi.ea_t, y: int, x: int, ustr: str, sflag: int
    ) ->ida_idaapi.ea_t:
    return _ida_search.find_text(start_ea, y, x, ustr, sflag)


def find_reg_access(out: 'reg_access_t', start_ea: ida_idaapi.ea_t, end_ea:
    ida_idaapi.ea_t, regname: str, sflag: int) ->ida_idaapi.ea_t:
    return _ida_search.find_reg_access(out, start_ea, end_ea, regname, sflag)

```
