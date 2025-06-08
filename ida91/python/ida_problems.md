```python
"""Functions that deal with the list of problems.

There are several problem lists. An address may be inserted to any list. The kernel simply maintains these lists, no additional processing is done.
The problem lists are accessible for the user from the View->Subviews->Problems menu item.
Addresses in the lists are kept sorted. In general IDA just maintains these lists without using them during analysis (except PR_ROLLED). 
    """
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_problems
else:
    import _ida_problems
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
SWIG_PYTHON_LEGACY_BOOL = _ida_problems.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi


def get_problem_desc(t: 'problist_id_t', ea: ida_idaapi.ea_t) ->str:
    """Get the human-friendly description of the problem, if one was provided to remember_problem. 
        
@param t: problem list type.
@param ea: linear address.
@returns the message length or -1 if none"""
    return _ida_problems.get_problem_desc(t, ea)


def remember_problem(type: 'problist_id_t', ea: ida_idaapi.ea_t, msg: str=None
    ) ->None:
    """Insert an address to a list of problems. Display a message saying about the problem (except of PR_ATTN,PR_FINAL) PR_JUMP is temporarily ignored. 
        
@param type: problem list type
@param ea: linear address
@param msg: a user-friendly message to be displayed instead of the default more generic one associated with the type of problem. Defaults to nullptr."""
    return _ida_problems.remember_problem(type, ea, msg)


def get_problem(type: 'problist_id_t', lowea: ida_idaapi.ea_t
    ) ->ida_idaapi.ea_t:
    """Get an address from the specified problem list. The address is not removed from the list. 
        
@param type: problem list type
@param lowea: the returned address will be higher or equal than the specified address
@returns linear address or BADADDR"""
    return _ida_problems.get_problem(type, lowea)


def forget_problem(type: 'problist_id_t', ea: ida_idaapi.ea_t) ->bool:
    """Remove an address from a problem list 
        
@param type: problem list type
@param ea: linear address
@returns success"""
    return _ida_problems.forget_problem(type, ea)


def get_problem_name(type: 'problist_id_t', longname: bool=True) ->str:
    """Get problem list description.
"""
    return _ida_problems.get_problem_name(type, longname)


def is_problem_present(t: 'problist_id_t', ea: ida_idaapi.ea_t) ->bool:
    """Check if the specified address is present in the problem list.
"""
    return _ida_problems.is_problem_present(t, ea)


def was_ida_decision(ea: ida_idaapi.ea_t) ->bool:
    return _ida_problems.was_ida_decision(ea)


cvar = _ida_problems.cvar
PR_NOBASE = cvar.PR_NOBASE
"""Can't find offset base.
"""
PR_NONAME = cvar.PR_NONAME
"""Can't find name.
"""
PR_NOFOP = cvar.PR_NOFOP
"""Can't find forced op (not used anymore)
"""
PR_NOCMT = cvar.PR_NOCMT
"""Can't find comment (not used anymore)
"""
PR_NOXREFS = cvar.PR_NOXREFS
"""Can't find references.
"""
PR_JUMP = cvar.PR_JUMP
"""Jump by table !!!! ignored.
"""
PR_DISASM = cvar.PR_DISASM
"""Can't disasm.
"""
PR_HEAD = cvar.PR_HEAD
"""Already head.
"""
PR_ILLADDR = cvar.PR_ILLADDR
"""Exec flows beyond limits.
"""
PR_MANYLINES = cvar.PR_MANYLINES
"""Too many lines.
"""
PR_BADSTACK = cvar.PR_BADSTACK
"""Failed to trace the value of the stack pointer.
"""
PR_ATTN = cvar.PR_ATTN
"""Attention! Probably erroneous situation.
"""
PR_FINAL = cvar.PR_FINAL
"""Decision to convert to instruction/data is made by IDA.
"""
PR_ROLLED = cvar.PR_ROLLED
"""The decision made by IDA was wrong and rolled back.
"""
PR_COLLISION = cvar.PR_COLLISION
"""FLAIR collision: the function with the given name already exists.
"""
PR_DECIMP = cvar.PR_DECIMP
"""FLAIR match indecision: the patterns matched, but not the function(s) being referenced.
"""
PR_END = cvar.PR_END
"""Number of problem types.
"""

```
