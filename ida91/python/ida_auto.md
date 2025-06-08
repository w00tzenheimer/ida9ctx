```python
"""Functions that work with the autoanalyzer queue.

The autoanalyzer works when IDA is not busy processing the user keystrokes. It has several queues, each queue having its own priority. The analyzer stops when all queues are empty.
A queue contains addresses or address ranges. The addresses are kept sorted by their values. The analyzer will process all addresses from the first queue, then switch to the second queue and so on. There are no limitations on the size of the queues.
This file also contains functions that deal with the IDA status indicator and the autoanalysis indicator. You may use these functions to change the indicator value. 
    """
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_auto
else:
    import _ida_auto
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
SWIG_PYTHON_LEGACY_BOOL = _ida_auto.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi


def get_auto_state() ->'atype_t':
    """Get current state of autoanalyzer. If auto_state == AU_NONE, IDA is currently not running the analysis (it could be temporarily interrupted to perform the user's requests, for example). 
        """
    return _ida_auto.get_auto_state()


def set_auto_state(new_state: 'atype_t') ->'atype_t':
    """Set current state of autoanalyzer. 
        
@param new_state: new state of autoanalyzer
@returns previous state"""
    return _ida_auto.set_auto_state(new_state)


class auto_display_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    type: 'atype_t' = property(_ida_auto.auto_display_t_type_get, _ida_auto
        .auto_display_t_type_set)
    ea: 'ea_t' = property(_ida_auto.auto_display_t_ea_get, _ida_auto.
        auto_display_t_ea_set)
    state: 'idastate_t' = property(_ida_auto.auto_display_t_state_get,
        _ida_auto.auto_display_t_state_set)

    def __init__(self):
        _ida_auto.auto_display_t_swiginit(self, _ida_auto.new_auto_display_t())
    __swig_destroy__ = _ida_auto.delete_auto_display_t


_ida_auto.auto_display_t_swigregister(auto_display_t)
cvar = _ida_auto.cvar
AU_NONE = cvar.AU_NONE
"""placeholder, not used
"""
AU_UNK = cvar.AU_UNK
"""0: convert to unexplored
"""
AU_CODE = cvar.AU_CODE
"""1: convert to instruction
"""
AU_WEAK = cvar.AU_WEAK
"""2: convert to instruction (ida decision)
"""
AU_PROC = cvar.AU_PROC
"""3: convert to procedure start
"""
AU_TAIL = cvar.AU_TAIL
"""4: add a procedure tail
"""
AU_FCHUNK = cvar.AU_FCHUNK
"""5: find func chunks
"""
AU_USED = cvar.AU_USED
"""6: reanalyze
"""
AU_USD2 = cvar.AU_USD2
"""7: reanalyze, second pass
"""
AU_TYPE = cvar.AU_TYPE
"""8: apply type information
"""
AU_LIBF = cvar.AU_LIBF
"""9: apply signature to address
"""
AU_LBF2 = cvar.AU_LBF2
"""10: the same, second pass
"""
AU_LBF3 = cvar.AU_LBF3
"""11: the same, third pass
"""
AU_CHLB = cvar.AU_CHLB
"""12: load signature file (file name is kept separately)
"""
AU_FINAL = cvar.AU_FINAL
"""13: final pass
"""
st_Ready = cvar.st_Ready
"""READY: IDA is doing nothing.
"""
st_Think = cvar.st_Think
"""THINKING: Autoanalysis on, the user may press keys.
"""
st_Waiting = cvar.st_Waiting
"""WAITING: Waiting for the user input.
"""
st_Work = cvar.st_Work
"""BUSY: IDA is busy.
"""


def get_auto_display(auto_display: 'auto_display_t') ->bool:
    """Get structure which holds the autoanalysis indicator contents.
"""
    return _ida_auto.get_auto_display(auto_display)


def show_auto(*args) ->None:
    """Change autoanalysis indicator value. 
        
@param ea: linear address being analyzed
@param type: autoanalysis type (see Autoanalysis queues)"""
    return _ida_auto.show_auto(*args)


def show_addr(ea: ida_idaapi.ea_t) ->None:
    """Show an address on the autoanalysis indicator. The address is displayed in the form " @:12345678". 
        
@param ea: - linear address to display"""
    return _ida_auto.show_addr(ea)


def set_ida_state(st: 'idastate_t') ->'idastate_t':
    """Change IDA status indicator value 
        
@param st: - new indicator status
@returns old indicator status"""
    return _ida_auto.set_ida_state(st)


def may_create_stkvars() ->bool:
    """Is it allowed to create stack variables automatically?. This function should be used by IDP modules before creating stack vars. 
        """
    return _ida_auto.may_create_stkvars()


def may_trace_sp() ->bool:
    """Is it allowed to trace stack pointer automatically?. This function should be used by IDP modules before tracing sp. 
        """
    return _ida_auto.may_trace_sp()


def auto_mark_range(start: ida_idaapi.ea_t, end: ida_idaapi.ea_t, type:
    'atype_t') ->None:
    """Put range of addresses into a queue. 'start' may be higher than 'end', the kernel will swap them in this case. 'end' doesn't belong to the range. 
        """
    return _ida_auto.auto_mark_range(start, end, type)


def auto_mark(ea: ida_idaapi.ea_t, type: 'atype_t') ->None:
    """Put single address into a queue. Queues keep addresses sorted.
"""
    return _ida_auto.auto_mark(ea, type)


def auto_unmark(start: ida_idaapi.ea_t, end: ida_idaapi.ea_t, type: 'atype_t'
    ) ->None:
    """Remove range of addresses from a queue. 'start' may be higher than 'end', the kernel will swap them in this case. 'end' doesn't belong to the range. 
        """
    return _ida_auto.auto_unmark(start, end, type)


def plan_ea(ea: ida_idaapi.ea_t) ->None:
    """Plan to perform reanalysis.
"""
    return _ida_auto.plan_ea(ea)


def plan_range(sEA: ida_idaapi.ea_t, eEA: ida_idaapi.ea_t) ->None:
    """Plan to perform reanalysis.
"""
    return _ida_auto.plan_range(sEA, eEA)


def auto_make_code(ea: ida_idaapi.ea_t) ->None:
    """Plan to make code.
"""
    return _ida_auto.auto_make_code(ea)


def auto_make_proc(ea: ida_idaapi.ea_t) ->None:
    """Plan to make code&function.
"""
    return _ida_auto.auto_make_proc(ea)


def auto_postpone_analysis(ea: ida_idaapi.ea_t) ->bool:
    """Plan to reanalyze on the second pass The typical usage of this function in emu.cpp is: if ( !auto_postpone_analysis(ea) ) op_offset(ea, 0, ...); (we make an offset only on the second pass) 
        """
    return _ida_auto.auto_postpone_analysis(ea)


def reanalyze_callers(ea: ida_idaapi.ea_t, noret: bool) ->None:
    """Plan to reanalyze callers of the specified address. This function will add to AU_USED queue all instructions that call (not jump to) the specified address. 
        
@param ea: linear address of callee
@param noret: !=0: the callee doesn't return, mark to undefine subsequent instructions in the caller. 0: do nothing."""
    return _ida_auto.reanalyze_callers(ea, noret)


def revert_ida_decisions(ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t) ->None:
    """Delete all analysis info that IDA generated for for the given range.
"""
    return _ida_auto.revert_ida_decisions(ea1, ea2)


def auto_apply_type(caller: ida_idaapi.ea_t, callee: ida_idaapi.ea_t) ->None:
    """Plan to apply the callee's type to the calling point.
"""
    return _ida_auto.auto_apply_type(caller, callee)


def auto_apply_tail(tail_ea: ida_idaapi.ea_t, parent_ea: ida_idaapi.ea_t
    ) ->None:
    """Plan to apply the tail_ea chunk to the parent 
        
@param tail_ea: linear address of start of tail
@param parent_ea: linear address within parent. If BADADDR, automatically try to find parent via xrefs."""
    return _ida_auto.auto_apply_tail(tail_ea, parent_ea)


def plan_and_wait(ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t, final_pass:
    bool=True) ->int:
    """Analyze the specified range. Try to create instructions where possible. Make the final pass over the specified range if specified. This function doesn't return until the range is analyzed. 
        
@retval 1: ok
@retval 0: Ctrl-Break was pressed"""
    return _ida_auto.plan_and_wait(ea1, ea2, final_pass)


def auto_wait() ->bool:
    """Process everything in the queues and return true. 
        
@returns false if the user clicked cancel. (the wait box must be displayed by the caller if desired)"""
    return _ida_auto.auto_wait()


def auto_wait_range(ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t) ->'ssize_t':
    """Process everything in the specified range and return true. 
        
@returns number of autoanalysis steps made. -1 if the user clicked cancel. (the wait box must be displayed by the caller if desired)"""
    return _ida_auto.auto_wait_range(ea1, ea2)


def auto_make_step(ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t) ->bool:
    """Analyze one address in the specified range and return true. 
        
@returns if processed anything. false means that there is nothing to process in the specified range."""
    return _ida_auto.auto_make_step(ea1, ea2)


def auto_cancel(ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t) ->None:
    """Remove an address range (ea1..ea2) from queues AU_CODE, AU_PROC, AU_USED. To remove an address range from other queues use auto_unmark() function. 'ea1' may be higher than 'ea2', the kernel will swap them in this case. 'ea2' doesn't belong to the range. 
        """
    return _ida_auto.auto_cancel(ea1, ea2)


def auto_is_ok() ->bool:
    """Are all queues empty? (i.e. has autoanalysis finished?). 
        """
    return _ida_auto.auto_is_ok()


def peek_auto_queue(low_ea: ida_idaapi.ea_t, type: 'atype_t'
    ) ->ida_idaapi.ea_t:
    """Peek into a queue 'type' for an address not lower than 'low_ea'. Do not remove address from the queue. 
        
@returns the address or BADADDR"""
    return _ida_auto.peek_auto_queue(low_ea, type)


def auto_get(type: 'atype_t *', lowEA: ida_idaapi.ea_t, highEA: ida_idaapi.ea_t
    ) ->ida_idaapi.ea_t:
    """Retrieve an address from queues regarding their priority. Returns BADADDR if no addresses not lower than 'lowEA' and less than 'highEA' are found in the queues. Otherwise *type will have queue type. 
        """
    return _ida_auto.auto_get(type, lowEA, highEA)


def auto_recreate_insn(ea: ida_idaapi.ea_t) ->int:
    """Try to create instruction 
        
@param ea: linear address of callee
@returns the length of the instruction or 0"""
    return _ida_auto.auto_recreate_insn(ea)


def is_auto_enabled() ->bool:
    """Get autoanalyzer state.
"""
    return _ida_auto.is_auto_enabled()


def enable_auto(enable: bool) ->bool:
    """Temporarily enable/disable autoanalyzer. Not user-facing, but rather because IDA sometimes need to turn AA on/off regardless of inf.s_genflags:INFFL_AUTO 
        
@returns old state"""
    return _ida_auto.enable_auto(enable)

```
