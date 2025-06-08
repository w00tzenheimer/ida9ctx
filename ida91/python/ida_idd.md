```python
"""Contains definition of the interface to IDD modules.

The interface consists of structures describing the target debugged processor and a debugging API. 
    """
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_idd
else:
    import _ida_idd
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
SWIG_PYTHON_LEGACY_BOOL = _ida_idd.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi
import ida_range


class excvec_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_idd.excvec_t_swiginit(self, _ida_idd.new_excvec_t(*args))
    __swig_destroy__ = _ida_idd.delete_excvec_t

    def push_back(self, *args) ->'exception_info_t &':
        return _ida_idd.excvec_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_idd.excvec_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_idd.excvec_t_size(self)

    def empty(self) ->bool:
        return _ida_idd.excvec_t_empty(self)

    def at(self, _idx: 'size_t') ->'exception_info_t const &':
        return _ida_idd.excvec_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_idd.excvec_t_qclear(self)

    def clear(self) ->None:
        return _ida_idd.excvec_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_idd.excvec_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_idd.excvec_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_idd.excvec_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_idd.excvec_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_idd.excvec_t_truncate(self)

    def swap(self, r: 'excvec_t') ->None:
        return _ida_idd.excvec_t_swap(self, r)

    def extract(self) ->'exception_info_t *':
        return _ida_idd.excvec_t_extract(self)

    def inject(self, s: 'exception_info_t', len: 'size_t') ->None:
        return _ida_idd.excvec_t_inject(self, s, len)

    def begin(self, *args) ->'qvector< exception_info_t >::const_iterator':
        return _ida_idd.excvec_t_begin(self, *args)

    def end(self, *args) ->'qvector< exception_info_t >::const_iterator':
        return _ida_idd.excvec_t_end(self, *args)

    def insert(self, it: 'exception_info_t', x: 'exception_info_t'
        ) ->'qvector< exception_info_t >::iterator':
        return _ida_idd.excvec_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< exception_info_t >::iterator':
        return _ida_idd.excvec_t_erase(self, *args)

    def __len__(self) ->'size_t':
        return _ida_idd.excvec_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'exception_info_t const &':
        return _ida_idd.excvec_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'exception_info_t') ->None:
        return _ida_idd.excvec_t___setitem__(self, i, v)

    def append(self, x: 'exception_info_t') ->None:
        return _ida_idd.excvec_t_append(self, x)

    def extend(self, x: 'excvec_t') ->None:
        return _ida_idd.excvec_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_idd.excvec_t_swigregister(excvec_t)


class procinfo_vec_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_idd.procinfo_vec_t_swiginit(self, _ida_idd.new_procinfo_vec_t(
            *args))
    __swig_destroy__ = _ida_idd.delete_procinfo_vec_t

    def push_back(self, *args) ->'process_info_t &':
        return _ida_idd.procinfo_vec_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_idd.procinfo_vec_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_idd.procinfo_vec_t_size(self)

    def empty(self) ->bool:
        return _ida_idd.procinfo_vec_t_empty(self)

    def at(self, _idx: 'size_t') ->'process_info_t const &':
        return _ida_idd.procinfo_vec_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_idd.procinfo_vec_t_qclear(self)

    def clear(self) ->None:
        return _ida_idd.procinfo_vec_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_idd.procinfo_vec_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_idd.procinfo_vec_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_idd.procinfo_vec_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_idd.procinfo_vec_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_idd.procinfo_vec_t_truncate(self)

    def swap(self, r: 'procinfo_vec_t') ->None:
        return _ida_idd.procinfo_vec_t_swap(self, r)

    def extract(self) ->'process_info_t *':
        return _ida_idd.procinfo_vec_t_extract(self)

    def inject(self, s: 'process_info_t', len: 'size_t') ->None:
        return _ida_idd.procinfo_vec_t_inject(self, s, len)

    def begin(self, *args) ->'qvector< process_info_t >::const_iterator':
        return _ida_idd.procinfo_vec_t_begin(self, *args)

    def end(self, *args) ->'qvector< process_info_t >::const_iterator':
        return _ida_idd.procinfo_vec_t_end(self, *args)

    def insert(self, it: 'process_info_t', x: 'process_info_t'
        ) ->'qvector< process_info_t >::iterator':
        return _ida_idd.procinfo_vec_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< process_info_t >::iterator':
        return _ida_idd.procinfo_vec_t_erase(self, *args)

    def __len__(self) ->'size_t':
        return _ida_idd.procinfo_vec_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'process_info_t const &':
        return _ida_idd.procinfo_vec_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'process_info_t') ->None:
        return _ida_idd.procinfo_vec_t___setitem__(self, i, v)

    def append(self, x: 'process_info_t') ->None:
        return _ida_idd.procinfo_vec_t_append(self, x)

    def extend(self, x: 'procinfo_vec_t') ->None:
        return _ida_idd.procinfo_vec_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_idd.procinfo_vec_t_swigregister(procinfo_vec_t)


class call_stack_info_vec_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_idd.call_stack_info_vec_t_swiginit(self, _ida_idd.
            new_call_stack_info_vec_t(*args))
    __swig_destroy__ = _ida_idd.delete_call_stack_info_vec_t

    def push_back(self, *args) ->'call_stack_info_t &':
        return _ida_idd.call_stack_info_vec_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_idd.call_stack_info_vec_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_idd.call_stack_info_vec_t_size(self)

    def empty(self) ->bool:
        return _ida_idd.call_stack_info_vec_t_empty(self)

    def at(self, _idx: 'size_t') ->'call_stack_info_t const &':
        return _ida_idd.call_stack_info_vec_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_idd.call_stack_info_vec_t_qclear(self)

    def clear(self) ->None:
        return _ida_idd.call_stack_info_vec_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_idd.call_stack_info_vec_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_idd.call_stack_info_vec_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_idd.call_stack_info_vec_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_idd.call_stack_info_vec_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_idd.call_stack_info_vec_t_truncate(self)

    def swap(self, r: 'call_stack_info_vec_t') ->None:
        return _ida_idd.call_stack_info_vec_t_swap(self, r)

    def extract(self) ->'call_stack_info_t *':
        return _ida_idd.call_stack_info_vec_t_extract(self)

    def inject(self, s: 'call_stack_info_t', len: 'size_t') ->None:
        return _ida_idd.call_stack_info_vec_t_inject(self, s, len)

    def __eq__(self, r: 'call_stack_info_vec_t') ->bool:
        return _ida_idd.call_stack_info_vec_t___eq__(self, r)

    def __ne__(self, r: 'call_stack_info_vec_t') ->bool:
        return _ida_idd.call_stack_info_vec_t___ne__(self, r)

    def begin(self, *args) ->'qvector< call_stack_info_t >::const_iterator':
        return _ida_idd.call_stack_info_vec_t_begin(self, *args)

    def end(self, *args) ->'qvector< call_stack_info_t >::const_iterator':
        return _ida_idd.call_stack_info_vec_t_end(self, *args)

    def insert(self, it: 'call_stack_info_t', x: 'call_stack_info_t'
        ) ->'qvector< call_stack_info_t >::iterator':
        return _ida_idd.call_stack_info_vec_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< call_stack_info_t >::iterator':
        return _ida_idd.call_stack_info_vec_t_erase(self, *args)

    def find(self, *args) ->'qvector< call_stack_info_t >::const_iterator':
        return _ida_idd.call_stack_info_vec_t_find(self, *args)

    def has(self, x: 'call_stack_info_t') ->bool:
        return _ida_idd.call_stack_info_vec_t_has(self, x)

    def add_unique(self, x: 'call_stack_info_t') ->bool:
        return _ida_idd.call_stack_info_vec_t_add_unique(self, x)

    def _del(self, x: 'call_stack_info_t') ->bool:
        return _ida_idd.call_stack_info_vec_t__del(self, x)

    def __len__(self) ->'size_t':
        return _ida_idd.call_stack_info_vec_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'call_stack_info_t const &':
        return _ida_idd.call_stack_info_vec_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'call_stack_info_t') ->None:
        return _ida_idd.call_stack_info_vec_t___setitem__(self, i, v)

    def append(self, x: 'call_stack_info_t') ->None:
        return _ida_idd.call_stack_info_vec_t_append(self, x)

    def extend(self, x: 'call_stack_info_vec_t') ->None:
        return _ida_idd.call_stack_info_vec_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_idd.call_stack_info_vec_t_swigregister(call_stack_info_vec_t)


class meminfo_vec_template_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_idd.meminfo_vec_template_t_swiginit(self, _ida_idd.
            new_meminfo_vec_template_t(*args))
    __swig_destroy__ = _ida_idd.delete_meminfo_vec_template_t

    def push_back(self, *args) ->'memory_info_t &':
        return _ida_idd.meminfo_vec_template_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_idd.meminfo_vec_template_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_idd.meminfo_vec_template_t_size(self)

    def empty(self) ->bool:
        return _ida_idd.meminfo_vec_template_t_empty(self)

    def at(self, _idx: 'size_t') ->'memory_info_t const &':
        return _ida_idd.meminfo_vec_template_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_idd.meminfo_vec_template_t_qclear(self)

    def clear(self) ->None:
        return _ida_idd.meminfo_vec_template_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_idd.meminfo_vec_template_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_idd.meminfo_vec_template_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_idd.meminfo_vec_template_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_idd.meminfo_vec_template_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_idd.meminfo_vec_template_t_truncate(self)

    def swap(self, r: 'meminfo_vec_template_t') ->None:
        return _ida_idd.meminfo_vec_template_t_swap(self, r)

    def extract(self) ->'memory_info_t *':
        return _ida_idd.meminfo_vec_template_t_extract(self)

    def inject(self, s: 'memory_info_t', len: 'size_t') ->None:
        return _ida_idd.meminfo_vec_template_t_inject(self, s, len)

    def __eq__(self, r: 'meminfo_vec_template_t') ->bool:
        return _ida_idd.meminfo_vec_template_t___eq__(self, r)

    def __ne__(self, r: 'meminfo_vec_template_t') ->bool:
        return _ida_idd.meminfo_vec_template_t___ne__(self, r)

    def begin(self, *args) ->'qvector< memory_info_t >::const_iterator':
        return _ida_idd.meminfo_vec_template_t_begin(self, *args)

    def end(self, *args) ->'qvector< memory_info_t >::const_iterator':
        return _ida_idd.meminfo_vec_template_t_end(self, *args)

    def insert(self, it: 'memory_info_t', x: 'memory_info_t'
        ) ->'qvector< memory_info_t >::iterator':
        return _ida_idd.meminfo_vec_template_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< memory_info_t >::iterator':
        return _ida_idd.meminfo_vec_template_t_erase(self, *args)

    def find(self, *args) ->'qvector< memory_info_t >::const_iterator':
        return _ida_idd.meminfo_vec_template_t_find(self, *args)

    def has(self, x: 'memory_info_t') ->bool:
        return _ida_idd.meminfo_vec_template_t_has(self, x)

    def add_unique(self, x: 'memory_info_t') ->bool:
        return _ida_idd.meminfo_vec_template_t_add_unique(self, x)

    def _del(self, x: 'memory_info_t') ->bool:
        return _ida_idd.meminfo_vec_template_t__del(self, x)

    def __len__(self) ->'size_t':
        return _ida_idd.meminfo_vec_template_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'memory_info_t const &':
        return _ida_idd.meminfo_vec_template_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'memory_info_t') ->None:
        return _ida_idd.meminfo_vec_template_t___setitem__(self, i, v)

    def append(self, x: 'memory_info_t') ->None:
        return _ida_idd.meminfo_vec_template_t_append(self, x)

    def extend(self, x: 'meminfo_vec_template_t') ->None:
        return _ida_idd.meminfo_vec_template_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_idd.meminfo_vec_template_t_swigregister(meminfo_vec_template_t)


class regvals_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_idd.regvals_t_swiginit(self, _ida_idd.new_regvals_t(*args))
    __swig_destroy__ = _ida_idd.delete_regvals_t

    def push_back(self, *args) ->'regval_t &':
        return _ida_idd.regvals_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_idd.regvals_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_idd.regvals_t_size(self)

    def empty(self) ->bool:
        return _ida_idd.regvals_t_empty(self)

    def at(self, _idx: 'size_t') ->'regval_t const &':
        return _ida_idd.regvals_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_idd.regvals_t_qclear(self)

    def clear(self) ->None:
        return _ida_idd.regvals_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_idd.regvals_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_idd.regvals_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_idd.regvals_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_idd.regvals_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_idd.regvals_t_truncate(self)

    def swap(self, r: 'regvals_t') ->None:
        return _ida_idd.regvals_t_swap(self, r)

    def extract(self) ->'regval_t *':
        return _ida_idd.regvals_t_extract(self)

    def inject(self, s: 'regval_t', len: 'size_t') ->None:
        return _ida_idd.regvals_t_inject(self, s, len)

    def __eq__(self, r: 'regvals_t') ->bool:
        return _ida_idd.regvals_t___eq__(self, r)

    def __ne__(self, r: 'regvals_t') ->bool:
        return _ida_idd.regvals_t___ne__(self, r)

    def begin(self, *args) ->'qvector< regval_t >::const_iterator':
        return _ida_idd.regvals_t_begin(self, *args)

    def end(self, *args) ->'qvector< regval_t >::const_iterator':
        return _ida_idd.regvals_t_end(self, *args)

    def insert(self, it: 'regval_t', x: 'regval_t'
        ) ->'qvector< regval_t >::iterator':
        return _ida_idd.regvals_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< regval_t >::iterator':
        return _ida_idd.regvals_t_erase(self, *args)

    def find(self, *args) ->'qvector< regval_t >::const_iterator':
        return _ida_idd.regvals_t_find(self, *args)

    def has(self, x: 'regval_t') ->bool:
        return _ida_idd.regvals_t_has(self, x)

    def add_unique(self, x: 'regval_t') ->bool:
        return _ida_idd.regvals_t_add_unique(self, x)

    def _del(self, x: 'regval_t') ->bool:
        return _ida_idd.regvals_t__del(self, x)

    def __len__(self) ->'size_t':
        return _ida_idd.regvals_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'regval_t const &':
        return _ida_idd.regvals_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'regval_t') ->None:
        return _ida_idd.regvals_t___setitem__(self, i, v)

    def append(self, x: 'regval_t') ->None:
        return _ida_idd.regvals_t_append(self, x)

    def extend(self, x: 'regvals_t') ->None:
        return _ida_idd.regvals_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_idd.regvals_t_swigregister(regvals_t)
IDD_INTERFACE_VERSION = _ida_idd.IDD_INTERFACE_VERSION
"""The IDD interface version number.
"""
NO_THREAD = _ida_idd.NO_THREAD
"""No thread. in PROCESS_STARTED this value can be used to specify that the main thread has not been created. It will be initialized later by a THREAD_STARTED event. 
        """


class process_info_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    pid: 'pid_t' = property(_ida_idd.process_info_t_pid_get, _ida_idd.
        process_info_t_pid_set)
    """process id
"""
    name: 'qstring' = property(_ida_idd.process_info_t_name_get, _ida_idd.
        process_info_t_name_set)
    """process name
"""

    def __init__(self):
        _ida_idd.process_info_t_swiginit(self, _ida_idd.new_process_info_t())
    __swig_destroy__ = _ida_idd.delete_process_info_t


_ida_idd.process_info_t_swigregister(process_info_t)


class debapp_attrs_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    cbsize: 'int32' = property(_ida_idd.debapp_attrs_t_cbsize_get, _ida_idd
        .debapp_attrs_t_cbsize_set)
    """control field: size of this structure
"""
    addrsize: 'int' = property(_ida_idd.debapp_attrs_t_addrsize_get,
        _ida_idd.debapp_attrs_t_addrsize_set)
    """address size of the process. Since 64-bit debuggers usually can debug 32-bit applications, we cannot rely on sizeof(ea_t) to detect the current address size. The following variable should be used instead. It is initialized with 8 for 64-bit debuggers but they should adjust it as soon as they learn that a 32-bit application is being debugged. For 32-bit debuggers it is initialized with 4. 
        """
    platform: 'qstring' = property(_ida_idd.debapp_attrs_t_platform_get,
        _ida_idd.debapp_attrs_t_platform_set)
    """platform name process is running/debugging under. (is used as a key value in exceptions.cfg) 
        """
    is_be: 'int' = property(_ida_idd.debapp_attrs_t_is_be_get, _ida_idd.
        debapp_attrs_t_is_be_set)

    def __init__(self):
        _ida_idd.debapp_attrs_t_swiginit(self, _ida_idd.new_debapp_attrs_t())
    __swig_destroy__ = _ida_idd.delete_debapp_attrs_t


_ida_idd.debapp_attrs_t_swigregister(debapp_attrs_t)
DEF_ADDRSIZE = _ida_idd.DEF_ADDRSIZE


class register_info_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    name: 'char const *' = property(_ida_idd.register_info_t_name_get,
        _ida_idd.register_info_t_name_set)
    """Register name.
"""
    flags: 'uint32' = property(_ida_idd.register_info_t_flags_get, _ida_idd
        .register_info_t_flags_set)
    """Register info attribute flags 
        """
    register_class: 'register_class_t' = property(_ida_idd.
        register_info_t_register_class_get, _ida_idd.
        register_info_t_register_class_set)
    """segment, mmx, etc.
"""
    dtype: 'op_dtype_t' = property(_ida_idd.register_info_t_dtype_get,
        _ida_idd.register_info_t_dtype_set)
    """Register size (see Operand value types)
"""
    default_bit_strings_mask: 'uval_t' = property(_ida_idd.
        register_info_t_default_bit_strings_mask_get, _ida_idd.
        register_info_t_default_bit_strings_mask_set)
    """mask of default bits
"""

    def __get_bit_strings(self) ->'PyObject *':
        return _ida_idd.register_info_t___get_bit_strings(self)
    bit_strings = property(__get_bit_strings)
    """strings corresponding to each bit of the register. (nullptr = no bit, same name = multi-bits mask) 
        """

    def __init__(self):
        _ida_idd.register_info_t_swiginit(self, _ida_idd.new_register_info_t())
    __swig_destroy__ = _ida_idd.delete_register_info_t


_ida_idd.register_info_t_swigregister(register_info_t)
REGISTER_READONLY = _ida_idd.REGISTER_READONLY
"""the user can't modify the current value of this register
"""
REGISTER_IP = _ida_idd.REGISTER_IP
"""instruction pointer
"""
REGISTER_SP = _ida_idd.REGISTER_SP
"""stack pointer
"""
REGISTER_FP = _ida_idd.REGISTER_FP
"""frame pointer
"""
REGISTER_ADDRESS = _ida_idd.REGISTER_ADDRESS
"""may contain an address
"""
REGISTER_CS = _ida_idd.REGISTER_CS
"""code segment
"""
REGISTER_SS = _ida_idd.REGISTER_SS
"""stack segment
"""
REGISTER_NOLF = _ida_idd.REGISTER_NOLF
"""displays this register without returning to the next line, allowing the next register to be displayed to its right (on the same line) 
        """
REGISTER_CUSTFMT = _ida_idd.REGISTER_CUSTFMT
"""register should be displayed using a custom data format. the format name is in bit_strings[0]; the corresponding regval_t will use bytevec_t 
        """


class memory_info_t(ida_range.range_t):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    name: 'qstring' = property(_ida_idd.memory_info_t_name_get, _ida_idd.
        memory_info_t_name_set)
    """Memory range name.
"""
    sclass: 'qstring' = property(_ida_idd.memory_info_t_sclass_get,
        _ida_idd.memory_info_t_sclass_set)
    """Memory range class name.
"""
    sbase: 'ea_t' = property(_ida_idd.memory_info_t_sbase_get, _ida_idd.
        memory_info_t_sbase_set)
    """Segment base (meaningful only for segmented architectures, e.g. 16-bit x86) The base is specified in paragraphs (i.e. shifted to the right by 4) 
        """
    bitness: 'uchar' = property(_ida_idd.memory_info_t_bitness_get,
        _ida_idd.memory_info_t_bitness_set)
    """Number of bits in segment addresses (0-16bit, 1-32bit, 2-64bit)
"""
    perm: 'uchar' = property(_ida_idd.memory_info_t_perm_get, _ida_idd.
        memory_info_t_perm_set)
    """Memory range permissions (0-no information): see segment.hpp.
"""

    def __eq__(self, r: 'memory_info_t') ->bool:
        return _ida_idd.memory_info_t___eq__(self, r)

    def __ne__(self, r: 'memory_info_t') ->bool:
        return _ida_idd.memory_info_t___ne__(self, r)

    def __init__(self):
        _ida_idd.memory_info_t_swiginit(self, _ida_idd.new_memory_info_t())
    __swig_destroy__ = _ida_idd.delete_memory_info_t


_ida_idd.memory_info_t_swigregister(memory_info_t)


class meminfo_vec_t(meminfo_vec_template_t):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_idd.meminfo_vec_t_swiginit(self, _ida_idd.new_meminfo_vec_t())
    __swig_destroy__ = _ida_idd.delete_meminfo_vec_t


_ida_idd.meminfo_vec_t_swigregister(meminfo_vec_t)


class scattered_segm_t(ida_range.range_t):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    name: 'qstring' = property(_ida_idd.scattered_segm_t_name_get, _ida_idd
        .scattered_segm_t_name_set)
    """name of the segment
"""

    def __init__(self):
        _ida_idd.scattered_segm_t_swiginit(self, _ida_idd.
            new_scattered_segm_t())
    __swig_destroy__ = _ida_idd.delete_scattered_segm_t


_ida_idd.scattered_segm_t_swigregister(scattered_segm_t)


class launch_env_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    merge: 'bool' = property(_ida_idd.launch_env_t_merge_get, _ida_idd.
        launch_env_t_merge_set)

    def set(self, envvar: str, value: str) ->None:
        return _ida_idd.launch_env_t_set(self, envvar, value)

    def envs(self) ->'PyObject *':
        return _ida_idd.launch_env_t_envs(self)

    def __init__(self):
        _ida_idd.launch_env_t_swiginit(self, _ida_idd.new_launch_env_t())
    __swig_destroy__ = _ida_idd.delete_launch_env_t


_ida_idd.launch_env_t_swigregister(launch_env_t)
NO_EVENT = _ida_idd.NO_EVENT
"""Not an interesting event. This event can be used if the debugger module needs to return an event but there are no valid events. 
          """
PROCESS_STARTED = _ida_idd.PROCESS_STARTED
"""New process has been started.
"""
PROCESS_EXITED = _ida_idd.PROCESS_EXITED
"""Process has been stopped.
"""
THREAD_STARTED = _ida_idd.THREAD_STARTED
"""New thread has been started.
"""
THREAD_EXITED = _ida_idd.THREAD_EXITED
"""Thread has been stopped.
"""
BREAKPOINT = _ida_idd.BREAKPOINT
"""Breakpoint has been reached. IDA will complain about unknown breakpoints, they should be reported as exceptions. 
          """
STEP = _ida_idd.STEP
"""One instruction has been executed. Spurious events of this kind are silently ignored by IDA. 
          """
EXCEPTION = _ida_idd.EXCEPTION
"""Exception.
"""
LIB_LOADED = _ida_idd.LIB_LOADED
"""New library has been loaded.
"""
LIB_UNLOADED = _ida_idd.LIB_UNLOADED
"""Library has been unloaded.
"""
INFORMATION = _ida_idd.INFORMATION
"""User-defined information. This event can be used to return empty information This will cause IDA to call get_debug_event() immediately once more. 
          """
PROCESS_ATTACHED = _ida_idd.PROCESS_ATTACHED
"""Successfully attached to running process.
"""
PROCESS_DETACHED = _ida_idd.PROCESS_DETACHED
"""Successfully detached from process.
"""
PROCESS_SUSPENDED = _ida_idd.PROCESS_SUSPENDED
"""Process has been suspended. This event can be used by the debugger module to signal if the process spontaneously gets suspended (not because of an exception, breakpoint, or single step). IDA will silently switch to the 'suspended process' mode without displaying any messages. 
          """
TRACE_FULL = _ida_idd.TRACE_FULL
"""The trace buffer of the tracer module is full and IDA needs to read it before continuing 
          """
STATUS_MASK = _ida_idd.STATUS_MASK
"""additional info about process state
"""
BITNESS_CHANGED = _ida_idd.BITNESS_CHANGED
"""Debugger detected the process bitness changing.
"""


def set_debug_event_code(ev: 'debug_event_t', id: 'event_id_t') ->None:
    return _ida_idd.set_debug_event_code(ev, id)


class modinfo_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    name: 'qstring' = property(_ida_idd.modinfo_t_name_get, _ida_idd.
        modinfo_t_name_set)
    """full name of the module
"""
    base: 'ea_t' = property(_ida_idd.modinfo_t_base_get, _ida_idd.
        modinfo_t_base_set)
    """module base address. if unknown pass BADADDR
"""
    size: 'asize_t' = property(_ida_idd.modinfo_t_size_get, _ida_idd.
        modinfo_t_size_set)
    """module size. if unknown pass 0
"""
    rebase_to: 'ea_t' = property(_ida_idd.modinfo_t_rebase_to_get, _ida_idd
        .modinfo_t_rebase_to_set)
    """if not BADADDR, then rebase the program to the specified address
"""

    def __init__(self):
        _ida_idd.modinfo_t_swiginit(self, _ida_idd.new_modinfo_t())
    __swig_destroy__ = _ida_idd.delete_modinfo_t


_ida_idd.modinfo_t_swigregister(modinfo_t)


class bptaddr_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    hea: 'ea_t' = property(_ida_idd.bptaddr_t_hea_get, _ida_idd.
        bptaddr_t_hea_set)
    """Possible address referenced by hardware breakpoints.
"""
    kea: 'ea_t' = property(_ida_idd.bptaddr_t_kea_get, _ida_idd.
        bptaddr_t_kea_set)
    """Address of the triggered bpt from the kernel's point of view. (for some systems with special memory mappings, the triggered ea might be different from event ea). Use to BADADDR for flat memory model. 
        """

    def __init__(self):
        _ida_idd.bptaddr_t_swiginit(self, _ida_idd.new_bptaddr_t())
    __swig_destroy__ = _ida_idd.delete_bptaddr_t


_ida_idd.bptaddr_t_swigregister(bptaddr_t)


class excinfo_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    code: 'uint32' = property(_ida_idd.excinfo_t_code_get, _ida_idd.
        excinfo_t_code_set)
    """Exception code.
"""
    can_cont: 'bool' = property(_ida_idd.excinfo_t_can_cont_get, _ida_idd.
        excinfo_t_can_cont_set)
    """Execution of the process can continue after this exception?
"""
    ea: 'ea_t' = property(_ida_idd.excinfo_t_ea_get, _ida_idd.excinfo_t_ea_set)
    """Possible address referenced by the exception.
"""
    info: 'qstring' = property(_ida_idd.excinfo_t_info_get, _ida_idd.
        excinfo_t_info_set)
    """Exception message.
"""

    def __init__(self):
        _ida_idd.excinfo_t_swiginit(self, _ida_idd.new_excinfo_t())
    __swig_destroy__ = _ida_idd.delete_excinfo_t


_ida_idd.excinfo_t_swigregister(excinfo_t)


class debug_event_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    pid: 'pid_t' = property(_ida_idd.debug_event_t_pid_get, _ida_idd.
        debug_event_t_pid_set)
    """Process where the event occurred.
"""
    tid: 'thid_t' = property(_ida_idd.debug_event_t_tid_get, _ida_idd.
        debug_event_t_tid_set)
    """Thread where the event occurred.
"""
    ea: 'ea_t' = property(_ida_idd.debug_event_t_ea_get, _ida_idd.
        debug_event_t_ea_set)
    """Address where the event occurred.
"""
    handled: 'bool' = property(_ida_idd.debug_event_t_handled_get, _ida_idd
        .debug_event_t_handled_set)
    """Is event handled by the debugger?. (from the system's point of view) Meaningful for EXCEPTION events 
        """

    def __init__(self, *args):
        _ida_idd.debug_event_t_swiginit(self, _ida_idd.new_debug_event_t(*args)
            )
    __swig_destroy__ = _ida_idd.delete_debug_event_t

    def copy(self, r: 'debug_event_t') ->'debug_event_t &':
        return _ida_idd.debug_event_t_copy(self, r)

    def clear(self) ->None:
        """clear the dependent information (see below), set event code to NO_EVENT
"""
        return _ida_idd.debug_event_t_clear(self)

    def clear_all(self) ->None:
        return _ida_idd.debug_event_t_clear_all(self)

    def eid(self) ->'event_id_t':
        """Event code.
"""
        return _ida_idd.debug_event_t_eid(self)

    def set_eid(self, id: 'event_id_t') ->None:
        """Set event code. If the new event code is compatible with the old one then the dependent information (see below) will be preserved. Otherwise the event will be cleared and the new event code will be set. 
        """
        return _ida_idd.debug_event_t_set_eid(self, id)

    def is_bitness_changed(self) ->bool:
        """process bitness
"""
        return _ida_idd.debug_event_t_is_bitness_changed(self)

    def set_bitness_changed(self, on: bool=True) ->None:
        return _ida_idd.debug_event_t_set_bitness_changed(self, on)

    def modinfo(self) ->'modinfo_t &':
        """Information that depends on the event code:

< PROCESS_STARTED, PROCESS_ATTACHED, LIB_LOADED PROCESS_EXITED, THREAD_EXITED 
        """
        return _ida_idd.debug_event_t_modinfo(self)

    def info(self) ->str:
        """BREAKPOINT
"""
        return _ida_idd.debug_event_t_info(self)

    def bpt(self) ->'bptaddr_t &':
        """EXCEPTION
"""
        return _ida_idd.debug_event_t_bpt(self)

    def exc(self) ->'excinfo_t &':
        return _ida_idd.debug_event_t_exc(self)

    def exit_code(self) ->'int const &':
        """THREAD_STARTED (thread name) LIB_UNLOADED (unloaded library name) INFORMATION (will be displayed in the output window if not empty) 
        """
        return _ida_idd.debug_event_t_exit_code(self)

    def set_modinfo(self, id: 'event_id_t') ->'modinfo_t &':
        return _ida_idd.debug_event_t_set_modinfo(self, id)

    def set_exit_code(self, id: 'event_id_t', code: int) ->None:
        return _ida_idd.debug_event_t_set_exit_code(self, id, code)

    def set_info(self, id: 'event_id_t') ->str:
        return _ida_idd.debug_event_t_set_info(self, id)

    def set_bpt(self) ->'bptaddr_t &':
        return _ida_idd.debug_event_t_set_bpt(self)

    def set_exception(self) ->'excinfo_t &':
        return _ida_idd.debug_event_t_set_exception(self)

    def bpt_ea(self) ->ida_idaapi.ea_t:
        """On some systems with special memory mappings the triggered ea might be different from the actual ea. Calculate the address to use. 
        """
        return _ida_idd.debug_event_t_bpt_ea(self)


_ida_idd.debug_event_t_swigregister(debug_event_t)


def get_debug_event_name(dev: 'debug_event_t') ->str:
    """get debug event name
"""
    return _ida_idd.get_debug_event_name(dev)


class exception_info_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    code: 'uint' = property(_ida_idd.exception_info_t_code_get, _ida_idd.
        exception_info_t_code_set)
    """exception code
"""
    flags: 'uint32' = property(_ida_idd.exception_info_t_flags_get,
        _ida_idd.exception_info_t_flags_set)
    """Exception info flags 
        """

    def break_on(self) ->bool:
        """Should we break on the exception?
"""
        return _ida_idd.exception_info_t_break_on(self)

    def handle(self) ->bool:
        """Should we handle the exception?
"""
        return _ida_idd.exception_info_t_handle(self)
    name: 'qstring' = property(_ida_idd.exception_info_t_name_get, _ida_idd
        .exception_info_t_name_set)
    """Exception standard name.
"""
    desc: 'qstring' = property(_ida_idd.exception_info_t_desc_get, _ida_idd
        .exception_info_t_desc_set)
    """Long message used to display info about the exception.
"""

    def __init__(self, *args):
        _ida_idd.exception_info_t_swiginit(self, _ida_idd.
            new_exception_info_t(*args))
    __swig_destroy__ = _ida_idd.delete_exception_info_t


_ida_idd.exception_info_t_swigregister(exception_info_t)
cvar = _ida_idd.cvar
BPT_WRITE = cvar.BPT_WRITE
"""Write access.
"""
BPT_READ = cvar.BPT_READ
"""Read access.
"""
BPT_RDWR = cvar.BPT_RDWR
"""Read/write access.
"""
BPT_SOFT = cvar.BPT_SOFT
"""Software breakpoint.
"""
BPT_EXEC = cvar.BPT_EXEC
"""Execute instruction.
"""
BPT_DEFAULT = cvar.BPT_DEFAULT
"""Choose bpt type automatically.
"""
EXC_BREAK = _ida_idd.EXC_BREAK
"""break on the exception
"""
EXC_HANDLE = _ida_idd.EXC_HANDLE
"""should be handled by the debugger?
"""
EXC_MSG = _ida_idd.EXC_MSG
"""instead of a warning, log the exception to the output window
"""
EXC_SILENT = _ida_idd.EXC_SILENT
"""do not warn or log to the output window
"""


class regval_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    rvtype: 'int32' = property(_ida_idd.regval_t_rvtype_get, _ida_idd.
        regval_t_rvtype_set)
    """one of Register value types
"""
    ival: 'uint64' = property(_ida_idd.regval_t_ival_get, _ida_idd.
        regval_t_ival_set)
    """RVT_INT.
"""

    def use_bytevec(self) ->bool:
        return _ida_idd.regval_t_use_bytevec(self)

    def __init__(self, *args):
        _ida_idd.regval_t_swiginit(self, _ida_idd.new_regval_t(*args))
    __swig_destroy__ = _ida_idd.delete_regval_t

    def clear(self) ->None:
        """Clear register value.
"""
        return _ida_idd.regval_t_clear(self)

    def __eq__(self, r: 'regval_t') ->bool:
        return _ida_idd.regval_t___eq__(self, r)

    def __ne__(self, r: 'regval_t') ->bool:
        return _ida_idd.regval_t___ne__(self, r)

    def swap(self, r: 'regval_t') ->None:
        """Set this = r and r = this.
"""
        return _ida_idd.regval_t_swap(self, r)

    def set_int(self, x: 'uint64') ->None:
        return _ida_idd.regval_t_set_int(self, x)

    def set_float(self, v: 'bytevec_t const &') ->None:
        return _ida_idd.regval_t_set_float(self, v)

    def set_bytes(self, *args) ->'bytevec_t &':
        return _ida_idd.regval_t_set_bytes(self, *args)

    def set_unavailable(self) ->None:
        return _ida_idd.regval_t_set_unavailable(self)

    def bytes(self, *args) ->'bytevec_t const &':
        return _ida_idd.regval_t_bytes(self, *args)

    def get_data(self, *args) ->'void const *':
        return _ida_idd.regval_t_get_data(self, *args)

    def get_data_size(self) ->'size_t':
        return _ida_idd.regval_t_get_data_size(self)

    def set_pyval(self, o: 'PyObject *', dtype: 'op_dtype_t') ->bool:
        return _ida_idd.regval_t_set_pyval(self, o, dtype)

    def pyval(self, dtype: 'op_dtype_t') ->'PyObject *':
        return _ida_idd.regval_t_pyval(self, dtype)


_ida_idd.regval_t_swigregister(regval_t)
RVT_FLOAT = _ida_idd.RVT_FLOAT
"""floating point
"""
RVT_INT = _ida_idd.RVT_INT
"""integer
"""
RVT_UNAVAILABLE = _ida_idd.RVT_UNAVAILABLE
"""unavailable; other values mean custom data type 
        """


class call_stack_info_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    callea: 'ea_t' = property(_ida_idd.call_stack_info_t_callea_get,
        _ida_idd.call_stack_info_t_callea_set)
    """the address of the call instruction. for the 0th frame this is usually just the current value of EIP. 
        """
    funcea: 'ea_t' = property(_ida_idd.call_stack_info_t_funcea_get,
        _ida_idd.call_stack_info_t_funcea_set)
    """the address of the called function
"""
    fp: 'ea_t' = property(_ida_idd.call_stack_info_t_fp_get, _ida_idd.
        call_stack_info_t_fp_set)
    """the value of the frame pointer of the called function
"""
    funcok: 'bool' = property(_ida_idd.call_stack_info_t_funcok_get,
        _ida_idd.call_stack_info_t_funcok_set)
    """is the function present?
"""

    def __eq__(self, r: 'call_stack_info_t') ->bool:
        return _ida_idd.call_stack_info_t___eq__(self, r)

    def __ne__(self, r: 'call_stack_info_t') ->bool:
        return _ida_idd.call_stack_info_t___ne__(self, r)

    def __init__(self):
        _ida_idd.call_stack_info_t_swiginit(self, _ida_idd.
            new_call_stack_info_t())
    __swig_destroy__ = _ida_idd.delete_call_stack_info_t


_ida_idd.call_stack_info_t_swigregister(call_stack_info_t)


class call_stack_t(call_stack_info_vec_t):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_idd.call_stack_t_swiginit(self, _ida_idd.new_call_stack_t())
    __swig_destroy__ = _ida_idd.delete_call_stack_t


_ida_idd.call_stack_t_swigregister(call_stack_t)


def dbg_appcall(retval: 'idc_value_t *', func_ea: ida_idaapi.ea_t, tid:
    'thid_t', ptif: 'tinfo_t', argv: 'idc_value_t *', argnum: 'size_t'
    ) ->'error_t':
    """Call a function from the debugged application. 
        
@param retval: function return value
* for APPCALL_MANUAL, r will hold the new stack point value
* for APPCALL_DEBEV, r will hold the exception information upon failure and the return code will be eExecThrow
@param func_ea: address to call
@param tid: thread to use. NO_THREAD means to use the current thread
@param ptif: pointer to type of the function to call
@param argv: array of arguments
@param argnum: number of actual arguments
@returns eOk if successful, otherwise an error code"""
    return _ida_idd.dbg_appcall(retval, func_ea, tid, ptif, argv, argnum)


def cleanup_appcall(tid: 'thid_t') ->'error_t':
    """Cleanup after manual appcall. 
        
@param tid: thread to use. NO_THREAD means to use the current thread The application state is restored as it was before calling the last appcall(). Nested appcalls are supported.
@returns eOk if successful, otherwise an error code"""
    return _ida_idd.cleanup_appcall(tid)


class thread_name_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    tid: 'thid_t' = property(_ida_idd.thread_name_t_tid_get, _ida_idd.
        thread_name_t_tid_set)
    """thread
"""
    name: 'qstring' = property(_ida_idd.thread_name_t_name_get, _ida_idd.
        thread_name_t_name_set)
    """new thread name
"""

    def __init__(self):
        _ida_idd.thread_name_t_swiginit(self, _ida_idd.new_thread_name_t())
    __swig_destroy__ = _ida_idd.delete_thread_name_t


_ida_idd.thread_name_t_swigregister(thread_name_t)
RESMOD_NONE = _ida_idd.RESMOD_NONE
"""no stepping, run freely
"""
RESMOD_INTO = _ida_idd.RESMOD_INTO
"""step into call (the most typical single stepping)
"""
RESMOD_OVER = _ida_idd.RESMOD_OVER
"""step over call
"""
RESMOD_OUT = _ida_idd.RESMOD_OUT
"""step out of the current function (run until return)
"""
RESMOD_SRCINTO = _ida_idd.RESMOD_SRCINTO
"""until control reaches a different source line
"""
RESMOD_SRCOVER = _ida_idd.RESMOD_SRCOVER
"""next source line in the current stack frame
"""
RESMOD_SRCOUT = _ida_idd.RESMOD_SRCOUT
"""next source line in the previous stack frame
"""
RESMOD_USER = _ida_idd.RESMOD_USER
"""step out to the user code
"""
RESMOD_HANDLE = _ida_idd.RESMOD_HANDLE
"""step into the exception handler
"""
RESMOD_BACKINTO = _ida_idd.RESMOD_BACKINTO
"""step backwards into call (in time-travel debugging)
"""
RESMOD_MAX = _ida_idd.RESMOD_MAX
STEP_TRACE = _ida_idd.STEP_TRACE
"""lowest level trace. trace buffers are not maintained
"""
INSN_TRACE = _ida_idd.INSN_TRACE
"""instruction tracing
"""
FUNC_TRACE = _ida_idd.FUNC_TRACE
"""function tracing
"""
BBLK_TRACE = _ida_idd.BBLK_TRACE
"""basic block tracing
"""
DRC_EVENTS = _ida_idd.DRC_EVENTS
"""success, there are pending events
"""
DRC_CRC = _ida_idd.DRC_CRC
"""success, but the input file crc does not match
"""
DRC_OK = _ida_idd.DRC_OK
"""success
"""
DRC_NONE = _ida_idd.DRC_NONE
"""reaction to the event not implemented
"""
DRC_FAILED = _ida_idd.DRC_FAILED
"""failed or false
"""
DRC_NETERR = _ida_idd.DRC_NETERR
"""network error
"""
DRC_NOFILE = _ida_idd.DRC_NOFILE
"""file not found
"""
DRC_IDBSEG = _ida_idd.DRC_IDBSEG
"""use idb segmentation
"""
DRC_NOPROC = _ida_idd.DRC_NOPROC
"""the process does not exist anymore
"""
DRC_NOCHG = _ida_idd.DRC_NOCHG
"""no changes
"""
DRC_ERROR = _ida_idd.DRC_ERROR
"""unclassified error, may be complemented by errbuf
"""


class debugger_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    version: 'int' = property(_ida_idd.debugger_t_version_get, _ida_idd.
        debugger_t_version_set)
    """Expected kernel version, should be IDD_INTERFACE_VERSION 
        """
    name: 'char const *' = property(_ida_idd.debugger_t_name_get, _ida_idd.
        debugger_t_name_set)
    """Short debugger name like win32 or linux.
"""
    id: 'int' = property(_ida_idd.debugger_t_id_get, _ida_idd.debugger_t_id_set
        )
    """one of Debugger API module id
"""
    processor: 'char const *' = property(_ida_idd.debugger_t_processor_get,
        _ida_idd.debugger_t_processor_set)
    """Required processor name. Used for instant debugging to load the correct processor module 
        """
    flags: 'uint64' = property(_ida_idd.debugger_t_flags_get, _ida_idd.
        debugger_t_flags_set)

    def is_remote(self) ->bool:
        return _ida_idd.debugger_t_is_remote(self)

    def must_have_hostname(self) ->bool:
        return _ida_idd.debugger_t_must_have_hostname(self)

    def can_continue_from_bpt(self) ->bool:
        return _ida_idd.debugger_t_can_continue_from_bpt(self)

    def may_disturb(self) ->bool:
        return _ida_idd.debugger_t_may_disturb(self)

    def is_safe(self) ->bool:
        return _ida_idd.debugger_t_is_safe(self)

    def use_sregs(self) ->bool:
        return _ida_idd.debugger_t_use_sregs(self)

    def cache_block_size(self) ->'size_t':
        return _ida_idd.debugger_t_cache_block_size(self)

    def use_memregs(self) ->bool:
        return _ida_idd.debugger_t_use_memregs(self)

    def may_take_exit_snapshot(self) ->bool:
        return _ida_idd.debugger_t_may_take_exit_snapshot(self)

    def virtual_threads(self) ->bool:
        return _ida_idd.debugger_t_virtual_threads(self)

    def supports_lowcnds(self) ->bool:
        return _ida_idd.debugger_t_supports_lowcnds(self)

    def supports_debthread(self) ->bool:
        return _ida_idd.debugger_t_supports_debthread(self)

    def can_debug_standalone_dlls(self) ->bool:
        return _ida_idd.debugger_t_can_debug_standalone_dlls(self)

    def fake_memory(self) ->bool:
        return _ida_idd.debugger_t_fake_memory(self)

    def is_ttd(self) ->bool:
        return _ida_idd.debugger_t_is_ttd(self)

    def has_get_processes(self) ->bool:
        return _ida_idd.debugger_t_has_get_processes(self)

    def has_attach_process(self) ->bool:
        return _ida_idd.debugger_t_has_attach_process(self)

    def has_detach_process(self) ->bool:
        return _ida_idd.debugger_t_has_detach_process(self)

    def has_request_pause(self) ->bool:
        return _ida_idd.debugger_t_has_request_pause(self)

    def has_set_exception_info(self) ->bool:
        return _ida_idd.debugger_t_has_set_exception_info(self)

    def has_thread_suspend(self) ->bool:
        return _ida_idd.debugger_t_has_thread_suspend(self)

    def has_thread_continue(self) ->bool:
        return _ida_idd.debugger_t_has_thread_continue(self)

    def has_set_resume_mode(self) ->bool:
        return _ida_idd.debugger_t_has_set_resume_mode(self)

    def has_thread_get_sreg_base(self) ->bool:
        return _ida_idd.debugger_t_has_thread_get_sreg_base(self)

    def has_check_bpt(self) ->bool:
        return _ida_idd.debugger_t_has_check_bpt(self)

    def has_open_file(self) ->bool:
        return _ida_idd.debugger_t_has_open_file(self)

    def has_update_call_stack(self) ->bool:
        return _ida_idd.debugger_t_has_update_call_stack(self)

    def has_appcall(self) ->bool:
        return _ida_idd.debugger_t_has_appcall(self)

    def has_rexec(self) ->bool:
        return _ida_idd.debugger_t_has_rexec(self)

    def has_map_address(self) ->bool:
        return _ida_idd.debugger_t_has_map_address(self)

    def has_soft_bpt(self) ->bool:
        return _ida_idd.debugger_t_has_soft_bpt(self)
    default_regclasses: 'int' = property(_ida_idd.
        debugger_t_default_regclasses_get, _ida_idd.
        debugger_t_default_regclasses_set)
    """Mask of default printed register classes.
"""

    def regs(self, idx: int) ->'register_info_t &':
        return _ida_idd.debugger_t_regs(self, idx)
    memory_page_size: 'int' = property(_ida_idd.
        debugger_t_memory_page_size_get, _ida_idd.
        debugger_t_memory_page_size_set)
    """Size of a memory page. Usually 4K.
"""
    bpt_size: 'uchar' = property(_ida_idd.debugger_t_bpt_size_get, _ida_idd
        .debugger_t_bpt_size_set)
    """Size of the software breakpoint instruction in bytes.
"""
    filetype: 'uchar' = property(_ida_idd.debugger_t_filetype_get, _ida_idd
        .debugger_t_filetype_set)
    """Input file type for the instant debugger. This value will be used after attaching to a new process. 
        """
    resume_modes: 'ushort' = property(_ida_idd.debugger_t_resume_modes_get,
        _ida_idd.debugger_t_resume_modes_set)
    """Resume modes 
        """

    def is_resmod_avail(self, resmod: int) ->bool:
        return _ida_idd.debugger_t_is_resmod_avail(self, resmod)
    ev_init_debugger = _ida_idd.debugger_t_ev_init_debugger
    """Initialize debugger. This event is generated in the main thread. 
          """
    ev_term_debugger = _ida_idd.debugger_t_ev_term_debugger
    """Terminate debugger. This event is generated in the main thread. 
          """
    ev_get_processes = _ida_idd.debugger_t_ev_get_processes
    """Return information about the running processes. This event is generated in the main thread. Available if DBG_HAS_GET_PROCESSES is set 
          """
    ev_start_process = _ida_idd.debugger_t_ev_start_process
    """Start an executable to debug. This event is generated in debthread. Must be implemented. 
          """
    ev_attach_process = _ida_idd.debugger_t_ev_attach_process
    """Attach to an existing running process. event_id should be equal to -1 if not attaching to a crashed process. This event is generated in debthread. Available if DBG_HAS_ATTACH_PROCESS is set 
          """
    ev_detach_process = _ida_idd.debugger_t_ev_detach_process
    """Detach from the debugged process. May be generated while the process is running or suspended. Must detach from the process in any case. The kernel will repeatedly call get_debug_event() until PROCESS_DETACHED is received. In this mode, all other events will be automatically handled and process will be resumed. This event is generated from debthread. Available if DBG_HAS_DETACH_PROCESS is set 
          """
    ev_get_debapp_attrs = _ida_idd.debugger_t_ev_get_debapp_attrs
    """Retrieve process- and debugger-specific runtime attributes. This event is generated in the main thread. 
          """
    ev_rebase_if_required_to = _ida_idd.debugger_t_ev_rebase_if_required_to
    """Rebase database if the debugged program has been rebased by the system. This event is generated in the main thread. 
          """
    ev_request_pause = _ida_idd.debugger_t_ev_request_pause
    """Prepare to pause the process. Normally the next get_debug_event() will pause the process If the process is sleeping, then the pause will not occur until the process wakes up. If the debugger module does not react to this event, then it will be impossible to pause the program. This event is generated in debthread. Available if DBG_HAS_REQUEST_PAUSE is set 
          """
    ev_exit_process = _ida_idd.debugger_t_ev_exit_process
    """Stop the process. May be generated while the process is running or suspended. Must terminate the process in any case. The kernel will repeatedly call get_debug_event() until PROCESS_EXITED is received. In this mode, all other events will be automatically handled and process will be resumed. This event is generated in debthread. Must be implemented. 
          """
    ev_get_debug_event = _ida_idd.debugger_t_ev_get_debug_event
    """Get a pending debug event and suspend the process. This event will be generated regularly by IDA. This event is generated in debthread. IMPORTANT: the BREAKPOINT/EXCEPTION/STEP events must be reported only after reporting other pending events for a thread. Must be implemented. 
          """
    ev_resume = _ida_idd.debugger_t_ev_resume
    """Continue after handling the event. This event is generated in debthread. Must be implemented. 
          """
    ev_set_backwards = _ida_idd.debugger_t_ev_set_backwards
    """Set whether the debugger should continue backwards or forwards. This event is generated in debthread. Available if DBG_FLAG_TTD is set 
          """
    ev_set_exception_info = _ida_idd.debugger_t_ev_set_exception_info
    """Set exception handling. This event is generated in debthread or the main thread. Available if DBG_HAS_SET_EXCEPTION_INFO is set 
          """
    ev_suspended = _ida_idd.debugger_t_ev_suspended
    """This event will be generated by the kernel each time it has suspended the debuggee process and refreshed the database. The debugger module may add information to the database if necessary.
The reason for introducing this event is that when an event like LOAD_DLL happens, the database does not reflect the memory state yet and therefore we can't add information about the dll into the database in the get_debug_event() function. Only when the kernel has adjusted the database we can do it. Example: for loaded PE DLLs we can add the exported function names to the list of debug names (see set_debug_names()).
This event is generated in the main thread. 
          """
    ev_thread_suspend = _ida_idd.debugger_t_ev_thread_suspend
    """Suspend a running thread Available if DBG_HAS_THREAD_SUSPEND is set 
          """
    ev_thread_continue = _ida_idd.debugger_t_ev_thread_continue
    """Resume a suspended thread Available if DBG_HAS_THREAD_CONTINUE is set 
          """
    ev_set_resume_mode = _ida_idd.debugger_t_ev_set_resume_mode
    """Specify resume action Available if DBG_HAS_SET_RESUME_MODE is set 
          """
    ev_read_registers = _ida_idd.debugger_t_ev_read_registers
    """Read thread registers. This event is generated in debthread. Must be implemented. 
          """
    ev_write_register = _ida_idd.debugger_t_ev_write_register
    """Write one thread register. This event is generated in debthread. Must be implemented. 
          """
    ev_thread_get_sreg_base = _ida_idd.debugger_t_ev_thread_get_sreg_base
    """Get information about the base of a segment register. Currently used by the IBM PC module to resolve references like fs:0. This event is generated in debthread. Available if DBG_HAS_THREAD_GET_SREG_BASE is set 
          """
    ev_get_memory_info = _ida_idd.debugger_t_ev_get_memory_info
    """Get information on the memory ranges. The debugger module fills 'ranges'. The returned vector must be sorted. This event is generated in debthread. Must be implemented. 
          """
    ev_read_memory = _ida_idd.debugger_t_ev_read_memory
    """Read process memory. This event is generated in debthread. 
          """
    ev_write_memory = _ida_idd.debugger_t_ev_write_memory
    """Write process memory. This event is generated in debthread. 
          """
    ev_check_bpt = _ida_idd.debugger_t_ev_check_bpt
    """Is it possible to set breakpoint? This event is generated in debthread or in the main thread if debthread is not running yet. It is generated to verify hardware breakpoints. Available if DBG_HAS_CHECK_BPT is set 
          """
    ev_update_bpts = _ida_idd.debugger_t_ev_update_bpts
    """Add/del breakpoints. bpts array contains nadd bpts to add, followed by ndel bpts to del. This event is generated in debthread. 
          """
    ev_update_lowcnds = _ida_idd.debugger_t_ev_update_lowcnds
    """Update low-level (server side) breakpoint conditions. This event is generated in debthread. 
          """
    ev_open_file = _ida_idd.debugger_t_ev_open_file
    ev_close_file = _ida_idd.debugger_t_ev_close_file
    ev_read_file = _ida_idd.debugger_t_ev_read_file
    ev_write_file = _ida_idd.debugger_t_ev_write_file
    ev_map_address = _ida_idd.debugger_t_ev_map_address
    """Map process address. The debugger module may ignore this event. This event is generated in debthread. IDA will generate this event only if DBG_HAS_MAP_ADDRESS is set. 
          """
    ev_get_debmod_extensions = _ida_idd.debugger_t_ev_get_debmod_extensions
    """Get pointer to debugger specific events. This event returns a pointer to a structure that holds pointers to debugger module specific events. For information on the structure layout, please check the corresponding debugger module. Most debugger modules return nullptr because they do not have any extensions. Available extensions may be generated from plugins. This event is generated in the main thread. 
          """
    ev_update_call_stack = _ida_idd.debugger_t_ev_update_call_stack
    """Calculate the call stack trace for the given thread. This event is generated when the process is suspended and should fill the 'trace' object with the information about the current call stack. If this event returns DRC_NONE, IDA will try to invoke a processor-specific mechanism (see processor_t::ev_update_call_stack). If the current processor module does not implement stack tracing, then IDA will fall back to a generic algorithm (based on the frame pointer chain) to calculate the trace. This event is ideal if the debugging targets manage stack frames in a peculiar way, requiring special analysis. This event is generated in the main thread. Available if DBG_HAS_UPDATE_CALL_STACK is set 
          """
    ev_appcall = _ida_idd.debugger_t_ev_appcall
    """Call application function. This event calls a function from the debugged application. This event is generated in debthread Available if HAS_APPCALL is set 
          """
    ev_cleanup_appcall = _ida_idd.debugger_t_ev_cleanup_appcall
    """Cleanup after appcall(). The debugger module must keep the stack blob in the memory until this event is generated. It will be generated by the kernel for each successful appcall(). There is an exception: if APPCALL_MANUAL, IDA may not call cleanup_appcall. If the user selects to terminate a manual appcall, then cleanup_appcall will be generated. Otherwise, the debugger module should terminate the appcall when the generated event returns. This event is generated in debthread. Available if HAS_APPCALL is set 
          """
    ev_eval_lowcnd = _ida_idd.debugger_t_ev_eval_lowcnd
    """Evaluate a low level breakpoint condition at 'ea'. Other evaluation errors are displayed in a dialog box. This call is used by IDA when the process has already been temporarily suspended for some reason and IDA has to decide whether the process should be resumed or definitely suspended because of a breakpoint with a low level condition. This event is generated in debthread. 
          """
    ev_send_ioctl = _ida_idd.debugger_t_ev_send_ioctl
    """Perform a debugger-specific event. This event is generated in debthread 
          """
    ev_dbg_enable_trace = _ida_idd.debugger_t_ev_dbg_enable_trace
    """Enable/Disable tracing. The kernel will generated this event if the debugger plugin set DBG_FLAG_TRACER_MODULE. TRACE_FLAGS can be a set of STEP_TRACE, INSN_TRACE, BBLK_TRACE or FUNC_TRACE. This event is generated in the main thread. 
          """
    ev_is_tracing_enabled = _ida_idd.debugger_t_ev_is_tracing_enabled
    """Is tracing enabled? The kernel will generated this event if the debugger plugin set DBG_FLAG_TRACER_MODULE. TRACE_BIT can be one of the following: STEP_TRACE, INSN_TRACE, BBLK_TRACE or FUNC_TRACE 
          """
    ev_rexec = _ida_idd.debugger_t_ev_rexec
    """Execute a command on the remote computer. Available if DBG_HAS_REXEC is set 
          """
    ev_get_srcinfo_path = _ida_idd.debugger_t_ev_get_srcinfo_path
    """Get the path to a file containing source debug info for the given module. This allows srcinfo providers to call into the debugger when looking for debug info. It is useful in certain cases like the iOS debugger, which is a remote debugger but the remote debugserver does not provide dwarf info. So, we allow the debugger client to decide where to look for debug info locally. 
          """
    ev_bin_search = _ida_idd.debugger_t_ev_bin_search
    """Search for a binary pattern in the program. 
          """
    ev_get_dynamic_register_set = (_ida_idd.
        debugger_t_ev_get_dynamic_register_set)
    """Ask debuger to send dynamic register set 
          """
    ev_set_dbg_options = _ida_idd.debugger_t_ev_set_dbg_options
    """Set debugger options (parameters that are specific to the debugger module). 
          """

    def init_debugger(self, hostname: str, portnum: int, password: str) ->bool:
        return _ida_idd.debugger_t_init_debugger(self, hostname, portnum,
            password)

    def term_debugger(self) ->bool:
        return _ida_idd.debugger_t_term_debugger(self)

    def get_processes(self, procs: 'procinfo_vec_t') ->'drc_t':
        return _ida_idd.debugger_t_get_processes(self, procs)

    def start_process(self, path: str, args: str, envs: 'launch_env_t',
        startdir: str, dbg_proc_flags: int, input_path: str,
        input_file_crc32: int) ->'drc_t':
        return _ida_idd.debugger_t_start_process(self, path, args, envs,
            startdir, dbg_proc_flags, input_path, input_file_crc32)

    def attach_process(self, pid: 'pid_t', event_id: int, dbg_proc_flags: int
        ) ->'drc_t':
        return _ida_idd.debugger_t_attach_process(self, pid, event_id,
            dbg_proc_flags)

    def detach_process(self) ->'drc_t':
        return _ida_idd.debugger_t_detach_process(self)

    def get_debapp_attrs(self, out_pattrs: 'debapp_attrs_t') ->bool:
        return _ida_idd.debugger_t_get_debapp_attrs(self, out_pattrs)

    def rebase_if_required_to(self, new_base: ida_idaapi.ea_t) ->None:
        return _ida_idd.debugger_t_rebase_if_required_to(self, new_base)

    def request_pause(self) ->'drc_t':
        return _ida_idd.debugger_t_request_pause(self)

    def exit_process(self) ->'drc_t':
        return _ida_idd.debugger_t_exit_process(self)

    def get_debug_event(self, event: 'debug_event_t', timeout_ms: int
        ) ->'gdecode_t':
        return _ida_idd.debugger_t_get_debug_event(self, event, timeout_ms)

    def resume(self, event: 'debug_event_t') ->'drc_t':
        return _ida_idd.debugger_t_resume(self, event)

    def set_backwards(self, backwards: bool) ->'drc_t':
        return _ida_idd.debugger_t_set_backwards(self, backwards)

    def set_exception_info(self, info: 'exception_info_t', qty: int) ->None:
        return _ida_idd.debugger_t_set_exception_info(self, info, qty)

    def suspended(self, dlls_added: bool, thr_names: 'thread_name_vec_t *'=None
        ) ->None:
        return _ida_idd.debugger_t_suspended(self, dlls_added, thr_names)

    def thread_suspend(self, tid: 'thid_t') ->'drc_t':
        return _ida_idd.debugger_t_thread_suspend(self, tid)

    def thread_continue(self, tid: 'thid_t') ->'drc_t':
        return _ida_idd.debugger_t_thread_continue(self, tid)

    def set_resume_mode(self, tid: 'thid_t', resmod: 'resume_mode_t'
        ) ->'drc_t':
        return _ida_idd.debugger_t_set_resume_mode(self, tid, resmod)

    def read_registers(self, tid: 'thid_t', clsmask: int, values: 'regval_t'
        ) ->'drc_t':
        return _ida_idd.debugger_t_read_registers(self, tid, clsmask, values)

    def write_register(self, tid: 'thid_t', regidx: int, value: 'regval_t'
        ) ->'drc_t':
        return _ida_idd.debugger_t_write_register(self, tid, regidx, value)

    def thread_get_sreg_base(self, answer: 'ea_t *', tid: 'thid_t',
        sreg_value: int) ->'drc_t':
        return _ida_idd.debugger_t_thread_get_sreg_base(self, answer, tid,
            sreg_value)

    def get_memory_info(self, ranges: 'meminfo_vec_t') ->'drc_t':
        return _ida_idd.debugger_t_get_memory_info(self, ranges)

    def read_memory(self, nbytes: 'size_t *', ea: ida_idaapi.ea_t, buffer:
        'void *', size: 'size_t') ->'drc_t':
        return _ida_idd.debugger_t_read_memory(self, nbytes, ea, buffer, size)

    def write_memory(self, nbytes: 'size_t *', ea: ida_idaapi.ea_t, buffer:
        'void const *', size: 'size_t') ->'drc_t':
        return _ida_idd.debugger_t_write_memory(self, nbytes, ea, buffer, size)

    def check_bpt(self, bptvc: 'int *', type: 'bpttype_t', ea:
        ida_idaapi.ea_t, len: int) ->'drc_t':
        return _ida_idd.debugger_t_check_bpt(self, bptvc, type, ea, len)

    def update_bpts(self, nbpts: 'int *', bpts: 'update_bpt_info_t *', nadd:
        int, ndel: int) ->'drc_t':
        return _ida_idd.debugger_t_update_bpts(self, nbpts, bpts, nadd, ndel)

    def update_lowcnds(self, nupdated: 'int *', lowcnds: 'lowcnd_t const *',
        nlowcnds: int) ->'drc_t':
        return _ida_idd.debugger_t_update_lowcnds(self, nupdated, lowcnds,
            nlowcnds)

    def open_file(self, file: str, fsize: 'uint64 *', readonly: bool) ->int:
        return _ida_idd.debugger_t_open_file(self, file, fsize, readonly)

    def close_file(self, fn: int) ->None:
        return _ida_idd.debugger_t_close_file(self, fn)

    def read_file(self, fn: int, off: 'qoff64_t', buf: 'void *', size: 'size_t'
        ) ->'ssize_t':
        return _ida_idd.debugger_t_read_file(self, fn, off, buf, size)

    def write_file(self, fn: int, off: 'qoff64_t', buf: 'void const *'
        ) ->'ssize_t':
        return _ida_idd.debugger_t_write_file(self, fn, off, buf)

    def map_address(self, off: ida_idaapi.ea_t, regs: 'regval_t', regnum: int
        ) ->ida_idaapi.ea_t:
        return _ida_idd.debugger_t_map_address(self, off, regs, regnum)

    def get_debmod_extensions(self) ->'void const *':
        return _ida_idd.debugger_t_get_debmod_extensions(self)

    def update_call_stack(self, tid: 'thid_t', trace: 'call_stack_t'
        ) ->'drc_t':
        return _ida_idd.debugger_t_update_call_stack(self, tid, trace)

    def cleanup_appcall(self, tid: 'thid_t') ->'drc_t':
        return _ida_idd.debugger_t_cleanup_appcall(self, tid)

    def eval_lowcnd(self, tid: 'thid_t', ea: ida_idaapi.ea_t) ->'drc_t':
        return _ida_idd.debugger_t_eval_lowcnd(self, tid, ea)

    def send_ioctl(self, fn: int, buf: 'void const *', poutbuf: 'void **',
        poutsize: 'ssize_t *') ->'drc_t':
        return _ida_idd.debugger_t_send_ioctl(self, fn, buf, poutbuf, poutsize)

    def dbg_enable_trace(self, tid: 'thid_t', enable: bool, trace_flags: int
        ) ->bool:
        return _ida_idd.debugger_t_dbg_enable_trace(self, tid, enable,
            trace_flags)

    def is_tracing_enabled(self, tid: 'thid_t', tracebit: int) ->bool:
        return _ida_idd.debugger_t_is_tracing_enabled(self, tid, tracebit)

    def rexec(self, cmdline: str) ->int:
        return _ida_idd.debugger_t_rexec(self, cmdline)

    def get_srcinfo_path(self, path: str, base: ida_idaapi.ea_t) ->bool:
        return _ida_idd.debugger_t_get_srcinfo_path(self, path, base)

    def bin_search(self, start_ea: ida_idaapi.ea_t, end_ea: ida_idaapi.ea_t,
        data: 'compiled_binpat_vec_t const &', srch_flags: int) ->'drc_t':
        return _ida_idd.debugger_t_bin_search(self, start_ea, end_ea, data,
            srch_flags)

    def get_dynamic_register_set(self, regset: 'dynamic_register_set_t *'
        ) ->bool:
        return _ida_idd.debugger_t_get_dynamic_register_set(self, regset)

    def have_set_options(self) ->bool:
        return _ida_idd.debugger_t_have_set_options(self)

    def __get_registers(self) ->'dynamic_wrapped_array_t< register_info_t >':
        return _ida_idd.debugger_t___get_registers(self)

    def __get_nregisters(self) ->int:
        return _ida_idd.debugger_t___get_nregisters(self)

    def __get_regclasses(self) ->'PyObject *':
        return _ida_idd.debugger_t___get_regclasses(self)

    def __get_bpt_bytes(self) ->'bytevec_t':
        return _ida_idd.debugger_t___get_bpt_bytes(self)
    registers = property(__get_registers)
    """Array of registers. Use regs() to access it.
"""
    nregisters = property(__get_nregisters)
    """Number of registers.
"""
    regclasses = property(__get_regclasses)
    """Array of register class names.
"""
    bpt_bytes = property(__get_bpt_bytes)
    """A software breakpoint instruction.
"""

    def __init__(self):
        _ida_idd.debugger_t_swiginit(self, _ida_idd.new_debugger_t())
    __swig_destroy__ = _ida_idd.delete_debugger_t


_ida_idd.debugger_t_swigregister(debugger_t)
DEBUGGER_ID_X86_IA32_WIN32_USER = _ida_idd.DEBUGGER_ID_X86_IA32_WIN32_USER
"""Userland win32 processes (win32 debugging APIs)
"""
DEBUGGER_ID_X86_IA32_LINUX_USER = _ida_idd.DEBUGGER_ID_X86_IA32_LINUX_USER
"""Userland linux processes (ptrace())
"""
DEBUGGER_ID_X86_IA32_MACOSX_USER = _ida_idd.DEBUGGER_ID_X86_IA32_MACOSX_USER
"""Userland MAC OS X processes.
"""
DEBUGGER_ID_ARM_IPHONE_USER = _ida_idd.DEBUGGER_ID_ARM_IPHONE_USER
"""iPhone 1.x
"""
DEBUGGER_ID_X86_IA32_BOCHS = _ida_idd.DEBUGGER_ID_X86_IA32_BOCHS
"""BochsDbg.exe 32.
"""
DEBUGGER_ID_6811_EMULATOR = _ida_idd.DEBUGGER_ID_6811_EMULATOR
"""MC6812 emulator (beta)
"""
DEBUGGER_ID_GDB_USER = _ida_idd.DEBUGGER_ID_GDB_USER
"""GDB remote.
"""
DEBUGGER_ID_WINDBG = _ida_idd.DEBUGGER_ID_WINDBG
"""WinDBG using Microsoft Debug engine.
"""
DEBUGGER_ID_X86_DOSBOX_EMULATOR = _ida_idd.DEBUGGER_ID_X86_DOSBOX_EMULATOR
"""Dosbox MS-DOS emulator.
"""
DEBUGGER_ID_ARM_LINUX_USER = _ida_idd.DEBUGGER_ID_ARM_LINUX_USER
"""Userland arm linux.
"""
DEBUGGER_ID_TRACE_REPLAYER = _ida_idd.DEBUGGER_ID_TRACE_REPLAYER
"""Fake debugger to replay recorded traces.
"""
DEBUGGER_ID_X86_PIN_TRACER = _ida_idd.DEBUGGER_ID_X86_PIN_TRACER
"""PIN Tracer module.
"""
DEBUGGER_ID_DALVIK_USER = _ida_idd.DEBUGGER_ID_DALVIK_USER
"""Dalvik.
"""
DEBUGGER_ID_XNU_USER = _ida_idd.DEBUGGER_ID_XNU_USER
"""XNU Kernel.
"""
DEBUGGER_ID_ARM_MACOS_USER = _ida_idd.DEBUGGER_ID_ARM_MACOS_USER
"""Userland arm MAC OS.
"""
DBG_FLAG_REMOTE = _ida_idd.DBG_FLAG_REMOTE
"""Remote debugger (requires remote host name unless DBG_FLAG_NOHOST)
"""
DBG_FLAG_NOHOST = _ida_idd.DBG_FLAG_NOHOST
"""Remote debugger with does not require network params (host/port/pass). (a unique device connected to the machine) 
        """
DBG_FLAG_FAKE_ATTACH = _ida_idd.DBG_FLAG_FAKE_ATTACH
"""PROCESS_ATTACHED is a fake event and does not suspend the execution 
        """
DBG_FLAG_HWDATBPT_ONE = _ida_idd.DBG_FLAG_HWDATBPT_ONE
"""Hardware data breakpoints are one byte size by default 
        """
DBG_FLAG_CAN_CONT_BPT = _ida_idd.DBG_FLAG_CAN_CONT_BPT
"""Debugger knows to continue from a bpt. This flag also means that the debugger module hides breakpoints from ida upon read_memory 
        """
DBG_FLAG_NEEDPORT = _ida_idd.DBG_FLAG_NEEDPORT
"""Remote debugger requires port number (to be used with DBG_FLAG_NOHOST)
"""
DBG_FLAG_DONT_DISTURB = _ida_idd.DBG_FLAG_DONT_DISTURB
"""Debugger can handle only get_debug_event(), request_pause(), exit_process() when the debugged process is running. The kernel may also call service functions (file I/O, map_address, etc) 
        """
DBG_FLAG_SAFE = _ida_idd.DBG_FLAG_SAFE
"""The debugger is safe (probably because it just emulates the application without really running it) 
        """
DBG_FLAG_CLEAN_EXIT = _ida_idd.DBG_FLAG_CLEAN_EXIT
"""IDA must suspend the application and remove all breakpoints before terminating the application. Usually this is not required because the application memory disappears upon termination. 
        """
DBG_FLAG_USE_SREGS = _ida_idd.DBG_FLAG_USE_SREGS
"""Take segment register values into account (non flat memory)
"""
DBG_FLAG_NOSTARTDIR = _ida_idd.DBG_FLAG_NOSTARTDIR
"""Debugger module doesn't use startup directory.
"""
DBG_FLAG_NOPARAMETERS = _ida_idd.DBG_FLAG_NOPARAMETERS
"""Debugger module doesn't use commandline parameters.
"""
DBG_FLAG_NOPASSWORD = _ida_idd.DBG_FLAG_NOPASSWORD
"""Remote debugger doesn't use password.
"""
DBG_FLAG_CONNSTRING = _ida_idd.DBG_FLAG_CONNSTRING
"""Display "Connection string" instead of "Hostname" and hide the "Port" field.
"""
DBG_FLAG_SMALLBLKS = _ida_idd.DBG_FLAG_SMALLBLKS
"""If set, IDA uses 256-byte blocks for caching memory contents. Otherwise, 1024-byte blocks are used 
        """
DBG_FLAG_MANMEMINFO = _ida_idd.DBG_FLAG_MANMEMINFO
"""If set, manual memory region manipulation commands will be available. Use this bit for debugger modules that cannot return memory layout information 
        """
DBG_FLAG_EXITSHOTOK = _ida_idd.DBG_FLAG_EXITSHOTOK
"""IDA may take a memory snapshot at PROCESS_EXITED event.
"""
DBG_FLAG_VIRTHREADS = _ida_idd.DBG_FLAG_VIRTHREADS
"""Thread IDs may be shuffled after each debug event. (to be used for virtual threads that represent cpus for windbg kmode) 
        """
DBG_FLAG_LOWCNDS = _ida_idd.DBG_FLAG_LOWCNDS
"""Low level breakpoint conditions are supported.
"""
DBG_FLAG_DEBTHREAD = _ida_idd.DBG_FLAG_DEBTHREAD
"""Supports creation of a separate thread in ida for the debugger (the debthread). Most debugger functions will be called from debthread (exceptions are marked below) The debugger module may directly call only THREAD_SAFE functions. To call other functions please use execute_sync(). The debthread significantly increases debugging speed, especially if debug events occur frequently. 
        """
DBG_FLAG_DEBUG_DLL = _ida_idd.DBG_FLAG_DEBUG_DLL
"""Can debug standalone DLLs. For example, Bochs debugger can debug any snippet of code 
        """
DBG_FLAG_FAKE_MEMORY = _ida_idd.DBG_FLAG_FAKE_MEMORY
"""get_memory_info()/read_memory()/write_memory() work with the idb. (there is no real process to read from, as for the replayer module) the kernel will not call these functions if this flag is set. however, third party plugins may call them, they must be implemented. 
        """
DBG_FLAG_ANYSIZE_HWBPT = _ida_idd.DBG_FLAG_ANYSIZE_HWBPT
"""The debugger supports arbitrary size hardware breakpoints.
"""
DBG_FLAG_TRACER_MODULE = _ida_idd.DBG_FLAG_TRACER_MODULE
"""The module is a tracer, not a full featured debugger module.
"""
DBG_FLAG_PREFER_SWBPTS = _ida_idd.DBG_FLAG_PREFER_SWBPTS
"""Prefer to use software breakpoints.
"""
DBG_FLAG_LAZY_WATCHPTS = _ida_idd.DBG_FLAG_LAZY_WATCHPTS
"""Watchpoints are triggered before the offending instruction is executed. The debugger must temporarily disable the watchpoint and single-step before resuming. 
        """
DBG_FLAG_FAST_STEP = _ida_idd.DBG_FLAG_FAST_STEP
"""Do not refresh memory layout info after single stepping.
"""
DBG_FLAG_ADD_ENVS = _ida_idd.DBG_FLAG_ADD_ENVS
"""The debugger supports launching processes with environment variables.
"""
DBG_FLAG_MERGE_ENVS = _ida_idd.DBG_FLAG_MERGE_ENVS
"""The debugger supports merge or replace setting for environment variables (only makes sense if DBG_FLAG_ADD_ENVS is set) 
        """
DBG_FLAG_DISABLE_ASLR = _ida_idd.DBG_FLAG_DISABLE_ASLR
"""The debugger support ASLR disabling (Address space layout randomization) 
        """
DBG_FLAG_TTD = _ida_idd.DBG_FLAG_TTD
"""The debugger is a time travel debugger and supports continuing backwards.
"""
DBG_FLAG_FULL_INSTR_BPT = _ida_idd.DBG_FLAG_FULL_INSTR_BPT
"""Setting a breakpoint in the middle of an instruction will also break.
"""
DBG_HAS_GET_PROCESSES = _ida_idd.DBG_HAS_GET_PROCESSES
"""supports ev_get_processes
"""
DBG_HAS_ATTACH_PROCESS = _ida_idd.DBG_HAS_ATTACH_PROCESS
"""supports ev_attach_process
"""
DBG_HAS_DETACH_PROCESS = _ida_idd.DBG_HAS_DETACH_PROCESS
"""supports ev_detach_process
"""
DBG_HAS_REQUEST_PAUSE = _ida_idd.DBG_HAS_REQUEST_PAUSE
"""supports ev_request_pause
"""
DBG_HAS_SET_EXCEPTION_INFO = _ida_idd.DBG_HAS_SET_EXCEPTION_INFO
"""supports ev_set_exception_info
"""
DBG_HAS_THREAD_SUSPEND = _ida_idd.DBG_HAS_THREAD_SUSPEND
"""supports ev_thread_suspend
"""
DBG_HAS_THREAD_CONTINUE = _ida_idd.DBG_HAS_THREAD_CONTINUE
"""supports ev_thread_continue
"""
DBG_HAS_SET_RESUME_MODE = _ida_idd.DBG_HAS_SET_RESUME_MODE
"""supports ev_set_resume_mode. Cannot be set inside the debugger_t::init_debugger() 
        """
DBG_HAS_THREAD_GET_SREG_BASE = _ida_idd.DBG_HAS_THREAD_GET_SREG_BASE
"""supports ev_thread_get_sreg_base
"""
DBG_HAS_CHECK_BPT = _ida_idd.DBG_HAS_CHECK_BPT
"""supports ev_check_bpt
"""
DBG_HAS_OPEN_FILE = _ida_idd.DBG_HAS_OPEN_FILE
"""supports ev_open_file, ev_close_file, ev_read_file, ev_write_file
"""
DBG_HAS_UPDATE_CALL_STACK = _ida_idd.DBG_HAS_UPDATE_CALL_STACK
"""supports ev_update_call_stack
"""
DBG_HAS_APPCALL = _ida_idd.DBG_HAS_APPCALL
"""supports ev_appcall, ev_cleanup_appcall
"""
DBG_HAS_REXEC = _ida_idd.DBG_HAS_REXEC
"""supports ev_rexec
"""
DBG_HAS_MAP_ADDRESS = _ida_idd.DBG_HAS_MAP_ADDRESS
"""supports ev_map_address. Avoid using this bit, especially together with DBG_FLAG_DEBTHREAD because it may cause big slow downs 
        """
DBG_RESMOD_STEP_INTO = _ida_idd.DBG_RESMOD_STEP_INTO
"""RESMOD_INTO is available
"""
DBG_RESMOD_STEP_OVER = _ida_idd.DBG_RESMOD_STEP_OVER
"""RESMOD_OVER is available
"""
DBG_RESMOD_STEP_OUT = _ida_idd.DBG_RESMOD_STEP_OUT
"""RESMOD_OUT is available
"""
DBG_RESMOD_STEP_SRCINTO = _ida_idd.DBG_RESMOD_STEP_SRCINTO
"""RESMOD_SRCINTO is available
"""
DBG_RESMOD_STEP_SRCOVER = _ida_idd.DBG_RESMOD_STEP_SRCOVER
"""RESMOD_SRCOVER is available
"""
DBG_RESMOD_STEP_SRCOUT = _ida_idd.DBG_RESMOD_STEP_SRCOUT
"""RESMOD_SRCOUT is available
"""
DBG_RESMOD_STEP_USER = _ida_idd.DBG_RESMOD_STEP_USER
"""RESMOD_USER is available
"""
DBG_RESMOD_STEP_HANDLE = _ida_idd.DBG_RESMOD_STEP_HANDLE
"""RESMOD_HANDLE is available
"""
DBG_RESMOD_STEP_BACKINTO = _ida_idd.DBG_RESMOD_STEP_BACKINTO
"""RESMOD_BACKINTO is available
"""
DBG_PROC_IS_DLL = _ida_idd.DBG_PROC_IS_DLL
"""database contains a dll (not exe)
"""
DBG_PROC_IS_GUI = _ida_idd.DBG_PROC_IS_GUI
"""using gui version of ida
"""
DBG_PROC_32BIT = _ida_idd.DBG_PROC_32BIT
"""application is 32-bit
"""
DBG_PROC_64BIT = _ida_idd.DBG_PROC_64BIT
"""application is 64-bit
"""
DBG_NO_TRACE = _ida_idd.DBG_NO_TRACE
"""do not trace the application (mac/linux)
"""
DBG_HIDE_WINDOW = _ida_idd.DBG_HIDE_WINDOW
"""application should be hidden on startup (windows)
"""
DBG_SUSPENDED = _ida_idd.DBG_SUSPENDED
"""application should be suspended on startup (mac)
"""
DBG_NO_ASLR = _ida_idd.DBG_NO_ASLR
"""disable ASLR (linux)
"""
BPT_OK = _ida_idd.BPT_OK
"""breakpoint can be set
"""
BPT_INTERNAL_ERR = _ida_idd.BPT_INTERNAL_ERR
"""interr occurred when verifying breakpoint
"""
BPT_BAD_TYPE = _ida_idd.BPT_BAD_TYPE
"""bpt type is not supported
"""
BPT_BAD_ALIGN = _ida_idd.BPT_BAD_ALIGN
"""alignment is invalid
"""
BPT_BAD_ADDR = _ida_idd.BPT_BAD_ADDR
"""ea is invalid
"""
BPT_BAD_LEN = _ida_idd.BPT_BAD_LEN
"""bpt len is invalid
"""
BPT_TOO_MANY = _ida_idd.BPT_TOO_MANY
"""reached max number of supported breakpoints
"""
BPT_READ_ERROR = _ida_idd.BPT_READ_ERROR
"""failed to read memory at bpt ea
"""
BPT_WRITE_ERROR = _ida_idd.BPT_WRITE_ERROR
"""failed to write memory at bpt ea
"""
BPT_SKIP = _ida_idd.BPT_SKIP
"""update_bpts(): do not process bpt
"""
BPT_PAGE_OK = _ida_idd.BPT_PAGE_OK
"""update_bpts(): ok, added a page bpt
"""
APPCALL_MANUAL = _ida_idd.APPCALL_MANUAL
"""Only set up the appcall, do not run. debugger_t::cleanup_appcall will not be generated by ida! 
        """
APPCALL_DEBEV = _ida_idd.APPCALL_DEBEV
"""Return debug event information.
"""
APPCALL_TIMEOUT = _ida_idd.APPCALL_TIMEOUT
"""Appcall with timeout. If timed out, errbuf will contain "timeout". See SET_APPCALL_TIMEOUT and GET_APPCALL_TIMEOUT 
        """
RQ_MASKING = _ida_idd.RQ_MASKING
"""masking step handler: unless errors, tmpbpt handlers won't be generated should be used only with request_internal_step() 
        """
RQ_SUSPEND = _ida_idd.RQ_SUSPEND
"""suspending step handler: suspends the app handle_debug_event: suspends the app 
        """
RQ_NOSUSP = _ida_idd.RQ_NOSUSP
"""running step handler: continues the app
"""
RQ_IGNWERR = _ida_idd.RQ_IGNWERR
"""ignore breakpoint write failures
"""
RQ_SILENT = _ida_idd.RQ_SILENT
"""all: no dialog boxes
"""
RQ_VERBOSE = _ida_idd.RQ_VERBOSE
"""all: display dialog boxes
"""
RQ_SWSCREEN = _ida_idd.RQ_SWSCREEN
"""handle_debug_event: switch screens
"""
RQ__NOTHRRF = _ida_idd.RQ__NOTHRRF
"""handle_debug_event: do not refresh threads
"""
RQ_PROCEXIT = _ida_idd.RQ_PROCEXIT
"""snapshots: the process is exiting
"""
RQ_IDAIDLE = _ida_idd.RQ_IDAIDLE
"""handle_debug_event: ida is idle
"""
RQ_SUSPRUN = _ida_idd.RQ_SUSPRUN
"""handle_debug_event: suspend at PROCESS_STARTED
"""
RQ_RESUME = _ida_idd.RQ_RESUME
"""handle_debug_event: resume application
"""
RQ_RESMOD = _ida_idd.RQ_RESMOD
"""resume_mode_t
"""
RQ_RESMOD_SHIFT = _ida_idd.RQ_RESMOD_SHIFT


def cpu2ieee(ieee_out: 'fpvalue_t *', cpu_fpval: 'void const *', size: int
    ) ->int:
    """Convert a floating point number in CPU native format to IDA's internal format. 
        
@param ieee_out: output buffer
@param cpu_fpval: floating point number in CPU native format
@param size: size of cpu_fpval in bytes (size of the input buffer)
@returns Floating point/IEEE Conversion codes"""
    return _ida_idd.cpu2ieee(ieee_out, cpu_fpval, size)


def ieee2cpu(cpu_fpval_out: 'void *', ieee: 'fpvalue_t const &', size: int
    ) ->int:
    """Convert a floating point number in IDA's internal format to CPU native format. 
        
@param cpu_fpval_out: output buffer
@param ieee: floating point number of IDA's internal format
@param size: size of cpu_fpval in bytes (size of the output buffer)
@returns Floating point/IEEE Conversion codes"""
    return _ida_idd.ieee2cpu(cpu_fpval_out, ieee, size)


class dyn_register_info_array(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    data: 'register_info_t *' = property(_ida_idd.
        dyn_register_info_array_data_get)
    count: 'size_t' = property(_ida_idd.dyn_register_info_array_count_get)

    def __init__(self, _data: 'register_info_t', _count: 'size_t'):
        _ida_idd.dyn_register_info_array_swiginit(self, _ida_idd.
            new_dyn_register_info_array(_data, _count))

    def __len__(self) ->'size_t':
        return _ida_idd.dyn_register_info_array___len__(self)

    def __getitem__(self, i: 'size_t') ->'register_info_t const &':
        return _ida_idd.dyn_register_info_array___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'register_info_t') ->None:
        return _ida_idd.dyn_register_info_array___setitem__(self, i, v)
    __iter__ = ida_idaapi._bounded_getitem_iterator
    __swig_destroy__ = _ida_idd.delete_dyn_register_info_array


_ida_idd.dyn_register_info_array_swigregister(dyn_register_info_array)


def get_dbg() ->'debugger_t *':
    return _ida_idd.get_dbg()


def dbg_get_registers():
    """This function returns the register definition from the currently loaded debugger.
Basically, it returns an array of structure similar to to idd.hpp / register_info_t

@return:
    None if no debugger is loaded
    tuple(name, flags, class, dtype, bit_strings, default_bit_strings_mask)
    The bit_strings can be a tuple of strings or None (if the register does not have bit_strings)"""
    return _ida_idd.dbg_get_registers()


def dbg_get_thread_sreg_base(tid, sreg_value):
    """Returns the segment register base value

@param tid: thread id
@param sreg_value: segment register (selector) value
@return:
    - The base as an 'ea'
    - Or None on failure"""
    return _ida_idd.dbg_get_thread_sreg_base(tid, sreg_value)


def dbg_read_memory(ea, sz):
    """Reads from the debugee's memory at the specified ea

@param ea: the debuggee's memory address
@param sz: the amount of data to read
@return:
    - The read buffer (as bytes)
    - Or None on failure"""
    return _ida_idd.dbg_read_memory(ea, sz)


def dbg_write_memory(ea, buffer):
    """Writes a buffer to the debugee's memory

@param ea: the debuggee's memory address
@param buf: a bytes object to write
@return: Boolean"""
    return _ida_idd.dbg_write_memory(ea, buffer)


def dbg_get_name():
    """This function returns the current debugger's name.

@return: Debugger name or None if no debugger is active"""
    return _ida_idd.dbg_get_name()


def dbg_get_memory_info():
    """This function returns the memory configuration of a debugged process.

@return:
    None if no debugger is active
    tuple(start_ea, end_ea, name, sclass, sbase, bitness, perm)"""
    return _ida_idd.dbg_get_memory_info()


def appcall(func_ea: ida_idaapi.ea_t, tid: 'thid_t', _type_or_none:
    'bytevec_t const &', _fields: 'bytevec_t const &', arg_list: 'PyObject *'
    ) ->'PyObject *':
    return _ida_idd.appcall(func_ea, tid, _type_or_none, _fields, arg_list)


def get_event_module_name(ev: 'debug_event_t') ->str:
    return _ida_idd.get_event_module_name(ev)


def get_event_module_base(ev: 'debug_event_t') ->ida_idaapi.ea_t:
    return _ida_idd.get_event_module_base(ev)


def get_event_module_size(ev: 'debug_event_t') ->'asize_t':
    return _ida_idd.get_event_module_size(ev)


def get_event_exc_info(ev: 'debug_event_t') ->str:
    return _ida_idd.get_event_exc_info(ev)


def get_event_info(ev: 'debug_event_t') ->str:
    return _ida_idd.get_event_info(ev)


def get_event_bpt_hea(ev: 'debug_event_t') ->ida_idaapi.ea_t:
    return _ida_idd.get_event_bpt_hea(ev)


def get_event_exc_code(ev: 'debug_event_t') ->'uint':
    return _ida_idd.get_event_exc_code(ev)


def get_event_exc_ea(ev: 'debug_event_t') ->ida_idaapi.ea_t:
    return _ida_idd.get_event_exc_ea(ev)


def can_exc_continue(ev: 'debug_event_t') ->bool:
    return _ida_idd.can_exc_continue(ev)


NO_PROCESS = 4294967295
"""No process.
"""
NO_THREAD = 0
"""No thread. in PROCESS_STARTED this value can be used to specify that the main thread has not been created. It will be initialized later by a THREAD_STARTED event. 
        """
import types
import _ida_idaapi
import _ida_dbg
import _ida_typeinf
import _ida_name
import _ida_bytes
import _ida_ida
import ida_idaapi
import ida_typeinf
dbg_can_query = _ida_dbg.dbg_can_query


class Appcall_array__(object):
    """This class is used with Appcall.array() method"""

    def __init__(self, tp):
        self.__type = tp

    def pack(self, L):
        """Packs a list or tuple into a byref buffer"""
        t = type(L)
        if not (t == list or t == tuple):
            raise ValueError('Either a list or a tuple must be passed')
        self.__size = len(L)
        if self.__size == 1:
            self.__typedobj = Appcall__.typedobj(self.__type + ';')
        else:
            self.__typedobj = Appcall__.typedobj('%s x[%d];' % (self.__type,
                self.__size))
        ok, buf = self.__typedobj.store(L)
        if ok:
            return Appcall__.byref(buf)
        else:
            return None

    def try_to_convert_to_list(self, obj):
        """Is this object a list? We check for the existance of attribute zero and attribute self.size-1"""
        if not (hasattr(obj, '0') and hasattr(obj, str(self.__size - 1))):
            return obj
        return [getattr(obj, str(x)) for x in range(0, self.__size)]

    def unpack(self, buf, as_list=True):
        """Unpacks an array back into a list or an object"""
        if isinstance(buf, ida_idaapi.PyIdc_cvt_refclass__):
            buf = buf.value
        if type(buf) != bytes:
            raise ValueError('Cannot unpack this type!')
        ok, obj = self.__typedobj.retrieve(buf)
        if not ok:
            raise ValueError('Failed while unpacking!')
        if not as_list:
            return obj
        return self.try_to_convert_to_list(obj)


class Appcall_callable__(object):
    """
    Helper class to issue appcalls using a natural syntax:
      appcall.FunctionNameInTheDatabase(arguments, ....)
    or
      appcall["Function@8"](arguments, ...)
    or
      f8 = appcall["Function@8"]
      f8(arg1, arg2, ...)
    or
      o = appcall.obj()
      i = byref(5)
      appcall.funcname(arg1, i, "hello", o)
    """

    def __init__(self, ea, tinfo_or_typestr=None, fields=None):
        """Initializes an appcall with a given function ea"""
        self.__ea = ea
        self.__tif = None
        self.__type = None
        self.__fields = None
        self.__options = None
        self.__timeout = None
        if tinfo_or_typestr:
            if isinstance(tinfo_or_typestr, ida_idaapi.string_types):
                tif = ida_typeinf.tinfo_t()
                if not tif.deserialize(None, tinfo_or_typestr, fields):
                    raise ValueError('Could not deserialize type string')
            else:
                if not isinstance(tinfo_or_typestr, ida_typeinf.tinfo_t):
                    raise ValueError("Invalid argument 'tinfo_or_typestr'")
                tif = tinfo_or_typestr
            self.__tif = tif
            self.__type, self.__fields, _ = tif.serialize()

    def __get_timeout(self):
        return self.__timeout

    def __set_timeout(self, v):
        self.__timeout = v
    timeout = property(__get_timeout, __set_timeout)
    """An Appcall instance can change its timeout value with this attribute"""

    def __get_options(self):
        return (self.__options if self.__options != None else Appcall__.
            get_appcall_options())

    def __set_options(self, v):
        if self.timeout:
            v |= Appcall__.APPCALL_TIMEOUT | self.timeout << 16
        else:
            v &= ~Appcall__.APPCALL_TIMEOUT
        self.__options = v
    options = property(__get_options, __set_options)
    """Sets the Appcall options locally to this Appcall instance"""

    def __call__(self, *args):
        """Make object callable. We redirect execution to idaapi.appcall()"""
        if self.ea is None:
            raise ValueError('Object not callable!')
        arg_list = list(args)
        old_opt = Appcall__.get_appcall_options()
        Appcall__.set_appcall_options(self.options)
        try:
            return _ida_idd.appcall(self.ea, _ida_dbg.get_current_thread(),
                self.type, self.fields, arg_list)
        finally:
            Appcall__.set_appcall_options(old_opt)

    def __get_ea(self):
        return self.__ea

    def __set_ea(self, val):
        self.__ea = val
    ea = property(__get_ea, __set_ea)
    """Returns or sets the EA associated with this object"""

    def __get_tif(self):
        return self.__tif
    tif = property(__get_tif)
    """Returns the tinfo_t object"""

    def __get_size(self):
        if self.__type == None:
            return -1
        r = _ida_typeinf.calc_type_size(None, self.__type)
        if not r:
            return -1
        return r
    size = property(__get_size)
    """Returns the size of the type"""

    def __get_type(self):
        return self.__type
    type = property(__get_type)
    """Returns the typestring"""

    def __get_fields(self):
        return self.__fields
    fields = property(__get_fields)
    """Returns the field names"""

    def retrieve(self, src=None, flags=0):
        """
        Unpacks a typed object from the database if an ea is given or from a string if a string was passed
        @param src: the address of the object or a string
        @return: Returns a tuple of boolean and object or error number (Bool, Error | Object).
        """
        if src is None:
            src = self.ea
        if type(src) == bytes:
            return _ida_typeinf.unpack_object_from_bv(None, self.type, self
                .fields, src, flags)
        else:
            return _ida_typeinf.unpack_object_from_idb(None, self.type,
                self.fields, src, flags)

    def store(self, obj, dest_ea=None, base_ea=0, flags=0):
        """
        Packs an object into a given ea if provided or into a string if no address was passed.
        @param obj: The object to pack
        @param dest_ea: If packing to idb this will be the store location
        @param base_ea: If packing to a buffer, this will be the base that will be used to relocate the pointers

        @return:
            - If packing to a string then a Tuple(Boolean, packed_string or error code)
            - If packing to the database then a return code is returned (0 is success)
        """
        if dest_ea is None:
            return _ida_typeinf.pack_object_to_bv(obj, None, self.type,
                self.fields, base_ea, flags)
        else:
            return _ida_typeinf.pack_object_to_idb(obj, None, self.type,
                self.fields, dest_ea, flags)


class Appcall_consts__(object):
    """
    Helper class used by Appcall.Consts attribute
    It is used to retrieve constants via attribute access
    """

    def __init__(self, default=None):
        self.__default = default

    def __getattr__(self, attr):
        v = Appcall__.valueof(attr, self.__default)
        if v is None:
            raise AttributeError('No constant with name ' + attr)
        return v


class Appcall__(object):
    APPCALL_MANUAL = 1
    """Only set up the appcall, do not run. debugger_t::cleanup_appcall will not be generated by ida! 
        """
    """
    Only set up the appcall, do not run it.
    you should call CleanupAppcall() when finished
    """
    APPCALL_DEBEV = 2
    """Return debug event information.
"""
    """
    Return debug event information
    If this bit is set, exceptions during appcall
    will generate idc exceptions with full
    information about the exception
    """
    APPCALL_TIMEOUT = 4
    """Appcall with timeout. If timed out, errbuf will contain "timeout". See SET_APPCALL_TIMEOUT and GET_APPCALL_TIMEOUT 
        """
    """
    Appcall with timeout
    The timeout value in milliseconds is specified
    in the high 2 bytes of the 'options' argument:
    If timed out, errbuf will contain "timeout".
    """
    __name__ = 'Appcall__'

    def __init__(self):
        self.__consts = Appcall_consts__()

    def __get_consts(self):
        return self.__consts
    Consts = property(__get_consts)
    """Use Appcall.Consts.CONST_NAME to access constants"""

    @staticmethod
    def __name_or_ea(name_or_ea):
        """
        Function that accepts a name or an ea and checks if the address is enabled.
        If a name is passed then idaapi.get_name_ea() is applied to retrieve the name
        @return:
            - Returns the resolved EA or
            - Raises an exception if the address is not enabled
        """
        if type(name_or_ea) in ida_idaapi.string_types:
            ea = _ida_name.get_name_ea(_ida_idaapi.BADADDR, name_or_ea)
        else:
            ea = name_or_ea
        if ea == _ida_idaapi.BADADDR or not _ida_bytes.is_mapped(ea):
            raise AttributeError('Undefined function ' + name_or_ea)
        return ea

    @staticmethod
    def __typedecl_or_tinfo(typedecl_or_tinfo, flags=None):
        """
        Function that accepts a tinfo_t object or type declaration as a string
        If a type declaration is passed then ida_typeinf.parse_decl() is applied to prepare tinfo_t object
        @return:
            - Returns the tinfo_t object
            - Raises an exception if the declaration cannot be parsed
        """
        if isinstance(typedecl_or_tinfo, ida_idaapi.string_types):
            if flags is None:
                flags = (ida_typeinf.PT_SIL | ida_typeinf.PT_NDC |
                    ida_typeinf.PT_TYP)
            tif = ida_typeinf.tinfo_t()
            if ida_typeinf.parse_decl(tif, None, typedecl_or_tinfo, flags
                ) == None:
                raise ValueError('Could not parse type: ' + typedecl_or_tinfo)
        else:
            if not isinstance(typedecl_or_tinfo, ida_typeinf.tinfo_t):
                raise ValueError("Invalid argument 'typedecl_or_tinfo'")
            tif = typedecl_or_tinfo
        return tif

    @staticmethod
    def proto(name_or_ea, proto_or_tinfo, flags=None):
        """
        Allows you to instantiate an appcall (callable object) with the desired prototype
        @param name_or_ea: The name of the function (will be resolved with LocByName())
        @param proto_or_tinfo: function prototype as a string or type of the function as tinfo_t object
        @return:
            - On failure it raises an exception if the prototype could not be parsed
              or the address is not resolvable
            - Returns a callbable Appcall instance with the given prototypes and flags
        """
        ea = Appcall__.__name_or_ea(name_or_ea)
        tif = Appcall__.__typedecl_or_tinfo(proto_or_tinfo, flags)
        return Appcall_callable__(ea, tif)

    def __getattr__(self, name_or_ea):
        """Allows you to call functions as if they were member functions (by returning a callable object)"""
        ea = self.__name_or_ea(name_or_ea)
        if ea == _ida_idaapi.BADADDR:
            raise AttributeError('Undefined function ' + name)
        return Appcall_callable__(ea)

    def __getitem__(self, idx):
        """
        Use self[func_name] syntax if the function name contains invalid characters for an attribute name
        See __getattr___
        """
        return self.__getattr__(idx)

    @staticmethod
    def valueof(name, default=0):
        """
        Returns the numeric value of a given name string.
        If the name could not be resolved then the default value will be returned
        """
        t, v = _ida_name.get_name_value(_ida_idaapi.BADADDR, name)
        if t == 0:
            v = default
        return v

    @staticmethod
    def int64(v):
        """Whenever a 64bit number is needed use this method to construct an object"""
        return ida_idaapi.PyIdc_cvt_int64__(v)

    @staticmethod
    def byref(val):
        """
        Method to create references to immutable objects
        Currently we support references to int/strings
        Objects need not be passed by reference (this will be done automatically)
        """
        return ida_idaapi.PyIdc_cvt_refclass__(val)

    @staticmethod
    def buffer(str=None, size=0, fill='\x00'):
        """
        Creates a string buffer. The returned value (r) will be a byref object.
        Use r.value to get the contents and r.size to get the buffer's size
        """
        if str is None:
            str = ''
        left = size - len(str)
        if left > 0:
            str = str + fill * left
        r = Appcall__.byref(str)
        r.size = size
        return r

    @staticmethod
    def obj(**kwds):
        """Returns an empty object or objects with attributes as passed via its keywords arguments"""
        return ida_idaapi.object_t(**kwds)

    @staticmethod
    def cstr(val):
        return ida_idaapi.as_cstr(val)

    @staticmethod
    def UTF16(s):
        return ida_idaapi.as_UTF16(s)
    unicode = UTF16

    @staticmethod
    def array(type_name):
        """Defines an array type. Later you need to pack() / unpack()"""
        return Appcall_array__(type_name)

    @staticmethod
    def typedobj(typedecl_or_tinfo, ea=None):
        """
        Returns an appcall object for a type (can be given as tinfo_t object or
        as a string declaration)
        One can then use retrieve() member method
        @param ea: Optional parameter that later can be used to retrieve the type
        @return: Appcall object or raises ValueError exception
        """
        tif = Appcall__.__typedecl_or_tinfo(typedecl_or_tinfo)
        return Appcall_callable__(ea, tif)

    @staticmethod
    def set_appcall_options(opt):
        """Method to change the Appcall options globally (not per Appcall)"""
        old_opt = Appcall__.get_appcall_options()
        _ida_ida.inf_set_appcall_options(opt)
        return old_opt

    @staticmethod
    def get_appcall_options():
        """Return the global Appcall options"""
        return _ida_ida.inf_get_appcall_options()

    @staticmethod
    def cleanup_appcall(tid=0):
        """Cleanup after manual appcall. 
        
@param tid: thread to use. NO_THREAD means to use the current thread The application state is restored as it was before calling the last appcall(). Nested appcalls are supported.
@returns eOk if successful, otherwise an error code"""
        return _ida_idd.cleanup_appcall(tid)


Appcall = Appcall__()

```
