```python
"""Architecture independent exception handling info.

Try blocks have the following general properties:
* A try block specifies a possibly fragmented guarded code region.
* Each try block has always at least one catch/except block description
* Each catch block contains its boundaries and a filter.
* Additionally a catch block can hold sp adjustment and the offset to the exception object offset (C++).
* Try blocks can be nested. Nesting is automatically calculated at the retrieval time.
* There may be (nested) multiple try blocks starting at the same address.


See examples in tests/input/src/eh_tests. 
    """
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_tryblks
else:
    import _ida_tryblks
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
SWIG_PYTHON_LEGACY_BOOL = _ida_tryblks.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi
import ida_range


class tryblks_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_tryblks.tryblks_t_swiginit(self, _ida_tryblks.new_tryblks_t(*args)
            )
    __swig_destroy__ = _ida_tryblks.delete_tryblks_t

    def push_back(self, *args) ->'tryblk_t &':
        return _ida_tryblks.tryblks_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_tryblks.tryblks_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_tryblks.tryblks_t_size(self)

    def empty(self) ->bool:
        return _ida_tryblks.tryblks_t_empty(self)

    def at(self, _idx: 'size_t') ->'tryblk_t const &':
        return _ida_tryblks.tryblks_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_tryblks.tryblks_t_qclear(self)

    def clear(self) ->None:
        return _ida_tryblks.tryblks_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_tryblks.tryblks_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_tryblks.tryblks_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_tryblks.tryblks_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_tryblks.tryblks_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_tryblks.tryblks_t_truncate(self)

    def swap(self, r: 'tryblks_t') ->None:
        return _ida_tryblks.tryblks_t_swap(self, r)

    def extract(self) ->'tryblk_t *':
        return _ida_tryblks.tryblks_t_extract(self)

    def inject(self, s: 'tryblk_t', len: 'size_t') ->None:
        return _ida_tryblks.tryblks_t_inject(self, s, len)

    def __eq__(self, r: 'tryblks_t') ->bool:
        return _ida_tryblks.tryblks_t___eq__(self, r)

    def __ne__(self, r: 'tryblks_t') ->bool:
        return _ida_tryblks.tryblks_t___ne__(self, r)

    def begin(self, *args) ->'qvector< tryblk_t >::const_iterator':
        return _ida_tryblks.tryblks_t_begin(self, *args)

    def end(self, *args) ->'qvector< tryblk_t >::const_iterator':
        return _ida_tryblks.tryblks_t_end(self, *args)

    def insert(self, it: 'tryblk_t', x: 'tryblk_t'
        ) ->'qvector< tryblk_t >::iterator':
        return _ida_tryblks.tryblks_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< tryblk_t >::iterator':
        return _ida_tryblks.tryblks_t_erase(self, *args)

    def find(self, *args) ->'qvector< tryblk_t >::const_iterator':
        return _ida_tryblks.tryblks_t_find(self, *args)

    def has(self, x: 'tryblk_t') ->bool:
        return _ida_tryblks.tryblks_t_has(self, x)

    def add_unique(self, x: 'tryblk_t') ->bool:
        return _ida_tryblks.tryblks_t_add_unique(self, x)

    def _del(self, x: 'tryblk_t') ->bool:
        return _ida_tryblks.tryblks_t__del(self, x)

    def __len__(self) ->'size_t':
        return _ida_tryblks.tryblks_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'tryblk_t const &':
        return _ida_tryblks.tryblks_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'tryblk_t') ->None:
        return _ida_tryblks.tryblks_t___setitem__(self, i, v)

    def append(self, x: 'tryblk_t') ->None:
        return _ida_tryblks.tryblks_t_append(self, x)

    def extend(self, x: 'tryblks_t') ->None:
        return _ida_tryblks.tryblks_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_tryblks.tryblks_t_swigregister(tryblks_t)


class catchvec_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_tryblks.catchvec_t_swiginit(self, _ida_tryblks.new_catchvec_t(
            *args))
    __swig_destroy__ = _ida_tryblks.delete_catchvec_t

    def push_back(self, *args) ->'catch_t &':
        return _ida_tryblks.catchvec_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_tryblks.catchvec_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_tryblks.catchvec_t_size(self)

    def empty(self) ->bool:
        return _ida_tryblks.catchvec_t_empty(self)

    def at(self, _idx: 'size_t') ->'catch_t const &':
        return _ida_tryblks.catchvec_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_tryblks.catchvec_t_qclear(self)

    def clear(self) ->None:
        return _ida_tryblks.catchvec_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_tryblks.catchvec_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_tryblks.catchvec_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_tryblks.catchvec_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_tryblks.catchvec_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_tryblks.catchvec_t_truncate(self)

    def swap(self, r: 'catchvec_t') ->None:
        return _ida_tryblks.catchvec_t_swap(self, r)

    def extract(self) ->'catch_t *':
        return _ida_tryblks.catchvec_t_extract(self)

    def inject(self, s: 'catch_t', len: 'size_t') ->None:
        return _ida_tryblks.catchvec_t_inject(self, s, len)

    def __eq__(self, r: 'catchvec_t') ->bool:
        return _ida_tryblks.catchvec_t___eq__(self, r)

    def __ne__(self, r: 'catchvec_t') ->bool:
        return _ida_tryblks.catchvec_t___ne__(self, r)

    def begin(self, *args) ->'qvector< catch_t >::const_iterator':
        return _ida_tryblks.catchvec_t_begin(self, *args)

    def end(self, *args) ->'qvector< catch_t >::const_iterator':
        return _ida_tryblks.catchvec_t_end(self, *args)

    def insert(self, it: 'catch_t', x: 'catch_t'
        ) ->'qvector< catch_t >::iterator':
        return _ida_tryblks.catchvec_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< catch_t >::iterator':
        return _ida_tryblks.catchvec_t_erase(self, *args)

    def find(self, *args) ->'qvector< catch_t >::const_iterator':
        return _ida_tryblks.catchvec_t_find(self, *args)

    def has(self, x: 'catch_t') ->bool:
        return _ida_tryblks.catchvec_t_has(self, x)

    def add_unique(self, x: 'catch_t') ->bool:
        return _ida_tryblks.catchvec_t_add_unique(self, x)

    def _del(self, x: 'catch_t') ->bool:
        return _ida_tryblks.catchvec_t__del(self, x)

    def __len__(self) ->'size_t':
        return _ida_tryblks.catchvec_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'catch_t const &':
        return _ida_tryblks.catchvec_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'catch_t') ->None:
        return _ida_tryblks.catchvec_t___setitem__(self, i, v)

    def append(self, x: 'catch_t') ->None:
        return _ida_tryblks.catchvec_t_append(self, x)

    def extend(self, x: 'catchvec_t') ->None:
        return _ida_tryblks.catchvec_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_tryblks.catchvec_t_swigregister(catchvec_t)


class try_handler_t(ida_range.rangevec_t):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    disp: 'sval_t' = property(_ida_tryblks.try_handler_t_disp_get,
        _ida_tryblks.try_handler_t_disp_set)
    fpreg: 'int' = property(_ida_tryblks.try_handler_t_fpreg_get,
        _ida_tryblks.try_handler_t_fpreg_set)

    def __init__(self):
        _ida_tryblks.try_handler_t_swiginit(self, _ida_tryblks.
            new_try_handler_t())

    def clear(self) ->None:
        return _ida_tryblks.try_handler_t_clear(self)
    __swig_destroy__ = _ida_tryblks.delete_try_handler_t


_ida_tryblks.try_handler_t_swigregister(try_handler_t)


class seh_t(try_handler_t):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    filter: 'rangevec_t' = property(_ida_tryblks.seh_t_filter_get,
        _ida_tryblks.seh_t_filter_set)
    seh_code: 'ea_t' = property(_ida_tryblks.seh_t_seh_code_get,
        _ida_tryblks.seh_t_seh_code_set)

    def clear(self) ->None:
        return _ida_tryblks.seh_t_clear(self)

    def __init__(self):
        _ida_tryblks.seh_t_swiginit(self, _ida_tryblks.new_seh_t())
    __swig_destroy__ = _ida_tryblks.delete_seh_t


_ida_tryblks.seh_t_swigregister(seh_t)


class catch_t(try_handler_t):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    obj: 'sval_t' = property(_ida_tryblks.catch_t_obj_get, _ida_tryblks.
        catch_t_obj_set)
    type_id: 'sval_t' = property(_ida_tryblks.catch_t_type_id_get,
        _ida_tryblks.catch_t_type_id_set)

    def __init__(self):
        _ida_tryblks.catch_t_swiginit(self, _ida_tryblks.new_catch_t())
    __swig_destroy__ = _ida_tryblks.delete_catch_t


_ida_tryblks.catch_t_swigregister(catch_t)


class tryblk_t(ida_range.rangevec_t):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    level: 'uchar' = property(_ida_tryblks.tryblk_t_level_get, _ida_tryblks
        .tryblk_t_level_set)

    def cpp(self) ->'catchvec_t &':
        return _ida_tryblks.tryblk_t_cpp(self)

    def seh(self) ->'seh_t &':
        return _ida_tryblks.tryblk_t_seh(self)
    __swig_destroy__ = _ida_tryblks.delete_tryblk_t

    def __init__(self, *args):
        _ida_tryblks.tryblk_t_swiginit(self, _ida_tryblks.new_tryblk_t(*args))

    def get_kind(self) ->'uchar':
        return _ida_tryblks.tryblk_t_get_kind(self)

    def empty(self) ->bool:
        return _ida_tryblks.tryblk_t_empty(self)

    def is_seh(self) ->bool:
        return _ida_tryblks.tryblk_t_is_seh(self)

    def is_cpp(self) ->bool:
        return _ida_tryblks.tryblk_t_is_cpp(self)

    def clear(self) ->None:
        return _ida_tryblks.tryblk_t_clear(self)

    def set_seh(self) ->'seh_t &':
        return _ida_tryblks.tryblk_t_set_seh(self)

    def set_cpp(self) ->'catchvec_t &':
        return _ida_tryblks.tryblk_t_set_cpp(self)


_ida_tryblks.tryblk_t_swigregister(tryblk_t)


def get_tryblks(tbv: 'tryblks_t', range: 'range_t') ->'size_t':
    """------------------------------------------------------------------------- Retrieve try block information from the specified address range. Try blocks are sorted by starting address and their nest levels calculated. 
        
@param tbv: output buffer; may be nullptr
@param range: address range to change
@returns number of found try blocks"""
    return _ida_tryblks.get_tryblks(tbv, range)


def del_tryblks(range: 'range_t') ->None:
    """Delete try block information in the specified range. 
        
@param range: the range to be cleared"""
    return _ida_tryblks.del_tryblks(range)


def add_tryblk(tb: 'tryblk_t') ->int:
    """Add one try block information. 
        
@param tb: try block to add.
@returns error code; 0 means good"""
    return _ida_tryblks.add_tryblk(tb)


TBERR_OK = _ida_tryblks.TBERR_OK
"""ok
"""
TBERR_START = _ida_tryblks.TBERR_START
"""bad start address
"""
TBERR_END = _ida_tryblks.TBERR_END
"""bad end address
"""
TBERR_ORDER = _ida_tryblks.TBERR_ORDER
"""bad address order
"""
TBERR_EMPTY = _ida_tryblks.TBERR_EMPTY
"""empty try block
"""
TBERR_KIND = _ida_tryblks.TBERR_KIND
"""illegal try block kind
"""
TBERR_NO_CATCHES = _ida_tryblks.TBERR_NO_CATCHES
"""no catch blocks at all
"""
TBERR_INTERSECT = _ida_tryblks.TBERR_INTERSECT
"""range would intersect inner tryblk
"""


def find_syseh(ea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
    """Find the start address of the system eh region including the argument. 
        
@param ea: search address
@returns start address of surrounding tryblk, otherwise BADADDR"""
    return _ida_tryblks.find_syseh(ea)


TBEA_TRY = _ida_tryblks.TBEA_TRY
"""is EA within a c++ try block?
"""
TBEA_CATCH = _ida_tryblks.TBEA_CATCH
"""is EA the start of a c++ catch/cleanup block?
"""
TBEA_SEHTRY = _ida_tryblks.TBEA_SEHTRY
"""is EA within a seh try block
"""
TBEA_SEHLPAD = _ida_tryblks.TBEA_SEHLPAD
"""is EA the start of a seh finally/except block?
"""
TBEA_SEHFILT = _ida_tryblks.TBEA_SEHFILT
"""is EA the start of a seh filter?
"""
TBEA_ANY = _ida_tryblks.TBEA_ANY
TBEA_FALLTHRU = _ida_tryblks.TBEA_FALLTHRU
"""is there a fall through into provided ea from an unwind region
"""


def is_ea_tryblks(ea: ida_idaapi.ea_t, flags: int) ->bool:
    """Check if the given address ea is part of tryblks description. 
        
@param ea: address to check
@param flags: combination of flags for is_ea_tryblks()"""
    return _ida_tryblks.is_ea_tryblks(ea, flags)

```
