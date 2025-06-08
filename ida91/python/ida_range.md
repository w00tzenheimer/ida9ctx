```python
"""Contains the definition of range_t.

A range is a non-empty continuous range of addresses (specified by its start and end addresses, the end address is excluded from the range).
Ranges are stored in the Btree part of the IDA database. To learn more about Btrees (Balanced Trees): [http://www.bluerwhite.org/btree/](http://www.bluerwhite.org/btree/) 
    """
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_range
else:
    import _ida_range
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
SWIG_PYTHON_LEGACY_BOOL = _ida_range.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi


class rangevec_base_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_range.rangevec_base_t_swiginit(self, _ida_range.
            new_rangevec_base_t(*args))
    __swig_destroy__ = _ida_range.delete_rangevec_base_t

    def push_back(self, *args) ->'range_t &':
        return _ida_range.rangevec_base_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_range.rangevec_base_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_range.rangevec_base_t_size(self)

    def empty(self) ->bool:
        return _ida_range.rangevec_base_t_empty(self)

    def at(self, _idx: 'size_t') ->'range_t const &':
        return _ida_range.rangevec_base_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_range.rangevec_base_t_qclear(self)

    def clear(self) ->None:
        return _ida_range.rangevec_base_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_range.rangevec_base_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_range.rangevec_base_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_range.rangevec_base_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_range.rangevec_base_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_range.rangevec_base_t_truncate(self)

    def swap(self, r: 'rangevec_base_t') ->None:
        return _ida_range.rangevec_base_t_swap(self, r)

    def extract(self) ->'range_t *':
        return _ida_range.rangevec_base_t_extract(self)

    def inject(self, s: 'range_t', len: 'size_t') ->None:
        return _ida_range.rangevec_base_t_inject(self, s, len)

    def __eq__(self, r: 'rangevec_base_t') ->bool:
        return _ida_range.rangevec_base_t___eq__(self, r)

    def __ne__(self, r: 'rangevec_base_t') ->bool:
        return _ida_range.rangevec_base_t___ne__(self, r)

    def begin(self, *args) ->'qvector< range_t >::const_iterator':
        return _ida_range.rangevec_base_t_begin(self, *args)

    def end(self, *args) ->'qvector< range_t >::const_iterator':
        return _ida_range.rangevec_base_t_end(self, *args)

    def insert(self, it: 'range_t', x: 'range_t'
        ) ->'qvector< range_t >::iterator':
        return _ida_range.rangevec_base_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< range_t >::iterator':
        return _ida_range.rangevec_base_t_erase(self, *args)

    def find(self, *args) ->'qvector< range_t >::const_iterator':
        return _ida_range.rangevec_base_t_find(self, *args)

    def has(self, x: 'range_t') ->bool:
        return _ida_range.rangevec_base_t_has(self, x)

    def add_unique(self, x: 'range_t') ->bool:
        return _ida_range.rangevec_base_t_add_unique(self, x)

    def _del(self, x: 'range_t') ->bool:
        return _ida_range.rangevec_base_t__del(self, x)

    def __len__(self) ->'size_t':
        return _ida_range.rangevec_base_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'range_t const &':
        return _ida_range.rangevec_base_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'range_t') ->None:
        return _ida_range.rangevec_base_t___setitem__(self, i, v)

    def append(self, x: 'range_t') ->None:
        return _ida_range.rangevec_base_t_append(self, x)

    def extend(self, x: 'rangevec_base_t') ->None:
        return _ida_range.rangevec_base_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_range.rangevec_base_t_swigregister(rangevec_base_t)


class array_of_rangesets(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_range.array_of_rangesets_swiginit(self, _ida_range.
            new_array_of_rangesets(*args))
    __swig_destroy__ = _ida_range.delete_array_of_rangesets

    def push_back(self, *args) ->'rangeset_t &':
        return _ida_range.array_of_rangesets_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_range.array_of_rangesets_pop_back(self)

    def size(self) ->'size_t':
        return _ida_range.array_of_rangesets_size(self)

    def empty(self) ->bool:
        return _ida_range.array_of_rangesets_empty(self)

    def at(self, _idx: 'size_t') ->'rangeset_t const &':
        return _ida_range.array_of_rangesets_at(self, _idx)

    def qclear(self) ->None:
        return _ida_range.array_of_rangesets_qclear(self)

    def clear(self) ->None:
        return _ida_range.array_of_rangesets_clear(self)

    def resize(self, *args) ->None:
        return _ida_range.array_of_rangesets_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_range.array_of_rangesets_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_range.array_of_rangesets_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_range.array_of_rangesets_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_range.array_of_rangesets_truncate(self)

    def swap(self, r: 'array_of_rangesets') ->None:
        return _ida_range.array_of_rangesets_swap(self, r)

    def extract(self) ->'rangeset_t *':
        return _ida_range.array_of_rangesets_extract(self)

    def inject(self, s: 'rangeset_t', len: 'size_t') ->None:
        return _ida_range.array_of_rangesets_inject(self, s, len)

    def __eq__(self, r: 'array_of_rangesets') ->bool:
        return _ida_range.array_of_rangesets___eq__(self, r)

    def __ne__(self, r: 'array_of_rangesets') ->bool:
        return _ida_range.array_of_rangesets___ne__(self, r)

    def begin(self, *args) ->'qvector< rangeset_t >::const_iterator':
        return _ida_range.array_of_rangesets_begin(self, *args)

    def end(self, *args) ->'qvector< rangeset_t >::const_iterator':
        return _ida_range.array_of_rangesets_end(self, *args)

    def insert(self, it: 'rangeset_t', x: 'rangeset_t'
        ) ->'qvector< rangeset_t >::iterator':
        return _ida_range.array_of_rangesets_insert(self, it, x)

    def erase(self, *args) ->'qvector< rangeset_t >::iterator':
        return _ida_range.array_of_rangesets_erase(self, *args)

    def find(self, *args) ->'qvector< rangeset_t >::const_iterator':
        return _ida_range.array_of_rangesets_find(self, *args)

    def has(self, x: 'rangeset_t') ->bool:
        return _ida_range.array_of_rangesets_has(self, x)

    def add_unique(self, x: 'rangeset_t') ->bool:
        return _ida_range.array_of_rangesets_add_unique(self, x)

    def _del(self, x: 'rangeset_t') ->bool:
        return _ida_range.array_of_rangesets__del(self, x)

    def __len__(self) ->'size_t':
        return _ida_range.array_of_rangesets___len__(self)

    def __getitem__(self, i: 'size_t') ->'rangeset_t const &':
        return _ida_range.array_of_rangesets___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'rangeset_t') ->None:
        return _ida_range.array_of_rangesets___setitem__(self, i, v)

    def append(self, x: 'rangeset_t') ->None:
        return _ida_range.array_of_rangesets_append(self, x)

    def extend(self, x: 'array_of_rangesets') ->None:
        return _ida_range.array_of_rangesets_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_range.array_of_rangesets_swigregister(array_of_rangesets)
import ida_idaapi


class range_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    start_ea: 'ea_t' = property(_ida_range.range_t_start_ea_get, _ida_range
        .range_t_start_ea_set)
    """start_ea included
"""
    end_ea: 'ea_t' = property(_ida_range.range_t_end_ea_get, _ida_range.
        range_t_end_ea_set)
    """end_ea excluded
"""

    def __init__(self, ea1: ida_idaapi.ea_t=0, ea2: ida_idaapi.ea_t=0):
        _ida_range.range_t_swiginit(self, _ida_range.new_range_t(ea1, ea2))

    def __eq__(self, r: 'range_t') ->bool:
        return _ida_range.range_t___eq__(self, r)

    def __ne__(self, r: 'range_t') ->bool:
        return _ida_range.range_t___ne__(self, r)

    def __lt__(self, r: 'range_t') ->bool:
        return _ida_range.range_t___lt__(self, r)

    def __gt__(self, r: 'range_t') ->bool:
        return _ida_range.range_t___gt__(self, r)

    def __le__(self, r: 'range_t') ->bool:
        return _ida_range.range_t___le__(self, r)

    def __ge__(self, r: 'range_t') ->bool:
        return _ida_range.range_t___ge__(self, r)

    def compare(self, r: 'range_t') ->int:
        return _ida_range.range_t_compare(self, r)

    def contains(self, *args) ->bool:
        """This function has the following signatures:

    0. contains(ea: ida_idaapi.ea_t) -> bool
    1. contains(r: const range_t &) -> bool

# 0: contains(ea: ida_idaapi.ea_t) -> bool

Compare two range_t instances, based on the start_ea.

Is 'ea' in the address range? 
        

# 1: contains(r: const range_t &) -> bool

Is every ea in 'r' also in this range_t?

"""
        return _ida_range.range_t_contains(self, *args)

    def overlaps(self, r: 'range_t') ->bool:
        """Is there an ea in 'r' that is also in this range_t?
"""
        return _ida_range.range_t_overlaps(self, r)

    def clear(self) ->None:
        """Set start_ea, end_ea to 0.
"""
        return _ida_range.range_t_clear(self)

    def empty(self) ->bool:
        """Is the size of the range_t <= 0?
"""
        return _ida_range.range_t_empty(self)

    def size(self) ->'asize_t':
        """Get end_ea - start_ea.
"""
        return _ida_range.range_t_size(self)

    def intersect(self, r: 'range_t') ->None:
        """Assign the range_t to the intersection between the range_t and 'r'.
"""
        return _ida_range.range_t_intersect(self, r)

    def extend(self, ea: ida_idaapi.ea_t) ->None:
        """Ensure that the range_t includes 'ea'.
"""
        return _ida_range.range_t_extend(self, ea)

    def _print(self, *args) ->'size_t':
        return _ida_range.range_t__print(self, *args)
    __swig_destroy__ = _ida_range.delete_range_t


_ida_range.range_t_swigregister(range_t)


def range_t_print(cb: 'range_t') ->str:
    """Helper function. Should not be called directly!
"""
    return _ida_range.range_t_print(cb)


class rangevec_t(rangevec_base_t):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_range.rangevec_t_swiginit(self, _ida_range.new_rangevec_t())
    __swig_destroy__ = _ida_range.delete_rangevec_t


_ida_range.rangevec_t_swigregister(rangevec_t)
RANGE_KIND_UNKNOWN = _ida_range.RANGE_KIND_UNKNOWN
RANGE_KIND_FUNC = _ida_range.RANGE_KIND_FUNC
"""func_t
"""
RANGE_KIND_SEGMENT = _ida_range.RANGE_KIND_SEGMENT
"""segment_t
"""
RANGE_KIND_HIDDEN_RANGE = _ida_range.RANGE_KIND_HIDDEN_RANGE
"""hidden_range_t
"""


class rangeset_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_range.rangeset_t_swiginit(self, _ida_range.new_rangeset_t(*args))

    def swap(self, r: 'rangeset_t') ->None:
        """Set this = 'r' and 'r' = this. See qvector::swap()
"""
        return _ida_range.rangeset_t_swap(self, r)

    def add(self, *args) ->bool:
        """This function has the following signatures:

    0. add(range: const range_t &) -> bool
    1. add(start: ida_idaapi.ea_t, _end: ida_idaapi.ea_t) -> bool
    2. add(aset: const rangeset_t &) -> bool

# 0: add(range: const range_t &) -> bool

Add an address range to the set. If 'range' intersects an existing element e, then e is extended to include 'range', and any superfluous elements (subsets of e) are removed. 
        
@returns false if 'range' was not added (the set was unchanged)

# 1: add(start: ida_idaapi.ea_t, _end: ida_idaapi.ea_t) -> bool

Create a new range_t from 'start' and 'end' and add it to the set.


# 2: add(aset: const rangeset_t &) -> bool

Add each element of 'aset' to the set. 
        
@returns false if no elements were added (the set was unchanged)
"""
        return _ida_range.rangeset_t_add(self, *args)

    def sub(self, *args) ->bool:
        """This function has the following signatures:

    0. sub(range: const range_t &) -> bool
    1. sub(ea: ida_idaapi.ea_t) -> bool
    2. sub(aset: const rangeset_t &) -> bool

# 0: sub(range: const range_t &) -> bool

Subtract an address range from the set. All subsets of 'range' will be removed, and all elements that intersect 'range' will be truncated/split so they do not include 'range'. 
        
@returns false if 'range' was not subtracted (the set was unchanged)

# 1: sub(ea: ida_idaapi.ea_t) -> bool

Subtract an ea (an range of size 1) from the set. See sub(const range_t &)


# 2: sub(aset: const rangeset_t &) -> bool

Subtract each range in 'aset' from the set 
        
@returns false if nothing was subtracted (the set was unchanged)
"""
        return _ida_range.rangeset_t_sub(self, *args)

    def includes(self, range: 'range_t') ->bool:
        """Is every ea in 'range' contained in the rangeset?
"""
        return _ida_range.rangeset_t_includes(self, range)

    def _print(self, *args) ->'size_t':
        return _ida_range.rangeset_t__print(self, *args)

    def getrange(self, idx: int) ->'range_t const &':
        """Get the range_t at index 'idx'.
"""
        return _ida_range.rangeset_t_getrange(self, idx)

    def lastrange(self) ->'range_t const &':
        """Get the last range_t in the set.
"""
        return _ida_range.rangeset_t_lastrange(self)

    def nranges(self) ->'size_t':
        """Get the number of range_t elements in the set.
"""
        return _ida_range.rangeset_t_nranges(self)

    def empty(self) ->bool:
        """Does the set have zero elements.
"""
        return _ida_range.rangeset_t_empty(self)

    def clear(self) ->None:
        """Delete all elements from the set. See qvector::clear()
"""
        return _ida_range.rangeset_t_clear(self)

    def has_common(self, *args) ->bool:
        """This function has the following signatures:

    0. has_common(range: const range_t &) -> bool
    1. has_common(aset: const rangeset_t &) -> bool

# 0: has_common(range: const range_t &) -> bool

Is there an ea in 'range' that is also in the rangeset?


# 1: has_common(aset: const rangeset_t &) -> bool

Does any element of 'aset' overlap with an element in this rangeset?. See range_t::overlaps()

"""
        return _ida_range.rangeset_t_has_common(self, *args)

    def contains(self, *args) ->bool:
        """This function has the following signatures:

    0. contains(ea: ida_idaapi.ea_t) -> bool
    1. contains(aset: const rangeset_t &) -> bool

# 0: contains(ea: ida_idaapi.ea_t) -> bool

Does an element of the rangeset contain 'ea'? See range_t::contains(ea_t)


# 1: contains(aset: const rangeset_t &) -> bool

Is every element in 'aset' contained in an element of this rangeset?. See range_t::contains(range_t)

"""
        return _ida_range.rangeset_t_contains(self, *args)

    def intersect(self, aset: 'rangeset_t') ->bool:
        """Set the rangeset to its intersection with 'aset'. 
        
@returns false if the set was unchanged"""
        return _ida_range.rangeset_t_intersect(self, aset)

    def is_subset_of(self, aset: 'rangeset_t') ->bool:
        """Is every element in the rangeset contained in an element of 'aset'?
"""
        return _ida_range.rangeset_t_is_subset_of(self, aset)

    def is_equal(self, aset: 'rangeset_t') ->bool:
        """Do this rangeset and 'aset' have identical elements?
"""
        return _ida_range.rangeset_t_is_equal(self, aset)

    def __eq__(self, aset: 'rangeset_t') ->bool:
        return _ida_range.rangeset_t___eq__(self, aset)

    def __ne__(self, aset: 'rangeset_t') ->bool:
        return _ida_range.rangeset_t___ne__(self, aset)

    def begin(self) ->'rangeset_t::iterator':
        """Get an iterator that points to the first element in the set.
"""
        return _ida_range.rangeset_t_begin(self)

    def end(self) ->'rangeset_t::iterator':
        """Get an iterator that points to the end of the set. (This is NOT the last element)
"""
        return _ida_range.rangeset_t_end(self)

    def find_range(self, ea: ida_idaapi.ea_t) ->'range_t const *':
        """Get the element from the set that contains 'ea'. 
        
@returns nullptr if there is no such element"""
        return _ida_range.rangeset_t_find_range(self, ea)

    def cached_range(self) ->'range_t const *':
        """When searching the rangeset, we keep a cached element to help speed up searches. 
        
@returns a pointer to the cached element"""
        return _ida_range.rangeset_t_cached_range(self)

    def next_addr(self, ea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
        """Get the smallest ea_t value greater than 'ea' contained in the rangeset.
"""
        return _ida_range.rangeset_t_next_addr(self, ea)

    def prev_addr(self, ea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
        """Get the largest ea_t value less than 'ea' contained in the rangeset.
"""
        return _ida_range.rangeset_t_prev_addr(self, ea)

    def next_range(self, ea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
        """Get the smallest ea_t value greater than 'ea' that is not in the same range as 'ea'.
"""
        return _ida_range.rangeset_t_next_range(self, ea)

    def prev_range(self, ea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
        """Get the largest ea_t value less than 'ea' that is not in the same range as 'ea'.
"""
        return _ida_range.rangeset_t_prev_range(self, ea)

    def __getitem__(self, idx):
        return self.getrange(idx)
    __len__ = nranges
    __iter__ = ida_idaapi._bounded_getitem_iterator
    __swig_destroy__ = _ida_range.delete_rangeset_t


_ida_range.rangeset_t_swigregister(rangeset_t)

```
