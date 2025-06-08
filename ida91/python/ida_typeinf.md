```python
"""Type information in IDA.

In IDA, types are represented by and manipulated through tinfo_t objects.
A tinfo_t can represent a simple type (e.g., `int`, `float`), a complex type (a structure, enum, union, typedef), or even an array, or a function prototype.
The key types in this file are:

* til_t - a type info library. Holds type information in serialized form.
* tinfo_t - information about a type (simple, complex, ...)


# Glossary
All throughout this file, there are certain terms that will keep appearing:

* udt: "user-defined type": a structure or union - but not enums. See udt_type_data_t
* udm: "udt member": i.e., a structure or union member. See udm_t
* edm: "enum member": i.e., an enumeration member - i.e., an enumerator. See edm_t


# Under the hood
The tinfo_t type provides a lot of useful methods already, but it's possible to achieve even more by retrieving its contents into the container classes:

* udt_type_data_t - for structures & unions. See tinfo_t::get_udt_details . Essentially, a vector of udm_t
* enum_type_data_t - for enumerations. See tinfo_t::get_enum_details . Essentially, a vector of edm_t
* ptr_type_data_t - for pointers. See tinfo_t::get_ptr_details
* array_type_data_t - for arrays. See tinfo_t::get_array_details
* func_type_data_t - for function prototypes. See tinfo_t::get_func_details
* bitfield_type_data_t - for bitfields. See tinfo_t::get_bitfield_details


# Attached & detached tinfo_t objects
tinfo_t objects can be attached to a til_t library, or can be created without using any til_t.
Here is an example, assigning a function prototype:
func_type_data_t func_info;
funcarg_t argc; argc.name = "argc"; argc.type = tinfo_t(BT_INT); func_info.push_back(argc);
funcarg_t argv; argc.name = "argv"; argc.type = tinfo_t("const char **"); func_info.push_back(argv)
tinfo_t tif; if ( tif.create_func(func_info) ) { ea_t ea = // get address of "main" apply_tinfo(ea, tif, TINFO_DEFINITE); }
This code manipulates a "detached" tinfo_t object, which does not depend on any til_t file. However, any complex type will require a til_t file. In IDA, there is always a default til_t file for each idb file. This til_t file can be specified by nullptr.
On the other hand, the following code manipulates an "attached" tinfo_t object, and any operation that modifies it, will also modify it in the hosting til_t:
tinfo_t tif; Load type from the "Local Types" til_t. Note: we could have used `get_idati()` instead of nullptr if ( tif.get_named_type(nullptr, "my_struct_t") ) tif.add_udm("extra_field", "unsigned long long");
You can check if a tinfo_t instance is attached to a type in a til_t file by calling tinfo_t::is_typeref 
    """
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_typeinf
else:
    import _ida_typeinf
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
SWIG_PYTHON_LEGACY_BOOL = _ida_typeinf.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi
import ida_idp
DEFMASK64 = _ida_typeinf.DEFMASK64
"""default bitmask 64bits
"""


def deserialize_tinfo(tif: 'tinfo_t', til: 'til_t', ptype:
    'type_t const **', pfields: 'p_list const **', pfldcmts:
    'p_list const **', cmt: str=None) ->bool:
    return _ida_typeinf.deserialize_tinfo(tif, til, ptype, pfields,
        pfldcmts, cmt)


class funcargvec_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_typeinf.funcargvec_t_swiginit(self, _ida_typeinf.
            new_funcargvec_t(*args))
    __swig_destroy__ = _ida_typeinf.delete_funcargvec_t

    def push_back(self, *args) ->'funcarg_t &':
        return _ida_typeinf.funcargvec_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_typeinf.funcargvec_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_typeinf.funcargvec_t_size(self)

    def empty(self) ->bool:
        return _ida_typeinf.funcargvec_t_empty(self)

    def at(self, _idx: 'size_t') ->'funcarg_t const &':
        return _ida_typeinf.funcargvec_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_typeinf.funcargvec_t_qclear(self)

    def clear(self) ->None:
        return _ida_typeinf.funcargvec_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_typeinf.funcargvec_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_typeinf.funcargvec_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_typeinf.funcargvec_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_typeinf.funcargvec_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_typeinf.funcargvec_t_truncate(self)

    def swap(self, r: 'funcargvec_t') ->None:
        return _ida_typeinf.funcargvec_t_swap(self, r)

    def extract(self) ->'funcarg_t *':
        return _ida_typeinf.funcargvec_t_extract(self)

    def inject(self, s: 'funcarg_t', len: 'size_t') ->None:
        return _ida_typeinf.funcargvec_t_inject(self, s, len)

    def __eq__(self, r: 'funcargvec_t') ->bool:
        return _ida_typeinf.funcargvec_t___eq__(self, r)

    def __ne__(self, r: 'funcargvec_t') ->bool:
        return _ida_typeinf.funcargvec_t___ne__(self, r)

    def begin(self, *args) ->'qvector< funcarg_t >::const_iterator':
        return _ida_typeinf.funcargvec_t_begin(self, *args)

    def end(self, *args) ->'qvector< funcarg_t >::const_iterator':
        return _ida_typeinf.funcargvec_t_end(self, *args)

    def insert(self, it: 'funcarg_t', x: 'funcarg_t'
        ) ->'qvector< funcarg_t >::iterator':
        return _ida_typeinf.funcargvec_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< funcarg_t >::iterator':
        return _ida_typeinf.funcargvec_t_erase(self, *args)

    def find(self, *args) ->'qvector< funcarg_t >::const_iterator':
        return _ida_typeinf.funcargvec_t_find(self, *args)

    def has(self, x: 'funcarg_t') ->bool:
        return _ida_typeinf.funcargvec_t_has(self, x)

    def add_unique(self, x: 'funcarg_t') ->bool:
        return _ida_typeinf.funcargvec_t_add_unique(self, x)

    def _del(self, x: 'funcarg_t') ->bool:
        return _ida_typeinf.funcargvec_t__del(self, x)

    def __len__(self) ->'size_t':
        return _ida_typeinf.funcargvec_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'funcarg_t const &':
        return _ida_typeinf.funcargvec_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'funcarg_t') ->None:
        return _ida_typeinf.funcargvec_t___setitem__(self, i, v)

    def append(self, x: 'funcarg_t') ->None:
        return _ida_typeinf.funcargvec_t_append(self, x)

    def extend(self, x: 'funcargvec_t') ->None:
        return _ida_typeinf.funcargvec_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_typeinf.funcargvec_t_swigregister(funcargvec_t)


class reginfovec_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_typeinf.reginfovec_t_swiginit(self, _ida_typeinf.
            new_reginfovec_t(*args))
    __swig_destroy__ = _ida_typeinf.delete_reginfovec_t

    def push_back(self, *args) ->'reg_info_t &':
        return _ida_typeinf.reginfovec_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_typeinf.reginfovec_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_typeinf.reginfovec_t_size(self)

    def empty(self) ->bool:
        return _ida_typeinf.reginfovec_t_empty(self)

    def at(self, _idx: 'size_t') ->'reg_info_t const &':
        return _ida_typeinf.reginfovec_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_typeinf.reginfovec_t_qclear(self)

    def clear(self) ->None:
        return _ida_typeinf.reginfovec_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_typeinf.reginfovec_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_typeinf.reginfovec_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_typeinf.reginfovec_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_typeinf.reginfovec_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_typeinf.reginfovec_t_truncate(self)

    def swap(self, r: 'reginfovec_t') ->None:
        return _ida_typeinf.reginfovec_t_swap(self, r)

    def extract(self) ->'reg_info_t *':
        return _ida_typeinf.reginfovec_t_extract(self)

    def inject(self, s: 'reg_info_t', len: 'size_t') ->None:
        return _ida_typeinf.reginfovec_t_inject(self, s, len)

    def __eq__(self, r: 'reginfovec_t') ->bool:
        return _ida_typeinf.reginfovec_t___eq__(self, r)

    def __ne__(self, r: 'reginfovec_t') ->bool:
        return _ida_typeinf.reginfovec_t___ne__(self, r)

    def begin(self, *args) ->'qvector< reg_info_t >::const_iterator':
        return _ida_typeinf.reginfovec_t_begin(self, *args)

    def end(self, *args) ->'qvector< reg_info_t >::const_iterator':
        return _ida_typeinf.reginfovec_t_end(self, *args)

    def insert(self, it: 'reg_info_t', x: 'reg_info_t'
        ) ->'qvector< reg_info_t >::iterator':
        return _ida_typeinf.reginfovec_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< reg_info_t >::iterator':
        return _ida_typeinf.reginfovec_t_erase(self, *args)

    def find(self, *args) ->'qvector< reg_info_t >::const_iterator':
        return _ida_typeinf.reginfovec_t_find(self, *args)

    def has(self, x: 'reg_info_t') ->bool:
        return _ida_typeinf.reginfovec_t_has(self, x)

    def add_unique(self, x: 'reg_info_t') ->bool:
        return _ida_typeinf.reginfovec_t_add_unique(self, x)

    def _del(self, x: 'reg_info_t') ->bool:
        return _ida_typeinf.reginfovec_t__del(self, x)

    def __len__(self) ->'size_t':
        return _ida_typeinf.reginfovec_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'reg_info_t const &':
        return _ida_typeinf.reginfovec_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'reg_info_t') ->None:
        return _ida_typeinf.reginfovec_t___setitem__(self, i, v)

    def append(self, x: 'reg_info_t') ->None:
        return _ida_typeinf.reginfovec_t_append(self, x)

    def extend(self, x: 'reginfovec_t') ->None:
        return _ida_typeinf.reginfovec_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_typeinf.reginfovec_t_swigregister(reginfovec_t)


class edmvec_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_typeinf.edmvec_t_swiginit(self, _ida_typeinf.new_edmvec_t(*args))
    __swig_destroy__ = _ida_typeinf.delete_edmvec_t

    def push_back(self, *args) ->'edm_t &':
        return _ida_typeinf.edmvec_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_typeinf.edmvec_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_typeinf.edmvec_t_size(self)

    def empty(self) ->bool:
        return _ida_typeinf.edmvec_t_empty(self)

    def at(self, _idx: 'size_t') ->'edm_t const &':
        return _ida_typeinf.edmvec_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_typeinf.edmvec_t_qclear(self)

    def clear(self) ->None:
        return _ida_typeinf.edmvec_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_typeinf.edmvec_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_typeinf.edmvec_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_typeinf.edmvec_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_typeinf.edmvec_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_typeinf.edmvec_t_truncate(self)

    def swap(self, r: 'edmvec_t') ->None:
        return _ida_typeinf.edmvec_t_swap(self, r)

    def extract(self) ->'edm_t *':
        return _ida_typeinf.edmvec_t_extract(self)

    def inject(self, s: 'edm_t', len: 'size_t') ->None:
        return _ida_typeinf.edmvec_t_inject(self, s, len)

    def __eq__(self, r: 'edmvec_t') ->bool:
        return _ida_typeinf.edmvec_t___eq__(self, r)

    def __ne__(self, r: 'edmvec_t') ->bool:
        return _ida_typeinf.edmvec_t___ne__(self, r)

    def begin(self, *args) ->'qvector< edm_t >::const_iterator':
        return _ida_typeinf.edmvec_t_begin(self, *args)

    def end(self, *args) ->'qvector< edm_t >::const_iterator':
        return _ida_typeinf.edmvec_t_end(self, *args)

    def insert(self, it: 'edm_t', x: 'edm_t') ->'qvector< edm_t >::iterator':
        return _ida_typeinf.edmvec_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< edm_t >::iterator':
        return _ida_typeinf.edmvec_t_erase(self, *args)

    def find(self, *args) ->'qvector< edm_t >::const_iterator':
        return _ida_typeinf.edmvec_t_find(self, *args)

    def has(self, x: 'edm_t') ->bool:
        return _ida_typeinf.edmvec_t_has(self, x)

    def add_unique(self, x: 'edm_t') ->bool:
        return _ida_typeinf.edmvec_t_add_unique(self, x)

    def _del(self, x: 'edm_t') ->bool:
        return _ida_typeinf.edmvec_t__del(self, x)

    def __len__(self) ->'size_t':
        return _ida_typeinf.edmvec_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'edm_t const &':
        return _ida_typeinf.edmvec_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'edm_t') ->None:
        return _ida_typeinf.edmvec_t___setitem__(self, i, v)

    def append(self, x: 'edm_t') ->None:
        return _ida_typeinf.edmvec_t_append(self, x)

    def extend(self, x: 'edmvec_t') ->None:
        return _ida_typeinf.edmvec_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_typeinf.edmvec_t_swigregister(edmvec_t)


class argpartvec_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_typeinf.argpartvec_t_swiginit(self, _ida_typeinf.
            new_argpartvec_t(*args))
    __swig_destroy__ = _ida_typeinf.delete_argpartvec_t

    def push_back(self, *args) ->'argpart_t &':
        return _ida_typeinf.argpartvec_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_typeinf.argpartvec_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_typeinf.argpartvec_t_size(self)

    def empty(self) ->bool:
        return _ida_typeinf.argpartvec_t_empty(self)

    def at(self, _idx: 'size_t') ->'argpart_t const &':
        return _ida_typeinf.argpartvec_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_typeinf.argpartvec_t_qclear(self)

    def clear(self) ->None:
        return _ida_typeinf.argpartvec_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_typeinf.argpartvec_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_typeinf.argpartvec_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_typeinf.argpartvec_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_typeinf.argpartvec_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_typeinf.argpartvec_t_truncate(self)

    def swap(self, r: 'argpartvec_t') ->None:
        return _ida_typeinf.argpartvec_t_swap(self, r)

    def extract(self) ->'argpart_t *':
        return _ida_typeinf.argpartvec_t_extract(self)

    def inject(self, s: 'argpart_t', len: 'size_t') ->None:
        return _ida_typeinf.argpartvec_t_inject(self, s, len)

    def __eq__(self, r: 'argpartvec_t') ->bool:
        return _ida_typeinf.argpartvec_t___eq__(self, r)

    def __ne__(self, r: 'argpartvec_t') ->bool:
        return _ida_typeinf.argpartvec_t___ne__(self, r)

    def begin(self, *args) ->'qvector< argpart_t >::const_iterator':
        return _ida_typeinf.argpartvec_t_begin(self, *args)

    def end(self, *args) ->'qvector< argpart_t >::const_iterator':
        return _ida_typeinf.argpartvec_t_end(self, *args)

    def insert(self, it: 'argpart_t', x: 'argpart_t'
        ) ->'qvector< argpart_t >::iterator':
        return _ida_typeinf.argpartvec_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< argpart_t >::iterator':
        return _ida_typeinf.argpartvec_t_erase(self, *args)

    def find(self, *args) ->'qvector< argpart_t >::const_iterator':
        return _ida_typeinf.argpartvec_t_find(self, *args)

    def has(self, x: 'argpart_t') ->bool:
        return _ida_typeinf.argpartvec_t_has(self, x)

    def add_unique(self, x: 'argpart_t') ->bool:
        return _ida_typeinf.argpartvec_t_add_unique(self, x)

    def _del(self, x: 'argpart_t') ->bool:
        return _ida_typeinf.argpartvec_t__del(self, x)

    def __len__(self) ->'size_t':
        return _ida_typeinf.argpartvec_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'argpart_t const &':
        return _ida_typeinf.argpartvec_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'argpart_t') ->None:
        return _ida_typeinf.argpartvec_t___setitem__(self, i, v)

    def append(self, x: 'argpart_t') ->None:
        return _ida_typeinf.argpartvec_t_append(self, x)

    def extend(self, x: 'argpartvec_t') ->None:
        return _ida_typeinf.argpartvec_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_typeinf.argpartvec_t_swigregister(argpartvec_t)


class valstrvec_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_typeinf.valstrvec_t_swiginit(self, _ida_typeinf.
            new_valstrvec_t(*args))
    __swig_destroy__ = _ida_typeinf.delete_valstrvec_t

    def push_back(self, *args) ->'valstr_t &':
        return _ida_typeinf.valstrvec_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_typeinf.valstrvec_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_typeinf.valstrvec_t_size(self)

    def empty(self) ->bool:
        return _ida_typeinf.valstrvec_t_empty(self)

    def at(self, _idx: 'size_t') ->'valstr_t const &':
        return _ida_typeinf.valstrvec_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_typeinf.valstrvec_t_qclear(self)

    def clear(self) ->None:
        return _ida_typeinf.valstrvec_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_typeinf.valstrvec_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_typeinf.valstrvec_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_typeinf.valstrvec_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_typeinf.valstrvec_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_typeinf.valstrvec_t_truncate(self)

    def swap(self, r: 'valstrvec_t') ->None:
        return _ida_typeinf.valstrvec_t_swap(self, r)

    def extract(self) ->'valstr_t *':
        return _ida_typeinf.valstrvec_t_extract(self)

    def inject(self, s: 'valstr_t', len: 'size_t') ->None:
        return _ida_typeinf.valstrvec_t_inject(self, s, len)

    def begin(self, *args) ->'qvector< valstr_t >::const_iterator':
        return _ida_typeinf.valstrvec_t_begin(self, *args)

    def end(self, *args) ->'qvector< valstr_t >::const_iterator':
        return _ida_typeinf.valstrvec_t_end(self, *args)

    def insert(self, it: 'valstr_t', x: 'valstr_t'
        ) ->'qvector< valstr_t >::iterator':
        return _ida_typeinf.valstrvec_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< valstr_t >::iterator':
        return _ida_typeinf.valstrvec_t_erase(self, *args)

    def __len__(self) ->'size_t':
        return _ida_typeinf.valstrvec_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'valstr_t const &':
        return _ida_typeinf.valstrvec_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'valstr_t') ->None:
        return _ida_typeinf.valstrvec_t___setitem__(self, i, v)

    def append(self, x: 'valstr_t') ->None:
        return _ida_typeinf.valstrvec_t_append(self, x)

    def extend(self, x: 'valstrvec_t') ->None:
        return _ida_typeinf.valstrvec_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_typeinf.valstrvec_t_swigregister(valstrvec_t)


class regobjvec_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_typeinf.regobjvec_t_swiginit(self, _ida_typeinf.
            new_regobjvec_t(*args))
    __swig_destroy__ = _ida_typeinf.delete_regobjvec_t

    def push_back(self, *args) ->'regobj_t &':
        return _ida_typeinf.regobjvec_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_typeinf.regobjvec_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_typeinf.regobjvec_t_size(self)

    def empty(self) ->bool:
        return _ida_typeinf.regobjvec_t_empty(self)

    def at(self, _idx: 'size_t') ->'regobj_t const &':
        return _ida_typeinf.regobjvec_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_typeinf.regobjvec_t_qclear(self)

    def clear(self) ->None:
        return _ida_typeinf.regobjvec_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_typeinf.regobjvec_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_typeinf.regobjvec_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_typeinf.regobjvec_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_typeinf.regobjvec_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_typeinf.regobjvec_t_truncate(self)

    def swap(self, r: 'regobjvec_t') ->None:
        return _ida_typeinf.regobjvec_t_swap(self, r)

    def extract(self) ->'regobj_t *':
        return _ida_typeinf.regobjvec_t_extract(self)

    def inject(self, s: 'regobj_t', len: 'size_t') ->None:
        return _ida_typeinf.regobjvec_t_inject(self, s, len)

    def begin(self, *args) ->'qvector< regobj_t >::const_iterator':
        return _ida_typeinf.regobjvec_t_begin(self, *args)

    def end(self, *args) ->'qvector< regobj_t >::const_iterator':
        return _ida_typeinf.regobjvec_t_end(self, *args)

    def insert(self, it: 'regobj_t', x: 'regobj_t'
        ) ->'qvector< regobj_t >::iterator':
        return _ida_typeinf.regobjvec_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< regobj_t >::iterator':
        return _ida_typeinf.regobjvec_t_erase(self, *args)

    def __len__(self) ->'size_t':
        return _ida_typeinf.regobjvec_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'regobj_t const &':
        return _ida_typeinf.regobjvec_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'regobj_t') ->None:
        return _ida_typeinf.regobjvec_t___setitem__(self, i, v)

    def append(self, x: 'regobj_t') ->None:
        return _ida_typeinf.regobjvec_t_append(self, x)

    def extend(self, x: 'regobjvec_t') ->None:
        return _ida_typeinf.regobjvec_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_typeinf.regobjvec_t_swigregister(regobjvec_t)


class type_attrs_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_typeinf.type_attrs_t_swiginit(self, _ida_typeinf.
            new_type_attrs_t(*args))
    __swig_destroy__ = _ida_typeinf.delete_type_attrs_t

    def push_back(self, *args) ->'type_attr_t &':
        return _ida_typeinf.type_attrs_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_typeinf.type_attrs_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_typeinf.type_attrs_t_size(self)

    def empty(self) ->bool:
        return _ida_typeinf.type_attrs_t_empty(self)

    def at(self, _idx: 'size_t') ->'type_attr_t const &':
        return _ida_typeinf.type_attrs_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_typeinf.type_attrs_t_qclear(self)

    def clear(self) ->None:
        return _ida_typeinf.type_attrs_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_typeinf.type_attrs_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_typeinf.type_attrs_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_typeinf.type_attrs_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_typeinf.type_attrs_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_typeinf.type_attrs_t_truncate(self)

    def swap(self, r: 'type_attrs_t') ->None:
        return _ida_typeinf.type_attrs_t_swap(self, r)

    def extract(self) ->'type_attr_t *':
        return _ida_typeinf.type_attrs_t_extract(self)

    def inject(self, s: 'type_attr_t', len: 'size_t') ->None:
        return _ida_typeinf.type_attrs_t_inject(self, s, len)

    def begin(self, *args) ->'qvector< type_attr_t >::const_iterator':
        return _ida_typeinf.type_attrs_t_begin(self, *args)

    def end(self, *args) ->'qvector< type_attr_t >::const_iterator':
        return _ida_typeinf.type_attrs_t_end(self, *args)

    def insert(self, it: 'type_attr_t', x: 'type_attr_t'
        ) ->'qvector< type_attr_t >::iterator':
        return _ida_typeinf.type_attrs_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< type_attr_t >::iterator':
        return _ida_typeinf.type_attrs_t_erase(self, *args)

    def __len__(self) ->'size_t':
        return _ida_typeinf.type_attrs_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'type_attr_t const &':
        return _ida_typeinf.type_attrs_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'type_attr_t') ->None:
        return _ida_typeinf.type_attrs_t___setitem__(self, i, v)

    def append(self, x: 'type_attr_t') ->None:
        return _ida_typeinf.type_attrs_t_append(self, x)

    def extend(self, x: 'type_attrs_t') ->None:
        return _ida_typeinf.type_attrs_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_typeinf.type_attrs_t_swigregister(type_attrs_t)


class udtmembervec_template_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_typeinf.udtmembervec_template_t_swiginit(self, _ida_typeinf.
            new_udtmembervec_template_t(*args))
    __swig_destroy__ = _ida_typeinf.delete_udtmembervec_template_t

    def push_back(self, *args) ->'udm_t &':
        return _ida_typeinf.udtmembervec_template_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_typeinf.udtmembervec_template_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_typeinf.udtmembervec_template_t_size(self)

    def empty(self) ->bool:
        return _ida_typeinf.udtmembervec_template_t_empty(self)

    def at(self, _idx: 'size_t') ->'udm_t const &':
        return _ida_typeinf.udtmembervec_template_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_typeinf.udtmembervec_template_t_qclear(self)

    def clear(self) ->None:
        return _ida_typeinf.udtmembervec_template_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_typeinf.udtmembervec_template_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_typeinf.udtmembervec_template_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_typeinf.udtmembervec_template_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_typeinf.udtmembervec_template_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_typeinf.udtmembervec_template_t_truncate(self)

    def swap(self, r: 'udtmembervec_template_t') ->None:
        return _ida_typeinf.udtmembervec_template_t_swap(self, r)

    def extract(self) ->'udm_t *':
        return _ida_typeinf.udtmembervec_template_t_extract(self)

    def inject(self, s: 'udm_t', len: 'size_t') ->None:
        return _ida_typeinf.udtmembervec_template_t_inject(self, s, len)

    def __eq__(self, r: 'udtmembervec_template_t') ->bool:
        return _ida_typeinf.udtmembervec_template_t___eq__(self, r)

    def __ne__(self, r: 'udtmembervec_template_t') ->bool:
        return _ida_typeinf.udtmembervec_template_t___ne__(self, r)

    def begin(self, *args) ->'qvector< udm_t >::const_iterator':
        return _ida_typeinf.udtmembervec_template_t_begin(self, *args)

    def end(self, *args) ->'qvector< udm_t >::const_iterator':
        return _ida_typeinf.udtmembervec_template_t_end(self, *args)

    def insert(self, it: 'udm_t', x: 'udm_t') ->'qvector< udm_t >::iterator':
        return _ida_typeinf.udtmembervec_template_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< udm_t >::iterator':
        return _ida_typeinf.udtmembervec_template_t_erase(self, *args)

    def find(self, *args) ->'qvector< udm_t >::const_iterator':
        return _ida_typeinf.udtmembervec_template_t_find(self, *args)

    def has(self, x: 'udm_t') ->bool:
        return _ida_typeinf.udtmembervec_template_t_has(self, x)

    def add_unique(self, x: 'udm_t') ->bool:
        return _ida_typeinf.udtmembervec_template_t_add_unique(self, x)

    def _del(self, x: 'udm_t') ->bool:
        return _ida_typeinf.udtmembervec_template_t__del(self, x)

    def __len__(self) ->'size_t':
        return _ida_typeinf.udtmembervec_template_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'udm_t const &':
        return _ida_typeinf.udtmembervec_template_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'udm_t') ->None:
        return _ida_typeinf.udtmembervec_template_t___setitem__(self, i, v)

    def append(self, x: 'udm_t') ->None:
        return _ida_typeinf.udtmembervec_template_t_append(self, x)

    def extend(self, x: 'udtmembervec_template_t') ->None:
        return _ida_typeinf.udtmembervec_template_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_typeinf.udtmembervec_template_t_swigregister(udtmembervec_template_t)
RESERVED_BYTE = _ida_typeinf.RESERVED_BYTE
"""multifunctional purpose
"""


def is_type_const(t: 'type_t') ->bool:
    """See BTM_CONST.
"""
    return _ida_typeinf.is_type_const(t)


def is_type_volatile(t: 'type_t') ->bool:
    """See BTM_VOLATILE.
"""
    return _ida_typeinf.is_type_volatile(t)


def get_base_type(t: 'type_t') ->'type_t':
    """Get get basic type bits (TYPE_BASE_MASK)
"""
    return _ida_typeinf.get_base_type(t)


def get_type_flags(t: 'type_t') ->'type_t':
    """Get type flags (TYPE_FLAGS_MASK)
"""
    return _ida_typeinf.get_type_flags(t)


def get_full_type(t: 'type_t') ->'type_t':
    """Get basic type bits + type flags (TYPE_FULL_MASK)
"""
    return _ida_typeinf.get_full_type(t)


def is_typeid_last(t: 'type_t') ->bool:
    """Is the type_t the last byte of type declaration? (there are no additional bytes after a basic type, see _BT_LAST_BASIC) 
        """
    return _ida_typeinf.is_typeid_last(t)


def is_type_partial(t: 'type_t') ->bool:
    """Identifies an unknown or void type with a known size (see Basic type: unknown & void)
"""
    return _ida_typeinf.is_type_partial(t)


def is_type_void(t: 'type_t') ->bool:
    """See BTF_VOID.
"""
    return _ida_typeinf.is_type_void(t)


def is_type_unknown(t: 'type_t') ->bool:
    """See BT_UNKNOWN.
"""
    return _ida_typeinf.is_type_unknown(t)


def is_type_ptr(t: 'type_t') ->bool:
    """See BT_PTR.
"""
    return _ida_typeinf.is_type_ptr(t)


def is_type_complex(t: 'type_t') ->bool:
    """See BT_COMPLEX.
"""
    return _ida_typeinf.is_type_complex(t)


def is_type_func(t: 'type_t') ->bool:
    """See BT_FUNC.
"""
    return _ida_typeinf.is_type_func(t)


def is_type_array(t: 'type_t') ->bool:
    """See BT_ARRAY.
"""
    return _ida_typeinf.is_type_array(t)


def is_type_typedef(t: 'type_t') ->bool:
    """See BTF_TYPEDEF.
"""
    return _ida_typeinf.is_type_typedef(t)


def is_type_sue(t: 'type_t') ->bool:
    """Is the type a struct/union/enum?
"""
    return _ida_typeinf.is_type_sue(t)


def is_type_struct(t: 'type_t') ->bool:
    """See BTF_STRUCT.
"""
    return _ida_typeinf.is_type_struct(t)


def is_type_union(t: 'type_t') ->bool:
    """See BTF_UNION.
"""
    return _ida_typeinf.is_type_union(t)


def is_type_struni(t: 'type_t') ->bool:
    """Is the type a struct or union?
"""
    return _ida_typeinf.is_type_struni(t)


def is_type_enum(t: 'type_t') ->bool:
    """See BTF_ENUM.
"""
    return _ida_typeinf.is_type_enum(t)


def is_type_bitfld(t: 'type_t') ->bool:
    """See BT_BITFIELD.
"""
    return _ida_typeinf.is_type_bitfld(t)


def is_type_int(bt: 'type_t') ->bool:
    """Does the type_t specify one of the basic types in Basic type: integer?
"""
    return _ida_typeinf.is_type_int(bt)


def is_type_int128(t: 'type_t') ->bool:
    """Does the type specify a 128-bit value? (signed or unsigned, see Basic type: integer)
"""
    return _ida_typeinf.is_type_int128(t)


def is_type_int64(t: 'type_t') ->bool:
    """Does the type specify a 64-bit value? (signed or unsigned, see Basic type: integer)
"""
    return _ida_typeinf.is_type_int64(t)


def is_type_int32(t: 'type_t') ->bool:
    """Does the type specify a 32-bit value? (signed or unsigned, see Basic type: integer)
"""
    return _ida_typeinf.is_type_int32(t)


def is_type_int16(t: 'type_t') ->bool:
    """Does the type specify a 16-bit value? (signed or unsigned, see Basic type: integer)
"""
    return _ida_typeinf.is_type_int16(t)


def is_type_char(t: 'type_t') ->bool:
    """Does the type specify a char value? (signed or unsigned, see Basic type: integer)
"""
    return _ida_typeinf.is_type_char(t)


def is_type_paf(t: 'type_t') ->bool:
    """Is the type a pointer, array, or function type?
"""
    return _ida_typeinf.is_type_paf(t)


def is_type_ptr_or_array(t: 'type_t') ->bool:
    """Is the type a pointer or array type?
"""
    return _ida_typeinf.is_type_ptr_or_array(t)


def is_type_floating(t: 'type_t') ->bool:
    """Is the type a floating point type?
"""
    return _ida_typeinf.is_type_floating(t)


def is_type_integral(t: 'type_t') ->bool:
    """Is the type an integral type (char/short/int/long/bool)?
"""
    return _ida_typeinf.is_type_integral(t)


def is_type_ext_integral(t: 'type_t') ->bool:
    """Is the type an extended integral type? (integral or enum)
"""
    return _ida_typeinf.is_type_ext_integral(t)


def is_type_arithmetic(t: 'type_t') ->bool:
    """Is the type an arithmetic type? (floating or integral)
"""
    return _ida_typeinf.is_type_arithmetic(t)


def is_type_ext_arithmetic(t: 'type_t') ->bool:
    """Is the type an extended arithmetic type? (arithmetic or enum)
"""
    return _ida_typeinf.is_type_ext_arithmetic(t)


def is_type_uint(t: 'type_t') ->bool:
    """See BTF_UINT.
"""
    return _ida_typeinf.is_type_uint(t)


def is_type_uchar(t: 'type_t') ->bool:
    """See BTF_UCHAR.
"""
    return _ida_typeinf.is_type_uchar(t)


def is_type_uint16(t: 'type_t') ->bool:
    """See BTF_UINT16.
"""
    return _ida_typeinf.is_type_uint16(t)


def is_type_uint32(t: 'type_t') ->bool:
    """See BTF_UINT32.
"""
    return _ida_typeinf.is_type_uint32(t)


def is_type_uint64(t: 'type_t') ->bool:
    """See BTF_UINT64.
"""
    return _ida_typeinf.is_type_uint64(t)


def is_type_uint128(t: 'type_t') ->bool:
    """See BTF_UINT128.
"""
    return _ida_typeinf.is_type_uint128(t)


def is_type_ldouble(t: 'type_t') ->bool:
    """See BTF_LDOUBLE.
"""
    return _ida_typeinf.is_type_ldouble(t)


def is_type_double(t: 'type_t') ->bool:
    """See BTF_DOUBLE.
"""
    return _ida_typeinf.is_type_double(t)


def is_type_float(t: 'type_t') ->bool:
    """See BTF_FLOAT.
"""
    return _ida_typeinf.is_type_float(t)


def is_type_tbyte(t: 'type_t') ->bool:
    """See BTF_FLOAT.
"""
    return _ida_typeinf.is_type_tbyte(t)


def is_type_bool(t: 'type_t') ->bool:
    """See BTF_BOOL.
"""
    return _ida_typeinf.is_type_bool(t)


TAH_BYTE = _ida_typeinf.TAH_BYTE
"""type attribute header byte
"""
FAH_BYTE = _ida_typeinf.FAH_BYTE
"""function argument attribute header byte
"""
MAX_DECL_ALIGN = _ida_typeinf.MAX_DECL_ALIGN
TAH_HASATTRS = _ida_typeinf.TAH_HASATTRS
"""has extended attributes
"""
TAUDT_UNALIGNED = _ida_typeinf.TAUDT_UNALIGNED
"""struct: unaligned struct
"""
TAUDT_MSSTRUCT = _ida_typeinf.TAUDT_MSSTRUCT
"""struct: gcc msstruct attribute
"""
TAUDT_CPPOBJ = _ida_typeinf.TAUDT_CPPOBJ
"""struct: a c++ object, not simple pod type
"""
TAUDT_VFTABLE = _ida_typeinf.TAUDT_VFTABLE
"""struct: is virtual function table
"""
TAUDT_FIXED = _ida_typeinf.TAUDT_FIXED
"""struct: fixed field offsets, stored in serialized form; cannot be set for unions 
        """
TAFLD_BASECLASS = _ida_typeinf.TAFLD_BASECLASS
"""field: do not include but inherit from the current field
"""
TAFLD_UNALIGNED = _ida_typeinf.TAFLD_UNALIGNED
"""field: unaligned field
"""
TAFLD_VIRTBASE = _ida_typeinf.TAFLD_VIRTBASE
"""field: virtual base (not supported yet)
"""
TAFLD_VFTABLE = _ida_typeinf.TAFLD_VFTABLE
"""field: ptr to virtual function table
"""
TAFLD_METHOD = _ida_typeinf.TAFLD_METHOD
"""denotes a udt member function
"""
TAFLD_GAP = _ida_typeinf.TAFLD_GAP
"""field: gap member (displayed as padding in type details)
"""
TAFLD_REGCMT = _ida_typeinf.TAFLD_REGCMT
"""field: the comment is regular (if not set, it is repeatable)
"""
TAFLD_FRAME_R = _ida_typeinf.TAFLD_FRAME_R
"""frame: function return address frame slot
"""
TAFLD_FRAME_S = _ida_typeinf.TAFLD_FRAME_S
"""frame: function saved registers frame slot
"""
TAFLD_BYTIL = _ida_typeinf.TAFLD_BYTIL
"""field: was the member created due to the type system
"""
TAPTR_PTR32 = _ida_typeinf.TAPTR_PTR32
"""ptr: __ptr32
"""
TAPTR_PTR64 = _ida_typeinf.TAPTR_PTR64
"""ptr: __ptr64
"""
TAPTR_RESTRICT = _ida_typeinf.TAPTR_RESTRICT
"""ptr: __restrict
"""
TAPTR_SHIFTED = _ida_typeinf.TAPTR_SHIFTED
"""ptr: __shifted(parent_struct, delta)
"""
TAENUM_64BIT = _ida_typeinf.TAENUM_64BIT
"""enum: store 64-bit values
"""
TAENUM_UNSIGNED = _ida_typeinf.TAENUM_UNSIGNED
"""enum: unsigned
"""
TAENUM_SIGNED = _ida_typeinf.TAENUM_SIGNED
"""enum: signed
"""
TAENUM_OCT = _ida_typeinf.TAENUM_OCT
"""enum: octal representation, if BTE_HEX
"""
TAENUM_BIN = _ida_typeinf.TAENUM_BIN
"""enum: binary representation, if BTE_HEX only one of OCT/BIN bits can be set. they are meaningful only if BTE_HEX is used. 
        """
TAENUM_NUMSIGN = _ida_typeinf.TAENUM_NUMSIGN
"""enum: signed representation, if BTE_HEX
"""
TAENUM_LZERO = _ida_typeinf.TAENUM_LZERO
"""enum: print numbers with leading zeroes (only for HEX/OCT/BIN)
"""
TAH_ALL = _ida_typeinf.TAH_ALL
"""all defined bits
"""


def is_tah_byte(t: 'type_t') ->bool:
    """The TAH byte (type attribute header byte) denotes the start of type attributes. (see "tah-typeattrs" in the type bit definitions) 
        """
    return _ida_typeinf.is_tah_byte(t)


def is_sdacl_byte(t: 'type_t') ->bool:
    """Identify an sdacl byte. The first sdacl byte has the following format: 11xx000x. The sdacl bytes are appended to udt fields. They indicate the start of type attributes (as the tah-bytes do). The sdacl bytes are used in the udt headers instead of the tah-byte. This is done for compatibility with old databases, they were already using sdacl bytes in udt headers and as udt field postfixes. (see "sdacl-typeattrs" in the type bit definitions) 
        """
    return _ida_typeinf.is_sdacl_byte(t)


class type_attr_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    key: 'qstring' = property(_ida_typeinf.type_attr_t_key_get,
        _ida_typeinf.type_attr_t_key_set)
    """one symbol keys are reserved to be used by the kernel the ones starting with an underscore are reserved too 
        """
    value: 'bytevec_t' = property(_ida_typeinf.type_attr_t_value_get,
        _ida_typeinf.type_attr_t_value_set)
    """attribute bytes
"""

    def __lt__(self, r: 'type_attr_t') ->bool:
        return _ida_typeinf.type_attr_t___lt__(self, r)

    def __ge__(self, r: 'type_attr_t') ->bool:
        return _ida_typeinf.type_attr_t___ge__(self, r)

    def __init__(self):
        _ida_typeinf.type_attr_t_swiginit(self, _ida_typeinf.new_type_attr_t())
    __swig_destroy__ = _ida_typeinf.delete_type_attr_t


_ida_typeinf.type_attr_t_swigregister(type_attr_t)
cvar = _ida_typeinf.cvar
TYPE_BASE_MASK = cvar.TYPE_BASE_MASK
"""the low 4 bits define the basic type
"""
TYPE_FLAGS_MASK = cvar.TYPE_FLAGS_MASK
"""type flags - they have different meaning depending on the basic type 
        """
TYPE_MODIF_MASK = cvar.TYPE_MODIF_MASK
"""modifiers.
* for BT_ARRAY see Derived type: array
* BT_VOID can have them ONLY in 'void *' 


        """
TYPE_FULL_MASK = cvar.TYPE_FULL_MASK
"""basic type with type flags
"""
BT_UNK = cvar.BT_UNK
"""unknown
"""
BT_VOID = cvar.BT_VOID
"""void
"""
BTMT_SIZE0 = cvar.BTMT_SIZE0
"""BT_VOID - normal void; BT_UNK - don't use
"""
BTMT_SIZE12 = cvar.BTMT_SIZE12
"""size = 1 byte if BT_VOID; 2 if BT_UNK
"""
BTMT_SIZE48 = cvar.BTMT_SIZE48
"""size = 4 bytes if BT_VOID; 8 if BT_UNK
"""
BTMT_SIZE128 = cvar.BTMT_SIZE128
"""size = 16 bytes if BT_VOID; unknown if BT_UNK (IN struct alignment - see below) 
        """
BT_INT8 = cvar.BT_INT8
"""__int8
"""
BT_INT16 = cvar.BT_INT16
"""__int16
"""
BT_INT32 = cvar.BT_INT32
"""__int32
"""
BT_INT64 = cvar.BT_INT64
"""__int64
"""
BT_INT128 = cvar.BT_INT128
"""__int128 (for alpha & future use)
"""
BT_INT = cvar.BT_INT
"""natural int. (size provided by idp module)
"""
BTMT_UNKSIGN = cvar.BTMT_UNKSIGN
"""unknown signedness
"""
BTMT_SIGNED = cvar.BTMT_SIGNED
"""signed
"""
BTMT_USIGNED = cvar.BTMT_USIGNED
"""unsigned
"""
BTMT_UNSIGNED = cvar.BTMT_UNSIGNED
BTMT_CHAR = cvar.BTMT_CHAR
"""specify char or segment register
* BT_INT8 - char
* BT_INT - segment register
* other BT_INT... - don't use 


        """
BT_BOOL = cvar.BT_BOOL
"""bool
"""
BTMT_DEFBOOL = cvar.BTMT_DEFBOOL
"""size is model specific or unknown(?)
"""
BTMT_BOOL1 = cvar.BTMT_BOOL1
"""size 1byte
"""
BTMT_BOOL2 = cvar.BTMT_BOOL2
"""size 2bytes - !inf_is_64bit()
"""
BTMT_BOOL8 = cvar.BTMT_BOOL8
"""size 8bytes - inf_is_64bit()
"""
BTMT_BOOL4 = cvar.BTMT_BOOL4
"""size 4bytes
"""
BT_FLOAT = cvar.BT_FLOAT
"""float
"""
BTMT_FLOAT = cvar.BTMT_FLOAT
"""float (4 bytes)
"""
BTMT_DOUBLE = cvar.BTMT_DOUBLE
"""double (8 bytes)
"""
BTMT_LNGDBL = cvar.BTMT_LNGDBL
"""long double (compiler specific)
"""
BTMT_SPECFLT = cvar.BTMT_SPECFLT
"""float (variable size). if processor_t::use_tbyte() then use processor_t::tbyte_size, otherwise 2 bytes 
        """
_BT_LAST_BASIC = cvar._BT_LAST_BASIC
"""the last basic type, all basic types may be followed by [tah-typeattrs] 
        """
BT_PTR = cvar.BT_PTR
"""pointer. has the following format: [db sizeof(ptr)]; [tah-typeattrs]; type_t... 
        """
BTMT_DEFPTR = cvar.BTMT_DEFPTR
"""default for model
"""
BTMT_NEAR = cvar.BTMT_NEAR
"""near
"""
BTMT_FAR = cvar.BTMT_FAR
"""far
"""
BTMT_CLOSURE = cvar.BTMT_CLOSURE
"""closure.
* if ptr to BT_FUNC - __closure. in this case next byte MUST be RESERVED_BYTE, and after it BT_FUNC
* else the next byte contains sizeof(ptr) allowed values are 1 - ph.max_ptr_size
* if value is bigger than ph.max_ptr_size, based_ptr_name_and_size() is called to find out the typeinfo 


        """
BT_ARRAY = cvar.BT_ARRAY
"""array
"""
BTMT_NONBASED = cvar.BTMT_NONBASED
"""
     set
       array base==0
       format: dt num_elem; [tah-typeattrs]; type_t...
       if num_elem==0 then the array size is unknown
    
       format: da num_elem, base; [tah-typeattrs]; type_t... 


        """
BTMT_ARRESERV = cvar.BTMT_ARRESERV
"""reserved bit
"""
BT_FUNC = cvar.BT_FUNC
"""function. format: 
      optional: CM_CC_SPOILED | num_of_spoiled_regs
                if num_of_spoiled_reg == BFA_FUNC_MARKER:
                  ::bfa_byte
                  if (bfa_byte & BFA_FUNC_EXT_FORMAT) != 0
                   ::fti_bits (only low bits: FTI_SPOILED,...,FTI_VIRTUAL)
                   num_of_spoiled_reg times: spoiled reg info (see extract_spoiledreg)
                  else
                    bfa_byte is function attribute byte (see Function attribute byte...)
                else:
                  num_of_spoiled_reg times: spoiled reg info (see extract_spoiledreg)
      cm_t ... calling convention and memory model
      [tah-typeattrs];
      type_t ... return type;
      [serialized argloc_t of returned value (if CM_CC_SPECIAL{PE} && !return void);
      if !CM_CC_VOIDARG:
        dt N (N=number of parameters)
        if ( N == 0 )
        if CM_CC_ELLIPSIS or CM_CC_SPECIALE
            func(...)
          else
            parameters are unknown
        else
          N records:
            type_t ... (i.e. type of each parameter)
            [serialized argloc_t (if CM_CC_SPECIAL{PE})] (i.e. place of each parameter)
            [FAH_BYTE + de( funcarg_t::flags )]  
        """
BTMT_DEFCALL = cvar.BTMT_DEFCALL
"""call method - default for model or unknown
"""
BTMT_NEARCALL = cvar.BTMT_NEARCALL
"""function returns by retn
"""
BTMT_FARCALL = cvar.BTMT_FARCALL
"""function returns by retf
"""
BTMT_INTCALL = cvar.BTMT_INTCALL
"""function returns by iret in this case cc MUST be 'unknown' 
        """
BT_COMPLEX = cvar.BT_COMPLEX
"""struct/union/enum/typedef. format: 
       [dt N (N=field count) if !BTMT_TYPEDEF]
       if N == 0:
         p_string name (unnamed types have names "anon_...")
         [sdacl-typeattrs];
       else, for struct & union:
         if N == 0x7FFE   // Support for high (i.e., > 4095) members count
           N = deserialize_de()
         ALPOW = N & 0x7
         MCNT = N >> 3
         if MCNT == 0
           empty struct
         if ALPOW == 0
           ALIGN = get_default_align()
         else
           ALIGN = (1 << (ALPOW - 1))
         [sdacl-typeattrs];
       else, for enums:
         if N == 0x7FFE   // Support for high enum entries count.
           N = deserialize_de()
         [tah-typeattrs];  
        """
BTMT_STRUCT = cvar.BTMT_STRUCT
"""struct: MCNT records: type_t; [sdacl-typeattrs]; 
        """
BTMT_UNION = cvar.BTMT_UNION
"""union: MCNT records: type_t... 
        """
BTMT_ENUM = cvar.BTMT_ENUM
"""enum: next byte bte_t (see below) N records: de delta(s) OR blocks (see below) 
        """
BTMT_TYPEDEF = cvar.BTMT_TYPEDEF
"""named reference always p_string name 
        """
BT_BITFIELD = cvar.BT_BITFIELD
"""bitfield (only in struct) ['bitmasked' enum see below] next byte is dt ((size in bits << 1) | (unsigned ? 1 : 0)) 
        """
BTMT_BFLDI8 = cvar.BTMT_BFLDI8
"""__int8
"""
BTMT_BFLDI16 = cvar.BTMT_BFLDI16
"""__int16
"""
BTMT_BFLDI32 = cvar.BTMT_BFLDI32
"""__int32
"""
BTMT_BFLDI64 = cvar.BTMT_BFLDI64
"""__int64
"""
BT_RESERVED = cvar.BT_RESERVED
"""RESERVED.
"""
BTM_CONST = cvar.BTM_CONST
"""const
"""
BTM_VOLATILE = cvar.BTM_VOLATILE
"""volatile
"""
BTE_SIZE_MASK = cvar.BTE_SIZE_MASK
"""storage size.
* if == 0 then inf_get_cc_size_e()
* else 1 << (n -1) = 1,2,4,8
* n == 5,6,7 are reserved 


        """
BTE_RESERVED = cvar.BTE_RESERVED
"""must be 0, in order to distinguish from a tah-byte 
        """
BTE_BITMASK = cvar.BTE_BITMASK
"""'subarrays'. In this case ANY record has the following format:
* 'de' mask (has name)
* 'dt' cnt
* cnt records of 'de' values (cnt CAN be 0)


"""
BTE_OUT_MASK = cvar.BTE_OUT_MASK
"""output style mask
"""
BTE_HEX = cvar.BTE_HEX
"""hex
"""
BTE_CHAR = cvar.BTE_CHAR
"""char or hex
"""
BTE_SDEC = cvar.BTE_SDEC
"""signed decimal
"""
BTE_UDEC = cvar.BTE_UDEC
"""unsigned decimal
"""
BTE_ALWAYS = cvar.BTE_ALWAYS
"""this bit MUST be present
"""
BT_SEGREG = cvar.BT_SEGREG
"""segment register
"""
BT_UNK_BYTE = cvar.BT_UNK_BYTE
"""1 byte
"""
BT_UNK_WORD = cvar.BT_UNK_WORD
"""2 bytes
"""
BT_UNK_DWORD = cvar.BT_UNK_DWORD
"""4 bytes
"""
BT_UNK_QWORD = cvar.BT_UNK_QWORD
"""8 bytes
"""
BT_UNK_OWORD = cvar.BT_UNK_OWORD
"""16 bytes
"""
BT_UNKNOWN = cvar.BT_UNKNOWN
"""unknown size - for parameters
"""
BTF_BYTE = cvar.BTF_BYTE
"""byte
"""
BTF_UNK = cvar.BTF_UNK
"""unknown
"""
BTF_VOID = cvar.BTF_VOID
"""void
"""
BTF_INT8 = cvar.BTF_INT8
"""signed byte
"""
BTF_CHAR = cvar.BTF_CHAR
"""signed char
"""
BTF_UCHAR = cvar.BTF_UCHAR
"""unsigned char
"""
BTF_UINT8 = cvar.BTF_UINT8
"""unsigned byte
"""
BTF_INT16 = cvar.BTF_INT16
"""signed short
"""
BTF_UINT16 = cvar.BTF_UINT16
"""unsigned short
"""
BTF_INT32 = cvar.BTF_INT32
"""signed int
"""
BTF_UINT32 = cvar.BTF_UINT32
"""unsigned int
"""
BTF_INT64 = cvar.BTF_INT64
"""signed long
"""
BTF_UINT64 = cvar.BTF_UINT64
"""unsigned long
"""
BTF_INT128 = cvar.BTF_INT128
"""signed 128-bit value
"""
BTF_UINT128 = cvar.BTF_UINT128
"""unsigned 128-bit value
"""
BTF_INT = cvar.BTF_INT
"""int, unknown signedness
"""
BTF_UINT = cvar.BTF_UINT
"""unsigned int
"""
BTF_SINT = cvar.BTF_SINT
"""singed int
"""
BTF_BOOL = cvar.BTF_BOOL
"""boolean
"""
BTF_FLOAT = cvar.BTF_FLOAT
"""float
"""
BTF_DOUBLE = cvar.BTF_DOUBLE
"""double
"""
BTF_LDOUBLE = cvar.BTF_LDOUBLE
"""long double
"""
BTF_TBYTE = cvar.BTF_TBYTE
"""see BTMT_SPECFLT
"""
BTF_STRUCT = cvar.BTF_STRUCT
"""struct
"""
BTF_UNION = cvar.BTF_UNION
"""union
"""
BTF_ENUM = cvar.BTF_ENUM
"""enum
"""
BTF_TYPEDEF = cvar.BTF_TYPEDEF
"""typedef
"""
TA_ORG_TYPEDEF = _ida_typeinf.TA_ORG_TYPEDEF
"""the original typedef name (simple string)
"""
TA_ORG_ARRDIM = _ida_typeinf.TA_ORG_ARRDIM
"""the original array dimension (pack_dd)
"""
TA_FORMAT = _ida_typeinf.TA_FORMAT
"""info about the 'format' argument. 3 times pack_dd: format_functype_t, argument number of 'format', argument number of '...' 
        """
TA_VALUE_REPR = _ida_typeinf.TA_VALUE_REPR
"""serialized value_repr_t (used for scalars and arrays)
"""


def append_argloc(out: 'qtype *', vloc: 'argloc_t') ->bool:
    """Serialize argument location 
        """
    return _ida_typeinf.append_argloc(out, vloc)


def extract_argloc(vloc: 'argloc_t', ptype: 'type_t const **',
    forbid_stkoff: bool) ->bool:
    """Deserialize an argument location. Argument FORBID_STKOFF checks location type. It can be used, for example, to check the return location of a function that cannot return a value in the stack 
        """
    return _ida_typeinf.extract_argloc(vloc, ptype, forbid_stkoff)


def resolve_typedef(til: 'til_t', type: 'type_t const *') ->'type_t const *':
    return _ida_typeinf.resolve_typedef(til, type)


def is_restype_void(til: 'til_t', type: 'type_t const *') ->bool:
    return _ida_typeinf.is_restype_void(til, type)


def is_restype_enum(til: 'til_t', type: 'type_t const *') ->bool:
    return _ida_typeinf.is_restype_enum(til, type)


def is_restype_struni(til: 'til_t', type: 'type_t const *') ->bool:
    return _ida_typeinf.is_restype_struni(til, type)


def is_restype_struct(til: 'til_t', type: 'type_t const *') ->bool:
    return _ida_typeinf.is_restype_struct(til, type)


def get_scalar_bt(size: int) ->'type_t':
    return _ida_typeinf.get_scalar_bt(size)


class til_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    name: 'char *' = property(_ida_typeinf.til_t_name_get, _ida_typeinf.
        til_t_name_set)
    """short file name (without path and extension)
"""
    desc: 'char *' = property(_ida_typeinf.til_t_desc_get, _ida_typeinf.
        til_t_desc_set)
    """human readable til description
"""
    nbases: 'int' = property(_ida_typeinf.til_t_nbases_get, _ida_typeinf.
        til_t_nbases_set)
    """number of base tils
"""
    flags: 'uint32' = property(_ida_typeinf.til_t_flags_get, _ida_typeinf.
        til_t_flags_set)
    """Type info library property bits 
        """

    def is_dirty(self) ->bool:
        """Has the til been modified? (TIL_MOD)
"""
        return _ida_typeinf.til_t_is_dirty(self)

    def set_dirty(self) ->None:
        """Mark the til as modified (TIL_MOD)
"""
        return _ida_typeinf.til_t_set_dirty(self)

    def find_base(self, n: str) ->'til_t *':
        """Find the base til with the provided name 
        
@param n: the base til name
@returns the found til_t, or nullptr"""
        return _ida_typeinf.til_t_find_base(self, n)
    cc: 'compiler_info_t' = property(_ida_typeinf.til_t_cc_get,
        _ida_typeinf.til_t_cc_set)
    """information about the target compiler
"""
    nrefs: 'int' = property(_ida_typeinf.til_t_nrefs_get, _ida_typeinf.
        til_t_nrefs_set)
    """number of references to the til
"""
    nstreams: 'int' = property(_ida_typeinf.til_t_nstreams_get,
        _ida_typeinf.til_t_nstreams_set)
    """number of extra streams
"""
    streams: 'til_stream_t **' = property(_ida_typeinf.til_t_streams_get,
        _ida_typeinf.til_t_streams_set)
    """symbol stream storage
"""

    def base(self, n: int) ->'til_t *':
        return _ida_typeinf.til_t_base(self, n)

    def __eq__(self, r: 'til_t') ->bool:
        return _ida_typeinf.til_t___eq__(self, r)

    def __ne__(self, r: 'til_t') ->bool:
        return _ida_typeinf.til_t___ne__(self, r)

    def import_type(self, src):
        """Import a type (and all its dependencies) into this type info library.

@param src The type to import
@return the imported copy, or None"""
        return _ida_typeinf.til_t_import_type(self, src)

    def named_types(self):
        """Returns a generator over the named types contained in this
type library.

Every iteration returns a fresh new tinfo_t object

@return a tinfo_t-producing generator"""
        for name in self.type_names:
            tif = tinfo_t()
            if tif.get_named_type(self, name):
                yield tif

    def numbered_types(self):
        """Returns a generator over the numbered types contained in this
type library.

Every iteration returns a fresh new tinfo_t object

@return a tinfo_t-producing generator"""
        for ord in range(1, get_ordinal_limit(self)):
            tif = tinfo_t()
            if tif.get_numbered_type(self, ord):
                yield tif

    def get_named_type(self, name):
        """Retrieves a tinfo_t representing the named type in this type library.

@param name a type name
@return a new tinfo_t object, or None if not found"""
        tif = tinfo_t()
        if tif.get_named_type(self, name):
            return tif

    def get_numbered_type(self, ordinal):
        """Retrieves a tinfo_t representing the numbered type in this type library.

@param ordinal a type ordinal
@return a new tinfo_t object, or None if not found"""
        tif = tinfo_t()
        if tif.get_numbered_type(self, ordinal):
            return tif

    def get_type_names(self):
        n = first_named_type(self, NTF_TYPE)
        while n:
            yield n
            n = next_named_type(self, n, NTF_TYPE)
    type_names = property(get_type_names)

    def __init__(self):
        _ida_typeinf.til_t_swiginit(self, _ida_typeinf.new_til_t())
    __swig_destroy__ = _ida_typeinf.delete_til_t


_ida_typeinf.til_t_swigregister(til_t)
no_sign = cvar.no_sign
"""no sign, or unknown
"""
type_signed = cvar.type_signed
"""signed type
"""
type_unsigned = cvar.type_unsigned
"""unsigned type
"""
TIL_ZIP = _ida_typeinf.TIL_ZIP
"""pack buckets using zip
"""
TIL_MAC = _ida_typeinf.TIL_MAC
"""til has macro table
"""
TIL_ESI = _ida_typeinf.TIL_ESI
"""extended sizeof info (short, long, longlong)
"""
TIL_UNI = _ida_typeinf.TIL_UNI
"""universal til for any compiler
"""
TIL_ORD = _ida_typeinf.TIL_ORD
"""type ordinal numbers are present
"""
TIL_ALI = _ida_typeinf.TIL_ALI
"""type aliases are present (this bit is used only on the disk)
"""
TIL_MOD = _ida_typeinf.TIL_MOD
"""til has been modified, should be saved
"""
TIL_STM = _ida_typeinf.TIL_STM
"""til has extra streams
"""
TIL_SLD = _ida_typeinf.TIL_SLD
"""sizeof(long double)
"""


def new_til(name: str, desc: str) ->'til_t *':
    """Initialize a til.
"""
    return _ida_typeinf.new_til(name, desc)


TIL_ADD_FAILED = _ida_typeinf.TIL_ADD_FAILED
"""see errbuf
"""
TIL_ADD_OK = _ida_typeinf.TIL_ADD_OK
"""some tils were added
"""
TIL_ADD_ALREADY = _ida_typeinf.TIL_ADD_ALREADY
"""the base til was already added
"""


def load_til(name: str, tildir: str=None) ->str:
    """Load til from a file without adding it to the database list (see also add_til). Failure to load base tils are reported into 'errbuf'. They do not prevent loading of the main til. 
        
@param name: filename of the til. If it's an absolute path, tildir is ignored.
* NB: the file extension is forced to .til
@param tildir: directory where to load the til from. nullptr means default til subdirectories.
@returns pointer to resulting til, nullptr if failed and error message is in errbuf"""
    return _ida_typeinf.load_til(name, tildir)


def compact_til(ti: 'til_t') ->bool:
    """Collect garbage in til. Must be called before storing the til. 
        
@returns true if any memory was freed"""
    return _ida_typeinf.compact_til(ti)


def store_til(ti: 'til_t', tildir: str, name: str) ->bool:
    """Store til to a file. If the til contains garbage, it will be collected before storing the til. Your plugin should call compact_til() before calling store_til(). 
        
@param ti: type library to store
@param tildir: directory where to store the til. nullptr means current directory.
@param name: filename of the til. If it's an absolute path, tildir is ignored.
* NB: the file extension is forced to .til
@returns success"""
    return _ida_typeinf.store_til(ti, tildir, name)


def free_til(ti: 'til_t') ->None:
    """Free memory allocated by til.
"""
    return _ida_typeinf.free_til(ti)


def load_til_header(tildir: str, name: str) ->str:
    """Get human-readable til description.
"""
    return _ida_typeinf.load_til_header(tildir, name)


def is_code_far(cm: 'cm_t') ->bool:
    """Does the given model specify far code?.
"""
    return _ida_typeinf.is_code_far(cm)


def is_data_far(cm: 'cm_t') ->bool:
    """Does the given model specify far data?.
"""
    return _ida_typeinf.is_data_far(cm)


class rrel_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    off: 'sval_t' = property(_ida_typeinf.rrel_t_off_get, _ida_typeinf.
        rrel_t_off_set)
    """displacement from the address pointed by the register
"""
    reg: 'int' = property(_ida_typeinf.rrel_t_reg_get, _ida_typeinf.
        rrel_t_reg_set)
    """register index (into ph.reg_names)
"""

    def __init__(self):
        _ida_typeinf.rrel_t_swiginit(self, _ida_typeinf.new_rrel_t())
    __swig_destroy__ = _ida_typeinf.delete_rrel_t


_ida_typeinf.rrel_t_swigregister(rrel_t)
CM_MASK = cvar.CM_MASK
CM_UNKNOWN = cvar.CM_UNKNOWN
"""unknown
"""
CM_N8_F16 = cvar.CM_N8_F16
"""if sizeof(int)<=2: near 1 byte, far 2 bytes
"""
CM_N64 = cvar.CM_N64
"""if sizeof(int)>2: near 8 bytes, far 8 bytes
"""
CM_N16_F32 = cvar.CM_N16_F32
"""near 2 bytes, far 4 bytes
"""
CM_N32_F48 = cvar.CM_N32_F48
"""near 4 bytes, far 6 bytes
"""
CM_M_MASK = cvar.CM_M_MASK
CM_M_NN = cvar.CM_M_NN
"""small: code=near, data=near (or unknown if CM_UNKNOWN)
"""
CM_M_FF = cvar.CM_M_FF
"""large: code=far, data=far
"""
CM_M_NF = cvar.CM_M_NF
"""compact: code=near, data=far
"""
CM_M_FN = cvar.CM_M_FN
"""medium: code=far, data=near
"""
CM_CC_MASK = cvar.CM_CC_MASK
CM_CC_INVALID = cvar.CM_CC_INVALID
"""this value is invalid
"""
CM_CC_UNKNOWN = cvar.CM_CC_UNKNOWN
"""unknown calling convention
"""
CM_CC_VOIDARG = cvar.CM_CC_VOIDARG
"""function without arguments if has other cc and argnum == 0, represent as f() - unknown list 
        """
CM_CC_CDECL = cvar.CM_CC_CDECL
"""stack
"""
CM_CC_ELLIPSIS = cvar.CM_CC_ELLIPSIS
"""cdecl + ellipsis
"""
CM_CC_STDCALL = cvar.CM_CC_STDCALL
"""stack, purged
"""
CM_CC_PASCAL = cvar.CM_CC_PASCAL
"""stack, purged, reverse order of args
"""
CM_CC_FASTCALL = cvar.CM_CC_FASTCALL
"""stack, purged (x86), first args are in regs (compiler-dependent)
"""
CM_CC_THISCALL = cvar.CM_CC_THISCALL
"""stack, purged (x86), first arg is in reg (compiler-dependent)
"""
CM_CC_SWIFT = cvar.CM_CC_SWIFT
"""(Swift) arguments and return values in registers (compiler-dependent)
"""
CM_CC_SPOILED = cvar.CM_CC_SPOILED
"""This is NOT a cc! Mark of __spoil record the low nibble is count and after n {spoilreg_t} present real cm_t byte. if n == BFA_FUNC_MARKER, the next byte is the function attribute byte. 
        """
CM_CC_GOLANG = cvar.CM_CC_GOLANG
"""(Go) arguments and return value in stack
"""
CM_CC_RESERVE3 = cvar.CM_CC_RESERVE3
CM_CC_SPECIALE = cvar.CM_CC_SPECIALE
"""CM_CC_SPECIAL with ellipsis
"""
CM_CC_SPECIALP = cvar.CM_CC_SPECIALP
"""Equal to CM_CC_SPECIAL, but with purged stack.
"""
CM_CC_SPECIAL = cvar.CM_CC_SPECIAL
"""usercall: locations of all arguments and the return value are explicitly specified 
        """
BFA_NORET = cvar.BFA_NORET
"""__noreturn
"""
BFA_PURE = cvar.BFA_PURE
"""__pure
"""
BFA_HIGH = cvar.BFA_HIGH
"""high level prototype (with possibly hidden args)
"""
BFA_STATIC = cvar.BFA_STATIC
"""static
"""
BFA_VIRTUAL = cvar.BFA_VIRTUAL
"""virtual
"""
BFA_FUNC_MARKER = cvar.BFA_FUNC_MARKER
"""This is NOT a cc! (used internally as a marker)
"""
BFA_FUNC_EXT_FORMAT = cvar.BFA_FUNC_EXT_FORMAT
"""This is NOT a real attribute (used internally as marker for extended format)
"""
ALOC_NONE = cvar.ALOC_NONE
"""none
"""
ALOC_STACK = cvar.ALOC_STACK
"""stack offset
"""
ALOC_DIST = cvar.ALOC_DIST
"""distributed (scattered)
"""
ALOC_REG1 = cvar.ALOC_REG1
"""one register (and offset within it)
"""
ALOC_REG2 = cvar.ALOC_REG2
"""register pair
"""
ALOC_RREL = cvar.ALOC_RREL
"""register relative
"""
ALOC_STATIC = cvar.ALOC_STATIC
"""global address
"""
ALOC_CUSTOM = cvar.ALOC_CUSTOM
"""custom argloc (7 or higher)
"""


class argloc_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_typeinf.argloc_t_swiginit(self, _ida_typeinf.new_argloc_t(*args))
    __swig_destroy__ = _ida_typeinf.delete_argloc_t

    def swap(self, r: 'argloc_t') ->None:
        """Assign this == r and r == this.
"""
        return _ida_typeinf.argloc_t_swap(self, r)

    def atype(self) ->'argloc_type_t':
        """Get type (Argument location types)
"""
        return _ida_typeinf.argloc_t_atype(self)

    def is_reg1(self) ->bool:
        """See ALOC_REG1.
"""
        return _ida_typeinf.argloc_t_is_reg1(self)

    def is_reg2(self) ->bool:
        """See ALOC_REG2.
"""
        return _ida_typeinf.argloc_t_is_reg2(self)

    def is_reg(self) ->bool:
        """is_reg1() || is_reg2()
"""
        return _ida_typeinf.argloc_t_is_reg(self)

    def is_rrel(self) ->bool:
        """See ALOC_RREL.
"""
        return _ida_typeinf.argloc_t_is_rrel(self)

    def is_ea(self) ->bool:
        """See ALOC_STATIC.
"""
        return _ida_typeinf.argloc_t_is_ea(self)

    def is_stkoff(self) ->bool:
        """See ALOC_STACK.
"""
        return _ida_typeinf.argloc_t_is_stkoff(self)

    def is_scattered(self) ->bool:
        """See ALOC_DIST.
"""
        return _ida_typeinf.argloc_t_is_scattered(self)

    def has_reg(self) ->bool:
        """TRUE if argloc has a register part.
"""
        return _ida_typeinf.argloc_t_has_reg(self)

    def has_stkoff(self) ->bool:
        """TRUE if argloc has a stack part.
"""
        return _ida_typeinf.argloc_t_has_stkoff(self)

    def is_mixed_scattered(self) ->bool:
        """mixed scattered: consists of register and stack parts
"""
        return _ida_typeinf.argloc_t_is_mixed_scattered(self)

    def in_stack(self) ->bool:
        """TRUE if argloc is in stack entirely.
"""
        return _ida_typeinf.argloc_t_in_stack(self)

    def is_fragmented(self) ->bool:
        """is_scattered() || is_reg2()
"""
        return _ida_typeinf.argloc_t_is_fragmented(self)

    def is_custom(self) ->bool:
        """See ALOC_CUSTOM.
"""
        return _ida_typeinf.argloc_t_is_custom(self)

    def is_badloc(self) ->bool:
        """See ALOC_NONE.
"""
        return _ida_typeinf.argloc_t_is_badloc(self)

    def reg1(self) ->int:
        """Get the register info. Use when atype() == ALOC_REG1 or ALOC_REG2 
        """
        return _ida_typeinf.argloc_t_reg1(self)

    def regoff(self) ->int:
        """Get offset from the beginning of the register in bytes. Use when atype() == ALOC_REG1 
        """
        return _ida_typeinf.argloc_t_regoff(self)

    def reg2(self) ->int:
        """Get info for the second register. Use when atype() == ALOC_REG2 
        """
        return _ida_typeinf.argloc_t_reg2(self)

    def get_reginfo(self) ->int:
        """Get all register info. Use when atype() == ALOC_REG1 or ALOC_REG2 
        """
        return _ida_typeinf.argloc_t_get_reginfo(self)

    def stkoff(self) ->int:
        """Get the stack offset. Use if atype() == ALOC_STACK 
        """
        return _ida_typeinf.argloc_t_stkoff(self)

    def get_ea(self) ->ida_idaapi.ea_t:
        """Get the global address. Use when atype() == ALOC_STATIC 
        """
        return _ida_typeinf.argloc_t_get_ea(self)

    def scattered(self) ->'scattered_aloc_t &':
        """Get scattered argument info. Use when atype() == ALOC_DIST 
        """
        return _ida_typeinf.argloc_t_scattered(self)

    def get_rrel(self) ->'rrel_t &':
        """Get register-relative info. Use when atype() == ALOC_RREL 
        """
        return _ida_typeinf.argloc_t_get_rrel(self)

    def get_custom(self) ->'void *':
        """Get custom argloc info. Use if atype() == ALOC_CUSTOM 
        """
        return _ida_typeinf.argloc_t_get_custom(self)

    def get_biggest(self) ->'argloc_t::biggest_t':
        """Get largest element in internal union.
"""
        return _ida_typeinf.argloc_t_get_biggest(self)

    def _set_badloc(self) ->None:
        """Use set_badloc()
"""
        return _ida_typeinf.argloc_t__set_badloc(self)

    def _set_reg1(self, reg: int, off: int=0) ->None:
        """Use set_reg1()
"""
        return _ida_typeinf.argloc_t__set_reg1(self, reg, off)

    def _set_reg2(self, _reg1: int, _reg2: int) ->None:
        """Use set_reg2()
"""
        return _ida_typeinf.argloc_t__set_reg2(self, _reg1, _reg2)

    def _set_stkoff(self, off: int) ->None:
        """Use set_stkoff()
"""
        return _ida_typeinf.argloc_t__set_stkoff(self, off)

    def _set_ea(self, _ea: ida_idaapi.ea_t) ->None:
        """Use set_ea 
        """
        return _ida_typeinf.argloc_t__set_ea(self, _ea)

    def _consume_rrel(self, p: 'rrel_t') ->bool:
        """Use consume_rrel()
"""
        return _ida_typeinf.argloc_t__consume_rrel(self, p)

    def _consume_scattered(self, p: 'scattered_aloc_t') ->bool:
        """Use consume_scattered()
"""
        return _ida_typeinf.argloc_t__consume_scattered(self, p)

    def _set_custom(self, ct: 'argloc_type_t', pdata: 'void *') ->None:
        """Set custom argument location (careful - this function does not clean up!)
"""
        return _ida_typeinf.argloc_t__set_custom(self, ct, pdata)

    def _set_biggest(self, ct: 'argloc_type_t', data: 'argloc_t::biggest_t'
        ) ->None:
        """Set biggest element in internal union (careful - this function does not clean up!)
"""
        return _ida_typeinf.argloc_t__set_biggest(self, ct, data)

    def set_reg1(self, reg: int, off: int=0) ->None:
        """Set register location.
"""
        return _ida_typeinf.argloc_t_set_reg1(self, reg, off)

    def set_reg2(self, _reg1: int, _reg2: int) ->None:
        """Set secondary register location.
"""
        return _ida_typeinf.argloc_t_set_reg2(self, _reg1, _reg2)

    def set_stkoff(self, off: int) ->None:
        """Set stack offset location.
"""
        return _ida_typeinf.argloc_t_set_stkoff(self, off)

    def set_ea(self, _ea: ida_idaapi.ea_t) ->None:
        """Set static ea location.
"""
        return _ida_typeinf.argloc_t_set_ea(self, _ea)

    def consume_rrel(self, p: 'rrel_t') ->None:
        """Set register-relative location - can't be nullptr.
"""
        return _ida_typeinf.argloc_t_consume_rrel(self, p)

    def set_badloc(self) ->None:
        """Set to invalid location.
"""
        return _ida_typeinf.argloc_t_set_badloc(self)

    def calc_offset(self) ->int:
        """Calculate offset that can be used to compare 2 similar arglocs.
"""
        return _ida_typeinf.argloc_t_calc_offset(self)

    def advance(self, delta: int) ->bool:
        """Move the location to point 'delta' bytes further.
"""
        return _ida_typeinf.argloc_t_advance(self, delta)

    def align_reg_high(self, size: 'size_t', _slotsize: 'size_t') ->None:
        """Set register offset to align it to the upper part of _SLOTSIZE.
"""
        return _ida_typeinf.argloc_t_align_reg_high(self, size, _slotsize)

    def align_stkoff_high(self, size: 'size_t', _slotsize: 'size_t') ->None:
        """Set stack offset to align to the upper part of _SLOTSIZE.
"""
        return _ida_typeinf.argloc_t_align_stkoff_high(self, size, _slotsize)

    def __eq__(self, r: 'argloc_t') ->bool:
        return _ida_typeinf.argloc_t___eq__(self, r)

    def __ne__(self, r: 'argloc_t') ->bool:
        return _ida_typeinf.argloc_t___ne__(self, r)

    def __lt__(self, r: 'argloc_t') ->bool:
        return _ida_typeinf.argloc_t___lt__(self, r)

    def __gt__(self, r: 'argloc_t') ->bool:
        return _ida_typeinf.argloc_t___gt__(self, r)

    def __le__(self, r: 'argloc_t') ->bool:
        return _ida_typeinf.argloc_t___le__(self, r)

    def __ge__(self, r: 'argloc_t') ->bool:
        return _ida_typeinf.argloc_t___ge__(self, r)

    def compare(self, r: 'argloc_t') ->int:
        return _ida_typeinf.argloc_t_compare(self, r)

    def consume_scattered(self, p: 'scattered_aloc_t') ->None:
        """Set distributed argument location.
"""
        return _ida_typeinf.argloc_t_consume_scattered(self, p)


_ida_typeinf.argloc_t_swigregister(argloc_t)


class argpart_t(argloc_t):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    off: 'ushort' = property(_ida_typeinf.argpart_t_off_get, _ida_typeinf.
        argpart_t_off_set)
    """offset from the beginning of the argument
"""
    size: 'ushort' = property(_ida_typeinf.argpart_t_size_get, _ida_typeinf
        .argpart_t_size_set)
    """the number of bytes
"""

    def __init__(self, *args):
        _ida_typeinf.argpart_t_swiginit(self, _ida_typeinf.new_argpart_t(*args)
            )

    def bad_offset(self) ->bool:
        """Does this argpart have a valid offset?
"""
        return _ida_typeinf.argpart_t_bad_offset(self)

    def bad_size(self) ->bool:
        """Does this argpart have a valid size?
"""
        return _ida_typeinf.argpart_t_bad_size(self)

    def __lt__(self, r: 'argpart_t') ->bool:
        return _ida_typeinf.argpart_t___lt__(self, r)

    def swap(self, r: 'argpart_t') ->None:
        """Assign this = r and r = this.
"""
        return _ida_typeinf.argpart_t_swap(self, r)
    __swig_destroy__ = _ida_typeinf.delete_argpart_t


_ida_typeinf.argpart_t_swigregister(argpart_t)


class scattered_aloc_t(argpartvec_t):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_typeinf.scattered_aloc_t_swiginit(self, _ida_typeinf.
            new_scattered_aloc_t())
    __swig_destroy__ = _ida_typeinf.delete_scattered_aloc_t


_ida_typeinf.scattered_aloc_t_swigregister(scattered_aloc_t)


def verify_argloc(vloc: 'argloc_t', size: int, gaps: 'rangeset_t') ->int:
    """Verify argloc_t. 
        
@param vloc: argloc to verify
@param size: total size of the variable
@param gaps: if not nullptr, specifies gaps in structure definition. these gaps should not map to any argloc, but everything else must be covered
@returns 0 if ok, otherwise an interr code."""
    return _ida_typeinf.verify_argloc(vloc, size, gaps)


def optimize_argloc(vloc: 'argloc_t', size: int, gaps: 'rangeset_t') ->bool:
    """Verify and optimize scattered argloc into simple form. All new arglocs must be processed by this function. 
        
@retval true: success
@retval false: the input argloc was illegal"""
    return _ida_typeinf.optimize_argloc(vloc, size, gaps)


def print_argloc(vloc: 'argloc_t', size: int=0, vflags: int=0) ->'size_t':
    """Convert an argloc to human readable form.
"""
    return _ida_typeinf.print_argloc(vloc, size, vflags)


PRALOC_VERIFY = _ida_typeinf.PRALOC_VERIFY
"""interr if illegal argloc
"""
PRALOC_STKOFF = _ida_typeinf.PRALOC_STKOFF
"""print stack offsets
"""


class aloc_visitor_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def visit_location(self, v: 'argloc_t', off: int, size: int) ->int:
        return _ida_typeinf.aloc_visitor_t_visit_location(self, v, off, size)
    __swig_destroy__ = _ida_typeinf.delete_aloc_visitor_t

    def __init__(self):
        if self.__class__ == aloc_visitor_t:
            _self = None
        else:
            _self = self
        _ida_typeinf.aloc_visitor_t_swiginit(self, _ida_typeinf.
            new_aloc_visitor_t(_self))

    def __disown__(self):
        self.this.disown()
        _ida_typeinf.disown_aloc_visitor_t(self)
        return weakref.proxy(self)


_ida_typeinf.aloc_visitor_t_swigregister(aloc_visitor_t)


def for_all_arglocs(vv: 'aloc_visitor_t', vloc: 'argloc_t', size: int, off:
    int=0) ->int:
    """Compress larger argloc types and initiate the aloc visitor.
"""
    return _ida_typeinf.for_all_arglocs(vv, vloc, size, off)


class const_aloc_visitor_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def visit_location(self, v: 'argloc_t', off: int, size: int) ->int:
        return _ida_typeinf.const_aloc_visitor_t_visit_location(self, v,
            off, size)
    __swig_destroy__ = _ida_typeinf.delete_const_aloc_visitor_t

    def __init__(self):
        if self.__class__ == const_aloc_visitor_t:
            _self = None
        else:
            _self = self
        _ida_typeinf.const_aloc_visitor_t_swiginit(self, _ida_typeinf.
            new_const_aloc_visitor_t(_self))

    def __disown__(self):
        self.this.disown()
        _ida_typeinf.disown_const_aloc_visitor_t(self)
        return weakref.proxy(self)


_ida_typeinf.const_aloc_visitor_t_swigregister(const_aloc_visitor_t)


def for_all_const_arglocs(vv: 'const_aloc_visitor_t', vloc: 'argloc_t',
    size: int, off: int=0) ->int:
    """See for_all_arglocs()
"""
    return _ida_typeinf.for_all_const_arglocs(vv, vloc, size, off)


def is_user_cc(cm: 'cm_t') ->bool:
    """Does the calling convention specify argument locations explicitly?
"""
    return _ida_typeinf.is_user_cc(cm)


def is_vararg_cc(cm: 'cm_t') ->bool:
    """Does the calling convention use ellipsis?
"""
    return _ida_typeinf.is_vararg_cc(cm)


def is_purging_cc(cm: 'cm_t') ->bool:
    """Does the calling convention clean the stack arguments upon return?. 
        """
    return _ida_typeinf.is_purging_cc(cm)


def is_golang_cc(cc: 'cm_t') ->bool:
    """GO language calling convention (return value in stack)?
"""
    return _ida_typeinf.is_golang_cc(cc)


def is_swift_cc(cc: 'cm_t') ->bool:
    """Swift calling convention (arguments and return values in registers)?
"""
    return _ida_typeinf.is_swift_cc(cc)


ARGREGS_POLICY_UNDEFINED = _ida_typeinf.ARGREGS_POLICY_UNDEFINED
ARGREGS_GP_ONLY = _ida_typeinf.ARGREGS_GP_ONLY
"""GP registers used for all arguments.
"""
ARGREGS_INDEPENDENT = _ida_typeinf.ARGREGS_INDEPENDENT
"""FP/GP registers used separately (like gcc64)
"""
ARGREGS_BY_SLOTS = _ida_typeinf.ARGREGS_BY_SLOTS
"""fixed FP/GP register per each slot (like vc64)
"""
ARGREGS_FP_MASKS_GP = _ida_typeinf.ARGREGS_FP_MASKS_GP
"""FP register also consumes one or more GP regs but not vice versa (aix ppc ABI)
"""
ARGREGS_MIPS_O32 = _ida_typeinf.ARGREGS_MIPS_O32
"""MIPS ABI o32.
"""
ARGREGS_RISCV = _ida_typeinf.ARGREGS_RISCV
"""Risc-V API FP arguments are passed in GP registers if FP registers are exhausted and GP ones are not. Wide FP arguments are passed in GP registers. Variadic FP arguments are passed in GP registers. 
          """


class callregs_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    policy: 'argreg_policy_t' = property(_ida_typeinf.callregs_t_policy_get,
        _ida_typeinf.callregs_t_policy_set)
    """argument policy
"""
    nregs: 'int' = property(_ida_typeinf.callregs_t_nregs_get, _ida_typeinf
        .callregs_t_nregs_set)
    """max number of registers that can be used in a call
"""
    gpregs: 'intvec_t' = property(_ida_typeinf.callregs_t_gpregs_get,
        _ida_typeinf.callregs_t_gpregs_set)
    """array of gp registers
"""
    fpregs: 'intvec_t' = property(_ida_typeinf.callregs_t_fpregs_get,
        _ida_typeinf.callregs_t_fpregs_set)
    """array of fp registers
"""

    def __init__(self, *args):
        _ida_typeinf.callregs_t_swiginit(self, _ida_typeinf.new_callregs_t(
            *args))

    def swap(self, r: 'callregs_t') ->None:
        """swap two instances
"""
        return _ida_typeinf.callregs_t_swap(self, r)

    def init_regs(self, cc: 'cm_t') ->None:
        """Init policy & registers for given CC.
"""
        return _ida_typeinf.callregs_t_init_regs(self, cc)

    def by_slots(self) ->bool:
        return _ida_typeinf.callregs_t_by_slots(self)

    def set(self, _policy: 'argreg_policy_t', gprs: 'int const *', fprs:
        'int const *') ->None:
        """Init policy & registers (arrays are -1-terminated)
"""
        return _ida_typeinf.callregs_t_set(self, _policy, gprs, fprs)
    GPREGS = _ida_typeinf.callregs_t_GPREGS
    FPREGS = _ida_typeinf.callregs_t_FPREGS

    def set_registers(self, kind: 'callregs_t::reg_kind_t', first_reg: int,
        last_reg: int) ->None:
        return _ida_typeinf.callregs_t_set_registers(self, kind, first_reg,
            last_reg)

    def reset(self) ->None:
        """Set policy and registers to invalid values.
"""
        return _ida_typeinf.callregs_t_reset(self)

    @staticmethod
    def regcount(cc: 'cm_t') ->int:
        """Get max number of registers may be used in a function call.
"""
        return _ida_typeinf.callregs_t_regcount(cc)

    def reginds(self, gp_ind: 'int *', fp_ind: 'int *', r: int) ->bool:
        """Get register indexes within GP/FP arrays. (-1 -> is not present in the corresponding array) 
        """
        return _ida_typeinf.callregs_t_reginds(self, gp_ind, fp_ind, r)
    __swig_destroy__ = _ida_typeinf.delete_callregs_t


_ida_typeinf.callregs_t_swigregister(callregs_t)
C_PC_TINY = cvar.C_PC_TINY
C_PC_SMALL = cvar.C_PC_SMALL
C_PC_COMPACT = cvar.C_PC_COMPACT
C_PC_MEDIUM = cvar.C_PC_MEDIUM
C_PC_LARGE = cvar.C_PC_LARGE
C_PC_HUGE = cvar.C_PC_HUGE
C_PC_FLAT = cvar.C_PC_FLAT


def get_comp(comp: 'comp_t') ->'comp_t':
    """Get compiler bits.
"""
    return _ida_typeinf.get_comp(comp)


def get_compiler_name(id: 'comp_t') ->str:
    """Get full compiler name.
"""
    return _ida_typeinf.get_compiler_name(id)


def get_compiler_abbr(id: 'comp_t') ->str:
    """Get abbreviated compiler name.
"""
    return _ida_typeinf.get_compiler_abbr(id)


def get_compilers(ids: 'compvec_t *', names: 'qstrvec_t *', abbrs:
    'qstrvec_t *') ->None:
    """Get names of all built-in compilers.
"""
    return _ida_typeinf.get_compilers(ids, names, abbrs)


def is_comp_unsure(comp: 'comp_t') ->'comp_t':
    """See COMP_UNSURE.
"""
    return _ida_typeinf.is_comp_unsure(comp)


def default_compiler() ->'comp_t':
    """Get compiler specified by inf.cc.
"""
    return _ida_typeinf.default_compiler()


def is_gcc() ->bool:
    """Is the target compiler COMP_GNU?
"""
    return _ida_typeinf.is_gcc()


def is_gcc32() ->bool:
    """Is the target compiler 32 bit gcc?
"""
    return _ida_typeinf.is_gcc32()


def is_gcc64() ->bool:
    """Is the target compiler 64 bit gcc?
"""
    return _ida_typeinf.is_gcc64()


def gcc_layout() ->bool:
    """Should use the struct/union layout as done by gcc?
"""
    return _ida_typeinf.gcc_layout()


def set_compiler(cc: 'compiler_info_t', flags: int, abiname: str=None) ->bool:
    """Change current compiler. 
        
@param cc: compiler to switch to
@param flags: Set compiler flags
@param abiname: ABI name
@returns success"""
    return _ida_typeinf.set_compiler(cc, flags, abiname)


SETCOMP_OVERRIDE = _ida_typeinf.SETCOMP_OVERRIDE
"""may override old compiler info
"""
SETCOMP_ONLY_ID = _ida_typeinf.SETCOMP_ONLY_ID
"""cc has only 'id' field; the rest will be set to defaults corresponding to the program bitness 
        """
SETCOMP_ONLY_ABI = _ida_typeinf.SETCOMP_ONLY_ABI
"""ignore cc field complete, use only abiname
"""
SETCOMP_BY_USER = _ida_typeinf.SETCOMP_BY_USER
"""invoked by user, cannot be replaced by module/loader
"""


def set_compiler_id(id: 'comp_t', abiname: str=None) ->bool:
    """Set the compiler id (see Compiler IDs)
"""
    return _ida_typeinf.set_compiler_id(id, abiname)


def set_abi_name(abiname: str, user_level: bool=False) ->bool:
    """Set abi name (see Compiler IDs)
"""
    return _ida_typeinf.set_abi_name(abiname, user_level)


def get_abi_name() ->str:
    """Get ABI name. 
        
@returns length of the name (>=0)"""
    return _ida_typeinf.get_abi_name()


def append_abi_opts(abi_opts: str, user_level: bool=False) ->bool:
    """Add/remove/check ABI option General form of full abi name: abiname-opt1-opt2-... or -opt1-opt2-... 
        
@param abi_opts: - ABI options to add/remove in form opt1-opt2-...
@param user_level: - initiated by user if TRUE (==SETCOMP_BY_USER)
@returns success"""
    return _ida_typeinf.append_abi_opts(abi_opts, user_level)


def remove_abi_opts(abi_opts: str, user_level: bool=False) ->bool:
    return _ida_typeinf.remove_abi_opts(abi_opts, user_level)


def set_compiler_string(compstr: str, user_level: bool) ->bool:
    """@param compstr: - compiler description in form <abbr>:<abiname>
@param user_level: - initiated by user if TRUE
@returns success"""
    return _ida_typeinf.set_compiler_string(compstr, user_level)


def use_golang_cc() ->bool:
    """is GOLANG calling convention used by default?
"""
    return _ida_typeinf.use_golang_cc()


def switch_to_golang() ->None:
    """switch to GOLANG calling convention (to be used as default CC)
"""
    return _ida_typeinf.switch_to_golang()


MAX_FUNC_ARGS = _ida_typeinf.MAX_FUNC_ARGS
"""max number of function arguments
"""
ABS_UNK = _ida_typeinf.ABS_UNK
ABS_NO = _ida_typeinf.ABS_NO
ABS_YES = _ida_typeinf.ABS_YES
SC_UNK = _ida_typeinf.SC_UNK
"""unknown
"""
SC_TYPE = _ida_typeinf.SC_TYPE
"""typedef
"""
SC_EXT = _ida_typeinf.SC_EXT
"""extern
"""
SC_STAT = _ida_typeinf.SC_STAT
"""static
"""
SC_REG = _ida_typeinf.SC_REG
"""register
"""
SC_AUTO = _ida_typeinf.SC_AUTO
"""auto
"""
SC_FRIEND = _ida_typeinf.SC_FRIEND
"""friend
"""
SC_VIRT = _ida_typeinf.SC_VIRT
"""virtual
"""
HTI_CPP = _ida_typeinf.HTI_CPP
"""C++ mode (not implemented)
"""
HTI_INT = _ida_typeinf.HTI_INT
"""debug: print internal representation of types
"""
HTI_EXT = _ida_typeinf.HTI_EXT
"""debug: print external representation of types
"""
HTI_LEX = _ida_typeinf.HTI_LEX
"""debug: print tokens
"""
HTI_UNP = _ida_typeinf.HTI_UNP
"""debug: check the result by unpacking it
"""
HTI_TST = _ida_typeinf.HTI_TST
"""test mode: discard the result
"""
HTI_FIL = _ida_typeinf.HTI_FIL
""""input" is file name, otherwise "input" contains a C declaration 
        """
HTI_MAC = _ida_typeinf.HTI_MAC
"""define macros from the base tils
"""
HTI_NWR = _ida_typeinf.HTI_NWR
"""no warning messages
"""
HTI_NER = _ida_typeinf.HTI_NER
"""ignore all errors but display them
"""
HTI_DCL = _ida_typeinf.HTI_DCL
"""don't complain about redeclarations
"""
HTI_NDC = _ida_typeinf.HTI_NDC
"""don't decorate names
"""
HTI_PAK = _ida_typeinf.HTI_PAK
"""explicit structure pack value (#pragma pack)
"""
HTI_PAK_SHIFT = _ida_typeinf.HTI_PAK_SHIFT
"""shift for HTI_PAK. This field should be used if you want to remember an explicit pack value for each structure/union type. See HTI_PAK... definitions 
        """
HTI_PAKDEF = _ida_typeinf.HTI_PAKDEF
"""default pack value
"""
HTI_PAK1 = _ida_typeinf.HTI_PAK1
"""#pragma pack(1)
"""
HTI_PAK2 = _ida_typeinf.HTI_PAK2
"""#pragma pack(2)
"""
HTI_PAK4 = _ida_typeinf.HTI_PAK4
"""#pragma pack(4)
"""
HTI_PAK8 = _ida_typeinf.HTI_PAK8
"""#pragma pack(8)
"""
HTI_PAK16 = _ida_typeinf.HTI_PAK16
"""#pragma pack(16)
"""
HTI_HIGH = _ida_typeinf.HTI_HIGH
"""assume high level prototypes (with hidden args, etc) 
        """
HTI_LOWER = _ida_typeinf.HTI_LOWER
"""lower the function prototypes
"""
HTI_RAWARGS = _ida_typeinf.HTI_RAWARGS
"""leave argument names unchanged (do not remove underscores)
"""
HTI_RELAXED = _ida_typeinf.HTI_RELAXED
"""accept references to unknown namespaces
"""
HTI_NOBASE = _ida_typeinf.HTI_NOBASE
"""do not inspect base tils
"""
HTI_SEMICOLON = _ida_typeinf.HTI_SEMICOLON
"""do not complain if the terminated semicolon is absent
"""


def convert_pt_flags_to_hti(pt_flags: int) ->int:
    """Convert Type parsing flags to Type formatting flags. Type parsing flags lesser than 0x10 don't have stable meaning and will be ignored (more on these flags can be seen in idc.idc) 
        """
    return _ida_typeinf.convert_pt_flags_to_hti(pt_flags)


def parse_decl(out_tif: 'tinfo_t', til: 'til_t', decl: str, pt_flags: int
    ) ->str:
    """Parse ONE declaration. If the input string contains more than one declaration, the first complete type declaration (PT_TYP) or the last variable declaration (PT_VAR) will be used. 
        
@param out_tif: type info
@param til: type library to use. may be nullptr
@param decl: C declaration to parse
@param pt_flags: combination of Type parsing flags bits
@retval true: ok
@retval false: declaration is bad, the error message is displayed if !PT_SIL"""
    return _ida_typeinf.parse_decl(out_tif, til, decl, pt_flags)


PT_SIL = _ida_typeinf.PT_SIL
"""silent, no messages
"""
PT_NDC = _ida_typeinf.PT_NDC
"""don't decorate names
"""
PT_TYP = _ida_typeinf.PT_TYP
"""return declared type information
"""
PT_VAR = _ida_typeinf.PT_VAR
"""return declared object information
"""
PT_PACKMASK = _ida_typeinf.PT_PACKMASK
"""mask for pack alignment values
"""
PT_HIGH = _ida_typeinf.PT_HIGH
"""assume high level prototypes (with hidden args, etc) 
        """
PT_LOWER = _ida_typeinf.PT_LOWER
"""lower the function prototypes
"""
PT_REPLACE = _ida_typeinf.PT_REPLACE
"""replace the old type (used in idc)
"""
PT_RAWARGS = _ida_typeinf.PT_RAWARGS
"""leave argument names unchanged (do not remove underscores)
"""
PT_RELAXED = _ida_typeinf.PT_RELAXED
"""accept references to unknown namespaces
"""
PT_EMPTY = _ida_typeinf.PT_EMPTY
"""accept empty decl
"""
PT_SEMICOLON = _ida_typeinf.PT_SEMICOLON
"""append the terminated semicolon
"""


def parse_decls(til: 'til_t', input: str, printer: 'printer_t *', hti_flags:
    int) ->int:
    """Parse many declarations and store them in a til. If there are any errors, they will be printed using 'printer'. This function uses default include path and predefined macros from the database settings. It always uses the HTI_DCL bit. 
        
@param til: type library to store the result
@param input: input string or file name (see hti_flags)
@param printer: function to output error messages (use msg or nullptr or your own callback)
@param hti_flags: combination of Type formatting flags
@returns number of errors, 0 means ok."""
    return _ida_typeinf.parse_decls(til, input, printer, hti_flags)


def print_type(ea: ida_idaapi.ea_t, prtype_flags: int) ->str:
    """Get type declaration for the specified address. 
        
@param ea: address
@param prtype_flags: combination of Type printing flags
@returns success"""
    return _ida_typeinf.print_type(ea, prtype_flags)


PRTYPE_1LINE = _ida_typeinf.PRTYPE_1LINE
"""print to one line
"""
PRTYPE_MULTI = _ida_typeinf.PRTYPE_MULTI
"""print to many lines
"""
PRTYPE_TYPE = _ida_typeinf.PRTYPE_TYPE
"""print type declaration (not variable declaration)
"""
PRTYPE_PRAGMA = _ida_typeinf.PRTYPE_PRAGMA
"""print pragmas for alignment
"""
PRTYPE_SEMI = _ida_typeinf.PRTYPE_SEMI
"""append ; to the end
"""
PRTYPE_CPP = _ida_typeinf.PRTYPE_CPP
"""use c++ name (only for print_type())
"""
PRTYPE_DEF = _ida_typeinf.PRTYPE_DEF
"""tinfo_t: print definition, if available
"""
PRTYPE_NOARGS = _ida_typeinf.PRTYPE_NOARGS
"""tinfo_t: do not print function argument names
"""
PRTYPE_NOARRS = _ida_typeinf.PRTYPE_NOARRS
"""tinfo_t: print arguments with FAI_ARRAY as pointers
"""
PRTYPE_NORES = _ida_typeinf.PRTYPE_NORES
"""tinfo_t: never resolve types (meaningful with PRTYPE_DEF)
"""
PRTYPE_RESTORE = _ida_typeinf.PRTYPE_RESTORE
"""tinfo_t: print restored types for FAI_ARRAY and FAI_STRUCT
"""
PRTYPE_NOREGEX = _ida_typeinf.PRTYPE_NOREGEX
"""do not apply regular expressions to beautify name
"""
PRTYPE_COLORED = _ida_typeinf.PRTYPE_COLORED
"""add color tag COLOR_SYMBOL for any parentheses, commas and colons
"""
PRTYPE_METHODS = _ida_typeinf.PRTYPE_METHODS
"""tinfo_t: print udt methods
"""
PRTYPE_1LINCMT = _ida_typeinf.PRTYPE_1LINCMT
"""print comments even in the one line mode
"""
PRTYPE_HEADER = _ida_typeinf.PRTYPE_HEADER
"""print only type header (only for definitions)
"""
PRTYPE_OFFSETS = _ida_typeinf.PRTYPE_OFFSETS
"""print udt member offsets
"""
PRTYPE_MAXSTR = _ida_typeinf.PRTYPE_MAXSTR
"""limit the output length to 1024 bytes (the output may be slightly longer)
"""
PRTYPE_TAIL = _ida_typeinf.PRTYPE_TAIL
"""print only the definition tail (only for definitions, exclusive with PRTYPE_HEADER)
"""
PRTYPE_ARGLOCS = _ida_typeinf.PRTYPE_ARGLOCS
"""print function arglocs (not only for usercall)
"""
NTF_TYPE = _ida_typeinf.NTF_TYPE
"""type name
"""
NTF_SYMU = _ida_typeinf.NTF_SYMU
"""symbol, name is unmangled ('func')
"""
NTF_SYMM = _ida_typeinf.NTF_SYMM
"""symbol, name is mangled ('_func'); only one of NTF_TYPE and NTF_SYMU, NTF_SYMM can be used 
        """
NTF_NOBASE = _ida_typeinf.NTF_NOBASE
"""don't inspect base tils (for get_named_type)
"""
NTF_REPLACE = _ida_typeinf.NTF_REPLACE
"""replace original type (for set_named_type)
"""
NTF_UMANGLED = _ida_typeinf.NTF_UMANGLED
"""name is unmangled (don't use this flag)
"""
NTF_NOCUR = _ida_typeinf.NTF_NOCUR
"""don't inspect current til file (for get_named_type)
"""
NTF_64BIT = _ida_typeinf.NTF_64BIT
"""value is 64bit
"""
NTF_FIXNAME = _ida_typeinf.NTF_FIXNAME
"""force-validate the name of the type when setting (set_named_type, set_numbered_type only) 
        """
NTF_IDBENC = _ida_typeinf.NTF_IDBENC
"""the name is given in the IDB encoding; non-ASCII bytes will be decoded accordingly (set_named_type, set_numbered_type only) 
        """
NTF_CHKSYNC = _ida_typeinf.NTF_CHKSYNC
"""check that synchronization to IDB passed OK (set_numbered_type, set_named_type) 
        """
NTF_NO_NAMECHK = _ida_typeinf.NTF_NO_NAMECHK
"""do not validate type name (set_numbered_type, set_named_type) 
        """
NTF_COPY = _ida_typeinf.NTF_COPY
"""save a new type definition, not a typeref (tinfo_t::set_numbered_type, tinfo_t::set_named_type)
"""
TERR_OK = _ida_typeinf.TERR_OK
"""ok
"""
TERR_SAVE_ERROR = _ida_typeinf.TERR_SAVE_ERROR
"""failed to save
"""
TERR_SERIALIZE = _ida_typeinf.TERR_SERIALIZE
"""failed to serialize
"""
TERR_BAD_NAME = _ida_typeinf.TERR_BAD_NAME
"""name s is not acceptable
"""
TERR_BAD_ARG = _ida_typeinf.TERR_BAD_ARG
"""bad argument
"""
TERR_BAD_TYPE = _ida_typeinf.TERR_BAD_TYPE
"""bad type
"""
TERR_BAD_SIZE = _ida_typeinf.TERR_BAD_SIZE
"""bad size d
"""
TERR_BAD_INDEX = _ida_typeinf.TERR_BAD_INDEX
"""bad index d
"""
TERR_BAD_ARRAY = _ida_typeinf.TERR_BAD_ARRAY
"""arrays are forbidden as function arguments
"""
TERR_BAD_BF = _ida_typeinf.TERR_BAD_BF
"""bitfields are forbidden as function arguments
"""
TERR_BAD_OFFSET = _ida_typeinf.TERR_BAD_OFFSET
"""bad member offset s
"""
TERR_BAD_UNIVAR = _ida_typeinf.TERR_BAD_UNIVAR
"""unions cannot have variable sized members
"""
TERR_BAD_VARLAST = _ida_typeinf.TERR_BAD_VARLAST
"""variable sized member must be the last member in the structure
"""
TERR_OVERLAP = _ida_typeinf.TERR_OVERLAP
"""the member overlaps with other members that cannot be deleted
"""
TERR_BAD_SUBTYPE = _ida_typeinf.TERR_BAD_SUBTYPE
"""recursive structure nesting is forbidden
"""
TERR_BAD_VALUE = _ida_typeinf.TERR_BAD_VALUE
"""value 0xI64X is not acceptable
"""
TERR_NO_BMASK = _ida_typeinf.TERR_NO_BMASK
"""bitmask 0xI64X is not found
"""
TERR_BAD_BMASK = _ida_typeinf.TERR_BAD_BMASK
"""Bad enum member mask 0xI64X. The specified mask should not intersect with any existing mask in the enum. Zero masks are prohibited too.
"""
TERR_BAD_MSKVAL = _ida_typeinf.TERR_BAD_MSKVAL
"""bad bmask and value combination (value=0xI64X; bitmask 0xI64X)
"""
TERR_BAD_REPR = _ida_typeinf.TERR_BAD_REPR
"""bad or incompatible field representation
"""
TERR_GRP_NOEMPTY = _ida_typeinf.TERR_GRP_NOEMPTY
"""could not delete group mask for not empty group 0xI64X
"""
TERR_DUPNAME = _ida_typeinf.TERR_DUPNAME
"""duplicate name s
"""
TERR_UNION_BF = _ida_typeinf.TERR_UNION_BF
"""unions cannot have bitfields
"""
TERR_BAD_TAH = _ida_typeinf.TERR_BAD_TAH
"""bad bits in the type attributes (TAH bits)
"""
TERR_BAD_BASE = _ida_typeinf.TERR_BAD_BASE
"""bad base class
"""
TERR_BAD_GAP = _ida_typeinf.TERR_BAD_GAP
"""bad gap
"""
TERR_NESTED = _ida_typeinf.TERR_NESTED
"""recursive structure nesting is forbidden
"""
TERR_NOT_COMPAT = _ida_typeinf.TERR_NOT_COMPAT
"""the new type is not compatible with the old type
"""
TERR_BAD_LAYOUT = _ida_typeinf.TERR_BAD_LAYOUT
"""failed to calculate the structure/union layout
"""
TERR_BAD_GROUPS = _ida_typeinf.TERR_BAD_GROUPS
"""bad group sizes for bitmask enum
"""
TERR_BAD_SERIAL = _ida_typeinf.TERR_BAD_SERIAL
"""enum value has too many serials
"""
TERR_ALIEN_NAME = _ida_typeinf.TERR_ALIEN_NAME
"""enum member name is used in another enum
"""
TERR_STOCK = _ida_typeinf.TERR_STOCK
"""stock type info cannot be modified
"""
TERR_ENUM_SIZE = _ida_typeinf.TERR_ENUM_SIZE
"""bad enum size
"""
TERR_NOT_IMPL = _ida_typeinf.TERR_NOT_IMPL
"""not implemented
"""
TERR_TYPE_WORSE = _ida_typeinf.TERR_TYPE_WORSE
"""the new type is worse than the old type
"""
TERR_BAD_FX_SIZE = _ida_typeinf.TERR_BAD_FX_SIZE
"""cannot extend struct beyond fixed size
"""
TERR_STRUCT_SIZE = _ida_typeinf.TERR_STRUCT_SIZE
"""bad fixed structure size
"""
TERR_NOT_FOUND = _ida_typeinf.TERR_NOT_FOUND
"""member not found
"""
TERR_COUNT = _ida_typeinf.TERR_COUNT


def tinfo_errstr(code: 'tinfo_code_t') ->str:
    """Helper function to convert an error code into a printable string. Additional arguments are handled using the functions from err.h 
        """
    return _ida_typeinf.tinfo_errstr(code)


def del_named_type(ti: 'til_t', name: str, ntf_flags: int) ->bool:
    """Delete information about a symbol. 
        
@param ti: type library
@param name: name of symbol
@param ntf_flags: combination of Flags for named types
@returns success"""
    return _ida_typeinf.del_named_type(ti, name, ntf_flags)


def first_named_type(ti: 'til_t', ntf_flags: int) ->str:
    """Enumerate types. 
        
@param ti: type library. nullptr means the local type library for the current database.
@param ntf_flags: combination of Flags for named types
@returns Type or symbol names, depending of ntf_flags. Returns mangled names. Never returns anonymous types. To include them, enumerate types by ordinals."""
    return _ida_typeinf.first_named_type(ti, ntf_flags)


def next_named_type(ti: 'til_t', name: str, ntf_flags: int) ->str:
    """Enumerate types. 
        
@param ti: type library. nullptr means the local type library for the current database.
@param name: the current name. the name that follows this one will be returned.
@param ntf_flags: combination of Flags for named types
@returns Type or symbol names, depending of ntf_flags. Returns mangled names. Never returns anonymous types. To include them, enumerate types by ordinals."""
    return _ida_typeinf.next_named_type(ti, name, ntf_flags)


def copy_named_type(dsttil: 'til_t', srctil: 'til_t', name: str) ->int:
    """Copy a named type from one til to another. This function will copy the specified type and all dependent types from the source type library to the destination library. 
        
@param dsttil: Destination til. It must have original types enabled
@param srctil: Source til.
@param name: name of the type to copy
@returns ordinal number of the copied type. 0 means error"""
    return _ida_typeinf.copy_named_type(dsttil, srctil, name)


def gen_decorate_name(name: str, mangle: bool, cc: 'cm_t', type: 'tinfo_t'
    ) ->str:
    """Generic function for decorate_name() (may be used in IDP modules)
"""
    return _ida_typeinf.gen_decorate_name(name, mangle, cc, type)


def calc_c_cpp_name(name: str, type: 'tinfo_t', ccn_flags: int) ->str:
    """Get C or C++ form of the name. 
        
@param name: original (mangled or decorated) name
@param type: name type if known, otherwise nullptr
@param ccn_flags: one of C/C++ naming flags"""
    return _ida_typeinf.calc_c_cpp_name(name, type, ccn_flags)


CCN_C = _ida_typeinf.CCN_C
CCN_CPP = _ida_typeinf.CCN_CPP


def enable_numbered_types(ti: 'til_t', enable: bool) ->bool:
    """Enable the use of numbered types in til. Currently it is impossible to disable numbered types once they are enabled 
        """
    return _ida_typeinf.enable_numbered_types(ti, enable)


def alloc_type_ordinals(ti: 'til_t', qty: int) ->int:
    """Allocate a range of ordinal numbers for new types. 
        
@param ti: type library
@param qty: number of ordinals to allocate
@returns the first ordinal. 0 means failure."""
    return _ida_typeinf.alloc_type_ordinals(ti, qty)


def alloc_type_ordinal(ti: 'til_t') ->int:
    """alloc_type_ordinals(ti, 1)
"""
    return _ida_typeinf.alloc_type_ordinal(ti)


def get_ordinal_limit(ti: 'til_t'=None) ->int:
    """Get number of allocated ordinals + 1. If there are no allocated ordinals, return 0. To enumerate all ordinals, use: for ( uint32 i = 1; i < limit; ++i ) 
        
@param ti: type library; nullptr means the local types for the current database.
@returns uint32(-1) if ordinals have not been enabled for the til. For local types (idati), ordinals are always enabled."""
    return _ida_typeinf.get_ordinal_limit(ti)


def get_ordinal_count(ti: 'til_t'=None) ->int:
    """Get number of allocated ordinals. 
        
@param ti: type library; nullptr means the local types for the current database.
@returns 0 if ordinals have not been enabled for the til."""
    return _ida_typeinf.get_ordinal_count(ti)


def del_numbered_type(ti: 'til_t', ordinal: int) ->bool:
    """Delete a numbered type.
"""
    return _ida_typeinf.del_numbered_type(ti, ordinal)


def set_type_alias(ti: 'til_t', src_ordinal: int, dst_ordinal: int) ->bool:
    """Create a type alias. Redirects all references to source type to the destination type. This is equivalent to instantaneous replacement all references to srctype by dsttype. 
        """
    return _ida_typeinf.set_type_alias(ti, src_ordinal, dst_ordinal)


def get_alias_target(ti: 'til_t', ordinal: int) ->int:
    """Find the final alias destination. If the ordinal has not been aliased, return the specified ordinal itself If failed, returns 0. 
        """
    return _ida_typeinf.get_alias_target(ti, ordinal)


def get_type_ordinal(ti: 'til_t', name: str) ->int:
    """Get type ordinal by its name.
"""
    return _ida_typeinf.get_type_ordinal(ti, name)


def get_numbered_type_name(ti: 'til_t', ordinal: int) ->str:
    """Get type name (if exists) by its ordinal. If the type is anonymous, returns "". If failed, returns nullptr 
        """
    return _ida_typeinf.get_numbered_type_name(ti, ordinal)


def create_numbered_type_name(ord: int) ->str:
    """Create anonymous name for numbered type. This name can be used to reference a numbered type by its ordinal Ordinal names have the following format: '#' + set_de(ord) Returns: -1 if error, otherwise the name length 
        """
    return _ida_typeinf.create_numbered_type_name(ord)


def is_ordinal_name(name: str, ord: 'uint32 *'=None) ->bool:
    """Check if the name is an ordinal name. Ordinal names have the following format: '#' + set_de(ord) 
        """
    return _ida_typeinf.is_ordinal_name(name, ord)


def is_type_choosable(ti: 'til_t', ordinal: int) ->bool:
    """Check if a struct/union type is choosable 
        
@param ti: type library
@param ordinal: ordinal number of a UDT type"""
    return _ida_typeinf.is_type_choosable(ti, ordinal)


def set_type_choosable(ti: 'til_t', ordinal: int, value: bool) ->None:
    """Enable/disable 'choosability' flag for a struct/union type 
        
@param ti: type library
@param ordinal: ordinal number of a UDT type
@param value: flag value"""
    return _ida_typeinf.set_type_choosable(ti, ordinal, value)


def get_vftable_ea(ordinal: int) ->ida_idaapi.ea_t:
    """Get address of a virtual function table. 
        
@param ordinal: ordinal number of a vftable type.
@returns address of the corresponding virtual function table in the current database."""
    return _ida_typeinf.get_vftable_ea(ordinal)


def get_vftable_ordinal(vftable_ea: ida_idaapi.ea_t) ->int:
    """Get ordinal number of the virtual function table. 
        
@param vftable_ea: address of a virtual function table.
@returns ordinal number of the corresponding vftable type. 0 - failure."""
    return _ida_typeinf.get_vftable_ordinal(vftable_ea)


def set_vftable_ea(ordinal: int, vftable_ea: ida_idaapi.ea_t) ->bool:
    """Set the address of a vftable instance for a vftable type. 
        
@param ordinal: ordinal number of the corresponding vftable type.
@param vftable_ea: address of a virtual function table.
@returns success"""
    return _ida_typeinf.set_vftable_ea(ordinal, vftable_ea)


def del_vftable_ea(ordinal: int) ->bool:
    """Delete the address of a vftable instance for a vftable type. 
        
@param ordinal: ordinal number of a vftable type.
@returns success"""
    return _ida_typeinf.del_vftable_ea(ordinal)


def deref_ptr(ptr_ea: 'ea_t *', tif: 'tinfo_t', closure_obj: 'ea_t *'=None
    ) ->bool:
    """Dereference a pointer. 
        
@param ptr_ea: in/out parameter
* in: address of the pointer
* out: the pointed address
@param tif: type of the pointer
@param closure_obj: closure object (not used yet)
@returns success"""
    return _ida_typeinf.deref_ptr(ptr_ea, tif, closure_obj)


def add_til(name: str, flags: int) ->int:
    """Load a til file and add it the database type libraries list. IDA will also apply function prototypes for matching function names. 
        
@param name: til name
@param flags: combination of Load TIL flags
@returns one of Load TIL result codes"""
    return _ida_typeinf.add_til(name, flags)


ADDTIL_DEFAULT = _ida_typeinf.ADDTIL_DEFAULT
"""default behavior
"""
ADDTIL_INCOMP = _ida_typeinf.ADDTIL_INCOMP
"""load incompatible tils
"""
ADDTIL_SILENT = _ida_typeinf.ADDTIL_SILENT
"""do not ask any questions
"""
ADDTIL_FAILED = _ida_typeinf.ADDTIL_FAILED
"""something bad, the warning is displayed
"""
ADDTIL_OK = _ida_typeinf.ADDTIL_OK
"""ok, til is loaded
"""
ADDTIL_COMP = _ida_typeinf.ADDTIL_COMP
"""ok, but til is not compatible with the current compiler
"""
ADDTIL_ABORTED = _ida_typeinf.ADDTIL_ABORTED
"""til was not loaded (incompatible til rejected by user)
"""


def del_til(name: str) ->bool:
    """Unload a til file.
"""
    return _ida_typeinf.del_til(name)


def apply_named_type(ea: ida_idaapi.ea_t, name: str) ->bool:
    """Apply the specified named type to the address. 
        
@param ea: linear address
@param name: the type name, e.g. "FILE"
@returns success"""
    return _ida_typeinf.apply_named_type(ea, name)


def apply_tinfo(ea: ida_idaapi.ea_t, tif: 'tinfo_t', flags: int) ->bool:
    """Apply the specified type to the specified address. This function sets the type and tries to convert the item at the specified address to conform the type. 
        
@param ea: linear address
@param tif: type string in internal format
@param flags: combination of Apply tinfo flags
@returns success"""
    return _ida_typeinf.apply_tinfo(ea, tif, flags)


TINFO_GUESSED = _ida_typeinf.TINFO_GUESSED
"""this is a guessed type
"""
TINFO_DEFINITE = _ida_typeinf.TINFO_DEFINITE
"""this is a definite type
"""
TINFO_DELAYFUNC = _ida_typeinf.TINFO_DELAYFUNC
"""if type is a function and no function exists at ea, schedule its creation and argument renaming to auto-analysis, otherwise try to create it immediately 
        """
TINFO_STRICT = _ida_typeinf.TINFO_STRICT
"""never convert given type to another one before applying
"""


def apply_cdecl(til: 'til_t', ea: ida_idaapi.ea_t, decl: str, flags: int=0
    ) ->bool:
    """Apply the specified type to the address. This function parses the declaration and calls apply_tinfo() 
        
@param til: type library
@param ea: linear address
@param decl: type declaration in C form
@param flags: flags to pass to apply_tinfo (TINFO_DEFINITE is always passed)
@returns success"""
    return _ida_typeinf.apply_cdecl(til, ea, decl, flags)


def apply_callee_tinfo(caller: ida_idaapi.ea_t, tif: 'tinfo_t') ->bool:
    """Apply the type of the called function to the calling instruction. This function will append parameter comments and rename the local variables of the calling function. It also stores information about the instructions that initialize call arguments in the database. Use get_arg_addrs() to retrieve it if necessary. Alternatively it is possible to hook to processor_t::arg_addrs_ready event. 
        
@param caller: linear address of the calling instruction. must belong to a function.
@param tif: type info
@returns success"""
    return _ida_typeinf.apply_callee_tinfo(caller, tif)


def apply_once_tinfo_and_name(dea: ida_idaapi.ea_t, tif: 'tinfo_t', name: str
    ) ->bool:
    """Apply the specified type and name to the address. This function checks if the address already has a type. If the old type 
does not exist or the new type is 'better' than the old type, then the 
new type will be applied. A type is considered better if it has more 
information (e.g. BTMT_STRUCT is better than BT_INT). 
The same logic is with the name: if the address already have a meaningful 
name, it will be preserved. Only if the old name does not exist or it 
is a dummy name like byte_123, it will be replaced by the new name. 
        
@param dea: linear address
@param tif: type string in the internal format
@param name: new name for the address
@returns success"""
    return _ida_typeinf.apply_once_tinfo_and_name(dea, tif, name)


def guess_tinfo(out: 'tinfo_t', id: 'tid_t') ->int:
    """Generate a type information about the id from the disassembly. id can be a structure/union/enum id or an address. 
        
@returns one of Guess tinfo codes"""
    return _ida_typeinf.guess_tinfo(out, id)


GUESS_FUNC_FAILED = _ida_typeinf.GUESS_FUNC_FAILED
"""couldn't guess the function type
"""
GUESS_FUNC_TRIVIAL = _ida_typeinf.GUESS_FUNC_TRIVIAL
"""the function type doesn't have interesting info
"""
GUESS_FUNC_OK = _ida_typeinf.GUESS_FUNC_OK
"""ok, some non-trivial information is gathered
"""


def set_c_header_path(incdir: str) ->None:
    """Set include directory path the target compiler.
"""
    return _ida_typeinf.set_c_header_path(incdir)


def get_c_header_path() ->str:
    """Get the include directory path of the target compiler.
"""
    return _ida_typeinf.get_c_header_path()


def set_c_macros(macros: str) ->None:
    """Set predefined macros for the target compiler.
"""
    return _ida_typeinf.set_c_macros(macros)


def get_c_macros() ->str:
    """Get predefined macros for the target compiler.
"""
    return _ida_typeinf.get_c_macros()


def get_idati() ->'til_t *':
    """Pointer to the local type library - this til is private for each IDB file Functions that accept til_t* default to `idati` when is nullptr provided. 
        """
    return _ida_typeinf.get_idati()


def get_idainfo_by_type(tif: 'tinfo_t'
    ) ->'size_t *, flags64_t *, opinfo_t *, size_t *':
    """Extract information from a tinfo_t. 
        
@param tif: the type to inspect"""
    return _ida_typeinf.get_idainfo_by_type(tif)


def get_tinfo_by_flags(out: 'tinfo_t', flags: 'flags64_t') ->bool:
    """Get tinfo object that corresponds to data flags 
        
@param out: type info
@param flags: simple flags (byte, word, ..., zword)"""
    return _ida_typeinf.get_tinfo_by_flags(out, flags)


STI_PCHAR = _ida_typeinf.STI_PCHAR
"""char *
"""
STI_PUCHAR = _ida_typeinf.STI_PUCHAR
"""uint8 *
"""
STI_PCCHAR = _ida_typeinf.STI_PCCHAR
"""const char *
"""
STI_PCUCHAR = _ida_typeinf.STI_PCUCHAR
"""const uint8 *
"""
STI_PBYTE = _ida_typeinf.STI_PBYTE
"""_BYTE *
"""
STI_PINT = _ida_typeinf.STI_PINT
"""int *
"""
STI_PUINT = _ida_typeinf.STI_PUINT
"""unsigned int *
"""
STI_PVOID = _ida_typeinf.STI_PVOID
"""void *
"""
STI_PPVOID = _ida_typeinf.STI_PPVOID
"""void **
"""
STI_PCVOID = _ida_typeinf.STI_PCVOID
"""const void *
"""
STI_ACHAR = _ida_typeinf.STI_ACHAR
"""char[]
"""
STI_AUCHAR = _ida_typeinf.STI_AUCHAR
"""uint8[]
"""
STI_ACCHAR = _ida_typeinf.STI_ACCHAR
"""const char[]
"""
STI_ACUCHAR = _ida_typeinf.STI_ACUCHAR
"""const uint8[]
"""
STI_FPURGING = _ida_typeinf.STI_FPURGING
"""void __userpurge(int)
"""
STI_FDELOP = _ida_typeinf.STI_FDELOP
"""void __cdecl(void *)
"""
STI_MSGSEND = _ida_typeinf.STI_MSGSEND
"""void *(void *, const char *, ...)
"""
STI_AEABI_LCMP = _ida_typeinf.STI_AEABI_LCMP
"""int __fastcall __pure(int64 x, int64 y)
"""
STI_AEABI_ULCMP = _ida_typeinf.STI_AEABI_ULCMP
"""int __fastcall __pure(uint64 x, uint64 y)
"""
STI_DONT_USE = _ida_typeinf.STI_DONT_USE
"""unused stock type id; should not be used
"""
STI_SIZE_T = _ida_typeinf.STI_SIZE_T
"""size_t
"""
STI_SSIZE_T = _ida_typeinf.STI_SSIZE_T
"""ssize_t
"""
STI_AEABI_MEMCPY = _ida_typeinf.STI_AEABI_MEMCPY
"""void __fastcall(void *, const void *, size_t)
"""
STI_AEABI_MEMSET = _ida_typeinf.STI_AEABI_MEMSET
"""void __fastcall(void *, size_t, int)
"""
STI_AEABI_MEMCLR = _ida_typeinf.STI_AEABI_MEMCLR
"""void __fastcall(void *, size_t)
"""
STI_RTC_CHECK_2 = _ida_typeinf.STI_RTC_CHECK_2
"""int16 __fastcall(int16 x)
"""
STI_RTC_CHECK_4 = _ida_typeinf.STI_RTC_CHECK_4
"""int32 __fastcall(int32 x)
"""
STI_RTC_CHECK_8 = _ida_typeinf.STI_RTC_CHECK_8
"""int64 __fastcall(int64 x)
"""
STI_COMPLEX64 = _ida_typeinf.STI_COMPLEX64
"""struct complex64_t { float real, imag; }
"""
STI_COMPLEX128 = _ida_typeinf.STI_COMPLEX128
"""struct complex128_t { double real, imag; }
"""
STI_PUNKNOWN = _ida_typeinf.STI_PUNKNOWN
"""_UNKNOWN *
"""
STI_LAST = _ida_typeinf.STI_LAST
ETF_NO_SAVE = _ida_typeinf.ETF_NO_SAVE
"""don't save to til (normally typerefs are saved to til) A call with ETF_NO_SAVE must be followed by a call without it. Otherwise there may be inconsistencies between the memory and the type library. 
          """
ETF_NO_LAYOUT = _ida_typeinf.ETF_NO_LAYOUT
"""don't calc type layout before editing
"""
ETF_MAY_DESTROY = _ida_typeinf.ETF_MAY_DESTROY
"""may destroy other members
"""
ETF_COMPATIBLE = _ida_typeinf.ETF_COMPATIBLE
"""new type must be compatible with the old
"""
ETF_FUNCARG = _ida_typeinf.ETF_FUNCARG
"""udm - member is a function argument (cannot create arrays)
"""
ETF_FORCENAME = _ida_typeinf.ETF_FORCENAME
"""anyway use name, see below for more usage description
"""
ETF_AUTONAME = _ida_typeinf.ETF_AUTONAME
"""udm - generate a member name if was not specified (add_udm, set_udm_type)
"""
ETF_BYTIL = _ida_typeinf.ETF_BYTIL
"""udm - new type was created by the type subsystem
"""
ETF_NO_ARRAY = _ida_typeinf.ETF_NO_ARRAY
"""add_udm, set_udm_type - do not convert type to an array on the size mismatch
"""
GTD_CALC_LAYOUT = _ida_typeinf.GTD_CALC_LAYOUT
"""calculate udt layout
"""
GTD_NO_LAYOUT = _ida_typeinf.GTD_NO_LAYOUT
"""don't calculate udt layout please note that udt layout may have been calculated earlier 
          """
GTD_DEL_BITFLDS = _ida_typeinf.GTD_DEL_BITFLDS
"""delete udt bitfields
"""
GTD_CALC_ARGLOCS = _ida_typeinf.GTD_CALC_ARGLOCS
"""calculate func arg locations
"""
GTD_NO_ARGLOCS = _ida_typeinf.GTD_NO_ARGLOCS
"""don't calculate func arg locations please note that the locations may have been calculated earlier 
          """
GTS_NESTED = _ida_typeinf.GTS_NESTED
"""nested type (embedded into a udt)
"""
GTS_BASECLASS = _ida_typeinf.GTS_BASECLASS
"""is baseclass of a udt
"""
SUDT_SORT = _ida_typeinf.SUDT_SORT
"""fields are not sorted by offset, sort them first
"""
SUDT_ALIGN = _ida_typeinf.SUDT_ALIGN
"""recalculate field alignments, struct packing, etc to match the offsets and size info 
        """
SUDT_GAPS = _ida_typeinf.SUDT_GAPS
"""allow to fill gaps with additional members (_BYTE[])
"""
SUDT_UNEX = _ida_typeinf.SUDT_UNEX
"""references to nonexistent member types are acceptable; in this case it is better to set the corresponding udm_t::fda field to the type alignment. If this field is not set, ida will try to guess the alignment. 
        """
SUDT_FAST = _ida_typeinf.SUDT_FAST
"""serialize without verifying offsets and alignments
"""
SUDT_CONST = _ida_typeinf.SUDT_CONST
"""only for serialize_udt: make type const
"""
SUDT_VOLATILE = _ida_typeinf.SUDT_VOLATILE
"""only for serialize_udt: make type volatile
"""
SUDT_TRUNC = _ida_typeinf.SUDT_TRUNC
"""serialize: truncate useless strings from fields, fldcmts
"""
SUDT_SERDEF = _ida_typeinf.SUDT_SERDEF
"""serialize: if a typeref, serialize its definition
"""


def copy_tinfo_t(_this: 'tinfo_t', r: 'tinfo_t') ->None:
    return _ida_typeinf.copy_tinfo_t(_this, r)


def detach_tinfo_t(_this: 'tinfo_t') ->bool:
    return _ida_typeinf.detach_tinfo_t(_this)


def clear_tinfo_t(_this: 'tinfo_t') ->None:
    return _ida_typeinf.clear_tinfo_t(_this)


def create_tinfo(_this: 'tinfo_t', bt: 'type_t', bt2: 'type_t', ptr: 'void *'
    ) ->bool:
    return _ida_typeinf.create_tinfo(_this, bt, bt2, ptr)


def verify_tinfo(typid: 'typid_t') ->int:
    return _ida_typeinf.verify_tinfo(typid)


def get_tinfo_details(typid: 'typid_t', bt2: 'type_t', buf: 'void *') ->bool:
    return _ida_typeinf.get_tinfo_details(typid, bt2, buf)


def get_tinfo_size(p_effalign: 'uint32 *', typid: 'typid_t', gts_code: int
    ) ->'size_t':
    return _ida_typeinf.get_tinfo_size(p_effalign, typid, gts_code)


def get_tinfo_pdata(outptr: 'void *', typid: 'typid_t', what: int) ->'size_t':
    return _ida_typeinf.get_tinfo_pdata(outptr, typid, what)


def get_tinfo_property(typid: 'typid_t', gta_prop: int) ->'size_t':
    return _ida_typeinf.get_tinfo_property(typid, gta_prop)


def get_tinfo_property4(typid: 'typid_t', gta_prop: int, p1: 'size_t', p2:
    'size_t', p3: 'size_t', p4: 'size_t') ->'size_t':
    return _ida_typeinf.get_tinfo_property4(typid, gta_prop, p1, p2, p3, p4)


def set_tinfo_property(tif: 'tinfo_t', sta_prop: int, x: 'size_t') ->'size_t':
    return _ida_typeinf.set_tinfo_property(tif, sta_prop, x)


def set_tinfo_property4(tif: 'tinfo_t', sta_prop: int, p1: 'size_t', p2:
    'size_t', p3: 'size_t', p4: 'size_t') ->'size_t':
    return _ida_typeinf.set_tinfo_property4(tif, sta_prop, p1, p2, p3, p4)


def serialize_tinfo(type: 'qtype *', fields: 'qtype *', fldcmts: 'qtype *',
    tif: 'tinfo_t', sudt_flags: int) ->bool:
    return _ida_typeinf.serialize_tinfo(type, fields, fldcmts, tif, sudt_flags)


def find_tinfo_udt_member(udm: 'udm_t', typid: 'typid_t', strmem_flags: int
    ) ->int:
    return _ida_typeinf.find_tinfo_udt_member(udm, typid, strmem_flags)


def print_tinfo(prefix: str, indent: int, cmtindent: int, flags: int, tif:
    'tinfo_t', name: str, cmt: str) ->str:
    return _ida_typeinf.print_tinfo(prefix, indent, cmtindent, flags, tif,
        name, cmt)


def dstr_tinfo(tif: 'tinfo_t') ->str:
    return _ida_typeinf.dstr_tinfo(tif)


def visit_subtypes(visitor: 'tinfo_visitor_t', out: 'type_mods_t', tif:
    'tinfo_t', name: str, cmt: str) ->int:
    return _ida_typeinf.visit_subtypes(visitor, out, tif, name, cmt)


def compare_tinfo(t1: 'typid_t', t2: 'typid_t', tcflags: int) ->bool:
    return _ida_typeinf.compare_tinfo(t1, t2, tcflags)


def lexcompare_tinfo(t1: 'typid_t', t2: 'typid_t', arg3: int) ->int:
    return _ida_typeinf.lexcompare_tinfo(t1, t2, arg3)


def get_stock_tinfo(tif: 'tinfo_t', id: 'stock_type_id_t') ->bool:
    return _ida_typeinf.get_stock_tinfo(tif, id)


def read_tinfo_bitfield_value(typid: 'typid_t', v: 'uint64', bitoff: int
    ) ->'uint64':
    return _ida_typeinf.read_tinfo_bitfield_value(typid, v, bitoff)


def write_tinfo_bitfield_value(typid: 'typid_t', dst: 'uint64', v: 'uint64',
    bitoff: int) ->'uint64':
    return _ida_typeinf.write_tinfo_bitfield_value(typid, dst, v, bitoff)


def get_tinfo_attr(typid: 'typid_t', key: str, bv: 'bytevec_t *', all_attrs:
    bool) ->bool:
    return _ida_typeinf.get_tinfo_attr(typid, key, bv, all_attrs)


def set_tinfo_attr(tif: 'tinfo_t', ta: 'type_attr_t', may_overwrite: bool
    ) ->bool:
    return _ida_typeinf.set_tinfo_attr(tif, ta, may_overwrite)


def del_tinfo_attr(tif: 'tinfo_t', key: str, make_copy: bool) ->bool:
    return _ida_typeinf.del_tinfo_attr(tif, key, make_copy)


def get_tinfo_attrs(typid: 'typid_t', tav: 'type_attrs_t',
    include_ref_attrs: bool) ->bool:
    return _ida_typeinf.get_tinfo_attrs(typid, tav, include_ref_attrs)


def set_tinfo_attrs(tif: 'tinfo_t', ta: 'type_attrs_t') ->bool:
    return _ida_typeinf.set_tinfo_attrs(tif, ta)


def score_tinfo(tif: 'tinfo_t') ->int:
    return _ida_typeinf.score_tinfo(tif)


def save_tinfo(tif: 'tinfo_t', til: 'til_t', ord: 'size_t', name: str,
    ntf_flags: int) ->'tinfo_code_t':
    return _ida_typeinf.save_tinfo(tif, til, ord, name, ntf_flags)


def append_tinfo_covered(out: 'rangeset_t', typid: 'typid_t', offset: 'uint64'
    ) ->bool:
    return _ida_typeinf.append_tinfo_covered(out, typid, offset)


def calc_tinfo_gaps(out: 'rangeset_t', typid: 'typid_t') ->bool:
    return _ida_typeinf.calc_tinfo_gaps(out, typid)


def value_repr_t__from_opinfo(_this: 'value_repr_t', flags: 'flags64_t',
    afl: 'aflags_t', opinfo: 'opinfo_t', ap: 'array_parameters_t') ->bool:
    return _ida_typeinf.value_repr_t__from_opinfo(_this, flags, afl, opinfo, ap
        )


def value_repr_t__print_(_this: 'value_repr_t', colored: bool) ->str:
    return _ida_typeinf.value_repr_t__print_(_this, colored)


def udt_type_data_t__find_member(_this: 'udt_type_data_t', udm: 'udm_t',
    strmem_flags: int) ->'ssize_t':
    return _ida_typeinf.udt_type_data_t__find_member(_this, udm, strmem_flags)


def udt_type_data_t__get_best_fit_member(_this: 'udt_type_data_t', disp:
    'asize_t') ->'ssize_t':
    return _ida_typeinf.udt_type_data_t__get_best_fit_member(_this, disp)


def get_tinfo_by_edm_name(tif: 'tinfo_t', til: 'til_t', mname: str
    ) ->'ssize_t':
    return _ida_typeinf.get_tinfo_by_edm_name(tif, til, mname)


class tinfo_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args, ordinal=None, name=None, tid=None, til=None):
        """Create a type object with the provided argumens.

This constructor has the following signatures:

    1. tinfo_t(decl_type: type_t)
    2. tinfo_t(decl: str, til: til_t = None, pt_flags: int = 0)

The latter form will create the type object by parsing the type declaration

Alternatively, you can use a form accepting the following keyword arguments:

* ordinal: int
* name: str
* tid: int
* til: til_t=None # `None` means `get_idati()`

E.g.,

* tinfo_t(ordinal=3)
* tinfo_t(ordinal=10, til=get_idati())
* tinfo_t(name="mytype_t")
* tinfo_t(name="thattype_t", til=my_other_til)
* tinfo_t(tid=ida_nalt.get_strid(some_address))

The constructor may raise an exception if data was invalid, or if parsing failed.

@param decl_type A simple type
@param decl A valid C declaration
@param til A type library, or `None` to use the (`get_idati()`) default
@param ordinal An ordinal in the type library
@param name A valid type name
@param pt_flags Parsing flags"""
        _ida_typeinf.tinfo_t_swiginit(self, _ida_typeinf.new_tinfo_t(*args))
        if args and self.empty():
            raise ValueError('Invalid input data: %s' % str(args))
        elif ordinal is not None:
            if not self.get_numbered_type(til, ordinal):
                raise ValueError(
                    'No type with ordinal %s in type library %s' % (ordinal,
                    til))
        elif name is not None:
            if not self.get_named_type(til, name):
                raise ValueError('No type with name %s in type library %s' %
                    (name, til))
        elif tid is not None:
            if not self.get_type_by_tid(tid):
                raise ValueError('No type with ID %s in type library %s' %
                    (name, til))

    def clear(self) ->None:
        """Clear contents of this tinfo, and remove from the type system.
"""
        return _ida_typeinf.tinfo_t_clear(self)

    def swap(self, r: 'tinfo_t') ->None:
        """Assign this = r and r = this.
"""
        return _ida_typeinf.tinfo_t_swap(self, r)

    def get_named_type(self, *args) ->bool:
        """This function has the following signatures:

    0. get_named_type(til: const til_t *, name: str, decl_type: type_t=BTF_TYPEDEF, resolve: bool=true, try_ordinal: bool=true) -> bool
    1. get_named_type(name: str, decl_type: type_t=BTF_TYPEDEF, resolve: bool=true, try_ordinal: bool=true) -> bool

# 0: get_named_type(til: const til_t *, name: str, decl_type: type_t=BTF_TYPEDEF, resolve: bool=true, try_ordinal: bool=true) -> bool

Create a tinfo_t object for an existing named type. 
        

# 1: get_named_type(name: str, decl_type: type_t=BTF_TYPEDEF, resolve: bool=true, try_ordinal: bool=true) -> bool

"""
        return _ida_typeinf.tinfo_t_get_named_type(self, *args)

    def get_numbered_type(self, *args) ->bool:
        """This function has the following signatures:

    0. get_numbered_type(til: const til_t *, ordinal: int, decl_type: type_t=BTF_TYPEDEF, resolve: bool=true) -> bool
    1. get_numbered_type(ordinal: int, decl_type: type_t=BTF_TYPEDEF, resolve: bool=true) -> bool

# 0: get_numbered_type(til: const til_t *, ordinal: int, decl_type: type_t=BTF_TYPEDEF, resolve: bool=true) -> bool

Create a tinfo_t object for an existing ordinal type. 
        

# 1: get_numbered_type(ordinal: int, decl_type: type_t=BTF_TYPEDEF, resolve: bool=true) -> bool

"""
        return _ida_typeinf.tinfo_t_get_numbered_type(self, *args)

    def detach(self) ->bool:
        """Detach tinfo_t from the underlying type. After calling this finction, tinfo_t will lose its link to the underlying named or numbered type (if any) and will become a reference to a unique type. After that, any modifications to tinfo_t will affect only its type. 
        """
        return _ida_typeinf.tinfo_t_detach(self)

    def is_correct(self) ->bool:
        """Is the type object correct?. It is possible to create incorrect types. For example, we can define a function that returns an enum and then delete the enum type. If this function returns false, the type should not be used in disassembly. Please note that this function does not verify all involved types: for example, pointers to undefined types are permitted. 
        """
        return _ida_typeinf.tinfo_t_is_correct(self)

    def get_realtype(self, full: bool=False) ->'type_t':
        """Get the resolved base type. Deserialization options:
* if full=true, the referenced type will be deserialized fully, this may not always be desirable (slows down things)
* if full=false, we just return the base type, the referenced type will be resolved again later if necessary (this may lead to multiple resolvings of the same type) imho full=false is a better approach because it does not perform unnecessary actions just in case. however, in some cases the caller knows that it is very likely that full type info will be required. in those cases full=true makes sense 


        """
        return _ida_typeinf.tinfo_t_get_realtype(self, full)

    def get_decltype(self) ->'type_t':
        """Get declared type (without resolving type references; they are returned as is). Obviously this is a very fast function and should be used instead of get_realtype() if possible. Please note that for typerefs this function will return BTF_TYPEDEF. To determine if a typeref is a typedef, use is_typedef() 
        """
        return _ida_typeinf.tinfo_t_get_decltype(self)

    def empty(self) ->bool:
        """Was tinfo_t initialized with some type info or not?
"""
        return _ida_typeinf.tinfo_t_empty(self)

    def present(self) ->bool:
        """Is the type really present? (not a reference to a missing type, for example)
"""
        return _ida_typeinf.tinfo_t_present(self)

    def get_size(self, p_effalign: 'uint32 *'=None, gts_code: int=0
        ) ->'size_t':
        """Get the type size in bytes. 
        
@param p_effalign: buffer for the alignment value
@param gts_code: combination of GTS_... constants
@returns BADSIZE in case of problems"""
        return _ida_typeinf.tinfo_t_get_size(self, p_effalign, gts_code)

    def get_unpadded_size(self) ->'size_t':
        """Get the type size in bytes without the final padding, in bytes. For some UDTs get_unpadded_size() != get_size() 
        """
        return _ida_typeinf.tinfo_t_get_unpadded_size(self)

    def get_alignment(self) ->int:
        """Get type alignment This function returns the effective type alignment. Zero means error. 
        """
        return _ida_typeinf.tinfo_t_get_alignment(self)

    def get_sign(self) ->'type_sign_t':
        """Get type sign.
"""
        return _ida_typeinf.tinfo_t_get_sign(self)

    def is_signed(self) ->bool:
        """Is this a signed type?
"""
        return _ida_typeinf.tinfo_t_is_signed(self)

    def is_unsigned(self) ->bool:
        """Is this an unsigned type?
"""
        return _ida_typeinf.tinfo_t_is_unsigned(self)

    def get_declalign(self) ->'uchar':
        """Get declared alignment of the type.
"""
        return _ida_typeinf.tinfo_t_get_declalign(self)

    def is_typeref(self) ->bool:
        """Is this type a type reference?.
"""
        return _ida_typeinf.tinfo_t_is_typeref(self)

    def has_details(self) ->bool:
        """Does this type refer to a nontrivial type?
"""
        return _ida_typeinf.tinfo_t_has_details(self)

    def get_type_name(self) ->bool:
        """Does a type refer to a name?. If yes, fill the provided buffer with the type name and return true. Names are returned for numbered types too: either a user-defined nice name or, if a user-provided name does not exist, an ordinal name (like #xx, see create_numbered_type_name()). 
        """
        return _ida_typeinf.tinfo_t_get_type_name(self)

    def get_nice_type_name(self) ->bool:
        """Get the beautified type name. Get the referenced name and apply regular expressions from goodname.cfg to beautify the name 
        """
        return _ida_typeinf.tinfo_t_get_nice_type_name(self)

    def rename_type(self, name: str, ntf_flags: int=0) ->'tinfo_code_t':
        """Rename a type 
        
@param name: new type name
@param ntf_flags: Flags for named types"""
        return _ida_typeinf.tinfo_t_rename_type(self, name, ntf_flags)

    def get_final_type_name(self) ->bool:
        """Use in the case of typedef chain (TYPE1 -> TYPE2 -> TYPE3...TYPEn). 
        
@returns the name of the last type in the chain (TYPEn). if there is no chain, returns TYPE1"""
        return _ida_typeinf.tinfo_t_get_final_type_name(self)

    def get_next_type_name(self) ->bool:
        """Use In the case of typedef chain (TYPE1 -> TYPE2 -> TYPE3...TYPEn). 
        
@returns the name of the next type in the chain (TYPE2). if there is no chain, returns failure"""
        return _ida_typeinf.tinfo_t_get_next_type_name(self)

    def get_tid(self) ->'tid_t':
        """Get the type tid Each type in the local type library has a so-called `tid` associated with it. The tid is used to collect xrefs to the type. The tid is created when the type is created in the local type library and does not change afterwards. It can be passed to xref-related functions instead of the address. 
        
@returns tid or BADADDR"""
        return _ida_typeinf.tinfo_t_get_tid(self)

    def force_tid(self) ->'tid_t':
        """Get the type tid. Create if it does not exist yet. If the type comes from a base til, the type will be copied to the local til and a new tid will be created for it. (if the type comes from a base til, it does not have a tid yet). If the type comes from the local til, this function is equivalent to get_tid() 
        
@returns tid or BADADDR"""
        return _ida_typeinf.tinfo_t_force_tid(self)

    def get_ordinal(self) ->int:
        """Get type ordinal (only if the type was created as a numbered type, 0 if none)
"""
        return _ida_typeinf.tinfo_t_get_ordinal(self)

    def get_final_ordinal(self) ->int:
        """Get final type ordinal (0 if none)
"""
        return _ida_typeinf.tinfo_t_get_final_ordinal(self)

    def get_til(self) ->'til_t *':
        """Get the type library for tinfo_t.
"""
        return _ida_typeinf.tinfo_t_get_til(self)

    def is_from_subtil(self) ->bool:
        """Was the named type found in some base type library (not the top level type library)?. If yes, it usually means that the type comes from some loaded type library, not the local type library for the database 
        """
        return _ida_typeinf.tinfo_t_is_from_subtil(self)

    def is_forward_decl(self) ->bool:
        """Is this a forward declaration?. Forward declarations are placeholders: the type definition does not exist 
        """
        return _ida_typeinf.tinfo_t_is_forward_decl(self)

    def get_forward_type(self) ->'type_t':
        """Get type of a forward declaration. For a forward declaration this function returns its base type. In other cases it returns BT_UNK 
        """
        return _ida_typeinf.tinfo_t_get_forward_type(self)

    def is_forward_struct(self) ->bool:
        return _ida_typeinf.tinfo_t_is_forward_struct(self)

    def is_forward_union(self) ->bool:
        return _ida_typeinf.tinfo_t_is_forward_union(self)

    def is_forward_enum(self) ->bool:
        return _ida_typeinf.tinfo_t_is_forward_enum(self)

    def is_typedef(self) ->bool:
        """Is this a typedef?. This function will return true for a reference to a local type that is declared as a typedef. 
        """
        return _ida_typeinf.tinfo_t_is_typedef(self)

    def get_type_cmt(self) ->int:
        """Get type comment 
        
@returns 0-failed, 1-returned regular comment, 2-returned repeatable comment"""
        return _ida_typeinf.tinfo_t_get_type_cmt(self)

    def get_type_rptcmt(self) ->bool:
        """Get type comment only if it is repeatable.
"""
        return _ida_typeinf.tinfo_t_get_type_rptcmt(self)

    def is_decl_const(self) ->bool:
        """is_type_const(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_const(self)

    def is_decl_volatile(self) ->bool:
        """is_type_volatile(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_volatile(self)

    def is_decl_void(self) ->bool:
        """is_type_void(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_void(self)

    def is_decl_partial(self) ->bool:
        """is_type_partial(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_partial(self)

    def is_decl_unknown(self) ->bool:
        """is_type_unknown(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_unknown(self)

    def is_decl_last(self) ->bool:
        """is_typeid_last(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_last(self)

    def is_decl_ptr(self) ->bool:
        """is_type_ptr(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_ptr(self)

    def is_decl_array(self) ->bool:
        """is_type_array(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_array(self)

    def is_decl_func(self) ->bool:
        """is_type_func(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_func(self)

    def is_decl_complex(self) ->bool:
        """is_type_complex(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_complex(self)

    def is_decl_typedef(self) ->bool:
        """is_type_typedef(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_typedef(self)

    def is_decl_sue(self) ->bool:
        """is_type_sue(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_sue(self)

    def is_decl_struct(self) ->bool:
        """is_type_struct(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_struct(self)

    def is_decl_union(self) ->bool:
        """is_type_union(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_union(self)

    def is_decl_udt(self) ->bool:
        """is_type_struni(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_udt(self)

    def is_decl_enum(self) ->bool:
        """is_type_enum(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_enum(self)

    def is_decl_bitfield(self) ->bool:
        """is_type_bitfld(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_bitfield(self)

    def is_decl_int128(self) ->bool:
        """is_type_int128(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_int128(self)

    def is_decl_int64(self) ->bool:
        """is_type_int64(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_int64(self)

    def is_decl_int32(self) ->bool:
        """is_type_int32(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_int32(self)

    def is_decl_int16(self) ->bool:
        """is_type_int16(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_int16(self)

    def is_decl_int(self) ->bool:
        """is_type_int(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_int(self)

    def is_decl_char(self) ->bool:
        """is_type_char(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_char(self)

    def is_decl_uint(self) ->bool:
        """is_type_uint(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_uint(self)

    def is_decl_uchar(self) ->bool:
        """is_type_uchar(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_uchar(self)

    def is_decl_uint16(self) ->bool:
        """is_type_uint16(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_uint16(self)

    def is_decl_uint32(self) ->bool:
        """is_type_uint32(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_uint32(self)

    def is_decl_uint64(self) ->bool:
        """is_type_uint64(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_uint64(self)

    def is_decl_uint128(self) ->bool:
        """is_type_uint128(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_uint128(self)

    def is_decl_ldouble(self) ->bool:
        """is_type_ldouble(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_ldouble(self)

    def is_decl_double(self) ->bool:
        """is_type_double(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_double(self)

    def is_decl_float(self) ->bool:
        """is_type_float(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_float(self)

    def is_decl_tbyte(self) ->bool:
        """is_type_tbyte(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_tbyte(self)

    def is_decl_floating(self) ->bool:
        """is_type_floating(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_floating(self)

    def is_decl_bool(self) ->bool:
        """is_type_bool(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_bool(self)

    def is_decl_paf(self) ->bool:
        """is_type_paf(get_decltype())
"""
        return _ida_typeinf.tinfo_t_is_decl_paf(self)

    def is_well_defined(self) ->bool:
        """!(empty()) && !(is_decl_partial()) && !(is_punknown())
"""
        return _ida_typeinf.tinfo_t_is_well_defined(self)

    def is_const(self) ->bool:
        """is_type_const(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_const(self)

    def is_volatile(self) ->bool:
        """is_type_volatile(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_volatile(self)

    def is_void(self) ->bool:
        """is_type_void(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_void(self)

    def is_partial(self) ->bool:
        """is_type_partial(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_partial(self)

    def is_unknown(self) ->bool:
        """is_type_unknown(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_unknown(self)

    def is_ptr(self) ->bool:
        """is_type_ptr(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_ptr(self)

    def is_array(self) ->bool:
        """is_type_array(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_array(self)

    def is_func(self) ->bool:
        """is_type_func(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_func(self)

    def is_complex(self) ->bool:
        """is_type_complex(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_complex(self)

    def is_struct(self) ->bool:
        """is_type_struct(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_struct(self)

    def is_union(self) ->bool:
        """is_type_union(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_union(self)

    def is_udt(self) ->bool:
        """is_type_struni(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_udt(self)

    def is_enum(self) ->bool:
        """is_type_enum(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_enum(self)

    def is_sue(self) ->bool:
        """is_type_sue(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_sue(self)

    def is_bitfield(self) ->bool:
        """is_type_bitfld(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_bitfield(self)

    def is_int128(self) ->bool:
        """is_type_int128(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_int128(self)

    def is_int64(self) ->bool:
        """is_type_int64(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_int64(self)

    def is_int32(self) ->bool:
        """is_type_int32(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_int32(self)

    def is_int16(self) ->bool:
        """is_type_int16(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_int16(self)

    def is_int(self) ->bool:
        """is_type_int(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_int(self)

    def is_char(self) ->bool:
        """is_type_char(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_char(self)

    def is_uint(self) ->bool:
        """is_type_uint(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_uint(self)

    def is_uchar(self) ->bool:
        """is_type_uchar(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_uchar(self)

    def is_uint16(self) ->bool:
        """is_type_uint16(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_uint16(self)

    def is_uint32(self) ->bool:
        """is_type_uint32(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_uint32(self)

    def is_uint64(self) ->bool:
        """is_type_uint64(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_uint64(self)

    def is_uint128(self) ->bool:
        """is_type_uint128(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_uint128(self)

    def is_ldouble(self) ->bool:
        """is_type_ldouble(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_ldouble(self)

    def is_double(self) ->bool:
        """is_type_double(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_double(self)

    def is_float(self) ->bool:
        """is_type_float(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_float(self)

    def is_tbyte(self) ->bool:
        """is_type_tbyte(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_tbyte(self)

    def is_bool(self) ->bool:
        """is_type_bool(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_bool(self)

    def is_paf(self) ->bool:
        """is_type_paf(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_paf(self)

    def is_ptr_or_array(self) ->bool:
        """is_type_ptr_or_array(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_ptr_or_array(self)

    def is_integral(self) ->bool:
        """is_type_integral(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_integral(self)

    def is_ext_integral(self) ->bool:
        """is_type_ext_integral(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_ext_integral(self)

    def is_floating(self) ->bool:
        """is_type_floating(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_floating(self)

    def is_arithmetic(self) ->bool:
        """is_type_arithmetic(get_realtype())
"""
        return _ida_typeinf.tinfo_t_is_arithmetic(self)

    def is_ext_arithmetic(self) ->bool:
        """is_type_ext_arithmetic(get_realtype()) 
        """
        return _ida_typeinf.tinfo_t_is_ext_arithmetic(self)

    def is_scalar(self) ->bool:
        """Does the type represent a single number?
"""
        return _ida_typeinf.tinfo_t_is_scalar(self)

    def get_ptr_details(self, pi: 'ptr_type_data_t') ->bool:
        """Get the pointer info.
"""
        return _ida_typeinf.tinfo_t_get_ptr_details(self, pi)

    def get_array_details(self, ai: 'array_type_data_t') ->bool:
        """Get the array specific info.
"""
        return _ida_typeinf.tinfo_t_get_array_details(self, ai)

    def get_enum_details(self, ei: 'enum_type_data_t') ->bool:
        """Get the enum specific info.
"""
        return _ida_typeinf.tinfo_t_get_enum_details(self, ei)

    def get_bitfield_details(self, bi: 'bitfield_type_data_t') ->bool:
        """Get the bitfield specific info.
"""
        return _ida_typeinf.tinfo_t_get_bitfield_details(self, bi)

    def get_udt_details(self, udt: 'udt_type_data_t', gtd: 'gtd_udt_t'=
        GTD_CALC_LAYOUT) ->bool:
        """Get the udt specific info.
"""
        return _ida_typeinf.tinfo_t_get_udt_details(self, udt, gtd)

    def get_func_details(self, fi: 'func_type_data_t', gtd: 'gtd_func_t'=
        GTD_CALC_ARGLOCS) ->bool:
        """Get only the function specific info for this tinfo_t.
"""
        return _ida_typeinf.tinfo_t_get_func_details(self, fi, gtd)

    def is_funcptr(self) ->bool:
        """Is this pointer to a function?
"""
        return _ida_typeinf.tinfo_t_is_funcptr(self)

    def is_shifted_ptr(self) ->bool:
        """Is a shifted pointer?
"""
        return _ida_typeinf.tinfo_t_is_shifted_ptr(self)

    def is_varstruct(self) ->bool:
        """Is a variable-size structure?
"""
        return _ida_typeinf.tinfo_t_is_varstruct(self)

    def is_varmember(self) ->bool:
        """Can the type be of a variable struct member? This function checks for: is_array() && array.nelems==0 Such a member can be only the very last member of a structure 
        """
        return _ida_typeinf.tinfo_t_is_varmember(self)

    def get_ptrarr_objsize(self) ->int:
        """BT_PTR & BT_ARRAY: get size of pointed object or array element. On error returns -1
"""
        return _ida_typeinf.tinfo_t_get_ptrarr_objsize(self)

    def get_ptrarr_object(self) ->'tinfo_t':
        """BT_PTR & BT_ARRAY: get the pointed object or array element. If the current type is not a pointer or array, return empty type info. 
        """
        return _ida_typeinf.tinfo_t_get_ptrarr_object(self)

    def get_pointed_object(self) ->'tinfo_t':
        """BT_PTR: get type of pointed object. If the current type is not a pointer, return empty type info. See also get_ptrarr_object() and remove_pointer() 
        """
        return _ida_typeinf.tinfo_t_get_pointed_object(self)

    def is_pvoid(self) ->bool:
        """Is "void *"?. This function does not check the pointer attributes and type modifiers.
"""
        return _ida_typeinf.tinfo_t_is_pvoid(self)

    def is_punknown(self) ->bool:
        """Is "_UNKNOWN *"?. This function does not check the pointer attributes and type modifiers.
"""
        return _ida_typeinf.tinfo_t_is_punknown(self)

    def get_array_element(self) ->'tinfo_t':
        """BT_ARRAY: get type of array element. See also get_ptrarr_object()
"""
        return _ida_typeinf.tinfo_t_get_array_element(self)

    def get_final_element(self) ->'tinfo_t':
        """repeat recursively: if an array, return the type of its element; else return the type itself.
"""
        return _ida_typeinf.tinfo_t_get_final_element(self)

    def get_array_nelems(self) ->int:
        """BT_ARRAY: get number of elements (-1 means error)
"""
        return _ida_typeinf.tinfo_t_get_array_nelems(self)

    def get_nth_arg(self, n: int) ->'tinfo_t':
        """BT_FUNC or BT_PTR BT_FUNC: Get type of n-th arg (-1 means return type, see get_rettype())
"""
        return _ida_typeinf.tinfo_t_get_nth_arg(self, n)

    def get_rettype(self) ->'tinfo_t':
        """BT_FUNC or BT_PTR BT_FUNC: Get the function's return type
"""
        return _ida_typeinf.tinfo_t_get_rettype(self)

    def get_nargs(self) ->int:
        """BT_FUNC or BT_PTR BT_FUNC: Calculate number of arguments (-1 - error)
"""
        return _ida_typeinf.tinfo_t_get_nargs(self)

    def is_user_cc(self) ->bool:
        """is_user_cc(get_cc())
"""
        return _ida_typeinf.tinfo_t_is_user_cc(self)

    def is_vararg_cc(self) ->bool:
        """is_vararg_cc(get_cc())
"""
        return _ida_typeinf.tinfo_t_is_vararg_cc(self)

    def is_purging_cc(self) ->bool:
        """is_purging_cc(get_cc())
"""
        return _ida_typeinf.tinfo_t_is_purging_cc(self)

    def calc_purged_bytes(self) ->int:
        """BT_FUNC: Calculate number of purged bytes
"""
        return _ida_typeinf.tinfo_t_calc_purged_bytes(self)

    def is_high_func(self) ->bool:
        """BT_FUNC: Is high level type?
"""
        return _ida_typeinf.tinfo_t_is_high_func(self)

    def get_methods(self, methods: 'udtmembervec_t') ->bool:
        """BT_COMPLEX: get a list of member functions declared in this udt. 
        
@returns false if no member functions exist"""
        return _ida_typeinf.tinfo_t_get_methods(self, methods)

    def get_bit_buckets(self, buckets: 'range64vec_t') ->bool:
        """::BT_STRUCT: get bit buckets Bit buckets are used to layout bitfields 
        
@returns false if wrong type was passed"""
        return _ida_typeinf.tinfo_t_get_bit_buckets(self, buckets)

    def find_udm(self, *args) ->int:
        """This function has the following signatures:

    0. find_udm(udm: udm_t *, strmem_flags: int) -> int
    1. find_udm(offset: uint64, strmem_flags: int=0) -> int
    2. find_udm(name: str, strmem_flags: int=0) -> int

# 0: find_udm(udm: udm_t *, strmem_flags: int) -> int

BTF_STRUCT,BTF_UNION: Find a udt member.
* at the specified offset (STRMEM_OFFSET)
* with the specified index (STRMEM_INDEX)
* with the specified type (STRMEM_TYPE)
* with the specified name (STRMEM_NAME)



@returns the index of the found member or -1

# 1: find_udm(offset: uint64, strmem_flags: int=0) -> int

BTF_STRUCT,BTF_UNION: Find an udt member at the specified offset 
        
@returns the index of the found member or -1

# 2: find_udm(name: str, strmem_flags: int=0) -> int

BTF_STRUCT,BTF_UNION: Find an udt member by name 
        
@returns the index of the found member or -1
"""
        return _ida_typeinf.tinfo_t_find_udm(self, *args)

    def get_udm(self, *args) ->Union[Tuple[int, 'udm_t'], Tuple[None, None]]:
        """Retrieve a structure/union member with either the specified name
or the specified index, in the specified tinfo_t object.

This function has the following signatures:

    1. get_udm(index: int)
    2. get_udm(name: str)

@param index a member index (1st form)
@param name a member name (2nd form)
@return a tuple (int, udm_t), or (-1, None) if member not found"""
        return _ida_typeinf.tinfo_t_get_udm(self, *args)

    def get_udm_by_offset(self, offset: int):
        """Retrieve a structure/union member with the specified offset,
in the specified tinfo_t object.

@param offset the member offset
@return a tuple (int, udm_t), or (-1, None) if member not found"""
        return _ida_typeinf.tinfo_t_get_udm_by_offset(self, offset)

    def get_udt_nmembers(self) ->int:
        """Get number of udt members. -1-error.
"""
        return _ida_typeinf.tinfo_t_get_udt_nmembers(self)

    def is_empty_udt(self) ->bool:
        """Is an empty struct/union? (has no fields)
"""
        return _ida_typeinf.tinfo_t_is_empty_udt(self)

    def is_small_udt(self) ->bool:
        """Is a small udt? (can fit a register or a pair of registers)
"""
        return _ida_typeinf.tinfo_t_is_small_udt(self)

    def requires_qualifier(self, name: str, offset: 'uint64') ->bool:
        """Requires full qualifier? (name is not unique) 
        
@param name: field name
@param offset: field offset in bits
@returns if the name is not unique, returns true"""
        return _ida_typeinf.tinfo_t_requires_qualifier(self, name, offset)

    def append_covered(self, out: 'rangeset_t', offset: 'uint64'=0) ->bool:
        """Calculate set of covered bytes for the type 
        
@param out: pointer to the output buffer. covered bytes will be appended to it.
@param offset: delta in bytes to add to all calculations. used internally during recurion."""
        return _ida_typeinf.tinfo_t_append_covered(self, out, offset)

    def calc_gaps(self, out: 'rangeset_t') ->bool:
        """Calculate set of padding bytes for the type 
        
@param out: pointer to the output buffer; old buffer contents will be lost."""
        return _ida_typeinf.tinfo_t_calc_gaps(self, out)

    def is_one_fpval(self) ->bool:
        """Floating value or an object consisting of one floating member entirely.
"""
        return _ida_typeinf.tinfo_t_is_one_fpval(self)

    def is_sse_type(self) ->bool:
        """Is a SSE vector type?
"""
        return _ida_typeinf.tinfo_t_is_sse_type(self)

    def is_anonymous_udt(self) ->bool:
        """Is an anonymous struct/union? We assume that types with names are anonymous if the name starts with $ 
        """
        return _ida_typeinf.tinfo_t_is_anonymous_udt(self)

    def is_vftable(self) ->bool:
        """Is a vftable type?
"""
        return _ida_typeinf.tinfo_t_is_vftable(self)

    def has_vftable(self) ->bool:
        """Has a vftable?
"""
        return _ida_typeinf.tinfo_t_has_vftable(self)

    def has_union(self) ->bool:
        """Has a member of type "union"?
"""
        return _ida_typeinf.tinfo_t_has_union(self)

    def get_enum_nmembers(self) ->'size_t':
        """Get number of enum members. 
        
@returns BADSIZE if error"""
        return _ida_typeinf.tinfo_t_get_enum_nmembers(self)

    def is_empty_enum(self) ->bool:
        """Is an empty enum? (has no constants)
"""
        return _ida_typeinf.tinfo_t_is_empty_enum(self)

    def get_enum_base_type(self) ->'type_t':
        """Get enum base type (convert enum to integer type) Returns BT_UNK if failed to convert 
        """
        return _ida_typeinf.tinfo_t_get_enum_base_type(self)

    def is_bitmask_enum(self) ->bool:
        """Is bitmask enum? 
        
@returns true for bitmask enum and false in other cases enum_type_data_t::is_bf()"""
        return _ida_typeinf.tinfo_t_is_bitmask_enum(self)

    def get_enum_radix(self) ->int:
        """Get enum constant radix 
        
@returns radix or 1 for BTE_CHAR enum_type_data_t::get_enum_radix()"""
        return _ida_typeinf.tinfo_t_get_enum_radix(self)

    def get_enum_repr(self, repr: 'value_repr_t') ->'tinfo_code_t':
        """Set the representation of enum members. 
        
@param repr: value_repr_t"""
        return _ida_typeinf.tinfo_t_get_enum_repr(self, repr)

    def get_enum_width(self) ->int:
        """Get enum width 
        
@returns width of enum base type in bytes, 0 - unspecified, or -1 enum_type_data_t::calc_nbytes()"""
        return _ida_typeinf.tinfo_t_get_enum_width(self)

    def calc_enum_mask(self) ->'uint64':
        return _ida_typeinf.tinfo_t_calc_enum_mask(self)

    def get_edm_by_value(self, value: int, bmask: int=DEFMASK64, serial: int=0
        ) ->Tuple[int, 'edm_t']:
        """Retrieve an enumerator with the specified value,
in the specified tinfo_t object.

@param value the enumerator value
@return a tuple (int, edm_t), or (-1, None) if member not found"""
        args = value, bmask, serial
        return _ida_typeinf.tinfo_t_get_edm_by_value(self, *args)

    def get_edm_tid(self, idx: 'size_t') ->'tid_t':
        """Get enum member TID 
        
@param idx: enum member index
@returns tid or BADADDR The tid is used to collect xrefs to the member, it can be passed to xref-related functions instead of the address."""
        return _ida_typeinf.tinfo_t_get_edm_tid(self, idx)

    def get_onemember_type(self) ->'tinfo_t':
        """For objects consisting of one member entirely: return type of the member.
"""
        return _ida_typeinf.tinfo_t_get_onemember_type(self)

    def get_innermost_udm(self, bitoffset: 'uint64') ->'tinfo_t':
        """Get the innermost member at the given offset 
        
@param bitoffset: bit offset into the structure
@retval udt: with the innermost member
@retval empty: type if it is not a struct type or OFFSET could not be found"""
        return _ida_typeinf.tinfo_t_get_innermost_udm(self, bitoffset)

    def get_innermost_member_type(self, bitoffset: 'uint64') ->'tinfo_t':
        """Get the innermost member type at the given offset 
        
@param bitoffset: bit offset into the structure
@retval the: innermost member type"""
        return _ida_typeinf.tinfo_t_get_innermost_member_type(self, bitoffset)

    def calc_score(self) ->int:
        """Calculate the type score (the higher - the nicer is the type)
"""
        return _ida_typeinf.tinfo_t_calc_score(self)

    def _print(self, name: str=None, prtype_flags: int=0, indent: int=0,
        cmtindent: int=0, prefix: str=None, cmt: str=None) ->bool:
        return _ida_typeinf.tinfo_t__print(self, name, prtype_flags, indent,
            cmtindent, prefix, cmt)

    def dstr(self) ->str:
        """Function to facilitate debugging.
"""
        return _ida_typeinf.tinfo_t_dstr(self)

    def get_attrs(self, tav: 'type_attrs_t', all_attrs: bool=False) ->bool:
        """Get type attributes (all_attrs: include attributes of referenced types, if any)
"""
        return _ida_typeinf.tinfo_t_get_attrs(self, tav, all_attrs)

    def set_attrs(self, tav: 'type_attrs_t') ->bool:
        """Set type attributes. If necessary, a new typid will be created. this function modifies tav! (returns old attributes, if any) 
        
@returns false: bad attributes"""
        return _ida_typeinf.tinfo_t_set_attrs(self, tav)

    def set_attr(self, ta: 'type_attr_t', may_overwrite: bool=True) ->bool:
        """Set a type attribute. If necessary, a new typid will be created.
"""
        return _ida_typeinf.tinfo_t_set_attr(self, ta, may_overwrite)

    def del_attrs(self) ->None:
        """Del all type attributes. typerefs cannot be modified by this function.
"""
        return _ida_typeinf.tinfo_t_del_attrs(self)

    def del_attr(self, key: str, make_copy: bool=True) ->bool:
        """Del a type attribute. typerefs cannot be modified by this function.
"""
        return _ida_typeinf.tinfo_t_del_attr(self, key, make_copy)

    def create_simple_type(self, decl_type: 'type_t') ->bool:
        return _ida_typeinf.tinfo_t_create_simple_type(self, decl_type)

    def create_ptr(self, *args) ->bool:
        return _ida_typeinf.tinfo_t_create_ptr(self, *args)

    def create_array(self, *args) ->bool:
        return _ida_typeinf.tinfo_t_create_array(self, *args)

    def create_typedef(self, *args) ->None:
        return _ida_typeinf.tinfo_t_create_typedef(self, *args)

    def create_bitfield(self, *args) ->bool:
        return _ida_typeinf.tinfo_t_create_bitfield(self, *args)

    def parse(self, decl: str, til: 'til_t'=None, pt_flags: int=0) ->bool:
        """Convenience function to parse a string with a type declaration 
        
@param decl: a type declaration
@param til: type library to use
@param pt_flags: combination of Type parsing flags bits"""
        return _ida_typeinf.tinfo_t_parse(self, decl, til, pt_flags)

    def create_udt(self, *args) ->bool:
        """Create an empty structure/union.
"""
        return _ida_typeinf.tinfo_t_create_udt(self, *args)

    def create_enum(self, *args) ->bool:
        """Create an empty enum.
"""
        return _ida_typeinf.tinfo_t_create_enum(self, *args)

    def create_func(self, *args) ->bool:
        return _ida_typeinf.tinfo_t_create_func(self, *args)

    def get_udm_by_tid(self, udm: 'udm_t', tid: 'tid_t') ->'ssize_t':
        return _ida_typeinf.tinfo_t_get_udm_by_tid(self, udm, tid)

    def get_edm_by_tid(self, edm: 'edm_t', tid: 'tid_t') ->'ssize_t':
        return _ida_typeinf.tinfo_t_get_edm_by_tid(self, edm, tid)

    def get_type_by_tid(self, tid: 'tid_t') ->bool:
        return _ida_typeinf.tinfo_t_get_type_by_tid(self, tid)

    def get_by_edm_name(self, mname: str, til: 'til_t'=None) ->'ssize_t':
        """Retrieve enum tinfo using enum member name 
        
@param mname: enum type member name
@param til: type library
@returns member index, otherwise returns -1. If the function fails, THIS object becomes empty."""
        return _ida_typeinf.tinfo_t_get_by_edm_name(self, mname, til)

    def set_named_type(self, til: 'til_t', name: str, ntf_flags: int=0
        ) ->'tinfo_code_t':
        return _ida_typeinf.tinfo_t_set_named_type(self, til, name, ntf_flags)

    def set_symbol_type(self, til: 'til_t', name: str, ntf_flags: int=0
        ) ->'tinfo_code_t':
        return _ida_typeinf.tinfo_t_set_symbol_type(self, til, name, ntf_flags)

    def set_numbered_type(self, til: 'til_t', ord: int, ntf_flags: int=0,
        name: str=None) ->'tinfo_code_t':
        return _ida_typeinf.tinfo_t_set_numbered_type(self, til, ord,
            ntf_flags, name)

    def save_type(self, *args) ->'tinfo_code_t':
        return _ida_typeinf.tinfo_t_save_type(self, *args)

    def copy_type(self, *args) ->'tinfo_code_t':
        return _ida_typeinf.tinfo_t_copy_type(self, *args)

    def create_forward_decl(self, til: 'til_t', decl_type: 'type_t', name:
        str, ntf_flags: int=0) ->'tinfo_code_t':
        """Create a forward declaration. decl_type: BTF_STRUCT, BTF_UNION, or BTF_ENUM 
        """
        return _ida_typeinf.tinfo_t_create_forward_decl(self, til,
            decl_type, name, ntf_flags)

    @staticmethod
    def get_stock(id: 'stock_type_id_t') ->'tinfo_t':
        """Get stock type information. This function can be used to get tinfo_t for some common types. The same tinfo_t will be returned for the same id, thus saving memory and increasing the speed Please note that retrieving the STI_SIZE_T or STI_SSIZE_T stock type, will also have the side-effect of adding that type to the 'idati' TIL, under the well-known name 'size_t' or 'ssize_t' (respectively). The same is valid for STI_COMPLEX64 and STI_COMPLEX64 stock types with names 'complex64_t' and 'complex128_t' (respectively). 
        """
        return _ida_typeinf.tinfo_t_get_stock(id)

    def convert_array_to_ptr(self) ->bool:
        """Convert an array into a pointer. type[] => type * 
        """
        return _ida_typeinf.tinfo_t_convert_array_to_ptr(self)

    def remove_ptr_or_array(self) ->bool:
        """Replace the current type with the ptr obj or array element. This function performs one of the following conversions:
* type[] => type
* type* => type If the conversion is performed successfully, return true 


        """
        return _ida_typeinf.tinfo_t_remove_ptr_or_array(self)

    def read_bitfield_value(self, v: 'uint64', bitoff: int) ->'uint64':
        return _ida_typeinf.tinfo_t_read_bitfield_value(self, v, bitoff)

    def write_bitfield_value(self, dst: 'uint64', v: 'uint64', bitoff: int
        ) ->'uint64':
        return _ida_typeinf.tinfo_t_write_bitfield_value(self, dst, v, bitoff)

    def get_modifiers(self) ->'type_t':
        return _ida_typeinf.tinfo_t_get_modifiers(self)

    def set_modifiers(self, mod: 'type_t') ->None:
        return _ida_typeinf.tinfo_t_set_modifiers(self, mod)

    def set_const(self) ->None:
        return _ida_typeinf.tinfo_t_set_const(self)

    def set_volatile(self) ->None:
        return _ida_typeinf.tinfo_t_set_volatile(self)

    def clr_decl_const_volatile(self) ->None:
        return _ida_typeinf.tinfo_t_clr_decl_const_volatile(self)

    def clr_const(self) ->bool:
        return _ida_typeinf.tinfo_t_clr_const(self)

    def clr_volatile(self) ->bool:
        return _ida_typeinf.tinfo_t_clr_volatile(self)

    def clr_const_volatile(self) ->bool:
        return _ida_typeinf.tinfo_t_clr_const_volatile(self)

    def set_type_alignment(self, declalign: 'uchar', etf_flags: 'uint'=0
        ) ->'tinfo_code_t':
        """Set type alignment.
"""
        return _ida_typeinf.tinfo_t_set_type_alignment(self, declalign,
            etf_flags)

    def set_declalign(self, declalign: 'uchar') ->bool:
        return _ida_typeinf.tinfo_t_set_declalign(self, declalign)

    def change_sign(self, sign: 'type_sign_t') ->bool:
        """Change the type sign. Works only for the types that may have sign.
"""
        return _ida_typeinf.tinfo_t_change_sign(self, sign)

    def calc_udt_aligns(self, sudt_flags: int=4) ->bool:
        """Calculate the udt alignments using the field offsets/sizes and the total udt size This function does not work on typerefs 
        """
        return _ida_typeinf.tinfo_t_calc_udt_aligns(self, sudt_flags)

    def set_methods(self, methods: 'udtmembervec_t') ->bool:
        """BT_COMPLEX: set the list of member functions. This function consumes 'methods' (makes it empty). 
        
@returns false if this type is not a udt, or if the given list is empty"""
        return _ida_typeinf.tinfo_t_set_methods(self, methods)

    def set_type_cmt(self, cmt: str, is_regcmt: bool=False, etf_flags: 'uint'=0
        ) ->'tinfo_code_t':
        """Set type comment This function works only for non-trivial types 
        """
        return _ida_typeinf.tinfo_t_set_type_cmt(self, cmt, is_regcmt,
            etf_flags)

    def get_alias_target(self) ->int:
        """Get type alias If the type has no alias, return 0. 
        """
        return _ida_typeinf.tinfo_t_get_alias_target(self)

    def is_aliased(self) ->bool:
        return _ida_typeinf.tinfo_t_is_aliased(self)

    def set_type_alias(self, dest_ord: int) ->bool:
        """Set type alias Redirects all references to source type to the destination type. This is equivalent to instantaneous replacement all references to srctype by dsttype. 
        """
        return _ida_typeinf.tinfo_t_set_type_alias(self, dest_ord)

    def set_udt_alignment(self, sda: int, etf_flags: 'uint'=0
        ) ->'tinfo_code_t':
        """Set declared structure alignment (sda) This alignment supersedes the alignment returned by get_declalign() and is really used when calculating the struct layout. However, the effective structure alignment may differ from `sda` because of packing. The type editing functions (they accept etf_flags) may overwrite this attribute. 
        """
        return _ida_typeinf.tinfo_t_set_udt_alignment(self, sda, etf_flags)

    def set_udt_pack(self, pack: int, etf_flags: 'uint'=0) ->'tinfo_code_t':
        """Set structure packing. The value controls how little a structure member alignment can be. Example: if pack=1, then it is possible to align a double to a byte. __attribute__((aligned(1))) double x; However, if pack=3, a double will be aligned to 8 (2**3) even if requested to be aligned to a byte. pack==0 will have the same effect. The type editing functions (they accept etf_flags) may overwrite this attribute. 
        """
        return _ida_typeinf.tinfo_t_set_udt_pack(self, pack, etf_flags)

    def get_udm_tid(self, idx: 'size_t') ->'tid_t':
        """Get udt member TID 
        
@param idx: the index of udt the member
@returns tid or BADADDR The tid is used to collect xrefs to the member, it can be passed to xref-related functions instead of the address."""
        return _ida_typeinf.tinfo_t_get_udm_tid(self, idx)

    def add_udm(self, *args):
        """Add a member to the current structure/union.

When creating a new structure/union from scratch, you might
want to first call `create_udt()`

This method has the following signatures:

    1. add_udm(udm: udm_t, etf_flags: int = 0, times: int = 1, idx: int = -1)
    2. add_udm(name: str, type: type_t | tinfo_t | str, offset: int = 0, etf_flags: int = 0, times: int = 1, idx: int = -1)

In the 2nd form, the 'type' descriptor, can be one of:

* type_t: if the type is simple (integral/floating/bool). E.g., `BTF_INT`
* tinfo_t: can handle more complex types (structures, pointers, arrays, ...)
* str: a C type declaration

If an input argument is incorrect, the constructor may raise an exception

@param udm       The member, fully initialized (1st form)
@param name      Member name - must not be empty
@param type      Member type
@param offset    the member offset in bits. It is the caller's responsibility
       to specify correct offsets.
@param etf_flags an OR'ed combination of ETF_ flags
@param times     how many times to add the new member
@param idx       the index in the udm array where the new udm should be placed.
                 If the specified index cannot be honored because it would spoil
                 the udm sorting order, it is silently ignored."""
        val = _ida_typeinf.tinfo_t_add_udm(self, *args)
        if val != 0:
            raise ValueError('Invalid input data: %s' % tinfo_errstr(val))
        return val

    def del_udm(self, index: 'size_t', etf_flags: 'uint'=0) ->'tinfo_code_t':
        """Delete a structure/union member.
"""
        return _ida_typeinf.tinfo_t_del_udm(self, index, etf_flags)

    def del_udms(self, idx1: 'size_t', idx2: 'size_t', etf_flags: 'uint'=0
        ) ->'tinfo_code_t':
        """Delete structure/union members in the range [idx1, idx2)
"""
        return _ida_typeinf.tinfo_t_del_udms(self, idx1, idx2, etf_flags)

    def rename_udm(self, index: 'size_t', name: str, etf_flags: 'uint'=0
        ) ->'tinfo_code_t':
        """Rename a structure/union member. The new name must be unique. 
        """
        return _ida_typeinf.tinfo_t_rename_udm(self, index, name, etf_flags)

    def set_udm_type(self, index: 'size_t', tif: 'tinfo_t', etf_flags:
        'uint'=0, repr: 'value_repr_t'=None) ->'tinfo_code_t':
        """Set type of a structure/union member. 
        
@param index: member index in the udm array
@param tif: new type for the member
@param etf_flags: etf_flag_t
@param repr: new representation for the member (optional)
@returns tinfo_code_t"""
        return _ida_typeinf.tinfo_t_set_udm_type(self, index, tif,
            etf_flags, repr)

    def set_udm_cmt(self, index: 'size_t', cmt: str, is_regcmt: bool=False,
        etf_flags: 'uint'=0) ->'tinfo_code_t':
        """Set a comment for a structure/union member. A member may have just one comment, and it is either repeatable or regular. 
        """
        return _ida_typeinf.tinfo_t_set_udm_cmt(self, index, cmt, is_regcmt,
            etf_flags)

    def set_udm_repr(self, index: 'size_t', repr: 'value_repr_t', etf_flags:
        'uint'=0) ->'tinfo_code_t':
        """Set the representation of a structure/union member.
"""
        return _ida_typeinf.tinfo_t_set_udm_repr(self, index, repr, etf_flags)

    def is_udm_by_til(self, idx: 'size_t') ->bool:
        """Was the member created due to the type system 
        
@param idx: index of the member"""
        return _ida_typeinf.tinfo_t_is_udm_by_til(self, idx)

    def set_udm_by_til(self, idx: 'size_t', on: bool=True, etf_flags: 'uint'=0
        ) ->'tinfo_code_t':
        """The member is created due to the type system 
        
@param idx: index of the member
@param etf_flags: etf_flag_t"""
        return _ida_typeinf.tinfo_t_set_udm_by_til(self, idx, on, etf_flags)

    def set_fixed_struct(self, on: bool=True) ->'tinfo_code_t':
        """Declare struct member offsets as fixed. For such structures, IDA will not recalculate the member offsets. If a member does not fit into its place anymore, it will be deleted. This function works only with structures (not unions). 
        """
        return _ida_typeinf.tinfo_t_set_fixed_struct(self, on)

    def set_struct_size(self, new_size: 'size_t') ->'tinfo_code_t':
        """Explicitly specify the struct size. This function works only with fixed structures. The new struct size can be equal or higher the unpadded struct size (IOW, all existing members should fit into the specified size). 
        
@param new_size: new structure size in bytes"""
        return _ida_typeinf.tinfo_t_set_struct_size(self, new_size)

    def is_fixed_struct(self) ->bool:
        """Is a structure with fixed offsets?
"""
        return _ida_typeinf.tinfo_t_is_fixed_struct(self)

    def expand_udt(self, idx: 'size_t', delta: 'adiff_t', etf_flags: 'uint'=0
        ) ->'tinfo_code_t':
        """Expand/shrink a structure by adding/removing a gap before the specified member.
For regular structures, either the gap can be accommodated by aligning the next member with an alignment directive, or an explicit "gap" member will be inserted. Also note that it is impossible to add a gap at the end of a regular structure.
When it comes to fixed-layout structures, there is no need to either add new "gap" members or align existing members, since all members have a fixed offset. It is possible to add a gap at the end of a fixed-layout structure, by passing `-1` as index.

@param idx: index of the member
@param delta: number of bytes to add or remove
@param etf_flags: etf_flag_t"""
        return _ida_typeinf.tinfo_t_expand_udt(self, idx, delta, etf_flags)

    def get_func_frame(self, pfn: 'func_t const *') ->bool:
        """Create a tinfo_t object for the function frame 
        
@param pfn: function"""
        return _ida_typeinf.tinfo_t_get_func_frame(self, pfn)

    def is_frame(self) ->bool:
        """Is a function frame?
"""
        return _ida_typeinf.tinfo_t_is_frame(self)

    def get_frame_func(self) ->ida_idaapi.ea_t:
        """Get function address for the frame.
"""
        return _ida_typeinf.tinfo_t_get_frame_func(self)

    def set_enum_width(self, nbytes: int, etf_flags: 'uint'=0
        ) ->'tinfo_code_t':
        """Set the width of enum base type 
        
@param nbytes: width of enum base type, allowed values: 0 (unspecified),1,2,4,8,16,32,64
@param etf_flags: etf_flag_t"""
        return _ida_typeinf.tinfo_t_set_enum_width(self, nbytes, etf_flags)

    def set_enum_sign(self, sign: 'type_sign_t', etf_flags: 'uint'=0
        ) ->'tinfo_code_t':
        """Set enum sign 
        
@param sign: type_sign_t
@param etf_flags: etf_flag_t"""
        return _ida_typeinf.tinfo_t_set_enum_sign(self, sign, etf_flags)
    ENUMBM_OFF = _ida_typeinf.tinfo_t_ENUMBM_OFF
    """convert to ordinal enum
"""
    ENUMBM_ON = _ida_typeinf.tinfo_t_ENUMBM_ON
    """convert to bitmask enum
"""
    ENUMBM_AUTO = _ida_typeinf.tinfo_t_ENUMBM_AUTO
    """convert to bitmask if the outcome is nice and useful
"""

    def set_enum_is_bitmask(self, *args) ->'tinfo_code_t':
        return _ida_typeinf.tinfo_t_set_enum_is_bitmask(self, *args)

    def set_enum_repr(self, repr: 'value_repr_t', etf_flags: 'uint'=0
        ) ->'tinfo_code_t':
        """Set the representation of enum members. 
        
@param repr: value_repr_t
@param etf_flags: etf_flag_t"""
        return _ida_typeinf.tinfo_t_set_enum_repr(self, repr, etf_flags)

    def set_enum_radix(self, radix: int, sign: bool, etf_flags: 'uint'=0
        ) ->'tinfo_code_t':
        """Set enum radix to display constants 
        
@param radix: radix 2, 4, 8, 16, with the special case 1 to display as character
@param sign: display as signed or unsigned
@param etf_flags: etf_flag_t"""
        return _ida_typeinf.tinfo_t_set_enum_radix(self, radix, sign, etf_flags
            )

    def add_edm(self, *args):
        """Add an enumerator to the current enumeration.

When creating a new enumeration from scratch, you might
want to first call `create_enum()`

This method has the following signatures:

    1. add_edm(edm: edm_t, bmask: int = -1, etf_flags: int = 0, idx: int = -1)
    2. add_edm(name: str, value: int, bmask: int = -1, etf_flags: int = 0, idx: int = -1)

If an input argument is incorrect, the constructor may raise an exception

@param edm       The member, fully initialized (1st form)
@param name      Enumerator name - must not be empty
@param value     Enumerator value
@param bmask     A bitmask to which the enumerator belongs
@param etf_flags an OR'ed combination of ETF_ flags
@param idx       the index in the edm array where the new udm should be placed.
                 If the specified index cannot be honored because it would spoil
                 the edm sorting order, it is silently ignored."""
        val = _ida_typeinf.tinfo_t_add_edm(self, *args)
        if val != 0:
            raise ValueError('Invalid input data: %s' % tinfo_errstr(val))
        return val

    def del_edms(self, idx1: 'size_t', idx2: 'size_t', etf_flags: 'uint'=0
        ) ->'tinfo_code_t':
        """Delete enum members 
        
@param idx1: index in edmvec_t
@param idx2: index in edmvec_t or size_t(-1)
@param etf_flags: etf_flag_t Delete enum members in [idx1, idx2)"""
        return _ida_typeinf.tinfo_t_del_edms(self, idx1, idx2, etf_flags)

    def del_edm(self, *args):
        """Delete an enumerator with the specified name
or the specified index, in the specified tinfo_t object.

This method has the following signatures:

    1. del_edm(name: str) -> int
    2. del_edm(index: int) -> int

@param name an enumerator name (1st form)
@param index an enumerator index (2nd form)
@return TERR_OK in case of success, or another TERR_* value in case of error"""
        return _ida_typeinf.tinfo_t_del_edm(self, *args)

    def del_edm_by_value(self, value: int, etf_flags: int=0, bmask: int=
        DEFMASK64, serial: int=0):
        """Delete an enumerator with the specified value,
in the specified tinfo_t object.

@param value the enumerator value
@return TERR_OK in case of success, or another TERR_* value in case of error"""
        args = value, etf_flags, bmask, serial
        return _ida_typeinf.tinfo_t_del_edm_by_value(self, *args)

    def rename_edm(self, idx: 'size_t', name: str, etf_flags: 'uint'=0
        ) ->'tinfo_code_t':
        """Rename a enum member 
        
@param idx: index in edmvec_t
@param name: new name
@param etf_flags: etf_flag_t ETF_FORCENAME may be used in case of TERR_ALIEN_NAME"""
        return _ida_typeinf.tinfo_t_rename_edm(self, idx, name, etf_flags)

    def set_edm_cmt(self, idx: 'size_t', cmt: str, etf_flags: 'uint'=0
        ) ->'tinfo_code_t':
        """Set a comment for an enum member. Such comments are always considered as repeatable. 
        
@param idx: index in edmvec_t
@param cmt: comment
@param etf_flags: etf_flag_t"""
        return _ida_typeinf.tinfo_t_set_edm_cmt(self, idx, cmt, etf_flags)

    def edit_edm(self, *args) ->'tinfo_code_t':
        """Change constant value and/or bitmask 
        
@param idx: index in edmvec_t
@param value: old or new value
@param bmask: old or new bitmask
@param etf_flags: etf_flag_t"""
        return _ida_typeinf.tinfo_t_edit_edm(self, *args)

    def rename_funcarg(self, index: 'size_t', name: str, etf_flags: 'uint'=0
        ) ->'tinfo_code_t':
        """Rename a function argument. The new name must be unique. 
        
@param index: argument index in the function array
@param name: new name
@param etf_flags: etf_flag_t"""
        return _ida_typeinf.tinfo_t_rename_funcarg(self, index, name, etf_flags
            )

    def set_funcarg_type(self, index: 'size_t', tif: 'tinfo_t', etf_flags:
        'uint'=0) ->'tinfo_code_t':
        """Set type of a function argument. 
        
@param index: argument index in the function array
@param tif: new type for the argument
@param etf_flags: etf_flag_t
@returns tinfo_code_t"""
        return _ida_typeinf.tinfo_t_set_funcarg_type(self, index, tif,
            etf_flags)

    def set_func_rettype(self, tif: 'tinfo_t', etf_flags: 'uint'=0
        ) ->'tinfo_code_t':
        """Set function return type . 
        
@param tif: new type for the return type
@param etf_flags: etf_flag_t
@returns tinfo_code_t"""
        return _ida_typeinf.tinfo_t_set_func_rettype(self, tif, etf_flags)

    def del_funcargs(self, idx1: 'size_t', idx2: 'size_t', etf_flags: 'uint'=0
        ) ->'tinfo_code_t':
        """Delete function arguments 
        
@param idx1: index in funcargvec_t
@param idx2: index in funcargvec_t or size_t(-1)
@param etf_flags: etf_flag_t Delete function arguments in [idx1, idx2)"""
        return _ida_typeinf.tinfo_t_del_funcargs(self, idx1, idx2, etf_flags)

    def del_funcarg(self, idx: 'size_t', etf_flags: 'uint'=0) ->'tinfo_code_t':
        return _ida_typeinf.tinfo_t_del_funcarg(self, idx, etf_flags)

    def add_funcarg(self, farg: 'funcarg_t', etf_flags: 'uint'=0, idx:
        'ssize_t'=-1) ->'tinfo_code_t':
        """Add a function argument. 
        
@param farg: argument to add
@param etf_flags: type changing flags flags
@param idx: the index in the funcarg array where the new funcarg should be placed. if the specified index cannot be honored because it would spoil the funcarg sorting order, it is silently ignored."""
        return _ida_typeinf.tinfo_t_add_funcarg(self, farg, etf_flags, idx)

    def set_func_cc(self, cc: 'cm_t', etf_flags: 'uint'=0) ->'tinfo_code_t':
        """Set function calling convention.
"""
        return _ida_typeinf.tinfo_t_set_func_cc(self, cc, etf_flags)

    def set_funcarg_loc(self, index: 'size_t', argloc: 'argloc_t',
        etf_flags: 'uint'=0) ->'tinfo_code_t':
        """Set location of a function argument. 
        
@param index: argument index in the function array
@param argloc: new location for the argument
@param etf_flags: etf_flag_t
@returns tinfo_code_t"""
        return _ida_typeinf.tinfo_t_set_funcarg_loc(self, index, argloc,
            etf_flags)

    def set_func_retloc(self, argloc: 'argloc_t', etf_flags: 'uint'=0
        ) ->'tinfo_code_t':
        """Set location of function return value. 
        
@param argloc: new location for the return value
@param etf_flags: etf_flag_t
@returns tinfo_code_t"""
        return _ida_typeinf.tinfo_t_set_func_retloc(self, argloc, etf_flags)

    def __eq__(self, r: 'tinfo_t') ->bool:
        return _ida_typeinf.tinfo_t___eq__(self, r)

    def __ne__(self, r: 'tinfo_t') ->bool:
        return _ida_typeinf.tinfo_t___ne__(self, r)

    def __lt__(self, r: 'tinfo_t') ->bool:
        return _ida_typeinf.tinfo_t___lt__(self, r)

    def __gt__(self, r: 'tinfo_t') ->bool:
        return _ida_typeinf.tinfo_t___gt__(self, r)

    def __le__(self, r: 'tinfo_t') ->bool:
        return _ida_typeinf.tinfo_t___le__(self, r)

    def __ge__(self, r: 'tinfo_t') ->bool:
        return _ida_typeinf.tinfo_t___ge__(self, r)

    def compare(self, r: 'tinfo_t') ->int:
        return _ida_typeinf.tinfo_t_compare(self, r)

    def compare_with(self, r: 'tinfo_t', tcflags: int=0) ->bool:
        """Compare two types, based on given flags (see tinfo_t comparison flags)
"""
        return _ida_typeinf.tinfo_t_compare_with(self, r, tcflags)

    def equals_to(self, r: 'tinfo_t') ->bool:
        return _ida_typeinf.tinfo_t_equals_to(self, r)

    def is_castable_to(self, target: 'tinfo_t') ->bool:
        return _ida_typeinf.tinfo_t_is_castable_to(self, target)

    def is_manually_castable_to(self, target: 'tinfo_t') ->bool:
        return _ida_typeinf.tinfo_t_is_manually_castable_to(self, target)

    def serialize(self, *args) ->'PyObject *':
        """Serialize tinfo_t object into a type string.
"""
        return _ida_typeinf.tinfo_t_serialize(self, *args)

    def deserialize(self, *args) ->bool:
        """This function has the following signatures:

    0. deserialize(til: const til_t *, ptype: const type_t **, pfields: const p_list **=nullptr, pfldcmts: const p_list **=nullptr, cmt: str=nullptr) -> bool
    1. deserialize(til: const til_t *, ptype: const qtype *, pfields: const qtype *=nullptr, pfldcmts: const qtype *=nullptr, cmt: str=nullptr) -> bool

# 0: deserialize(til: const til_t *, ptype: const type_t **, pfields: const p_list **=nullptr, pfldcmts: const p_list **=nullptr, cmt: str=nullptr) -> bool

Deserialize a type string into a tinfo_t object.


# 1: deserialize(til: const til_t *, ptype: const qtype *, pfields: const qtype *=nullptr, pfldcmts: const qtype *=nullptr, cmt: str=nullptr) -> bool

Deserialize a type string into a tinfo_t object.

"""
        return _ida_typeinf.tinfo_t_deserialize(self, *args)

    def get_stkvar(self, insn: 'insn_t const &', x: 'op_t const', v: int
        ) ->'ssize_t':
        """Retrieve frame tinfo for a stack variable 
        
@param insn: the instruction
@param x: reference to instruction operand, may be nullptr
@param v: immediate value in the operand (usually x.addr)
@returns returns the member index, otherwise returns -1. if the function fails, THIS object becomes empty."""
        return _ida_typeinf.tinfo_t_get_stkvar(self, insn, x, v)

    def copy(self) ->'tinfo_t':
        return _ida_typeinf.tinfo_t_copy(self)

    def __str__(self) ->str:
        return _ida_typeinf.tinfo_t___str__(self)
    __swig_destroy__ = _ida_typeinf.delete_tinfo_t

    def get_attr(self, key: str, all_attrs: bool=True) ->'PyObject *':
        """Get a type attribute.
"""
        return _ida_typeinf.tinfo_t_get_attr(self, key, all_attrs)

    def get_edm(self, *args) ->Tuple[int, 'edm_t']:
        """Retrieve an enumerator with either the specified name
or the specified index, in the specified tinfo_t object.

This function has the following signatures:

    1. get_edm(index: int)
    2. get_edm(name: str)

@param index an enumerator index (1st form).
@param name an enumerator name (2nd form).
@return a tuple (int, edm_t), or (-1, None) if member not found"""
        return _ida_typeinf.tinfo_t_get_edm(self, *args)

    def find_edm(self, *args) ->'ssize_t':
        return _ida_typeinf.tinfo_t_find_edm(self, *args)

    def __repr__(self):
        if self.present():
            til = self.get_til()
            if til == get_idati():
                name = self.get_type_name()
                if name:
                    return (
                        f'{self.__class__.__module__}.{self.__class__.__name__}(get_idati(), "{name}")'
                        )
                else:
                    ord = self.get_ordinal()
                    if ord > 0:
                        return (
                            f'{self.__class__.__module__}.{self.__class__.__name__}(get_idati(), {ord})'
                            )
            return (
                f'{self.__class__.__module__}.{self.__class__.__name__}("""{self._print()}""")'
                )
        return f'{self.__class__.__module__}.{self.__class__.__name__}()'

    def iter_struct(self):
        """Iterate on the members composing this structure.

Example:

    til = ida_typeinf.get_idati()
    tif = til.get_named_type("my_struc")
    for udm in tif.iter_struct():
        print(f"{udm.name} at bit offset {udm.offset}")

Will raise an exception if this type is not a structure.

@return a udm_t-producing generator"""
        udt = udt_type_data_t()
        if not self.is_struct() or not self.get_udt_details(udt):
            raise TypeError('Type is not a structure')
        for udm in udt:
            yield udm_t(udm)

    def iter_union(self):
        """Iterate on the members composing this union.

Example:

    til = ida_typeinf.get_idati()
    tif = til.get_named_type("my_union")
    for udm in tif.iter_union():
        print(f"{udm.name}, with type {udm.type}")

Will raise an exception if this type is not a union.

@return a udm_t-producing generator"""
        udt = udt_type_data_t()
        if not self.is_union() or not self.get_udt_details(udt):
            raise TypeError('Type is not a union')
        for udm in udt:
            yield udm_t(udm)

    def iter_udt(self):
        """Iterate on the members composing this structure, or union.

Example:

    til = ida_typeinf.get_idati()
    tif = til.get_named_type("my_type")
    for udm in tif.iter_udt():
        print(f"{udm.name} at bit offset {udm.offset} with type {udm.type}")

Will raise an exception if this type is not a structure, or union

@return a udm_t-producing generator"""
        udt = udt_type_data_t()
        if not self.is_udt() or not self.get_udt_details(udt):
            raise TypeError('Type is not a structure or union')
        for udm in udt:
            yield udm_t(udm)

    def iter_enum(self):
        """Iterate on the members composing this enumeration.

Example:

    til = ida_typeinf.get_idati()
    tif = til.get_named_type("my_enum")
    for edm in tif.iter_enum():
        print(f"{edm.name} = {edm.value}")

Will raise an exception if this type is not an enumeration

@return a edm_t-producing generator"""
        edt = enum_type_data_t()
        if not self.is_enum() or not self.get_enum_details(edt):
            raise TypeError('Type is not a structure')
        for edm in edt:
            yield edm_t(edm)

    def iter_func(self):
        """Iterate on the arguments contained in this function prototype

Example:

    address = ...
    func = ida_funcs.get_func(address)
    func_type = func.prototype
    for arg in func_type.iter_func():
        print(f"{arg.name}, of type {arg.type}")

Will raise an exception if this type is not a function

@return a funcarg_t-producing generator"""
        fdt = func_type_data_t()
        if not self.is_func() or not self.get_func_details(fdt):
            raise TypeError('Type is not a function')
        for arg in fdt:
            yield funcarg_t(arg)
    get_edm_by_name = get_by_edm_name


_ida_typeinf.tinfo_t_swigregister(tinfo_t)
COMP_MASK = cvar.COMP_MASK
COMP_UNK = cvar.COMP_UNK
"""Unknown.
"""
COMP_MS = cvar.COMP_MS
"""Visual C++.
"""
COMP_BC = cvar.COMP_BC
"""Borland C++.
"""
COMP_WATCOM = cvar.COMP_WATCOM
"""Watcom C++.
"""
COMP_GNU = cvar.COMP_GNU
"""GNU C++.
"""
COMP_VISAGE = cvar.COMP_VISAGE
"""Visual Age C++.
"""
COMP_BP = cvar.COMP_BP
"""Delphi.
"""
COMP_UNSURE = cvar.COMP_UNSURE
"""uncertain compiler id
"""
BADSIZE = cvar.BADSIZE
"""bad type size
"""
FIRST_NONTRIVIAL_TYPID = cvar.FIRST_NONTRIVIAL_TYPID
"""Denotes the first bit describing a nontrivial type.
"""
TYPID_ISREF = cvar.TYPID_ISREF
"""Identifies that a type that is a typeref.
"""
TYPID_SHIFT = cvar.TYPID_SHIFT
"""First type detail bit.
"""


def remove_pointer(tif: 'tinfo_t') ->'tinfo_t':
    """BT_PTR: If the current type is a pointer, return the pointed object. If the current type is not a pointer, return the current type. See also get_ptrarr_object() and get_pointed_object() 
        """
    return _ida_typeinf.remove_pointer(tif)


STRMEM_MASK = _ida_typeinf.STRMEM_MASK
STRMEM_OFFSET = _ida_typeinf.STRMEM_OFFSET
"""get member by offset
* in: udm->offset - is a member offset in bits 


        """
STRMEM_INDEX = _ida_typeinf.STRMEM_INDEX
"""get member by number
* in: udm->offset - is a member number 


        """
STRMEM_AUTO = _ida_typeinf.STRMEM_AUTO
"""get member by offset if struct, or get member by index if union
* nb: union: index is stored in the udm->offset field!
* nb: struct: offset is in bytes (not in bits)! 


        """
STRMEM_NAME = _ida_typeinf.STRMEM_NAME
"""get member by name
* in: udm->name - the desired member name. 


        """
STRMEM_TYPE = _ida_typeinf.STRMEM_TYPE
"""get member by type.
* in: udm->type - the desired member type. member types are compared with tinfo_t::equals_to() 


        """
STRMEM_SIZE = _ida_typeinf.STRMEM_SIZE
"""get member by size.
* in: udm->size - the desired member size. 


        """
STRMEM_MINS = _ida_typeinf.STRMEM_MINS
"""get smallest member by size.
"""
STRMEM_MAXS = _ida_typeinf.STRMEM_MAXS
"""get biggest member by size.
"""
STRMEM_LOWBND = _ida_typeinf.STRMEM_LOWBND
"""get member by offset or the next member (lower bound)
* in: udm->offset - is a member offset in bits 


        """
STRMEM_NEXT = _ida_typeinf.STRMEM_NEXT
"""get next member after the offset
* in: udm->offset - is a member offset in bits 


        """
STRMEM_VFTABLE = _ida_typeinf.STRMEM_VFTABLE
"""can be combined with STRMEM_OFFSET, STRMEM_AUTO get vftable instead of the base class 
        """
STRMEM_SKIP_EMPTY = _ida_typeinf.STRMEM_SKIP_EMPTY
"""can be combined with STRMEM_OFFSET, STRMEM_AUTO skip empty members (i.e. having zero size) only last empty member can be returned 
        """
STRMEM_CASTABLE_TO = _ida_typeinf.STRMEM_CASTABLE_TO
"""can be combined with STRMEM_TYPE: member type must be castable to the specified type 
        """
STRMEM_ANON = _ida_typeinf.STRMEM_ANON
"""can be combined with STRMEM_NAME: look inside anonymous members too. 
        """
STRMEM_SKIP_GAPS = _ida_typeinf.STRMEM_SKIP_GAPS
"""can be combined with STRMEM_OFFSET, STRMEM_LOWBND skip gap members 
        """
TCMP_EQUAL = _ida_typeinf.TCMP_EQUAL
"""are types equal?
"""
TCMP_IGNMODS = _ida_typeinf.TCMP_IGNMODS
"""ignore const/volatile modifiers
"""
TCMP_AUTOCAST = _ida_typeinf.TCMP_AUTOCAST
"""can t1 be cast into t2 automatically?
"""
TCMP_MANCAST = _ida_typeinf.TCMP_MANCAST
"""can t1 be cast into t2 manually?
"""
TCMP_CALL = _ida_typeinf.TCMP_CALL
"""can t1 be called with t2 type?
"""
TCMP_DELPTR = _ida_typeinf.TCMP_DELPTR
"""remove pointer from types before comparing
"""
TCMP_DECL = _ida_typeinf.TCMP_DECL
"""compare declarations without resolving them
"""
TCMP_ANYBASE = _ida_typeinf.TCMP_ANYBASE
"""accept any base class when casting
"""
TCMP_SKIPTHIS = _ida_typeinf.TCMP_SKIPTHIS
"""skip the first function argument in comparison
"""


class simd_info_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    name: 'char const *' = property(_ida_typeinf.simd_info_t_name_get,
        _ida_typeinf.simd_info_t_name_set)
    """name of SIMD type (nullptr-undefined)
"""
    tif: 'tinfo_t' = property(_ida_typeinf.simd_info_t_tif_get,
        _ida_typeinf.simd_info_t_tif_set)
    """SIMD type (empty-undefined)
"""
    size: 'uint16' = property(_ida_typeinf.simd_info_t_size_get,
        _ida_typeinf.simd_info_t_size_set)
    """SIMD type size in bytes (0-undefined)
"""
    memtype: 'type_t' = property(_ida_typeinf.simd_info_t_memtype_get,
        _ida_typeinf.simd_info_t_memtype_set)
    """member type BTF_INT8/16/32/64/128, BTF_UINT8/16/32/64/128 BTF_INT - integrals of any size/sign BTF_FLOAT, BTF_DOUBLE BTF_TBYTE - floatings of any size BTF_UNION - union of integral and floating types BTF_UNK - undefined 
        """

    def __init__(self, *args):
        _ida_typeinf.simd_info_t_swiginit(self, _ida_typeinf.
            new_simd_info_t(*args))

    def match_pattern(self, pattern: 'simd_info_t') ->bool:
        return _ida_typeinf.simd_info_t_match_pattern(self, pattern)
    __swig_destroy__ = _ida_typeinf.delete_simd_info_t


_ida_typeinf.simd_info_t_swigregister(simd_info_t)


def guess_func_cc(fti: 'func_type_data_t', npurged: int, cc_flags: int
    ) ->'cm_t':
    """Use func_type_data_t::guess_cc()
"""
    return _ida_typeinf.guess_func_cc(fti, npurged, cc_flags)


def dump_func_type_data(fti: 'func_type_data_t', praloc_bits: int) ->str:
    """Use func_type_data_t::dump()
"""
    return _ida_typeinf.dump_func_type_data(fti, praloc_bits)


class ptr_type_data_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    obj_type: 'tinfo_t' = property(_ida_typeinf.
        ptr_type_data_t_obj_type_get, _ida_typeinf.ptr_type_data_t_obj_type_set
        )
    """pointed object type
"""
    closure: 'tinfo_t' = property(_ida_typeinf.ptr_type_data_t_closure_get,
        _ida_typeinf.ptr_type_data_t_closure_set)
    """cannot have both closure and based_ptr_size
"""
    parent: 'tinfo_t' = property(_ida_typeinf.ptr_type_data_t_parent_get,
        _ida_typeinf.ptr_type_data_t_parent_set)
    """Parent struct.
"""
    delta: 'int32' = property(_ida_typeinf.ptr_type_data_t_delta_get,
        _ida_typeinf.ptr_type_data_t_delta_set)
    """Offset from the beginning of the parent struct.
"""
    based_ptr_size: 'uchar' = property(_ida_typeinf.
        ptr_type_data_t_based_ptr_size_get, _ida_typeinf.
        ptr_type_data_t_based_ptr_size_set)
    taptr_bits: 'uchar' = property(_ida_typeinf.
        ptr_type_data_t_taptr_bits_get, _ida_typeinf.
        ptr_type_data_t_taptr_bits_set)
    """TAH bits.
"""

    def __init__(self, *args):
        _ida_typeinf.ptr_type_data_t_swiginit(self, _ida_typeinf.
            new_ptr_type_data_t(*args))

    def swap(self, r: 'ptr_type_data_t') ->None:
        """Set this = r and r = this.
"""
        return _ida_typeinf.ptr_type_data_t_swap(self, r)

    def __eq__(self, r: 'ptr_type_data_t') ->bool:
        return _ida_typeinf.ptr_type_data_t___eq__(self, r)

    def __ne__(self, r: 'ptr_type_data_t') ->bool:
        return _ida_typeinf.ptr_type_data_t___ne__(self, r)

    def is_code_ptr(self) ->bool:
        """Are we pointing to code?
"""
        return _ida_typeinf.ptr_type_data_t_is_code_ptr(self)

    def is_shifted(self) ->bool:
        return _ida_typeinf.ptr_type_data_t_is_shifted(self)
    __swig_destroy__ = _ida_typeinf.delete_ptr_type_data_t


_ida_typeinf.ptr_type_data_t_swigregister(ptr_type_data_t)


class array_type_data_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    elem_type: 'tinfo_t' = property(_ida_typeinf.
        array_type_data_t_elem_type_get, _ida_typeinf.
        array_type_data_t_elem_type_set)
    """element type
"""
    base: 'uint32' = property(_ida_typeinf.array_type_data_t_base_get,
        _ida_typeinf.array_type_data_t_base_set)
    """array base
"""
    nelems: 'uint32' = property(_ida_typeinf.array_type_data_t_nelems_get,
        _ida_typeinf.array_type_data_t_nelems_set)
    """number of elements
"""

    def __init__(self, b: 'size_t'=0, n: 'size_t'=0):
        _ida_typeinf.array_type_data_t_swiginit(self, _ida_typeinf.
            new_array_type_data_t(b, n))

    def swap(self, r: 'array_type_data_t') ->None:
        """set this = r and r = this
"""
        return _ida_typeinf.array_type_data_t_swap(self, r)
    __swig_destroy__ = _ida_typeinf.delete_array_type_data_t


_ida_typeinf.array_type_data_t_swigregister(array_type_data_t)


class funcarg_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    argloc: 'argloc_t' = property(_ida_typeinf.funcarg_t_argloc_get,
        _ida_typeinf.funcarg_t_argloc_set)
    """argument location
"""
    name: 'qstring' = property(_ida_typeinf.funcarg_t_name_get,
        _ida_typeinf.funcarg_t_name_set)
    """argument name (may be empty)
"""
    cmt: 'qstring' = property(_ida_typeinf.funcarg_t_cmt_get, _ida_typeinf.
        funcarg_t_cmt_set)
    """argument comment (may be empty)
"""
    type: 'tinfo_t' = property(_ida_typeinf.funcarg_t_type_get,
        _ida_typeinf.funcarg_t_type_set)
    """argument type
"""
    flags: 'uint32' = property(_ida_typeinf.funcarg_t_flags_get,
        _ida_typeinf.funcarg_t_flags_set)
    """Function argument property bits 
        """

    def __eq__(self, r: 'funcarg_t') ->bool:
        return _ida_typeinf.funcarg_t___eq__(self, r)

    def __ne__(self, r: 'funcarg_t') ->bool:
        return _ida_typeinf.funcarg_t___ne__(self, r)

    def __init__(self, *args):
        """Create a function argument, with the specified name and type.

This constructor has the following signatures:

    1. funcarg_t(name: str, type, argloc: argloc_t)
    2. funcarg_t(funcarg: funcarg_t)

In the 1st form, the 'type' descriptor, can be one of:

    * type_t: if the type is simple (integral/floating/bool). E.g., `BTF_INT`
    * tinfo_t: can handle more complex types (structures, pointers, arrays, ...)
    * str: a C type declaration

If an input argument is incorrect, the constructor may raise an exception

@param name a valid argument name. May not be empty (1st form).
@param type the member type (1st form).
@param argloc the argument location. Can be empty (1st form).
@param funcarg a funcarg_t to copy"""
        _ida_typeinf.funcarg_t_swiginit(self, _ida_typeinf.new_funcarg_t(*args)
            )
        if args and self.type.empty():
            raise ValueError('Invalid input data: %s' % str(args))
    __swig_destroy__ = _ida_typeinf.delete_funcarg_t


_ida_typeinf.funcarg_t_swigregister(funcarg_t)
FAI_HIDDEN = _ida_typeinf.FAI_HIDDEN
"""hidden argument
"""
FAI_RETPTR = _ida_typeinf.FAI_RETPTR
"""pointer to return value. implies hidden
"""
FAI_STRUCT = _ida_typeinf.FAI_STRUCT
"""was initially a structure
"""
FAI_ARRAY = _ida_typeinf.FAI_ARRAY
"""was initially an array; see "__org_typedef" or "__org_arrdim" type attributes to determine the original type 
        """
FAI_UNUSED = _ida_typeinf.FAI_UNUSED
"""argument is not used by the function
"""


class func_type_data_t(funcargvec_t):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    flags: 'int' = property(_ida_typeinf.func_type_data_t_flags_get,
        _ida_typeinf.func_type_data_t_flags_set)
    """Function type data property bits 
        """
    rettype: 'tinfo_t' = property(_ida_typeinf.func_type_data_t_rettype_get,
        _ida_typeinf.func_type_data_t_rettype_set)
    """return type
"""
    retloc: 'argloc_t' = property(_ida_typeinf.func_type_data_t_retloc_get,
        _ida_typeinf.func_type_data_t_retloc_set)
    """return location
"""
    stkargs: 'uval_t' = property(_ida_typeinf.func_type_data_t_stkargs_get,
        _ida_typeinf.func_type_data_t_stkargs_set)
    """size of stack arguments (not used in build_func_type)
"""
    spoiled: 'reginfovec_t' = property(_ida_typeinf.
        func_type_data_t_spoiled_get, _ida_typeinf.func_type_data_t_spoiled_set
        )
    """spoiled register information. if spoiled register info is present, it overrides the standard spoil info (eax, edx, ecx for x86) 
        """
    cc: 'cm_t' = property(_ida_typeinf.func_type_data_t_cc_get,
        _ida_typeinf.func_type_data_t_cc_set)
    """calling convention
"""

    def swap(self, r: 'func_type_data_t') ->None:
        return _ida_typeinf.func_type_data_t_swap(self, r)

    def is_high(self) ->bool:
        return _ida_typeinf.func_type_data_t_is_high(self)

    def is_noret(self) ->bool:
        return _ida_typeinf.func_type_data_t_is_noret(self)

    def is_pure(self) ->bool:
        return _ida_typeinf.func_type_data_t_is_pure(self)

    def is_static(self) ->bool:
        return _ida_typeinf.func_type_data_t_is_static(self)

    def is_virtual(self) ->bool:
        return _ida_typeinf.func_type_data_t_is_virtual(self)

    def is_const(self) ->bool:
        return _ida_typeinf.func_type_data_t_is_const(self)

    def is_ctor(self) ->bool:
        return _ida_typeinf.func_type_data_t_is_ctor(self)

    def is_dtor(self) ->bool:
        return _ida_typeinf.func_type_data_t_is_dtor(self)

    def get_call_method(self) ->int:
        return _ida_typeinf.func_type_data_t_get_call_method(self)

    def is_vararg_cc(self) ->bool:
        return _ida_typeinf.func_type_data_t_is_vararg_cc(self)

    def is_golang_cc(self) ->bool:
        return _ida_typeinf.func_type_data_t_is_golang_cc(self)

    def is_swift_cc(self) ->bool:
        return _ida_typeinf.func_type_data_t_is_swift_cc(self)

    def guess_cc(self, purged: int, cc_flags: int) ->'cm_t':
        """Guess function calling convention use the following info: argument locations and 'stkargs' 
        """
        return _ida_typeinf.func_type_data_t_guess_cc(self, purged, cc_flags)

    def dump(self, praloc_bits: int=2) ->bool:
        """Dump information that is not always visible in the function prototype. (argument locations, return location, total stkarg size) 
        """
        return _ida_typeinf.func_type_data_t_dump(self, praloc_bits)

    def find_argument(self, *args) ->'ssize_t':
        """find argument by name
"""
        return _ida_typeinf.func_type_data_t_find_argument(self, *args)
    __swig_destroy__ = _ida_typeinf.delete_func_type_data_t

    def __init__(self):
        _ida_typeinf.func_type_data_t_swiginit(self, _ida_typeinf.
            new_func_type_data_t())


_ida_typeinf.func_type_data_t_swigregister(func_type_data_t)
FTI_SPOILED = _ida_typeinf.FTI_SPOILED
"""information about spoiled registers is present
"""
FTI_NORET = _ida_typeinf.FTI_NORET
"""noreturn
"""
FTI_PURE = _ida_typeinf.FTI_PURE
"""__pure
"""
FTI_HIGH = _ida_typeinf.FTI_HIGH
"""high level prototype (with possibly hidden args)
"""
FTI_STATIC = _ida_typeinf.FTI_STATIC
"""static
"""
FTI_VIRTUAL = _ida_typeinf.FTI_VIRTUAL
"""virtual
"""
FTI_CALLTYPE = _ida_typeinf.FTI_CALLTYPE
"""mask for FTI_*CALL
"""
FTI_DEFCALL = _ida_typeinf.FTI_DEFCALL
"""default call
"""
FTI_NEARCALL = _ida_typeinf.FTI_NEARCALL
"""near call
"""
FTI_FARCALL = _ida_typeinf.FTI_FARCALL
"""far call
"""
FTI_INTCALL = _ida_typeinf.FTI_INTCALL
"""interrupt call
"""
FTI_ARGLOCS = _ida_typeinf.FTI_ARGLOCS
"""info about argument locations has been calculated (stkargs and retloc too) 
        """
FTI_EXPLOCS = _ida_typeinf.FTI_EXPLOCS
"""all arglocs are specified explicitly
"""
FTI_CONST = _ida_typeinf.FTI_CONST
"""const member function
"""
FTI_CTOR = _ida_typeinf.FTI_CTOR
"""constructor
"""
FTI_DTOR = _ida_typeinf.FTI_DTOR
"""destructor
"""
FTI_ALL = _ida_typeinf.FTI_ALL
"""all defined bits
"""
CC_CDECL_OK = _ida_typeinf.CC_CDECL_OK
"""can use __cdecl calling convention?
"""
CC_ALLOW_ARGPERM = _ida_typeinf.CC_ALLOW_ARGPERM
"""disregard argument order?
"""
CC_ALLOW_REGHOLES = _ida_typeinf.CC_ALLOW_REGHOLES
"""allow holes in register argument list?
"""
CC_HAS_ELLIPSIS = _ida_typeinf.CC_HAS_ELLIPSIS
"""function has a variable list of arguments?
"""
CC_GOLANG_OK = _ida_typeinf.CC_GOLANG_OK
"""can use __golang calling convention 
        """
FMTFUNC_PRINTF = _ida_typeinf.FMTFUNC_PRINTF
FMTFUNC_SCANF = _ida_typeinf.FMTFUNC_SCANF
FMTFUNC_STRFTIME = _ida_typeinf.FMTFUNC_STRFTIME
FMTFUNC_STRFMON = _ida_typeinf.FMTFUNC_STRFMON


class stkarg_area_info_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    cb: 'size_t' = property(_ida_typeinf.stkarg_area_info_t_cb_get,
        _ida_typeinf.stkarg_area_info_t_cb_set)
    stkarg_offset: 'sval_t' = property(_ida_typeinf.
        stkarg_area_info_t_stkarg_offset_get, _ida_typeinf.
        stkarg_area_info_t_stkarg_offset_set)
    """Offset from the SP to the first stack argument (can include linkage area) examples: pc: 0, hppa: -0x34, ppc aix: 0x18 
        """
    shadow_size: 'sval_t' = property(_ida_typeinf.
        stkarg_area_info_t_shadow_size_get, _ida_typeinf.
        stkarg_area_info_t_shadow_size_set)
    """Size of the shadow area. explanations at: [https://stackoverflow.com/questions/30190132/what-is-the-shadow-space-in-x64-assembly](https://stackoverflow.com/questions/30190132/what-is-the-shadow-space-in-x64-assembly) examples: x64 Visual Studio C++: 0x20, x64 gcc: 0, ppc aix: 0x20 
        """
    linkage_area: 'sval_t' = property(_ida_typeinf.
        stkarg_area_info_t_linkage_area_get, _ida_typeinf.
        stkarg_area_info_t_linkage_area_set)
    """Size of the linkage area. explanations at: [https://www.ibm.com/docs/en/xl-fortran-aix/16.1.0?topic=conventions-linkage-area](https://www.ibm.com/docs/en/xl-fortran-aix/16.1.0?topic=conventions-linkage-area) examples: pc: 0, hppa: 0, ppc aix: 0x18 (equal to stkarg_offset) 
        """

    def __init__(self):
        _ida_typeinf.stkarg_area_info_t_swiginit(self, _ida_typeinf.
            new_stkarg_area_info_t())
    __swig_destroy__ = _ida_typeinf.delete_stkarg_area_info_t


_ida_typeinf.stkarg_area_info_t_swigregister(stkarg_area_info_t)


class edm_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    name: 'qstring' = property(_ida_typeinf.edm_t_name_get, _ida_typeinf.
        edm_t_name_set)
    cmt: 'qstring' = property(_ida_typeinf.edm_t_cmt_get, _ida_typeinf.
        edm_t_cmt_set)
    value: 'uint64' = property(_ida_typeinf.edm_t_value_get, _ida_typeinf.
        edm_t_value_set)

    def empty(self) ->bool:
        return _ida_typeinf.edm_t_empty(self)

    def __eq__(self, r: 'edm_t') ->bool:
        return _ida_typeinf.edm_t___eq__(self, r)

    def __ne__(self, r: 'edm_t') ->bool:
        return _ida_typeinf.edm_t___ne__(self, r)

    def swap(self, r: 'edm_t') ->None:
        return _ida_typeinf.edm_t_swap(self, r)

    def get_tid(self) ->'tid_t':
        return _ida_typeinf.edm_t_get_tid(self)

    def __init__(self, *args):
        """Create an enumerator, with the specified name and value

This constructor has the following signatures:

    1. edm_t(edm: edm_t)
    2. edm_t(name: str, value: int, cmt: str=None)

@param name  Enumerator name. Must not be empty (1st form)
@param value Enumerator value (1st form)
@param cmt   Enumerator repeatable comment. May be empty (1st form)
@param edm   An enum member to copy"""
        _ida_typeinf.edm_t_swiginit(self, _ida_typeinf.new_edm_t(*args))
    __swig_destroy__ = _ida_typeinf.delete_edm_t


_ida_typeinf.edm_t_swigregister(edm_t)


class enum_type_data_t(edmvec_t):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    group_sizes: 'intvec_t' = property(_ida_typeinf.
        enum_type_data_t_group_sizes_get, _ida_typeinf.
        enum_type_data_t_group_sizes_set)
    """if present, specifies bitmask group sizes each non-trivial group starts with a mask member 
        """
    taenum_bits: 'uint32' = property(_ida_typeinf.
        enum_type_data_t_taenum_bits_get, _ida_typeinf.
        enum_type_data_t_taenum_bits_set)
    """Type attributes for enums
"""
    bte: 'bte_t' = property(_ida_typeinf.enum_type_data_t_bte_get,
        _ida_typeinf.enum_type_data_t_bte_set)
    """enum member sizes (shift amount) and style. do not manually set BTE_BITMASK, use set_enum_is_bitmask() 
        """

    def __init__(self, *args):
        _ida_typeinf.enum_type_data_t_swiginit(self, _ida_typeinf.
            new_enum_type_data_t(*args))

    def get_enum_radix(self) ->int:
        """Get enum constant radix 
        
@returns radix or 1 for BTE_CHAR"""
        return _ida_typeinf.enum_type_data_t_get_enum_radix(self)

    def is_number_signed(self) ->bool:
        return _ida_typeinf.enum_type_data_t_is_number_signed(self)

    def set_enum_radix(self, radix: int, sign: bool) ->None:
        """Set radix to display constants 
        
@param radix: radix with the special case 1 to display as character"""
        return _ida_typeinf.enum_type_data_t_set_enum_radix(self, radix, sign)

    def is_char(self) ->bool:
        return _ida_typeinf.enum_type_data_t_is_char(self)

    def is_dec(self) ->bool:
        return _ida_typeinf.enum_type_data_t_is_dec(self)

    def is_hex(self) ->bool:
        return _ida_typeinf.enum_type_data_t_is_hex(self)

    def is_oct(self) ->bool:
        return _ida_typeinf.enum_type_data_t_is_oct(self)

    def is_bin(self) ->bool:
        return _ida_typeinf.enum_type_data_t_is_bin(self)

    def is_udec(self) ->bool:
        return _ida_typeinf.enum_type_data_t_is_udec(self)

    def is_shex(self) ->bool:
        return _ida_typeinf.enum_type_data_t_is_shex(self)

    def is_soct(self) ->bool:
        return _ida_typeinf.enum_type_data_t_is_soct(self)

    def is_sbin(self) ->bool:
        return _ida_typeinf.enum_type_data_t_is_sbin(self)

    def has_lzero(self) ->bool:
        return _ida_typeinf.enum_type_data_t_has_lzero(self)

    def set_lzero(self, on: bool) ->None:
        return _ida_typeinf.enum_type_data_t_set_lzero(self, on)

    def calc_mask(self) ->'uint64':
        return _ida_typeinf.enum_type_data_t_calc_mask(self)

    def store_64bit_values(self) ->bool:
        return _ida_typeinf.enum_type_data_t_store_64bit_values(self)

    def is_bf(self) ->bool:
        """is bitmask or ordinary enum?
"""
        return _ida_typeinf.enum_type_data_t_is_bf(self)

    def calc_nbytes(self) ->int:
        """get the width of enum in bytes
"""
        return _ida_typeinf.enum_type_data_t_calc_nbytes(self)

    def set_nbytes(self, nbytes: int) ->bool:
        """set enum width (nbytes)
"""
        return _ida_typeinf.enum_type_data_t_set_nbytes(self, nbytes)

    def is_group_mask_at(self, idx: 'size_t') ->bool:
        """is the enum member at IDX a non-trivial group mask? a trivial group consist of one bit and has just one member, which can be considered as a mask or a bitfield constant 
        
@param idx: index
@returns success"""
        return _ida_typeinf.enum_type_data_t_is_group_mask_at(self, idx)

    def is_valid_group_sizes(self) ->bool:
        """is valid group sizes
"""
        return _ida_typeinf.enum_type_data_t_is_valid_group_sizes(self)

    def find_member(self, *args) ->'ssize_t':
        """This function has the following signatures:

    0. find_member(name: str, from: size_t=0, to: size_t=size_t(-1)) -> ssize_t
    1. find_member(value: uint64, serial: uchar, from: size_t=0, to: size_t=size_t(-1), vmask: uint64=uint64(-1)) -> ssize_t

# 0: find_member(name: str, from: size_t=0, to: size_t=size_t(-1)) -> ssize_t

find member (constant or bmask) by name


# 1: find_member(value: uint64, serial: uchar, from: size_t=0, to: size_t=size_t(-1), vmask: uint64=uint64(-1)) -> ssize_t

find member (constant or bmask) by value

"""
        return _ida_typeinf.enum_type_data_t_find_member(self, *args)

    def swap(self, r: 'enum_type_data_t') ->None:
        """swap two instances
"""
        return _ida_typeinf.enum_type_data_t_swap(self, r)

    def add_constant(self, name: str, value: 'uint64', cmt: str=None) ->None:
        """add constant for regular enum
"""
        return _ida_typeinf.enum_type_data_t_add_constant(self, name, value,
            cmt)

    def get_value_repr(self, repr: 'value_repr_t') ->'tinfo_code_t':
        """get enum radix and other representation info 
        
@param repr: value display info"""
        return _ida_typeinf.enum_type_data_t_get_value_repr(self, repr)

    def set_value_repr(self, repr: 'value_repr_t') ->'tinfo_code_t':
        """set enum radix and other representation info 
        
@param repr: value display info"""
        return _ida_typeinf.enum_type_data_t_set_value_repr(self, repr)

    def get_serial(self, index: 'size_t') ->'uchar':
        """returns serial for the constant
"""
        return _ida_typeinf.enum_type_data_t_get_serial(self, index)

    def get_max_serial(self, value: 'uint64') ->'uchar':
        """return the maximum serial for the value
"""
        return _ida_typeinf.enum_type_data_t_get_max_serial(self, value)

    def get_constant_group(self, *args) ->'PyObject *':
        """get group parameters for the constant, valid for bitmask enum 
        
@param group_start_index: index of the group mask
@param group_size: group size (>=1)
@param idx: constant index
@returns success"""
        return _ida_typeinf.enum_type_data_t_get_constant_group(self, *args)

    def all_groups(self, skip_trivial=False):
        """
        Generate tuples for bitmask enum groups.
        Each tupple is:
        [0] enum member index of group start
        [1] group size
        Tupples may include or not the group with 1 element.
        """
        if len(self.group_sizes) != 0 and self.is_valid_group_sizes():
            grp_start = 0
            for grp_size in self.group_sizes:
                if not skip_trivial or grp_size != 1:
                    yield grp_start, grp_size
                grp_start += grp_size
            return None

    def all_constants(self):
        """
        Generate tupples of all constants except of bitmasks.
        Each tupple is:
        [0] constant index
        [1] enum member index of group start
        [2] group size
        In case of regular enum the second element of tupple is 0 and the third element of tupple is the number of enum members.
        """
        if len(self.group_sizes) != 0:
            for grp_start, grp_size in self.all_groups():
                grp_end = grp_start + grp_size
                if grp_size != 1:
                    grp_start += 1
                for idx in range(grp_start, grp_end):
                    yield idx, grp_start, grp_size
        else:
            sz = self.size()
            for idx in range(0, sz):
                yield idx, 0, sz
        return None
    __swig_destroy__ = _ida_typeinf.delete_enum_type_data_t


_ida_typeinf.enum_type_data_t_swigregister(enum_type_data_t)


class typedef_type_data_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    til: 'til_t const *' = property(_ida_typeinf.
        typedef_type_data_t_til_get, _ida_typeinf.typedef_type_data_t_til_set)
    """type library to use when resolving
"""
    name: 'char const *' = property(_ida_typeinf.
        typedef_type_data_t_name_get, _ida_typeinf.typedef_type_data_t_name_set
        )
    """is_ordref=false: target type name. we do not own this pointer!
"""
    ordinal: 'uint32' = property(_ida_typeinf.
        typedef_type_data_t_ordinal_get, _ida_typeinf.
        typedef_type_data_t_ordinal_set)
    """is_ordref=true: type ordinal number
"""
    is_ordref: 'bool' = property(_ida_typeinf.
        typedef_type_data_t_is_ordref_get, _ida_typeinf.
        typedef_type_data_t_is_ordref_set)
    """is reference by ordinal?
"""
    resolve: 'bool' = property(_ida_typeinf.typedef_type_data_t_resolve_get,
        _ida_typeinf.typedef_type_data_t_resolve_set)
    """should resolve immediately?
"""

    def __init__(self, *args):
        _ida_typeinf.typedef_type_data_t_swiginit(self, _ida_typeinf.
            new_typedef_type_data_t(*args))

    def swap(self, r: 'typedef_type_data_t') ->None:
        return _ida_typeinf.typedef_type_data_t_swap(self, r)
    __swig_destroy__ = _ida_typeinf.delete_typedef_type_data_t


_ida_typeinf.typedef_type_data_t_swigregister(typedef_type_data_t)
MAX_ENUM_SERIAL = cvar.MAX_ENUM_SERIAL
"""Max number of identical constants allowed for one enum type.
"""


class custom_data_type_info_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    dtid: 'int16' = property(_ida_typeinf.custom_data_type_info_t_dtid_get,
        _ida_typeinf.custom_data_type_info_t_dtid_set)
    """data type id
"""
    fid: 'int16' = property(_ida_typeinf.custom_data_type_info_t_fid_get,
        _ida_typeinf.custom_data_type_info_t_fid_set)
    """data format ids
"""

    def __init__(self):
        _ida_typeinf.custom_data_type_info_t_swiginit(self, _ida_typeinf.
            new_custom_data_type_info_t())
    __swig_destroy__ = _ida_typeinf.delete_custom_data_type_info_t


_ida_typeinf.custom_data_type_info_t_swigregister(custom_data_type_info_t)


class value_repr_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    bits: 'uint64' = property(_ida_typeinf.value_repr_t_bits_get,
        _ida_typeinf.value_repr_t_bits_set)
    ri: 'refinfo_t' = property(_ida_typeinf.value_repr_t_ri_get,
        _ida_typeinf.value_repr_t_ri_set)
    """FRB_OFFSET.
"""
    strtype: 'int32' = property(_ida_typeinf.value_repr_t_strtype_get,
        _ida_typeinf.value_repr_t_strtype_set)
    """FRB_STRLIT.
"""
    delta: 'adiff_t' = property(_ida_typeinf.value_repr_t_delta_get,
        _ida_typeinf.value_repr_t_delta_set)
    """FRB_STROFF.
"""
    type_ordinal: 'uint32' = property(_ida_typeinf.
        value_repr_t_type_ordinal_get, _ida_typeinf.
        value_repr_t_type_ordinal_set)
    """FRB_STROFF, FRB_ENUM.
"""
    cd: 'custom_data_type_info_t' = property(_ida_typeinf.
        value_repr_t_cd_get, _ida_typeinf.value_repr_t_cd_set)
    """FRB_CUSTOM.
"""
    ap: 'array_parameters_t' = property(_ida_typeinf.value_repr_t_ap_get,
        _ida_typeinf.value_repr_t_ap_set)
    """FRB_TABFORM, AP_SIGNED is ignored, use FRB_SIGNED instead 
        """

    def swap(self, r: 'value_repr_t') ->None:
        return _ida_typeinf.value_repr_t_swap(self, r)

    def clear(self) ->None:
        return _ida_typeinf.value_repr_t_clear(self)

    def empty(self) ->bool:
        return _ida_typeinf.value_repr_t_empty(self)

    def is_enum(self) ->bool:
        return _ida_typeinf.value_repr_t_is_enum(self)

    def is_offset(self) ->bool:
        return _ida_typeinf.value_repr_t_is_offset(self)

    def is_strlit(self) ->bool:
        return _ida_typeinf.value_repr_t_is_strlit(self)

    def is_custom(self) ->bool:
        return _ida_typeinf.value_repr_t_is_custom(self)

    def is_stroff(self) ->bool:
        return _ida_typeinf.value_repr_t_is_stroff(self)

    def is_typref(self) ->bool:
        return _ida_typeinf.value_repr_t_is_typref(self)

    def is_signed(self) ->bool:
        return _ida_typeinf.value_repr_t_is_signed(self)

    def has_tabform(self) ->bool:
        return _ida_typeinf.value_repr_t_has_tabform(self)

    def has_lzeroes(self) ->bool:
        return _ida_typeinf.value_repr_t_has_lzeroes(self)

    def get_vtype(self) ->'uint64':
        return _ida_typeinf.value_repr_t_get_vtype(self)

    def set_vtype(self, vt: 'uint64') ->None:
        return _ida_typeinf.value_repr_t_set_vtype(self, vt)

    def set_signed(self, on: bool) ->None:
        return _ida_typeinf.value_repr_t_set_signed(self, on)

    def set_tabform(self, on: bool) ->None:
        return _ida_typeinf.value_repr_t_set_tabform(self, on)

    def set_lzeroes(self, on: bool) ->None:
        return _ida_typeinf.value_repr_t_set_lzeroes(self, on)

    def set_ap(self, _ap: 'array_parameters_t') ->None:
        return _ida_typeinf.value_repr_t_set_ap(self, _ap)

    def init_ap(self, _ap: 'array_parameters_t') ->None:
        return _ida_typeinf.value_repr_t_init_ap(self, _ap)

    def from_opinfo(self, flags: 'flags64_t', afl: 'aflags_t', opinfo:
        'opinfo_t', _ap: 'array_parameters_t') ->bool:
        return _ida_typeinf.value_repr_t_from_opinfo(self, flags, afl,
            opinfo, _ap)

    def _print(self, colored: bool=False) ->'size_t':
        return _ida_typeinf.value_repr_t__print(self, colored)

    def parse_value_repr(self, *args) ->bool:
        return _ida_typeinf.value_repr_t_parse_value_repr(self, *args)

    def __str__(self) ->str:
        return _ida_typeinf.value_repr_t___str__(self)

    def __init__(self):
        _ida_typeinf.value_repr_t_swiginit(self, _ida_typeinf.
            new_value_repr_t())
    __swig_destroy__ = _ida_typeinf.delete_value_repr_t


_ida_typeinf.value_repr_t_swigregister(value_repr_t)
FRB_MASK = _ida_typeinf.FRB_MASK
"""Mask for the value type (* means requires additional info):
"""
FRB_UNK = _ida_typeinf.FRB_UNK
"""Unknown.
"""
FRB_NUMB = _ida_typeinf.FRB_NUMB
"""Binary number.
"""
FRB_NUMO = _ida_typeinf.FRB_NUMO
"""Octal number.
"""
FRB_NUMH = _ida_typeinf.FRB_NUMH
"""Hexadecimal number.
"""
FRB_NUMD = _ida_typeinf.FRB_NUMD
"""Decimal number.
"""
FRB_FLOAT = _ida_typeinf.FRB_FLOAT
"""Floating point number (for interpreting an integer type as a floating value) 
        """
FRB_CHAR = _ida_typeinf.FRB_CHAR
"""Char.
"""
FRB_SEG = _ida_typeinf.FRB_SEG
"""Segment.
"""
FRB_ENUM = _ida_typeinf.FRB_ENUM
"""*Enumeration
"""
FRB_OFFSET = _ida_typeinf.FRB_OFFSET
"""*Offset
"""
FRB_STRLIT = _ida_typeinf.FRB_STRLIT
"""*String literal (used for arrays)
"""
FRB_STROFF = _ida_typeinf.FRB_STROFF
"""*Struct offset
"""
FRB_CUSTOM = _ida_typeinf.FRB_CUSTOM
"""*Custom data type
"""
FRB_INVSIGN = _ida_typeinf.FRB_INVSIGN
"""Invert sign (0x01 is represented as -0xFF)
"""
FRB_INVBITS = _ida_typeinf.FRB_INVBITS
"""Invert bits (0x01 is represented as ~0xFE)
"""
FRB_SIGNED = _ida_typeinf.FRB_SIGNED
"""Force signed representation.
"""
FRB_LZERO = _ida_typeinf.FRB_LZERO
"""Toggle leading zeroes (used for integers)
"""
FRB_TABFORM = _ida_typeinf.FRB_TABFORM
"""has additional tabular parameters 
        """


class udm_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    offset: 'uint64' = property(_ida_typeinf.udm_t_offset_get, _ida_typeinf
        .udm_t_offset_set)
    """member offset in bits
"""
    size: 'uint64' = property(_ida_typeinf.udm_t_size_get, _ida_typeinf.
        udm_t_size_set)
    """size in bits
"""
    name: 'qstring' = property(_ida_typeinf.udm_t_name_get, _ida_typeinf.
        udm_t_name_set)
    """member name
"""
    cmt: 'qstring' = property(_ida_typeinf.udm_t_cmt_get, _ida_typeinf.
        udm_t_cmt_set)
    """member comment
"""
    type: 'tinfo_t' = property(_ida_typeinf.udm_t_type_get, _ida_typeinf.
        udm_t_type_set)
    """member type
"""
    repr: 'value_repr_t' = property(_ida_typeinf.udm_t_repr_get,
        _ida_typeinf.udm_t_repr_set)
    """radix, refinfo, strpath, custom_id, strtype
"""
    effalign: 'int' = property(_ida_typeinf.udm_t_effalign_get,
        _ida_typeinf.udm_t_effalign_set)
    """effective field alignment (in bytes)
"""
    tafld_bits: 'uint32' = property(_ida_typeinf.udm_t_tafld_bits_get,
        _ida_typeinf.udm_t_tafld_bits_set)
    """TAH bits.
"""
    fda: 'uchar' = property(_ida_typeinf.udm_t_fda_get, _ida_typeinf.
        udm_t_fda_set)
    """field alignment (shift amount)
"""

    def empty(self) ->bool:
        return _ida_typeinf.udm_t_empty(self)

    def is_bitfield(self) ->bool:
        return _ida_typeinf.udm_t_is_bitfield(self)

    def is_zero_bitfield(self) ->bool:
        return _ida_typeinf.udm_t_is_zero_bitfield(self)

    def is_unaligned(self) ->bool:
        return _ida_typeinf.udm_t_is_unaligned(self)

    def is_baseclass(self) ->bool:
        return _ida_typeinf.udm_t_is_baseclass(self)

    def is_virtbase(self) ->bool:
        return _ida_typeinf.udm_t_is_virtbase(self)

    def is_vftable(self) ->bool:
        return _ida_typeinf.udm_t_is_vftable(self)

    def is_method(self) ->bool:
        return _ida_typeinf.udm_t_is_method(self)

    def is_gap(self) ->bool:
        return _ida_typeinf.udm_t_is_gap(self)

    def is_regcmt(self) ->bool:
        return _ida_typeinf.udm_t_is_regcmt(self)

    def is_retaddr(self) ->bool:
        return _ida_typeinf.udm_t_is_retaddr(self)

    def is_savregs(self) ->bool:
        return _ida_typeinf.udm_t_is_savregs(self)

    def is_special_member(self) ->bool:
        return _ida_typeinf.udm_t_is_special_member(self)

    def is_by_til(self) ->bool:
        return _ida_typeinf.udm_t_is_by_til(self)

    def set_unaligned(self, on: bool=True) ->None:
        return _ida_typeinf.udm_t_set_unaligned(self, on)

    def set_baseclass(self, on: bool=True) ->None:
        return _ida_typeinf.udm_t_set_baseclass(self, on)

    def set_virtbase(self, on: bool=True) ->None:
        return _ida_typeinf.udm_t_set_virtbase(self, on)

    def set_vftable(self, on: bool=True) ->None:
        return _ida_typeinf.udm_t_set_vftable(self, on)

    def set_method(self, on: bool=True) ->None:
        return _ida_typeinf.udm_t_set_method(self, on)

    def set_regcmt(self, on: bool=True) ->None:
        return _ida_typeinf.udm_t_set_regcmt(self, on)

    def set_retaddr(self, on: bool=True) ->None:
        return _ida_typeinf.udm_t_set_retaddr(self, on)

    def set_savregs(self, on: bool=True) ->None:
        return _ida_typeinf.udm_t_set_savregs(self, on)

    def set_by_til(self, on: bool=True) ->None:
        return _ida_typeinf.udm_t_set_by_til(self, on)

    def clr_unaligned(self) ->None:
        return _ida_typeinf.udm_t_clr_unaligned(self)

    def clr_baseclass(self) ->None:
        return _ida_typeinf.udm_t_clr_baseclass(self)

    def clr_virtbase(self) ->None:
        return _ida_typeinf.udm_t_clr_virtbase(self)

    def clr_vftable(self) ->None:
        return _ida_typeinf.udm_t_clr_vftable(self)

    def clr_method(self) ->None:
        return _ida_typeinf.udm_t_clr_method(self)

    def begin(self) ->'uint64':
        return _ida_typeinf.udm_t_begin(self)

    def end(self) ->'uint64':
        return _ida_typeinf.udm_t_end(self)

    def __lt__(self, r: 'udm_t') ->bool:
        return _ida_typeinf.udm_t___lt__(self, r)

    def __eq__(self, r: 'udm_t') ->bool:
        return _ida_typeinf.udm_t___eq__(self, r)

    def __ne__(self, r: 'udm_t') ->bool:
        return _ida_typeinf.udm_t___ne__(self, r)

    def swap(self, r: 'udm_t') ->None:
        return _ida_typeinf.udm_t_swap(self, r)

    def is_anonymous_udm(self) ->bool:
        return _ida_typeinf.udm_t_is_anonymous_udm(self)

    def set_value_repr(self, r: 'value_repr_t') ->None:
        return _ida_typeinf.udm_t_set_value_repr(self, r)

    def can_be_dtor(self) ->bool:
        return _ida_typeinf.udm_t_can_be_dtor(self)

    def can_rename(self) ->bool:
        return _ida_typeinf.udm_t_can_rename(self)

    def __init__(self, *args):
        """Create a structure/union member, with the specified name and type.

This constructor has the following signatures:

    1. udm_t(udm: udm_t)
    2. udm_t(name: str, type, offset: int)

The 'type' descriptor, can be one of:

* type_t: if the type is simple (integral/floating/bool). E.g., `BTF_INT`
* tinfo_t: can handle more complex types (structures, pointers, arrays, ...)
* str: a C type declaration

If an input argument is incorrect, the constructor may raise an exception
The size will be computed automatically.

@param udm a source udm_t
@param name a valid member name. Must not be empty.
@param type the member type
@param offset the member offset in bits. It is the caller's responsibility
       to specify correct offsets."""
        _ida_typeinf.udm_t_swiginit(self, _ida_typeinf.new_udm_t(*args))
        if args and self.empty():
            raise ValueError('Invalid input data: %s' % str(args))
    __swig_destroy__ = _ida_typeinf.delete_udm_t


_ida_typeinf.udm_t_swigregister(udm_t)


class udtmembervec_t(udtmembervec_template_t):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_typeinf.udtmembervec_t_swiginit(self, _ida_typeinf.
            new_udtmembervec_t())
    __swig_destroy__ = _ida_typeinf.delete_udtmembervec_t


_ida_typeinf.udtmembervec_t_swigregister(udtmembervec_t)


class udt_type_data_t(udtmembervec_t):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    total_size: 'size_t' = property(_ida_typeinf.
        udt_type_data_t_total_size_get, _ida_typeinf.
        udt_type_data_t_total_size_set)
    """total structure size in bytes
"""
    unpadded_size: 'size_t' = property(_ida_typeinf.
        udt_type_data_t_unpadded_size_get, _ida_typeinf.
        udt_type_data_t_unpadded_size_set)
    """unpadded structure size in bytes
"""
    effalign: 'uint32' = property(_ida_typeinf.udt_type_data_t_effalign_get,
        _ida_typeinf.udt_type_data_t_effalign_set)
    """effective structure alignment (in bytes)
"""
    taudt_bits: 'uint32' = property(_ida_typeinf.
        udt_type_data_t_taudt_bits_get, _ida_typeinf.
        udt_type_data_t_taudt_bits_set)
    """TA... and TAUDT... bits.
"""
    version: 'uchar' = property(_ida_typeinf.udt_type_data_t_version_get,
        _ida_typeinf.udt_type_data_t_version_set)
    """version of udt_type_data_t
"""
    sda: 'uchar' = property(_ida_typeinf.udt_type_data_t_sda_get,
        _ida_typeinf.udt_type_data_t_sda_set)
    """declared structure alignment (shift amount+1). 0 - unspecified
"""
    pack: 'uchar' = property(_ida_typeinf.udt_type_data_t_pack_get,
        _ida_typeinf.udt_type_data_t_pack_set)
    """#pragma pack() alignment (shift amount)
"""
    is_union: 'bool' = property(_ida_typeinf.udt_type_data_t_is_union_get,
        _ida_typeinf.udt_type_data_t_is_union_set)
    """is union or struct?
"""

    def swap(self, r: 'udt_type_data_t') ->None:
        return _ida_typeinf.udt_type_data_t_swap(self, r)

    def is_unaligned(self) ->bool:
        return _ida_typeinf.udt_type_data_t_is_unaligned(self)

    def is_msstruct(self) ->bool:
        return _ida_typeinf.udt_type_data_t_is_msstruct(self)

    def is_cppobj(self) ->bool:
        return _ida_typeinf.udt_type_data_t_is_cppobj(self)

    def is_vftable(self) ->bool:
        return _ida_typeinf.udt_type_data_t_is_vftable(self)

    def is_fixed(self) ->bool:
        return _ida_typeinf.udt_type_data_t_is_fixed(self)

    def set_vftable(self, on: bool=True) ->None:
        return _ida_typeinf.udt_type_data_t_set_vftable(self, on)

    def set_fixed(self, on: bool=True) ->None:
        return _ida_typeinf.udt_type_data_t_set_fixed(self, on)

    def is_last_baseclass(self, idx: 'size_t') ->bool:
        return _ida_typeinf.udt_type_data_t_is_last_baseclass(self, idx)

    def add_member(self, _name: str, _type: 'tinfo_t', _offset: 'uint64'=0
        ) ->'udm_t &':
        """Add a new member to a structure or union. This function just pushes a new member to the back of the structure/union member vector.

@param _name: Member name. Must not be nullptr.
@param _type: Member type. Must not be empty.
@param _offset: Member offset in bits. It is the caller's responsibility to specify correct offsets.
@returns { Reference to the newly added member }"""
        return _ida_typeinf.udt_type_data_t_add_member(self, _name, _type,
            _offset)

    def find_member(self, *args) ->'ssize_t':
        """This function has the following signatures:

    0. find_member(pattern_udm: udm_t *, strmem_flags: int) -> ssize_t
    1. find_member(name: str) -> ssize_t
    2. find_member(bit_offset: uint64) -> ssize_t

# 0: find_member(pattern_udm: udm_t *, strmem_flags: int) -> ssize_t

tinfo_t::find_udm 
        
@returns the index of the found member or -1

# 1: find_member(name: str) -> ssize_t


# 2: find_member(bit_offset: uint64) -> ssize_t

"""
        return _ida_typeinf.udt_type_data_t_find_member(self, *args)

    def get_best_fit_member(self, disp):
        """Get the member that is most likely referenced by the specified offset.

@param disp the byte offset
@return a tuple (int, udm_t), or (-1, None) if member not found"""
        return _ida_typeinf.udt_type_data_t_get_best_fit_member(self, disp)
    __swig_destroy__ = _ida_typeinf.delete_udt_type_data_t

    def __init__(self):
        _ida_typeinf.udt_type_data_t_swiginit(self, _ida_typeinf.
            new_udt_type_data_t())


_ida_typeinf.udt_type_data_t_swigregister(udt_type_data_t)
STRUC_SEPARATOR = _ida_typeinf.STRUC_SEPARATOR
"""structname.fieldname
"""
VTBL_SUFFIX = _ida_typeinf.VTBL_SUFFIX
VTBL_MEMNAME = _ida_typeinf.VTBL_MEMNAME


def stroff_as_size(plen: int, tif: 'tinfo_t', value: 'asize_t') ->bool:
    """Should display a structure offset expression as the structure size?
"""
    return _ida_typeinf.stroff_as_size(plen, tif, value)


class udm_visitor_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def visit_udm(self, tid: 'tid_t', tif: 'tinfo_t', udt:
        'udt_type_data_t', idx: 'ssize_t') ->int:
        """@param tid: udt tid
@param tif: udt type info (may be nullptr for corrupted idbs)
@param udt: udt type data (may be nullptr for corrupted idbs)
@param idx: the index of udt the member (may be -1 if udm was not found)"""
        return _ida_typeinf.udm_visitor_t_visit_udm(self, tid, tif, udt, idx)
    __swig_destroy__ = _ida_typeinf.delete_udm_visitor_t

    def __init__(self):
        if self.__class__ == udm_visitor_t:
            _self = None
        else:
            _self = self
        _ida_typeinf.udm_visitor_t_swiginit(self, _ida_typeinf.
            new_udm_visitor_t(_self))

    def __disown__(self):
        self.this.disown()
        _ida_typeinf.disown_udm_visitor_t(self)
        return weakref.proxy(self)


_ida_typeinf.udm_visitor_t_swigregister(udm_visitor_t)


def visit_stroff_udms(sfv: 'udm_visitor_t', path: 'tid_t const *', disp:
    'adiff_t *', appzero: bool) ->'adiff_t *':
    """Visit structure fields in a stroff expression or in a reference to a struct data variable. This function can be used to enumerate all components of an expression like 'a.b.c'. 
        
@param sfv: visitor object
@param path: struct path (path[0] contains the initial struct id)
@param disp: offset into structure
@param appzero: should visit field at offset zero?
@returns visitor result"""
    return _ida_typeinf.visit_stroff_udms(sfv, path, disp, appzero)


class bitfield_type_data_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    nbytes: 'uchar' = property(_ida_typeinf.bitfield_type_data_t_nbytes_get,
        _ida_typeinf.bitfield_type_data_t_nbytes_set)
    """enclosing type size (1,2,4,8 bytes)
"""
    width: 'uchar' = property(_ida_typeinf.bitfield_type_data_t_width_get,
        _ida_typeinf.bitfield_type_data_t_width_set)
    """number of bits
"""
    is_unsigned: 'bool' = property(_ida_typeinf.
        bitfield_type_data_t_is_unsigned_get, _ida_typeinf.
        bitfield_type_data_t_is_unsigned_set)
    """is bitfield unsigned?
"""

    def __init__(self, _nbytes: 'uchar'=0, _width: 'uchar'=0, _is_unsigned:
        bool=False):
        _ida_typeinf.bitfield_type_data_t_swiginit(self, _ida_typeinf.
            new_bitfield_type_data_t(_nbytes, _width, _is_unsigned))

    def __eq__(self, r: 'bitfield_type_data_t') ->bool:
        return _ida_typeinf.bitfield_type_data_t___eq__(self, r)

    def __ne__(self, r: 'bitfield_type_data_t') ->bool:
        return _ida_typeinf.bitfield_type_data_t___ne__(self, r)

    def __lt__(self, r: 'bitfield_type_data_t') ->bool:
        return _ida_typeinf.bitfield_type_data_t___lt__(self, r)

    def __gt__(self, r: 'bitfield_type_data_t') ->bool:
        return _ida_typeinf.bitfield_type_data_t___gt__(self, r)

    def __le__(self, r: 'bitfield_type_data_t') ->bool:
        return _ida_typeinf.bitfield_type_data_t___le__(self, r)

    def __ge__(self, r: 'bitfield_type_data_t') ->bool:
        return _ida_typeinf.bitfield_type_data_t___ge__(self, r)

    def compare(self, r: 'bitfield_type_data_t') ->int:
        return _ida_typeinf.bitfield_type_data_t_compare(self, r)

    def swap(self, r: 'bitfield_type_data_t') ->None:
        return _ida_typeinf.bitfield_type_data_t_swap(self, r)

    def is_valid_bitfield(self) ->bool:
        return _ida_typeinf.bitfield_type_data_t_is_valid_bitfield(self)
    __swig_destroy__ = _ida_typeinf.delete_bitfield_type_data_t


_ida_typeinf.bitfield_type_data_t_swigregister(bitfield_type_data_t)
TPOS_LNNUM = _ida_typeinf.TPOS_LNNUM
TPOS_REGCMT = _ida_typeinf.TPOS_REGCMT


def is_one_bit_mask(mask: int) ->bool:
    """Is bitmask one bit?
"""
    return _ida_typeinf.is_one_bit_mask(mask)


def inf_pack_stkargs(*args) ->bool:
    return _ida_typeinf.inf_pack_stkargs(*args)


def inf_big_arg_align(*args) ->bool:
    return _ida_typeinf.inf_big_arg_align(*args)


def inf_huge_arg_align(*args) ->bool:
    return _ida_typeinf.inf_huge_arg_align(*args)


class type_mods_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    type: 'tinfo_t' = property(_ida_typeinf.type_mods_t_type_get,
        _ida_typeinf.type_mods_t_type_set)
    """current type
"""
    name: 'qstring' = property(_ida_typeinf.type_mods_t_name_get,
        _ida_typeinf.type_mods_t_name_set)
    """current type name
"""
    cmt: 'qstring' = property(_ida_typeinf.type_mods_t_cmt_get,
        _ida_typeinf.type_mods_t_cmt_set)
    """comment for current type
"""
    flags: 'int' = property(_ida_typeinf.type_mods_t_flags_get,
        _ida_typeinf.type_mods_t_flags_set)
    """Type modification bits 
        """

    def clear(self) ->None:
        return _ida_typeinf.type_mods_t_clear(self)

    def set_new_type(self, t: 'tinfo_t') ->None:
        """The visit_type() function may optionally save the modified type info. Use the following functions for that. The new name and comment will be applied only if the current tinfo element has storage for them. 
        """
        return _ida_typeinf.type_mods_t_set_new_type(self, t)

    def set_new_name(self, n: str) ->None:
        return _ida_typeinf.type_mods_t_set_new_name(self, n)

    def set_new_cmt(self, c: str, rptcmt: bool) ->None:
        return _ida_typeinf.type_mods_t_set_new_cmt(self, c, rptcmt)

    def has_type(self) ->bool:
        return _ida_typeinf.type_mods_t_has_type(self)

    def has_name(self) ->bool:
        return _ida_typeinf.type_mods_t_has_name(self)

    def has_cmt(self) ->bool:
        return _ida_typeinf.type_mods_t_has_cmt(self)

    def is_rptcmt(self) ->bool:
        return _ida_typeinf.type_mods_t_is_rptcmt(self)

    def has_info(self) ->bool:
        return _ida_typeinf.type_mods_t_has_info(self)

    def __init__(self):
        _ida_typeinf.type_mods_t_swiginit(self, _ida_typeinf.new_type_mods_t())
    __swig_destroy__ = _ida_typeinf.delete_type_mods_t


_ida_typeinf.type_mods_t_swigregister(type_mods_t)
TVIS_TYPE = _ida_typeinf.TVIS_TYPE
"""new type info is present
"""
TVIS_NAME = _ida_typeinf.TVIS_NAME
"""new name is present (only for funcargs and udt members)
"""
TVIS_CMT = _ida_typeinf.TVIS_CMT
"""new comment is present (only for udt members)
"""
TVIS_RPTCMT = _ida_typeinf.TVIS_RPTCMT
"""the new comment is repeatable
"""


class tinfo_visitor_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    state: 'int' = property(_ida_typeinf.tinfo_visitor_t_state_get,
        _ida_typeinf.tinfo_visitor_t_state_set)
    """tinfo visitor states 
        """

    def __init__(self, s: int=0):
        if self.__class__ == tinfo_visitor_t:
            _self = None
        else:
            _self = self
        _ida_typeinf.tinfo_visitor_t_swiginit(self, _ida_typeinf.
            new_tinfo_visitor_t(_self, s))
    __swig_destroy__ = _ida_typeinf.delete_tinfo_visitor_t

    def visit_type(self, out: 'type_mods_t', tif: 'tinfo_t', name: str, cmt:
        str) ->int:
        """Visit a subtype. this function must be implemented in the derived class. it may optionally fill out with the new type info. this can be used to modify types (in this case the 'out' argument of apply_to() may not be nullptr) return 0 to continue the traversal. return !=0 to stop the traversal. 
        """
        return _ida_typeinf.tinfo_visitor_t_visit_type(self, out, tif, name,
            cmt)

    def prune_now(self) ->None:
        """To refuse to visit children of the current type, use this:
"""
        return _ida_typeinf.tinfo_visitor_t_prune_now(self)

    def apply_to(self, tif: 'tinfo_t', out: 'type_mods_t'=None, name: str=
        None, cmt: str=None) ->int:
        """Call this function to initiate the traversal.
"""
        return _ida_typeinf.tinfo_visitor_t_apply_to(self, tif, out, name, cmt)

    def __disown__(self):
        self.this.disown()
        _ida_typeinf.disown_tinfo_visitor_t(self)
        return weakref.proxy(self)


_ida_typeinf.tinfo_visitor_t_swigregister(tinfo_visitor_t)
TVST_PRUNE = _ida_typeinf.TVST_PRUNE
"""don't visit children of current type
"""
TVST_DEF = _ida_typeinf.TVST_DEF
"""visit type definition (meaningful for typerefs)
"""
TVST_LEVEL = _ida_typeinf.TVST_LEVEL


class regobj_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    regidx: 'int' = property(_ida_typeinf.regobj_t_regidx_get, _ida_typeinf
        .regobj_t_regidx_set)
    """index into dbg->registers
"""
    relocate: 'int' = property(_ida_typeinf.regobj_t_relocate_get,
        _ida_typeinf.regobj_t_relocate_set)
    """0-plain num, 1-must relocate
"""
    value: 'bytevec_t' = property(_ida_typeinf.regobj_t_value_get,
        _ida_typeinf.regobj_t_value_set)

    def size(self) ->'size_t':
        return _ida_typeinf.regobj_t_size(self)

    def __init__(self):
        _ida_typeinf.regobj_t_swiginit(self, _ida_typeinf.new_regobj_t())
    __swig_destroy__ = _ida_typeinf.delete_regobj_t


_ida_typeinf.regobj_t_swigregister(regobj_t)


class regobjs_t(regobjvec_t):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_typeinf.regobjs_t_swiginit(self, _ida_typeinf.new_regobjs_t())
    __swig_destroy__ = _ida_typeinf.delete_regobjs_t


_ida_typeinf.regobjs_t_swigregister(regobjs_t)


def unpack_idcobj_from_idb(obj: 'idc_value_t *', tif: 'tinfo_t', ea:
    ida_idaapi.ea_t, off0: 'bytevec_t const *', pio_flags: int=0) ->'error_t':
    """Collection of register objects.

Read a typed idc object from the database 
        """
    return _ida_typeinf.unpack_idcobj_from_idb(obj, tif, ea, off0, pio_flags)


PIO_NOATTR_FAIL = _ida_typeinf.PIO_NOATTR_FAIL
"""missing attributes are not ok
"""
PIO_IGNORE_PTRS = _ida_typeinf.PIO_IGNORE_PTRS
"""do not follow pointers
"""


def unpack_idcobj_from_bv(obj: 'idc_value_t *', tif: 'tinfo_t', bytes:
    'bytevec_t const &', pio_flags: int=0) ->'error_t':
    """Read a typed idc object from the byte vector.
"""
    return _ida_typeinf.unpack_idcobj_from_bv(obj, tif, bytes, pio_flags)


def pack_idcobj_to_idb(obj: 'idc_value_t const *', tif: 'tinfo_t', ea:
    ida_idaapi.ea_t, pio_flags: int=0) ->'error_t':
    """Write a typed idc object to the database.
"""
    return _ida_typeinf.pack_idcobj_to_idb(obj, tif, ea, pio_flags)


def pack_idcobj_to_bv(obj: 'idc_value_t const *', tif: 'tinfo_t', bytes:
    'relobj_t', objoff: 'void *', pio_flags: int=0) ->'error_t':
    """Write a typed idc object to the byte vector. Byte vector may be non-empty, this function will append data to it 
        """
    return _ida_typeinf.pack_idcobj_to_bv(obj, tif, bytes, objoff, pio_flags)


def apply_tinfo_to_stkarg(insn: 'insn_t const &', x: 'op_t const &', v: int,
    tif: 'tinfo_t', name: str) ->bool:
    """Helper function for the processor modules. to be called from processor_t::use_stkarg_type 
        """
    return _ida_typeinf.apply_tinfo_to_stkarg(insn, x, v, tif, name)


class argtinfo_helper_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    reserved: 'size_t' = property(_ida_typeinf.
        argtinfo_helper_t_reserved_get, _ida_typeinf.
        argtinfo_helper_t_reserved_set)
    __swig_destroy__ = _ida_typeinf.delete_argtinfo_helper_t

    def set_op_tinfo(self, insn: 'insn_t const &', x: 'op_t const &', tif:
        'tinfo_t', name: str) ->bool:
        """Set the operand type as specified.
"""
        return _ida_typeinf.argtinfo_helper_t_set_op_tinfo(self, insn, x,
            tif, name)

    def is_stkarg_load(self, insn: 'insn_t const &', src: 'int *', dst: 'int *'
        ) ->bool:
        """Is the current insn a stkarg load?. if yes:
* src: index of the source operand in insn_t::ops
* dst: index of the destination operand in insn_t::ops insn_t::ops[dst].addr is expected to have the stack offset 


        """
        return _ida_typeinf.argtinfo_helper_t_is_stkarg_load(self, insn,
            src, dst)

    def has_delay_slot(self, arg0: ida_idaapi.ea_t) ->bool:
        """The call instruction with a delay slot?.
"""
        return _ida_typeinf.argtinfo_helper_t_has_delay_slot(self, arg0)

    def use_arg_tinfos(self, caller: ida_idaapi.ea_t, fti:
        'func_type_data_t', rargs: 'funcargvec_t') ->None:
        """This function is to be called by the processor module in response to ev_use_arg_types. 
        """
        return _ida_typeinf.argtinfo_helper_t_use_arg_tinfos(self, caller,
            fti, rargs)

    def __init__(self):
        if self.__class__ == argtinfo_helper_t:
            _self = None
        else:
            _self = self
        _ida_typeinf.argtinfo_helper_t_swiginit(self, _ida_typeinf.
            new_argtinfo_helper_t(_self))

    def __disown__(self):
        self.this.disown()
        _ida_typeinf.disown_argtinfo_helper_t(self)
        return weakref.proxy(self)


_ida_typeinf.argtinfo_helper_t_swigregister(argtinfo_helper_t)


def gen_use_arg_tinfos(_this: 'argtinfo_helper_t', caller: ida_idaapi.ea_t,
    fti: 'func_type_data_t', rargs: 'funcargvec_t') ->None:
    """Do not call this function directly, use argtinfo_helper_t.
"""
    return _ida_typeinf.gen_use_arg_tinfos(_this, caller, fti, rargs)


def func_has_stkframe_hole(ea: ida_idaapi.ea_t, fti: 'func_type_data_t'
    ) ->bool:
    """Looks for a hole at the beginning of the stack arguments. Will make use of the IDB's func_t function at that place (if present) to help determine the presence of such a hole. 
        """
    return _ida_typeinf.func_has_stkframe_hole(ea, fti)


class lowertype_helper_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')

    def __init__(self, *args, **kwargs):
        raise AttributeError('No constructor defined - class is abstract')
    __repr__ = _swig_repr
    __swig_destroy__ = _ida_typeinf.delete_lowertype_helper_t

    def func_has_stkframe_hole(self, candidate: 'tinfo_t', candidate_data:
        'func_type_data_t') ->bool:
        return _ida_typeinf.lowertype_helper_t_func_has_stkframe_hole(self,
            candidate, candidate_data)

    def get_func_purged_bytes(self, candidate: 'tinfo_t', candidate_data:
        'func_type_data_t') ->int:
        return _ida_typeinf.lowertype_helper_t_get_func_purged_bytes(self,
            candidate, candidate_data)


_ida_typeinf.lowertype_helper_t_swigregister(lowertype_helper_t)


class ida_lowertype_helper_t(lowertype_helper_t):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, _tif: 'tinfo_t', _ea: ida_idaapi.ea_t, _pb: int):
        _ida_typeinf.ida_lowertype_helper_t_swiginit(self, _ida_typeinf.
            new_ida_lowertype_helper_t(_tif, _ea, _pb))

    def func_has_stkframe_hole(self, candidate: 'tinfo_t', candidate_data:
        'func_type_data_t') ->bool:
        return _ida_typeinf.ida_lowertype_helper_t_func_has_stkframe_hole(self,
            candidate, candidate_data)

    def get_func_purged_bytes(self, candidate: 'tinfo_t', arg3:
        'func_type_data_t') ->int:
        return _ida_typeinf.ida_lowertype_helper_t_get_func_purged_bytes(self,
            candidate, arg3)
    __swig_destroy__ = _ida_typeinf.delete_ida_lowertype_helper_t


_ida_typeinf.ida_lowertype_helper_t_swigregister(ida_lowertype_helper_t)


def lower_type(til: 'til_t', tif: 'tinfo_t', name: str=None, _helper:
    'lowertype_helper_t'=None) ->int:
    """Lower type. Inspect the type and lower all function subtypes using lower_func_type(). 
We call the prototypes usually encountered in source files "high level" 
They may have implicit arguments, array arguments, big structure retvals, etc 
We introduce explicit arguments (i.e. 'this' pointer) and call the result 
"low level prototype". See FTI_HIGH.
In order to improve heuristics for recognition of big structure retvals, 
it is recommended to pass a helper that will be used to make decisions. 
That helper will be used only for lowering 'tif', and not for the children 
types walked through by recursion. 
        
@retval 1: removed FTI_HIGH,
@retval 2: made substantial changes
@retval -1: failure"""
    return _ida_typeinf.lower_type(til, tif, name, _helper)


def replace_ordinal_typerefs(til: 'til_t', tif: 'tinfo_t') ->int:
    """Replace references to ordinal types by name references. This function 'unties' the type from the current local type library and makes it easier to export it. 
        
@param til: type library to use. may be nullptr.
@param tif: type to modify (in/out)
@retval number: of replaced subtypes, -1 on failure"""
    return _ida_typeinf.replace_ordinal_typerefs(til, tif)


UTP_ENUM = _ida_typeinf.UTP_ENUM
UTP_STRUCT = _ida_typeinf.UTP_STRUCT


def begin_type_updating(utp: 'update_type_t') ->None:
    """Mark the beginning of a large update operation on the types. Can be used with add_enum_member(), add_struc_member, etc... Also see end_type_updating() 
        """
    return _ida_typeinf.begin_type_updating(utp)


def end_type_updating(utp: 'update_type_t') ->None:
    """Mark the end of a large update operation on the types (see begin_type_updating())
"""
    return _ida_typeinf.end_type_updating(utp)


def get_named_type_tid(name: str) ->'tid_t':
    """Get named local type TID 
        
@param name: type name
@returns TID or BADADDR"""
    return _ida_typeinf.get_named_type_tid(name)


def get_tid_name(tid: 'tid_t') ->str:
    """Get a type name for the specified TID 
        
@param tid: type TID
@returns true if there is type with TID"""
    return _ida_typeinf.get_tid_name(tid)


def get_tid_ordinal(tid: 'tid_t') ->int:
    """Get type ordinal number for TID 
        
@param tid: type/enum constant/udt member TID
@returns type ordinal number or 0"""
    return _ida_typeinf.get_tid_ordinal(tid)


def get_udm_by_fullname(udm: 'udm_t', fullname: str) ->'ssize_t':
    """Get udt member by full name 
        
@param udm: member, can be NULL
@param fullname: udt member name in format <udt name>.<member name>
@returns member index into udt_type_data_t or -1"""
    return _ida_typeinf.get_udm_by_fullname(udm, fullname)


def get_idainfo_by_udm(*args) ->bool:
    """Calculate IDA info from udt member 
        
@param udm: udt member
@param refinfo_ea: if specified will be used to adjust the refinfo_t data"""
    return _ida_typeinf.get_idainfo_by_udm(*args)


def create_enum_type(enum_name: str, ei: 'enum_type_data_t', enum_width:
    int, sign: 'type_sign_t', convert_to_bitmask: bool, enum_cmt: str=None
    ) ->'tid_t':
    """Create type enum 
        
@param enum_name: type name
@param ei: enum type data
@param enum_width: the width of an enum element allowed values: 0 (unspecified),1,2,4,8,16,32,64
@param sign: enum sign
@param convert_to_bitmask: try convert enum to bitmask enum
@param enum_cmt: enum type comment
@returns enum TID"""
    return _ida_typeinf.create_enum_type(enum_name, ei, enum_width, sign,
        convert_to_bitmask, enum_cmt)


class valstr_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    oneline: 'qstring' = property(_ida_typeinf.valstr_t_oneline_get,
        _ida_typeinf.valstr_t_oneline_set)
    """result if printed on one line in UTF-8 encoding
"""
    length: 'size_t' = property(_ida_typeinf.valstr_t_length_get,
        _ida_typeinf.valstr_t_length_set)
    """length if printed on one line
"""
    members: 'valstrs_t *' = property(_ida_typeinf.valstr_t_members_get,
        _ida_typeinf.valstr_t_members_set)
    """strings for members, each member separately
"""
    info: 'valinfo_t *' = property(_ida_typeinf.valstr_t_info_get,
        _ida_typeinf.valstr_t_info_set)
    """additional info
"""
    props: 'int' = property(_ida_typeinf.valstr_t_props_get, _ida_typeinf.
        valstr_t_props_set)
    """temporary properties, used internally
"""

    def __init__(self):
        _ida_typeinf.valstr_t_swiginit(self, _ida_typeinf.new_valstr_t())
    __swig_destroy__ = _ida_typeinf.delete_valstr_t


_ida_typeinf.valstr_t_swigregister(valstr_t)
VALSTR_OPEN = _ida_typeinf.VALSTR_OPEN
"""printed opening curly brace '{'
"""


class valstrs_t(valstrvec_t):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_typeinf.valstrs_t_swiginit(self, _ida_typeinf.new_valstrs_t())
    __swig_destroy__ = _ida_typeinf.delete_valstrs_t


_ida_typeinf.valstrs_t_swigregister(valstrs_t)


class text_sink_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    __swig_destroy__ = _ida_typeinf.delete_text_sink_t

    def _print(self, str: str) ->int:
        return _ida_typeinf.text_sink_t__print(self, str)

    def __init__(self):
        if self.__class__ == text_sink_t:
            _self = None
        else:
            _self = self
        _ida_typeinf.text_sink_t_swiginit(self, _ida_typeinf.
            new_text_sink_t(_self))

    def __disown__(self):
        self.this.disown()
        _ida_typeinf.disown_text_sink_t(self)
        return weakref.proxy(self)


_ida_typeinf.text_sink_t_swigregister(text_sink_t)
PDF_INCL_DEPS = _ida_typeinf.PDF_INCL_DEPS
"""Include all type dependencies.
"""
PDF_DEF_FWD = _ida_typeinf.PDF_DEF_FWD
"""Allow forward declarations.
"""
PDF_DEF_BASE = _ida_typeinf.PDF_DEF_BASE
"""Include base types: __int8, __int16, etc..
"""
PDF_HEADER_CMT = _ida_typeinf.PDF_HEADER_CMT
"""Prepend output with a descriptive comment.
"""


def calc_number_of_children(loc: 'argloc_t', tif: 'tinfo_t', dont_deref_ptr:
    bool=False) ->int:
    """Calculate max number of lines of a formatted c data, when expanded (PTV_EXPAND). 
        
@param loc: location of the data (ALOC_STATIC or ALOC_CUSTOM)
@param tif: type info
@param dont_deref_ptr: consider 'ea' as the ptr value
@retval 0: data is not expandable
@retval -1: error, see qerrno
@retval else: the max number of lines"""
    return _ida_typeinf.calc_number_of_children(loc, tif, dont_deref_ptr)


def get_enum_member_expr(tif: 'tinfo_t', serial: int, value: 'uint64') ->str:
    """Return a C expression that can be used to represent an enum member. If the value does not correspond to any single enum member, this function tries to find a bitwise combination of enum members that correspond to it. If more than half of value bits do not match any enum members, it fails. 
        
@param tif: enumeration type
@param serial: which enumeration member to use (0 means the first with the given value)
@param value: value to search in the enumeration type
@returns success"""
    return _ida_typeinf.get_enum_member_expr(tif, serial, value)


class til_symbol_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    name: 'char const *' = property(_ida_typeinf.til_symbol_t_name_get,
        _ida_typeinf.til_symbol_t_name_set)
    """symbol name
"""
    til: 'til_t const *' = property(_ida_typeinf.til_symbol_t_til_get,
        _ida_typeinf.til_symbol_t_til_set)
    """pointer to til
"""

    def __init__(self, n: str=None, t: 'til_t'=None):
        _ida_typeinf.til_symbol_t_swiginit(self, _ida_typeinf.
            new_til_symbol_t(n, t))
    __swig_destroy__ = _ida_typeinf.delete_til_symbol_t


_ida_typeinf.til_symbol_t_swigregister(til_symbol_t)


class predicate_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def should_display(self, til: 'til_t', name: str, type:
        'type_t const *', fields: 'p_list const *') ->bool:
        return _ida_typeinf.predicate_t_should_display(self, til, name,
            type, fields)
    __swig_destroy__ = _ida_typeinf.delete_predicate_t

    def __init__(self):
        if self.__class__ == predicate_t:
            _self = None
        else:
            _self = self
        _ida_typeinf.predicate_t_swiginit(self, _ida_typeinf.
            new_predicate_t(_self))

    def __disown__(self):
        self.this.disown()
        _ida_typeinf.disown_predicate_t(self)
        return weakref.proxy(self)


_ida_typeinf.predicate_t_swigregister(predicate_t)


def choose_named_type(out_sym: 'til_symbol_t', root_til: 'til_t', title:
    str, ntf_flags: int, predicate: 'predicate_t'=None) ->bool:
    """Choose a type from a type library. 
        
@param out_sym: pointer to be filled with the chosen type
@param root_til: pointer to starting til (the function will inspect the base tils if allowed by flags)
@param title: title of listbox to display
@param ntf_flags: combination of Flags for named types
@param predicate: predicate to select types to display (maybe nullptr)
@returns false if nothing is chosen, otherwise true"""
    return _ida_typeinf.choose_named_type(out_sym, root_til, title,
        ntf_flags, predicate)


def choose_local_tinfo(ti: 'til_t', title: str, func:
    'local_tinfo_predicate_t *'=None, def_ord: int=0, ud: 'void *'=None) ->int:
    """Choose a type from the local type library. 
        
@param ti: pointer to til
@param title: title of listbox to display
@param func: predicate to select types to display (maybe nullptr)
@param def_ord: ordinal to position cursor before choose
@param ud: user data
@returns == 0 means nothing is chosen, otherwise an ordinal number"""
    return _ida_typeinf.choose_local_tinfo(ti, title, func, def_ord, ud)


def choose_local_tinfo_and_delta(delta: 'int32 *', ti: 'til_t', title: str,
    func: 'local_tinfo_predicate_t *'=None, def_ord: int=0, ud: 'void *'=None
    ) ->int:
    """Choose a type from the local type library and specify the pointer shift value. 
        
@param delta: pointer shift value
@param ti: pointer to til
@param title: title of listbox to display
@param func: predicate to select types to display (maybe nullptr)
@param def_ord: ordinal to position cursor before choose
@param ud: user data
@returns == 0 means nothing is chosen, otherwise an ordinal number"""
    return _ida_typeinf.choose_local_tinfo_and_delta(delta, ti, title, func,
        def_ord, ud)


class til_type_ref_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    cb: 'size_t' = property(_ida_typeinf.til_type_ref_t_cb_get,
        _ida_typeinf.til_type_ref_t_cb_set)
    tif: 'tinfo_t' = property(_ida_typeinf.til_type_ref_t_tif_get,
        _ida_typeinf.til_type_ref_t_tif_set)
    cursor: 'tif_cursor_t' = property(_ida_typeinf.
        til_type_ref_t_cursor_get, _ida_typeinf.til_type_ref_t_cursor_set)
    ordinal: 'uint32' = property(_ida_typeinf.til_type_ref_t_ordinal_get,
        _ida_typeinf.til_type_ref_t_ordinal_set)
    is_writable: 'bool' = property(_ida_typeinf.
        til_type_ref_t_is_writable_get, _ida_typeinf.
        til_type_ref_t_is_writable_set)
    is_detached: 'bool' = property(_ida_typeinf.
        til_type_ref_t_is_detached_get, _ida_typeinf.
        til_type_ref_t_is_detached_set)
    is_forward: 'bool' = property(_ida_typeinf.
        til_type_ref_t_is_forward_get, _ida_typeinf.
        til_type_ref_t_is_forward_set)
    kind: 'type_t' = property(_ida_typeinf.til_type_ref_t_kind_get,
        _ida_typeinf.til_type_ref_t_kind_set)
    memidx: 'ssize_t' = property(_ida_typeinf.til_type_ref_t_memidx_get,
        _ida_typeinf.til_type_ref_t_memidx_set)
    nmembers: 'size_t' = property(_ida_typeinf.til_type_ref_t_nmembers_get,
        _ida_typeinf.til_type_ref_t_nmembers_set)
    udm: 'udm_t' = property(_ida_typeinf.til_type_ref_t_udm_get,
        _ida_typeinf.til_type_ref_t_udm_set)
    """BTF_STRUCT or BTF_UNION: the current member.
"""
    total_size: 'size_t' = property(_ida_typeinf.
        til_type_ref_t_total_size_get, _ida_typeinf.
        til_type_ref_t_total_size_set)
    unpadded_size: 'size_t' = property(_ida_typeinf.
        til_type_ref_t_unpadded_size_get, _ida_typeinf.
        til_type_ref_t_unpadded_size_set)
    last_udm_offset: 'uint64' = property(_ida_typeinf.
        til_type_ref_t_last_udm_offset_get, _ida_typeinf.
        til_type_ref_t_last_udm_offset_set)
    bucket_start: 'uint64' = property(_ida_typeinf.
        til_type_ref_t_bucket_start_get, _ida_typeinf.
        til_type_ref_t_bucket_start_set)
    bf_bitoff: 'int' = property(_ida_typeinf.til_type_ref_t_bf_bitoff_get,
        _ida_typeinf.til_type_ref_t_bf_bitoff_set)
    offset: 'uint64' = property(_ida_typeinf.til_type_ref_t_offset_get,
        _ida_typeinf.til_type_ref_t_offset_set)
    edm: 'edm_t' = property(_ida_typeinf.til_type_ref_t_edm_get,
        _ida_typeinf.til_type_ref_t_edm_set)
    """BTF_ENUM: the current enum member.
"""
    fa: 'funcarg_t const *' = property(_ida_typeinf.til_type_ref_t_fa_get,
        _ida_typeinf.til_type_ref_t_fa_set)
    """BT_FUNC: the current argument, nullptr - ellipsis.
"""

    def clear(self) ->None:
        return _ida_typeinf.til_type_ref_t_clear(self)

    def on_member(self) ->bool:
        return _ida_typeinf.til_type_ref_t_on_member(self)

    def is_typedef(self) ->bool:
        return _ida_typeinf.til_type_ref_t_is_typedef(self)

    def is_struct(self) ->bool:
        return _ida_typeinf.til_type_ref_t_is_struct(self)

    def is_union(self) ->bool:
        return _ida_typeinf.til_type_ref_t_is_union(self)

    def is_enum(self) ->bool:
        return _ida_typeinf.til_type_ref_t_is_enum(self)

    def is_func(self) ->bool:
        return _ida_typeinf.til_type_ref_t_is_func(self)

    def is_udt(self) ->bool:
        return _ida_typeinf.til_type_ref_t_is_udt(self)

    def __init__(self):
        _ida_typeinf.til_type_ref_t_swiginit(self, _ida_typeinf.
            new_til_type_ref_t())
    __swig_destroy__ = _ida_typeinf.delete_til_type_ref_t


_ida_typeinf.til_type_ref_t_swigregister(til_type_ref_t)


def idc_parse_decl(til: til_t, decl: str, flags: int) ->Tuple[str, bytes, bytes
    ]:
    """    """
    return _ida_typeinf.idc_parse_decl(til, decl, flags)


def calc_type_size(til: til_t, type: bytes):
    """Returns the size of a type
@param til: Type info library. 'None' can be passed.
@param type: serialized type byte string
@return:
    - None on failure
    - The size of the type"""
    return _ida_typeinf.calc_type_size(til, type)


def apply_type(til: til_t, type: bytes, fields: bytes, ea: ida_idaapi.ea_t,
    flags: int) ->bool:
    """Apply the specified type to the address

@param til: Type info library. 'None' can be used.
@param type: type string
@param fields: fields string (may be empty or None)
@param ea: the address of the object
@param flags: combination of TINFO_... constants or 0
@return: Boolean"""
    return _ida_typeinf.apply_type(til, type, fields, ea, flags)


def get_arg_addrs(caller: ida_idaapi.ea_t):
    """Retrieve addresses of argument initialization instructions

@param caller: the address of the call instruction
@return: list of instruction addresses"""
    return _ida_typeinf.get_arg_addrs(caller)


def unpack_object_from_idb(til: til_t, type: bytes, fields: bytes, ea:
    ida_idaapi.ea_t, pio_flags: int=0):
    """Unpacks from the database at 'ea' to an object.
Please refer to unpack_object_from_bv()"""
    return _ida_typeinf.unpack_object_from_idb(til, type, fields, ea, pio_flags
        )


def unpack_object_from_bv(til: til_t, type: bytes, fields: bytes, bytes,
    pio_flags: int=0):
    """Unpacks a buffer into an object.
Returns the error_t returned by idaapi.pack_object_to_idb

@param til: Type library. 'None' can be passed.
@param type: type string
@param fields: fields string (may be empty or None)
@param bytes: the bytes to unpack
@param pio_flags: flags used while unpacking
@return:
    - tuple(0, err) on failure
    - tuple(1, obj) on success"""
    return _ida_typeinf.unpack_object_from_bv(til, type, fields, bytes,
        pio_flags)


def pack_object_to_idb(obj, til: til_t, type: bytes, fields: bytes, ea:
    ida_idaapi.ea_t, pio_flags: int=0):
    """Write a typed object to the database.
Raises an exception if wrong parameters were passed or conversion fails
Returns the error_t returned by idaapi.pack_object_to_idb

@param til: Type library. 'None' can be passed.
@param type: type string
@param fields: fields string (may be empty or None)
@param ea: ea to be used while packing
@param pio_flags: flags used while unpacking"""
    return _ida_typeinf.pack_object_to_idb(obj, til, type, fields, ea,
        pio_flags)


def pack_object_to_bv(obj, til: til_t, type: bytes, fields: bytes, base_ea:
    ida_idaapi.ea_t, pio_flags: int=0):
    """Packs a typed object to a string

@param til: Type library. 'None' can be passed.
@param type: type string
@param fields: fields string (may be empty or None)
@param base_ea: base ea used to relocate the pointers in the packed object
@param pio_flags: flags used while unpacking
@return:
    tuple(0, err_code) on failure
    tuple(1, packed_buf) on success"""
    return _ida_typeinf.pack_object_to_bv(obj, til, type, fields, base_ea,
        pio_flags)


PT_FILE = _ida_typeinf.PT_FILE


def idc_parse_types(input: str, flags: int) ->int:
    return _ida_typeinf.idc_parse_types(input, flags)


def idc_get_type_raw(ea: ida_idaapi.ea_t) ->'PyObject *':
    return _ida_typeinf.idc_get_type_raw(ea)


def idc_get_local_type_raw(ordinal) ->Tuple[bytes, bytes]:
    """    """
    return _ida_typeinf.idc_get_local_type_raw(ordinal)


def idc_guess_type(ea: ida_idaapi.ea_t) ->str:
    return _ida_typeinf.idc_guess_type(ea)


def idc_get_type(ea: ida_idaapi.ea_t) ->str:
    return _ida_typeinf.idc_get_type(ea)


def idc_set_local_type(ordinal: int, dcl: str, flags: int) ->int:
    return _ida_typeinf.idc_set_local_type(ordinal, dcl, flags)


def idc_get_local_type(ordinal: int, flags: int) ->str:
    return _ida_typeinf.idc_get_local_type(ordinal, flags)


def idc_print_type(type: bytes, fields: bytes, name: str, flags: int) ->str:
    """    """
    return _ida_typeinf.idc_print_type(type, fields, name, flags)


def idc_get_local_type_name(ordinal: int) ->str:
    return _ida_typeinf.idc_get_local_type_name(ordinal)


def get_named_type(til: til_t, name: str, ntf_flags: int):
    """Get a type data by its name.

@param til: Type library
@param name: the type name
@param ntf_flags: a combination of NTF_* constants
@return:
    None on failure
    tuple(code, type_str, fields_str, cmt, field_cmts, sclass, value) on success"""
    return _ida_typeinf.get_named_type(til, name, ntf_flags)


def get_named_type64(til: til_t, name: str, ntf_flags: int=0) ->Union[Tuple
    [int, bytes, bytes, str, str, int, int], None]:
    """Get a named type from a type library.

Please use til_t.get_named_type instead."""
    return _ida_typeinf.get_named_type64(til, name, ntf_flags)


def print_decls(printer: text_sink_t, til: til_t, ordinals: List[int],
    flags: int) ->int:
    """Print types (and possibly their dependencies) in a format suitable for using in
a header file. This is the reverse parse_decls().

@param printer a handler for printing text
@param til the type library holding the ordinals
@param ordinals a list of ordinals corresponding to the types to print
@param flags a combination of PDF_ constants
@return
        >0: the number of types exported
         0: an error occurred
        <0: the negated number of types exported. There were minor errors and
            the resulting output might not be compilable."""
    return _ida_typeinf.print_decls(printer, til, ordinals, flags)


def remove_tinfo_pointer(tif: tinfo_t, name: str, til: til_t) ->Tuple[bool, str
    ]:
    """Remove pointer of a type. (i.e. convert "char *" into "char"). Optionally remove
the "lp" (or similar) prefix of the input name. If the input type is not a
pointer, then fail.

@param tif the type info
@param name the name of the type to "unpointerify"
@param til the type library
@return a tuple (success, new-name)"""
    return _ida_typeinf.remove_tinfo_pointer(tif, name, til)


def get_numbered_type(til: til_t, ordinal: int) ->Union[Tuple[bytes, bytes,
    str, str, int], None]:
    """Get a type from a type library, by its ordinal

Please use til_t.get_numbered_type instead."""
    return _ida_typeinf.get_numbered_type(til, ordinal)


def set_numbered_type(ti: 'til_t', ordinal: int, ntf_flags: int, name: str,
    type: 'type_t const *', fields: 'p_list const *'=None, cmt: str=None,
    fldcmts: 'p_list const *'=None, sclass: 'sclass_t const *'=None
    ) ->'tinfo_code_t':
    return _ida_typeinf.set_numbered_type(ti, ordinal, ntf_flags, name,
        type, fields, cmt, fldcmts, sclass)


import ida_idaapi
ida_idaapi._listify_types(reginfovec_t)
_real_cvar = cvar
_notify_idati = ida_idaapi._make_one_time_warning_message('idati',
    'get_idati()')


class _wrap_cvar(object):

    def __getattr__(self, attr):
        if attr == 'idati':
            _notify_idati()
            return get_idati()
        return getattr(_real_cvar, attr)

    def __setattr__(self, attr, value):
        if attr != 'idati':
            setattr(_real_cvar, attr, value)


cvar = _wrap_cvar()
sc_auto = SC_AUTO
sc_ext = SC_EXT
sc_friend = SC_FRIEND
sc_reg = SC_REG
sc_stat = SC_STAT
sc_type = SC_TYPE
sc_unk = SC_UNK
sc_virt = SC_VIRT
TERR_SAVE = TERR_SAVE_ERROR
TERR_WRONGNAME = TERR_BAD_NAME
BADORD = 4294967295
enum_member_vec_t = edmvec_t
enum_member_t = edm_t
udt_member_t = udm_t
tinfo_t.find_udt_member = tinfo_t.find_udm

```
