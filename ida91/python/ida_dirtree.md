```python
"""Types involved in grouping of item into folders.

The dirtree_t class is used to organize a directory tree on top of any collection that allows for accessing its elements by an id (inode).
No requirements are imposed on the inodes apart from the forbidden value -1 (used to denote a bad inode).
The dirspec_t class is used to specialize the dirtree. It can be used to introduce a directory structure for:
* local types
* structs
* enums
* functions
* names
* etc


"""
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_dirtree
else:
    import _ida_dirtree
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
SWIG_PYTHON_LEGACY_BOOL = _ida_dirtree.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi


class direntry_vec_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_dirtree.direntry_vec_t_swiginit(self, _ida_dirtree.
            new_direntry_vec_t(*args))
    __swig_destroy__ = _ida_dirtree.delete_direntry_vec_t

    def push_back(self, *args) ->'direntry_t &':
        return _ida_dirtree.direntry_vec_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_dirtree.direntry_vec_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_dirtree.direntry_vec_t_size(self)

    def empty(self) ->bool:
        return _ida_dirtree.direntry_vec_t_empty(self)

    def at(self, _idx: 'size_t') ->'direntry_t const &':
        return _ida_dirtree.direntry_vec_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_dirtree.direntry_vec_t_qclear(self)

    def clear(self) ->None:
        return _ida_dirtree.direntry_vec_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_dirtree.direntry_vec_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_dirtree.direntry_vec_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_dirtree.direntry_vec_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_dirtree.direntry_vec_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_dirtree.direntry_vec_t_truncate(self)

    def swap(self, r: 'direntry_vec_t') ->None:
        return _ida_dirtree.direntry_vec_t_swap(self, r)

    def extract(self) ->'direntry_t *':
        return _ida_dirtree.direntry_vec_t_extract(self)

    def inject(self, s: 'direntry_t', len: 'size_t') ->None:
        return _ida_dirtree.direntry_vec_t_inject(self, s, len)

    def __eq__(self, r: 'direntry_vec_t') ->bool:
        return _ida_dirtree.direntry_vec_t___eq__(self, r)

    def __ne__(self, r: 'direntry_vec_t') ->bool:
        return _ida_dirtree.direntry_vec_t___ne__(self, r)

    def begin(self, *args) ->'qvector< direntry_t >::const_iterator':
        return _ida_dirtree.direntry_vec_t_begin(self, *args)

    def end(self, *args) ->'qvector< direntry_t >::const_iterator':
        return _ida_dirtree.direntry_vec_t_end(self, *args)

    def insert(self, it: 'direntry_t', x: 'direntry_t'
        ) ->'qvector< direntry_t >::iterator':
        return _ida_dirtree.direntry_vec_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< direntry_t >::iterator':
        return _ida_dirtree.direntry_vec_t_erase(self, *args)

    def find(self, *args) ->'qvector< direntry_t >::const_iterator':
        return _ida_dirtree.direntry_vec_t_find(self, *args)

    def has(self, x: 'direntry_t') ->bool:
        return _ida_dirtree.direntry_vec_t_has(self, x)

    def add_unique(self, x: 'direntry_t') ->bool:
        return _ida_dirtree.direntry_vec_t_add_unique(self, x)

    def _del(self, x: 'direntry_t') ->bool:
        return _ida_dirtree.direntry_vec_t__del(self, x)

    def __len__(self) ->'size_t':
        return _ida_dirtree.direntry_vec_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'direntry_t const &':
        return _ida_dirtree.direntry_vec_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'direntry_t') ->None:
        return _ida_dirtree.direntry_vec_t___setitem__(self, i, v)

    def append(self, x: 'direntry_t') ->None:
        return _ida_dirtree.direntry_vec_t_append(self, x)

    def extend(self, x: 'direntry_vec_t') ->None:
        return _ida_dirtree.direntry_vec_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_dirtree.direntry_vec_t_swigregister(direntry_vec_t)


class dirtree_cursor_vec_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_dirtree.dirtree_cursor_vec_t_swiginit(self, _ida_dirtree.
            new_dirtree_cursor_vec_t(*args))
    __swig_destroy__ = _ida_dirtree.delete_dirtree_cursor_vec_t

    def push_back(self, *args) ->'dirtree_cursor_t &':
        return _ida_dirtree.dirtree_cursor_vec_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_dirtree.dirtree_cursor_vec_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_dirtree.dirtree_cursor_vec_t_size(self)

    def empty(self) ->bool:
        return _ida_dirtree.dirtree_cursor_vec_t_empty(self)

    def at(self, _idx: 'size_t') ->'dirtree_cursor_t const &':
        return _ida_dirtree.dirtree_cursor_vec_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_dirtree.dirtree_cursor_vec_t_qclear(self)

    def clear(self) ->None:
        return _ida_dirtree.dirtree_cursor_vec_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_dirtree.dirtree_cursor_vec_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_dirtree.dirtree_cursor_vec_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_dirtree.dirtree_cursor_vec_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_dirtree.dirtree_cursor_vec_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_dirtree.dirtree_cursor_vec_t_truncate(self)

    def swap(self, r: 'dirtree_cursor_vec_t') ->None:
        return _ida_dirtree.dirtree_cursor_vec_t_swap(self, r)

    def extract(self) ->'dirtree_cursor_t *':
        return _ida_dirtree.dirtree_cursor_vec_t_extract(self)

    def inject(self, s: 'dirtree_cursor_t', len: 'size_t') ->None:
        return _ida_dirtree.dirtree_cursor_vec_t_inject(self, s, len)

    def __eq__(self, r: 'dirtree_cursor_vec_t') ->bool:
        return _ida_dirtree.dirtree_cursor_vec_t___eq__(self, r)

    def __ne__(self, r: 'dirtree_cursor_vec_t') ->bool:
        return _ida_dirtree.dirtree_cursor_vec_t___ne__(self, r)

    def begin(self, *args) ->'qvector< dirtree_cursor_t >::const_iterator':
        return _ida_dirtree.dirtree_cursor_vec_t_begin(self, *args)

    def end(self, *args) ->'qvector< dirtree_cursor_t >::const_iterator':
        return _ida_dirtree.dirtree_cursor_vec_t_end(self, *args)

    def insert(self, it: 'dirtree_cursor_t', x: 'dirtree_cursor_t'
        ) ->'qvector< dirtree_cursor_t >::iterator':
        return _ida_dirtree.dirtree_cursor_vec_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< dirtree_cursor_t >::iterator':
        return _ida_dirtree.dirtree_cursor_vec_t_erase(self, *args)

    def find(self, *args) ->'qvector< dirtree_cursor_t >::const_iterator':
        return _ida_dirtree.dirtree_cursor_vec_t_find(self, *args)

    def has(self, x: 'dirtree_cursor_t') ->bool:
        return _ida_dirtree.dirtree_cursor_vec_t_has(self, x)

    def add_unique(self, x: 'dirtree_cursor_t') ->bool:
        return _ida_dirtree.dirtree_cursor_vec_t_add_unique(self, x)

    def _del(self, x: 'dirtree_cursor_t') ->bool:
        return _ida_dirtree.dirtree_cursor_vec_t__del(self, x)

    def __len__(self) ->'size_t':
        return _ida_dirtree.dirtree_cursor_vec_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'dirtree_cursor_t const &':
        return _ida_dirtree.dirtree_cursor_vec_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'dirtree_cursor_t') ->None:
        return _ida_dirtree.dirtree_cursor_vec_t___setitem__(self, i, v)

    def append(self, x: 'dirtree_cursor_t') ->None:
        return _ida_dirtree.dirtree_cursor_vec_t_append(self, x)

    def extend(self, x: 'dirtree_cursor_vec_t') ->None:
        return _ida_dirtree.dirtree_cursor_vec_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_dirtree.dirtree_cursor_vec_t_swigregister(dirtree_cursor_vec_t)


class direntry_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    idx: 'uval_t' = property(_ida_dirtree.direntry_t_idx_get, _ida_dirtree.
        direntry_t_idx_set)
    """diridx_t or inode_t
"""
    isdir: 'bool' = property(_ida_dirtree.direntry_t_isdir_get,
        _ida_dirtree.direntry_t_isdir_set)
    """is 'idx' a diridx_t, or an inode_t
"""
    BADIDX = _ida_dirtree.direntry_t_BADIDX
    ROOTIDX = _ida_dirtree.direntry_t_ROOTIDX

    def __init__(self, *args):
        _ida_dirtree.direntry_t_swiginit(self, _ida_dirtree.new_direntry_t(
            *args))

    def valid(self) ->bool:
        return _ida_dirtree.direntry_t_valid(self)

    def __eq__(self, r: 'direntry_t') ->bool:
        return _ida_dirtree.direntry_t___eq__(self, r)

    def __ne__(self, r: 'direntry_t') ->bool:
        return _ida_dirtree.direntry_t___ne__(self, r)

    def __lt__(self, r: 'direntry_t') ->bool:
        return _ida_dirtree.direntry_t___lt__(self, r)
    __swig_destroy__ = _ida_dirtree.delete_direntry_t


_ida_dirtree.direntry_t_swigregister(direntry_t)
DTN_FULL_NAME = _ida_dirtree.DTN_FULL_NAME
"""use long form of the entry name. That name is unique. 
          """
DTN_DISPLAY_NAME = _ida_dirtree.DTN_DISPLAY_NAME
"""use short, displayable form of the entry name. for example, 'std::string' instead of 'std::basic_string<char, ...>'. Note that more than one "full name" can have the same displayable name. 
          """


class dirspec_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    flags: 'uint32' = property(_ida_dirtree.dirspec_t_flags_get,
        _ida_dirtree.dirspec_t_flags_set)
    DSF_INODE_EA = _ida_dirtree.dirspec_t_DSF_INODE_EA
    DSF_PRIVRANGE = _ida_dirtree.dirspec_t_DSF_PRIVRANGE
    DSF_ORDERABLE = _ida_dirtree.dirspec_t_DSF_ORDERABLE
    id: 'qstring' = property(_ida_dirtree.dirspec_t_id_get, _ida_dirtree.
        dirspec_t_id_set)

    def __init__(self, nm: str=None, f: int=0):
        if self.__class__ == dirspec_t:
            _self = None
        else:
            _self = self
        _ida_dirtree.dirspec_t_swiginit(self, _ida_dirtree.new_dirspec_t(
            _self, nm, f))
    __swig_destroy__ = _ida_dirtree.delete_dirspec_t

    def get_name(self, inode: 'inode_t', name_flags: int=DTN_FULL_NAME) ->bool:
        """get the entry name. for example, the structure name 
        
@param inode: inode number of the entry
@param name_flags: how exactly the name should be retrieved. combination of bits for get_...name() methods bits
@returns false if the entry does not exist."""
        return _ida_dirtree.dirspec_t_get_name(self, inode, name_flags)

    def get_inode(self, dirpath: str, name: str) ->'inode_t':
        """get the entry inode in the specified directory 
        
@param dirpath: the absolute directory path with trailing slash
@param name: the entry name in the directory
@returns the entry inode"""
        return _ida_dirtree.dirspec_t_get_inode(self, dirpath, name)

    def get_attrs(self, inode: 'inode_t') ->str:
        return _ida_dirtree.dirspec_t_get_attrs(self, inode)

    def rename_inode(self, inode: 'inode_t', newname: str) ->bool:
        """rename the entry 
        
@returns success"""
        return _ida_dirtree.dirspec_t_rename_inode(self, inode, newname)

    def unlink_inode(self, inode: 'inode_t') ->None:
        """event: unlinked an inode 
        """
        return _ida_dirtree.dirspec_t_unlink_inode(self, inode)

    def is_orderable(self) ->bool:
        return _ida_dirtree.dirspec_t_is_orderable(self)
    nodename = id

    def __disown__(self):
        self.this.disown()
        _ida_dirtree.disown_dirspec_t(self)
        return weakref.proxy(self)


_ida_dirtree.dirspec_t_swigregister(dirspec_t)


class dirtree_cursor_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    parent: 'diridx_t' = property(_ida_dirtree.dirtree_cursor_t_parent_get,
        _ida_dirtree.dirtree_cursor_t_parent_set)
    """the parent directory
"""
    rank: 'size_t' = property(_ida_dirtree.dirtree_cursor_t_rank_get,
        _ida_dirtree.dirtree_cursor_t_rank_set)
    """the index into the parent directory
"""

    def __init__(self, *args):
        _ida_dirtree.dirtree_cursor_t_swiginit(self, _ida_dirtree.
            new_dirtree_cursor_t(*args))

    def valid(self) ->bool:
        return _ida_dirtree.dirtree_cursor_t_valid(self)

    def is_root_cursor(self) ->bool:
        return _ida_dirtree.dirtree_cursor_t_is_root_cursor(self)

    def set_root_cursor(self) ->None:
        return _ida_dirtree.dirtree_cursor_t_set_root_cursor(self)

    @staticmethod
    def root_cursor() ->'dirtree_cursor_t':
        return _ida_dirtree.dirtree_cursor_t_root_cursor()

    def __eq__(self, r: 'dirtree_cursor_t') ->bool:
        return _ida_dirtree.dirtree_cursor_t___eq__(self, r)

    def __ne__(self, r: 'dirtree_cursor_t') ->bool:
        return _ida_dirtree.dirtree_cursor_t___ne__(self, r)

    def __lt__(self, r: 'dirtree_cursor_t') ->bool:
        return _ida_dirtree.dirtree_cursor_t___lt__(self, r)

    def __gt__(self, r: 'dirtree_cursor_t') ->bool:
        return _ida_dirtree.dirtree_cursor_t___gt__(self, r)

    def __le__(self, r: 'dirtree_cursor_t') ->bool:
        return _ida_dirtree.dirtree_cursor_t___le__(self, r)

    def __ge__(self, r: 'dirtree_cursor_t') ->bool:
        return _ida_dirtree.dirtree_cursor_t___ge__(self, r)

    def compare(self, r: 'dirtree_cursor_t') ->int:
        return _ida_dirtree.dirtree_cursor_t_compare(self, r)
    __swig_destroy__ = _ida_dirtree.delete_dirtree_cursor_t


_ida_dirtree.dirtree_cursor_t_swigregister(dirtree_cursor_t)


class dirtree_selection_t(dirtree_cursor_vec_t):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_dirtree.dirtree_selection_t_swiginit(self, _ida_dirtree.
            new_dirtree_selection_t())
    __swig_destroy__ = _ida_dirtree.delete_dirtree_selection_t


_ida_dirtree.dirtree_selection_t_swigregister(dirtree_selection_t)


class dirtree_iterator_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    pattern: 'qstring' = property(_ida_dirtree.
        dirtree_iterator_t_pattern_get, _ida_dirtree.
        dirtree_iterator_t_pattern_set)
    cursor: 'dirtree_cursor_t' = property(_ida_dirtree.
        dirtree_iterator_t_cursor_get, _ida_dirtree.
        dirtree_iterator_t_cursor_set)

    def __init__(self):
        _ida_dirtree.dirtree_iterator_t_swiginit(self, _ida_dirtree.
            new_dirtree_iterator_t())
    __swig_destroy__ = _ida_dirtree.delete_dirtree_iterator_t


_ida_dirtree.dirtree_iterator_t_swigregister(dirtree_iterator_t)
DTE_OK = _ida_dirtree.DTE_OK
"""ok
"""
DTE_ALREADY_EXISTS = _ida_dirtree.DTE_ALREADY_EXISTS
"""item already exists
"""
DTE_NOT_FOUND = _ida_dirtree.DTE_NOT_FOUND
"""item not found
"""
DTE_NOT_DIRECTORY = _ida_dirtree.DTE_NOT_DIRECTORY
"""item is not a directory
"""
DTE_NOT_EMPTY = _ida_dirtree.DTE_NOT_EMPTY
"""directory is not empty
"""
DTE_BAD_PATH = _ida_dirtree.DTE_BAD_PATH
"""invalid path
"""
DTE_CANT_RENAME = _ida_dirtree.DTE_CANT_RENAME
"""failed to rename an item
"""
DTE_OWN_CHILD = _ida_dirtree.DTE_OWN_CHILD
"""moving inside subdirectory of itself
"""
DTE_MAX_DIR = _ida_dirtree.DTE_MAX_DIR
"""maximum directory count achieved
"""
DTE_LAST = _ida_dirtree.DTE_LAST


class dirtree_visitor_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    __swig_destroy__ = _ida_dirtree.delete_dirtree_visitor_t

    def visit(self, c: 'dirtree_cursor_t', de: 'direntry_t') ->'ssize_t':
        """Will be called for each entry in the dirtree_t If something other than 0 is returned, iteration will stop. 
        
@param c: the current cursor
@param de: the current entry
@returns 0 to keep iterating, or anything else to stop"""
        return _ida_dirtree.dirtree_visitor_t_visit(self, c, de)

    def __init__(self):
        if self.__class__ == dirtree_visitor_t:
            _self = None
        else:
            _self = self
        _ida_dirtree.dirtree_visitor_t_swiginit(self, _ida_dirtree.
            new_dirtree_visitor_t(_self))

    def __disown__(self):
        self.this.disown()
        _ida_dirtree.disown_dirtree_visitor_t(self)
        return weakref.proxy(self)


_ida_dirtree.dirtree_visitor_t_swigregister(dirtree_visitor_t)


class dirtree_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, ds: 'dirspec_t'):
        _ida_dirtree.dirtree_t_swiginit(self, _ida_dirtree.new_dirtree_t(ds))
    __swig_destroy__ = _ida_dirtree.delete_dirtree_t

    @staticmethod
    def errstr(err: 'dterr_t') ->str:
        """Get textual representation of the error code.
"""
        return _ida_dirtree.dirtree_t_errstr(err)

    def is_orderable(self) ->bool:
        """Is dirtree orderable? 
        
@returns true if the dirtree is orderable"""
        return _ida_dirtree.dirtree_t_is_orderable(self)

    def chdir(self, path: str) ->'dterr_t':
        """Change current directory 
        
@param path: new current directory
@returns dterr_t error code"""
        return _ida_dirtree.dirtree_t_chdir(self, path)

    def getcwd(self) ->str:
        """Get current directory 
        
@returns the current working directory"""
        return _ida_dirtree.dirtree_t_getcwd(self)

    def get_abspath(self, *args) ->str:
        """This function has the following signatures:

    0. get_abspath(cursor: const dirtree_cursor_t &, name_flags: int=DTN_FULL_NAME) -> str
    1. get_abspath(relpath: str) -> str

# 0: get_abspath(cursor: const dirtree_cursor_t &, name_flags: int=DTN_FULL_NAME) -> str

Get absolute path pointed by the cursor 
        
@returns path; empty string if error

# 1: get_abspath(relpath: str) -> str

Construct an absolute path from the specified relative path. This function verifies the directory part of the specified path. The last component of the specified path is not verified. 
        
@returns path. empty path means wrong directory part of RELPATH
"""
        return _ida_dirtree.dirtree_t_get_abspath(self, *args)

    def resolve_cursor(self, cursor: 'dirtree_cursor_t') ->'direntry_t':
        """Resolve cursor 
        
@param cursor: to analyze
@returns directory entry; if the cursor is bad, the resolved entry will be invalid."""
        return _ida_dirtree.dirtree_t_resolve_cursor(self, cursor)

    def resolve_path(self, path: str) ->'direntry_t':
        """Resolve path 
        
@param path: to analyze
@returns directory entry"""
        return _ida_dirtree.dirtree_t_resolve_path(self, path)

    def isdir(self, *args) ->bool:
        """This function has the following signatures:

    0. isdir(path: str) -> bool
    1. isdir(de: const direntry_t &) -> bool

# 0: isdir(path: str) -> bool

Is a directory? 
        
@returns true if the specified path is a directory

# 1: isdir(de: const direntry_t &) -> bool

"""
        return _ida_dirtree.dirtree_t_isdir(self, *args)

    def isfile(self, *args) ->bool:
        """This function has the following signatures:

    0. isfile(path: str) -> bool
    1. isfile(de: const direntry_t &) -> bool

# 0: isfile(path: str) -> bool

Is a file? 
        
@returns true if the specified path is a file

# 1: isfile(de: const direntry_t &) -> bool

"""
        return _ida_dirtree.dirtree_t_isfile(self, *args)

    def get_entry_name(self, de: 'direntry_t', name_flags: int=DTN_FULL_NAME
        ) ->str:
        """Get entry name 
        
@param de: directory entry
@param name_flags: how exactly the name should be retrieved. combination of bits for get_...name() methods bits
@returns name"""
        return _ida_dirtree.dirtree_t_get_entry_name(self, de, name_flags)

    def is_dir_ordered(self, diridx: 'diridx_t') ->bool:
        """Is dir ordered? 
        
@returns true if the dirtree has natural ordering"""
        return _ida_dirtree.dirtree_t_is_dir_ordered(self, diridx)

    def set_natural_order(self, diridx: 'diridx_t', enable: bool) ->bool:
        """Enable/disable natural inode order in a directory. 
        
@param diridx: directory index
@param enable: action to do TRUE - enable ordering: re-order existing entries so that all subdirs are at the to beginning of the list, file entries are sorted and placed after the subdirs FALSE - disable ordering, no changes to existing entries
@returns SUCCESS"""
        return _ida_dirtree.dirtree_t_set_natural_order(self, diridx, enable)

    def get_dir_size(self, diridx: 'diridx_t') ->'ssize_t':
        """Get dir size 
        
@param diridx: directory index
@returns number of entries under this directory; if error, return -1"""
        return _ida_dirtree.dirtree_t_get_dir_size(self, diridx)

    def get_entry_attrs(self, de: 'direntry_t') ->str:
        """Get entry attributes 
        
@param de: directory entry
@returns name"""
        return _ida_dirtree.dirtree_t_get_entry_attrs(self, de)

    def findfirst(self, ff: 'dirtree_iterator_t', pattern: str) ->bool:
        """Start iterating over files in a directory 
        
@param ff: directory iterator. it will be initialized by the function
@param pattern: pattern to search for
@returns success"""
        return _ida_dirtree.dirtree_t_findfirst(self, ff, pattern)

    def findnext(self, ff: 'dirtree_iterator_t') ->bool:
        """Continue iterating over files in a directory 
        
@param ff: directory iterator
@returns success"""
        return _ida_dirtree.dirtree_t_findnext(self, ff)

    def mkdir(self, path: str) ->'dterr_t':
        """Create a directory. 
        
@param path: directory to create
@returns dterr_t error code"""
        return _ida_dirtree.dirtree_t_mkdir(self, path)

    def rmdir(self, path: str) ->'dterr_t':
        """Remove a directory. 
        
@param path: directory to delete
@returns dterr_t error code"""
        return _ida_dirtree.dirtree_t_rmdir(self, path)

    def link(self, *args) ->'dterr_t':
        """This function has the following signatures:

    0. link(path: str) -> dterr_t
    1. link(inode: inode_t) -> dterr_t

# 0: link(path: str) -> dterr_t

Add a file item into a directory. 
        
@returns dterr_t error code

# 1: link(inode: inode_t) -> dterr_t

Add an inode into the current directory 
        
@returns dterr_t error code
"""
        return _ida_dirtree.dirtree_t_link(self, *args)

    def unlink(self, *args) ->'dterr_t':
        """This function has the following signatures:

    0. unlink(path: str) -> dterr_t
    1. unlink(inode: inode_t) -> dterr_t

# 0: unlink(path: str) -> dterr_t

Remove a file item from a directory. 
        
@returns dterr_t error code

# 1: unlink(inode: inode_t) -> dterr_t

Remove an inode from the current directory 
        
@returns dterr_t error code
"""
        return _ida_dirtree.dirtree_t_unlink(self, *args)

    def rename(self, _from: str, to: str) ->'dterr_t':
        """Rename a directory entry. 
        
@param to: destination path
@returns dterr_t error code"""
        return _ida_dirtree.dirtree_t_rename(self, _from, to)

    def get_rank(self, diridx: 'diridx_t', de: 'direntry_t') ->'ssize_t':
        """Get ordering rank of an item. 
        
@param diridx: index of the parent directory
@param de: directory entry
@returns number in a range of [0..n) where n is the number of entries in the parent directory. -1 if error"""
        return _ida_dirtree.dirtree_t_get_rank(self, diridx, de)

    def change_rank(self, path: str, rank_delta: 'ssize_t') ->'dterr_t':
        """Change ordering rank of an item. 
        
@param path: path to the item
@param rank_delta: the amount of the change. positive numbers mean to move down in the list; negative numbers mean to move up.
@returns dterr_t error code"""
        return _ida_dirtree.dirtree_t_change_rank(self, path, rank_delta)

    def get_parent_cursor(self, cursor: 'dirtree_cursor_t'
        ) ->'dirtree_cursor_t':
        """Get parent cursor. 
        
@param cursor: a valid ditree cursor
@returns cursor's parent"""
        return _ida_dirtree.dirtree_t_get_parent_cursor(self, cursor)

    def load(self) ->bool:
        """Load the tree structure from the netnode. If dirspec_t::id is empty, the operation will be considered a success. In addition, calling load() more than once will not do anything, and will be considered a success. 
        
@returns success"""
        return _ida_dirtree.dirtree_t_load(self)

    def save(self) ->bool:
        """Save the tree structure to the netnode. 
        
@returns success"""
        return _ida_dirtree.dirtree_t_save(self)

    def get_id(self) ->str:
        """netnode name
"""
        return _ida_dirtree.dirtree_t_get_id(self)

    def set_id(self, nm: str) ->None:
        return _ida_dirtree.dirtree_t_set_id(self, nm)

    def notify_dirtree(self, added: bool, inode: 'inode_t') ->None:
        """Notify dirtree about a change of an inode. 
        
@param added: are we adding or deleting an inode?
@param inode: inode in question"""
        return _ida_dirtree.dirtree_t_notify_dirtree(self, added, inode)

    def traverse(self, v: 'dirtree_visitor_t') ->'ssize_t':
        """Traverse dirtree, and be notified at each entry If the the visitor returns anything other than 0, iteration will stop, and that value returned. The tree is traversed using a depth-first algorithm. It is forbidden to modify the dirtree_t during traversal; doing so will result in undefined behavior. 
        
@param v: the callback
@returns 0, or whatever the visitor returned"""
        return _ida_dirtree.dirtree_t_traverse(self, v)

    def find_entry(self, de: 'direntry_t') ->'dirtree_cursor_t':
        """Find the cursor corresponding to an entry of a directory 
        
@param de: directory entry
@returns cursor corresponding to the directory entry"""
        return _ida_dirtree.dirtree_t_find_entry(self, de)
    get_nodename = get_id
    set_nodename = set_id


_ida_dirtree.dirtree_t_swigregister(dirtree_t)
DIRTREE_LOCAL_TYPES = _ida_dirtree.DIRTREE_LOCAL_TYPES
DIRTREE_FUNCS = _ida_dirtree.DIRTREE_FUNCS
DIRTREE_NAMES = _ida_dirtree.DIRTREE_NAMES
DIRTREE_IMPORTS = _ida_dirtree.DIRTREE_IMPORTS
DIRTREE_IDAPLACE_BOOKMARKS = _ida_dirtree.DIRTREE_IDAPLACE_BOOKMARKS
DIRTREE_BPTS = _ida_dirtree.DIRTREE_BPTS
DIRTREE_LTYPES_BOOKMARKS = _ida_dirtree.DIRTREE_LTYPES_BOOKMARKS
DIRTREE_END = _ida_dirtree.DIRTREE_END


def get_std_dirtree(id: 'dirtree_id_t') ->'dirtree_t *':
    return _ida_dirtree.get_std_dirtree(id)

```
