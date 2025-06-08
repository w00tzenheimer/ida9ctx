```python
"""Functions that provide the lowest level public interface to the database. Namely, we use Btree. To learn more about BTree:

[https://en.wikipedia.org/wiki/B-tree](https://en.wikipedia.org/wiki/B-tree)
We do not use Btree directly. Instead, we have another layer built on the top of Btree. Here is a brief explanation of this layer.
An object called "netnode" is modeled on the top of Btree. Each netnode has a unique id: a 32-bit value (64-bit for ida64). Initially there is a trivial mapping of the linear addresses used in the program to netnodes (later this mapping may be modified using ea2node and node2ea functions; this is used for fast database rebasings). If we have additional information about an address (for example, a comment is attached to it), this information is stored in the corresponding netnode. See nalt.hpp to see how the kernel uses netnodes. Also, some netnodes have no corresponding linear address (however, they still have an id). They are used to store information not related to a particular address.
Each netnode _may_ have the following attributes:

* a name: an arbitrary non-empty string, up to 255KB-1 bytes
* a value: arbitrary sized object, max size is MAXSPECSIZE
* altvals: a sparse array of 32-bit values. indexes in this array may be 8-bit or 32-bit values
* supvals: an array of arbitrary sized objects. (size of each object is limited by MAXSPECSIZE) indexes in this array may be 8-bit or 32-bit values
* charvals: a sparse array of 8-bit values. indexes in this array may be 8-bit or 32-bit values
* hashvals: a hash (an associative array). indexes in this array are strings values are arbitrary sized (max size is MAXSPECSIZE)


Initially a new netnode contains no information at all so no disk space is used for it. As you add new information, the netnode grows.
All arrays that are attached to the netnode behave in the same manner. Initially:
* all members of altvals/charvals array are zeroes
* all members of supvals/hashvals array are undefined


If you need to store objects bigger that MAXSPECSIZE, please note that there are high-level functions to store arbitrary sized objects in supvals. See setblob/getblob and other blob-related functions.
You may use netnodes to store additional information about the program. Limitations on the use of netnodes are the following:

* use netnodes only if you could not find a kernel service to store your type of information
* do not create netnodes with valid identifier names. Use the "$ " prefix (or any other prefix with characters not allowed in the identifiers for the names of your netnodes. Although you will probably not destroy anything by accident, using already defined names for the names of your netnodes is still discouraged.
* you may create as many netnodes as you want (creation of an unnamed netnode does not increase the size of the database). however, since each netnode has a number, creating too many netnodes could lead to the exhaustion of the netnode numbers (the numbering starts at 0xFF000000)
* remember that netnodes are automatically saved to the disk by the kernel.


Advanced info:
In fact a netnode may contain up to 256 arrays of arbitrary sized objects (not only the 4 listed above). Each array has an 8-bit tag. Usually tags are represented by character constants. For example, altvals and supvals are simply 2 of 256 arrays, with the tags 'A' and 'S' respectively. 
    """
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_netnode
else:
    import _ida_netnode
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
SWIG_PYTHON_LEGACY_BOOL = _ida_netnode.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi
BADNODE = _ida_netnode.BADNODE
"""A number to represent a bad netnode reference.
"""
SIZEOF_nodeidx_t = _ida_netnode.SIZEOF_nodeidx_t


class netnode(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_netnode.netnode_swiginit(self, _ida_netnode.new_netnode(*args))

    @staticmethod
    def exist(_name: str) ->bool:
        """Does the netnode with the specified name exist?
"""
        return _ida_netnode.netnode_exist(_name)

    def create(self, *args) ->bool:
        return _ida_netnode.netnode_create(self, *args)

    def kill(self) ->None:
        return _ida_netnode.netnode_kill(self)

    def get_name(self) ->'ssize_t':
        return _ida_netnode.netnode_get_name(self)

    def rename(self, newname: str, namlen: 'size_t'=0) ->bool:
        return _ida_netnode.netnode_rename(self, newname, namlen)

    def valobj(self, *args) ->'ssize_t':
        return _ida_netnode.netnode_valobj(self, *args)

    def valstr(self) ->'ssize_t':
        return _ida_netnode.netnode_valstr(self)

    def set(self, value: 'void const *') ->bool:
        return _ida_netnode.netnode_set(self, value)

    def delvalue(self) ->bool:
        return _ida_netnode.netnode_delvalue(self)

    def set_long(self, x: 'nodeidx_t') ->bool:
        return _ida_netnode.netnode_set_long(self, x)

    def value_exists(self) ->bool:
        return _ida_netnode.netnode_value_exists(self)

    def long_value(self) ->'nodeidx_t':
        return _ida_netnode.netnode_long_value(self)

    def altval(self, *args) ->'nodeidx_t':
        return _ida_netnode.netnode_altval(self, *args)

    def altval_ea(self, *args) ->'nodeidx_t':
        return _ida_netnode.netnode_altval_ea(self, *args)

    def altset(self, *args) ->bool:
        return _ida_netnode.netnode_altset(self, *args)

    def altset_ea(self, *args) ->bool:
        return _ida_netnode.netnode_altset_ea(self, *args)

    def altdel_ea(self, *args) ->bool:
        return _ida_netnode.netnode_altdel_ea(self, *args)

    def easet(self, ea: ida_idaapi.ea_t, addr: ida_idaapi.ea_t, tag: 'uchar'
        ) ->bool:
        return _ida_netnode.netnode_easet(self, ea, addr, tag)

    def eaget(self, ea: ida_idaapi.ea_t, tag: 'uchar') ->ida_idaapi.ea_t:
        return _ida_netnode.netnode_eaget(self, ea, tag)

    def eadel(self, ea: ida_idaapi.ea_t, tag: 'uchar') ->bool:
        return _ida_netnode.netnode_eadel(self, ea, tag)

    def easet_idx(self, idx: 'nodeidx_t', addr: ida_idaapi.ea_t, tag: 'uchar'
        ) ->bool:
        return _ida_netnode.netnode_easet_idx(self, idx, addr, tag)

    def eaget_idx(self, idx: 'nodeidx_t', tag: 'uchar') ->ida_idaapi.ea_t:
        return _ida_netnode.netnode_eaget_idx(self, idx, tag)

    def easet_idx8(self, idx: 'uchar', addr: ida_idaapi.ea_t, tag: 'uchar'
        ) ->bool:
        return _ida_netnode.netnode_easet_idx8(self, idx, addr, tag)

    def eaget_idx8(self, idx: 'uchar', tag: 'uchar') ->ida_idaapi.ea_t:
        return _ida_netnode.netnode_eaget_idx8(self, idx, tag)

    def eadel_idx8(self, idx: 'uchar', tag: 'uchar') ->bool:
        return _ida_netnode.netnode_eadel_idx8(self, idx, tag)

    def altfirst(self, *args) ->'nodeidx_t':
        return _ida_netnode.netnode_altfirst(self, *args)

    def altnext(self, *args) ->'nodeidx_t':
        return _ida_netnode.netnode_altnext(self, *args)

    def altlast(self, *args) ->'nodeidx_t':
        return _ida_netnode.netnode_altlast(self, *args)

    def altprev(self, *args) ->'nodeidx_t':
        return _ida_netnode.netnode_altprev(self, *args)

    def altshift(self, *args) ->'size_t':
        return _ida_netnode.netnode_altshift(self, *args)

    def charval(self, alt: 'nodeidx_t', tag: 'uchar') ->'uchar':
        return _ida_netnode.netnode_charval(self, alt, tag)

    def charset(self, alt: 'nodeidx_t', val: 'uchar', tag: 'uchar') ->bool:
        return _ida_netnode.netnode_charset(self, alt, val, tag)

    def chardel(self, alt: 'nodeidx_t', tag: 'uchar') ->bool:
        return _ida_netnode.netnode_chardel(self, alt, tag)

    def charval_ea(self, ea: ida_idaapi.ea_t, tag: 'uchar') ->'uchar':
        return _ida_netnode.netnode_charval_ea(self, ea, tag)

    def charset_ea(self, ea: ida_idaapi.ea_t, val: 'uchar', tag: 'uchar'
        ) ->bool:
        return _ida_netnode.netnode_charset_ea(self, ea, val, tag)

    def chardel_ea(self, ea: ida_idaapi.ea_t, tag: 'uchar') ->bool:
        return _ida_netnode.netnode_chardel_ea(self, ea, tag)

    def charfirst(self, tag: 'uchar') ->'nodeidx_t':
        return _ida_netnode.netnode_charfirst(self, tag)

    def charnext(self, cur: 'nodeidx_t', tag: 'uchar') ->'nodeidx_t':
        return _ida_netnode.netnode_charnext(self, cur, tag)

    def charlast(self, tag: 'uchar') ->'nodeidx_t':
        return _ida_netnode.netnode_charlast(self, tag)

    def charprev(self, cur: 'nodeidx_t', tag: 'uchar') ->'nodeidx_t':
        return _ida_netnode.netnode_charprev(self, cur, tag)

    def charshift(self, _from: 'nodeidx_t', to: 'nodeidx_t', size:
        'nodeidx_t', tag: 'uchar') ->'size_t':
        return _ida_netnode.netnode_charshift(self, _from, to, size, tag)

    def altval_idx8(self, alt: 'uchar', tag: 'uchar') ->'nodeidx_t':
        return _ida_netnode.netnode_altval_idx8(self, alt, tag)

    def altset_idx8(self, alt: 'uchar', val: 'nodeidx_t', tag: 'uchar') ->bool:
        return _ida_netnode.netnode_altset_idx8(self, alt, val, tag)

    def altdel_idx8(self, alt: 'uchar', tag: 'uchar') ->bool:
        return _ida_netnode.netnode_altdel_idx8(self, alt, tag)

    def altfirst_idx8(self, tag: 'uchar') ->'nodeidx_t':
        return _ida_netnode.netnode_altfirst_idx8(self, tag)

    def altnext_idx8(self, cur: 'uchar', tag: 'uchar') ->'nodeidx_t':
        return _ida_netnode.netnode_altnext_idx8(self, cur, tag)

    def altlast_idx8(self, tag: 'uchar') ->'nodeidx_t':
        return _ida_netnode.netnode_altlast_idx8(self, tag)

    def altprev_idx8(self, cur: 'uchar', tag: 'uchar') ->'nodeidx_t':
        return _ida_netnode.netnode_altprev_idx8(self, cur, tag)

    def charval_idx8(self, alt: 'uchar', tag: 'uchar') ->'uchar':
        return _ida_netnode.netnode_charval_idx8(self, alt, tag)

    def charset_idx8(self, alt: 'uchar', val: 'uchar', tag: 'uchar') ->bool:
        return _ida_netnode.netnode_charset_idx8(self, alt, val, tag)

    def chardel_idx8(self, alt: 'uchar', tag: 'uchar') ->bool:
        return _ida_netnode.netnode_chardel_idx8(self, alt, tag)

    def charfirst_idx8(self, tag: 'uchar') ->'nodeidx_t':
        return _ida_netnode.netnode_charfirst_idx8(self, tag)

    def charnext_idx8(self, cur: 'uchar', tag: 'uchar') ->'nodeidx_t':
        return _ida_netnode.netnode_charnext_idx8(self, cur, tag)

    def charlast_idx8(self, tag: 'uchar') ->'nodeidx_t':
        return _ida_netnode.netnode_charlast_idx8(self, tag)

    def charprev_idx8(self, cur: 'uchar', tag: 'uchar') ->'nodeidx_t':
        return _ida_netnode.netnode_charprev_idx8(self, cur, tag)

    def altdel(self, *args) ->bool:
        return _ida_netnode.netnode_altdel(self, *args)

    def altdel_all(self, *args) ->bool:
        return _ida_netnode.netnode_altdel_all(self, *args)

    def supval(self, *args) ->'ssize_t':
        return _ida_netnode.netnode_supval(self, *args)

    def supval_ea(self, *args) ->'ssize_t':
        return _ida_netnode.netnode_supval_ea(self, *args)

    def supstr(self, *args) ->'ssize_t':
        return _ida_netnode.netnode_supstr(self, *args)

    def supstr_ea(self, *args) ->'ssize_t':
        return _ida_netnode.netnode_supstr_ea(self, *args)

    def supdel_ea(self, *args) ->bool:
        return _ida_netnode.netnode_supdel_ea(self, *args)

    def lower_bound(self, *args) ->'nodeidx_t':
        return _ida_netnode.netnode_lower_bound(self, *args)

    def lower_bound_ea(self, *args) ->'nodeidx_t':
        return _ida_netnode.netnode_lower_bound_ea(self, *args)

    def supfirst(self, *args) ->'nodeidx_t':
        return _ida_netnode.netnode_supfirst(self, *args)

    def supnext(self, *args) ->'nodeidx_t':
        return _ida_netnode.netnode_supnext(self, *args)

    def suplast(self, *args) ->'nodeidx_t':
        return _ida_netnode.netnode_suplast(self, *args)

    def supprev(self, *args) ->'nodeidx_t':
        return _ida_netnode.netnode_supprev(self, *args)

    def supshift(self, *args) ->'size_t':
        return _ida_netnode.netnode_supshift(self, *args)

    def supval_idx8(self, *args) ->'ssize_t':
        return _ida_netnode.netnode_supval_idx8(self, *args)

    def supstr_idx8(self, alt: 'uchar', tag: 'uchar') ->'ssize_t':
        return _ida_netnode.netnode_supstr_idx8(self, alt, tag)

    def supset_idx8(self, alt: 'uchar', value: 'void const *', tag: 'uchar'
        ) ->bool:
        return _ida_netnode.netnode_supset_idx8(self, alt, value, tag)

    def supdel_idx8(self, alt: 'uchar', tag: 'uchar') ->bool:
        return _ida_netnode.netnode_supdel_idx8(self, alt, tag)

    def lower_bound_idx8(self, alt: 'uchar', tag: 'uchar') ->'nodeidx_t':
        return _ida_netnode.netnode_lower_bound_idx8(self, alt, tag)

    def supfirst_idx8(self, tag: 'uchar') ->'nodeidx_t':
        return _ida_netnode.netnode_supfirst_idx8(self, tag)

    def supnext_idx8(self, alt: 'uchar', tag: 'uchar') ->'nodeidx_t':
        return _ida_netnode.netnode_supnext_idx8(self, alt, tag)

    def suplast_idx8(self, tag: 'uchar') ->'nodeidx_t':
        return _ida_netnode.netnode_suplast_idx8(self, tag)

    def supprev_idx8(self, alt: 'uchar', tag: 'uchar') ->'nodeidx_t':
        return _ida_netnode.netnode_supprev_idx8(self, alt, tag)

    def supdel(self, *args) ->bool:
        return _ida_netnode.netnode_supdel(self, *args)

    def supdel_all(self, tag: 'uchar') ->bool:
        return _ida_netnode.netnode_supdel_all(self, tag)

    def supdel_range(self, idx1: 'nodeidx_t', idx2: 'nodeidx_t', tag: 'uchar'
        ) ->int:
        return _ida_netnode.netnode_supdel_range(self, idx1, idx2, tag)

    def supdel_range_idx8(self, idx1: 'uchar', idx2: 'uchar', tag: 'uchar'
        ) ->int:
        return _ida_netnode.netnode_supdel_range_idx8(self, idx1, idx2, tag)

    def hashval(self, *args) ->'ssize_t':
        return _ida_netnode.netnode_hashval(self, *args)

    def hashstr(self, *args) ->'ssize_t':
        return _ida_netnode.netnode_hashstr(self, *args)

    def hashval_long(self, *args) ->'nodeidx_t':
        return _ida_netnode.netnode_hashval_long(self, *args)

    def hashset(self, *args) ->bool:
        return _ida_netnode.netnode_hashset(self, *args)

    def hashset_idx(self, *args) ->bool:
        return _ida_netnode.netnode_hashset_idx(self, *args)

    def hashdel(self, *args) ->bool:
        return _ida_netnode.netnode_hashdel(self, *args)

    def hashfirst(self, *args) ->'ssize_t':
        return _ida_netnode.netnode_hashfirst(self, *args)

    def hashnext(self, *args) ->'ssize_t':
        return _ida_netnode.netnode_hashnext(self, *args)

    def hashlast(self, *args) ->'ssize_t':
        return _ida_netnode.netnode_hashlast(self, *args)

    def hashprev(self, *args) ->'ssize_t':
        return _ida_netnode.netnode_hashprev(self, *args)

    def hashdel_all(self, *args) ->bool:
        return _ida_netnode.netnode_hashdel_all(self, *args)

    def blobsize(self, _start: 'nodeidx_t', tag: 'uchar') ->'size_t':
        return _ida_netnode.netnode_blobsize(self, _start, tag)

    def blobsize_ea(self, ea: ida_idaapi.ea_t, tag: 'uchar') ->'size_t':
        return _ida_netnode.netnode_blobsize_ea(self, ea, tag)

    def setblob(self, buf: 'void const *', _start: 'nodeidx_t', tag: 'uchar'
        ) ->bool:
        return _ida_netnode.netnode_setblob(self, buf, _start, tag)

    def setblob_ea(self, buf: 'void const *', ea: ida_idaapi.ea_t, tag: 'uchar'
        ) ->bool:
        return _ida_netnode.netnode_setblob_ea(self, buf, ea, tag)

    def delblob(self, _start: 'nodeidx_t', tag: 'uchar') ->int:
        return _ida_netnode.netnode_delblob(self, _start, tag)

    def delblob_ea(self, ea: ida_idaapi.ea_t, tag: 'uchar') ->int:
        return _ida_netnode.netnode_delblob_ea(self, ea, tag)

    def blobshift(self, _from: 'nodeidx_t', to: 'nodeidx_t', size:
        'nodeidx_t', tag: 'uchar') ->'size_t':
        return _ida_netnode.netnode_blobshift(self, _from, to, size, tag)

    def start(self) ->bool:
        return _ida_netnode.netnode_start(self)

    def end(self) ->bool:
        return _ida_netnode.netnode_end(self)

    def next(self) ->bool:
        return _ida_netnode.netnode_next(self)

    def prev(self) ->bool:
        return _ida_netnode.netnode_prev(self)

    def copyto(self, destnode: 'netnode', count: 'nodeidx_t'=1) ->'size_t':
        return _ida_netnode.netnode_copyto(self, destnode, count)

    def moveto(self, destnode: 'netnode', count: 'nodeidx_t'=1) ->'size_t':
        return _ida_netnode.netnode_moveto(self, destnode, count)

    def __eq__(self, *args) ->bool:
        return _ida_netnode.netnode___eq__(self, *args)

    def __ne__(self, *args) ->bool:
        return _ida_netnode.netnode___ne__(self, *args)

    def index(self) ->'nodeidx_t':
        return _ida_netnode.netnode_index(self)

    def getblob(self, start, tag) ->Union[bytes, None]:
        """Get a blob from a netnode.

@param start the index where the blob starts (it may span on multiple indexes)
@param tag the netnode tag
@return a blob, or None"""
        return _ida_netnode.netnode_getblob(self, start, tag)

    def getclob(self, start, tag) ->Union[str, None]:
        """Get a large amount of text from a netnode.

@param start the index where the clob starts (it may span on multiple indexes)
@param tag the netnode tag
@return a clob, or None"""
        return _ida_netnode.netnode_getclob(self, start, tag)

    def getblob_ea(self, ea: ida_idaapi.ea_t, tag: 'char') ->'PyObject *':
        return _ida_netnode.netnode_getblob_ea(self, ea, tag)

    def hashstr_buf(self, *args) ->'PyObject *':
        return _ida_netnode.netnode_hashstr_buf(self, *args)

    def hashset_buf(self, *args) ->bool:
        return _ida_netnode.netnode_hashset_buf(self, *args)

    def supset(self, *args) ->bool:
        return _ida_netnode.netnode_supset(self, *args)

    def supset_ea(self, *args) ->bool:
        return _ida_netnode.netnode_supset_ea(self, *args)
    __swig_destroy__ = _ida_netnode.delete_netnode


_ida_netnode.netnode_swigregister(netnode)
cvar = _ida_netnode.cvar
MAXNAMESIZE = cvar.MAXNAMESIZE
"""Maximum length of a netnode name. WILL BE REMOVED IN THE FUTURE.
"""
MAX_NODENAME_SIZE = cvar.MAX_NODENAME_SIZE
"""Maximum length of a name. We permit names up to 32KB-1 bytes.
"""
MAXSPECSIZE = cvar.MAXSPECSIZE
"""Maximum length of strings or objects stored in a supval array element.
"""
atag = cvar.atag
"""Array of altvals.
"""
stag = cvar.stag
"""Array of supvals.
"""
htag = cvar.htag
"""Array of hashvals.
"""
vtag = cvar.vtag
"""Value of netnode.
"""
ntag = cvar.ntag
"""Name of netnode.
"""
ltag = cvar.ltag
"""Links between netnodes.
"""
NETMAP_IDX = cvar.NETMAP_IDX
NETMAP_VAL = cvar.NETMAP_VAL
NETMAP_STR = cvar.NETMAP_STR
NETMAP_X8 = cvar.NETMAP_X8
NETMAP_V8 = cvar.NETMAP_V8
NETMAP_VAL_NDX = cvar.NETMAP_VAL_NDX


def exist(n: 'netnode') ->bool:
    return _ida_netnode.exist(n)


netnode_exist = netnode.exist

```
