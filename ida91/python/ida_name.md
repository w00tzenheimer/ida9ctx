```python
"""Functions that deal with names.

A non-tail address of the program may have a name. Tail addresses (i.e. the addresses in the middle of an instruction or data item) cannot have names. 
    """
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_name
else:
    import _ida_name
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
SWIG_PYTHON_LEGACY_BOOL = _ida_name.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi


class ea_name_vec_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_name.ea_name_vec_t_swiginit(self, _ida_name.new_ea_name_vec_t(
            *args))
    __swig_destroy__ = _ida_name.delete_ea_name_vec_t

    def push_back(self, *args) ->'ea_name_t &':
        return _ida_name.ea_name_vec_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_name.ea_name_vec_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_name.ea_name_vec_t_size(self)

    def empty(self) ->bool:
        return _ida_name.ea_name_vec_t_empty(self)

    def at(self, _idx: 'size_t') ->'ea_name_t const &':
        return _ida_name.ea_name_vec_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_name.ea_name_vec_t_qclear(self)

    def clear(self) ->None:
        return _ida_name.ea_name_vec_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_name.ea_name_vec_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_name.ea_name_vec_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_name.ea_name_vec_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_name.ea_name_vec_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_name.ea_name_vec_t_truncate(self)

    def swap(self, r: 'ea_name_vec_t') ->None:
        return _ida_name.ea_name_vec_t_swap(self, r)

    def extract(self) ->'ea_name_t *':
        return _ida_name.ea_name_vec_t_extract(self)

    def inject(self, s: 'ea_name_t', len: 'size_t') ->None:
        return _ida_name.ea_name_vec_t_inject(self, s, len)

    def begin(self, *args) ->'qvector< ea_name_t >::const_iterator':
        return _ida_name.ea_name_vec_t_begin(self, *args)

    def end(self, *args) ->'qvector< ea_name_t >::const_iterator':
        return _ida_name.ea_name_vec_t_end(self, *args)

    def insert(self, it: 'ea_name_t', x: 'ea_name_t'
        ) ->'qvector< ea_name_t >::iterator':
        return _ida_name.ea_name_vec_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< ea_name_t >::iterator':
        return _ida_name.ea_name_vec_t_erase(self, *args)

    def __len__(self) ->'size_t':
        return _ida_name.ea_name_vec_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'ea_name_t const &':
        return _ida_name.ea_name_vec_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'ea_name_t') ->None:
        return _ida_name.ea_name_vec_t___setitem__(self, i, v)

    def append(self, x: 'ea_name_t') ->None:
        return _ida_name.ea_name_vec_t_append(self, x)

    def extend(self, x: 'ea_name_vec_t') ->None:
        return _ida_name.ea_name_vec_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_name.ea_name_vec_t_swigregister(ea_name_vec_t)


def get_name(ea: ida_idaapi.ea_t) ->str:
    return _ida_name.get_name(ea)


def get_colored_name(ea: ida_idaapi.ea_t) ->str:
    return _ida_name.get_colored_name(ea)


MAXNAMELEN = _ida_name.MAXNAMELEN
"""Maximum length of a name in IDA (with the trailing zero)
"""
FUNC_IMPORT_PREFIX = _ida_name.FUNC_IMPORT_PREFIX
"""Name prefix used by IDA for the imported functions.
"""


def set_name(ea: ida_idaapi.ea_t, name: str, flags: int=0) ->bool:
    """Set or delete name of an item at the specified address. An item can be anything: instruction, function, data byte, word, string, structure, etc... Include name into the list of names. 
        
@param ea: linear address. do nothing if ea is not valid (return 0). tail bytes can't have names.
@param name: new name.
* nullptr: do nothing (return 0).
* "" : delete name.
* otherwise this is a new name.
@param flags: Set name flags. If a bit is not specified, then the corresponding action is not performed and the name will retain the same bits as before calling this function. For new names, default is: non-public, non-weak, non-auto.
@retval 1: ok, name is changed
@retval 0: failure, a warning is displayed"""
    return _ida_name.set_name(ea, name, flags)


SN_CHECK = _ida_name.SN_CHECK
"""Fail if the name contains invalid characters.
"""
SN_NOCHECK = _ida_name.SN_NOCHECK
"""Replace invalid characters silently. If this bit is set, all invalid chars (not in NameChars or MangleChars) will be replaced by '_' List of valid characters is defined in ida.cfg 
        """
SN_PUBLIC = _ida_name.SN_PUBLIC
"""if set, make name public
"""
SN_NON_PUBLIC = _ida_name.SN_NON_PUBLIC
"""if set, make name non-public
"""
SN_WEAK = _ida_name.SN_WEAK
"""if set, make name weak
"""
SN_NON_WEAK = _ida_name.SN_NON_WEAK
"""if set, make name non-weak
"""
SN_AUTO = _ida_name.SN_AUTO
"""if set, make name autogenerated
"""
SN_NON_AUTO = _ida_name.SN_NON_AUTO
"""if set, make name non-autogenerated
"""
SN_NOLIST = _ida_name.SN_NOLIST
"""if set, exclude name from the list. if not set, then include the name into the list (however, if other bits are set, the name might be immediately excluded from the list). 
        """
SN_NOWARN = _ida_name.SN_NOWARN
"""don't display a warning if failed
"""
SN_LOCAL = _ida_name.SN_LOCAL
"""create local name. a function should exist. local names can't be public or weak. also they are not included into the list of names they can't have dummy prefixes. 
        """
SN_IDBENC = _ida_name.SN_IDBENC
"""the name is given in the IDB encoding; non-ASCII bytes will be decoded accordingly. Specifying SN_IDBENC also implies SN_NODUMMY 
        """
SN_FORCE = _ida_name.SN_FORCE
"""if the specified name is already present in the database, try variations with a numerical suffix like "_123" 
        """
SN_NODUMMY = _ida_name.SN_NODUMMY
"""automatically prepend the name with '_' if it begins with a dummy suffix such as 'sub_'. See also SN_IDBENC 
        """
SN_DELTAIL = _ida_name.SN_DELTAIL
"""if name cannot be set because of a tail byte, delete the hindering item 
        """


def force_name(ea: ida_idaapi.ea_t, name: str, flags: int=0) ->bool:
    return _ida_name.force_name(ea, name, flags)


def del_global_name(ea: ida_idaapi.ea_t) ->bool:
    return _ida_name.del_global_name(ea)


def del_local_name(ea: ida_idaapi.ea_t) ->bool:
    return _ida_name.del_local_name(ea)


def set_dummy_name(_from: ida_idaapi.ea_t, ea: ida_idaapi.ea_t) ->bool:
    """Give an autogenerated (dummy) name. Autogenerated names have special prefixes (loc_...). 
        
@param ea: linear address
@retval 1: ok, dummy name is generated or the byte already had a name
@retval 0: failure, invalid address or tail byte"""
    return _ida_name.set_dummy_name(_from, ea)


def make_name_auto(ea: ida_idaapi.ea_t) ->bool:
    return _ida_name.make_name_auto(ea)


def make_name_user(ea: ida_idaapi.ea_t) ->bool:
    return _ida_name.make_name_user(ea)


UCDR_STRLIT = _ida_name.UCDR_STRLIT
"""string literals
"""
UCDR_NAME = _ida_name.UCDR_NAME
"""regular (unmangled) names
"""
UCDR_MANGLED = _ida_name.UCDR_MANGLED
"""mangled names
"""
UCDR_TYPE = _ida_name.UCDR_TYPE
"""type names
"""
VNT_IDENT = _ida_name.VNT_IDENT
"""identifier (e.g., function name)
"""
VNT_TYPE = _ida_name.VNT_TYPE
"""type name (can contain '<', '>', ...)
"""
VNT_UDTMEM = _ida_name.VNT_UDTMEM
"""UDT (structure, union, enum) member.
"""
VNT_STRLIT = _ida_name.VNT_STRLIT
"""string literal
"""
VNT_VISIBLE = _ida_name.VNT_VISIBLE
"""visible cp (obsolete; will be deleted)
"""


def is_valid_cp(cp: 'wchar32_t', kind: 'nametype_t', data: 'void *'=None
    ) ->bool:
    """Is the given codepoint acceptable in the given context?
"""
    return _ida_name.is_valid_cp(cp, kind, data)


def set_cp_validity(*args) ->None:
    """Mark the given codepoint (or range) as acceptable or unacceptable in the given context If 'endcp' is not BADCP, it is considered to be the end of the range: [cp, endcp), and is not included in the range 
        """
    return _ida_name.set_cp_validity(*args)


def get_cp_validity(*args) ->bool:
    """Is the given codepoint (or range) acceptable in the given context? If 'endcp' is not BADCP, it is considered to be the end of the range: [cp, endcp), and is not included in the range 
        """
    return _ida_name.get_cp_validity(*args)


def is_ident_cp(cp: 'wchar32_t') ->bool:
    """Can a character appear in a name? (present in ::NameChars or ::MangleChars)
"""
    return _ida_name.is_ident_cp(cp)


def is_strlit_cp(cp: 'wchar32_t', specific_ranges:
    'rangeset_crefvec_t const *'=None) ->bool:
    """Can a character appear in a string literal (present in ::StrlitChars) If 'specific_ranges' are specified, those will be used instead of the ones corresponding to the current culture (only if ::StrlitChars is configured to use the current culture) 
        """
    return _ida_name.is_strlit_cp(cp, specific_ranges)


def is_visible_cp(cp: 'wchar32_t') ->bool:
    """Can a character be displayed in a name? (present in ::NameChars)
"""
    return _ida_name.is_visible_cp(cp)


def is_ident(name: str) ->bool:
    """Is a valid name? (including ::MangleChars)
"""
    return _ida_name.is_ident(name)


def is_uname(name: str) ->bool:
    """Is valid user-specified name? (valid name & !dummy prefix). 
        
@param name: name to test. may be nullptr.
@retval 1: yes
@retval 0: no"""
    return _ida_name.is_uname(name)


def is_valid_typename(name: str) ->bool:
    """Is valid type name? 
        
@param name: name to test. may be nullptr.
@retval 1: yes
@retval 0: no"""
    return _ida_name.is_valid_typename(name)


def extract_name(line: str, x: int) ->str:
    """Extract a name or address from the specified string. 
        
@param line: input string
@param x: x coordinate of cursor
@returns -1 if cannot extract. otherwise length of the name"""
    return _ida_name.extract_name(line, x)


def hide_name(ea: ida_idaapi.ea_t) ->None:
    """Remove name from the list of names 
        
@param ea: address of the name"""
    return _ida_name.hide_name(ea)


def show_name(ea: ida_idaapi.ea_t) ->None:
    """Insert name to the list of names.
"""
    return _ida_name.show_name(ea)


def get_name_ea(_from: ida_idaapi.ea_t, name: str) ->ida_idaapi.ea_t:
    """Get the address of a name. This function resolves a name into an address. It can handle regular global and local names, as well as debugger names. 
        
@param name: any name in the program or nullptr
@returns address of the name or BADADDR"""
    return _ida_name.get_name_ea(_from, name)


def get_name_base_ea(_from: ida_idaapi.ea_t, to: ida_idaapi.ea_t
    ) ->ida_idaapi.ea_t:
    """Get address of the name used in the expression for the address 
        
@param to: the referenced address
@returns address of the name used to represent the operand"""
    return _ida_name.get_name_base_ea(_from, to)


def get_name_value(_from: ida_idaapi.ea_t, name: str) ->'uval_t *':
    """Get value of the name. This function knows about: regular names, enums, special segments, etc. 
        
@param name: any name in the program or nullptr
@returns Name value result codes"""
    return _ida_name.get_name_value(_from, name)


NT_NONE = _ida_name.NT_NONE
"""name doesn't exist or has no value
"""
NT_BYTE = _ida_name.NT_BYTE
"""name is byte name (regular name)
"""
NT_LOCAL = _ida_name.NT_LOCAL
"""name is local label
"""
NT_STKVAR = _ida_name.NT_STKVAR
"""name is stack variable name
"""
NT_ENUM = _ida_name.NT_ENUM
"""name is symbolic constant
"""
NT_ABS = _ida_name.NT_ABS
"""name is absolute symbol (SEG_ABSSYM)
"""
NT_SEG = _ida_name.NT_SEG
"""name is segment or segment register name
"""
NT_STROFF = _ida_name.NT_STROFF
"""name is structure member
"""
NT_BMASK = _ida_name.NT_BMASK
"""name is a bit group mask name
"""
NT_REGVAR = _ida_name.NT_REGVAR
"""name is a renamed register (*value is idx into pfn->regvars)
"""
GN_VISIBLE = _ida_name.GN_VISIBLE
"""replace forbidden characters by SUBSTCHAR
"""
GN_COLORED = _ida_name.GN_COLORED
"""return colored name
"""
GN_DEMANGLED = _ida_name.GN_DEMANGLED
"""return demangled name
"""
GN_STRICT = _ida_name.GN_STRICT
"""fail if cannot demangle
"""
GN_SHORT = _ida_name.GN_SHORT
"""use short form of demangled name
"""
GN_LONG = _ida_name.GN_LONG
"""use long form of demangled name
"""
GN_LOCAL = _ida_name.GN_LOCAL
"""try to get local name first; if failed, get global
"""
GN_ISRET = _ida_name.GN_ISRET
"""for dummy names: use retloc
"""
GN_NOT_ISRET = _ida_name.GN_NOT_ISRET
"""for dummy names: do not use retloc
"""
GN_NOT_DUMMY = _ida_name.GN_NOT_DUMMY
"""do not return a dummy name
"""


def get_visible_name(ea: ida_idaapi.ea_t, gtn_flags: int=0) ->str:
    return _ida_name.get_visible_name(ea, gtn_flags)


def get_short_name(ea: ida_idaapi.ea_t, gtn_flags: int=0) ->str:
    return _ida_name.get_short_name(ea, gtn_flags)


def get_long_name(ea: ida_idaapi.ea_t, gtn_flags: int=0) ->str:
    return _ida_name.get_long_name(ea, gtn_flags)


def get_colored_short_name(ea: ida_idaapi.ea_t, gtn_flags: int=0) ->str:
    return _ida_name.get_colored_short_name(ea, gtn_flags)


def get_colored_long_name(ea: ida_idaapi.ea_t, gtn_flags: int=0) ->str:
    return _ida_name.get_colored_long_name(ea, gtn_flags)


def get_demangled_name(ea: ida_idaapi.ea_t, inhibitor: int, demform: int,
    gtn_flags: int=0) ->str:
    return _ida_name.get_demangled_name(ea, inhibitor, demform, gtn_flags)


def get_colored_demangled_name(ea: ida_idaapi.ea_t, inhibitor: int, demform:
    int, gtn_flags: int=0) ->str:
    return _ida_name.get_colored_demangled_name(ea, inhibitor, demform,
        gtn_flags)


def get_name_color(_from: ida_idaapi.ea_t, ea: ida_idaapi.ea_t) ->'color_t':
    """Calculate flags for get_ea_name() function.

Get name color. 
        
@param ea: linear address"""
    return _ida_name.get_name_color(_from, ea)


GETN_APPZERO = _ida_name.GETN_APPZERO
"""meaningful only if the name refers to a structure. append a struct field name if the field offset is zero? 
        """
GETN_NOFIXUP = _ida_name.GETN_NOFIXUP
"""ignore the fixup information when producing the name
"""
GETN_NODUMMY = _ida_name.GETN_NODUMMY
"""do not create a new dummy name but pretend it exists
"""


def get_name_expr(_from: ida_idaapi.ea_t, n: int, ea: ida_idaapi.ea_t, off:
    int, flags: int=1) ->str:
    """Convert address to name expression (name with a displacement). This function takes into account fixup information and returns a colored name expression (in the form <name> +/- <offset>). It also knows about structure members and arrays. If the specified address doesn't have a name, a dummy name is generated. 
        
@param n: number of referencing operand. for data items specify 0
@param ea: address to convert to name expression
@param off: the value of name expression. this parameter is used only to check that the name expression will have the wanted value. 'off' may be equal to BADADDR but this is discouraged because it prohibits checks.
@param flags: Name expression flags
@returns < 0 if address is not valid, no segment or other failure. otherwise the length of the name expression in characters."""
    return _ida_name.get_name_expr(_from, n, ea, off, flags)


def get_nice_colored_name(ea: ida_idaapi.ea_t, flags: int=0) ->str:
    """Get a nice colored name at the specified address. Ex:
* segment:sub+offset
* segment:sub:local_label
* segment:label
* segment:address
* segment:address+offset



@param ea: linear address
@param flags: Nice colored name flags
@returns the length of the generated name in bytes."""
    return _ida_name.get_nice_colored_name(ea, flags)


GNCN_NOSEG = _ida_name.GNCN_NOSEG
"""ignore the segment prefix when producing the name
"""
GNCN_NOCOLOR = _ida_name.GNCN_NOCOLOR
"""generate an uncolored name
"""
GNCN_NOLABEL = _ida_name.GNCN_NOLABEL
"""don't generate labels
"""
GNCN_NOFUNC = _ida_name.GNCN_NOFUNC
"""don't generate funcname+... expressions
"""
GNCN_SEG_FUNC = _ida_name.GNCN_SEG_FUNC
"""generate both segment and function names (default is to omit segment name if a function name is present)
"""
GNCN_SEGNUM = _ida_name.GNCN_SEGNUM
"""segment part is displayed as a hex number
"""
GNCN_REQFUNC = _ida_name.GNCN_REQFUNC
"""return 0 if the address does not belong to a function
"""
GNCN_REQNAME = _ida_name.GNCN_REQNAME
"""return 0 if the address can only be represented as a hex number
"""
GNCN_NODBGNM = _ida_name.GNCN_NODBGNM
"""don't use debug names
"""
GNCN_PREFDBG = _ida_name.GNCN_PREFDBG
"""if using debug names, prefer debug names over function names
"""


def append_struct_fields(disp: 'adiff_t *', n: int, path: 'tid_t const *',
    flags: 'flags64_t', delta: 'adiff_t', appzero: bool) ->str:
    """Append names of struct fields to a name if the name is a struct name. 
        
@param disp: displacement from the name
@param n: operand number in which the name appears
@param path: path in the struct. path is an array of id's. maximal length of array is MAXSTRUCPATH. the first element of the array is the structure id. consecutive elements are id's of used union members (if any).
@param flags: the input flags. they will be returned if the struct cannot be found.
@param delta: delta to add to displacement
@param appzero: should append a struct field name if the displacement is zero?
@returns flags of the innermost struct member or the input flags"""
    return _ida_name.append_struct_fields(disp, n, path, flags, delta, appzero)


def is_public_name(ea: ida_idaapi.ea_t) ->bool:
    return _ida_name.is_public_name(ea)


def make_name_public(ea: ida_idaapi.ea_t) ->None:
    return _ida_name.make_name_public(ea)


def make_name_non_public(ea: ida_idaapi.ea_t) ->None:
    return _ida_name.make_name_non_public(ea)


def is_weak_name(ea: ida_idaapi.ea_t) ->bool:
    return _ida_name.is_weak_name(ea)


def make_name_weak(ea: ida_idaapi.ea_t) ->None:
    return _ida_name.make_name_weak(ea)


def make_name_non_weak(ea: ida_idaapi.ea_t) ->None:
    return _ida_name.make_name_non_weak(ea)


def get_nlist_size() ->'size_t':
    return _ida_name.get_nlist_size()


def get_nlist_idx(ea: ida_idaapi.ea_t) ->'size_t':
    return _ida_name.get_nlist_idx(ea)


def is_in_nlist(ea: ida_idaapi.ea_t) ->bool:
    return _ida_name.is_in_nlist(ea)


def get_nlist_ea(idx: 'size_t') ->ida_idaapi.ea_t:
    return _ida_name.get_nlist_ea(idx)


def get_nlist_name(idx: 'size_t') ->str:
    return _ida_name.get_nlist_name(idx)


def rebuild_nlist() ->None:
    return _ida_name.rebuild_nlist()


def reorder_dummy_names() ->None:
    """Renumber dummy names.
"""
    return _ida_name.reorder_dummy_names()


DEBNAME_EXACT = _ida_name.DEBNAME_EXACT
"""find a name at exactly the specified address
"""
DEBNAME_LOWER = _ida_name.DEBNAME_LOWER
"""find a name with the address >= the specified address
"""
DEBNAME_UPPER = _ida_name.DEBNAME_UPPER
"""find a name with the address > the specified address
"""
DEBNAME_NICE = _ida_name.DEBNAME_NICE
"""find a name with the address <= the specified address
"""


class ea_name_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    ea: 'ea_t' = property(_ida_name.ea_name_t_ea_get, _ida_name.
        ea_name_t_ea_set)
    name: 'qstring' = property(_ida_name.ea_name_t_name_get, _ida_name.
        ea_name_t_name_set)

    def __init__(self, *args):
        _ida_name.ea_name_t_swiginit(self, _ida_name.new_ea_name_t(*args))
    __swig_destroy__ = _ida_name.delete_ea_name_t


_ida_name.ea_name_t_swigregister(ea_name_t)


def set_debug_name(ea: ida_idaapi.ea_t, name: str) ->bool:
    return _ida_name.set_debug_name(ea, name)


def get_debug_name(ea_ptr: 'ea_t *', how: 'debug_name_how_t') ->str:
    return _ida_name.get_debug_name(ea_ptr, how)


def del_debug_names(ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t) ->None:
    return _ida_name.del_debug_names(ea1, ea2)


def get_debug_name_ea(name: str) ->ida_idaapi.ea_t:
    return _ida_name.get_debug_name_ea(name)


DQT_NPURGED_8 = _ida_name.DQT_NPURGED_8
"""only calculate number of purged bytes (sizeof(arg)==8)
"""
DQT_NPURGED_4 = _ida_name.DQT_NPURGED_4
"""only calculate number of purged bytes (sizeof(arg)==4)
"""
DQT_NPURGED_2 = _ida_name.DQT_NPURGED_2
"""only calculate number of purged bytes (sizeof(arg)==2)
"""
DQT_COMPILER = _ida_name.DQT_COMPILER
"""only detect compiler that generated the name
"""
DQT_NAME_TYPE = _ida_name.DQT_NAME_TYPE
"""only detect the name type (data/code)
"""
DQT_FULL = _ida_name.DQT_FULL
"""really demangle
"""


def demangle_name(name: str, disable_mask: int, demreq: 'demreq_type_t'=
    DQT_FULL) ->str:
    """Demangle a name. 
        
@param name: name to demangle
@param disable_mask: bits to inhibit parts of demangled name (see MNG_). by the M_COMPILER bits a specific compiler can be selected (see MT_).
@param demreq: the request type demreq_type_t
@returns ME_... or MT__ bitmasks from demangle.hpp"""
    return _ida_name.demangle_name(name, disable_mask, demreq)


def is_name_defined_locally(*args) ->bool:
    """Is the name defined locally in the specified function? 
        
@param pfn: pointer to function
@param name: name to check
@param ignore_name_def: which names to ignore when checking
@param ea1: the starting address of the range inside the function (optional)
@param ea2: the ending address of the range inside the function (optional)
@returns true if the name has been defined"""
    return _ida_name.is_name_defined_locally(*args)


def cleanup_name(ea: ida_idaapi.ea_t, name: str, flags: int=0) ->str:
    return _ida_name.cleanup_name(ea, name, flags)


CN_KEEP_TRAILING_DIGITS = _ida_name.CN_KEEP_TRAILING_DIGITS
"""do not remove "_\\d+" at the end of name
"""
CN_KEEP_UNDERSCORES = _ida_name.CN_KEEP_UNDERSCORES
"""do not remove leading underscores. but it is ok to remove __imp_. 
        """
ME_INTERR = _ida_name.ME_INTERR
ME_PARAMERR = _ida_name.ME_PARAMERR
ME_ILLSTR = _ida_name.ME_ILLSTR
ME_SMALLANS = _ida_name.ME_SMALLANS
ME_FRAME = _ida_name.ME_FRAME
ME_NOCOMP = _ida_name.ME_NOCOMP
ME_ERRAUTO = _ida_name.ME_ERRAUTO
ME_NOHASHMEM = _ida_name.ME_NOHASHMEM
ME_NOSTRMEM = _ida_name.ME_NOSTRMEM
ME_NOERROR_LIMIT = _ida_name.ME_NOERROR_LIMIT
M_PRCMSK = _ida_name.M_PRCMSK
MT_DEFAULT = _ida_name.MT_DEFAULT
MT_CDECL = _ida_name.MT_CDECL
MT_PASCAL = _ida_name.MT_PASCAL
MT_STDCALL = _ida_name.MT_STDCALL
MT_FASTCALL = _ida_name.MT_FASTCALL
MT_THISCALL = _ida_name.MT_THISCALL
MT_FORTRAN = _ida_name.MT_FORTRAN
MT_SYSCALL = _ida_name.MT_SYSCALL
MT_INTERRUPT = _ida_name.MT_INTERRUPT
MT_MSFASTCALL = _ida_name.MT_MSFASTCALL
MT_CLRCALL = _ida_name.MT_CLRCALL
MT_DMDCALL = _ida_name.MT_DMDCALL
MT_VECTORCALL = _ida_name.MT_VECTORCALL
MT_REGCALL = _ida_name.MT_REGCALL
MT_LOCALNAME = _ida_name.MT_LOCALNAME
M_SAVEREGS = _ida_name.M_SAVEREGS
M_CLASS = _ida_name.M_CLASS
MT_PUBLIC = _ida_name.MT_PUBLIC
MT_PRIVATE = _ida_name.MT_PRIVATE
MT_PROTECT = _ida_name.MT_PROTECT
MT_MEMBER = _ida_name.MT_MEMBER
MT_VTABLE = _ida_name.MT_VTABLE
MT_RTTI = _ida_name.MT_RTTI
M_PARMSK = _ida_name.M_PARMSK
MT_PARSHF = _ida_name.MT_PARSHF
MT_PARMAX = _ida_name.MT_PARMAX
M_ELLIPSIS = _ida_name.M_ELLIPSIS
MT_VOIDARG = _ida_name.MT_VOIDARG
M_STATIC = _ida_name.M_STATIC
M_VIRTUAL = _ida_name.M_VIRTUAL
M_AUTOCRT = _ida_name.M_AUTOCRT
M_TYPMASK = _ida_name.M_TYPMASK
MT_OPERAT = _ida_name.MT_OPERAT
MT_CONSTR = _ida_name.MT_CONSTR
MT_DESTR = _ida_name.MT_DESTR
MT_CASTING = _ida_name.MT_CASTING
MT_CLRCDTOR = _ida_name.MT_CLRCDTOR
M_TRUNCATE = _ida_name.M_TRUNCATE
M_THUNK = _ida_name.M_THUNK
M_ANONNSP = _ida_name.M_ANONNSP
M_TMPLNAM = _ida_name.M_TMPLNAM
M_DBGNAME = _ida_name.M_DBGNAME
M_COMPILER = _ida_name.M_COMPILER
MT_MSCOMP = _ida_name.MT_MSCOMP
MT_BORLAN = _ida_name.MT_BORLAN
MT_WATCOM = _ida_name.MT_WATCOM
MT_OTHER = _ida_name.MT_OTHER
MT_GNU = _ida_name.MT_GNU
MT_GCC3 = _ida_name.MT_GCC3
MT_VISAGE = _ida_name.MT_VISAGE
MNG_PTRMSK = _ida_name.MNG_PTRMSK
MNG_DEFNEAR = _ida_name.MNG_DEFNEAR
MNG_DEFNEARANY = _ida_name.MNG_DEFNEARANY
MNG_DEFFAR = _ida_name.MNG_DEFFAR
MNG_NOPTRTYP16 = _ida_name.MNG_NOPTRTYP16
MNG_DEFHUGE = _ida_name.MNG_DEFHUGE
MNG_DEFPTR64 = _ida_name.MNG_DEFPTR64
MNG_DEFNONE = _ida_name.MNG_DEFNONE
MNG_NOPTRTYP = _ida_name.MNG_NOPTRTYP
MNG_NODEFINIT = _ida_name.MNG_NODEFINIT
MNG_NOUNDERSCORE = _ida_name.MNG_NOUNDERSCORE
MNG_NOTYPE = _ida_name.MNG_NOTYPE
MNG_NORETTYPE = _ida_name.MNG_NORETTYPE
MNG_NOBASEDT = _ida_name.MNG_NOBASEDT
MNG_NOCALLC = _ida_name.MNG_NOCALLC
MNG_NOPOSTFC = _ida_name.MNG_NOPOSTFC
MNG_NOSCTYP = _ida_name.MNG_NOSCTYP
MNG_NOTHROW = _ida_name.MNG_NOTHROW
MNG_NOSTVIR = _ida_name.MNG_NOSTVIR
MNG_NOECSU = _ida_name.MNG_NOECSU
MNG_NOCSVOL = _ida_name.MNG_NOCSVOL
MNG_NOCLOSUR = _ida_name.MNG_NOCLOSUR
MNG_NOUNALG = _ida_name.MNG_NOUNALG
MNG_NOMANAGE = _ida_name.MNG_NOMANAGE
MNG_NOMODULE = _ida_name.MNG_NOMODULE
MNG_SHORT_S = _ida_name.MNG_SHORT_S
MNG_SHORT_U = _ida_name.MNG_SHORT_U
MNG_ZPT_SPACE = _ida_name.MNG_ZPT_SPACE
MNG_DROP_IMP = _ida_name.MNG_DROP_IMP
MNG_IGN_ANYWAY = _ida_name.MNG_IGN_ANYWAY
MNG_IGN_JMP = _ida_name.MNG_IGN_JMP
MNG_MOVE_JMP = _ida_name.MNG_MOVE_JMP
MNG_COMPILER_MSK = _ida_name.MNG_COMPILER_MSK
MNG_SHORT_FORM = _ida_name.MNG_SHORT_FORM
MNG_LONG_FORM = _ida_name.MNG_LONG_FORM
MNG_CALC_VALID = _ida_name.MNG_CALC_VALID


def get_mangled_name_type(name: str) ->'mangled_name_type_t':
    return _ida_name.get_mangled_name_type(name)


def get_debug_names(*args) ->'PyObject *':
    return _ida_name.get_debug_names(*args)


def get_ea_name(ea: ida_idaapi.ea_t, gtn_flags: int=0) ->str:
    """Get name at the specified address. 
        
@param ea: linear address
@param gtn_flags: how exactly the name should be retrieved. combination of bits for get_ea_name() function. There is a convenience bits
@returns success"""
    return _ida_name.get_ea_name(ea, gtn_flags)


def validate_name(name: str, type: 'nametype_t', flags: int=1) ->'PyObject *':
    """Validate a name. If SN_NOCHECK is specified, this function replaces all invalid characters in the name with SUBSTCHAR. However, it will return false if name is valid but not allowed to be an identifier (is a register name).

@param name: ptr to name. the name will be modified
@param type: the type of name we want to validate
@param flags: see SN_*
@returns success"""
    return _ida_name.validate_name(name, type, flags)


import _ida_idaapi
import _ida_funcs
import bisect


class NearestName(object):
    """
    Utility class to help find the nearest name in a given ea/name dictionary
    """

    def __init__(self, ea_names):
        self.update(ea_names)

    def update(self, ea_names):
        """Updates the ea/names map"""
        self._names = ea_names
        self._addrs = list(ea_names.keys())
        self._addrs.sort()

    def find(self, ea):
        """
        Returns a tupple (ea, name, pos) that is the nearest to the passed ea
        If no name is matched then None is returned
        """
        pos = bisect.bisect_left(self._addrs, ea)
        if pos >= len(self._addrs):
            return None
        if self._addrs[pos] != ea:
            pos -= 1
        if pos < 0:
            return None
        return self[pos]

    def _get_item(self, index):
        ea = self._addrs[index]
        return ea, self._names[ea], index

    def __iter__(self):
        return (self._get_item(index) for index in range(0, len(self._addrs)))

    def __getitem__(self, index):
        """Returns the tupple (ea, name, index)"""
        if index > len(self._addrs):
            raise StopIteration
        return self._get_item(index)


def calc_gtn_flags(fromaddr, ea):
    """
    Calculate flags for get_ea_name() function

    @param fromaddr: the referring address. May be BADADDR.
    @param ea: linear address

    @return: flags
    """
    gtn_flags = 0
    if fromaddr != _ida_idaapi.BADADDR:
        pfn = _ida_funcs.get_func(fromaddr)
        if _ida_funcs.func_contains(pfn, ea):
            gtn_flags = GN_LOCAL
    return gtn_flags


cvar = _ida_name.cvar
ignore_none = cvar.ignore_none
ignore_regvar = cvar.ignore_regvar
ignore_llabel = cvar.ignore_llabel
ignore_stkvar = cvar.ignore_stkvar
ignore_glabel = cvar.ignore_glabel
MANGLED_CODE = cvar.MANGLED_CODE
MANGLED_DATA = cvar.MANGLED_DATA
MANGLED_UNKNOWN = cvar.MANGLED_UNKNOWN

```
