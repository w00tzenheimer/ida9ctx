```python
"""Definitions of various information kept in netnodes.

Each address in the program has a corresponding netnode: netnode(ea).
If we have no information about an address, the corresponding netnode is not created. Otherwise we will create a netnode and save information in it. All variable length information (names, comments, offset information, etc) is stored in the netnode.
Don't forget that some information is already stored in the flags (bytes.hpp)
netnode. 
    """
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_nalt
else:
    import _ida_nalt
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
SWIG_PYTHON_LEGACY_BOOL = _ida_nalt.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi


class custom_data_type_ids_fids_array(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    data: 'short (&)[8]' = property(_ida_nalt.
        custom_data_type_ids_fids_array_data_get)

    def __init__(self, data: 'short (&)[8]'):
        _ida_nalt.custom_data_type_ids_fids_array_swiginit(self, _ida_nalt.
            new_custom_data_type_ids_fids_array(data))

    def __len__(self) ->'size_t':
        return _ida_nalt.custom_data_type_ids_fids_array___len__(self)

    def __getitem__(self, i: 'size_t') ->'short const &':
        return _ida_nalt.custom_data_type_ids_fids_array___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'short const &') ->None:
        return _ida_nalt.custom_data_type_ids_fids_array___setitem__(self, i, v
            )

    def _get_bytes(self) ->'bytevec_t':
        return _ida_nalt.custom_data_type_ids_fids_array__get_bytes(self)

    def _set_bytes(self, bts: 'bytevec_t const &') ->None:
        return _ida_nalt.custom_data_type_ids_fids_array__set_bytes(self, bts)
    __iter__ = ida_idaapi._bounded_getitem_iterator
    bytes = property(_get_bytes, _set_bytes)
    __swig_destroy__ = _ida_nalt.delete_custom_data_type_ids_fids_array


_ida_nalt.custom_data_type_ids_fids_array_swigregister(
    custom_data_type_ids_fids_array)


class strpath_ids_array(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    data: 'unsigned long long (&)[32]' = property(_ida_nalt.
        strpath_ids_array_data_get)

    def __init__(self, data: 'unsigned long long (&)[32]'):
        _ida_nalt.strpath_ids_array_swiginit(self, _ida_nalt.
            new_strpath_ids_array(data))

    def __len__(self) ->'size_t':
        return _ida_nalt.strpath_ids_array___len__(self)

    def __getitem__(self, i: 'size_t') ->'unsigned long long const &':
        return _ida_nalt.strpath_ids_array___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'unsigned long long const &') ->None:
        return _ida_nalt.strpath_ids_array___setitem__(self, i, v)

    def _get_bytes(self) ->'bytevec_t':
        return _ida_nalt.strpath_ids_array__get_bytes(self)

    def _set_bytes(self, bts: 'bytevec_t const &') ->None:
        return _ida_nalt.strpath_ids_array__set_bytes(self, bts)
    __iter__ = ida_idaapi._bounded_getitem_iterator
    bytes = property(_get_bytes, _set_bytes)
    __swig_destroy__ = _ida_nalt.delete_strpath_ids_array


_ida_nalt.strpath_ids_array_swigregister(strpath_ids_array)
NALT_SWITCH = _ida_nalt.NALT_SWITCH
"""switch idiom address (used at jump targets)
"""
NALT_STRUCT = _ida_nalt.NALT_STRUCT
"""struct id
"""
NALT_AFLAGS = _ida_nalt.NALT_AFLAGS
"""additional flags for an item
"""
NALT_LINNUM = _ida_nalt.NALT_LINNUM
"""source line number
"""
NALT_ABSBASE = _ida_nalt.NALT_ABSBASE
"""absolute segment location
"""
NALT_ENUM0 = _ida_nalt.NALT_ENUM0
"""enum id for the first operand
"""
NALT_ENUM1 = _ida_nalt.NALT_ENUM1
"""enum id for the second operand
"""
NALT_PURGE = _ida_nalt.NALT_PURGE
"""number of bytes purged from the stack when a function is called indirectly
"""
NALT_STRTYPE = _ida_nalt.NALT_STRTYPE
"""type of string item
"""
NALT_ALIGN = _ida_nalt.NALT_ALIGN
"""alignment value if the item is FF_ALIGN (should by equal to power of 2) 
        """
NALT_COLOR = _ida_nalt.NALT_COLOR
"""instruction/data background color
"""
NSUP_CMT = _ida_nalt.NSUP_CMT
"""regular comment
"""
NSUP_REPCMT = _ida_nalt.NSUP_REPCMT
"""repeatable comment
"""
NSUP_FOP1 = _ida_nalt.NSUP_FOP1
"""forced operand 1
"""
NSUP_FOP2 = _ida_nalt.NSUP_FOP2
"""forced operand 2
"""
NSUP_JINFO = _ida_nalt.NSUP_JINFO
"""jump table info
"""
NSUP_ARRAY = _ida_nalt.NSUP_ARRAY
"""array parameters
"""
NSUP_OMFGRP = _ida_nalt.NSUP_OMFGRP
"""OMF: group of segments (not used anymore)
"""
NSUP_FOP3 = _ida_nalt.NSUP_FOP3
"""forced operand 3
"""
NSUP_SWITCH = _ida_nalt.NSUP_SWITCH
"""switch information
"""
NSUP_REF0 = _ida_nalt.NSUP_REF0
"""complex reference information for operand 1
"""
NSUP_REF1 = _ida_nalt.NSUP_REF1
"""complex reference information for operand 2
"""
NSUP_REF2 = _ida_nalt.NSUP_REF2
"""complex reference information for operand 3
"""
NSUP_OREF0 = _ida_nalt.NSUP_OREF0
"""outer complex reference information for operand 1
"""
NSUP_OREF1 = _ida_nalt.NSUP_OREF1
"""outer complex reference information for operand 2
"""
NSUP_OREF2 = _ida_nalt.NSUP_OREF2
"""outer complex reference information for operand 3
"""
NSUP_STROFF0 = _ida_nalt.NSUP_STROFF0
"""stroff: struct path for the first operand
"""
NSUP_STROFF1 = _ida_nalt.NSUP_STROFF1
"""stroff: struct path for the second operand
"""
NSUP_SEGTRANS = _ida_nalt.NSUP_SEGTRANS
"""segment translations
"""
NSUP_FOP4 = _ida_nalt.NSUP_FOP4
"""forced operand 4
"""
NSUP_FOP5 = _ida_nalt.NSUP_FOP5
"""forced operand 5
"""
NSUP_FOP6 = _ida_nalt.NSUP_FOP6
"""forced operand 6
"""
NSUP_REF3 = _ida_nalt.NSUP_REF3
"""complex reference information for operand 4
"""
NSUP_REF4 = _ida_nalt.NSUP_REF4
"""complex reference information for operand 5
"""
NSUP_REF5 = _ida_nalt.NSUP_REF5
"""complex reference information for operand 6
"""
NSUP_OREF3 = _ida_nalt.NSUP_OREF3
"""outer complex reference information for operand 4
"""
NSUP_OREF4 = _ida_nalt.NSUP_OREF4
"""outer complex reference information for operand 5
"""
NSUP_OREF5 = _ida_nalt.NSUP_OREF5
"""outer complex reference information for operand 6
"""
NSUP_XREFPOS = _ida_nalt.NSUP_XREFPOS
"""saved xref address and type in the xrefs window
"""
NSUP_CUSTDT = _ida_nalt.NSUP_CUSTDT
"""custom data type id
"""
NSUP_GROUPS = _ida_nalt.NSUP_GROUPS
"""SEG_GRP: pack_dd encoded list of selectors.
"""
NSUP_ARGEAS = _ida_nalt.NSUP_ARGEAS
"""instructions that initialize call arguments
"""
NSUP_FOP7 = _ida_nalt.NSUP_FOP7
"""forced operand 7
"""
NSUP_FOP8 = _ida_nalt.NSUP_FOP8
"""forced operand 8
"""
NSUP_REF6 = _ida_nalt.NSUP_REF6
"""complex reference information for operand 7
"""
NSUP_REF7 = _ida_nalt.NSUP_REF7
"""complex reference information for operand 8
"""
NSUP_OREF6 = _ida_nalt.NSUP_OREF6
"""outer complex reference information for operand 7
"""
NSUP_OREF7 = _ida_nalt.NSUP_OREF7
"""outer complex reference information for operand 8
"""
NSUP_EX_FLAGS = _ida_nalt.NSUP_EX_FLAGS
"""Extended flags.
"""
NSUP_POINTS = _ida_nalt.NSUP_POINTS
"""SP change points blob (see funcs.cpp). values NSUP_POINTS..NSUP_POINTS+0x1000 are reserved 
        """
NSUP_MANUAL = _ida_nalt.NSUP_MANUAL
"""manual instruction. values NSUP_MANUAL..NSUP_MANUAL+0x1000 are reserved 
        """
NSUP_TYPEINFO = _ida_nalt.NSUP_TYPEINFO
"""type information. values NSUP_TYPEINFO..NSUP_TYPEINFO+0x1000 are reserved 
        """
NSUP_REGVAR = _ida_nalt.NSUP_REGVAR
"""register variables. values NSUP_REGVAR..NSUP_REGVAR+0x1000 are reserved 
        """
NSUP_LLABEL = _ida_nalt.NSUP_LLABEL
"""local labels. values NSUP_LLABEL..NSUP_LLABEL+0x1000 are reserved 
        """
NSUP_REGARG = _ida_nalt.NSUP_REGARG
"""register argument type/name descriptions values NSUP_REGARG..NSUP_REGARG+0x1000 are reserved 
        """
NSUP_FTAILS = _ida_nalt.NSUP_FTAILS
"""function tails or tail referers values NSUP_FTAILS..NSUP_FTAILS+0x1000 are reserved 
        """
NSUP_GROUP = _ida_nalt.NSUP_GROUP
"""graph group information values NSUP_GROUP..NSUP_GROUP+0x1000 are reserved 
        """
NSUP_OPTYPES = _ida_nalt.NSUP_OPTYPES
"""operand type information. values NSUP_OPTYPES..NSUP_OPTYPES+0x100000 are reserved 
        """
NSUP_ORIGFMD = _ida_nalt.NSUP_ORIGFMD
"""function metadata before lumina information was applied values NSUP_ORIGFMD..NSUP_ORIGFMD+0x1000 are reserved 
        """
NSUP_FRAME = _ida_nalt.NSUP_FRAME
"""function frame type values NSUP_FRAME..NSUP_FRAME+0x10000 are reserved 
        """
NALT_CREF_TO = _ida_nalt.NALT_CREF_TO
"""code xref to, idx: target address
"""
NALT_CREF_FROM = _ida_nalt.NALT_CREF_FROM
"""code xref from, idx: source address
"""
NALT_DREF_TO = _ida_nalt.NALT_DREF_TO
"""data xref to, idx: target address
"""
NALT_DREF_FROM = _ida_nalt.NALT_DREF_FROM
"""data xref from, idx: source address
"""
NSUP_GR_INFO = _ida_nalt.NSUP_GR_INFO
"""group node info: color, ea, text
"""
NALT_GR_LAYX = _ida_nalt.NALT_GR_LAYX
"""group layout ptrs, hash: md5 of 'belongs'
"""
NSUP_GR_LAYT = _ida_nalt.NSUP_GR_LAYT
"""group layouts, idx: layout pointer
"""
PATCH_TAG = _ida_nalt.PATCH_TAG
"""Patch netnode tag.
"""
IDB_DESKTOPS_NODE_NAME = _ida_nalt.IDB_DESKTOPS_NODE_NAME
"""hash indexed by desktop name with dekstop netnode
"""
IDB_DESKTOPS_TAG = _ida_nalt.IDB_DESKTOPS_TAG
"""tag to store desktop blob & timestamp
"""


def ea2node(ea: ida_idaapi.ea_t) ->'nodeidx_t':
    """Get netnode for the specified address.
"""
    return _ida_nalt.ea2node(ea)


def node2ea(ndx: 'nodeidx_t') ->ida_idaapi.ea_t:
    return _ida_nalt.node2ea(ndx)


def end_ea2node(ea: ida_idaapi.ea_t) ->'nodeidx_t':
    return _ida_nalt.end_ea2node(ea)


def getnode(ea: ida_idaapi.ea_t) ->'netnode':
    return _ida_nalt.getnode(ea)


def get_strid(ea: ida_idaapi.ea_t) ->'tid_t':
    return _ida_nalt.get_strid(ea)


AFL_LINNUM = _ida_nalt.AFL_LINNUM
"""has line number info
"""
AFL_USERSP = _ida_nalt.AFL_USERSP
"""user-defined SP value
"""
AFL_PUBNAM = _ida_nalt.AFL_PUBNAM
"""name is public (inter-file linkage)
"""
AFL_WEAKNAM = _ida_nalt.AFL_WEAKNAM
"""name is weak
"""
AFL_HIDDEN = _ida_nalt.AFL_HIDDEN
"""the item is hidden completely
"""
AFL_MANUAL = _ida_nalt.AFL_MANUAL
"""the instruction/data is specified by the user
"""
AFL_NOBRD = _ida_nalt.AFL_NOBRD
"""the code/data border is hidden
"""
AFL_ZSTROFF = _ida_nalt.AFL_ZSTROFF
"""display struct field name at 0 offset when displaying an offset. example: `offset somestruct.field_0 ` if this flag is clear, then `offset somestruct ` 
        """
AFL_BNOT0 = _ida_nalt.AFL_BNOT0
"""the 1st operand is bitwise negated
"""
AFL_BNOT1 = _ida_nalt.AFL_BNOT1
"""the 2nd operand is bitwise negated
"""
AFL_LIB = _ida_nalt.AFL_LIB
"""item from the standard library. low level flag, is used to set FUNC_LIB of func_t 
        """
AFL_TI = _ida_nalt.AFL_TI
"""has typeinfo? (NSUP_TYPEINFO); used only for addresses, not for member_t
"""
AFL_TI0 = _ida_nalt.AFL_TI0
"""has typeinfo for operand 0? (NSUP_OPTYPES)
"""
AFL_TI1 = _ida_nalt.AFL_TI1
"""has typeinfo for operand 1? (NSUP_OPTYPES+1)
"""
AFL_LNAME = _ida_nalt.AFL_LNAME
"""has local name too (FF_NAME should be set)
"""
AFL_TILCMT = _ida_nalt.AFL_TILCMT
"""has type comment? (such a comment may be changed by IDA)
"""
AFL_LZERO0 = _ida_nalt.AFL_LZERO0
"""toggle leading zeroes for the 1st operand
"""
AFL_LZERO1 = _ida_nalt.AFL_LZERO1
"""toggle leading zeroes for the 2nd operand
"""
AFL_COLORED = _ida_nalt.AFL_COLORED
"""has user defined instruction color?
"""
AFL_TERSESTR = _ida_nalt.AFL_TERSESTR
"""terse structure variable display?
"""
AFL_SIGN0 = _ida_nalt.AFL_SIGN0
"""code: toggle sign of the 1st operand
"""
AFL_SIGN1 = _ida_nalt.AFL_SIGN1
"""code: toggle sign of the 2nd operand
"""
AFL_NORET = _ida_nalt.AFL_NORET
"""for imported function pointers: doesn't return. this flag can also be used for any instruction which halts or finishes the program execution 
        """
AFL_FIXEDSPD = _ida_nalt.AFL_FIXEDSPD
"""sp delta value is fixed by analysis. should not be modified by modules 
        """
AFL_ALIGNFLOW = _ida_nalt.AFL_ALIGNFLOW
"""the previous insn was created for alignment purposes only
"""
AFL_USERTI = _ida_nalt.AFL_USERTI
"""the type information is definitive. (comes from the user or type library) if not set see AFL_TYPE_GUESSED 
        """
AFL_RETFP = _ida_nalt.AFL_RETFP
"""function returns a floating point value
"""
AFL_USEMODSP = _ida_nalt.AFL_USEMODSP
"""insn modifes SP and uses the modified value; example: pop [rsp+N] 
        """
AFL_NOTCODE = _ida_nalt.AFL_NOTCODE
"""autoanalysis should not create code here
"""
AFL_NOTPROC = _ida_nalt.AFL_NOTPROC
"""autoanalysis should not create proc here
"""
AFL_TYPE_GUESSED = _ida_nalt.AFL_TYPE_GUESSED
"""who guessed the type information?
"""
AFL_IDA_GUESSED = _ida_nalt.AFL_IDA_GUESSED
"""the type is guessed by IDA
"""
AFL_HR_GUESSED_FUNC = _ida_nalt.AFL_HR_GUESSED_FUNC
"""the function type is guessed by the decompiler
"""
AFL_HR_GUESSED_DATA = _ida_nalt.AFL_HR_GUESSED_DATA
"""the data type is guessed by the decompiler
"""
AFL_HR_DETERMINED = _ida_nalt.AFL_HR_DETERMINED
"""the type is definitely guessed by the decompiler
"""


def set_aflags(ea: ida_idaapi.ea_t, flags: 'aflags_t') ->None:
    return _ida_nalt.set_aflags(ea, flags)


def upd_abits(ea: ida_idaapi.ea_t, clr_bits: 'aflags_t', set_bits: 'aflags_t'
    ) ->None:
    return _ida_nalt.upd_abits(ea, clr_bits, set_bits)


def set_abits(ea: ida_idaapi.ea_t, bits: 'aflags_t') ->None:
    return _ida_nalt.set_abits(ea, bits)


def clr_abits(ea: ida_idaapi.ea_t, bits: 'aflags_t') ->None:
    return _ida_nalt.clr_abits(ea, bits)


def get_aflags(ea: ida_idaapi.ea_t) ->'aflags_t':
    return _ida_nalt.get_aflags(ea)


def del_aflags(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.del_aflags(ea)


def has_aflag_linnum(flags: 'aflags_t') ->bool:
    return _ida_nalt.has_aflag_linnum(flags)


def is_aflag_usersp(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag_usersp(flags)


def is_aflag_public_name(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag_public_name(flags)


def is_aflag_weak_name(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag_weak_name(flags)


def is_aflag_hidden_item(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag_hidden_item(flags)


def is_aflag_manual_insn(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag_manual_insn(flags)


def is_aflag_hidden_border(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag_hidden_border(flags)


def is_aflag_zstroff(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag_zstroff(flags)


def is_aflag__bnot0(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag__bnot0(flags)


def is_aflag__bnot1(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag__bnot1(flags)


def is_aflag_libitem(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag_libitem(flags)


def has_aflag_ti(flags: 'aflags_t') ->bool:
    return _ida_nalt.has_aflag_ti(flags)


def has_aflag_ti0(flags: 'aflags_t') ->bool:
    return _ida_nalt.has_aflag_ti0(flags)


def has_aflag_ti1(flags: 'aflags_t') ->bool:
    return _ida_nalt.has_aflag_ti1(flags)


def has_aflag_lname(flags: 'aflags_t') ->bool:
    return _ida_nalt.has_aflag_lname(flags)


def is_aflag_tilcmt(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag_tilcmt(flags)


def is_aflag_lzero0(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag_lzero0(flags)


def is_aflag_lzero1(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag_lzero1(flags)


def is_aflag_colored_item(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag_colored_item(flags)


def is_aflag_terse_struc(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag_terse_struc(flags)


def is_aflag__invsign0(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag__invsign0(flags)


def is_aflag__invsign1(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag__invsign1(flags)


def is_aflag_noret(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag_noret(flags)


def is_aflag_fixed_spd(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag_fixed_spd(flags)


def is_aflag_align_flow(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag_align_flow(flags)


def is_aflag_userti(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag_userti(flags)


def is_aflag_retfp(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag_retfp(flags)


def uses_aflag_modsp(flags: 'aflags_t') ->bool:
    return _ida_nalt.uses_aflag_modsp(flags)


def is_aflag_notcode(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag_notcode(flags)


def is_aflag_notproc(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag_notproc(flags)


def is_aflag_type_guessed_by_ida(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag_type_guessed_by_ida(flags)


def is_aflag_func_guessed_by_hexrays(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag_func_guessed_by_hexrays(flags)


def is_aflag_data_guessed_by_hexrays(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag_data_guessed_by_hexrays(flags)


def is_aflag_type_determined_by_hexrays(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag_type_determined_by_hexrays(flags)


def is_aflag_type_guessed_by_hexrays(flags: 'aflags_t') ->bool:
    return _ida_nalt.is_aflag_type_guessed_by_hexrays(flags)


def is_hidden_item(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.is_hidden_item(ea)


def hide_item(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.hide_item(ea)


def unhide_item(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.unhide_item(ea)


def is_hidden_border(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.is_hidden_border(ea)


def hide_border(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.hide_border(ea)


def unhide_border(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.unhide_border(ea)


def uses_modsp(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.uses_modsp(ea)


def set_usemodsp(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_usemodsp(ea)


def clr_usemodsp(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.clr_usemodsp(ea)


def is_zstroff(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.is_zstroff(ea)


def set_zstroff(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_zstroff(ea)


def clr_zstroff(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.clr_zstroff(ea)


def is__bnot0(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.is__bnot0(ea)


def set__bnot0(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set__bnot0(ea)


def clr__bnot0(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.clr__bnot0(ea)


def is__bnot1(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.is__bnot1(ea)


def set__bnot1(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set__bnot1(ea)


def clr__bnot1(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.clr__bnot1(ea)


def is_libitem(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.is_libitem(ea)


def set_libitem(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_libitem(ea)


def clr_libitem(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.clr_libitem(ea)


def has_ti(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.has_ti(ea)


def set_has_ti(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_has_ti(ea)


def clr_has_ti(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.clr_has_ti(ea)


def has_ti0(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.has_ti0(ea)


def set_has_ti0(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_has_ti0(ea)


def clr_has_ti0(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.clr_has_ti0(ea)


def has_ti1(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.has_ti1(ea)


def set_has_ti1(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_has_ti1(ea)


def clr_has_ti1(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.clr_has_ti1(ea)


def has_lname(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.has_lname(ea)


def set_has_lname(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_has_lname(ea)


def clr_has_lname(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.clr_has_lname(ea)


def is_tilcmt(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.is_tilcmt(ea)


def set_tilcmt(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_tilcmt(ea)


def clr_tilcmt(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.clr_tilcmt(ea)


def is_usersp(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.is_usersp(ea)


def set_usersp(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_usersp(ea)


def clr_usersp(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.clr_usersp(ea)


def is_lzero0(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.is_lzero0(ea)


def set_lzero0(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_lzero0(ea)


def clr_lzero0(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.clr_lzero0(ea)


def is_lzero1(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.is_lzero1(ea)


def set_lzero1(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_lzero1(ea)


def clr_lzero1(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.clr_lzero1(ea)


def is_colored_item(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.is_colored_item(ea)


def set_colored_item(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_colored_item(ea)


def clr_colored_item(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.clr_colored_item(ea)


def is_terse_struc(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.is_terse_struc(ea)


def set_terse_struc(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_terse_struc(ea)


def clr_terse_struc(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.clr_terse_struc(ea)


def is__invsign0(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.is__invsign0(ea)


def set__invsign0(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set__invsign0(ea)


def clr__invsign0(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.clr__invsign0(ea)


def is__invsign1(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.is__invsign1(ea)


def set__invsign1(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set__invsign1(ea)


def clr__invsign1(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.clr__invsign1(ea)


def is_noret(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.is_noret(ea)


def set_noret(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_noret(ea)


def clr_noret(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.clr_noret(ea)


def is_fixed_spd(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.is_fixed_spd(ea)


def set_fixed_spd(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_fixed_spd(ea)


def clr_fixed_spd(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.clr_fixed_spd(ea)


def is_align_flow(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.is_align_flow(ea)


def set_align_flow(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_align_flow(ea)


def clr_align_flow(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.clr_align_flow(ea)


def is_userti(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.is_userti(ea)


def set_userti(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_userti(ea)


def clr_userti(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.clr_userti(ea)


def is_retfp(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.is_retfp(ea)


def set_retfp(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_retfp(ea)


def clr_retfp(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.clr_retfp(ea)


def is_notproc(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.is_notproc(ea)


def set_notproc(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_notproc(ea)


def clr_notproc(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.clr_notproc(ea)


def is_type_guessed_by_ida(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.is_type_guessed_by_ida(ea)


def is_func_guessed_by_hexrays(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.is_func_guessed_by_hexrays(ea)


def is_data_guessed_by_hexrays(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.is_data_guessed_by_hexrays(ea)


def is_type_determined_by_hexrays(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.is_type_determined_by_hexrays(ea)


def is_type_guessed_by_hexrays(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.is_type_guessed_by_hexrays(ea)


def set_type_guessed_by_ida(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_type_guessed_by_ida(ea)


def set_func_guessed_by_hexrays(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_func_guessed_by_hexrays(ea)


def set_data_guessed_by_hexrays(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_data_guessed_by_hexrays(ea)


def set_type_determined_by_hexrays(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_type_determined_by_hexrays(ea)


def set_notcode(ea: ida_idaapi.ea_t) ->None:
    """Mark address so that it cannot be converted to instruction.
"""
    return _ida_nalt.set_notcode(ea)


def clr_notcode(ea: ida_idaapi.ea_t) ->None:
    """Clear not-code mark.
"""
    return _ida_nalt.clr_notcode(ea)


def is_notcode(ea: ida_idaapi.ea_t) ->bool:
    """Is the address marked as not-code?
"""
    return _ida_nalt.is_notcode(ea)


def set_visible_item(ea: ida_idaapi.ea_t, visible: bool) ->None:
    """Change visibility of item at given ea.
"""
    return _ida_nalt.set_visible_item(ea, visible)


def is_visible_item(ea: ida_idaapi.ea_t) ->bool:
    """Test visibility of item at given ea.
"""
    return _ida_nalt.is_visible_item(ea)


def is_finally_visible_item(ea: ida_idaapi.ea_t) ->bool:
    """Is instruction visible?
"""
    return _ida_nalt.is_finally_visible_item(ea)


def set_source_linnum(ea: ida_idaapi.ea_t, lnnum: int) ->None:
    return _ida_nalt.set_source_linnum(ea, lnnum)


def get_source_linnum(ea: ida_idaapi.ea_t) ->int:
    return _ida_nalt.get_source_linnum(ea)


def del_source_linnum(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.del_source_linnum(ea)


def get_absbase(ea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
    return _ida_nalt.get_absbase(ea)


def set_absbase(ea: ida_idaapi.ea_t, x: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_absbase(ea, x)


def del_absbase(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.del_absbase(ea)


def get_ind_purged(ea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
    return _ida_nalt.get_ind_purged(ea)


def del_ind_purged(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.del_ind_purged(ea)


def get_str_type(ea: ida_idaapi.ea_t) ->int:
    return _ida_nalt.get_str_type(ea)


def set_str_type(ea: ida_idaapi.ea_t, x: int) ->None:
    return _ida_nalt.set_str_type(ea, x)


def del_str_type(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.del_str_type(ea)


STRWIDTH_1B = _ida_nalt.STRWIDTH_1B
STRWIDTH_2B = _ida_nalt.STRWIDTH_2B
STRWIDTH_4B = _ida_nalt.STRWIDTH_4B
STRWIDTH_MASK = _ida_nalt.STRWIDTH_MASK
STRLYT_TERMCHR = _ida_nalt.STRLYT_TERMCHR
STRLYT_PASCAL1 = _ida_nalt.STRLYT_PASCAL1
STRLYT_PASCAL2 = _ida_nalt.STRLYT_PASCAL2
STRLYT_PASCAL4 = _ida_nalt.STRLYT_PASCAL4
STRLYT_MASK = _ida_nalt.STRLYT_MASK
STRLYT_SHIFT = _ida_nalt.STRLYT_SHIFT
STRTYPE_TERMCHR = _ida_nalt.STRTYPE_TERMCHR
"""C-style string.
"""
STRTYPE_C = _ida_nalt.STRTYPE_C
"""Zero-terminated 16bit chars.
"""
STRTYPE_C_16 = _ida_nalt.STRTYPE_C_16
"""Zero-terminated 32bit chars.
"""
STRTYPE_C_32 = _ida_nalt.STRTYPE_C_32
"""Pascal-style, one-byte length prefix.
"""
STRTYPE_PASCAL = _ida_nalt.STRTYPE_PASCAL
"""Pascal-style, 16bit chars, one-byte length prefix.
"""
STRTYPE_PASCAL_16 = _ida_nalt.STRTYPE_PASCAL_16
"""Pascal-style, 32bit chars, one-byte length prefix.
"""
STRTYPE_PASCAL_32 = _ida_nalt.STRTYPE_PASCAL_32
"""Pascal-style, two-byte length prefix.
"""
STRTYPE_LEN2 = _ida_nalt.STRTYPE_LEN2
"""Pascal-style, 16bit chars, two-byte length prefix.
"""
STRTYPE_LEN2_16 = _ida_nalt.STRTYPE_LEN2_16
"""Pascal-style, 32bit chars, two-byte length prefix.
"""
STRTYPE_LEN2_32 = _ida_nalt.STRTYPE_LEN2_32
"""Pascal-style, four-byte length prefix.
"""
STRTYPE_LEN4 = _ida_nalt.STRTYPE_LEN4
"""Pascal-style, 16bit chars, four-byte length prefix.
"""
STRTYPE_LEN4_16 = _ida_nalt.STRTYPE_LEN4_16
"""Pascal-style, 32bit chars, four-byte length prefix.
"""
STRTYPE_LEN4_32 = _ida_nalt.STRTYPE_LEN4_32


def get_str_type_code(strtype: int) ->'uchar':
    return _ida_nalt.get_str_type_code(strtype)


def get_str_term1(strtype: int) ->'char':
    return _ida_nalt.get_str_term1(strtype)


def get_str_term2(strtype: int) ->'char':
    return _ida_nalt.get_str_term2(strtype)


def get_str_encoding_idx(strtype: int) ->'uchar':
    return _ida_nalt.get_str_encoding_idx(strtype)


def set_str_encoding_idx(strtype: int, encoding_idx: int) ->int:
    return _ida_nalt.set_str_encoding_idx(strtype, encoding_idx)


def make_str_type(type_code: 'uchar', encoding_idx: int, term1: 'uchar'=0,
    term2: 'uchar'=0) ->int:
    return _ida_nalt.make_str_type(type_code, encoding_idx, term1, term2)


def is_pascal(strtype: int) ->bool:
    return _ida_nalt.is_pascal(strtype)


def get_str_type_prefix_length(strtype: int) ->'size_t':
    return _ida_nalt.get_str_type_prefix_length(strtype)


STRENC_DEFAULT = _ida_nalt.STRENC_DEFAULT
"""use default encoding for this type (see get_default_encoding_idx())
"""
STRENC_NONE = _ida_nalt.STRENC_NONE
"""force no-conversion encoding
"""


def get_alignment(ea: ida_idaapi.ea_t) ->int:
    return _ida_nalt.get_alignment(ea)


def set_alignment(ea: ida_idaapi.ea_t, x: int) ->None:
    return _ida_nalt.set_alignment(ea, x)


def del_alignment(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.del_alignment(ea)


def set_item_color(ea: ida_idaapi.ea_t, color: 'bgcolor_t') ->None:
    return _ida_nalt.set_item_color(ea, color)


def get_item_color(ea: ida_idaapi.ea_t) ->'bgcolor_t':
    return _ida_nalt.get_item_color(ea)


def del_item_color(ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.del_item_color(ea)


class array_parameters_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    flags: 'int32' = property(_ida_nalt.array_parameters_t_flags_get,
        _ida_nalt.array_parameters_t_flags_set)
    lineitems: 'int32' = property(_ida_nalt.
        array_parameters_t_lineitems_get, _ida_nalt.
        array_parameters_t_lineitems_set)
    """number of items on a line
"""
    alignment: 'int32' = property(_ida_nalt.
        array_parameters_t_alignment_get, _ida_nalt.
        array_parameters_t_alignment_set)
    """-1 - don't align. 0 - align automatically. else item width 
        """

    def __init__(self, _f: int=1, _l: int=0, _a: int=-1):
        _ida_nalt.array_parameters_t_swiginit(self, _ida_nalt.
            new_array_parameters_t(_f, _l, _a))

    def is_default(self) ->bool:
        return _ida_nalt.array_parameters_t_is_default(self)
    __swig_destroy__ = _ida_nalt.delete_array_parameters_t


_ida_nalt.array_parameters_t_swigregister(array_parameters_t)
AP_ALLOWDUPS = _ida_nalt.AP_ALLOWDUPS
"""use 'dup' construct
"""
AP_SIGNED = _ida_nalt.AP_SIGNED
"""treats numbers as signed
"""
AP_INDEX = _ida_nalt.AP_INDEX
"""display array element indexes as comments
"""
AP_ARRAY = _ida_nalt.AP_ARRAY
"""create as array (this flag is not stored in database)
"""
AP_IDXBASEMASK = _ida_nalt.AP_IDXBASEMASK
"""mask for number base of the indexes
"""
AP_IDXDEC = _ida_nalt.AP_IDXDEC
"""display indexes in decimal
"""
AP_IDXHEX = _ida_nalt.AP_IDXHEX
"""display indexes in hex
"""
AP_IDXOCT = _ida_nalt.AP_IDXOCT
"""display indexes in octal
"""
AP_IDXBIN = _ida_nalt.AP_IDXBIN
"""display indexes in binary
"""


def get_array_parameters(out: 'array_parameters_t', ea: ida_idaapi.ea_t
    ) ->'ssize_t':
    return _ida_nalt.get_array_parameters(out, ea)


def set_array_parameters(ea: ida_idaapi.ea_t, _in: 'array_parameters_t'
    ) ->None:
    return _ida_nalt.set_array_parameters(ea, _in)


def del_array_parameters(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.del_array_parameters(ea)


class switch_info_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    flags: 'uint32' = property(_ida_nalt.switch_info_t_flags_get, _ida_nalt
        .switch_info_t_flags_set)
    """Switch info flags 
        """

    def get_shift(self) ->int:
        """See SWI_SHIFT_MASK. possible answers: 0..3. 
        """
        return _ida_nalt.switch_info_t_get_shift(self)

    def set_shift(self, shift: int) ->None:
        """See SWI_SHIFT_MASK.
"""
        return _ida_nalt.switch_info_t_set_shift(self, shift)

    def get_jtable_element_size(self) ->int:
        return _ida_nalt.switch_info_t_get_jtable_element_size(self)

    def set_jtable_element_size(self, size: int) ->None:
        return _ida_nalt.switch_info_t_set_jtable_element_size(self, size)

    def get_vtable_element_size(self) ->int:
        return _ida_nalt.switch_info_t_get_vtable_element_size(self)

    def set_vtable_element_size(self, size: int) ->None:
        return _ida_nalt.switch_info_t_set_vtable_element_size(self, size)

    def has_default(self) ->bool:
        return _ida_nalt.switch_info_t_has_default(self)

    def has_elbase(self) ->bool:
        return _ida_nalt.switch_info_t_has_elbase(self)

    def is_sparse(self) ->bool:
        return _ida_nalt.switch_info_t_is_sparse(self)

    def is_custom(self) ->bool:
        return _ida_nalt.switch_info_t_is_custom(self)

    def is_indirect(self) ->bool:
        return _ida_nalt.switch_info_t_is_indirect(self)

    def is_subtract(self) ->bool:
        return _ida_nalt.switch_info_t_is_subtract(self)

    def is_nolowcase(self) ->bool:
        return _ida_nalt.switch_info_t_is_nolowcase(self)

    def use_std_table(self) ->bool:
        return _ida_nalt.switch_info_t_use_std_table(self)

    def is_user_defined(self) ->bool:
        return _ida_nalt.switch_info_t_is_user_defined(self)
    ncases: 'ushort' = property(_ida_nalt.switch_info_t_ncases_get,
        _ida_nalt.switch_info_t_ncases_set)
    """number of cases (excluding default)
"""
    jumps: 'ea_t' = property(_ida_nalt.switch_info_t_jumps_get, _ida_nalt.
        switch_info_t_jumps_set)
    """jump table start address
"""
    values: 'ea_t' = property(_ida_nalt.switch_info_t_values_get, _ida_nalt
        .switch_info_t_values_set)
    """values table address (if SWI_SPARSE is set)
"""
    lowcase: 'uval_t' = property(_ida_nalt.switch_info_t_lowcase_get,
        _ida_nalt.switch_info_t_lowcase_set)
    """the lowest value in cases
"""
    defjump: 'ea_t' = property(_ida_nalt.switch_info_t_defjump_get,
        _ida_nalt.switch_info_t_defjump_set)
    """default jump address (BADADDR if no default case)
"""
    startea: 'ea_t' = property(_ida_nalt.switch_info_t_startea_get,
        _ida_nalt.switch_info_t_startea_set)
    """start of the switch idiom
"""
    jcases: 'int' = property(_ida_nalt.switch_info_t_jcases_get, _ida_nalt.
        switch_info_t_jcases_set)
    """number of entries in the jump table (SWI_INDIRECT)
"""
    ind_lowcase: 'sval_t' = property(_ida_nalt.
        switch_info_t_ind_lowcase_get, _ida_nalt.switch_info_t_ind_lowcase_set)

    def get_lowcase(self) ->int:
        return _ida_nalt.switch_info_t_get_lowcase(self)
    elbase: 'ea_t' = property(_ida_nalt.switch_info_t_elbase_get, _ida_nalt
        .switch_info_t_elbase_set)
    """element base
"""
    regnum: 'int' = property(_ida_nalt.switch_info_t_regnum_get, _ida_nalt.
        switch_info_t_regnum_set)
    """the switch expression as a value of the REGNUM register before the instruction at EXPR_EA. -1 means 'unknown' 
        """
    regdtype: 'op_dtype_t' = property(_ida_nalt.switch_info_t_regdtype_get,
        _ida_nalt.switch_info_t_regdtype_set)
    """size of the switch expression register as dtype
"""

    def get_jtable_size(self) ->int:
        return _ida_nalt.switch_info_t_get_jtable_size(self)

    def set_jtable_size(self, size: int) ->None:
        return _ida_nalt.switch_info_t_set_jtable_size(self, size)

    def set_elbase(self, base: ida_idaapi.ea_t) ->None:
        return _ida_nalt.switch_info_t_set_elbase(self, base)

    def set_expr(self, r: int, dt: 'op_dtype_t') ->None:
        return _ida_nalt.switch_info_t_set_expr(self, r, dt)

    def get_jrange_vrange(self, jrange: 'range_t'=None, vrange: 'range_t'=None
        ) ->bool:
        """get separate parts of the switch
"""
        return _ida_nalt.switch_info_t_get_jrange_vrange(self, jrange, vrange)
    custom: 'uval_t' = property(_ida_nalt.switch_info_t_custom_get,
        _ida_nalt.switch_info_t_custom_set)
    """information for custom tables (filled and used by modules)
"""
    SWITCH_INFO_VERSION = _ida_nalt.switch_info_t_SWITCH_INFO_VERSION

    def get_version(self) ->int:
        return _ida_nalt.switch_info_t_get_version(self)
    expr_ea: 'ea_t' = property(_ida_nalt.switch_info_t_expr_ea_get,
        _ida_nalt.switch_info_t_expr_ea_set)
    """the address before that the switch expression is in REGNUM. If BADADDR, then the first insn marked as IM_SWITCH after STARTEA is used. 
        """
    marks: 'eavec_t' = property(_ida_nalt.switch_info_t_marks_get,
        _ida_nalt.switch_info_t_marks_set)
    """the insns marked as IM_SWITCH. They are used to delete the switch.
"""

    def __init__(self):
        _ida_nalt.switch_info_t_swiginit(self, _ida_nalt.new_switch_info_t())

    def clear(self) ->None:
        return _ida_nalt.switch_info_t_clear(self)

    def assign(self, other: 'switch_info_t') ->None:
        return _ida_nalt.switch_info_t_assign(self, other)

    def _get_values_lowcase(self) ->ida_idaapi.ea_t:
        return _ida_nalt.switch_info_t__get_values_lowcase(self)

    def _set_values_lowcase(self, values: ida_idaapi.ea_t) ->None:
        return _ida_nalt.switch_info_t__set_values_lowcase(self, values)
    values = property(_get_values_lowcase, _set_values_lowcase)
    """values table address (if SWI_SPARSE is set)
"""
    lowcase = property(_get_values_lowcase, _set_values_lowcase)
    """the lowest value in cases
"""
    __swig_destroy__ = _ida_nalt.delete_switch_info_t


_ida_nalt.switch_info_t_swigregister(switch_info_t)
SWI_SPARSE = _ida_nalt.SWI_SPARSE
"""sparse switch (value table present), otherwise lowcase present 
        """
SWI_V32 = _ida_nalt.SWI_V32
"""32-bit values in table
"""
SWI_J32 = _ida_nalt.SWI_J32
"""32-bit jump offsets
"""
SWI_VSPLIT = _ida_nalt.SWI_VSPLIT
"""value table is split (only for 32-bit values)
"""
SWI_USER = _ida_nalt.SWI_USER
"""user specified switch (starting from version 2)
"""
SWI_DEF_IN_TBL = _ida_nalt.SWI_DEF_IN_TBL
"""default case is an entry in the jump table. This flag is applicable in 2 cases:
* The sparse indirect switch (i.e. a switch with a values table) {jump table size} == {value table size} + 1. The default case entry is the last one in the table (or the first one in the case of an inversed jump table).
* The switch with insns in the jump table. The default case entry is before the first entry of the table. 
 See also the find_defjump_from_table() helper function. 


        """
SWI_JMP_INV = _ida_nalt.SWI_JMP_INV
"""jumptable is inversed. (last entry is for first entry in values table) 
        """
SWI_SHIFT_MASK = _ida_nalt.SWI_SHIFT_MASK
"""use formula (element<<shift) + elbase to find jump targets
"""
SWI_ELBASE = _ida_nalt.SWI_ELBASE
"""elbase is present (otherwise the base of the switch segment will be used) 
        """
SWI_JSIZE = _ida_nalt.SWI_JSIZE
"""jump offset expansion bit
"""
SWI_VSIZE = _ida_nalt.SWI_VSIZE
"""value table element size expansion bit
"""
SWI_SEPARATE = _ida_nalt.SWI_SEPARATE
"""create an array of individual elements (otherwise separate items)
"""
SWI_SIGNED = _ida_nalt.SWI_SIGNED
"""jump table entries are signed
"""
SWI_CUSTOM = _ida_nalt.SWI_CUSTOM
"""custom jump table. processor_t::create_switch_xrefs will be called to create code xrefs for the table. Custom jump table must be created by the module (see also SWI_STDTBL) 
        """
SWI_INDIRECT = _ida_nalt.SWI_INDIRECT
"""value table elements are used as indexes into the jump table (for sparse switches) 
        """
SWI_SUBTRACT = _ida_nalt.SWI_SUBTRACT
"""table values are subtracted from the elbase instead of being added
"""
SWI_HXNOLOWCASE = _ida_nalt.SWI_HXNOLOWCASE
"""lowcase value should not be used by the decompiler (internal flag)
"""
SWI_STDTBL = _ida_nalt.SWI_STDTBL
"""custom jump table with standard table formatting. ATM IDA doesn't use SWI_CUSTOM for switches with standard table formatting. So this flag can be considered as obsolete. 
        """
SWI_DEFRET = _ida_nalt.SWI_DEFRET
"""return in the default case (defjump==BADADDR)
"""
SWI_SELFREL = _ida_nalt.SWI_SELFREL
"""jump address is relative to the element not to ELBASE
"""
SWI_JMPINSN = _ida_nalt.SWI_JMPINSN
"""jump table entries are insns. For such entries SHIFT has a different meaning. It denotes the number of insns in the entry. For example, 0 - the entry contains the jump to the case, 1 - the entry contains one insn like a 'mov' and jump to the end of case, and so on. 
        """
SWI_VERSION = _ida_nalt.SWI_VERSION
"""the structure contains the VERSION member
"""


def get_switch_info(out: 'switch_info_t', ea: ida_idaapi.ea_t) ->'ssize_t':
    return _ida_nalt.get_switch_info(out, ea)


def set_switch_info(ea: ida_idaapi.ea_t, _in: 'switch_info_t') ->None:
    return _ida_nalt.set_switch_info(ea, _in)


def del_switch_info(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.del_switch_info(ea)


def get_switch_parent(ea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
    return _ida_nalt.get_switch_parent(ea)


def set_switch_parent(ea: ida_idaapi.ea_t, x: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_switch_parent(ea, x)


def del_switch_parent(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.del_switch_parent(ea)


class custom_data_type_ids_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    dtid: 'int16' = property(_ida_nalt.custom_data_type_ids_t_dtid_get,
        _ida_nalt.custom_data_type_ids_t_dtid_set)
    """data type id
"""
    fids: 'int16 [8]' = property(_ida_nalt.custom_data_type_ids_t_fids_get,
        _ida_nalt.custom_data_type_ids_t_fids_set)
    """data format ids
"""

    def set(self, tid: 'tid_t') ->None:
        return _ida_nalt.custom_data_type_ids_t_set(self, tid)

    def get_dtid(self) ->'tid_t':
        return _ida_nalt.custom_data_type_ids_t_get_dtid(self)

    def __getFids(self) ->'wrapped_array_t< int16,8 >':
        return _ida_nalt.custom_data_type_ids_t___getFids(self)
    fids = property(__getFids)
    """data format ids
"""

    def __init__(self):
        _ida_nalt.custom_data_type_ids_t_swiginit(self, _ida_nalt.
            new_custom_data_type_ids_t())
    __swig_destroy__ = _ida_nalt.delete_custom_data_type_ids_t


_ida_nalt.custom_data_type_ids_t_swigregister(custom_data_type_ids_t)


def get_custom_data_type_ids(cdis: 'custom_data_type_ids_t', ea:
    ida_idaapi.ea_t) ->int:
    return _ida_nalt.get_custom_data_type_ids(cdis, ea)


def set_custom_data_type_ids(ea: ida_idaapi.ea_t, cdis:
    'custom_data_type_ids_t') ->None:
    return _ida_nalt.set_custom_data_type_ids(ea, cdis)


def del_custom_data_type_ids(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.del_custom_data_type_ids(ea)


def is_reftype_target_optional(type: 'reftype_t') ->bool:
    """Can the target be calculated using operand value?
"""
    return _ida_nalt.is_reftype_target_optional(type)


def get_reftype_by_size(size: 'size_t') ->'reftype_t':
    """Get REF_... constant from size Supported sizes: 1,2,4,8,16 For other sizes returns reftype_t(-1) 
        """
    return _ida_nalt.get_reftype_by_size(size)


class refinfo_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    target: 'ea_t' = property(_ida_nalt.refinfo_t_target_get, _ida_nalt.
        refinfo_t_target_set)
    """reference target (BADADDR-none)
"""
    base: 'ea_t' = property(_ida_nalt.refinfo_t_base_get, _ida_nalt.
        refinfo_t_base_set)
    """base of reference (may be BADADDR)
"""
    tdelta: 'adiff_t' = property(_ida_nalt.refinfo_t_tdelta_get, _ida_nalt.
        refinfo_t_tdelta_set)
    """offset from the target
"""
    flags: 'uint32' = property(_ida_nalt.refinfo_t_flags_get, _ida_nalt.
        refinfo_t_flags_set)
    """Reference info flags 
        """

    def type(self) ->'reftype_t':
        return _ida_nalt.refinfo_t_type(self)

    def is_target_optional(self) ->bool:
        """< is_reftype_target_optional()
"""
        return _ida_nalt.refinfo_t_is_target_optional(self)

    def no_base_xref(self) ->bool:
        return _ida_nalt.refinfo_t_no_base_xref(self)

    def is_pastend(self) ->bool:
        return _ida_nalt.refinfo_t_is_pastend(self)

    def is_rvaoff(self) ->bool:
        return _ida_nalt.refinfo_t_is_rvaoff(self)

    def is_custom(self) ->bool:
        return _ida_nalt.refinfo_t_is_custom(self)

    def is_subtract(self) ->bool:
        return _ida_nalt.refinfo_t_is_subtract(self)

    def is_signed(self) ->bool:
        return _ida_nalt.refinfo_t_is_signed(self)

    def is_no_zeros(self) ->bool:
        return _ida_nalt.refinfo_t_is_no_zeros(self)

    def is_no_ones(self) ->bool:
        return _ida_nalt.refinfo_t_is_no_ones(self)

    def is_selfref(self) ->bool:
        return _ida_nalt.refinfo_t_is_selfref(self)

    def set_type(self, rt: 'reftype_t') ->None:
        return _ida_nalt.refinfo_t_set_type(self, rt)

    def init(self, *args) ->None:
        return _ida_nalt.refinfo_t_init(self, *args)

    def __init__(self):
        _ida_nalt.refinfo_t_swiginit(self, _ida_nalt.new_refinfo_t())
    __swig_destroy__ = _ida_nalt.delete_refinfo_t


_ida_nalt.refinfo_t_swigregister(refinfo_t)
cvar = _ida_nalt.cvar
V695_REF_OFF8 = cvar.V695_REF_OFF8
"""reserved
"""
REF_OFF16 = cvar.REF_OFF16
"""16bit full offset
"""
REF_OFF32 = cvar.REF_OFF32
"""32bit full offset
"""
REF_LOW8 = cvar.REF_LOW8
"""low 8bits of 16bit offset
"""
REF_LOW16 = cvar.REF_LOW16
"""low 16bits of 32bit offset
"""
REF_HIGH8 = cvar.REF_HIGH8
"""high 8bits of 16bit offset
"""
REF_HIGH16 = cvar.REF_HIGH16
"""high 16bits of 32bit offset
"""
V695_REF_VHIGH = cvar.V695_REF_VHIGH
"""obsolete
"""
V695_REF_VLOW = cvar.V695_REF_VLOW
"""obsolete
"""
REF_OFF64 = cvar.REF_OFF64
"""64bit full offset
"""
REF_OFF8 = cvar.REF_OFF8
"""8bit full offset
"""
REF_LAST = cvar.REF_LAST
REFINFO_TYPE = _ida_nalt.REFINFO_TYPE
"""reference type (reftype_t), or custom reference ID if REFINFO_CUSTOM set 
        """
REFINFO_RVAOFF = _ida_nalt.REFINFO_RVAOFF
"""based reference (rva); refinfo_t::base will be forced to get_imagebase(); such a reference is displayed with the asm_t::a_rva keyword 
        """
REFINFO_PASTEND = _ida_nalt.REFINFO_PASTEND
"""reference past an item; it may point to an nonexistent address; do not destroy alignment dirs 
        """
REFINFO_CUSTOM = _ida_nalt.REFINFO_CUSTOM
"""a custom reference. see custom_refinfo_handler_t. the id of the custom refinfo is stored under the REFINFO_TYPE mask. 
        """
REFINFO_NOBASE = _ida_nalt.REFINFO_NOBASE
"""don't create the base xref; implies that the base can be any value. nb: base xrefs are created only if the offset base points to the middle of a segment 
        """
REFINFO_SUBTRACT = _ida_nalt.REFINFO_SUBTRACT
"""the reference value is subtracted from the base value instead of (as usual) being added to it
"""
REFINFO_SIGNEDOP = _ida_nalt.REFINFO_SIGNEDOP
"""the operand value is sign-extended (only supported for REF_OFF8/16/32/64)
"""
REFINFO_NO_ZEROS = _ida_nalt.REFINFO_NO_ZEROS
"""an opval of 0 will be considered invalid
"""
REFINFO_NO_ONES = _ida_nalt.REFINFO_NO_ONES
"""an opval of ~0 will be considered invalid
"""
REFINFO_SELFREF = _ida_nalt.REFINFO_SELFREF
"""the self-based reference; refinfo_t::base will be forced to the reference address 
        """


def find_custom_refinfo(name: str) ->int:
    """Get id of a custom refinfo type.
"""
    return _ida_nalt.find_custom_refinfo(name)


def get_custom_refinfo(crid: int) ->'custom_refinfo_handler_t const *':
    """Get definition of a registered custom refinfo type.
"""
    return _ida_nalt.get_custom_refinfo(crid)


MAXSTRUCPATH = _ida_nalt.MAXSTRUCPATH
"""maximal inclusion depth of unions
"""


class strpath_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    len: 'int' = property(_ida_nalt.strpath_t_len_get, _ida_nalt.
        strpath_t_len_set)
    ids: 'tid_t [32]' = property(_ida_nalt.strpath_t_ids_get, _ida_nalt.
        strpath_t_ids_set)
    delta: 'adiff_t' = property(_ida_nalt.strpath_t_delta_get, _ida_nalt.
        strpath_t_delta_set)

    def __getIds(self) ->'wrapped_array_t< tid_t,32 >':
        return _ida_nalt.strpath_t___getIds(self)
    ids = property(__getIds)

    def __init__(self):
        _ida_nalt.strpath_t_swiginit(self, _ida_nalt.new_strpath_t())
    __swig_destroy__ = _ida_nalt.delete_strpath_t


_ida_nalt.strpath_t_swigregister(strpath_t)


class enum_const_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    tid: 'tid_t' = property(_ida_nalt.enum_const_t_tid_get, _ida_nalt.
        enum_const_t_tid_set)
    serial: 'uchar' = property(_ida_nalt.enum_const_t_serial_get, _ida_nalt
        .enum_const_t_serial_set)

    def __init__(self):
        _ida_nalt.enum_const_t_swiginit(self, _ida_nalt.new_enum_const_t())
    __swig_destroy__ = _ida_nalt.delete_enum_const_t


_ida_nalt.enum_const_t_swigregister(enum_const_t)


class opinfo_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    ri: 'refinfo_t' = property(_ida_nalt.opinfo_t_ri_get, _ida_nalt.
        opinfo_t_ri_set)
    """for offset members
"""
    tid: 'tid_t' = property(_ida_nalt.opinfo_t_tid_get, _ida_nalt.
        opinfo_t_tid_set)
    """for struct, etc. members
"""
    path: 'strpath_t' = property(_ida_nalt.opinfo_t_path_get, _ida_nalt.
        opinfo_t_path_set)
    """for stroff
"""
    strtype: 'int32' = property(_ida_nalt.opinfo_t_strtype_get, _ida_nalt.
        opinfo_t_strtype_set)
    """for strings (String type codes)
"""
    ec: 'enum_const_t' = property(_ida_nalt.opinfo_t_ec_get, _ida_nalt.
        opinfo_t_ec_set)
    """for enums
"""
    cd: 'custom_data_type_ids_t' = property(_ida_nalt.opinfo_t_cd_get,
        _ida_nalt.opinfo_t_cd_set)
    """for custom data
"""

    def __init__(self):
        _ida_nalt.opinfo_t_swiginit(self, _ida_nalt.new_opinfo_t())
    __swig_destroy__ = _ida_nalt.delete_opinfo_t


_ida_nalt.opinfo_t_swigregister(opinfo_t)


class printop_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    ti: 'opinfo_t' = property(_ida_nalt.printop_t_ti_get, _ida_nalt.
        printop_t_ti_set)
    features: 'uchar' = property(_ida_nalt.printop_t_features_get,
        _ida_nalt.printop_t_features_set)
    suspop: 'int' = property(_ida_nalt.printop_t_suspop_get, _ida_nalt.
        printop_t_suspop_set)
    aflags: 'aflags_t' = property(_ida_nalt.printop_t_aflags_get, _ida_nalt
        .printop_t_aflags_set)
    flags: 'flags64_t' = property(_ida_nalt.printop_t_flags_get, _ida_nalt.
        printop_t_flags_set)

    def __init__(self):
        _ida_nalt.printop_t_swiginit(self, _ida_nalt.new_printop_t())

    def is_ti_initialized(self) ->bool:
        return _ida_nalt.printop_t_is_ti_initialized(self)

    def set_ti_initialized(self, v: bool=True) ->None:
        return _ida_nalt.printop_t_set_ti_initialized(self, v)

    def is_aflags_initialized(self) ->bool:
        return _ida_nalt.printop_t_is_aflags_initialized(self)

    def set_aflags_initialized(self, v: bool=True) ->None:
        return _ida_nalt.printop_t_set_aflags_initialized(self, v)

    def is_f64(self) ->bool:
        return _ida_nalt.printop_t_is_f64(self)

    def get_ti(self) ->'opinfo_t const *':
        return _ida_nalt.printop_t_get_ti(self)
    is_ti_valid = property(is_ti_initialized, set_ti_initialized)
    __swig_destroy__ = _ida_nalt.delete_printop_t


_ida_nalt.printop_t_swigregister(printop_t)
POF_VALID_TI = _ida_nalt.POF_VALID_TI
POF_VALID_AFLAGS = _ida_nalt.POF_VALID_AFLAGS
POF_IS_F64 = _ida_nalt.POF_IS_F64


def set_refinfo_ex(ea: ida_idaapi.ea_t, n: int, ri: 'refinfo_t') ->bool:
    return _ida_nalt.set_refinfo_ex(ea, n, ri)


def set_refinfo(*args) ->bool:
    return _ida_nalt.set_refinfo(*args)


def get_refinfo(ri: 'refinfo_t', ea: ida_idaapi.ea_t, n: int) ->bool:
    return _ida_nalt.get_refinfo(ri, ea, n)


def del_refinfo(ea: ida_idaapi.ea_t, n: int) ->bool:
    return _ida_nalt.del_refinfo(ea, n)


def get_tinfo(tif: 'tinfo_t', ea: ida_idaapi.ea_t) ->bool:
    return _ida_nalt.get_tinfo(tif, ea)


def set_tinfo(ea: ida_idaapi.ea_t, tif: 'tinfo_t') ->bool:
    return _ida_nalt.set_tinfo(ea, tif)


def del_tinfo(ea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.del_tinfo(ea)


def get_op_tinfo(tif: 'tinfo_t', ea: ida_idaapi.ea_t, n: int) ->bool:
    return _ida_nalt.get_op_tinfo(tif, ea, n)


def set_op_tinfo(ea: ida_idaapi.ea_t, n: int, tif: 'tinfo_t') ->bool:
    return _ida_nalt.set_op_tinfo(ea, n, tif)


def del_op_tinfo(ea: ida_idaapi.ea_t, n: int) ->None:
    return _ida_nalt.del_op_tinfo(ea, n)


RIDX_FILE_FORMAT_NAME = _ida_nalt.RIDX_FILE_FORMAT_NAME
"""file format name for loader modules
"""
RIDX_SELECTORS = _ida_nalt.RIDX_SELECTORS
"""2..63 are for selector_t blob (see init_selectors())
"""
RIDX_GROUPS = _ida_nalt.RIDX_GROUPS
"""segment group information (see init_groups())
"""
RIDX_H_PATH = _ida_nalt.RIDX_H_PATH
"""C header path.
"""
RIDX_C_MACROS = _ida_nalt.RIDX_C_MACROS
"""C predefined macros.
"""
RIDX_SMALL_IDC_OLD = _ida_nalt.RIDX_SMALL_IDC_OLD
"""Instant IDC statements (obsolete)
"""
RIDX_NOTEPAD = _ida_nalt.RIDX_NOTEPAD
"""notepad blob, occupies 1000 indexes (1MB of text)
"""
RIDX_INCLUDE = _ida_nalt.RIDX_INCLUDE
"""assembler include file name
"""
RIDX_SMALL_IDC = _ida_nalt.RIDX_SMALL_IDC
"""Instant IDC statements, blob.
"""
RIDX_DUALOP_GRAPH = _ida_nalt.RIDX_DUALOP_GRAPH
"""Graph text representation options.
"""
RIDX_DUALOP_TEXT = _ida_nalt.RIDX_DUALOP_TEXT
"""Text text representation options.
"""
RIDX_MD5 = _ida_nalt.RIDX_MD5
"""MD5 of the input file.
"""
RIDX_IDA_VERSION = _ida_nalt.RIDX_IDA_VERSION
"""version of ida which created the database
"""
RIDX_STR_ENCODINGS = _ida_nalt.RIDX_STR_ENCODINGS
"""a list of encodings for the program strings
"""
RIDX_SRCDBG_PATHS = _ida_nalt.RIDX_SRCDBG_PATHS
"""source debug paths, occupies 20 indexes
"""
RIDX_DBG_BINPATHS = _ida_nalt.RIDX_DBG_BINPATHS
"""unused (20 indexes)
"""
RIDX_SHA256 = _ida_nalt.RIDX_SHA256
"""SHA256 of the input file.
"""
RIDX_ABINAME = _ida_nalt.RIDX_ABINAME
"""ABI name (processor specific)
"""
RIDX_ARCHIVE_PATH = _ida_nalt.RIDX_ARCHIVE_PATH
"""archive file path
"""
RIDX_PROBLEMS = _ida_nalt.RIDX_PROBLEMS
"""problem lists
"""
RIDX_SRCDBG_UNDESIRED = _ida_nalt.RIDX_SRCDBG_UNDESIRED
"""user-closed source files, occupies 20 indexes
"""


def get_root_filename() ->str:
    """Get file name only of the input file.
"""
    return _ida_nalt.get_root_filename()


def dbg_get_input_path() ->str:
    """Get debugger input file name/path (see LFLG_DBG_NOPATH)
"""
    return _ida_nalt.dbg_get_input_path()


def get_input_file_path() ->str:
    """Get full path of the input file.
"""
    return _ida_nalt.get_input_file_path()


def set_root_filename(file: str) ->None:
    """Set full path of the input file.
"""
    return _ida_nalt.set_root_filename(file)


def retrieve_input_file_size() ->'size_t':
    """Get size of input file in bytes.
"""
    return _ida_nalt.retrieve_input_file_size()


def retrieve_input_file_crc32() ->int:
    """Get input file crc32 stored in the database. it can be used to check that the input file has not been changed. 
        """
    return _ida_nalt.retrieve_input_file_crc32()


def retrieve_input_file_md5() ->bytes:
    """Get input file md5.
"""
    return _ida_nalt.retrieve_input_file_md5()


def retrieve_input_file_sha256() ->bytes:
    """Get input file sha256.
"""
    return _ida_nalt.retrieve_input_file_sha256()


def get_asm_inc_file() ->str:
    """Get name of the include file.
"""
    return _ida_nalt.get_asm_inc_file()


def set_asm_inc_file(file: str) ->bool:
    """Set name of the include file.
"""
    return _ida_nalt.set_asm_inc_file(file)


def get_imagebase() ->ida_idaapi.ea_t:
    """Get image base address.
"""
    return _ida_nalt.get_imagebase()


def set_imagebase(base: ida_idaapi.ea_t) ->None:
    """Set image base address.
"""
    return _ida_nalt.set_imagebase(base)


def get_ids_modnode() ->'netnode':
    """Get ids modnode.
"""
    return _ida_nalt.get_ids_modnode()


def set_ids_modnode(id: 'netnode') ->None:
    """Set ids modnode.
"""
    return _ida_nalt.set_ids_modnode(id)


def get_archive_path() ->str:
    """Get archive file path from which input file was extracted.
"""
    return _ida_nalt.get_archive_path()


def set_archive_path(file: str) ->bool:
    """Set archive file path from which input file was extracted.
"""
    return _ida_nalt.set_archive_path(file)


def get_loader_format_name() ->str:
    """Get file format name for loader modules.
"""
    return _ida_nalt.get_loader_format_name()


def set_loader_format_name(name: str) ->None:
    """Set file format name for loader modules.
"""
    return _ida_nalt.set_loader_format_name(name)


def get_initial_ida_version() ->str:
    """Get version of ida which created the database (string format like "7.5")
"""
    return _ida_nalt.get_initial_ida_version()


def get_ida_notepad_text() ->str:
    """Get notepad text.
"""
    return _ida_nalt.get_ida_notepad_text()


def set_ida_notepad_text(text: str, size: 'size_t'=0) ->None:
    """Set notepad text.
"""
    return _ida_nalt.set_ida_notepad_text(text, size)


def get_srcdbg_paths() ->str:
    """Get source debug paths.
"""
    return _ida_nalt.get_srcdbg_paths()


def set_srcdbg_paths(paths: str) ->None:
    """Set source debug paths.
"""
    return _ida_nalt.set_srcdbg_paths(paths)


def get_srcdbg_undesired_paths() ->str:
    """Get user-closed source files.
"""
    return _ida_nalt.get_srcdbg_undesired_paths()


def set_srcdbg_undesired_paths(paths: str) ->None:
    """Set user-closed source files.
"""
    return _ida_nalt.set_srcdbg_undesired_paths(paths)


def get_initial_idb_version() ->'ushort':
    """Get initial version of the database (numeric format like 700)
"""
    return _ida_nalt.get_initial_idb_version()


def get_idb_ctime() ->'time_t':
    """Get database creation timestamp.
"""
    return _ida_nalt.get_idb_ctime()


def get_elapsed_secs() ->'size_t':
    """Get seconds database stayed open.
"""
    return _ida_nalt.get_elapsed_secs()


def get_idb_nopens() ->'size_t':
    """Get number of times the database is opened.
"""
    return _ida_nalt.get_idb_nopens()


def get_encoding_qty() ->int:
    return _ida_nalt.get_encoding_qty()


def get_encoding_name(idx: int) ->str:
    return _ida_nalt.get_encoding_name(idx)


def add_encoding(encname: str) ->int:
    return _ida_nalt.add_encoding(encname)


def del_encoding(idx: int) ->bool:
    return _ida_nalt.del_encoding(idx)


def rename_encoding(idx: int, encname: str) ->bool:
    return _ida_nalt.rename_encoding(idx, encname)


BPU_1B = _ida_nalt.BPU_1B
BPU_2B = _ida_nalt.BPU_2B
BPU_4B = _ida_nalt.BPU_4B


def get_encoding_bpu(idx: int) ->int:
    return _ida_nalt.get_encoding_bpu(idx)


def get_encoding_bpu_by_name(encname: str) ->int:
    return _ida_nalt.get_encoding_bpu_by_name(encname)


def get_strtype_bpu(strtype: int) ->int:
    return _ida_nalt.get_strtype_bpu(strtype)


def get_default_encoding_idx(bpu: int) ->int:
    return _ida_nalt.get_default_encoding_idx(bpu)


def set_default_encoding_idx(bpu: int, idx: int) ->bool:
    return _ida_nalt.set_default_encoding_idx(bpu, idx)


def encoding_from_strtype(strtype: int) ->str:
    return _ida_nalt.encoding_from_strtype(strtype)


def get_outfile_encoding_idx() ->int:
    return _ida_nalt.get_outfile_encoding_idx()


def set_outfile_encoding_idx(idx: int) ->bool:
    return _ida_nalt.set_outfile_encoding_idx(idx)


def get_import_module_qty() ->'uint':
    return _ida_nalt.get_import_module_qty()


def delete_imports() ->None:
    return _ida_nalt.delete_imports()


GOTEA_NODE_NAME = _ida_nalt.GOTEA_NODE_NAME
"""node containing address of .got section
"""
GOTEA_NODE_IDX = _ida_nalt.GOTEA_NODE_IDX


def set_gotea(gotea: ida_idaapi.ea_t) ->None:
    return _ida_nalt.set_gotea(gotea)


def get_gotea() ->ida_idaapi.ea_t:
    return _ida_nalt.get_gotea()


def get_import_module_name(mod_index):
    """Returns the name of an imported module given its index

@param mod_index: the module index
@return: None or the module name"""
    return _ida_nalt.get_import_module_name(mod_index)


def enum_import_names(mod_index, callback):
    """Enumerate imports from a specific module.
Please refer to list_imports.py example.

@param mod_index: The module index
@param callback: A callable object that will be invoked with an ea, name (could be None) and ordinal.
@return: 1-finished ok, -1 on error, otherwise callback return value (<=0)"""
    return _ida_nalt.enum_import_names(mod_index, callback)


def switch_info_t__from_ptrval__(ptrval: 'size_t') ->'switch_info_t *':
    return _ida_nalt.switch_info_t__from_ptrval__(ptrval)


_real_get_switch_info = get_switch_info


def get_switch_info(*args):
    if len(args) == 1:
        si, ea = switch_info_t(), args[0]
    else:
        si, ea = args
    return None if _real_get_switch_info(si, ea) <= 0 else si


def get_abi_name():
    import ida_typeinf
    return ida_typeinf.get_abi_name()


get_initial_version = get_initial_idb_version

```
