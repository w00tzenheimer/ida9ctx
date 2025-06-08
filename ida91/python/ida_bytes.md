```python
"""Contains functions that deal with individual byte characteristics.

Each byte of the disassembled program is represented by a 32-bit value. We will call this value 'flags'. The structure of the flags is here.
You are not allowed to inspect individual bits of flags and modify them directly. Use special functions to inspect and/or modify flags.
Flags are kept in a virtual array file (*.id1). Addresses (ea) are all 32-bit (or 64-bit) quantities. 
    """
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_bytes
else:
    import _ida_bytes
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
SWIG_PYTHON_LEGACY_BOOL = _ida_bytes.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi
import ida_range


class compiled_binpat_vec_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_bytes.compiled_binpat_vec_t_swiginit(self, _ida_bytes.
            new_compiled_binpat_vec_t(*args))
    __swig_destroy__ = _ida_bytes.delete_compiled_binpat_vec_t

    def push_back(self, *args) ->'compiled_binpat_t &':
        return _ida_bytes.compiled_binpat_vec_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_bytes.compiled_binpat_vec_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_bytes.compiled_binpat_vec_t_size(self)

    def empty(self) ->bool:
        return _ida_bytes.compiled_binpat_vec_t_empty(self)

    def at(self, _idx: 'size_t') ->'compiled_binpat_t const &':
        return _ida_bytes.compiled_binpat_vec_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_bytes.compiled_binpat_vec_t_qclear(self)

    def clear(self) ->None:
        return _ida_bytes.compiled_binpat_vec_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_bytes.compiled_binpat_vec_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_bytes.compiled_binpat_vec_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_bytes.compiled_binpat_vec_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_bytes.compiled_binpat_vec_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_bytes.compiled_binpat_vec_t_truncate(self)

    def swap(self, r: 'compiled_binpat_vec_t') ->None:
        return _ida_bytes.compiled_binpat_vec_t_swap(self, r)

    def extract(self) ->'compiled_binpat_t *':
        return _ida_bytes.compiled_binpat_vec_t_extract(self)

    def inject(self, s: 'compiled_binpat_t', len: 'size_t') ->None:
        return _ida_bytes.compiled_binpat_vec_t_inject(self, s, len)

    def __eq__(self, r: 'compiled_binpat_vec_t') ->bool:
        return _ida_bytes.compiled_binpat_vec_t___eq__(self, r)

    def __ne__(self, r: 'compiled_binpat_vec_t') ->bool:
        return _ida_bytes.compiled_binpat_vec_t___ne__(self, r)

    def begin(self, *args) ->'qvector< compiled_binpat_t >::const_iterator':
        return _ida_bytes.compiled_binpat_vec_t_begin(self, *args)

    def end(self, *args) ->'qvector< compiled_binpat_t >::const_iterator':
        return _ida_bytes.compiled_binpat_vec_t_end(self, *args)

    def insert(self, it: 'compiled_binpat_t', x: 'compiled_binpat_t'
        ) ->'qvector< compiled_binpat_t >::iterator':
        return _ida_bytes.compiled_binpat_vec_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< compiled_binpat_t >::iterator':
        return _ida_bytes.compiled_binpat_vec_t_erase(self, *args)

    def find(self, *args) ->'qvector< compiled_binpat_t >::const_iterator':
        return _ida_bytes.compiled_binpat_vec_t_find(self, *args)

    def has(self, x: 'compiled_binpat_t') ->bool:
        return _ida_bytes.compiled_binpat_vec_t_has(self, x)

    def add_unique(self, x: 'compiled_binpat_t') ->bool:
        return _ida_bytes.compiled_binpat_vec_t_add_unique(self, x)

    def _del(self, x: 'compiled_binpat_t') ->bool:
        return _ida_bytes.compiled_binpat_vec_t__del(self, x)

    def __len__(self) ->'size_t':
        return _ida_bytes.compiled_binpat_vec_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'compiled_binpat_t const &':
        return _ida_bytes.compiled_binpat_vec_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'compiled_binpat_t') ->None:
        return _ida_bytes.compiled_binpat_vec_t___setitem__(self, i, v)

    def append(self, x: 'compiled_binpat_t') ->None:
        return _ida_bytes.compiled_binpat_vec_t_append(self, x)

    def extend(self, x: 'compiled_binpat_vec_t') ->None:
        return _ida_bytes.compiled_binpat_vec_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_bytes.compiled_binpat_vec_t_swigregister(compiled_binpat_vec_t)


def enable_flags(start_ea: ida_idaapi.ea_t, end_ea: ida_idaapi.ea_t, stt:
    'storage_type_t') ->'error_t':
    """Allocate flags for address range. This function does not change the storage type of existing ranges. Exit with an error message if not enough disk space. 
        
@param start_ea: should be lower than end_ea.
@param end_ea: does not belong to the range.
@param stt: storage_type_t
@returns 0 if ok, otherwise an error code"""
    return _ida_bytes.enable_flags(start_ea, end_ea, stt)


def disable_flags(start_ea: ida_idaapi.ea_t, end_ea: ida_idaapi.ea_t
    ) ->'error_t':
    """Deallocate flags for address range. Exit with an error message if not enough disk space (this may occur too). 
        
@param start_ea: should be lower than end_ea.
@param end_ea: does not belong to the range.
@returns 0 if ok, otherwise return error code"""
    return _ida_bytes.disable_flags(start_ea, end_ea)


def change_storage_type(start_ea: ida_idaapi.ea_t, end_ea: ida_idaapi.ea_t,
    stt: 'storage_type_t') ->'error_t':
    """Change flag storage type for address range. 
        
@param start_ea: should be lower than end_ea.
@param end_ea: does not belong to the range.
@param stt: storage_type_t
@returns error code"""
    return _ida_bytes.change_storage_type(start_ea, end_ea, stt)


def next_addr(ea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
    """Get next address in the program (i.e. next address which has flags). 
        
@returns BADADDR if no such address exist."""
    return _ida_bytes.next_addr(ea)


def prev_addr(ea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
    """Get previous address in the program. 
        
@returns BADADDR if no such address exist."""
    return _ida_bytes.prev_addr(ea)


def next_chunk(ea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
    """Get the first address of next contiguous chunk in the program. 
        
@returns BADADDR if next chunk doesn't exist."""
    return _ida_bytes.next_chunk(ea)


def prev_chunk(ea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
    """Get the last address of previous contiguous chunk in the program. 
        
@returns BADADDR if previous chunk doesn't exist."""
    return _ida_bytes.prev_chunk(ea)


def chunk_start(ea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
    """Get start of the contiguous address block containing 'ea'. 
        
@returns BADADDR if 'ea' doesn't belong to the program."""
    return _ida_bytes.chunk_start(ea)


def chunk_size(ea: ida_idaapi.ea_t) ->'asize_t':
    """Get size of the contiguous address block containing 'ea'. 
        
@returns 0 if 'ea' doesn't belong to the program."""
    return _ida_bytes.chunk_size(ea)


def find_free_chunk(start: ida_idaapi.ea_t, size: 'asize_t', alignment:
    'asize_t') ->ida_idaapi.ea_t:
    """Search for a hole in the addressing space of the program. 
        
@param start: Address to start searching from
@param size: Size of the desired empty range
@param alignment: Alignment bitmask, must be a pow2-1. (for example, 0xF would align the returned range to 16 bytes).
@returns Start of the found empty range or BADADDR"""
    return _ida_bytes.find_free_chunk(start, size, alignment)


def next_that(ea: ida_idaapi.ea_t, maxea: ida_idaapi.ea_t, testf: 'testf_t *'
    ) ->ida_idaapi.ea_t:
    """Find next address with a flag satisfying the function 'testf'. 
        
@param ea: start searching at this address + 1
@param maxea: not included in the search range.
@param testf: test function to find next address
@returns the found address or BADADDR."""
    return _ida_bytes.next_that(ea, maxea, testf)


def next_unknown(ea: ida_idaapi.ea_t, maxea: ida_idaapi.ea_t
    ) ->ida_idaapi.ea_t:
    """Similar to next_that(), but will find the next address that is unexplored.
"""
    return _ida_bytes.next_unknown(ea, maxea)


def prev_that(ea: ida_idaapi.ea_t, minea: ida_idaapi.ea_t, testf: 'testf_t *'
    ) ->ida_idaapi.ea_t:
    """Find previous address with a flag satisfying the function 'testf'. 
        
@param ea: start searching from this address - 1.
@param minea: included in the search range.
@param testf: test function to find previous address
@returns the found address or BADADDR."""
    return _ida_bytes.prev_that(ea, minea, testf)


def prev_unknown(ea: ida_idaapi.ea_t, minea: ida_idaapi.ea_t
    ) ->ida_idaapi.ea_t:
    """Similar to prev_that(), but will find the previous address that is unexplored.
"""
    return _ida_bytes.prev_unknown(ea, minea)


def prev_head(ea: ida_idaapi.ea_t, minea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
    """Get start of previous defined item. 
        
@param ea: begin search at this address
@param minea: included in the search range
@returns BADADDR if none exists."""
    return _ida_bytes.prev_head(ea, minea)


def next_head(ea: ida_idaapi.ea_t, maxea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
    """Get start of next defined item. 
        
@param ea: begin search at this address
@param maxea: not included in the search range
@returns BADADDR if none exists."""
    return _ida_bytes.next_head(ea, maxea)


def prev_not_tail(ea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
    """Get address of previous non-tail byte. 
        
@returns BADADDR if none exists."""
    return _ida_bytes.prev_not_tail(ea)


def next_not_tail(ea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
    """Get address of next non-tail byte. 
        
@returns BADADDR if none exists."""
    return _ida_bytes.next_not_tail(ea)


def prev_visea(ea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
    """Get previous visible address. 
        
@returns BADADDR if none exists."""
    return _ida_bytes.prev_visea(ea)


def next_visea(ea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
    """Get next visible address. 
        
@returns BADADDR if none exists."""
    return _ida_bytes.next_visea(ea)


def get_item_head(ea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
    """Get the start address of the item at 'ea'. If there is no current item, then 'ea' will be returned (see definition at the end of bytes.hpp source) 
        """
    return _ida_bytes.get_item_head(ea)


def get_item_end(ea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
    """Get the end address of the item at 'ea'. The returned address doesn't belong to the current item. Unexplored bytes are counted as 1 byte entities. 
        """
    return _ida_bytes.get_item_end(ea)


def calc_max_item_end(ea: ida_idaapi.ea_t, how: int=15) ->ida_idaapi.ea_t:
    """Calculate maximal reasonable end address of a new item. This function will limit the item with the current segment bounds. 
        
@param ea: linear address
@param how: when to stop the search. A combination of Item end search flags
@returns end of new item. If it is not possible to create an item, it will return 'ea'. If operation was cancelled by user, it will return 'ea'"""
    return _ida_bytes.calc_max_item_end(ea, how)


ITEM_END_FIXUP = _ida_bytes.ITEM_END_FIXUP
"""stop at the first fixup
"""
ITEM_END_INITED = _ida_bytes.ITEM_END_INITED
"""stop when initialization changes i.e.
* if is_loaded(ea): stop if uninitialized byte is encountered
* if !is_loaded(ea): stop if initialized byte is encountered 


        """
ITEM_END_NAME = _ida_bytes.ITEM_END_NAME
"""stop at the first named location
"""
ITEM_END_XREF = _ida_bytes.ITEM_END_XREF
"""stop at the first referenced location
"""
ITEM_END_CANCEL = _ida_bytes.ITEM_END_CANCEL
"""stop when operation cancelled, it is the responsibility of the caller to show the wait dialog 
        """


def get_item_size(ea: ida_idaapi.ea_t) ->'asize_t':
    """Get size of item (instruction/data) in bytes. Unexplored bytes have length of 1 byte. This function returns 0 only for BADADDR. 
        """
    return _ida_bytes.get_item_size(ea)


def is_mapped(ea: ida_idaapi.ea_t) ->bool:
    """Is the specified address 'ea' present in the program?
"""
    return _ida_bytes.is_mapped(ea)


def get_flags_ex(ea: ida_idaapi.ea_t, how: int) ->'flags64_t':
    """Get flags for the specified address, extended form.
"""
    return _ida_bytes.get_flags_ex(ea, how)


GFE_VALUE = _ida_bytes.GFE_VALUE
"""get flags with FF_IVL & MS_VAL. It is much slower under remote debugging because the kernel needs to read the process memory. 
        """
GFE_IDB_VALUE = _ida_bytes.GFE_IDB_VALUE
"""get flags with FF_IVL & MS_VAL. but never use the debugger memory. 
        """


def get_flags(ea: ida_idaapi.ea_t) ->'flags64_t':
    """get flags with FF_IVL & MS_VAL. It is much slower under remote debugging because the kernel needs to read the process memory. 
        """
    return _ida_bytes.get_flags(ea)


def get_full_flags(ea: ida_idaapi.ea_t) ->'flags64_t':
    """Get flags value for address 'ea'. 
        
@returns 0 if address is not present in the program"""
    return _ida_bytes.get_full_flags(ea)


def get_item_flag(_from: ida_idaapi.ea_t, n: int, ea: ida_idaapi.ea_t,
    appzero: bool) ->'flags64_t':
    """Get flag of the item at 'ea' even if it is a tail byte of some array or structure. This function is used to get flags of structure members or array elements. 
        
@param n: operand number which refers to 'ea' or OPND_ALL for one of the operands
@param ea: the referenced address
@param appzero: append a struct field name if the field offset is zero? meaningful only if the name refers to a structure.
@returns flags or 0 (if failed)"""
    return _ida_bytes.get_item_flag(_from, n, ea, appzero)


def get_item_refinfo(ri: 'refinfo_t', ea: ida_idaapi.ea_t, n: int) ->bool:
    """Get refinfo of the item at 'ea'. This function works for a regular offset operand as well as for a tail byte of a structure variable (in this case refinfo to corresponding structure member will be returned) 
        
@param ri: refinfo holder
@param ea: the item address
@param n: operand number which refers to 'ea' or OPND_ALL for one of the operands
@returns success"""
    return _ida_bytes.get_item_refinfo(ri, ea, n)


MS_VAL = _ida_bytes.MS_VAL
"""Mask for byte value.
"""
FF_IVL = _ida_bytes.FF_IVL
"""Byte has value ?
"""


def has_value(F: 'flags64_t') ->bool:
    """Do flags contain byte value?
"""
    return _ida_bytes.has_value(F)


def del_value(ea: ida_idaapi.ea_t) ->None:
    """Delete byte value from flags. The corresponding byte becomes uninitialized. 
        """
    return _ida_bytes.del_value(ea)


def is_loaded(ea: ida_idaapi.ea_t) ->bool:
    """Does the specified address have a byte value (is initialized?)
"""
    return _ida_bytes.is_loaded(ea)


def nbits(ea: ida_idaapi.ea_t) ->int:
    """Get number of bits in a byte at the given address. 
        
@returns processor_t::dnbits() if the address doesn't belong to a segment, otherwise the result depends on the segment type"""
    return _ida_bytes.nbits(ea)


def bytesize(ea: ida_idaapi.ea_t) ->int:
    """Get number of bytes required to store a byte at the given address.
"""
    return _ida_bytes.bytesize(ea)


def get_byte(ea: ida_idaapi.ea_t) ->'uchar':
    """Get one byte (8-bit) of the program at 'ea'. This function works only for 8bit byte processors. 
        """
    return _ida_bytes.get_byte(ea)


def get_db_byte(ea: ida_idaapi.ea_t) ->'uchar':
    """Get one byte (8-bit) of the program at 'ea' from the database. Works even if the debugger is active. See also get_dbg_byte() to read the process memory directly. This function works only for 8bit byte processors. 
        """
    return _ida_bytes.get_db_byte(ea)


def get_word(ea: ida_idaapi.ea_t) ->'ushort':
    """Get one word (16-bit) of the program at 'ea'. This function takes into account order of bytes specified in idainfo::is_be() This function works only for 8bit byte processors. 
        """
    return _ida_bytes.get_word(ea)


def get_dword(ea: ida_idaapi.ea_t) ->int:
    """Get one dword (32-bit) of the program at 'ea'. This function takes into account order of bytes specified in idainfo::is_be() This function works only for 8bit byte processors. 
        """
    return _ida_bytes.get_dword(ea)


def get_qword(ea: ida_idaapi.ea_t) ->'uint64':
    """Get one qword (64-bit) of the program at 'ea'. This function takes into account order of bytes specified in idainfo::is_be() This function works only for 8bit byte processors. 
        """
    return _ida_bytes.get_qword(ea)


def get_wide_byte(ea: ida_idaapi.ea_t) ->'uint64':
    """Get one wide byte of the program at 'ea'. Some processors may access more than 8bit quantity at an address. These processors have 32-bit byte organization from the IDA's point of view. 
        """
    return _ida_bytes.get_wide_byte(ea)


def get_wide_word(ea: ida_idaapi.ea_t) ->'uint64':
    """Get one wide word (2 'byte') of the program at 'ea'. Some processors may access more than 8bit quantity at an address. These processors have 32-bit byte organization from the IDA's point of view. This function takes into account order of bytes specified in idainfo::is_be() 
        """
    return _ida_bytes.get_wide_word(ea)


def get_wide_dword(ea: ida_idaapi.ea_t) ->'uint64':
    """Get two wide words (4 'bytes') of the program at 'ea'. Some processors may access more than 8bit quantity at an address. These processors have 32-bit byte organization from the IDA's point of view. This function takes into account order of bytes specified in idainfo::is_be() 
        """
    return _ida_bytes.get_wide_dword(ea)


class octet_generator_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    value: 'uint64' = property(_ida_bytes.octet_generator_t_value_get,
        _ida_bytes.octet_generator_t_value_set)
    ea: 'ea_t' = property(_ida_bytes.octet_generator_t_ea_get, _ida_bytes.
        octet_generator_t_ea_set)
    avail_bits: 'int' = property(_ida_bytes.
        octet_generator_t_avail_bits_get, _ida_bytes.
        octet_generator_t_avail_bits_set)
    high_byte_first: 'bool' = property(_ida_bytes.
        octet_generator_t_high_byte_first_get, _ida_bytes.
        octet_generator_t_high_byte_first_set)

    def __init__(self, _ea: ida_idaapi.ea_t):
        _ida_bytes.octet_generator_t_swiginit(self, _ida_bytes.
            new_octet_generator_t(_ea))

    def invert_byte_order(self) ->None:
        return _ida_bytes.octet_generator_t_invert_byte_order(self)
    __swig_destroy__ = _ida_bytes.delete_octet_generator_t


_ida_bytes.octet_generator_t_swigregister(octet_generator_t)


def get_octet(ogen: 'octet_generator_t') ->'uchar *':
    return _ida_bytes.get_octet(ogen)


def get_16bit(ea: ida_idaapi.ea_t) ->int:
    """Get 16bits of the program at 'ea'. 
        
@returns 1 byte (getFullByte()) if the current processor has 16-bit byte, otherwise return get_word()"""
    return _ida_bytes.get_16bit(ea)


def get_32bit(ea: ida_idaapi.ea_t) ->int:
    """Get not more than 32bits of the program at 'ea'. 
        
@returns 32 bit value, depending on processor_t::nbits:
* if ( nbits <= 8 ) return get_dword(ea);
* if ( nbits <= 16) return get_wide_word(ea);
* return get_wide_byte(ea);"""
    return _ida_bytes.get_32bit(ea)


def get_64bit(ea: ida_idaapi.ea_t) ->'uint64':
    """Get not more than 64bits of the program at 'ea'. 
        
@returns 64 bit value, depending on processor_t::nbits:
* if ( nbits <= 8 ) return get_qword(ea);
* if ( nbits <= 16) return get_wide_dword(ea);
* return get_wide_byte(ea);"""
    return _ida_bytes.get_64bit(ea)


def get_data_value(v: 'uval_t *', ea: ida_idaapi.ea_t, size: 'asize_t') ->bool:
    """Get the value at of the item at 'ea'. This function works with entities up to sizeof(ea_t) (bytes, word, etc) 
        
@param v: pointer to the result. may be nullptr
@param ea: linear address
@param size: size of data to read. If 0, then the item type at 'ea' will be used
@returns success"""
    return _ida_bytes.get_data_value(v, ea, size)


def get_original_byte(ea: ida_idaapi.ea_t) ->'uint64':
    """Get original byte value (that was before patching). This function works for wide byte processors too. 
        """
    return _ida_bytes.get_original_byte(ea)


def get_original_word(ea: ida_idaapi.ea_t) ->'uint64':
    """Get original word value (that was before patching). This function works for wide byte processors too. This function takes into account order of bytes specified in idainfo::is_be() 
        """
    return _ida_bytes.get_original_word(ea)


def get_original_dword(ea: ida_idaapi.ea_t) ->'uint64':
    """Get original dword (that was before patching) This function works for wide byte processors too. This function takes into account order of bytes specified in idainfo::is_be() 
        """
    return _ida_bytes.get_original_dword(ea)


def get_original_qword(ea: ida_idaapi.ea_t) ->'uint64':
    """Get original qword value (that was before patching) This function DOESN'T work for wide byte processors too. This function takes into account order of bytes specified in idainfo::is_be() 
        """
    return _ida_bytes.get_original_qword(ea)


def put_byte(ea: ida_idaapi.ea_t, x: 'uint64') ->bool:
    """Set value of one byte of the program. This function modifies the database. If the debugger is active then the debugged process memory is patched too. 
        
@param ea: linear address
@param x: byte value
@returns true if the database has been modified"""
    return _ida_bytes.put_byte(ea, x)


def put_word(ea: ida_idaapi.ea_t, x: 'uint64') ->None:
    """Set value of one word of the program. This function takes into account order of bytes specified in idainfo::is_be() This function works for wide byte processors too. 
        """
    return _ida_bytes.put_word(ea, x)


def put_dword(ea: ida_idaapi.ea_t, x: 'uint64') ->None:
    """Set value of one dword of the program. This function takes into account order of bytes specified in idainfo::is_be() This function works for wide byte processors too. 
        
@param ea: linear address
@param x: dword value"""
    return _ida_bytes.put_dword(ea, x)


def put_qword(ea: ida_idaapi.ea_t, x: 'uint64') ->None:
    """Set value of one qword (8 bytes) of the program. This function takes into account order of bytes specified in idainfo::is_be() This function DOESN'T works for wide byte processors. 
        
@param ea: linear address
@param x: qword value"""
    return _ida_bytes.put_qword(ea, x)


def patch_byte(ea: ida_idaapi.ea_t, x: 'uint64') ->bool:
    """Patch a byte of the program. The original value of the byte is saved and can be obtained by get_original_byte(). This function works for wide byte processors too. 
        
@retval true: the database has been modified,
@retval false: the debugger is running and the process' memory has value 'x' at address 'ea', or the debugger is not running, and the IDB has value 'x' at address 'ea already."""
    return _ida_bytes.patch_byte(ea, x)


def patch_word(ea: ida_idaapi.ea_t, x: 'uint64') ->bool:
    """Patch a word of the program. The original value of the word is saved and can be obtained by get_original_word(). This function works for wide byte processors too. This function takes into account order of bytes specified in idainfo::is_be() 
        
@retval true: the database has been modified,
@retval false: the debugger is running and the process' memory has value 'x' at address 'ea', or the debugger is not running, and the IDB has value 'x' at address 'ea already."""
    return _ida_bytes.patch_word(ea, x)


def patch_dword(ea: ida_idaapi.ea_t, x: 'uint64') ->bool:
    """Patch a dword of the program. The original value of the dword is saved and can be obtained by get_original_dword(). This function DOESN'T work for wide byte processors. This function takes into account order of bytes specified in idainfo::is_be() 
        
@retval true: the database has been modified,
@retval false: the debugger is running and the process' memory has value 'x' at address 'ea', or the debugger is not running, and the IDB has value 'x' at address 'ea already."""
    return _ida_bytes.patch_dword(ea, x)


def patch_qword(ea: ida_idaapi.ea_t, x: 'uint64') ->bool:
    """Patch a qword of the program. The original value of the qword is saved and can be obtained by get_original_qword(). This function DOESN'T work for wide byte processors. This function takes into account order of bytes specified in idainfo::is_be() 
        
@retval true: the database has been modified,
@retval false: the debugger is running and the process' memory has value 'x' at address 'ea', or the debugger is not running, and the IDB has value 'x' at address 'ea already."""
    return _ida_bytes.patch_qword(ea, x)


def revert_byte(ea: ida_idaapi.ea_t) ->bool:
    """Revert patched byte 
        
@retval true: byte was patched before and reverted now"""
    return _ida_bytes.revert_byte(ea)


def add_byte(ea: ida_idaapi.ea_t, value: int) ->None:
    """Add a value to one byte of the program. This function works for wide byte processors too. 
        
@param ea: linear address
@param value: byte value"""
    return _ida_bytes.add_byte(ea, value)


def add_word(ea: ida_idaapi.ea_t, value: 'uint64') ->None:
    """Add a value to one word of the program. This function works for wide byte processors too. This function takes into account order of bytes specified in idainfo::is_be() 
        
@param ea: linear address
@param value: byte value"""
    return _ida_bytes.add_word(ea, value)


def add_dword(ea: ida_idaapi.ea_t, value: 'uint64') ->None:
    """Add a value to one dword of the program. This function works for wide byte processors too. This function takes into account order of bytes specified in idainfo::is_be() 
        
@param ea: linear address
@param value: byte value"""
    return _ida_bytes.add_dword(ea, value)


def add_qword(ea: ida_idaapi.ea_t, value: 'uint64') ->None:
    """Add a value to one qword of the program. This function does not work for wide byte processors. This function takes into account order of bytes specified in idainfo::is_be() 
        
@param ea: linear address
@param value: byte value"""
    return _ida_bytes.add_qword(ea, value)


def get_zero_ranges(zranges: 'rangeset_t', range: 'range_t') ->bool:
    """Return set of ranges with zero initialized bytes. The returned set includes only big zero initialized ranges (at least >1KB). Some zero initialized byte ranges may be not included. Only zero bytes that use the sparse storage method (STT_MM) are reported. 
        
@param zranges: pointer to the return value. cannot be nullptr
@param range: the range of addresses to verify. can be nullptr - means all ranges
@returns true if the result is a non-empty set"""
    return _ida_bytes.get_zero_ranges(zranges, range)


GMB_READALL = _ida_bytes.GMB_READALL
"""try to read all bytes; if this bit is not set, fail at first uninited byte 
        """
GMB_WAITBOX = _ida_bytes.GMB_WAITBOX
"""show wait box (may return -1 in this case)
"""


def put_bytes(ea: ida_idaapi.ea_t, buf: 'void const *') ->None:
    """Modify the specified number of bytes of the program. This function does not save the original values of bytes. See also patch_bytes(). 
        
@param ea: linear address
@param buf: buffer with new values of bytes"""
    return _ida_bytes.put_bytes(ea, buf)


def patch_bytes(ea: ida_idaapi.ea_t, buf: 'void const *') ->None:
    """Patch the specified number of bytes of the program. Original values of bytes are saved and are available with get_original...() functions. See also put_bytes(). 
        
@param ea: linear address
@param buf: buffer with new values of bytes"""
    return _ida_bytes.patch_bytes(ea, buf)


MS_CLS = _ida_bytes.MS_CLS
"""Mask for typing.
"""
FF_CODE = _ida_bytes.FF_CODE
"""Code ?
"""
FF_DATA = _ida_bytes.FF_DATA
"""Data ?
"""
FF_TAIL = _ida_bytes.FF_TAIL
"""Tail ?
"""
FF_UNK = _ida_bytes.FF_UNK
"""Unknown ?
"""


def is_code(F: 'flags64_t') ->bool:
    """Does flag denote start of an instruction?
"""
    return _ida_bytes.is_code(F)


def f_is_code(F: 'flags64_t', arg2: 'void *') ->bool:
    """Does flag denote start of an instruction?
"""
    return _ida_bytes.f_is_code(F, arg2)


def is_data(F: 'flags64_t') ->bool:
    """Does flag denote start of data?
"""
    return _ida_bytes.is_data(F)


def f_is_data(F: 'flags64_t', arg2: 'void *') ->bool:
    """Does flag denote start of data?
"""
    return _ida_bytes.f_is_data(F, arg2)


def is_tail(F: 'flags64_t') ->bool:
    """Does flag denote tail byte?
"""
    return _ida_bytes.is_tail(F)


def f_is_tail(F: 'flags64_t', arg2: 'void *') ->bool:
    """Does flag denote tail byte?
"""
    return _ida_bytes.f_is_tail(F, arg2)


def is_not_tail(F: 'flags64_t') ->bool:
    """Does flag denote tail byte?
"""
    return _ida_bytes.is_not_tail(F)


def f_is_not_tail(F: 'flags64_t', arg2: 'void *') ->bool:
    """Does flag denote tail byte?
"""
    return _ida_bytes.f_is_not_tail(F, arg2)


def is_unknown(F: 'flags64_t') ->bool:
    """Does flag denote unexplored byte?
"""
    return _ida_bytes.is_unknown(F)


def is_head(F: 'flags64_t') ->bool:
    """Does flag denote start of instruction OR data?
"""
    return _ida_bytes.is_head(F)


def f_is_head(F: 'flags64_t', arg2: 'void *') ->bool:
    """Does flag denote start of instruction OR data?
"""
    return _ida_bytes.f_is_head(F, arg2)


def del_items(ea: ida_idaapi.ea_t, flags: int=0, nbytes: 'asize_t'=1,
    may_destroy: 'may_destroy_cb_t *'=None) ->bool:
    """Convert item (instruction/data) to unexplored bytes. The whole item (including the head and tail bytes) will be destroyed. It is allowed to pass any address in the item to this function 
        
@param ea: any address within the first item to delete
@param flags: combination of Unexplored byte conversion flags
@param nbytes: number of bytes in the range to be undefined
@param may_destroy: optional routine invoked before deleting a head item. If callback returns false then item is not to be deleted and operation fails
@returns true on sucessful operation, otherwise false"""
    return _ida_bytes.del_items(ea, flags, nbytes, may_destroy)


DELIT_SIMPLE = _ida_bytes.DELIT_SIMPLE
"""simply undefine the specified item(s)
"""
DELIT_EXPAND = _ida_bytes.DELIT_EXPAND
"""propagate undefined items; for example if removing an instruction removes all references to the next instruction, then plan to convert to unexplored the next instruction too. 
        """
DELIT_DELNAMES = _ida_bytes.DELIT_DELNAMES
"""delete any names at the specified address range (except for the starting address). this bit is valid if nbytes > 1 
        """
DELIT_NOTRUNC = _ida_bytes.DELIT_NOTRUNC
"""don't truncate the current function even if AF_TRFUNC is set 
        """
DELIT_NOUNAME = _ida_bytes.DELIT_NOUNAME
"""reject to delete if a user name is in address range (except for the starting address). this bit is valid if nbytes > 1 
        """
DELIT_NOCMT = _ida_bytes.DELIT_NOCMT
"""reject to delete if a comment is in address range (except for the starting address). this bit is valid if nbytes > 1 
        """
DELIT_KEEPFUNC = _ida_bytes.DELIT_KEEPFUNC
"""do not undefine the function start. Just delete xrefs, ops e.t.c. 
        """


def is_manual_insn(ea: ida_idaapi.ea_t) ->bool:
    """Is the instruction overridden? 
        
@param ea: linear address of the instruction or data item"""
    return _ida_bytes.is_manual_insn(ea)


def get_manual_insn(ea: ida_idaapi.ea_t) ->str:
    """Retrieve the user-specified string for the manual instruction. 
        
@param ea: linear address of the instruction or data item
@returns size of manual instruction or -1"""
    return _ida_bytes.get_manual_insn(ea)


def set_manual_insn(ea: ida_idaapi.ea_t, manual_insn: str) ->None:
    """Set manual instruction string. 
        
@param ea: linear address of the instruction or data item
@param manual_insn: "" - delete manual string. nullptr - do nothing"""
    return _ida_bytes.set_manual_insn(ea, manual_insn)


MS_COMM = _ida_bytes.MS_COMM
"""Mask of common bits.
"""
FF_COMM = _ida_bytes.FF_COMM
"""Has comment ?
"""
FF_REF = _ida_bytes.FF_REF
"""has references
"""
FF_LINE = _ida_bytes.FF_LINE
"""Has next or prev lines ?
"""
FF_NAME = _ida_bytes.FF_NAME
"""Has name ?
"""
FF_LABL = _ida_bytes.FF_LABL
"""Has dummy name?
"""
FF_FLOW = _ida_bytes.FF_FLOW
"""Exec flow from prev instruction.
"""
FF_SIGN = _ida_bytes.FF_SIGN
"""Inverted sign of operands.
"""
FF_BNOT = _ida_bytes.FF_BNOT
"""Bitwise negation of operands.
"""
FF_UNUSED = _ida_bytes.FF_UNUSED
"""unused bit (was used for variable bytes)
"""


def is_flow(F: 'flags64_t') ->bool:
    """Does the previous instruction exist and pass execution flow to the current byte?
"""
    return _ida_bytes.is_flow(F)


def has_extra_cmts(F: 'flags64_t') ->bool:
    """Does the current byte have additional anterior or posterior lines?
"""
    return _ida_bytes.has_extra_cmts(F)


def f_has_extra_cmts(f: 'flags64_t', arg2: 'void *') ->bool:
    return _ida_bytes.f_has_extra_cmts(f, arg2)


def has_cmt(F: 'flags64_t') ->bool:
    """Does the current byte have an indented comment?
"""
    return _ida_bytes.has_cmt(F)


def f_has_cmt(f: 'flags64_t', arg2: 'void *') ->bool:
    return _ida_bytes.f_has_cmt(f, arg2)


def has_xref(F: 'flags64_t') ->bool:
    """Does the current byte have cross-references to it?
"""
    return _ida_bytes.has_xref(F)


def f_has_xref(f: 'flags64_t', arg2: 'void *') ->bool:
    """Does the current byte have cross-references to it?
"""
    return _ida_bytes.f_has_xref(f, arg2)


def has_name(F: 'flags64_t') ->bool:
    """Does the current byte have non-trivial (non-dummy) name?
"""
    return _ida_bytes.has_name(F)


def f_has_name(f: 'flags64_t', arg2: 'void *') ->bool:
    """Does the current byte have non-trivial (non-dummy) name?
"""
    return _ida_bytes.f_has_name(f, arg2)


FF_ANYNAME = _ida_bytes.FF_ANYNAME
"""Has name or dummy name?
"""


def has_dummy_name(F: 'flags64_t') ->bool:
    """Does the current byte have dummy (auto-generated, with special prefix) name?
"""
    return _ida_bytes.has_dummy_name(F)


def f_has_dummy_name(f: 'flags64_t', arg2: 'void *') ->bool:
    """Does the current byte have dummy (auto-generated, with special prefix) name?
"""
    return _ida_bytes.f_has_dummy_name(f, arg2)


def has_auto_name(F: 'flags64_t') ->bool:
    """Does the current byte have auto-generated (no special prefix) name?
"""
    return _ida_bytes.has_auto_name(F)


def has_any_name(F: 'flags64_t') ->bool:
    """Does the current byte have any name?
"""
    return _ida_bytes.has_any_name(F)


def has_user_name(F: 'flags64_t') ->bool:
    """Does the current byte have user-specified name?
"""
    return _ida_bytes.has_user_name(F)


def f_has_user_name(F: 'flags64_t', arg2: 'void *') ->bool:
    """Does the current byte have user-specified name?
"""
    return _ida_bytes.f_has_user_name(F, arg2)


def is_invsign(ea: ida_idaapi.ea_t, F: 'flags64_t', n: int) ->bool:
    """Should sign of n-th operand inverted during output?. allowed values of n: 0-first operand, 1-other operands 
        """
    return _ida_bytes.is_invsign(ea, F, n)


def toggle_sign(ea: ida_idaapi.ea_t, n: int) ->bool:
    """Toggle sign of n-th operand. allowed values of n: 0-first operand, 1-other operands 
        """
    return _ida_bytes.toggle_sign(ea, n)


def is_bnot(ea: ida_idaapi.ea_t, F: 'flags64_t', n: int) ->bool:
    """Should we negate the operand?. asm_t::a_bnot should be defined in the idp module in order to work with this function 
        """
    return _ida_bytes.is_bnot(ea, F, n)


def toggle_bnot(ea: ida_idaapi.ea_t, n: int) ->bool:
    """Toggle binary negation of operand. also see is_bnot()
"""
    return _ida_bytes.toggle_bnot(ea, n)


def is_lzero(ea: ida_idaapi.ea_t, n: int) ->bool:
    """Display leading zeroes? Display leading zeroes in operands. The global switch for the leading zeroes is in idainfo::s_genflags Note: the leading zeroes doesn't work if for the target assembler octal numbers start with 0. 
        
@param ea: the item (insn/data) address
@param n: the operand number (0-first operand, 1-other operands)
@returns success"""
    return _ida_bytes.is_lzero(ea, n)


def set_lzero(ea: ida_idaapi.ea_t, n: int) ->bool:
    """Set toggle lzero bit. This function changes the display of leading zeroes for the specified operand. If the default is not to display leading zeroes, this function will display them and vice versa. 
        
@param ea: the item (insn/data) address
@param n: the operand number (0-first operand, 1-other operands)
@returns success"""
    return _ida_bytes.set_lzero(ea, n)


def clr_lzero(ea: ida_idaapi.ea_t, n: int) ->bool:
    """Clear toggle lzero bit. This function reset the display of leading zeroes for the specified operand to the default. If the default is not to display leading zeroes, leading zeroes will not be displayed, as vice versa. 
        
@param ea: the item (insn/data) address
@param n: the operand number (0-first operand, 1-other operands)
@returns success"""
    return _ida_bytes.clr_lzero(ea, n)


def toggle_lzero(ea: ida_idaapi.ea_t, n: int) ->bool:
    """Toggle lzero bit. 
        
@param ea: the item (insn/data) address
@param n: the operand number (0-first operand, 1-other operands)
@returns success"""
    return _ida_bytes.toggle_lzero(ea, n)


def leading_zero_important(ea: ida_idaapi.ea_t, n: int) ->bool:
    """Check if leading zeroes are important.
"""
    return _ida_bytes.leading_zero_important(ea, n)


MS_N_TYPE = _ida_bytes.MS_N_TYPE
"""Mask for nth arg (a 64-bit constant)
"""
FF_N_VOID = _ida_bytes.FF_N_VOID
"""Void (unknown)?
"""
FF_N_NUMH = _ida_bytes.FF_N_NUMH
"""Hexadecimal number?
"""
FF_N_NUMD = _ida_bytes.FF_N_NUMD
"""Decimal number?
"""
FF_N_CHAR = _ida_bytes.FF_N_CHAR
"""Char ('x')?
"""
FF_N_SEG = _ida_bytes.FF_N_SEG
"""Segment?
"""
FF_N_OFF = _ida_bytes.FF_N_OFF
"""Offset?
"""
FF_N_NUMB = _ida_bytes.FF_N_NUMB
"""Binary number?
"""
FF_N_NUMO = _ida_bytes.FF_N_NUMO
"""Octal number?
"""
FF_N_ENUM = _ida_bytes.FF_N_ENUM
"""Enumeration?
"""
FF_N_FOP = _ida_bytes.FF_N_FOP
"""Forced operand?
"""
FF_N_STRO = _ida_bytes.FF_N_STRO
"""Struct offset?
"""
FF_N_STK = _ida_bytes.FF_N_STK
"""Stack variable?
"""
FF_N_FLT = _ida_bytes.FF_N_FLT
"""Floating point number?
"""
FF_N_CUST = _ida_bytes.FF_N_CUST
"""Custom representation?
"""


def get_operand_type_shift(n: int) ->int:
    """Get the shift in `flags64_t` for the nibble representing operand `n`'s type
Note: n must be < UA_MAXOP, and is not checked

@param n: the operand number
@returns the shift to the nibble"""
    return _ida_bytes.get_operand_type_shift(n)


def get_operand_flag(typebits: 'uint8', n: int) ->'flags64_t':
    """Place operand `n`'s type flag in the right nibble of a 64-bit flags set.

@param typebits: the type bits (one of `FF_N_`)
@param n: the operand number
@returns the shift to the nibble"""
    return _ida_bytes.get_operand_flag(typebits, n)


def is_flag_for_operand(F: 'flags64_t', typebits: 'uint8', n: int) ->bool:
    """Check that the 64-bit flags set has the expected type for operand `n`.

@param F: the flags
@param typebits: the type bits (one of `FF_N_`)
@param n: the operand number
@returns success"""
    return _ida_bytes.is_flag_for_operand(F, typebits, n)


def is_defarg0(F: 'flags64_t') ->bool:
    """Is the first operand defined? Initially operand has no defined representation.
"""
    return _ida_bytes.is_defarg0(F)


def is_defarg1(F: 'flags64_t') ->bool:
    """Is the second operand defined? Initially operand has no defined representation.
"""
    return _ida_bytes.is_defarg1(F)


def is_off0(F: 'flags64_t') ->bool:
    """Is the first operand offset? (example: push offset xxx)
"""
    return _ida_bytes.is_off0(F)


def is_off1(F: 'flags64_t') ->bool:
    """Is the second operand offset? (example: mov ax, offset xxx)
"""
    return _ida_bytes.is_off1(F)


def is_char0(F: 'flags64_t') ->bool:
    """Is the first operand character constant? (example: push 'a')
"""
    return _ida_bytes.is_char0(F)


def is_char1(F: 'flags64_t') ->bool:
    """Is the second operand character constant? (example: mov al, 'a')
"""
    return _ida_bytes.is_char1(F)


def is_seg0(F: 'flags64_t') ->bool:
    """Is the first operand segment selector? (example: push seg seg001)
"""
    return _ida_bytes.is_seg0(F)


def is_seg1(F: 'flags64_t') ->bool:
    """Is the second operand segment selector? (example: mov dx, seg dseg)
"""
    return _ida_bytes.is_seg1(F)


def is_enum0(F: 'flags64_t') ->bool:
    """Is the first operand a symbolic constant (enum member)?
"""
    return _ida_bytes.is_enum0(F)


def is_enum1(F: 'flags64_t') ->bool:
    """Is the second operand a symbolic constant (enum member)?
"""
    return _ida_bytes.is_enum1(F)


def is_stroff0(F: 'flags64_t') ->bool:
    """Is the first operand an offset within a struct?
"""
    return _ida_bytes.is_stroff0(F)


def is_stroff1(F: 'flags64_t') ->bool:
    """Is the second operand an offset within a struct?
"""
    return _ida_bytes.is_stroff1(F)


def is_stkvar0(F: 'flags64_t') ->bool:
    """Is the first operand a stack variable?
"""
    return _ida_bytes.is_stkvar0(F)


def is_stkvar1(F: 'flags64_t') ->bool:
    """Is the second operand a stack variable?
"""
    return _ida_bytes.is_stkvar1(F)


def is_float0(F: 'flags64_t') ->bool:
    """Is the first operand a floating point number?
"""
    return _ida_bytes.is_float0(F)


def is_float1(F: 'flags64_t') ->bool:
    """Is the second operand a floating point number?
"""
    return _ida_bytes.is_float1(F)


def is_custfmt0(F: 'flags64_t') ->bool:
    """Does the first operand use a custom data representation?
"""
    return _ida_bytes.is_custfmt0(F)


def is_custfmt1(F: 'flags64_t') ->bool:
    """Does the second operand use a custom data representation?
"""
    return _ida_bytes.is_custfmt1(F)


def is_numop0(F: 'flags64_t') ->bool:
    """Is the first operand a number (i.e. binary, octal, decimal or hex?)
"""
    return _ida_bytes.is_numop0(F)


def is_numop1(F: 'flags64_t') ->bool:
    """Is the second operand a number (i.e. binary, octal, decimal or hex?)
"""
    return _ida_bytes.is_numop1(F)


def get_optype_flags0(F: 'flags64_t') ->'flags64_t':
    """Get flags for first operand.
"""
    return _ida_bytes.get_optype_flags0(F)


def get_optype_flags1(F: 'flags64_t') ->'flags64_t':
    """Get flags for second operand.
"""
    return _ida_bytes.get_optype_flags1(F)


OPND_OUTER = _ida_bytes.OPND_OUTER
"""outer offset base (combined with operand number). used only in set, get, del_offset() functions 
        """
OPND_MASK = _ida_bytes.OPND_MASK
"""mask for operand number
"""
OPND_ALL = _ida_bytes.OPND_ALL
"""all operands
"""


def is_defarg(F: 'flags64_t', n: int) ->bool:
    """is defined?
"""
    return _ida_bytes.is_defarg(F, n)


def is_off(F: 'flags64_t', n: int) ->bool:
    """is offset?
"""
    return _ida_bytes.is_off(F, n)


def is_char(F: 'flags64_t', n: int) ->bool:
    """is character constant?
"""
    return _ida_bytes.is_char(F, n)


def is_seg(F: 'flags64_t', n: int) ->bool:
    """is segment?
"""
    return _ida_bytes.is_seg(F, n)


def is_enum(F: 'flags64_t', n: int) ->bool:
    """is enum?
"""
    return _ida_bytes.is_enum(F, n)


def is_manual(F: 'flags64_t', n: int) ->bool:
    """is forced operand? (use is_forced_operand())
"""
    return _ida_bytes.is_manual(F, n)


def is_stroff(F: 'flags64_t', n: int) ->bool:
    """is struct offset?
"""
    return _ida_bytes.is_stroff(F, n)


def is_stkvar(F: 'flags64_t', n: int) ->bool:
    """is stack variable?
"""
    return _ida_bytes.is_stkvar(F, n)


def is_fltnum(F: 'flags64_t', n: int) ->bool:
    """is floating point number?
"""
    return _ida_bytes.is_fltnum(F, n)


def is_custfmt(F: 'flags64_t', n: int) ->bool:
    """is custom data format?
"""
    return _ida_bytes.is_custfmt(F, n)


def is_numop(F: 'flags64_t', n: int) ->bool:
    """is number (bin, oct, dec, hex)?
"""
    return _ida_bytes.is_numop(F, n)


def is_suspop(ea: ida_idaapi.ea_t, F: 'flags64_t', n: int) ->bool:
    """is suspicious operand?
"""
    return _ida_bytes.is_suspop(ea, F, n)


def op_adds_xrefs(F: 'flags64_t', n: int) ->bool:
    """Should processor module create xrefs from the operand?. Currently 'offset' and 'structure offset' operands create xrefs 
        """
    return _ida_bytes.op_adds_xrefs(F, n)


def set_op_type(ea: ida_idaapi.ea_t, type: 'flags64_t', n: int) ->bool:
    """(internal function) change representation of operand(s). 
        
@param ea: linear address
@param type: new flag value (should be obtained from char_flag(), num_flag() and similar functions)
@param n: 0..UA_MAXOP-1 operand number, OPND_ALL all operands
@retval 1: ok
@retval 0: failed (applied to a tail byte)"""
    return _ida_bytes.set_op_type(ea, type, n)


def op_seg(ea: ida_idaapi.ea_t, n: int) ->bool:
    """Set operand representation to be 'segment'. If applied to unexplored bytes, converts them to 16/32bit word data 
        
@param ea: linear address
@param n: 0..UA_MAXOP-1 operand number, OPND_ALL all operands
@returns success"""
    return _ida_bytes.op_seg(ea, n)


def op_enum(ea: ida_idaapi.ea_t, n: int, id: 'tid_t', serial: 'uchar'=0
    ) ->bool:
    """Set operand representation to be enum type If applied to unexplored bytes, converts them to 16/32bit word data 
        
@param ea: linear address
@param n: 0..UA_MAXOP-1 operand number, OPND_ALL all operands
@param id: id of enum
@param serial: the serial number of the constant in the enumeration, usually 0. the serial numbers are used if the enumeration contains several constants with the same value
@returns success"""
    return _ida_bytes.op_enum(ea, n, id, serial)


def get_enum_id(ea: ida_idaapi.ea_t, n: int) ->'uchar *':
    """Get enum id of 'enum' operand. 
        
@param ea: linear address
@param n: 0..UA_MAXOP-1 operand number, OPND_ALL one of the operands
@returns id of enum or BADNODE"""
    return _ida_bytes.get_enum_id(ea, n)


def op_based_stroff(insn: 'insn_t const &', n: int, opval: 'adiff_t', base:
    ida_idaapi.ea_t) ->bool:
    """Set operand representation to be 'struct offset' if the operand likely points to a structure member. For example, let's there is a structure at 1000 1000 stru_1000 Elf32_Sym <...> the operand #8 will be represented as '#Elf32_Sym.st_size' after the call of 'op_based_stroff(..., 8, 0x1000)' By the way, after the call of 'op_plain_offset(..., 0x1000)' it will be represented as '#(stru_1000.st_size - 0x1000)' 
        
@param insn: the instruction
@param n: 0..UA_MAXOP-1 operand number, OPND_ALL all operands
@param opval: operand value (usually op_t::value or op_t::addr)
@param base: base reference
@returns success"""
    return _ida_bytes.op_based_stroff(insn, n, opval, base)


def op_stkvar(ea: ida_idaapi.ea_t, n: int) ->bool:
    """Set operand representation to be 'stack variable'. Should be applied to an instruction within a function. Should be applied after creating a stack var using insn_t::create_stkvar(). 
        
@param ea: linear address
@param n: 0..UA_MAXOP-1 operand number, OPND_ALL all operands
@returns success"""
    return _ida_bytes.op_stkvar(ea, n)


def set_forced_operand(ea: ida_idaapi.ea_t, n: int, op: str) ->bool:
    """Set forced operand. 
        
@param ea: linear address
@param n: 0..UA_MAXOP-1 operand number
@param op: text of operand
* nullptr: do nothing (return 0)
* "" : delete forced operand
@returns success"""
    return _ida_bytes.set_forced_operand(ea, n, op)


def get_forced_operand(ea: ida_idaapi.ea_t, n: int) ->str:
    """Get forced operand. 
        
@param ea: linear address
@param n: 0..UA_MAXOP-1 operand number
@returns size of forced operand or -1"""
    return _ida_bytes.get_forced_operand(ea, n)


def is_forced_operand(ea: ida_idaapi.ea_t, n: int) ->bool:
    """Is operand manually defined?. 
        
@param ea: linear address
@param n: 0..UA_MAXOP-1 operand number"""
    return _ida_bytes.is_forced_operand(ea, n)


def combine_flags(F: 'flags64_t') ->'flags64_t':
    return _ida_bytes.combine_flags(F)


def char_flag() ->'flags64_t':
    """see FF_opbits
"""
    return _ida_bytes.char_flag()


def off_flag() ->'flags64_t':
    """see FF_opbits
"""
    return _ida_bytes.off_flag()


def enum_flag() ->'flags64_t':
    """see FF_opbits
"""
    return _ida_bytes.enum_flag()


def stroff_flag() ->'flags64_t':
    """see FF_opbits
"""
    return _ida_bytes.stroff_flag()


def stkvar_flag() ->'flags64_t':
    """see FF_opbits
"""
    return _ida_bytes.stkvar_flag()


def flt_flag() ->'flags64_t':
    """see FF_opbits
"""
    return _ida_bytes.flt_flag()


def custfmt_flag() ->'flags64_t':
    """see FF_opbits
"""
    return _ida_bytes.custfmt_flag()


def seg_flag() ->'flags64_t':
    """see FF_opbits
"""
    return _ida_bytes.seg_flag()


def num_flag() ->'flags64_t':
    """Get number of default base (bin, oct, dec, hex) 
        """
    return _ida_bytes.num_flag()


def hex_flag() ->'flags64_t':
    """Get number flag of the base, regardless of current processor - better to use num_flag()
"""
    return _ida_bytes.hex_flag()


def dec_flag() ->'flags64_t':
    """Get number flag of the base, regardless of current processor - better to use num_flag()
"""
    return _ida_bytes.dec_flag()


def oct_flag() ->'flags64_t':
    """Get number flag of the base, regardless of current processor - better to use num_flag()
"""
    return _ida_bytes.oct_flag()


def bin_flag() ->'flags64_t':
    """Get number flag of the base, regardless of current processor - better to use num_flag()
"""
    return _ida_bytes.bin_flag()


def op_chr(ea: ida_idaapi.ea_t, n: int) ->bool:
    """set op type to char_flag()
"""
    return _ida_bytes.op_chr(ea, n)


def op_num(ea: ida_idaapi.ea_t, n: int) ->bool:
    """set op type to num_flag()
"""
    return _ida_bytes.op_num(ea, n)


def op_hex(ea: ida_idaapi.ea_t, n: int) ->bool:
    """set op type to hex_flag()
"""
    return _ida_bytes.op_hex(ea, n)


def op_dec(ea: ida_idaapi.ea_t, n: int) ->bool:
    """set op type to dec_flag()
"""
    return _ida_bytes.op_dec(ea, n)


def op_oct(ea: ida_idaapi.ea_t, n: int) ->bool:
    """set op type to oct_flag()
"""
    return _ida_bytes.op_oct(ea, n)


def op_bin(ea: ida_idaapi.ea_t, n: int) ->bool:
    """set op type to bin_flag()
"""
    return _ida_bytes.op_bin(ea, n)


def op_flt(ea: ida_idaapi.ea_t, n: int) ->bool:
    """set op type to flt_flag()
"""
    return _ida_bytes.op_flt(ea, n)


def op_custfmt(ea: ida_idaapi.ea_t, n: int, fid: int) ->bool:
    """Set custom data format for operand (fid-custom data format id)
"""
    return _ida_bytes.op_custfmt(ea, n, fid)


def clr_op_type(ea: ida_idaapi.ea_t, n: int) ->bool:
    """Remove operand representation information. (set operand representation to be 'undefined') 
        
@param ea: linear address
@param n: 0..UA_MAXOP-1 operand number, OPND_ALL all operands
@returns success"""
    return _ida_bytes.clr_op_type(ea, n)


def get_default_radix() ->int:
    """Get default base of number for the current processor. 
        
@returns 2, 8, 10, 16"""
    return _ida_bytes.get_default_radix()


def get_radix(F: 'flags64_t', n: int) ->int:
    """Get radix of the operand, in: flags. If the operand is not a number, returns get_default_radix() 
        
@param F: flags
@param n: number of operand (0, 1, -1)
@returns 2, 8, 10, 16"""
    return _ida_bytes.get_radix(F, n)


DT_TYPE = _ida_bytes.DT_TYPE
"""Mask for DATA typing.
"""
FF_BYTE = _ida_bytes.FF_BYTE
"""byte
"""
FF_WORD = _ida_bytes.FF_WORD
"""word
"""
FF_DWORD = _ida_bytes.FF_DWORD
"""double word
"""
FF_QWORD = _ida_bytes.FF_QWORD
"""quadro word
"""
FF_TBYTE = _ida_bytes.FF_TBYTE
"""tbyte
"""
FF_STRLIT = _ida_bytes.FF_STRLIT
"""string literal
"""
FF_STRUCT = _ida_bytes.FF_STRUCT
"""struct variable
"""
FF_OWORD = _ida_bytes.FF_OWORD
"""octaword/xmm word (16 bytes/128 bits)
"""
FF_FLOAT = _ida_bytes.FF_FLOAT
"""float
"""
FF_DOUBLE = _ida_bytes.FF_DOUBLE
"""double
"""
FF_PACKREAL = _ida_bytes.FF_PACKREAL
"""packed decimal real
"""
FF_ALIGN = _ida_bytes.FF_ALIGN
"""alignment directive
"""
FF_CUSTOM = _ida_bytes.FF_CUSTOM
"""custom data type
"""
FF_YWORD = _ida_bytes.FF_YWORD
"""ymm word (32 bytes/256 bits)
"""
FF_ZWORD = _ida_bytes.FF_ZWORD
"""zmm word (64 bytes/512 bits)
"""


def code_flag() ->'flags64_t':
    """FF_CODE
"""
    return _ida_bytes.code_flag()


def byte_flag() ->'flags64_t':
    """Get a flags64_t representing a byte.
"""
    return _ida_bytes.byte_flag()


def word_flag() ->'flags64_t':
    """Get a flags64_t representing a word.
"""
    return _ida_bytes.word_flag()


def dword_flag() ->'flags64_t':
    """Get a flags64_t representing a double word.
"""
    return _ida_bytes.dword_flag()


def qword_flag() ->'flags64_t':
    """Get a flags64_t representing a quad word.
"""
    return _ida_bytes.qword_flag()


def oword_flag() ->'flags64_t':
    """Get a flags64_t representing a octaword.
"""
    return _ida_bytes.oword_flag()


def yword_flag() ->'flags64_t':
    """Get a flags64_t representing a ymm word.
"""
    return _ida_bytes.yword_flag()


def zword_flag() ->'flags64_t':
    """Get a flags64_t representing a zmm word.
"""
    return _ida_bytes.zword_flag()


def tbyte_flag() ->'flags64_t':
    """Get a flags64_t representing a tbyte.
"""
    return _ida_bytes.tbyte_flag()


def strlit_flag() ->'flags64_t':
    """Get a flags64_t representing a string literal.
"""
    return _ida_bytes.strlit_flag()


def stru_flag() ->'flags64_t':
    """Get a flags64_t representing a struct.
"""
    return _ida_bytes.stru_flag()


def cust_flag() ->'flags64_t':
    """Get a flags64_t representing custom type data.
"""
    return _ida_bytes.cust_flag()


def align_flag() ->'flags64_t':
    """Get a flags64_t representing an alignment directive.
"""
    return _ida_bytes.align_flag()


def float_flag() ->'flags64_t':
    """Get a flags64_t representing a float.
"""
    return _ida_bytes.float_flag()


def double_flag() ->'flags64_t':
    """Get a flags64_t representing a double.
"""
    return _ida_bytes.double_flag()


def packreal_flag() ->'flags64_t':
    """Get a flags64_t representing a packed decimal real.
"""
    return _ida_bytes.packreal_flag()


def is_byte(F: 'flags64_t') ->bool:
    """FF_BYTE
"""
    return _ida_bytes.is_byte(F)


def is_word(F: 'flags64_t') ->bool:
    """FF_WORD
"""
    return _ida_bytes.is_word(F)


def is_dword(F: 'flags64_t') ->bool:
    """FF_DWORD
"""
    return _ida_bytes.is_dword(F)


def is_qword(F: 'flags64_t') ->bool:
    """FF_QWORD
"""
    return _ida_bytes.is_qword(F)


def is_oword(F: 'flags64_t') ->bool:
    """FF_OWORD
"""
    return _ida_bytes.is_oword(F)


def is_yword(F: 'flags64_t') ->bool:
    """FF_YWORD
"""
    return _ida_bytes.is_yword(F)


def is_zword(F: 'flags64_t') ->bool:
    """FF_ZWORD
"""
    return _ida_bytes.is_zword(F)


def is_tbyte(F: 'flags64_t') ->bool:
    """FF_TBYTE
"""
    return _ida_bytes.is_tbyte(F)


def is_float(F: 'flags64_t') ->bool:
    """FF_FLOAT
"""
    return _ida_bytes.is_float(F)


def is_double(F: 'flags64_t') ->bool:
    """FF_DOUBLE
"""
    return _ida_bytes.is_double(F)


def is_pack_real(F: 'flags64_t') ->bool:
    """FF_PACKREAL
"""
    return _ida_bytes.is_pack_real(F)


def is_strlit(F: 'flags64_t') ->bool:
    """FF_STRLIT
"""
    return _ida_bytes.is_strlit(F)


def is_struct(F: 'flags64_t') ->bool:
    """FF_STRUCT
"""
    return _ida_bytes.is_struct(F)


def is_align(F: 'flags64_t') ->bool:
    """FF_ALIGN
"""
    return _ida_bytes.is_align(F)


def is_custom(F: 'flags64_t') ->bool:
    """FF_CUSTOM
"""
    return _ida_bytes.is_custom(F)


def f_is_byte(F: 'flags64_t', arg2: 'void *') ->bool:
    """See is_byte()
"""
    return _ida_bytes.f_is_byte(F, arg2)


def f_is_word(F: 'flags64_t', arg2: 'void *') ->bool:
    """See is_word()
"""
    return _ida_bytes.f_is_word(F, arg2)


def f_is_dword(F: 'flags64_t', arg2: 'void *') ->bool:
    """See is_dword()
"""
    return _ida_bytes.f_is_dword(F, arg2)


def f_is_qword(F: 'flags64_t', arg2: 'void *') ->bool:
    """See is_qword()
"""
    return _ida_bytes.f_is_qword(F, arg2)


def f_is_oword(F: 'flags64_t', arg2: 'void *') ->bool:
    """See is_oword()
"""
    return _ida_bytes.f_is_oword(F, arg2)


def f_is_yword(F: 'flags64_t', arg2: 'void *') ->bool:
    """See is_yword()
"""
    return _ida_bytes.f_is_yword(F, arg2)


def f_is_tbyte(F: 'flags64_t', arg2: 'void *') ->bool:
    """See is_tbyte()
"""
    return _ida_bytes.f_is_tbyte(F, arg2)


def f_is_float(F: 'flags64_t', arg2: 'void *') ->bool:
    """See is_float()
"""
    return _ida_bytes.f_is_float(F, arg2)


def f_is_double(F: 'flags64_t', arg2: 'void *') ->bool:
    """See is_double()
"""
    return _ida_bytes.f_is_double(F, arg2)


def f_is_pack_real(F: 'flags64_t', arg2: 'void *') ->bool:
    """See is_pack_real()
"""
    return _ida_bytes.f_is_pack_real(F, arg2)


def f_is_strlit(F: 'flags64_t', arg2: 'void *') ->bool:
    """See is_strlit()
"""
    return _ida_bytes.f_is_strlit(F, arg2)


def f_is_struct(F: 'flags64_t', arg2: 'void *') ->bool:
    """See is_struct()
"""
    return _ida_bytes.f_is_struct(F, arg2)


def f_is_align(F: 'flags64_t', arg2: 'void *') ->bool:
    """See is_align()
"""
    return _ida_bytes.f_is_align(F, arg2)


def f_is_custom(F: 'flags64_t', arg2: 'void *') ->bool:
    """See is_custom()
"""
    return _ida_bytes.f_is_custom(F, arg2)


def is_same_data_type(F1: 'flags64_t', F2: 'flags64_t') ->bool:
    """Do the given flags specify the same data type?
"""
    return _ida_bytes.is_same_data_type(F1, F2)


def get_flags_by_size(size: 'size_t') ->'flags64_t':
    """Get flags from size (in bytes). Supported sizes: 1, 2, 4, 8, 16, 32. For other sizes returns 0 
        """
    return _ida_bytes.get_flags_by_size(size)


def create_data(ea: ida_idaapi.ea_t, dataflag: 'flags64_t', size: 'asize_t',
    tid: 'tid_t') ->bool:
    """Convert to data (byte, word, dword, etc). This function may be used to create arrays. 
        
@param ea: linear address
@param dataflag: type of data. Value of function byte_flag(), word_flag(), etc.
@param size: size of array in bytes. should be divisible by the size of one item of the specified type. for variable sized items it can be specified as 0, and the kernel will try to calculate the size.
@param tid: type id. If the specified type is a structure, then tid is structure id. Otherwise should be BADNODE.
@returns success"""
    return _ida_bytes.create_data(ea, dataflag, size, tid)


def calc_dflags(f: 'flags64_t', force: bool) ->'flags64_t':
    return _ida_bytes.calc_dflags(f, force)


def create_byte(ea: ida_idaapi.ea_t, length: 'asize_t', force: bool=False
    ) ->bool:
    """Convert to byte.
"""
    return _ida_bytes.create_byte(ea, length, force)


def create_word(ea: ida_idaapi.ea_t, length: 'asize_t', force: bool=False
    ) ->bool:
    """Convert to word.
"""
    return _ida_bytes.create_word(ea, length, force)


def create_dword(ea: ida_idaapi.ea_t, length: 'asize_t', force: bool=False
    ) ->bool:
    """Convert to dword.
"""
    return _ida_bytes.create_dword(ea, length, force)


def create_qword(ea: ida_idaapi.ea_t, length: 'asize_t', force: bool=False
    ) ->bool:
    """Convert to quadword.
"""
    return _ida_bytes.create_qword(ea, length, force)


def create_oword(ea: ida_idaapi.ea_t, length: 'asize_t', force: bool=False
    ) ->bool:
    """Convert to octaword/xmm word.
"""
    return _ida_bytes.create_oword(ea, length, force)


def create_yword(ea: ida_idaapi.ea_t, length: 'asize_t', force: bool=False
    ) ->bool:
    """Convert to ymm word.
"""
    return _ida_bytes.create_yword(ea, length, force)


def create_zword(ea: ida_idaapi.ea_t, length: 'asize_t', force: bool=False
    ) ->bool:
    """Convert to zmm word.
"""
    return _ida_bytes.create_zword(ea, length, force)


def create_tbyte(ea: ida_idaapi.ea_t, length: 'asize_t', force: bool=False
    ) ->bool:
    """Convert to tbyte.
"""
    return _ida_bytes.create_tbyte(ea, length, force)


def create_float(ea: ida_idaapi.ea_t, length: 'asize_t', force: bool=False
    ) ->bool:
    """Convert to float.
"""
    return _ida_bytes.create_float(ea, length, force)


def create_double(ea: ida_idaapi.ea_t, length: 'asize_t', force: bool=False
    ) ->bool:
    """Convert to double.
"""
    return _ida_bytes.create_double(ea, length, force)


def create_packed_real(ea: ida_idaapi.ea_t, length: 'asize_t', force: bool=
    False) ->bool:
    """Convert to packed decimal real.
"""
    return _ida_bytes.create_packed_real(ea, length, force)


def create_struct(ea: ida_idaapi.ea_t, length: 'asize_t', tid: 'tid_t',
    force: bool=False) ->bool:
    """Convert to struct.
"""
    return _ida_bytes.create_struct(ea, length, tid, force)


def create_custdata(ea: ida_idaapi.ea_t, length: 'asize_t', dtid: int, fid:
    int, force: bool=False) ->bool:
    """Convert to custom data type.
"""
    return _ida_bytes.create_custdata(ea, length, dtid, fid, force)


def create_align(ea: ida_idaapi.ea_t, length: 'asize_t', alignment: int
    ) ->bool:
    """Create an alignment item. 
        
@param ea: linear address
@param length: size of the item in bytes. 0 means to infer from ALIGNMENT
@param alignment: alignment exponent. Example: 3 means align to 8 bytes. 0 means to infer from LENGTH It is forbidden to specify both LENGTH and ALIGNMENT as 0.
@returns success"""
    return _ida_bytes.create_align(ea, length, alignment)


def calc_min_align(length: 'asize_t') ->int:
    """Calculate the minimal possible alignment exponent. 
        
@param length: size of the item in bytes.
@returns a value in the 1..32 range"""
    return _ida_bytes.calc_min_align(length)


def calc_max_align(endea: ida_idaapi.ea_t) ->int:
    """Calculate the maximal possible alignment exponent. 
        
@param endea: end address of the alignment item.
@returns a value in the 0..32 range"""
    return _ida_bytes.calc_max_align(endea)


def calc_def_align(ea: ida_idaapi.ea_t, mina: int, maxa: int) ->int:
    """Calculate the default alignment exponent. 
        
@param ea: linear address
@param mina: minimal possible alignment exponent.
@param maxa: minimal possible alignment exponent."""
    return _ida_bytes.calc_def_align(ea, mina, maxa)


def create_16bit_data(ea: ida_idaapi.ea_t, length: 'asize_t') ->bool:
    """Convert to 16-bit quantity (take the byte size into account)
"""
    return _ida_bytes.create_16bit_data(ea, length)


def create_32bit_data(ea: ida_idaapi.ea_t, length: 'asize_t') ->bool:
    """Convert to 32-bit quantity (take the byte size into account)
"""
    return _ida_bytes.create_32bit_data(ea, length)


ALOPT_IGNHEADS = _ida_bytes.ALOPT_IGNHEADS
"""don't stop if another data item is encountered. only the byte values will be used to determine the string length. if not set, a defined data item or instruction will truncate the string 
        """
ALOPT_IGNPRINT = _ida_bytes.ALOPT_IGNPRINT
"""if set, don't stop at non-printable codepoints, but only at the terminating character (or not unicode-mapped character (e.g., 0x8f in CP1252)) 
        """
ALOPT_IGNCLT = _ida_bytes.ALOPT_IGNCLT
"""if set, don't stop at codepoints that are not part of the current 'culture'; accept all those that are graphical (this is typically used used by user-initiated actions creating string literals.) 
        """
ALOPT_MAX4K = _ida_bytes.ALOPT_MAX4K
"""if string length is more than 4K, return the accumulated length 
        """
ALOPT_ONLYTERM = _ida_bytes.ALOPT_ONLYTERM
"""only the termination characters can be at the string end. Without this option illegal characters also terminate the string. 
        """
ALOPT_APPEND = _ida_bytes.ALOPT_APPEND
"""if an existing strlit is encountered, then append it to the string. 
        """


def get_max_strlit_length(ea: ida_idaapi.ea_t, strtype: int, options: int=0
    ) ->'size_t':
    """Determine maximum length of string literal.
If the string literal has a length prefix (e.g., STRTYPE_LEN2 has a two-byte length prefix), the length of that prefix (i.e., 2) will be part of the returned value.

@param ea: starting address
@param strtype: string type. one of String type codes
@param options: combination of string literal length options
@returns length of the string in octets (octet==8bit)"""
    return _ida_bytes.get_max_strlit_length(ea, strtype, options)


STRCONV_ESCAPE = _ida_bytes.STRCONV_ESCAPE
"""convert non-printable characters to C escapes (
, \\xNN, \\uNNNN)
"""
STRCONV_REPLCHAR = _ida_bytes.STRCONV_REPLCHAR
"""convert non-printable characters to the Unicode replacement character (U+FFFD)
"""
STRCONV_INCLLEN = _ida_bytes.STRCONV_INCLLEN
"""for Pascal-style strings, include the prefixing length byte(s) as C-escaped sequence
"""


def create_strlit(start: ida_idaapi.ea_t, len: 'size_t', strtype: int) ->bool:
    """Convert to string literal and give a meaningful name. 'start' may be higher than 'end', the kernel will swap them in this case 
        
@param start: starting address
@param len: length of the string in bytes. if 0, then get_max_strlit_length() will be used to determine the length
@param strtype: string type. one of String type codes
@returns success"""
    return _ida_bytes.create_strlit(start, len, strtype)


PSTF_TNORM = _ida_bytes.PSTF_TNORM
"""use normal name
"""
PSTF_TBRIEF = _ida_bytes.PSTF_TBRIEF
"""use brief name (e.g., in the 'Strings' window)
"""
PSTF_TINLIN = _ida_bytes.PSTF_TINLIN
"""use 'inline' name (e.g., in the structures comments)
"""
PSTF_TMASK = _ida_bytes.PSTF_TMASK
"""type mask
"""
PSTF_HOTKEY = _ida_bytes.PSTF_HOTKEY
"""have hotkey markers part of the name
"""
PSTF_ENC = _ida_bytes.PSTF_ENC
"""if encoding is specified, append it
"""
PSTF_ONLY_ENC = _ida_bytes.PSTF_ONLY_ENC
"""generate only the encoding name
"""
PSTF_ATTRIB = _ida_bytes.PSTF_ATTRIB
"""generate for type attribute usage
"""


def get_opinfo(buf: 'opinfo_t', ea: ida_idaapi.ea_t, n: int, flags: 'flags64_t'
    ) ->'opinfo_t *':
    """Get additional information about an operand representation. 
        
@param buf: buffer to receive the result. may not be nullptr
@param ea: linear address of item
@param n: number of operand, 0 or 1
@param flags: flags of the item
@returns nullptr if no additional representation information"""
    return _ida_bytes.get_opinfo(buf, ea, n, flags)


def set_opinfo(ea: ida_idaapi.ea_t, n: int, flag: 'flags64_t', ti:
    'opinfo_t', suppress_events: bool=False) ->bool:
    """Set additional information about an operand representation. This function is a low level one. Only the kernel should use it. 
        
@param ea: linear address of the item
@param n: number of operand, 0 or 1 (see the note below)
@param flag: flags of the item
@param ti: additional representation information
@param suppress_events: do not generate changing_op_type and op_type_changed events
@returns success"""
    return _ida_bytes.set_opinfo(ea, n, flag, ti, suppress_events)


def get_data_elsize(ea: ida_idaapi.ea_t, F: 'flags64_t', ti: 'opinfo_t'=None
    ) ->'asize_t':
    """Get size of data type specified in flags 'F'. 
        
@param ea: linear address of the item
@param F: flags
@param ti: additional information about the data type. For example, if the current item is a structure instance, then ti->tid is structure id. Otherwise is ignored (may be nullptr). If specified as nullptr, will be automatically retrieved from the database
@returns * byte : 1
* word : 2
* etc..."""
    return _ida_bytes.get_data_elsize(ea, F, ti)


def get_full_data_elsize(ea: ida_idaapi.ea_t, F: 'flags64_t', ti:
    'opinfo_t'=None) ->'asize_t':
    """Get full size of data type specified in flags 'F'. takes into account processors with wide bytes e.g. returns 2 for a byte element with 16-bit bytes 
        """
    return _ida_bytes.get_full_data_elsize(ea, F, ti)


def is_varsize_item(ea: ida_idaapi.ea_t, F: 'flags64_t', ti: 'opinfo_t'=
    None, itemsize: 'asize_t *'=None) ->int:
    """Is the item at 'ea' variable size?. 
        
@param ea: linear address of the item
@param F: flags
@param ti: additional information about the data type. For example, if the current item is a structure instance, then ti->tid is structure id. Otherwise is ignored (may be nullptr). If specified as nullptr, will be automatically retrieved from the database
@param itemsize: if not nullptr and the item is varsize, itemsize will contain the calculated item size (for struct types, the minimal size is returned)
@retval 1: varsize item
@retval 0: fixed item
@retval -1: error (bad data definition)"""
    return _ida_bytes.is_varsize_item(ea, F, ti, itemsize)


def get_possible_item_varsize(ea: ida_idaapi.ea_t, tif: 'tinfo_t') ->'asize_t':
    """Return the possible size of the item at EA of type TIF if TIF is the variable structure. 
        
@param ea: the linear address of the item
@param tif: the item type
@returns the possible size
@retval asize_t(-1): TIF is not a variable structure"""
    return _ida_bytes.get_possible_item_varsize(ea, tif)


def can_define_item(ea: ida_idaapi.ea_t, length: 'asize_t', flags: 'flags64_t'
    ) ->bool:
    """Can define item (instruction/data) of the specified 'length', starting at 'ea'? 
* a new item would cross segment boundaries
* a new item would overlap with existing items (except items specified by 'flags') 


        
@param ea: start of the range for the new item
@param length: length of the new item in bytes
@param flags: if not 0, then the kernel will ignore the data types specified by the flags and destroy them. For example: 
                 1000 dw 5
                 1002 db 5 ; undef
                 1003 db 5 ; undef
                 1004 dw 5
                 1006 dd 5
                  can_define_item(1000, 6, 0) - false because of dw at 1004 
 can_define_item(1000, 6, word_flag()) - true, word at 1004 is destroyed
@returns 1-yes, 0-no"""
    return _ida_bytes.can_define_item(ea, length, flags)


MS_CODE = _ida_bytes.MS_CODE
"""Mask for code bits.
"""
FF_FUNC = _ida_bytes.FF_FUNC
"""function start?
"""
FF_IMMD = _ida_bytes.FF_IMMD
"""Has Immediate value ?
"""
FF_JUMP = _ida_bytes.FF_JUMP
"""Has jump table or switch_info?
"""


def has_immd(F: 'flags64_t') ->bool:
    """Has immediate value?
"""
    return _ida_bytes.has_immd(F)


def is_func(F: 'flags64_t') ->bool:
    """Is function start?
"""
    return _ida_bytes.is_func(F)


def set_immd(ea: ida_idaapi.ea_t) ->bool:
    """Set 'has immediate operand' flag. Returns true if the FF_IMMD bit was not set and now is set 
        """
    return _ida_bytes.set_immd(ea)


class data_type_t(object):
    """Information about a data type"""
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    props: 'int' = property(_ida_bytes.data_type_t_props_get, _ida_bytes.
        data_type_t_props_set)
    """properties
"""
    name: 'char const *' = property(_ida_bytes.data_type_t_name_get,
        _ida_bytes.data_type_t_name_set)
    """name of the data type. must be unique
"""
    menu_name: 'char const *' = property(_ida_bytes.
        data_type_t_menu_name_get, _ida_bytes.data_type_t_menu_name_set)
    """Visible data type name to use in menus if nullptr, no menu item will be created 
        """
    hotkey: 'char const *' = property(_ida_bytes.data_type_t_hotkey_get,
        _ida_bytes.data_type_t_hotkey_set)
    """Hotkey for the corresponding menu item if nullptr, no hotkey will be associated with the menu item 
        """
    asm_keyword: 'char const *' = property(_ida_bytes.
        data_type_t_asm_keyword_get, _ida_bytes.data_type_t_asm_keyword_set)
    """keyword to use for this type in the assembly if nullptr, the data type cannot be used in the listing it can still be used in cpuregs window 
        """
    value_size: 'asize_t' = property(_ida_bytes.data_type_t_value_size_get,
        _ida_bytes.data_type_t_value_size_set)
    """size of the value in bytes
"""

    def is_present_in_menus(self) ->bool:
        """Should this type be shown in UI menus 
        
@returns success"""
        return _ida_bytes.data_type_t_is_present_in_menus(self)

    def __init__(self, _self: 'PyObject *', name: str, value_size:
        'asize_t'=0, menu_name: str=None, hotkey: str=None, asm_keyword:
        str=None, props: int=0):
        _ida_bytes.data_type_t_swiginit(self, _ida_bytes.new_data_type_t(
            _self, name, value_size, menu_name, hotkey, asm_keyword, props))
    __swig_destroy__ = _ida_bytes.delete_data_type_t

    def __get_id(self) ->int:
        return _ida_bytes.data_type_t___get_id(self)
    id = property(__get_id)
    __real__init__ = __init__

    def __init__(self, *args):
        self.__real__init__(self, *args)


_ida_bytes.data_type_t_swigregister(data_type_t)
DTP_NODUP = _ida_bytes.DTP_NODUP
"""do not use dup construct
"""


class data_format_t(object):
    """Information about a data format"""
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    props: 'int' = property(_ida_bytes.data_format_t_props_get, _ida_bytes.
        data_format_t_props_set)
    """properties (currently 0)
"""
    name: 'char const *' = property(_ida_bytes.data_format_t_name_get,
        _ida_bytes.data_format_t_name_set)
    """Format name, must be unique.
"""
    menu_name: 'char const *' = property(_ida_bytes.
        data_format_t_menu_name_get, _ida_bytes.data_format_t_menu_name_set)
    """Visible format name to use in menus if nullptr, no menu item will be created 
        """
    hotkey: 'char const *' = property(_ida_bytes.data_format_t_hotkey_get,
        _ida_bytes.data_format_t_hotkey_set)
    """Hotkey for the corresponding menu item if nullptr, no hotkey will be associated with the menu item 
        """
    value_size: 'asize_t' = property(_ida_bytes.
        data_format_t_value_size_get, _ida_bytes.data_format_t_value_size_set)
    """size of the value in bytes 0 means any size is ok data formats that are registered for standard types (dtid 0) may be called with any value_size (instruction operands only) 
        """
    text_width: 'int32' = property(_ida_bytes.data_format_t_text_width_get,
        _ida_bytes.data_format_t_text_width_set)
    """Usual width of the text representation This value is used to calculate the width of the control to display values of this type 
        """

    def is_present_in_menus(self) ->bool:
        """Should this format be shown in UI menus 
        
@returns success"""
        return _ida_bytes.data_format_t_is_present_in_menus(self)

    def __init__(self, _self: 'PyObject *', name: str, value_size:
        'asize_t'=0, menu_name: str=None, props: int=0, hotkey: str=None,
        text_width: int=0):
        _ida_bytes.data_format_t_swiginit(self, _ida_bytes.
            new_data_format_t(_self, name, value_size, menu_name, props,
            hotkey, text_width))
    __swig_destroy__ = _ida_bytes.delete_data_format_t

    def __get_id(self) ->int:
        return _ida_bytes.data_format_t___get_id(self)
    id = property(__get_id)
    __real__init__ = __init__

    def __init__(self, *args):
        self.__real__init__(self, *args)


_ida_bytes.data_format_t_swigregister(data_format_t)


def get_custom_data_type(dtid: int) ->'data_type_t const *':
    """Get definition of a registered custom data type. 
        
@param dtid: data type id
@returns data type definition or nullptr"""
    return _ida_bytes.get_custom_data_type(dtid)


def get_custom_data_format(dfid: int) ->'data_format_t const *':
    """Get definition of a registered custom data format. 
        
@param dfid: data format id
@returns data format definition or nullptr"""
    return _ida_bytes.get_custom_data_format(dfid)


def attach_custom_data_format(dtid: int, dfid: int) ->bool:
    """Attach the data format to the data type. 
        
@param dtid: data type id that can use the data format. 0 means all standard data types. Such data formats can be applied to any data item or instruction operands. For instruction operands, the data_format_t::value_size check is not performed by the kernel.
@param dfid: data format id
@retval true: ok
@retval false: no such `dtid`, or no such `dfid', or the data format has already been attached to the data type"""
    return _ida_bytes.attach_custom_data_format(dtid, dfid)


def detach_custom_data_format(dtid: int, dfid: int) ->bool:
    """Detach the data format from the data type. Unregistering a custom data type detaches all attached data formats, no need to detach them explicitly. You still need unregister them. Unregistering a custom data format detaches it from all attached data types. 
        
@param dtid: data type id to detach data format from
@param dfid: data format id to detach
@retval true: ok
@retval false: no such `dtid`, or no such `dfid', or the data format was not attached to the data type"""
    return _ida_bytes.detach_custom_data_format(dtid, dfid)


def is_attached_custom_data_format(dtid: int, dfid: int) ->bool:
    """Is the custom data format attached to the custom data type? 
        
@param dtid: data type id
@param dfid: data format id
@returns true or false"""
    return _ida_bytes.is_attached_custom_data_format(dtid, dfid)


def get_custom_data_types(*args) ->int:
    """Get list of registered custom data type ids. 
        
@param out: buffer for the output. may be nullptr
@param min_size: minimum value size
@param max_size: maximum value size
@returns number of custom data types with the specified size limits"""
    return _ida_bytes.get_custom_data_types(*args)


def get_custom_data_formats(out: 'intvec_t *', dtid: int) ->int:
    """Get list of attached custom data formats for the specified data type. 
        
@param out: buffer for the output. may be nullptr
@param dtid: data type id
@returns number of returned custom data formats. if error, returns -1"""
    return _ida_bytes.get_custom_data_formats(out, dtid)


def find_custom_data_type(name: str) ->int:
    """Get id of a custom data type. 
        
@param name: name of the custom data type
@returns id or -1"""
    return _ida_bytes.find_custom_data_type(name)


def find_custom_data_format(name: str) ->int:
    """Get id of a custom data format. 
        
@param name: name of the custom data format
@returns id or -1"""
    return _ida_bytes.find_custom_data_format(name)


def set_cmt(ea: ida_idaapi.ea_t, comm: str, rptble: bool) ->bool:
    """Set an indented comment. 
        
@param ea: linear address
@param comm: comment string
* nullptr: do nothing (return 0)
* "" : delete comment
@param rptble: is repeatable?
@returns success"""
    return _ida_bytes.set_cmt(ea, comm, rptble)


def get_cmt(ea: ida_idaapi.ea_t, rptble: bool) ->str:
    """Get an indented comment. 
        
@param ea: linear address. may point to tail byte, the function will find start of the item
@param rptble: get repeatable comment?
@returns size of comment or -1"""
    return _ida_bytes.get_cmt(ea, rptble)


def append_cmt(ea: ida_idaapi.ea_t, str: str, rptble: bool) ->bool:
    """Append to an indented comment. Creates a new comment if none exists. Appends a newline character and the specified string otherwise. 
        
@param ea: linear address
@param str: comment string to append
@param rptble: append to repeatable comment?
@returns success"""
    return _ida_bytes.append_cmt(ea, str, rptble)


def get_predef_insn_cmt(ins: 'insn_t const &') ->str:
    """Get predefined comment. 
        
@param ins: current instruction information
@returns size of comment or -1"""
    return _ida_bytes.get_predef_insn_cmt(ins)


def find_byte(sEA: ida_idaapi.ea_t, size: 'asize_t', value: 'uchar',
    bin_search_flags: int) ->ida_idaapi.ea_t:
    """Find forward a byte with the specified value (only 8-bit value from the database). example: ea=4 size=3 will inspect addresses 4, 5, and 6 
        
@param sEA: linear address
@param size: number of bytes to inspect
@param value: value to find
@param bin_search_flags: combination of Search flags
@returns address of byte or BADADDR"""
    return _ida_bytes.find_byte(sEA, size, value, bin_search_flags)


def find_byter(sEA: ida_idaapi.ea_t, size: 'asize_t', value: 'uchar',
    bin_search_flags: int) ->ida_idaapi.ea_t:
    """Find reverse a byte with the specified value (only 8-bit value from the database). example: ea=4 size=3 will inspect addresses 6, 5, and 4 
        
@param sEA: the lower address of the search range
@param size: number of bytes to inspect
@param value: value to find
@param bin_search_flags: combination of Search flags
@returns address of byte or BADADDR"""
    return _ida_bytes.find_byter(sEA, size, value, bin_search_flags)


class compiled_binpat_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    bytes: 'bytevec_t' = property(_ida_bytes.compiled_binpat_t_bytes_get,
        _ida_bytes.compiled_binpat_t_bytes_set)
    mask: 'bytevec_t' = property(_ida_bytes.compiled_binpat_t_mask_get,
        _ida_bytes.compiled_binpat_t_mask_set)
    strlits: 'rangevec_t' = property(_ida_bytes.
        compiled_binpat_t_strlits_get, _ida_bytes.compiled_binpat_t_strlits_set
        )
    encidx: 'int' = property(_ida_bytes.compiled_binpat_t_encidx_get,
        _ida_bytes.compiled_binpat_t_encidx_set)

    def __init__(self):
        _ida_bytes.compiled_binpat_t_swiginit(self, _ida_bytes.
            new_compiled_binpat_t())

    def all_bytes_defined(self) ->bool:
        return _ida_bytes.compiled_binpat_t_all_bytes_defined(self)

    def qclear(self) ->None:
        return _ida_bytes.compiled_binpat_t_qclear(self)

    def __eq__(self, r: 'compiled_binpat_t') ->bool:
        return _ida_bytes.compiled_binpat_t___eq__(self, r)

    def __ne__(self, r: 'compiled_binpat_t') ->bool:
        return _ida_bytes.compiled_binpat_t___ne__(self, r)
    __swig_destroy__ = _ida_bytes.delete_compiled_binpat_t


_ida_bytes.compiled_binpat_t_swigregister(compiled_binpat_t)
PBSENC_DEF1BPU = _ida_bytes.PBSENC_DEF1BPU
"""Use the default 1 byte-per-unit IDB encoding.
"""
PBSENC_ALL = _ida_bytes.PBSENC_ALL
"""Use all IDB encodings.
"""


def parse_binpat_str(out: 'compiled_binpat_vec_t', ea: ida_idaapi.ea_t, _in:
    str, radix: int, strlits_encoding: int=0) ->bool:
    """Convert user-specified binary string to internal representation. The 'in' parameter contains space-separated tokens: 
     numbers (numeric base is determined by 'radix')
        - if value of number fits a byte, it is considered as a byte
        - if value of number fits a word, it is considered as 2 bytes
        - if value of number fits a dword,it is considered as 4 bytes
     "..." string constants
     'x'  single-character constants
     ?    variable bytes


Note that string constants are surrounded with double quotes.
Here are a few examples (assuming base 16): 
     21          - bytes 0xCD, 0x21
               - bytes 0xCD, 0x21 (little endian ) or 0x21, 0xCD (big-endian)
     0     - the null terminated string "Hello"
           - 'H', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0
     ? ? ? ? 90  - byte 0xB8, 4 bytes with any value, byte 0x90


        
@param out: a vector of compiled binary patterns, for use with bin_search()
@param ea: linear address to convert for (the conversion depends on the address, because the number of bits in a byte depend on the segment type)
@param radix: numeric base of numbers (8,10,16)
@param strlits_encoding: the target encoding into which the string literals present in 'in', should be encoded. Can be any from [1, get_encoding_qty()), or the special values PBSENC_*
@returns false either in case of parsing error, or if at least one requested target encoding couldn't encode the string literals present in "in"."""
    return _ida_bytes.parse_binpat_str(out, ea, _in, radix, strlits_encoding)


def bin_search(*args):
    """Search for a set of bytes in the program

This function has the following signatures:

    1. bin_search(start_ea: ida_idaapi.ea_t, end_ea: ida_idaapi.ea_t, data: compiled_binpat_vec_t, flags: int) -> Tuple[ida_idaapi.ea_t, int]
    2. bin_search(start_ea: ida_idaapi.ea_t, end_ea: ida_idaapi.ea_t, image: bytes, mask: bytes, len: int, flags: int) -> ida_idaapi.ea_t

The return value type will differ depending on the form:

    1. a tuple `(matched-address, index-in-compiled_binpat_vec_t)` (1st form)
    2. the address of a match, or ida_idaapi.BADADDR if not found (2nd form)

This is a low-level function; more user-friendly alternatives
are available. Please see 'find_bytes' and 'find_string'.

@param start_ea: linear address, start of range to search
@param end_ea: linear address, end of range to search (exclusive)
@param data: (1st form) the prepared data to search for (see parse_binpat_str())
@param bytes: (2nd form) a set of bytes to match
@param mask: (2nd form) a mask to apply to the set of bytes
@param flags: combination of BIN_SEARCH_* flags
@return: either a tuple holding both the address of the match and the index of the compiled pattern that matched, or the address of a match (ida_idaapi.BADADDR if not found)"""
    return _ida_bytes.bin_search(*args)


BIN_SEARCH_CASE = _ida_bytes.BIN_SEARCH_CASE
"""case sensitive
"""
BIN_SEARCH_NOCASE = _ida_bytes.BIN_SEARCH_NOCASE
"""case insensitive
"""
BIN_SEARCH_NOBREAK = _ida_bytes.BIN_SEARCH_NOBREAK
"""don't check for Ctrl-Break
"""
BIN_SEARCH_INITED = _ida_bytes.BIN_SEARCH_INITED
"""find_byte, find_byter: any initilized value
"""
BIN_SEARCH_NOSHOW = _ida_bytes.BIN_SEARCH_NOSHOW
"""don't show search progress or update screen
"""
BIN_SEARCH_FORWARD = _ida_bytes.BIN_SEARCH_FORWARD
"""search forward for bytes
"""
BIN_SEARCH_BACKWARD = _ida_bytes.BIN_SEARCH_BACKWARD
"""search backward for bytes
"""
BIN_SEARCH_BITMASK = _ida_bytes.BIN_SEARCH_BITMASK
"""searching using strict bit mask
"""


def next_inited(ea: ida_idaapi.ea_t, maxea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
    """Find the next initialized address.
"""
    return _ida_bytes.next_inited(ea, maxea)


def prev_inited(ea: ida_idaapi.ea_t, minea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
    """Find the previous initialized address.
"""
    return _ida_bytes.prev_inited(ea, minea)


def equal_bytes(ea: ida_idaapi.ea_t, image: 'uchar const *', mask:
    'uchar const *', len: 'size_t', bin_search_flags: int) ->bool:
    """Compare 'len' bytes of the program starting from 'ea' with 'image'. 
        
@param ea: linear address
@param image: bytes to compare with
@param mask: array of mask bytes, it's length is 'len'. if the flag BIN_SEARCH_BITMASK is passsed, 'bitwise AND' is used to compare. if not; 1 means to perform the comparison of the corresponding byte. 0 means not to perform. if mask == nullptr, then all bytes of 'image' will be compared. if mask == SKIP_FF_MASK then 0xFF bytes will be skipped
@param len: length of block to compare in bytes.
@param bin_search_flags: combination of Search flags
@retval 1: equal
@retval 0: not equal"""
    return _ida_bytes.equal_bytes(ea, image, mask, len, bin_search_flags)


class hidden_range_t(ida_range.range_t):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    description: 'char *' = property(_ida_bytes.
        hidden_range_t_description_get, _ida_bytes.
        hidden_range_t_description_set)
    """description to display if the range is collapsed
"""
    header: 'char *' = property(_ida_bytes.hidden_range_t_header_get,
        _ida_bytes.hidden_range_t_header_set)
    """header lines to display if the range is expanded
"""
    footer: 'char *' = property(_ida_bytes.hidden_range_t_footer_get,
        _ida_bytes.hidden_range_t_footer_set)
    """footer lines to display if the range is expanded
"""
    visible: 'bool' = property(_ida_bytes.hidden_range_t_visible_get,
        _ida_bytes.hidden_range_t_visible_set)
    """the range state
"""
    color: 'bgcolor_t' = property(_ida_bytes.hidden_range_t_color_get,
        _ida_bytes.hidden_range_t_color_set)
    """range color
"""

    def __init__(self):
        _ida_bytes.hidden_range_t_swiginit(self, _ida_bytes.
            new_hidden_range_t())
    __swig_destroy__ = _ida_bytes.delete_hidden_range_t


_ida_bytes.hidden_range_t_swigregister(hidden_range_t)


def update_hidden_range(ha: 'hidden_range_t') ->bool:
    """Update hidden range information in the database. You cannot use this function to change the range boundaries 
        
@param ha: range to update
@returns success"""
    return _ida_bytes.update_hidden_range(ha)


def add_hidden_range(*args) ->bool:
    """Mark a range of addresses as hidden. The range will be created in the invisible state with the default color 
        
@param ea1: linear address of start of the address range
@param ea2: linear address of end of the address range
@param description: range parameters
@param header: range parameters
@param footer: range parameters
@param color: the range color
@returns success"""
    return _ida_bytes.add_hidden_range(*args)


def get_hidden_range(ea: ida_idaapi.ea_t) ->'hidden_range_t *':
    """Get pointer to hidden range structure, in: linear address. 
        
@param ea: any address in the hidden range"""
    return _ida_bytes.get_hidden_range(ea)


def getn_hidden_range(n: int) ->'hidden_range_t *':
    """Get pointer to hidden range structure, in: number of hidden range. 
        
@param n: number of hidden range, is in range 0..get_hidden_range_qty()-1"""
    return _ida_bytes.getn_hidden_range(n)


def get_hidden_range_qty() ->int:
    """Get number of hidden ranges.
"""
    return _ida_bytes.get_hidden_range_qty()


def get_hidden_range_num(ea: ida_idaapi.ea_t) ->int:
    """Get number of a hidden range. 
        
@param ea: any address in the hidden range
@returns number of hidden range (0..get_hidden_range_qty()-1)"""
    return _ida_bytes.get_hidden_range_num(ea)


def get_prev_hidden_range(ea: ida_idaapi.ea_t) ->'hidden_range_t *':
    """Get pointer to previous hidden range. 
        
@param ea: any address in the program
@returns ptr to hidden range or nullptr if previous hidden range doesn't exist"""
    return _ida_bytes.get_prev_hidden_range(ea)


def get_next_hidden_range(ea: ida_idaapi.ea_t) ->'hidden_range_t *':
    """Get pointer to next hidden range. 
        
@param ea: any address in the program
@returns ptr to hidden range or nullptr if next hidden range doesn't exist"""
    return _ida_bytes.get_next_hidden_range(ea)


def get_first_hidden_range() ->'hidden_range_t *':
    """Get pointer to the first hidden range. 
        
@returns ptr to hidden range or nullptr"""
    return _ida_bytes.get_first_hidden_range()


def get_last_hidden_range() ->'hidden_range_t *':
    """Get pointer to the last hidden range. 
        
@returns ptr to hidden range or nullptr"""
    return _ida_bytes.get_last_hidden_range()


def del_hidden_range(ea: ida_idaapi.ea_t) ->bool:
    """Delete hidden range. 
        
@param ea: any address in the hidden range
@returns success"""
    return _ida_bytes.del_hidden_range(ea)


def add_mapping(_from: ida_idaapi.ea_t, to: ida_idaapi.ea_t, size: 'asize_t'
    ) ->bool:
    """IDA supports memory mapping. References to the addresses from the mapped range use data and meta-data from the mapping range. 
        
@param to: start of the mapping range (existent address)
@param size: size of the range
@returns success"""
    return _ida_bytes.add_mapping(_from, to, size)


def del_mapping(ea: ida_idaapi.ea_t) ->None:
    """Delete memory mapping range. 
        
@param ea: any address in the mapped range"""
    return _ida_bytes.del_mapping(ea)


def use_mapping(ea: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
    """Translate address according to current mappings. 
        
@param ea: address to translate
@returns translated address"""
    return _ida_bytes.use_mapping(ea)


def get_mappings_qty() ->'size_t':
    """Get number of mappings.
"""
    return _ida_bytes.get_mappings_qty()


def get_mapping(n: 'size_t') ->'ea_t *, ea_t *, asize_t *':
    """Get memory mapping range by its number. 
        
@param n: number of mapping range (0..get_mappings_qty()-1)
@returns false if the specified range doesn't exist, otherwise returns `from`, `to`, `size`"""
    return _ida_bytes.get_mapping(n)


MS_0TYPE = _ida_bytes.MS_0TYPE
FF_0VOID = _ida_bytes.FF_0VOID
FF_0NUMH = _ida_bytes.FF_0NUMH
FF_0NUMD = _ida_bytes.FF_0NUMD
FF_0CHAR = _ida_bytes.FF_0CHAR
FF_0SEG = _ida_bytes.FF_0SEG
FF_0OFF = _ida_bytes.FF_0OFF
FF_0NUMB = _ida_bytes.FF_0NUMB
FF_0NUMO = _ida_bytes.FF_0NUMO
FF_0ENUM = _ida_bytes.FF_0ENUM
FF_0FOP = _ida_bytes.FF_0FOP
FF_0STRO = _ida_bytes.FF_0STRO
FF_0STK = _ida_bytes.FF_0STK
FF_0FLT = _ida_bytes.FF_0FLT
FF_0CUST = _ida_bytes.FF_0CUST
MS_1TYPE = _ida_bytes.MS_1TYPE
FF_1VOID = _ida_bytes.FF_1VOID
FF_1NUMH = _ida_bytes.FF_1NUMH
FF_1NUMD = _ida_bytes.FF_1NUMD
FF_1CHAR = _ida_bytes.FF_1CHAR
FF_1SEG = _ida_bytes.FF_1SEG
FF_1OFF = _ida_bytes.FF_1OFF
FF_1NUMB = _ida_bytes.FF_1NUMB
FF_1NUMO = _ida_bytes.FF_1NUMO
FF_1ENUM = _ida_bytes.FF_1ENUM
FF_1FOP = _ida_bytes.FF_1FOP
FF_1STRO = _ida_bytes.FF_1STRO
FF_1STK = _ida_bytes.FF_1STK
FF_1FLT = _ida_bytes.FF_1FLT
FF_1CUST = _ida_bytes.FF_1CUST


def visit_patched_bytes(ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t, callable):
    """Enumerates patched bytes in the given range and invokes a callable

@param ea1: start address
@param ea2: end address
@param callable: a Python callable with the following prototype:
                 callable(ea, fpos, org_val, patch_val).
                 If the callable returns non-zero then that value will be
                 returned to the caller and the enumeration will be
                 interrupted.
@return: Zero if the enumeration was successful or the return
         value of the callback if enumeration was interrupted."""
    return _ida_bytes.visit_patched_bytes(ea1, ea2, callable)


def get_bytes(ea: ida_idaapi.ea_t, size: int, gmb_flags: int=GMB_READALL):
    """Get the specified number of bytes of the program.

@param ea: program address
@param size: number of bytes to return
@param gmb_flags: OR'ed combination of GMB_* values (defaults to GMB_READALL)
@return: the bytes (as bytes object), or None in case of failure"""
    return _ida_bytes.get_bytes(ea, size, gmb_flags)


def get_bytes_and_mask(ea: ida_idaapi.ea_t, size: int, gmb_flags: int=
    GMB_READALL):
    """Get the specified number of bytes of the program, and a bitmask
specifying what bytes are defined and what bytes are not.

@param ea: program address
@param size: number of bytes to return
@param gmb_flags: OR'ed combination of GMB_* values (defaults to GMB_READALL)
@return: a tuple (bytes, mask), or None in case of failure.
         Both 'bytes' and 'mask' are 'str' instances."""
    return _ida_bytes.get_bytes_and_mask(ea, size, gmb_flags)


def get_strlit_contents(ea: ida_idaapi.ea_t, len: int, type: int, flags: int=0
    ):
    """Get contents of string literal, as UTF-8-encoded codepoints.
It works even if the string has not been created in the database yet.

Note that the returned value will be of type 'bytes'; if
you want auto-conversion to unicode strings (that is: real Python
strings), you should probably be using the idautils.Strings class.

@param ea: linear address of the string
@param len: length of the string in bytes (including terminating 0)
@param type: type of the string. Represents both the character encoding,
             <u>and</u> the 'type' of string at the given location.
@param flags: combination of STRCONV_..., to perform output conversion.
@return: a bytes-filled str object."""
    return _ida_bytes.get_strlit_contents(ea, len, type, flags)


def print_strlit_type(strtype: int, flags: int=0) ->'PyObject *':
    """Get string type information: the string type name (possibly decorated with hotkey markers), and the tooltip.

@param strtype: the string type
@param flags: or'ed PSTF_* constants
@returns length of generated text"""
    return _ida_bytes.print_strlit_type(strtype, flags)


def op_stroff(*args) ->bool:
    """Set operand representation to be 'struct offset'.

This function has the following signatures:

    1. op_stroff(ins: ida_ua.insn_t, n: int, path: List[int], delta: int)
    2. op_stroff(ins: ida_ua.insn_t, n: int, path: ida_pro.tid_array, path_len: int, delta: int) (backward-compatibility only)

Here is an example using this function:

    ins = ida_ua.insn_t()
    if ida_ua.decode_insn(ins, some_address):
        operand = 0
        path = [ida_typeinf.get_named_type_tid("my_stucture_t")] # a one-element path
        ida_bytes.op_stroff(ins, operand, path, 0)"""
    return _ida_bytes.op_stroff(*args)


def get_stroff_path(*args):
    """Get the structure offset path for operand `n`, at the
specified address.

This function has the following signatures:

    1. get_stroff_path(ea: ida_idaapi.ea_t, n : int) -> Tuple[List[int], int]
    2. get_stroff_path(path: tid_array, delta: sval_pointer, ea: ida_idaapi.ea_t, n : int) (backward-compatibility only)

@param ea address where the operand holds a path to a structure offset (1st form)
@param n operand number (1st form)
@return a tuple holding a (list_of_tid_t's, delta_within_the_last_type), or (None, None)"""
    val = _ida_bytes.get_stroff_path(*args)
    if isinstance(val, tuple):
        val = val[1], val[2]
    return val


def register_custom_data_type(dt):
    """Registers a custom data type.

@param dt: an instance of the data_type_t class
@return:
    < 0 if failed to register
    > 0 data type id"""
    return _ida_bytes.register_custom_data_type(dt)


def unregister_custom_data_type(dtid):
    """Unregisters a custom data type.

@param dtid: the data type id
@return: Boolean"""
    return _ida_bytes.unregister_custom_data_type(dtid)


def register_custom_data_format(df):
    """Registers a custom data format with a given data type.

@param df: an instance of data_format_t
@return:
    < 0 if failed to register
    > 0 data format id"""
    return _ida_bytes.register_custom_data_format(df)


def unregister_custom_data_format(dfid):
    """Unregisters a custom data format

@param dfid: data format id
@return: Boolean"""
    return _ida_bytes.unregister_custom_data_format(dfid)


def __to_bytevec(_in: 'bytevec_t const &') ->'bytevec_t':
    return _ida_bytes.__to_bytevec(_in)


DTP_NODUP = 1
"""do not use dup construct
"""


def __walk_types_and_formats(formats, type_action, format_action, installing):
    broken = False
    for f in formats:
        if len(f) == 1:
            if not format_action(f[0], 0):
                broken = True
                break
        else:
            dt = f[0]
            dfs = f[1:]
            if installing and not type_action(dt):
                broken = True
                break
            for df in dfs:
                if not format_action(df, dt.id):
                    broken = True
                    break
            if not installing and not type_action(dt):
                broken = True
                break
    return not broken


def register_data_types_and_formats(formats):
    """
    Registers multiple data types and formats at once.
    To register one type/format at a time use register_custom_data_type/register_custom_data_format

    It employs a special table of types and formats described below:

    The 'formats' is a list of tuples. If a tuple has one element then it is the format to be registered with dtid=0
    If the tuple has more than one element, then tuple[0] is the data type and tuple[1:] are the data formats. For example:
    many_formats = [
      (pascal_data_type(), pascal_data_format()),
      (simplevm_data_type(), simplevm_data_format()),
      (makedword_data_format(),),
      (simplevm_data_format(),)
    ]
    The first two tuples describe data types and their associated formats.
    The last two tuples describe two data formats to be used with built-in data types.
    The data format may be attached to several data types. The id of the
    data format is stored in the first data_format_t object. For example:
    assert many_formats[1][1] != -1
    assert many_formats[2][0] != -1
    assert many_formats[3][0] == -1
    """

    def __reg_format(df, dtid):
        dfid = register_custom_data_format(df)
        if dfid == -1:
            dfid = find_custom_data_format(df.name)
            if dfid == -1:
                return False
        attach_custom_data_format(dtid, dfid)
        if dtid == 0:
            print("Registered format '%s' with built-in types, ID=%d" % (df
                .name, dfid))
        else:
            print("   Registered format '%s', ID=%d (dtid=%d)" % (df.name,
                dfid, dtid))
        return True

    def __reg_type(dt):
        register_custom_data_type(dt)
        print("Registered type '%s', ID=%d" % (dt.name, dt.id))
        return dt.id != -1
    ok = __walk_types_and_formats(formats, __reg_type, __reg_format, True)
    return 1 if ok else -1


def unregister_data_types_and_formats(formats):
    """
    As opposed to register_data_types_and_formats(), this function
    unregisters multiple data types and formats at once.
    """

    def __unreg_format(df, dtid):
        print("%snregistering format '%s'" % ('U' if dtid == 0 else '   u',
            df.name))
        unregister_custom_data_format(df.id)
        return True

    def __unreg_type(dt):
        print("Unregistering type '%s', ID=%d" % (dt.name, dt.id))
        unregister_custom_data_type(dt.id)
        return True
    ok = __walk_types_and_formats(formats, __unreg_type, __unreg_format, False)
    return 1 if ok else -1


import typing
import ida_idaapi
import ida_nalt
import ida_range


def find_bytes(bs: typing.Union[bytes, bytearray, str], range_start: int,
    range_size: typing.Optional[int]=None, range_end: typing.Optional[int]=
    ida_idaapi.BADADDR, mask: typing.Optional[typing.Union[bytes, bytearray
    ]]=None, flags: typing.Optional[int]=BIN_SEARCH_FORWARD |
    BIN_SEARCH_NOSHOW, radix: typing.Optional[int]=16, strlit_encoding:
    typing.Optional[typing.Union[int, str]]=PBSENC_DEF1BPU) ->int:
    if isinstance(range_start, ida_range.range_t):
        range_start, range_end = range_start.start_ea, range_start.end_ea
    patterns = compiled_binpat_vec_t()
    if isinstance(bs, str):
        if isinstance(strlit_encoding, str):
            strlit_encoding_i = ida_nalt.add_encoding(strlit_encoding)
            if strlit_encoding_i > 0:
                strlit_encoding = strlit_encoding_i
            else:
                raise Exception('Unknown encoding: "%s"' % strlit_encoding)
        parse_result = parse_binpat_str(patterns, range_start, bs, radix,
            strlit_encoding)
        if parse_result is False or isinstance(parse_result, str) and len(
            parse_result) > 0:
            raise Exception('Could not parse pattern: %s' % (parse_result or
                'unknown error',))
    else:
        p0 = patterns.push_back()
        p0.bytes = __to_bytevec(bs)
        if mask is not None:
            p0.mask = __to_bytevec(mask)
    if range_size is not None:
        range_end = range_start + range_size
    ea, _ = bin_search(range_start, range_end, patterns, flags)
    return ea


def find_string(_str: str, range_start: int, range_end: typing.Optional[int
    ]=ida_idaapi.BADADDR, range_size: typing.Optional[int]=None,
    strlit_encoding: typing.Optional[typing.Union[int, str]]=PBSENC_DEF1BPU,
    flags: typing.Optional[int]=BIN_SEARCH_FORWARD | BIN_SEARCH_NOSHOW) ->int:
    escaped = _str.replace('"', '\\22')
    return find_bytes('"' + escaped + '"', range_start, range_end=range_end,
        range_size=range_size, flags=flags, strlit_encoding=strlit_encoding)

```
