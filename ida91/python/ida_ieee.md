```python
"""IEEE floating point functions.
"""
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_ieee
else:
    import _ida_ieee
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
SWIG_PYTHON_LEGACY_BOOL = _ida_ieee.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi


class fpvalue_shorts_array_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    data: 'unsigned short (&)[FPVAL_NWORDS]' = property(_ida_ieee.
        fpvalue_shorts_array_t_data_get)

    def __init__(self, data: 'unsigned short (&)[FPVAL_NWORDS]'):
        _ida_ieee.fpvalue_shorts_array_t_swiginit(self, _ida_ieee.
            new_fpvalue_shorts_array_t(data))

    def __len__(self) ->'size_t':
        return _ida_ieee.fpvalue_shorts_array_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'unsigned short const &':
        return _ida_ieee.fpvalue_shorts_array_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'unsigned short const &') ->None:
        return _ida_ieee.fpvalue_shorts_array_t___setitem__(self, i, v)

    def _get_bytes(self) ->'bytevec_t':
        return _ida_ieee.fpvalue_shorts_array_t__get_bytes(self)

    def _set_bytes(self, bts: 'bytevec_t const &') ->None:
        return _ida_ieee.fpvalue_shorts_array_t__set_bytes(self, bts)
    __iter__ = ida_idaapi._bounded_getitem_iterator
    bytes = property(_get_bytes, _set_bytes)
    __swig_destroy__ = _ida_ieee.delete_fpvalue_shorts_array_t


_ida_ieee.fpvalue_shorts_array_t_swigregister(fpvalue_shorts_array_t)
FPVAL_NWORDS = _ida_ieee.FPVAL_NWORDS
"""number of words in fpvalue_t
"""
FPV_BADARG = _ida_ieee.FPV_BADARG
"""wrong value of max_exp
"""
FPV_NORM = _ida_ieee.FPV_NORM
"""regular value
"""
FPV_NAN = _ida_ieee.FPV_NAN
"""NaN.
"""
FPV_PINF = _ida_ieee.FPV_PINF
"""positive infinity
"""
FPV_NINF = _ida_ieee.FPV_NINF
"""negative infinity
"""
REAL_ERROR_OK = _ida_ieee.REAL_ERROR_OK
"""no error
"""
REAL_ERROR_FORMAT = _ida_ieee.REAL_ERROR_FORMAT
"""realcvt: not supported format for current .idp
"""
REAL_ERROR_RANGE = _ida_ieee.REAL_ERROR_RANGE
"""realcvt: number too big (small) for store (mem NOT modified)
"""
REAL_ERROR_BADDATA = _ida_ieee.REAL_ERROR_BADDATA
"""realcvt: illegal real data for load (IEEE data not filled)
"""
REAL_ERROR_FPOVER = _ida_ieee.REAL_ERROR_FPOVER
"""floating overflow or underflow
"""
REAL_ERROR_BADSTR = _ida_ieee.REAL_ERROR_BADSTR
"""asctoreal: illegal input string
"""
REAL_ERROR_ZERODIV = _ida_ieee.REAL_ERROR_ZERODIV
"""ediv: divide by 0
"""
REAL_ERROR_INTOVER = _ida_ieee.REAL_ERROR_INTOVER
"""eetol*: integer overflow
"""


class fpvalue_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    w: 'uint16 [8]' = property(_ida_ieee.fpvalue_t_w_get, _ida_ieee.
        fpvalue_t_w_set)

    def clear(self) ->None:
        return _ida_ieee.fpvalue_t_clear(self)

    def __eq__(self, r: 'fpvalue_t') ->bool:
        return _ida_ieee.fpvalue_t___eq__(self, r)

    def __ne__(self, r: 'fpvalue_t') ->bool:
        return _ida_ieee.fpvalue_t___ne__(self, r)

    def __lt__(self, r: 'fpvalue_t') ->bool:
        return _ida_ieee.fpvalue_t___lt__(self, r)

    def __gt__(self, r: 'fpvalue_t') ->bool:
        return _ida_ieee.fpvalue_t___gt__(self, r)

    def __le__(self, r: 'fpvalue_t') ->bool:
        return _ida_ieee.fpvalue_t___le__(self, r)

    def __ge__(self, r: 'fpvalue_t') ->bool:
        return _ida_ieee.fpvalue_t___ge__(self, r)

    def compare(self, r: 'fpvalue_t') ->int:
        return _ida_ieee.fpvalue_t_compare(self, r)

    def from_10bytes(self, fpval: 'void const *') ->'fpvalue_error_t':
        """Conversions for 10-byte floating point values.
"""
        return _ida_ieee.fpvalue_t_from_10bytes(self, fpval)

    def to_10bytes(self, fpval: 'void *') ->'fpvalue_error_t':
        return _ida_ieee.fpvalue_t_to_10bytes(self, fpval)

    def from_12bytes(self, fpval: 'void const *') ->'fpvalue_error_t':
        """Conversions for 12-byte floating point values.
"""
        return _ida_ieee.fpvalue_t_from_12bytes(self, fpval)

    def to_12bytes(self, fpval: 'void *') ->'fpvalue_error_t':
        return _ida_ieee.fpvalue_t_to_12bytes(self, fpval)

    def to_str(self, *args) ->None:
        """Convert IEEE to string. 
        
@param buf: the output buffer
@param bufsize: the size of the output buffer
@param mode: broken down into:
* low byte: number of digits after '.'
* second byte: FPNUM_LENGTH
* third byte: FPNUM_DIGITS"""
        return _ida_ieee.fpvalue_t_to_str(self, *args)

    def from_sval(self, x: int) ->None:
        """Convert integer to IEEE.
"""
        return _ida_ieee.fpvalue_t_from_sval(self, x)

    def from_int64(self, x: 'int64') ->None:
        return _ida_ieee.fpvalue_t_from_int64(self, x)

    def from_uint64(self, x: 'uint64') ->None:
        return _ida_ieee.fpvalue_t_from_uint64(self, x)

    def to_sval(self, round: bool=False) ->'fpvalue_error_t':
        """Convert IEEE to integer (+-0.5 if round)
"""
        return _ida_ieee.fpvalue_t_to_sval(self, round)

    def to_int64(self, round: bool=False) ->'fpvalue_error_t':
        return _ida_ieee.fpvalue_t_to_int64(self, round)

    def to_uint64(self, round: bool=False) ->'fpvalue_error_t':
        return _ida_ieee.fpvalue_t_to_uint64(self, round)

    def fadd(self, y: 'fpvalue_t') ->'fpvalue_error_t':
        """Arithmetic operations.
"""
        return _ida_ieee.fpvalue_t_fadd(self, y)

    def fsub(self, y: 'fpvalue_t') ->'fpvalue_error_t':
        return _ida_ieee.fpvalue_t_fsub(self, y)

    def fmul(self, y: 'fpvalue_t') ->'fpvalue_error_t':
        return _ida_ieee.fpvalue_t_fmul(self, y)

    def fdiv(self, y: 'fpvalue_t') ->'fpvalue_error_t':
        return _ida_ieee.fpvalue_t_fdiv(self, y)

    def mul_pow2(self, power_of_2: int) ->'fpvalue_error_t':
        """Multiply by a power of 2.
"""
        return _ida_ieee.fpvalue_t_mul_pow2(self, power_of_2)

    def eabs(self) ->None:
        """Calculate absolute value.
"""
        return _ida_ieee.fpvalue_t_eabs(self)

    def is_negative(self) ->bool:
        """Is negative value?
"""
        return _ida_ieee.fpvalue_t_is_negative(self)

    def negate(self) ->None:
        """Negate.
"""
        return _ida_ieee.fpvalue_t_negate(self)

    def get_kind(self) ->'fpvalue_kind_t':
        """Get value kind.
"""
        return _ida_ieee.fpvalue_t_get_kind(self)

    def __init__(self, *args):
        _ida_ieee.fpvalue_t_swiginit(self, _ida_ieee.new_fpvalue_t(*args))

    def _get_bytes(self) ->None:
        return _ida_ieee.fpvalue_t__get_bytes(self)

    def _set_bytes(self, _in: 'bytevec16_t const &') ->None:
        return _ida_ieee.fpvalue_t__set_bytes(self, _in)

    def _get_float(self) ->'double':
        return _ida_ieee.fpvalue_t__get_float(self)

    def _set_float(self, v: 'double') ->None:
        return _ida_ieee.fpvalue_t__set_float(self, v)

    def copy(self) ->'fpvalue_t':
        return _ida_ieee.fpvalue_t_copy(self)

    def __str__(self) ->str:
        return _ida_ieee.fpvalue_t___str__(self)

    def _get_shorts(self) ->'wrapped_array_t< uint16,FPVAL_NWORDS >':
        return _ida_ieee.fpvalue_t__get_shorts(self)

    @staticmethod
    def new_from_str(p: str) ->'fpvalue_t':
        return _ida_ieee.fpvalue_t_new_from_str(p)

    def from_str(self, p: str) ->'fpvalue_error_t':
        """Convert string to IEEE. 
        """
        return _ida_ieee.fpvalue_t_from_str(self, p)

    def assign(self, r: 'fpvalue_t') ->None:
        return _ida_ieee.fpvalue_t_assign(self, r)
    bytes = property(_get_bytes, _set_bytes)
    shorts = property(_get_shorts)
    float = property(_get_float, _set_float)
    sval = property(lambda self: self.to_sval(), lambda self, v: self.
        from_sval(v))
    int64 = property(lambda self: self.to_int64(), lambda self, v: self.
        from_int64(v))
    uint64 = property(lambda self: self.to_uint64(), lambda self, v: self.
        from_uint64(v))

    def __iter__(self):
        shorts = self.shorts
        for one in shorts:
            yield one

    def __getitem__(self, i):
        return self.shorts[i]

    def __setitem__(self, i, v):
        self.shorts[i] = v

    def __repr__(self):
        return (
            f"{self.__class__.__module__}.{self.__class__.__name__}.new_from_str('{str(self)}')"
            )

    def __add__(self, o: 'fpvalue_t') ->'fpvalue_t':
        return _ida_ieee.fpvalue_t___add__(self, o)

    def __sub__(self, o: 'fpvalue_t') ->'fpvalue_t':
        return _ida_ieee.fpvalue_t___sub__(self, o)

    def __mul__(self, o: 'fpvalue_t') ->'fpvalue_t':
        return _ida_ieee.fpvalue_t___mul__(self, o)

    def __truediv__(self, o: 'fpvalue_t') ->'fpvalue_t':
        return _ida_ieee.fpvalue_t___truediv__(self, o)
    __swig_destroy__ = _ida_ieee.delete_fpvalue_t


_ida_ieee.fpvalue_t_swigregister(fpvalue_t)
cvar = _ida_ieee.cvar
MAXEXP_FLOAT = cvar.MAXEXP_FLOAT
MAXEXP_DOUBLE = cvar.MAXEXP_DOUBLE
MAXEXP_LNGDBL = cvar.MAXEXP_LNGDBL
IEEE_EXONE = _ida_ieee.IEEE_EXONE
"""The exponent of 1.0.
"""
E_SPECIAL_EXP = _ida_ieee.E_SPECIAL_EXP
"""Exponent in fpvalue_t for NaN and Inf.
"""
IEEE_NI = _ida_ieee.IEEE_NI
"""Number of 16 bit words in eNI.
"""
IEEE_E = _ida_ieee.IEEE_E
"""Array offset to exponent.
"""
IEEE_M = _ida_ieee.IEEE_M
"""Array offset to high guard word 
        """


def ecleaz(x: 'eNI') ->None:
    return _ida_ieee.ecleaz(x)


EZERO = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
EONE = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\xff?'
ETWO = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00@'

```
