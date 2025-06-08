```python
"""System independent counterparts of FILE* related functions from Clib.

You should not use C standard I/O functions in your modules. The reason: Each module compiled with Borland (and statically linked to Borland's library) will host a copy of the FILE * information.
So, if you open a file in the plugin and pass the handle to the kernel, the kernel will not be able to use it.
If you really need to use the standard functions, define USE_STANDARD_FILE_FUNCTIONS. In this case do not mix them with q... functions. 
    """
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_fpro
else:
    import _ida_fpro
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
SWIG_PYTHON_LEGACY_BOOL = _ida_fpro.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi


class qfile_t(object):
    """A helper class to work with FILE related functions."""
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    __idc_cvt_id__: 'int' = property(_ida_fpro.qfile_t___idc_cvt_id___get,
        _ida_fpro.qfile_t___idc_cvt_id___set)

    def __init__(self, *args):
        _ida_fpro.qfile_t_swiginit(self, _ida_fpro.new_qfile_t(*args))

    def opened(self):
        """Checks if the file is opened or not"""
        return _ida_fpro.qfile_t_opened(self)

    def close(self):
        """Closes the file"""
        return _ida_fpro.qfile_t_close(self)
    __swig_destroy__ = _ida_fpro.delete_qfile_t

    def open(self, filename, mode):
        """Opens a file

@param filename: the file name
@param mode: The mode string, ala fopen() style
@return: Boolean"""
        return _ida_fpro.qfile_t_open(self, filename, mode)

    @staticmethod
    def from_fp(fp: 'FILE *') ->'qfile_t *':
        return _ida_fpro.qfile_t_from_fp(fp)

    @staticmethod
    def from_capsule(pycapsule: 'PyObject *') ->'qfile_t *':
        return _ida_fpro.qfile_t_from_capsule(pycapsule)

    @staticmethod
    def tmpfile():
        """A static method to construct an instance using a temporary file"""
        return _ida_fpro.qfile_t_tmpfile()

    def get_fp(self) ->'FILE *':
        return _ida_fpro.qfile_t_get_fp(self)

    def seek(self, offset, whence=ida_idaapi.SEEK_SET):
        """Set input source position

@param offset: the seek offset
@param whence: the position to seek from
@return: the new position (not 0 as fseek!)"""
        return _ida_fpro.qfile_t_seek(self, offset, whence)

    def tell(self):
        """Returns the current position"""
        return _ida_fpro.qfile_t_tell(self)

    def readbytes(self, size, big_endian):
        """Similar to read() but it respect the endianness

@param size: the maximum number of bytes to read
@param big_endian: endianness
@return a str, or None"""
        return _ida_fpro.qfile_t_readbytes(self, size, big_endian)

    def read(self, size):
        """Reads from the file. Returns the buffer or None

@param size: the maximum number of bytes to read
@return: a str, or None"""
        return _ida_fpro.qfile_t_read(self, size)

    def gets(self, len):
        """Reads a line from the input file. Returns the read line or None

@param len: the maximum line length"""
        return _ida_fpro.qfile_t_gets(self, size)

    def writebytes(self, size, big_endian):
        """Similar to write() but it respect the endianness

@param buf: the str to write
@param big_endian: endianness
@return: result code"""
        return _ida_fpro.qfile_t_writebytes(self, py_buf, big_endian)

    def write(self, buf):
        """Writes to the file. Returns 0 or the number of bytes written

@param buf: the str to write
@return: result code"""
        return _ida_fpro.qfile_t_write(self, py_buf)

    def puts(self, str: str) ->int:
        return _ida_fpro.qfile_t_puts(self, str)

    def size(self) ->'int64':
        return _ida_fpro.qfile_t_size(self)

    def flush(self):
        return _ida_fpro.qfile_t_flush(self)

    def filename(self) ->'PyObject *':
        return _ida_fpro.qfile_t_filename(self)

    def get_byte(self):
        """Reads a single byte from the file. Returns None if EOF or the read byte"""
        return _ida_fpro.qfile_t_get_byte(self)

    def put_byte(self):
        """Writes a single byte to the file

@param chr: the byte value"""
        return _ida_fpro.qfile_t_put_byte(self, chr)


_ida_fpro.qfile_t_swigregister(qfile_t)


def qfclose(fp: 'FILE *') ->int:
    return _ida_fpro.qfclose(fp)


QMOVE_CROSS_FS = _ida_fpro.QMOVE_CROSS_FS
QMOVE_OVERWRITE = _ida_fpro.QMOVE_OVERWRITE
QMOVE_OVR_RO = _ida_fpro.QMOVE_OVR_RO
qfile_t_from_fp = qfile_t.from_fp
qfile_t_from_capsule = qfile_t.from_capsule
qfile_t_tmpfile = qfile_t.tmpfile

```
