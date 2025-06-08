```python
"""File I/O functions for IDA.

You should not use standard C file I/O functions in modules. Use functions from this header, pro.h and fpro.h instead.
This file also declares a call_system() function. 
    """
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_diskio
else:
    import _ida_diskio
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
SWIG_PYTHON_LEGACY_BOOL = _ida_diskio.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi
VAULT_CACHE_SUBDIR = _ida_diskio.VAULT_CACHE_SUBDIR
"""subdir name for cached deltas and old files
"""
VAULT_CACHE_FNAME = _ida_diskio.VAULT_CACHE_FNAME
"""to store file caches
"""


def idadir(subdir: str) ->str:
    """Get IDA directory (if subdir==nullptr) or the specified subdirectory (see IDA subdirectories) 
        """
    return _ida_diskio.idadir(subdir)


def getsysfile(filename: str, subdir: str) ->str:
    """Search for IDA system file. This function searches for a file in:
0. each directory specified by IDAUSR%
1. ida directory [+ subdir]


and returns the first match. 
        
@param filename: name of file to search
@param subdir: if specified, the file is looked for in the specified subdirectory of the ida directory first (see IDA subdirectories)
@returns nullptr if not found, otherwise a pointer to full file name."""
    return _ida_diskio.getsysfile(filename, subdir)


CFG_SUBDIR = _ida_diskio.CFG_SUBDIR
IDC_SUBDIR = _ida_diskio.IDC_SUBDIR
IDS_SUBDIR = _ida_diskio.IDS_SUBDIR
IDP_SUBDIR = _ida_diskio.IDP_SUBDIR
LDR_SUBDIR = _ida_diskio.LDR_SUBDIR
SIG_SUBDIR = _ida_diskio.SIG_SUBDIR
TIL_SUBDIR = _ida_diskio.TIL_SUBDIR
PLG_SUBDIR = _ida_diskio.PLG_SUBDIR
THM_SUBDIR = _ida_diskio.THM_SUBDIR


def get_user_idadir() ->str:
    """Get user ida related directory. 
     if $IDAUSR is defined:
        - the first element in $IDAUSR
     else
        - default user directory ($HOME/.idapro or %APPDATA%Hex-Rays/IDA Pro)


        """
    return _ida_diskio.get_user_idadir()


def get_ida_subdirs(subdir: str, flags: int=0) ->'qstrvec_t *':
    """Get list of directories in which to find a specific IDA resource (see IDA subdirectories). The order of the resulting list is as follows: 
     [$IDAUSR/subdir (0..N entries)]
     $IDADIR/subdir


        
@param subdir: name of the resource to list (can be nullptr)
@param flags: Subdirectory modification flags bits
@returns number of directories appended to 'dirs'"""
    return _ida_diskio.get_ida_subdirs(subdir, flags)


IDA_SUBDIR_IDP = _ida_diskio.IDA_SUBDIR_IDP
"""append the processor name as a subdirectory
"""
IDA_SUBDIR_IDADIR_FIRST = _ida_diskio.IDA_SUBDIR_IDADIR_FIRST
"""$IDADIR/subdir will be first, not last
"""
IDA_SUBDIR_ONLY_EXISTING = _ida_diskio.IDA_SUBDIR_ONLY_EXISTING
"""only existing directories will be present
"""


def get_special_folder(csidl: int) ->str:
    """Get a folder location by CSIDL (see Common CSIDLs). Path should be of at least MAX_PATH size 
        """
    return _ida_diskio.get_special_folder(csidl)


CSIDL_APPDATA = _ida_diskio.CSIDL_APPDATA
CSIDL_LOCAL_APPDATA = _ida_diskio.CSIDL_LOCAL_APPDATA
CSIDL_PROGRAM_FILES = _ida_diskio.CSIDL_PROGRAM_FILES
CSIDL_PROGRAM_FILES_COMMON = _ida_diskio.CSIDL_PROGRAM_FILES_COMMON
CSIDL_PROGRAM_FILESX86 = _ida_diskio.CSIDL_PROGRAM_FILESX86


class file_enumerator_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def visit_file(self, file: str) ->int:
        return _ida_diskio.file_enumerator_t_visit_file(self, file)
    __swig_destroy__ = _ida_diskio.delete_file_enumerator_t

    def __init__(self):
        if self.__class__ == file_enumerator_t:
            _self = None
        else:
            _self = self
        _ida_diskio.file_enumerator_t_swiginit(self, _ida_diskio.
            new_file_enumerator_t(_self))

    def __disown__(self):
        self.this.disown()
        _ida_diskio.disown_file_enumerator_t(self)
        return weakref.proxy(self)


_ida_diskio.file_enumerator_t_swigregister(file_enumerator_t)


def fopenWT(file: str) ->'FILE *':
    return _ida_diskio.fopenWT(file)


def fopenWB(file: str) ->'FILE *':
    return _ida_diskio.fopenWB(file)


def fopenRT(file: str) ->'FILE *':
    return _ida_diskio.fopenRT(file)


def fopenRB(file: str) ->'FILE *':
    return _ida_diskio.fopenRB(file)


def fopenM(file: str) ->'FILE *':
    return _ida_diskio.fopenM(file)


def fopenA(file: str) ->'FILE *':
    return _ida_diskio.fopenA(file)


class ioports_fallback_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    __swig_destroy__ = _ida_diskio.delete_ioports_fallback_t

    def handle(self, ports: 'ioports_t const &', line: str) ->bool:
        """@param ports: i/o port definitions
@param line: input line to parse
@returns success or fills ERRBUF with an error message"""
        return _ida_diskio.ioports_fallback_t_handle(self, ports, line)

    def __init__(self):
        if self.__class__ == ioports_fallback_t:
            _self = None
        else:
            _self = self
        _ida_diskio.ioports_fallback_t_swiginit(self, _ida_diskio.
            new_ioports_fallback_t(_self))

    def __disown__(self):
        self.this.disown()
        _ida_diskio.disown_ioports_fallback_t(self)
        return weakref.proxy(self)


_ida_diskio.ioports_fallback_t_swigregister(ioports_fallback_t)


def read_ioports(ports: 'ioports_t *', device: str, file: str, callback:
    'ioports_fallback_t'=None) ->'ssize_t':
    return _ida_diskio.read_ioports(ports, device, file, callback)


class choose_ioport_parser_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    __swig_destroy__ = _ida_diskio.delete_choose_ioport_parser_t

    def parse(self, param: str, line: str) ->bool:
        """@retval true: and fill PARAM with a displayed string
@retval false: and empty PARAM to skip the current device
@retval false: and fill PARAM with an error message"""
        return _ida_diskio.choose_ioport_parser_t_parse(self, param, line)

    def __init__(self):
        if self.__class__ == choose_ioport_parser_t:
            _self = None
        else:
            _self = self
        _ida_diskio.choose_ioport_parser_t_swiginit(self, _ida_diskio.
            new_choose_ioport_parser_t(_self))

    def __disown__(self):
        self.this.disown()
        _ida_diskio.disown_choose_ioport_parser_t(self)
        return weakref.proxy(self)


_ida_diskio.choose_ioport_parser_t_swigregister(choose_ioport_parser_t)


def choose_ioport_device2(_device: str, file: str, parse_params:
    'choose_ioport_parser_t') ->bool:
    return _ida_diskio.choose_ioport_device2(_device, file, parse_params)


LINPUT_NONE = _ida_diskio.LINPUT_NONE
LINPUT_LOCAL = _ida_diskio.LINPUT_LOCAL
LINPUT_RFILE = _ida_diskio.LINPUT_RFILE
LINPUT_PROCMEM = _ida_diskio.LINPUT_PROCMEM
LINPUT_GENERIC = _ida_diskio.LINPUT_GENERIC


def qlgetz(li: 'linput_t *', fpos: 'int64') ->str:
    return _ida_diskio.qlgetz(li, fpos)


def open_linput(file: str, remote: bool) ->'linput_t *':
    return _ida_diskio.open_linput(file, remote)


class generic_linput_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')

    def __init__(self, *args, **kwargs):
        raise AttributeError('No constructor defined - class is abstract')
    __repr__ = _swig_repr
    filesize: 'uint64' = property(_ida_diskio.generic_linput_t_filesize_get,
        _ida_diskio.generic_linput_t_filesize_set)
    blocksize: 'uint32' = property(_ida_diskio.
        generic_linput_t_blocksize_get, _ida_diskio.
        generic_linput_t_blocksize_set)

    def read(self, off: 'qoff64_t', buffer: 'void *', nbytes: 'size_t'
        ) ->'ssize_t':
        return _ida_diskio.generic_linput_t_read(self, off, buffer, nbytes)
    __swig_destroy__ = _ida_diskio.delete_generic_linput_t


_ida_diskio.generic_linput_t_swigregister(generic_linput_t)


def create_generic_linput(gl: 'generic_linput_t') ->'linput_t *':
    return _ida_diskio.create_generic_linput(gl)


def create_memory_linput(start: ida_idaapi.ea_t, size: 'asize_t'
    ) ->'linput_t *':
    return _ida_diskio.create_memory_linput(start, size)


def get_linput_type(li: 'linput_t *') ->'linput_type_t':
    return _ida_diskio.get_linput_type(li)


LOC_CLOSE = _ida_diskio.LOC_CLOSE
"""close the inner linput
"""
LOC_UNMAKE = _ida_diskio.LOC_UNMAKE
"""unmake the inner linput
"""
LOC_KEEP = _ida_diskio.LOC_KEEP
"""do nothing
"""


def enumerate_files(path, fname, callback):
    """Enumerate files in the specified directory while the callback returns 0.

@param path: directory to enumerate files in
@param fname: mask of file names to enumerate
@param callback: a callable object that takes the filename as
                 its first argument and it returns 0 to continue
                 enumeration or non-zero to stop enumeration.
@return:
    None in case of script errors
    tuple(code, fname) : If the callback returns non-zero"""
    return _ida_diskio.enumerate_files(path, fname, callback)


def create_bytearray_linput(s: str) ->'linput_t *':
    return _ida_diskio.create_bytearray_linput(s)


def close_linput(li: 'linput_t *') ->None:
    return _ida_diskio.close_linput(li)

```
