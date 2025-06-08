```python
"""This is the first header included in the IDA project.

It defines the most common types, functions and data. Also, it tries to make system dependent definitions.
The following preprocessor macros are used in the project (the list may be incomplete)
Platform must be specified as one of:
__NT__ - MS Windows (all platforms) 
 __LINUX__ - Linux 
 __MAC__ - MAC OS X
__EA64__ - 64-bit address size (sizeof(ea_t)==8) 
 __X86__ - 32-bit debug servers (sizeof(void*)==4) 
 __X64__ - x64 processor (sizeof(void*)==8) default 
 __PPC__ - PowerPC 
 __ARM__ - ARM 
    """
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_pro
else:
    import _ida_pro
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
SWIG_PYTHON_LEGACY_BOOL = _ida_pro.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi
BADDIFF = _ida_pro.BADDIFF
IDA_SDK_VERSION = _ida_pro.IDA_SDK_VERSION
"""IDA SDK v9.1.
"""
BADMEMSIZE = _ida_pro.BADMEMSIZE
_CRT_DECLARE_NONSTDC_NAMES = _ida_pro._CRT_DECLARE_NONSTDC_NAMES
MAXSTR = _ida_pro.MAXSTR
"""maximum string size
"""
__MF__ = _ida_pro.__MF__
"""byte sex of our platform (Most significant byte First). 0: little endian (Intel 80x86). 1: big endian (PowerPC). 
        """


def qatoll(nptr: str) ->'int64':
    return _ida_pro.qatoll(nptr)


FMT_64 = _ida_pro.FMT_64
FMT_Z = _ida_pro.FMT_Z
FMT_ZX = _ida_pro.FMT_ZX
FMT_ZS = _ida_pro.FMT_ZS
FMT_EA = _ida_pro.FMT_EA


def qexit(code: int) ->None:
    """Call qatexit functions, shut down UI and kernel, and exit. 
        
@param code: exit code"""
    return _ida_pro.qexit(code)


def log2ceil(d64: 'uint64') ->int:
    """calculate ceil(log2(d64)) or floor(log2(d64)), it returns 0 if d64 == 0 
        """
    return _ida_pro.log2ceil(d64)


def log2floor(d64: 'uint64') ->int:
    return _ida_pro.log2floor(d64)


def extend_sign(v: 'uint64', nbytes: int, sign_extend: bool) ->'uint64':
    """Sign-, or zero-extend the value 'v' to occupy 64 bits. The value 'v' is considered to be of size 'nbytes'. 
        """
    return _ida_pro.extend_sign(v, nbytes, sign_extend)


def readbytes(h: int, res: 'uint32 *', size: int, mf: bool) ->int:
    """Read at most 4 bytes from file. 
        
@param h: file handle
@param res: value read from file
@param size: size of value in bytes (1,2,4)
@param mf: is MSB first?
@returns 0 on success, nonzero otherwise"""
    return _ida_pro.readbytes(h, res, size, mf)


def writebytes(h: int, l: int, size: int, mf: bool) ->int:
    """Write at most 4 bytes to file. 
        
@param h: file handle
@param l: value to write
@param size: size of value in bytes (1,2,4)
@param mf: is MSB first?
@returns 0 on success, nonzero otherwise"""
    return _ida_pro.writebytes(h, l, size, mf)


def reloc_value(value: 'void *', size: int, delta: 'adiff_t', mf: bool) ->None:
    return _ida_pro.reloc_value(value, size, delta, mf)


def qvector_reserve(vec: 'void *', old: 'void *', cnt: 'size_t', elsize:
    'size_t') ->'void *':
    """Change capacity of given qvector. 
        
@param vec: a pointer to a qvector
@param old: a pointer to the qvector's array
@param cnt: number of elements to reserve
@param elsize: size of each element
@returns a pointer to the newly allocated array"""
    return _ida_pro.qvector_reserve(vec, old, cnt, elsize)


class qrefcnt_obj_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')

    def __init__(self, *args, **kwargs):
        raise AttributeError('No constructor defined - class is abstract')
    __repr__ = _swig_repr
    refcnt: 'int' = property(_ida_pro.qrefcnt_obj_t_refcnt_get, _ida_pro.
        qrefcnt_obj_t_refcnt_set)
    """counter 
        """

    def release(self) ->None:
        """Call destructor. We use release() instead of operator delete() to maintain binary compatibility with all compilers (vc and gcc use different vtable layouts for operator delete) 
        """
        return _ida_pro.qrefcnt_obj_t_release(self)
    __swig_destroy__ = _ida_pro.delete_qrefcnt_obj_t


_ida_pro.qrefcnt_obj_t_swigregister(qrefcnt_obj_t)


def relocate_relobj(_relobj: 'relobj_t *', ea: ida_idaapi.ea_t, mf: bool
    ) ->bool:
    return _ida_pro.relocate_relobj(_relobj, ea, mf)


IDBDEC_ESCAPE = _ida_pro.IDBDEC_ESCAPE
"""convert non-printable characters to C escapes (
, \\xNN, \\uNNNN)
"""
CP_BOM = _ida_pro.CP_BOM
UTF8_BOM = _ida_pro.UTF8_BOM
UTF16LE_BOM = _ida_pro.UTF16LE_BOM
UTF16BE_BOM = _ida_pro.UTF16BE_BOM
UTF32LE_BOM = _ida_pro.UTF32LE_BOM
UTF32BE_BOM = _ida_pro.UTF32BE_BOM
CP_ELLIPSIS = _ida_pro.CP_ELLIPSIS
UTF8_ELLIPSIS = _ida_pro.UTF8_ELLIPSIS
CP_REPLCHAR = _ida_pro.CP_REPLCHAR
UTF8_REPLCHAR = _ida_pro.UTF8_REPLCHAR
MAX_UTF8_SEQ_LEN = _ida_pro.MAX_UTF8_SEQ_LEN


def is_cvt64() ->bool:
    """is IDA converting IDB into I64?
"""
    return _ida_pro.is_cvt64()


CEF_RETERR = _ida_pro.CEF_RETERR
ENC_WIN1252 = _ida_pro.ENC_WIN1252
ENC_UTF8 = _ida_pro.ENC_UTF8
ENC_MUTF8 = _ida_pro.ENC_MUTF8
ENC_UTF16 = _ida_pro.ENC_UTF16
ENC_UTF16LE = _ida_pro.ENC_UTF16LE
ENC_UTF16BE = _ida_pro.ENC_UTF16BE
ENC_UTF32 = _ida_pro.ENC_UTF32
ENC_UTF32LE = _ida_pro.ENC_UTF32LE
ENC_UTF32BE = _ida_pro.ENC_UTF32BE
CP_UTF8 = _ida_pro.CP_UTF8
CP_UTF16 = _ida_pro.CP_UTF16
"""UTF-16 codepage.
"""
SUBSTCHAR = _ida_pro.SUBSTCHAR
"""default char, used if a char cannot be represented in a codepage
"""


class channel_redir_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    fd: 'int' = property(_ida_pro.channel_redir_t_fd_get, _ida_pro.
        channel_redir_t_fd_set)
    """channel number
"""
    file: 'qstring' = property(_ida_pro.channel_redir_t_file_get, _ida_pro.
        channel_redir_t_file_set)
    """file name to redirect to/from. if empty, the channel must be closed. 
        """
    flags: 'int' = property(_ida_pro.channel_redir_t_flags_get, _ida_pro.
        channel_redir_t_flags_set)
    """i/o redirection flags 
        """

    def is_input(self) ->bool:
        return _ida_pro.channel_redir_t_is_input(self)

    def is_output(self) ->bool:
        return _ida_pro.channel_redir_t_is_output(self)

    def is_append(self) ->bool:
        return _ida_pro.channel_redir_t_is_append(self)

    def is_quoted(self) ->bool:
        return _ida_pro.channel_redir_t_is_quoted(self)
    start: 'int' = property(_ida_pro.channel_redir_t_start_get, _ida_pro.
        channel_redir_t_start_set)
    """begin of the redirection string in the command line
"""
    length: 'int' = property(_ida_pro.channel_redir_t_length_get, _ida_pro.
        channel_redir_t_length_set)
    """length of the redirection string in the command line
"""

    def __init__(self):
        _ida_pro.channel_redir_t_swiginit(self, _ida_pro.new_channel_redir_t())
    __swig_destroy__ = _ida_pro.delete_channel_redir_t


_ida_pro.channel_redir_t_swigregister(channel_redir_t)
IOREDIR_INPUT = _ida_pro.IOREDIR_INPUT
"""input redirection
"""
IOREDIR_OUTPUT = _ida_pro.IOREDIR_OUTPUT
"""output redirection
"""
IOREDIR_APPEND = _ida_pro.IOREDIR_APPEND
"""append, do not overwrite the output file
"""
IOREDIR_QUOTED = _ida_pro.IOREDIR_QUOTED
"""the file name was quoted
"""


def quote_cmdline_arg(arg: str) ->bool:
    """Quote a command line argument if it contains escape characters. For example, *.c will be converted into "*.c" because * may be inadvertently expanded by the shell 
        
@returns true: modified 'arg'"""
    return _ida_pro.quote_cmdline_arg(arg)


class plugin_options_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def find(self, name: str) ->'plugin_option_t const *':
        return _ida_pro.plugin_options_t_find(self, name)

    def erase(self, name: str) ->bool:
        return _ida_pro.plugin_options_t_erase(self, name)

    def __init__(self):
        _ida_pro.plugin_options_t_swiginit(self, _ida_pro.
            new_plugin_options_t())
    __swig_destroy__ = _ida_pro.delete_plugin_options_t


_ida_pro.plugin_options_t_swigregister(plugin_options_t)


class instant_dbgopts_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    debmod: 'qstring' = property(_ida_pro.instant_dbgopts_t_debmod_get,
        _ida_pro.instant_dbgopts_t_debmod_set)
    """name of debugger module
"""
    env: 'qstring' = property(_ida_pro.instant_dbgopts_t_env_get, _ida_pro.
        instant_dbgopts_t_env_set)
    """config variables for debmod. example: DEFAULT_CPU=13;MAXPACKETSIZE=-1
"""
    host: 'qstring' = property(_ida_pro.instant_dbgopts_t_host_get,
        _ida_pro.instant_dbgopts_t_host_set)
    """remote hostname (if remote debugging)
"""
    _pass: 'qstring' = property(_ida_pro.instant_dbgopts_t__pass_get,
        _ida_pro.instant_dbgopts_t__pass_set)
    port: 'int' = property(_ida_pro.instant_dbgopts_t_port_get, _ida_pro.
        instant_dbgopts_t_port_set)
    """port number for the remote debugger server
"""
    pid: 'int' = property(_ida_pro.instant_dbgopts_t_pid_get, _ida_pro.
        instant_dbgopts_t_pid_set)
    """process to attach to (-1: ask the user)
"""
    event_id: 'int' = property(_ida_pro.instant_dbgopts_t_event_id_get,
        _ida_pro.instant_dbgopts_t_event_id_set)
    """event to trigger upon attaching
"""
    attach: 'bool' = property(_ida_pro.instant_dbgopts_t_attach_get,
        _ida_pro.instant_dbgopts_t_attach_set)
    """should attach to a process?
"""

    def __init__(self):
        _ida_pro.instant_dbgopts_t_swiginit(self, _ida_pro.
            new_instant_dbgopts_t())
    __swig_destroy__ = _ida_pro.delete_instant_dbgopts_t


_ida_pro.instant_dbgopts_t_swigregister(instant_dbgopts_t)


def parse_dbgopts(ido: 'instant_dbgopts_t', r_switch: str) ->bool:
    """Parse the -r command line switch (for instant debugging). r_switch points to the value of the -r switch. Example: win32@localhost+ 
        
@returns true-ok, false-parse error"""
    return _ida_pro.parse_dbgopts(ido, r_switch)


QWCONTINUED = _ida_pro.QWCONTINUED
QWNOHANG = _ida_pro.QWNOHANG


def check_process_exit(handle: 'void *', exit_code: 'int *', msecs: int=-1
    ) ->int:
    """Check whether process has terminated or not. 
        
@param handle: process handle to wait for
@param exit_code: pointer to the buffer for the exit code
@retval 0: process has exited, and the exit code is available. if *exit_code < 0: the process was killed with a signal -*exit_code
@retval 1: process has not exited yet
@retval -1: error happened, see error code for winerr() in *exit_code"""
    return _ida_pro.check_process_exit(handle, exit_code, msecs)


TCT_UNKNOWN = _ida_pro.TCT_UNKNOWN
TCT_OWNER = _ida_pro.TCT_OWNER
TCT_NOT_OWNER = _ida_pro.TCT_NOT_OWNER


def is_control_tty(fd: int) ->'enum tty_control_t':
    """Check if the current process is the owner of the TTY specified by 'fd' (typically an opened descriptor to /dev/tty). 
        """
    return _ida_pro.is_control_tty(fd)


def qdetach_tty() ->None:
    """If the current terminal is the controlling terminal of the calling process, give up this controlling terminal. 
        """
    return _ida_pro.qdetach_tty()


def qcontrol_tty() ->None:
    """Make the current terminal the controlling terminal of the calling process. 
        """
    return _ida_pro.qcontrol_tty()


class __qthread_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.__qthread_t_swiginit(self, _ida_pro.new___qthread_t())
    __swig_destroy__ = _ida_pro.delete___qthread_t


_ida_pro.__qthread_t_swigregister(__qthread_t)


def qthread_equal(q1: '__qthread_t', q2: '__qthread_t') ->bool:
    """Are two threads equal?
"""
    return _ida_pro.qthread_equal(q1, q2)


def is_main_thread() ->bool:
    """Are we running in the main thread?
"""
    return _ida_pro.is_main_thread()


class __qsemaphore_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.__qsemaphore_t_swiginit(self, _ida_pro.new___qsemaphore_t())
    __swig_destroy__ = _ida_pro.delete___qsemaphore_t


_ida_pro.__qsemaphore_t_swigregister(__qsemaphore_t)


class __qmutex_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.__qmutex_t_swiginit(self, _ida_pro.new___qmutex_t())
    __swig_destroy__ = _ida_pro.delete___qmutex_t


_ida_pro.__qmutex_t_swigregister(__qmutex_t)


class qmutex_locker_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, _lock: '__qmutex_t'):
        _ida_pro.qmutex_locker_t_swiginit(self, _ida_pro.
            new_qmutex_locker_t(_lock))
    __swig_destroy__ = _ida_pro.delete_qmutex_locker_t


_ida_pro.qmutex_locker_t_swigregister(qmutex_locker_t)


def get_login_name() ->str:
    """Get the user name for the current desktop session 
        
@returns success"""
    return _ida_pro.get_login_name()


def get_physical_core_count() ->int:
    """Get the total CPU physical core count 
        
@returns the physical core count, or -1 on error"""
    return _ida_pro.get_physical_core_count()


def get_logical_core_count() ->int:
    """Get the total CPU logical core count 
        
@returns the logical core count, or -1 on error"""
    return _ida_pro.get_logical_core_count()


def get_available_core_count() ->int:
    """Get the number of logical CPU cores available to the current process if supported by the OS. 
        
@returns the logical core count available for the process, or -1 on error"""
    return _ida_pro.get_available_core_count()


class intvec_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_pro.intvec_t_swiginit(self, _ida_pro.new_intvec_t(*args))
    __swig_destroy__ = _ida_pro.delete_intvec_t

    def push_back(self, *args) ->'int &':
        return _ida_pro.intvec_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_pro.intvec_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_pro.intvec_t_size(self)

    def empty(self) ->bool:
        return _ida_pro.intvec_t_empty(self)

    def at(self, _idx: 'size_t') ->'int const &':
        return _ida_pro.intvec_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_pro.intvec_t_qclear(self)

    def clear(self) ->None:
        return _ida_pro.intvec_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_pro.intvec_t_resize(self, *args)

    def capacity(self) ->'size_t':
        return _ida_pro.intvec_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_pro.intvec_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_pro.intvec_t_truncate(self)

    def swap(self, r: 'intvec_t') ->None:
        return _ida_pro.intvec_t_swap(self, r)

    def extract(self) ->'int *':
        return _ida_pro.intvec_t_extract(self)

    def inject(self, s: 'int *', len: 'size_t') ->None:
        return _ida_pro.intvec_t_inject(self, s, len)

    def __eq__(self, r: 'intvec_t') ->bool:
        return _ida_pro.intvec_t___eq__(self, r)

    def __ne__(self, r: 'intvec_t') ->bool:
        return _ida_pro.intvec_t___ne__(self, r)

    def begin(self, *args) ->'qvector< int >::const_iterator':
        return _ida_pro.intvec_t_begin(self, *args)

    def end(self, *args) ->'qvector< int >::const_iterator':
        return _ida_pro.intvec_t_end(self, *args)

    def insert(self, it: 'qvector< int >::iterator', x: 'int const &'
        ) ->'qvector< int >::iterator':
        return _ida_pro.intvec_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< int >::iterator':
        return _ida_pro.intvec_t_erase(self, *args)

    def find(self, *args) ->'qvector< int >::const_iterator':
        return _ida_pro.intvec_t_find(self, *args)

    def has(self, x: 'int const &') ->bool:
        return _ida_pro.intvec_t_has(self, x)

    def add_unique(self, x: 'int const &') ->bool:
        return _ida_pro.intvec_t_add_unique(self, x)

    def _del(self, x: 'int const &') ->bool:
        return _ida_pro.intvec_t__del(self, x)

    def __len__(self) ->'size_t':
        return _ida_pro.intvec_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'int const &':
        return _ida_pro.intvec_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'int const &') ->None:
        return _ida_pro.intvec_t___setitem__(self, i, v)

    def append(self, x: 'int const &') ->None:
        return _ida_pro.intvec_t_append(self, x)

    def extend(self, x: 'intvec_t') ->None:
        return _ida_pro.intvec_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_pro.intvec_t_swigregister(intvec_t)
cvar = _ida_pro.cvar
NULL_PIPE_HANDLE = cvar.NULL_PIPE_HANDLE


class uintvec_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_pro.uintvec_t_swiginit(self, _ida_pro.new_uintvec_t(*args))
    __swig_destroy__ = _ida_pro.delete_uintvec_t

    def push_back(self, *args) ->'unsigned int &':
        return _ida_pro.uintvec_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_pro.uintvec_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_pro.uintvec_t_size(self)

    def empty(self) ->bool:
        return _ida_pro.uintvec_t_empty(self)

    def at(self, _idx: 'size_t') ->'unsigned int const &':
        return _ida_pro.uintvec_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_pro.uintvec_t_qclear(self)

    def clear(self) ->None:
        return _ida_pro.uintvec_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_pro.uintvec_t_resize(self, *args)

    def capacity(self) ->'size_t':
        return _ida_pro.uintvec_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_pro.uintvec_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_pro.uintvec_t_truncate(self)

    def swap(self, r: 'uintvec_t') ->None:
        return _ida_pro.uintvec_t_swap(self, r)

    def extract(self) ->'unsigned int *':
        return _ida_pro.uintvec_t_extract(self)

    def inject(self, s: 'unsigned int *', len: 'size_t') ->None:
        return _ida_pro.uintvec_t_inject(self, s, len)

    def __eq__(self, r: 'uintvec_t') ->bool:
        return _ida_pro.uintvec_t___eq__(self, r)

    def __ne__(self, r: 'uintvec_t') ->bool:
        return _ida_pro.uintvec_t___ne__(self, r)

    def begin(self, *args) ->'qvector< unsigned int >::const_iterator':
        return _ida_pro.uintvec_t_begin(self, *args)

    def end(self, *args) ->'qvector< unsigned int >::const_iterator':
        return _ida_pro.uintvec_t_end(self, *args)

    def insert(self, it: 'qvector< unsigned int >::iterator', x:
        'unsigned int const &') ->'qvector< unsigned int >::iterator':
        return _ida_pro.uintvec_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< unsigned int >::iterator':
        return _ida_pro.uintvec_t_erase(self, *args)

    def find(self, *args) ->'qvector< unsigned int >::const_iterator':
        return _ida_pro.uintvec_t_find(self, *args)

    def has(self, x: 'unsigned int const &') ->bool:
        return _ida_pro.uintvec_t_has(self, x)

    def add_unique(self, x: 'unsigned int const &') ->bool:
        return _ida_pro.uintvec_t_add_unique(self, x)

    def _del(self, x: 'unsigned int const &') ->bool:
        return _ida_pro.uintvec_t__del(self, x)

    def __len__(self) ->'size_t':
        return _ida_pro.uintvec_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'unsigned int const &':
        return _ida_pro.uintvec_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'unsigned int const &') ->None:
        return _ida_pro.uintvec_t___setitem__(self, i, v)

    def append(self, x: 'unsigned int const &') ->None:
        return _ida_pro.uintvec_t_append(self, x)

    def extend(self, x: 'uintvec_t') ->None:
        return _ida_pro.uintvec_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_pro.uintvec_t_swigregister(uintvec_t)


class int64vec_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_pro.int64vec_t_swiginit(self, _ida_pro.new_int64vec_t(*args))
    __swig_destroy__ = _ida_pro.delete_int64vec_t

    def push_back(self, *args) ->'long long &':
        return _ida_pro.int64vec_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_pro.int64vec_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_pro.int64vec_t_size(self)

    def empty(self) ->bool:
        return _ida_pro.int64vec_t_empty(self)

    def at(self, _idx: 'size_t') ->'long long const &':
        return _ida_pro.int64vec_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_pro.int64vec_t_qclear(self)

    def clear(self) ->None:
        return _ida_pro.int64vec_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_pro.int64vec_t_resize(self, *args)

    def capacity(self) ->'size_t':
        return _ida_pro.int64vec_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_pro.int64vec_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_pro.int64vec_t_truncate(self)

    def swap(self, r: 'int64vec_t') ->None:
        return _ida_pro.int64vec_t_swap(self, r)

    def extract(self) ->'long long *':
        return _ida_pro.int64vec_t_extract(self)

    def inject(self, s: 'long long *', len: 'size_t') ->None:
        return _ida_pro.int64vec_t_inject(self, s, len)

    def __eq__(self, r: 'int64vec_t') ->bool:
        return _ida_pro.int64vec_t___eq__(self, r)

    def __ne__(self, r: 'int64vec_t') ->bool:
        return _ida_pro.int64vec_t___ne__(self, r)

    def begin(self, *args) ->'qvector< long long >::const_iterator':
        return _ida_pro.int64vec_t_begin(self, *args)

    def end(self, *args) ->'qvector< long long >::const_iterator':
        return _ida_pro.int64vec_t_end(self, *args)

    def insert(self, it: 'qvector< long long >::iterator', x:
        'long long const &') ->'qvector< long long >::iterator':
        return _ida_pro.int64vec_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< long long >::iterator':
        return _ida_pro.int64vec_t_erase(self, *args)

    def find(self, *args) ->'qvector< long long >::const_iterator':
        return _ida_pro.int64vec_t_find(self, *args)

    def has(self, x: 'long long const &') ->bool:
        return _ida_pro.int64vec_t_has(self, x)

    def add_unique(self, x: 'long long const &') ->bool:
        return _ida_pro.int64vec_t_add_unique(self, x)

    def _del(self, x: 'long long const &') ->bool:
        return _ida_pro.int64vec_t__del(self, x)

    def __len__(self) ->'size_t':
        return _ida_pro.int64vec_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'long long const &':
        return _ida_pro.int64vec_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'long long const &') ->None:
        return _ida_pro.int64vec_t___setitem__(self, i, v)

    def append(self, x: 'long long const &') ->None:
        return _ida_pro.int64vec_t_append(self, x)

    def extend(self, x: 'int64vec_t') ->None:
        return _ida_pro.int64vec_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_pro.int64vec_t_swigregister(int64vec_t)


class uint64vec_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_pro.uint64vec_t_swiginit(self, _ida_pro.new_uint64vec_t(*args))
    __swig_destroy__ = _ida_pro.delete_uint64vec_t

    def push_back(self, *args) ->'unsigned long long &':
        return _ida_pro.uint64vec_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_pro.uint64vec_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_pro.uint64vec_t_size(self)

    def empty(self) ->bool:
        return _ida_pro.uint64vec_t_empty(self)

    def at(self, _idx: 'size_t') ->'unsigned long long const &':
        return _ida_pro.uint64vec_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_pro.uint64vec_t_qclear(self)

    def clear(self) ->None:
        return _ida_pro.uint64vec_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_pro.uint64vec_t_resize(self, *args)

    def capacity(self) ->'size_t':
        return _ida_pro.uint64vec_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_pro.uint64vec_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_pro.uint64vec_t_truncate(self)

    def swap(self, r: 'uint64vec_t') ->None:
        return _ida_pro.uint64vec_t_swap(self, r)

    def extract(self) ->'unsigned long long *':
        return _ida_pro.uint64vec_t_extract(self)

    def inject(self, s: 'unsigned long long *', len: 'size_t') ->None:
        return _ida_pro.uint64vec_t_inject(self, s, len)

    def __eq__(self, r: 'uint64vec_t') ->bool:
        return _ida_pro.uint64vec_t___eq__(self, r)

    def __ne__(self, r: 'uint64vec_t') ->bool:
        return _ida_pro.uint64vec_t___ne__(self, r)

    def begin(self, *args) ->'qvector< unsigned long long >::const_iterator':
        return _ida_pro.uint64vec_t_begin(self, *args)

    def end(self, *args) ->'qvector< unsigned long long >::const_iterator':
        return _ida_pro.uint64vec_t_end(self, *args)

    def insert(self, it: 'qvector< unsigned long long >::iterator', x:
        'unsigned long long const &'
        ) ->'qvector< unsigned long long >::iterator':
        return _ida_pro.uint64vec_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< unsigned long long >::iterator':
        return _ida_pro.uint64vec_t_erase(self, *args)

    def find(self, *args) ->'qvector< unsigned long long >::const_iterator':
        return _ida_pro.uint64vec_t_find(self, *args)

    def has(self, x: 'unsigned long long const &') ->bool:
        return _ida_pro.uint64vec_t_has(self, x)

    def add_unique(self, x: 'unsigned long long const &') ->bool:
        return _ida_pro.uint64vec_t_add_unique(self, x)

    def _del(self, x: 'unsigned long long const &') ->bool:
        return _ida_pro.uint64vec_t__del(self, x)

    def __len__(self) ->'size_t':
        return _ida_pro.uint64vec_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'unsigned long long const &':
        return _ida_pro.uint64vec_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'unsigned long long const &') ->None:
        return _ida_pro.uint64vec_t___setitem__(self, i, v)

    def append(self, x: 'unsigned long long const &') ->None:
        return _ida_pro.uint64vec_t_append(self, x)

    def extend(self, x: 'uint64vec_t') ->None:
        return _ida_pro.uint64vec_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_pro.uint64vec_t_swigregister(uint64vec_t)


class boolvec_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_pro.boolvec_t_swiginit(self, _ida_pro.new_boolvec_t(*args))
    __swig_destroy__ = _ida_pro.delete_boolvec_t

    def push_back(self, *args) ->'bool &':
        return _ida_pro.boolvec_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_pro.boolvec_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_pro.boolvec_t_size(self)

    def empty(self) ->bool:
        return _ida_pro.boolvec_t_empty(self)

    def at(self, _idx: 'size_t') ->'bool const &':
        return _ida_pro.boolvec_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_pro.boolvec_t_qclear(self)

    def clear(self) ->None:
        return _ida_pro.boolvec_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_pro.boolvec_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_pro.boolvec_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_pro.boolvec_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_pro.boolvec_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_pro.boolvec_t_truncate(self)

    def swap(self, r: 'boolvec_t') ->None:
        return _ida_pro.boolvec_t_swap(self, r)

    def extract(self) ->'bool *':
        return _ida_pro.boolvec_t_extract(self)

    def inject(self, s: 'bool *', len: 'size_t') ->None:
        return _ida_pro.boolvec_t_inject(self, s, len)

    def __eq__(self, r: 'boolvec_t') ->bool:
        return _ida_pro.boolvec_t___eq__(self, r)

    def __ne__(self, r: 'boolvec_t') ->bool:
        return _ida_pro.boolvec_t___ne__(self, r)

    def begin(self, *args) ->'qvector< bool >::const_iterator':
        return _ida_pro.boolvec_t_begin(self, *args)

    def end(self, *args) ->'qvector< bool >::const_iterator':
        return _ida_pro.boolvec_t_end(self, *args)

    def insert(self, it: 'qvector< bool >::iterator', x: 'bool const &'
        ) ->'qvector< bool >::iterator':
        return _ida_pro.boolvec_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< bool >::iterator':
        return _ida_pro.boolvec_t_erase(self, *args)

    def find(self, *args) ->'qvector< bool >::const_iterator':
        return _ida_pro.boolvec_t_find(self, *args)

    def has(self, x: 'bool const &') ->bool:
        return _ida_pro.boolvec_t_has(self, x)

    def add_unique(self, x: 'bool const &') ->bool:
        return _ida_pro.boolvec_t_add_unique(self, x)

    def _del(self, x: 'bool const &') ->bool:
        return _ida_pro.boolvec_t__del(self, x)

    def __len__(self) ->'size_t':
        return _ida_pro.boolvec_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'bool const &':
        return _ida_pro.boolvec_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'bool const &') ->None:
        return _ida_pro.boolvec_t___setitem__(self, i, v)

    def append(self, x: 'bool const &') ->None:
        return _ida_pro.boolvec_t_append(self, x)

    def extend(self, x: 'boolvec_t') ->None:
        return _ida_pro.boolvec_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_pro.boolvec_t_swigregister(boolvec_t)


class strvec_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_pro.strvec_t_swiginit(self, _ida_pro.new_strvec_t(*args))
    __swig_destroy__ = _ida_pro.delete_strvec_t

    def push_back(self, *args) ->'simpleline_t &':
        return _ida_pro.strvec_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_pro.strvec_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_pro.strvec_t_size(self)

    def empty(self) ->bool:
        return _ida_pro.strvec_t_empty(self)

    def at(self, _idx: 'size_t') ->'simpleline_t const &':
        return _ida_pro.strvec_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_pro.strvec_t_qclear(self)

    def clear(self) ->None:
        return _ida_pro.strvec_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_pro.strvec_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_pro.strvec_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_pro.strvec_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_pro.strvec_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_pro.strvec_t_truncate(self)

    def swap(self, r: 'strvec_t') ->None:
        return _ida_pro.strvec_t_swap(self, r)

    def extract(self) ->'simpleline_t *':
        return _ida_pro.strvec_t_extract(self)

    def inject(self, s: 'simpleline_t *', len: 'size_t') ->None:
        return _ida_pro.strvec_t_inject(self, s, len)

    def begin(self, *args) ->'qvector< simpleline_t >::const_iterator':
        return _ida_pro.strvec_t_begin(self, *args)

    def end(self, *args) ->'qvector< simpleline_t >::const_iterator':
        return _ida_pro.strvec_t_end(self, *args)

    def insert(self, it: 'qvector< simpleline_t >::iterator', x:
        'simpleline_t const &') ->'qvector< simpleline_t >::iterator':
        return _ida_pro.strvec_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< simpleline_t >::iterator':
        return _ida_pro.strvec_t_erase(self, *args)

    def __len__(self) ->'size_t':
        return _ida_pro.strvec_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'simpleline_t const &':
        return _ida_pro.strvec_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'simpleline_t const &') ->None:
        return _ida_pro.strvec_t___setitem__(self, i, v)

    def append(self, x: 'simpleline_t const &') ->None:
        return _ida_pro.strvec_t_append(self, x)

    def extend(self, x: 'strvec_t') ->None:
        return _ida_pro.strvec_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_pro.strvec_t_swigregister(strvec_t)


class sizevec_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_pro.sizevec_t_swiginit(self, _ida_pro.new_sizevec_t(*args))
    __swig_destroy__ = _ida_pro.delete_sizevec_t

    def push_back(self, *args) ->'size_t &':
        return _ida_pro.sizevec_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_pro.sizevec_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_pro.sizevec_t_size(self)

    def empty(self) ->bool:
        return _ida_pro.sizevec_t_empty(self)

    def at(self, _idx: 'size_t') ->'size_t const &':
        return _ida_pro.sizevec_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_pro.sizevec_t_qclear(self)

    def clear(self) ->None:
        return _ida_pro.sizevec_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_pro.sizevec_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_pro.sizevec_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_pro.sizevec_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_pro.sizevec_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_pro.sizevec_t_truncate(self)

    def swap(self, r: 'sizevec_t') ->None:
        return _ida_pro.sizevec_t_swap(self, r)

    def extract(self) ->'size_t *':
        return _ida_pro.sizevec_t_extract(self)

    def inject(self, s: 'size_t *', len: 'size_t') ->None:
        return _ida_pro.sizevec_t_inject(self, s, len)

    def __eq__(self, r: 'sizevec_t') ->bool:
        return _ida_pro.sizevec_t___eq__(self, r)

    def __ne__(self, r: 'sizevec_t') ->bool:
        return _ida_pro.sizevec_t___ne__(self, r)

    def begin(self, *args) ->'qvector< size_t >::const_iterator':
        return _ida_pro.sizevec_t_begin(self, *args)

    def end(self, *args) ->'qvector< size_t >::const_iterator':
        return _ida_pro.sizevec_t_end(self, *args)

    def insert(self, it: 'qvector< size_t >::iterator', x: 'size_t const &'
        ) ->'qvector< size_t >::iterator':
        return _ida_pro.sizevec_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< size_t >::iterator':
        return _ida_pro.sizevec_t_erase(self, *args)

    def find(self, *args) ->'qvector< size_t >::const_iterator':
        return _ida_pro.sizevec_t_find(self, *args)

    def has(self, x: 'size_t const &') ->bool:
        return _ida_pro.sizevec_t_has(self, x)

    def add_unique(self, x: 'size_t const &') ->bool:
        return _ida_pro.sizevec_t_add_unique(self, x)

    def _del(self, x: 'size_t const &') ->bool:
        return _ida_pro.sizevec_t__del(self, x)

    def __len__(self) ->'size_t':
        return _ida_pro.sizevec_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'size_t const &':
        return _ida_pro.sizevec_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'size_t const &') ->None:
        return _ida_pro.sizevec_t___setitem__(self, i, v)

    def append(self, x: 'size_t const &') ->None:
        return _ida_pro.sizevec_t_append(self, x)

    def extend(self, x: 'sizevec_t') ->None:
        return _ida_pro.sizevec_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_pro.sizevec_t_swigregister(sizevec_t)


def qstrvec_t_create() ->'PyObject *':
    return _ida_pro.qstrvec_t_create()


def qstrvec_t_destroy(py_obj: 'PyObject *') ->bool:
    return _ida_pro.qstrvec_t_destroy(py_obj)


def qstrvec_t_get_clink(_self: 'PyObject *') ->'qstrvec_t *':
    return _ida_pro.qstrvec_t_get_clink(_self)


def qstrvec_t_get_clink_ptr(_self: 'PyObject *') ->'PyObject *':
    return _ida_pro.qstrvec_t_get_clink_ptr(_self)


def qstrvec_t_assign(_self: 'PyObject *', other: 'PyObject *') ->bool:
    return _ida_pro.qstrvec_t_assign(_self, other)


def qstrvec_t_addressof(_self: 'PyObject *', idx: 'size_t') ->'PyObject *':
    return _ida_pro.qstrvec_t_addressof(_self, idx)


def qstrvec_t_set(_self: 'PyObject *', idx: 'size_t', s: str) ->bool:
    return _ida_pro.qstrvec_t_set(_self, idx, s)


def qstrvec_t_from_list(_self: 'PyObject *', py_list: 'PyObject *') ->bool:
    return _ida_pro.qstrvec_t_from_list(_self, py_list)


def qstrvec_t_size(_self: 'PyObject *') ->'size_t':
    return _ida_pro.qstrvec_t_size(_self)


def qstrvec_t_get(_self: 'PyObject *', idx: 'size_t') ->'PyObject *':
    return _ida_pro.qstrvec_t_get(_self, idx)


def qstrvec_t_add(_self: 'PyObject *', s: str) ->bool:
    return _ida_pro.qstrvec_t_add(_self, s)


def qstrvec_t_clear(_self: 'PyObject *', qclear: bool) ->bool:
    return _ida_pro.qstrvec_t_clear(_self, qclear)


def qstrvec_t_insert(_self: 'PyObject *', idx: 'size_t', s: str) ->bool:
    return _ida_pro.qstrvec_t_insert(_self, idx, s)


def qstrvec_t_remove(_self: 'PyObject *', idx: 'size_t') ->bool:
    return _ida_pro.qstrvec_t_remove(_self, idx)


def str2user(str):
    """Insert C-style escape characters to string

@param str: the input string
@return: new string with escape characters inserted, or None"""
    return _ida_pro.str2user(str)


class uchar_array(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, nelements: 'size_t'):
        _ida_pro.uchar_array_swiginit(self, _ida_pro.new_uchar_array(nelements)
            )
    __swig_destroy__ = _ida_pro.delete_uchar_array

    def __getitem__(self, index: 'size_t') ->'uchar':
        return _ida_pro.uchar_array___getitem__(self, index)

    def __setitem__(self, index: 'size_t', value: 'uchar') ->None:
        return _ida_pro.uchar_array___setitem__(self, index, value)

    def cast(self) ->'uchar *':
        return _ida_pro.uchar_array_cast(self)

    @staticmethod
    def frompointer(t: 'uchar *') ->'uchar_array *':
        return _ida_pro.uchar_array_frompointer(t)


_ida_pro.uchar_array_swigregister(uchar_array)


class tid_array(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, nelements: 'size_t'):
        _ida_pro.tid_array_swiginit(self, _ida_pro.new_tid_array(nelements))
    __swig_destroy__ = _ida_pro.delete_tid_array

    def __getitem__(self, index: 'size_t') ->'tid_t':
        return _ida_pro.tid_array___getitem__(self, index)

    def __setitem__(self, index: 'size_t', value: 'tid_t') ->None:
        return _ida_pro.tid_array___setitem__(self, index, value)

    def cast(self) ->'tid_t *':
        return _ida_pro.tid_array_cast(self)

    @staticmethod
    def frompointer(t: 'tid_t *') ->'tid_array *':
        return _ida_pro.tid_array_frompointer(t)


_ida_pro.tid_array_swigregister(tid_array)


class ea_array(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, nelements: 'size_t'):
        _ida_pro.ea_array_swiginit(self, _ida_pro.new_ea_array(nelements))
    __swig_destroy__ = _ida_pro.delete_ea_array

    def __getitem__(self, index: 'size_t') ->ida_idaapi.ea_t:
        return _ida_pro.ea_array___getitem__(self, index)

    def __setitem__(self, index: 'size_t', value: ida_idaapi.ea_t) ->None:
        return _ida_pro.ea_array___setitem__(self, index, value)

    def cast(self) ->'ea_t *':
        return _ida_pro.ea_array_cast(self)

    @staticmethod
    def frompointer(t: 'ea_t *') ->'ea_array *':
        return _ida_pro.ea_array_frompointer(t)


_ida_pro.ea_array_swigregister(ea_array)


class sel_array(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, nelements: 'size_t'):
        _ida_pro.sel_array_swiginit(self, _ida_pro.new_sel_array(nelements))
    __swig_destroy__ = _ida_pro.delete_sel_array

    def __getitem__(self, index: 'size_t') ->'sel_t':
        return _ida_pro.sel_array___getitem__(self, index)

    def __setitem__(self, index: 'size_t', value: 'sel_t') ->None:
        return _ida_pro.sel_array___setitem__(self, index, value)

    def cast(self) ->'sel_t *':
        return _ida_pro.sel_array_cast(self)

    @staticmethod
    def frompointer(t: 'sel_t *') ->'sel_array *':
        return _ida_pro.sel_array_frompointer(t)


_ida_pro.sel_array_swigregister(sel_array)


class uval_array(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, nelements: 'size_t'):
        _ida_pro.uval_array_swiginit(self, _ida_pro.new_uval_array(nelements))
    __swig_destroy__ = _ida_pro.delete_uval_array

    def __getitem__(self, index: 'size_t') ->int:
        return _ida_pro.uval_array___getitem__(self, index)

    def __setitem__(self, index: 'size_t', value: int) ->None:
        return _ida_pro.uval_array___setitem__(self, index, value)

    def cast(self) ->'uval_t *':
        return _ida_pro.uval_array_cast(self)

    @staticmethod
    def frompointer(t: 'uval_t *') ->'uval_array *':
        return _ida_pro.uval_array_frompointer(t)


_ida_pro.uval_array_swigregister(uval_array)


class uchar_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.uchar_pointer_swiginit(self, _ida_pro.new_uchar_pointer())
    __swig_destroy__ = _ida_pro.delete_uchar_pointer

    def assign(self, value: 'uchar') ->None:
        return _ida_pro.uchar_pointer_assign(self, value)

    def value(self) ->'uchar':
        return _ida_pro.uchar_pointer_value(self)

    def cast(self) ->'uchar *':
        return _ida_pro.uchar_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'uchar *') ->'uchar_pointer *':
        return _ida_pro.uchar_pointer_frompointer(t)


_ida_pro.uchar_pointer_swigregister(uchar_pointer)


class ushort_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.ushort_pointer_swiginit(self, _ida_pro.new_ushort_pointer())
    __swig_destroy__ = _ida_pro.delete_ushort_pointer

    def assign(self, value: 'ushort') ->None:
        return _ida_pro.ushort_pointer_assign(self, value)

    def value(self) ->'ushort':
        return _ida_pro.ushort_pointer_value(self)

    def cast(self) ->'ushort *':
        return _ida_pro.ushort_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'ushort *') ->'ushort_pointer *':
        return _ida_pro.ushort_pointer_frompointer(t)


_ida_pro.ushort_pointer_swigregister(ushort_pointer)


class uint_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.uint_pointer_swiginit(self, _ida_pro.new_uint_pointer())
    __swig_destroy__ = _ida_pro.delete_uint_pointer

    def assign(self, value: 'uint') ->None:
        return _ida_pro.uint_pointer_assign(self, value)

    def value(self) ->'uint':
        return _ida_pro.uint_pointer_value(self)

    def cast(self) ->'uint *':
        return _ida_pro.uint_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'uint *') ->'uint_pointer *':
        return _ida_pro.uint_pointer_frompointer(t)


_ida_pro.uint_pointer_swigregister(uint_pointer)


class sint8_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.sint8_pointer_swiginit(self, _ida_pro.new_sint8_pointer())
    __swig_destroy__ = _ida_pro.delete_sint8_pointer

    def assign(self, value: 'sint8') ->None:
        return _ida_pro.sint8_pointer_assign(self, value)

    def value(self) ->'sint8':
        return _ida_pro.sint8_pointer_value(self)

    def cast(self) ->'sint8 *':
        return _ida_pro.sint8_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'sint8 *') ->'sint8_pointer *':
        return _ida_pro.sint8_pointer_frompointer(t)


_ida_pro.sint8_pointer_swigregister(sint8_pointer)


class int8_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.int8_pointer_swiginit(self, _ida_pro.new_int8_pointer())
    __swig_destroy__ = _ida_pro.delete_int8_pointer

    def assign(self, value: 'int8') ->None:
        return _ida_pro.int8_pointer_assign(self, value)

    def value(self) ->'int8':
        return _ida_pro.int8_pointer_value(self)

    def cast(self) ->'int8 *':
        return _ida_pro.int8_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'int8 *') ->'int8_pointer *':
        return _ida_pro.int8_pointer_frompointer(t)


_ida_pro.int8_pointer_swigregister(int8_pointer)


class uint8_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.uint8_pointer_swiginit(self, _ida_pro.new_uint8_pointer())
    __swig_destroy__ = _ida_pro.delete_uint8_pointer

    def assign(self, value: 'uint8') ->None:
        return _ida_pro.uint8_pointer_assign(self, value)

    def value(self) ->'uint8':
        return _ida_pro.uint8_pointer_value(self)

    def cast(self) ->'uint8 *':
        return _ida_pro.uint8_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'uint8 *') ->'uint8_pointer *':
        return _ida_pro.uint8_pointer_frompointer(t)


_ida_pro.uint8_pointer_swigregister(uint8_pointer)


class int16_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.int16_pointer_swiginit(self, _ida_pro.new_int16_pointer())
    __swig_destroy__ = _ida_pro.delete_int16_pointer

    def assign(self, value: 'int16') ->None:
        return _ida_pro.int16_pointer_assign(self, value)

    def value(self) ->'int16':
        return _ida_pro.int16_pointer_value(self)

    def cast(self) ->'int16 *':
        return _ida_pro.int16_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'int16 *') ->'int16_pointer *':
        return _ida_pro.int16_pointer_frompointer(t)


_ida_pro.int16_pointer_swigregister(int16_pointer)


class uint16_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.uint16_pointer_swiginit(self, _ida_pro.new_uint16_pointer())
    __swig_destroy__ = _ida_pro.delete_uint16_pointer

    def assign(self, value: 'uint16') ->None:
        return _ida_pro.uint16_pointer_assign(self, value)

    def value(self) ->'uint16':
        return _ida_pro.uint16_pointer_value(self)

    def cast(self) ->'uint16 *':
        return _ida_pro.uint16_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'uint16 *') ->'uint16_pointer *':
        return _ida_pro.uint16_pointer_frompointer(t)


_ida_pro.uint16_pointer_swigregister(uint16_pointer)


class int32_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.int32_pointer_swiginit(self, _ida_pro.new_int32_pointer())
    __swig_destroy__ = _ida_pro.delete_int32_pointer

    def assign(self, value: int) ->None:
        return _ida_pro.int32_pointer_assign(self, value)

    def value(self) ->int:
        return _ida_pro.int32_pointer_value(self)

    def cast(self) ->'int32 *':
        return _ida_pro.int32_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'int32 *') ->'int32_pointer *':
        return _ida_pro.int32_pointer_frompointer(t)


_ida_pro.int32_pointer_swigregister(int32_pointer)


class uint32_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.uint32_pointer_swiginit(self, _ida_pro.new_uint32_pointer())
    __swig_destroy__ = _ida_pro.delete_uint32_pointer

    def assign(self, value: int) ->None:
        return _ida_pro.uint32_pointer_assign(self, value)

    def value(self) ->int:
        return _ida_pro.uint32_pointer_value(self)

    def cast(self) ->'uint32 *':
        return _ida_pro.uint32_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'uint32 *') ->'uint32_pointer *':
        return _ida_pro.uint32_pointer_frompointer(t)


_ida_pro.uint32_pointer_swigregister(uint32_pointer)


class int64_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.int64_pointer_swiginit(self, _ida_pro.new_int64_pointer())
    __swig_destroy__ = _ida_pro.delete_int64_pointer

    def assign(self, value: 'int64') ->None:
        return _ida_pro.int64_pointer_assign(self, value)

    def value(self) ->'int64':
        return _ida_pro.int64_pointer_value(self)

    def cast(self) ->'int64 *':
        return _ida_pro.int64_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'int64 *') ->'int64_pointer *':
        return _ida_pro.int64_pointer_frompointer(t)


_ida_pro.int64_pointer_swigregister(int64_pointer)


class uint64_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.uint64_pointer_swiginit(self, _ida_pro.new_uint64_pointer())
    __swig_destroy__ = _ida_pro.delete_uint64_pointer

    def assign(self, value: 'uint64') ->None:
        return _ida_pro.uint64_pointer_assign(self, value)

    def value(self) ->'uint64':
        return _ida_pro.uint64_pointer_value(self)

    def cast(self) ->'uint64 *':
        return _ida_pro.uint64_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'uint64 *') ->'uint64_pointer *':
        return _ida_pro.uint64_pointer_frompointer(t)


_ida_pro.uint64_pointer_swigregister(uint64_pointer)


class ssize_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.ssize_pointer_swiginit(self, _ida_pro.new_ssize_pointer())
    __swig_destroy__ = _ida_pro.delete_ssize_pointer

    def assign(self, value: 'ssize_t') ->None:
        return _ida_pro.ssize_pointer_assign(self, value)

    def value(self) ->'ssize_t':
        return _ida_pro.ssize_pointer_value(self)

    def cast(self) ->'ssize_t *':
        return _ida_pro.ssize_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'ssize_t *') ->'ssize_pointer *':
        return _ida_pro.ssize_pointer_frompointer(t)


_ida_pro.ssize_pointer_swigregister(ssize_pointer)


class bool_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.bool_pointer_swiginit(self, _ida_pro.new_bool_pointer())
    __swig_destroy__ = _ida_pro.delete_bool_pointer

    def assign(self, value: bool) ->None:
        return _ida_pro.bool_pointer_assign(self, value)

    def value(self) ->bool:
        return _ida_pro.bool_pointer_value(self)

    def cast(self) ->'bool *':
        return _ida_pro.bool_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'bool *') ->'bool_pointer *':
        return _ida_pro.bool_pointer_frompointer(t)


_ida_pro.bool_pointer_swigregister(bool_pointer)


class char_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.char_pointer_swiginit(self, _ida_pro.new_char_pointer())
    __swig_destroy__ = _ida_pro.delete_char_pointer

    def assign(self, value: 'char') ->None:
        return _ida_pro.char_pointer_assign(self, value)

    def value(self) ->'char':
        return _ida_pro.char_pointer_value(self)

    def cast(self) ->'char *':
        return _ida_pro.char_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'char *') ->'char_pointer *':
        return _ida_pro.char_pointer_frompointer(t)


_ida_pro.char_pointer_swigregister(char_pointer)


class short_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.short_pointer_swiginit(self, _ida_pro.new_short_pointer())
    __swig_destroy__ = _ida_pro.delete_short_pointer

    def assign(self, value: 'short') ->None:
        return _ida_pro.short_pointer_assign(self, value)

    def value(self) ->'short':
        return _ida_pro.short_pointer_value(self)

    def cast(self) ->'short *':
        return _ida_pro.short_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'short *') ->'short_pointer *':
        return _ida_pro.short_pointer_frompointer(t)


_ida_pro.short_pointer_swigregister(short_pointer)


class int_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.int_pointer_swiginit(self, _ida_pro.new_int_pointer())
    __swig_destroy__ = _ida_pro.delete_int_pointer

    def assign(self, value: int) ->None:
        return _ida_pro.int_pointer_assign(self, value)

    def value(self) ->int:
        return _ida_pro.int_pointer_value(self)

    def cast(self) ->'int *':
        return _ida_pro.int_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'int *') ->'int_pointer *':
        return _ida_pro.int_pointer_frompointer(t)


_ida_pro.int_pointer_swigregister(int_pointer)


class ea_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.ea_pointer_swiginit(self, _ida_pro.new_ea_pointer())
    __swig_destroy__ = _ida_pro.delete_ea_pointer

    def assign(self, value: ida_idaapi.ea_t) ->None:
        return _ida_pro.ea_pointer_assign(self, value)

    def value(self) ->ida_idaapi.ea_t:
        return _ida_pro.ea_pointer_value(self)

    def cast(self) ->'ea_t *':
        return _ida_pro.ea_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'ea_t *') ->'ea_pointer *':
        return _ida_pro.ea_pointer_frompointer(t)


_ida_pro.ea_pointer_swigregister(ea_pointer)


class sel_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.sel_pointer_swiginit(self, _ida_pro.new_sel_pointer())
    __swig_destroy__ = _ida_pro.delete_sel_pointer

    def assign(self, value: 'sel_t') ->None:
        return _ida_pro.sel_pointer_assign(self, value)

    def value(self) ->'sel_t':
        return _ida_pro.sel_pointer_value(self)

    def cast(self) ->'sel_t *':
        return _ida_pro.sel_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'sel_t *') ->'sel_pointer *':
        return _ida_pro.sel_pointer_frompointer(t)


_ida_pro.sel_pointer_swigregister(sel_pointer)


class asize_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.asize_pointer_swiginit(self, _ida_pro.new_asize_pointer())
    __swig_destroy__ = _ida_pro.delete_asize_pointer

    def assign(self, value: 'asize_t') ->None:
        return _ida_pro.asize_pointer_assign(self, value)

    def value(self) ->'asize_t':
        return _ida_pro.asize_pointer_value(self)

    def cast(self) ->'asize_t *':
        return _ida_pro.asize_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'asize_t *') ->'asize_pointer *':
        return _ida_pro.asize_pointer_frompointer(t)


_ida_pro.asize_pointer_swigregister(asize_pointer)


class adiff_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.adiff_pointer_swiginit(self, _ida_pro.new_adiff_pointer())
    __swig_destroy__ = _ida_pro.delete_adiff_pointer

    def assign(self, value: 'adiff_t') ->None:
        return _ida_pro.adiff_pointer_assign(self, value)

    def value(self) ->'adiff_t':
        return _ida_pro.adiff_pointer_value(self)

    def cast(self) ->'adiff_t *':
        return _ida_pro.adiff_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'adiff_t *') ->'adiff_pointer *':
        return _ida_pro.adiff_pointer_frompointer(t)


_ida_pro.adiff_pointer_swigregister(adiff_pointer)


class uval_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.uval_pointer_swiginit(self, _ida_pro.new_uval_pointer())
    __swig_destroy__ = _ida_pro.delete_uval_pointer

    def assign(self, value: int) ->None:
        return _ida_pro.uval_pointer_assign(self, value)

    def value(self) ->int:
        return _ida_pro.uval_pointer_value(self)

    def cast(self) ->'uval_t *':
        return _ida_pro.uval_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'uval_t *') ->'uval_pointer *':
        return _ida_pro.uval_pointer_frompointer(t)


_ida_pro.uval_pointer_swigregister(uval_pointer)


class sval_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.sval_pointer_swiginit(self, _ida_pro.new_sval_pointer())
    __swig_destroy__ = _ida_pro.delete_sval_pointer

    def assign(self, value: int) ->None:
        return _ida_pro.sval_pointer_assign(self, value)

    def value(self) ->int:
        return _ida_pro.sval_pointer_value(self)

    def cast(self) ->'sval_t *':
        return _ida_pro.sval_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'sval_t *') ->'sval_pointer *':
        return _ida_pro.sval_pointer_frompointer(t)


_ida_pro.sval_pointer_swigregister(sval_pointer)


class ea32_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.ea32_pointer_swiginit(self, _ida_pro.new_ea32_pointer())
    __swig_destroy__ = _ida_pro.delete_ea32_pointer

    def assign(self, value: 'ea32_t') ->None:
        return _ida_pro.ea32_pointer_assign(self, value)

    def value(self) ->'ea32_t':
        return _ida_pro.ea32_pointer_value(self)

    def cast(self) ->'ea32_t *':
        return _ida_pro.ea32_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'ea32_t *') ->'ea32_pointer *':
        return _ida_pro.ea32_pointer_frompointer(t)


_ida_pro.ea32_pointer_swigregister(ea32_pointer)


class ea64_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.ea64_pointer_swiginit(self, _ida_pro.new_ea64_pointer())
    __swig_destroy__ = _ida_pro.delete_ea64_pointer

    def assign(self, value: 'ea64_t') ->None:
        return _ida_pro.ea64_pointer_assign(self, value)

    def value(self) ->'ea64_t':
        return _ida_pro.ea64_pointer_value(self)

    def cast(self) ->'ea64_t *':
        return _ida_pro.ea64_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'ea64_t *') ->'ea64_pointer *':
        return _ida_pro.ea64_pointer_frompointer(t)


_ida_pro.ea64_pointer_swigregister(ea64_pointer)


class flags_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.flags_pointer_swiginit(self, _ida_pro.new_flags_pointer())
    __swig_destroy__ = _ida_pro.delete_flags_pointer

    def assign(self, value: 'flags_t') ->None:
        return _ida_pro.flags_pointer_assign(self, value)

    def value(self) ->'flags_t':
        return _ida_pro.flags_pointer_value(self)

    def cast(self) ->'flags_t *':
        return _ida_pro.flags_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'flags_t *') ->'flags_pointer *':
        return _ida_pro.flags_pointer_frompointer(t)


_ida_pro.flags_pointer_swigregister(flags_pointer)


class flags64_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.flags64_pointer_swiginit(self, _ida_pro.new_flags64_pointer())
    __swig_destroy__ = _ida_pro.delete_flags64_pointer

    def assign(self, value: 'flags64_t') ->None:
        return _ida_pro.flags64_pointer_assign(self, value)

    def value(self) ->'flags64_t':
        return _ida_pro.flags64_pointer_value(self)

    def cast(self) ->'flags64_t *':
        return _ida_pro.flags64_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'flags64_t *') ->'flags64_pointer *':
        return _ida_pro.flags64_pointer_frompointer(t)


_ida_pro.flags64_pointer_swigregister(flags64_pointer)


class tid_pointer(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self):
        _ida_pro.tid_pointer_swiginit(self, _ida_pro.new_tid_pointer())
    __swig_destroy__ = _ida_pro.delete_tid_pointer

    def assign(self, value: 'tid_t') ->None:
        return _ida_pro.tid_pointer_assign(self, value)

    def value(self) ->'tid_t':
        return _ida_pro.tid_pointer_value(self)

    def cast(self) ->'tid_t *':
        return _ida_pro.tid_pointer_cast(self)

    @staticmethod
    def frompointer(t: 'tid_t *') ->'tid_pointer *':
        return _ida_pro.tid_pointer_frompointer(t)


_ida_pro.tid_pointer_swigregister(tid_pointer)
import ida_idaapi
longlongvec_t = int64vec_t
ulonglongvec_t = uint64vec_t
if ida_idaapi.__EA64__:
    svalvec_t = int64vec_t
    uvalvec_t = uint64vec_t
else:
    svalvec_t = intvec_t
    uvalvec_t = uintvec_t
eavec_t = uvalvec_t
ida_idaapi._listify_types(intvec_t, uintvec_t, int64vec_t, uint64vec_t,
    boolvec_t, strvec_t)


class _qstrvec_t(ida_idaapi.py_clinked_object_t):
    """
    WARNING: It is very unlikely an IDAPython user should ever, ever
    have to use this type. It should only be used for IDAPython internals.

    For example, in py_askusingform.py, we ctypes-expose to the IDA
    kernel & UI a qstrvec instance, in case a DropdownListControl is
    constructed.
    That's because that's what ask_form expects, and we have no
    choice but to make a DropdownListControl hold a qstrvec_t.
    This is, afaict, the only situation where a Python
    _qstrvec_t is required.
    """

    def __init__(self, items=None):
        ida_idaapi.py_clinked_object_t.__init__(self)
        if items:
            self.from_list(items)

    def _create_clink(self):
        return _ida_pro.qstrvec_t_create()

    def _del_clink(self, lnk):
        return _ida_pro.qstrvec_t_destroy(lnk)

    def _get_clink_ptr(self):
        return _ida_pro.qstrvec_t_get_clink_ptr(self)

    def assign(self, other):
        """Copies the contents of 'other' to 'self'"""
        return _ida_pro.qstrvec_t_assign(self, other)

    def __setitem__(self, idx, s):
        """Sets string at the given index"""
        return _ida_pro.qstrvec_t_set(self, idx, s)

    def __getitem__(self, idx):
        """Gets the string at the given index"""
        return _ida_pro.qstrvec_t_get(self, idx)

    def __get_size(self):
        return _ida_pro.qstrvec_t_size(self)
    size = property(__get_size)
    """Returns the count of elements"""

    def addressof(self, idx):
        """Returns the address (as number) of the qstring at the given index"""
        return _ida_pro.qstrvec_t_addressof(self, idx)

    def add(self, s):
        """Add a string to the vector"""
        return _ida_pro.qstrvec_t_add(self, s)

    def from_list(self, lst):
        """Populates the vector from a Python string list"""
        return _ida_pro.qstrvec_t_from_list(self, lst)

    def clear(self, qclear=False):
        """
        Clears all strings from the vector.
        @param qclear: Just reset the size but do not actually free the memory
        """
        return _ida_pro.qstrvec_t_clear(self, qclear)

    def insert(self, idx, s):
        """Insert a string into the vector"""
        return _ida_pro.qstrvec_t_insert(self, idx, s)

    def remove(self, idx):
        """Removes a string from the vector"""
        return _ida_pro.qstrvec_t_remove(self, idx)

```
