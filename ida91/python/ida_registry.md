```python
"""Registry related functions.

IDA uses the registry to store global configuration options that must persist after IDA has been closed.
On Windows, IDA uses the Windows registry directly. On Unix systems, the registry is stored in a file (typically ~/.idapro/ida.reg).
The root key for accessing IDA settings in the registry is defined by ROOT_KEY_NAME. 
    """
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_registry
else:
    import _ida_registry
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
SWIG_PYTHON_LEGACY_BOOL = _ida_registry.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi


def reg_read_string(name: str, subkey: str=None, _def: str=None
    ) ->'PyObject *':
    """Read a string from the registry. 
        
@param name: value name
@param subkey: key name
@returns success"""
    return _ida_registry.reg_read_string(name, subkey, _def)


def reg_data_type(name: str, subkey: str=None) ->'regval_type_t':
    """Get data type of a given value. 
        
@param name: value name
@param subkey: key name
@returns false if the [key+]value doesn't exist"""
    return _ida_registry.reg_data_type(name, subkey)


def reg_read_binary(name: str, subkey: str=None) ->'PyObject *':
    """Read binary data from the registry. 
        
@param name: value name
@param subkey: key name
@returns false if 'data' is not large enough to hold all data present. in this case 'data' is left untouched."""
    return _ida_registry.reg_read_binary(name, subkey)


def reg_write_binary(name: str, py_bytes: 'PyObject *', subkey: str=None
    ) ->'PyObject *':
    """Write binary data to the registry. 
        
@param name: value name
@param subkey: key name"""
    return _ida_registry.reg_write_binary(name, py_bytes, subkey)


def reg_subkey_subkeys(name: str) ->'PyObject *':
    """Get all subkey names of given key.
"""
    return _ida_registry.reg_subkey_subkeys(name)


def reg_subkey_values(name: str) ->'PyObject *':
    """Get all value names under given key.
"""
    return _ida_registry.reg_subkey_values(name)


IDA_REGISTRY_NAME = _ida_registry.IDA_REGISTRY_NAME
HVUI_REGISTRY_NAME = _ida_registry.HVUI_REGISTRY_NAME
ROOT_KEY_NAME = _ida_registry.ROOT_KEY_NAME
"""Default key used to store IDA settings in registry (Windows version). 
        """
reg_unknown = _ida_registry.reg_unknown
"""unknown
"""
reg_sz = _ida_registry.reg_sz
"""utf8 string
"""
reg_binary = _ida_registry.reg_binary
"""binary data
"""
reg_dword = _ida_registry.reg_dword
"""32-bit number
"""


def reg_delete_subkey(name: str) ->bool:
    """Delete a key from the registry.
"""
    return _ida_registry.reg_delete_subkey(name)


def reg_delete_tree(name: str) ->bool:
    """Delete a subtree from the registry.
"""
    return _ida_registry.reg_delete_tree(name)


def reg_delete(name: str, subkey: str=None) ->bool:
    """Delete a value from the registry. 
        
@param name: value name
@param subkey: parent key
@returns success"""
    return _ida_registry.reg_delete(name, subkey)


def reg_subkey_exists(name: str) ->bool:
    """Is there already a key with the given name?
"""
    return _ida_registry.reg_subkey_exists(name)


def reg_exists(name: str, subkey: str=None) ->bool:
    """Is there already a value with the given name? 
        
@param name: value name
@param subkey: parent key"""
    return _ida_registry.reg_exists(name, subkey)


def reg_read_strlist(subkey: str) ->'qstrvec_t *':
    """Retrieve all string values associated with the given key. Also see reg_update_strlist(), reg_write_strlist() 
        """
    return _ida_registry.reg_read_strlist(subkey)


def reg_write_strlist(_in: 'qstrvec_t const &', subkey: str) ->None:
    """Write string values associated with the given key. Also see reg_read_strlist(), reg_update_strlist() 
        """
    return _ida_registry.reg_write_strlist(_in, subkey)


def reg_update_strlist(subkey: str, add: str, maxrecs: 'size_t', rem: str=
    None, ignorecase: bool=False) ->None:
    """Update list of strings associated with given key. 
        
@param subkey: key name
@param add: string to be added to list, can be nullptr
@param maxrecs: limit list to this size
@param rem: string to be removed from list, can be nullptr
@param ignorecase: ignore case for 'add' and 'rem'"""
    return _ida_registry.reg_update_strlist(subkey, add, maxrecs, rem,
        ignorecase)


def reg_write_string(name: str, utf8: str, subkey: str=None) ->None:
    """Write a string to the registry. 
        
@param name: value name
@param utf8: utf8-encoded string
@param subkey: key name"""
    return _ida_registry.reg_write_string(name, utf8, subkey)


def reg_read_int(name: str, defval: int, subkey: str=None) ->int:
    """Read integer value from the registry. 
        
@param name: value name
@param defval: default value
@param subkey: key name
@returns the value read from the registry, or 'defval' if the read failed"""
    return _ida_registry.reg_read_int(name, defval, subkey)


def reg_write_int(name: str, value: int, subkey: str=None) ->None:
    """Write integer value to the registry. 
        
@param name: value name
@param value: value to write
@param subkey: key name"""
    return _ida_registry.reg_write_int(name, value, subkey)


def reg_read_bool(name: str, defval: bool, subkey: str=None) ->bool:
    """Read boolean value from the registry. 
        
@param name: value name
@param defval: default value
@param subkey: key name
@returns boolean read from registry, or 'defval' if the read failed"""
    return _ida_registry.reg_read_bool(name, defval, subkey)


def reg_write_bool(name: str, value: int, subkey: str=None) ->None:
    """Write boolean value to the registry. 
        
@param name: value name
@param value: boolean to write (nonzero = true)
@param subkey: key name"""
    return _ida_registry.reg_write_bool(name, value, subkey)


def reg_update_filestrlist(subkey: str, add: str, maxrecs: 'size_t', rem:
    str=None) ->None:
    """Update registry with a file list. Case sensitivity will vary depending on the target OS. 
        """
    return _ida_registry.reg_update_filestrlist(subkey, add, maxrecs, rem)


def set_registry_name(name: str) ->bool:
    return _ida_registry.set_registry_name(name)

```
