```python
"""Functions that deal with C-like expressions and built-in IDC language.

Functions marked THREAD_SAFE may be called from any thread. No simultaneous calls should be made for the same variable. We protect only global structures, individual variables must be protected manually. 
    """
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_expr
else:
    import _ida_expr
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
SWIG_PYTHON_LEGACY_BOOL = _ida_expr.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi


def compile_idc_file(nonnul_line: str) ->str:
    return _ida_expr.compile_idc_file(nonnul_line)


def compile_idc_text(nonnul_line: str) ->str:
    return _ida_expr.compile_idc_text(nonnul_line)


def py_get_call_idc_func() ->'size_t':
    return _ida_expr.py_get_call_idc_func()


def pyw_register_idc_func(name: str, args: str, py_fp: 'PyObject *'
    ) ->'size_t':
    return _ida_expr.pyw_register_idc_func(name, args, py_fp)


def pyw_unregister_idc_func(ctxptr: 'size_t') ->bool:
    return _ida_expr.pyw_unregister_idc_func(ctxptr)


def pyw_convert_defvals(out: 'idc_values_t', py_seq: 'PyObject *') ->bool:
    return _ida_expr.pyw_convert_defvals(out, py_seq)


def py_add_idc_func(name: str, fp_ptr: 'size_t', args: str, defvals:
    'idc_values_t', flags: int) ->bool:
    return _ida_expr.py_add_idc_func(name, fp_ptr, args, defvals, flags)


def eval_expr(rv: 'idc_value_t', where: ida_idaapi.ea_t, line: str) ->str:
    """Compile and calculate an expression. 
        
@param rv: pointer to the result
@param where: the current linear address in the addressing space of the program being disassembled. If will be used to resolve names of local variables etc. if not applicable, then should be BADADDR.
@param line: the expression to evaluate
@retval true: ok
@retval false: error, see errbuf"""
    return _ida_expr.eval_expr(rv, where, line)


def eval_idc_expr(rv: 'idc_value_t', where: ida_idaapi.ea_t, line: str) ->str:
    """Same as eval_expr(), but will always use the IDC interpreter regardless of the currently installed extlang. 
        """
    return _ida_expr.eval_idc_expr(rv, where, line)


IDC_LANG_EXT = _ida_expr.IDC_LANG_EXT
"""IDC script extension.
"""


def idcv_long(v: 'idc_value_t') ->'error_t':
    """Convert IDC variable to a long (32/64bit) number. 
        
@returns v = 0 if impossible to convert to long"""
    return _ida_expr.idcv_long(v)


def idcv_int64(v: 'idc_value_t') ->'error_t':
    """Convert IDC variable to a 64bit number. 
        
@returns v = 0 if impossible to convert to int64"""
    return _ida_expr.idcv_int64(v)


def idcv_num(v: 'idc_value_t') ->'error_t':
    """Convert IDC variable to a long number. 
        
@returns * v = 0 if IDC variable = "false" string
* v = 1 if IDC variable = "true" string
* v = number if IDC variable is number or string containing a number
* eTypeConflict if IDC variable = empty string"""
    return _ida_expr.idcv_num(v)


def idcv_string(v: 'idc_value_t') ->'error_t':
    """Convert IDC variable to a text string.
"""
    return _ida_expr.idcv_string(v)


def idcv_float(v: 'idc_value_t') ->'error_t':
    """Convert IDC variable to a floating point.
"""
    return _ida_expr.idcv_float(v)


def idcv_object(v: 'idc_value_t', icls: 'idc_class_t const *'=None
    ) ->'error_t':
    """Create an IDC object. The original value of 'v' is discarded (freed). 
        
@param v: variable to hold the object. any previous value will be cleaned
@param icls: ptr to the desired class. nullptr means "object" class this ptr must be returned by add_idc_class() or find_idc_class()
@returns always eOk"""
    return _ida_expr.idcv_object(v, icls)


def move_idcv(dst: 'idc_value_t', src: 'idc_value_t') ->'error_t':
    """Move 'src' to 'dst'. This function is more effective than copy_idcv since it never copies big amounts of data. 
        """
    return _ida_expr.move_idcv(dst, src)


def copy_idcv(dst: 'idc_value_t', src: 'idc_value_t') ->'error_t':
    """Copy 'src' to 'dst'. For idc objects only a reference is copied. 
        """
    return _ida_expr.copy_idcv(dst, src)


def deep_copy_idcv(dst: 'idc_value_t', src: 'idc_value_t') ->'error_t':
    """Deep copy an IDC object. This function performs deep copy of idc objects. If 'src' is not an object, copy_idcv() will be called 
        """
    return _ida_expr.deep_copy_idcv(dst, src)


def free_idcv(v: 'idc_value_t') ->None:
    """Free storage used by VT_STR/VT_OBJ IDC variables. After this call the variable has a numeric value 0 
        """
    return _ida_expr.free_idcv(v)


def swap_idcvs(v1: 'idc_value_t', v2: 'idc_value_t') ->None:
    """Swap 2 variables.
"""
    return _ida_expr.swap_idcvs(v1, v2)


def get_idcv_class_name(obj: 'idc_value_t') ->str:
    """Retrieves the IDC object class name. 
        
@param obj: class instance variable
@returns error code, eOk on success"""
    return _ida_expr.get_idcv_class_name(obj)


def get_idcv_attr(res: 'idc_value_t', obj: 'idc_value_t', attr: str,
    may_use_getattr: bool=False) ->'error_t':
    """Get an object attribute. 
        
@param res: buffer for the attribute value
@param obj: variable that holds an object reference. if obj is nullptr it searches global variables, then user functions
@param attr: attribute name
@param may_use_getattr: may call getattr functions to calculate the attribute if it does not exist
@returns error code, eOk on success"""
    return _ida_expr.get_idcv_attr(res, obj, attr, may_use_getattr)


def set_idcv_attr(obj: 'idc_value_t', attr: str, value: 'idc_value_t',
    may_use_setattr: bool=False) ->'error_t':
    """Set an object attribute. 
        
@param obj: variable that holds an object reference. if obj is nullptr then it tries to modify a global variable with the attribute name
@param attr: attribute name
@param value: new attribute value
@param may_use_setattr: may call setattr functions for the class
@returns error code, eOk on success"""
    return _ida_expr.set_idcv_attr(obj, attr, value, may_use_setattr)


def del_idcv_attr(obj: 'idc_value_t', attr: str) ->'error_t':
    """Delete an object attribute. 
        
@param obj: variable that holds an object reference
@param attr: attribute name
@returns error code, eOk on success"""
    return _ida_expr.del_idcv_attr(obj, attr)


def first_idcv_attr(obj: 'idc_value_t') ->str:
    return _ida_expr.first_idcv_attr(obj)


def last_idcv_attr(obj: 'idc_value_t') ->str:
    return _ida_expr.last_idcv_attr(obj)


def next_idcv_attr(obj: 'idc_value_t', attr: str) ->str:
    return _ida_expr.next_idcv_attr(obj, attr)


def prev_idcv_attr(obj: 'idc_value_t', attr: str) ->str:
    return _ida_expr.prev_idcv_attr(obj, attr)


def print_idcv(v: 'idc_value_t', name: str=None, indent: int=0) ->str:
    """Get text representation of idc_value_t.
"""
    return _ida_expr.print_idcv(v, name, indent)


def get_idcv_slice(res: 'idc_value_t', v: 'idc_value_t', i1: int, i2: int,
    flags: int=0) ->'error_t':
    """Get slice. 
        
@param res: output variable that will contain the slice
@param v: input variable (string or object)
@param i1: slice start index
@param i2: slice end index (excluded)
@param flags: IDC variable slice flags or 0
@returns eOk if success"""
    return _ida_expr.get_idcv_slice(res, v, i1, i2, flags)


VARSLICE_SINGLE = _ida_expr.VARSLICE_SINGLE
"""return single index (i2 is ignored)
"""


def set_idcv_slice(v: 'idc_value_t', i1: int, i2: int, _in: 'idc_value_t',
    flags: int=0) ->'error_t':
    """Set slice. 
        
@param v: variable to modify (string or object)
@param i1: slice start index
@param i2: slice end index (excluded)
@param flags: IDC variable slice flags or 0
@returns eOk on success"""
    return _ida_expr.set_idcv_slice(v, i1, i2, _in, flags)


def add_idc_class(name: str, super: 'idc_class_t const *'=None
    ) ->'idc_class_t *':
    """Create a new IDC class. 
        
@param name: name of the new class
@param super: the base class for the new class. if the new class is not based on any other class, pass nullptr
@returns pointer to the created class. If such a class already exists, a pointer to it will be returned. Pointers to other existing classes may be invalidated by this call."""
    return _ida_expr.add_idc_class(name, super)


def find_idc_class(name: str) ->'idc_class_t *':
    """Find an existing IDC class by its name. 
        
@param name: name of the class
@returns pointer to the class or nullptr. The returned pointer is valid until a new call to add_idc_class()"""
    return _ida_expr.find_idc_class(name)


def deref_idcv(v: 'idc_value_t', vref_flags: int) ->'idc_value_t *':
    """Dereference a VT_REF variable. 
        
@param v: variable to dereference
@param vref_flags: Dereference IDC variable flags
@returns pointer to the dereference result or nullptr. If returns nullptr, qerrno is set to eExecBadRef "Illegal variable reference\""""
    return _ida_expr.deref_idcv(v, vref_flags)


VREF_LOOP = _ida_expr.VREF_LOOP
"""dereference until we get a non VT_REF
"""
VREF_ONCE = _ida_expr.VREF_ONCE
"""dereference only once, do not loop
"""
VREF_COPY = _ida_expr.VREF_COPY
"""copy the result to the input var (v)
"""


def create_idcv_ref(ref: 'idc_value_t', v: 'idc_value_t') ->bool:
    """Create a variable reference. Currently only references to global variables can be created. 
        
@param ref: ptr to the result
@param v: variable to reference
@returns success"""
    return _ida_expr.create_idcv_ref(ref, v)


def add_idc_gvar(name: str) ->'idc_value_t *':
    """Add global IDC variable. 
        
@param name: name of the global variable
@returns pointer to the created variable or existing variable. NB: the returned pointer is valid until a new global var is added."""
    return _ida_expr.add_idc_gvar(name)


def find_idc_gvar(name: str) ->'idc_value_t *':
    """Find an existing global IDC variable by its name. 
        
@param name: name of the global variable
@returns pointer to the variable or nullptr. NB: the returned pointer is valid until a new global var is added. FIXME: it is difficult to use this function in a thread safe manner"""
    return _ida_expr.find_idc_gvar(name)


class idc_value_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    vtype: 'char' = property(_ida_expr.idc_value_t_vtype_get, _ida_expr.
        idc_value_t_vtype_set)
    """IDC value types
"""
    num: 'sval_t' = property(_ida_expr.idc_value_t_num_get, _ida_expr.
        idc_value_t_num_set)
    """VT_LONG
"""
    e: 'fpvalue_t' = property(_ida_expr.idc_value_t_e_get, _ida_expr.
        idc_value_t_e_set)
    """VT_FLOAT
"""
    obj: 'idc_object_t *' = property(_ida_expr.idc_value_t_obj_get,
        _ida_expr.idc_value_t_obj_set)
    funcidx: 'int' = property(_ida_expr.idc_value_t_funcidx_get, _ida_expr.
        idc_value_t_funcidx_set)
    """VT_FUNC
"""
    pvoid: 'void *' = property(_ida_expr.idc_value_t_pvoid_get, _ida_expr.
        idc_value_t_pvoid_set)
    """VT_PVOID
"""
    i64: 'int64' = property(_ida_expr.idc_value_t_i64_get, _ida_expr.
        idc_value_t_i64_set)
    """VT_INT64
"""
    reserve: 'uchar [sizeof(qstring)]' = property(_ida_expr.
        idc_value_t_reserve_get, _ida_expr.idc_value_t_reserve_set)
    """VT_STR.
"""

    def __init__(self, *args):
        _ida_expr.idc_value_t_swiginit(self, _ida_expr.new_idc_value_t(*args))
    __swig_destroy__ = _ida_expr.delete_idc_value_t

    def clear(self) ->None:
        """See free_idcv()
"""
        return _ida_expr.idc_value_t_clear(self)

    def qstr(self) ->str:
        """VT_STR
"""
        return _ida_expr.idc_value_t_qstr(self)

    def c_str(self) ->str:
        """VT_STR
"""
        return _ida_expr.idc_value_t_c_str(self)

    def u_str(self) ->'uchar const *':
        """VT_STR
"""
        return _ida_expr.idc_value_t_u_str(self)

    def swap(self, v: 'idc_value_t') ->None:
        """Set this = r and v = this.
"""
        return _ida_expr.idc_value_t_swap(self, v)

    def is_zero(self) ->bool:
        """Does value represent the integer 0?
"""
        return _ida_expr.idc_value_t_is_zero(self)

    def is_integral(self) ->bool:
        """Does value represent a whole number? 
        """
        return _ida_expr.idc_value_t_is_integral(self)

    def is_convertible(self) ->bool:
        """Convertible types are VT_LONG, VT_FLOAT, VT_INT64, and VT_STR.
"""
        return _ida_expr.idc_value_t_is_convertible(self)

    def _create_empty_string(self) ->None:
        return _ida_expr.idc_value_t__create_empty_string(self)

    def create_empty_string(self) ->None:
        return _ida_expr.idc_value_t_create_empty_string(self)

    def set_string(self, *args) ->None:
        return _ida_expr.idc_value_t_set_string(self, *args)

    def set_long(self, v: int) ->None:
        return _ida_expr.idc_value_t_set_long(self, v)

    def set_pvoid(self, p: 'void *') ->None:
        return _ida_expr.idc_value_t_set_pvoid(self, p)

    def set_int64(self, v: 'int64') ->None:
        return _ida_expr.idc_value_t_set_int64(self, v)

    def set_float(self, f: 'fpvalue_t const &') ->None:
        return _ida_expr.idc_value_t_set_float(self, f)
    str = property(lambda self: self.c_str(), lambda self, v: self.
        set_string(v))


_ida_expr.idc_value_t_swigregister(idc_value_t)
VT_LONG = _ida_expr.VT_LONG
"""Integer (see idc_value_t::num)
"""
VT_FLOAT = _ida_expr.VT_FLOAT
"""Floating point (see idc_value_t::e)
"""
VT_WILD = _ida_expr.VT_WILD
"""Function with arbitrary number of arguments. The actual number of arguments will be passed in idc_value_t::num. This value should not be used for idc_value_t. 
        """
VT_OBJ = _ida_expr.VT_OBJ
"""Object (see idc_value_t::obj)
"""
VT_FUNC = _ida_expr.VT_FUNC
"""Function (see idc_value_t::funcidx)
"""
VT_STR = _ida_expr.VT_STR
"""String (see qstr() and similar functions)
"""
VT_PVOID = _ida_expr.VT_PVOID
"""void *
"""
VT_INT64 = _ida_expr.VT_INT64
"""i64
"""
VT_REF = _ida_expr.VT_REF
"""Reference.
"""


class idc_global_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    name: 'qstring' = property(_ida_expr.idc_global_t_name_get, _ida_expr.
        idc_global_t_name_set)
    value: 'idc_value_t' = property(_ida_expr.idc_global_t_value_get,
        _ida_expr.idc_global_t_value_set)

    def __init__(self, *args):
        _ida_expr.idc_global_t_swiginit(self, _ida_expr.new_idc_global_t(*args)
            )
    __swig_destroy__ = _ida_expr.delete_idc_global_t


_ida_expr.idc_global_t_swigregister(idc_global_t)
eExecThrow = _ida_expr.eExecThrow
"""See return value of idc_func_t.
"""


def find_idc_func(prefix: str, n: int=0) ->str:
    return _ida_expr.find_idc_func(prefix, n)


HF_DEFAULT = _ida_expr.HF_DEFAULT
HF_KEYWORD1 = _ida_expr.HF_KEYWORD1
HF_KEYWORD2 = _ida_expr.HF_KEYWORD2
HF_KEYWORD3 = _ida_expr.HF_KEYWORD3
HF_STRING = _ida_expr.HF_STRING
HF_COMMENT = _ida_expr.HF_COMMENT
HF_PREPROC = _ida_expr.HF_PREPROC
HF_NUMBER = _ida_expr.HF_NUMBER
HF_USER1 = _ida_expr.HF_USER1
HF_USER2 = _ida_expr.HF_USER2
HF_USER3 = _ida_expr.HF_USER3
HF_USER4 = _ida_expr.HF_USER4
HF_MAX = _ida_expr.HF_MAX


class highlighter_cbs_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    __swig_destroy__ = _ida_expr.delete_highlighter_cbs_t

    def set_style(self, arg0: int, arg1: int, arg2: 'syntax_highlight_style'
        ) ->None:
        return _ida_expr.highlighter_cbs_t_set_style(self, arg0, arg1, arg2)

    def prev_block_state(self) ->int:
        return _ida_expr.highlighter_cbs_t_prev_block_state(self)

    def cur_block_state(self) ->int:
        return _ida_expr.highlighter_cbs_t_cur_block_state(self)

    def set_block_state(self, arg0: int) ->None:
        return _ida_expr.highlighter_cbs_t_set_block_state(self, arg0)

    def __init__(self):
        if self.__class__ == highlighter_cbs_t:
            _self = None
        else:
            _self = self
        _ida_expr.highlighter_cbs_t_swiginit(self, _ida_expr.
            new_highlighter_cbs_t(_self))

    def __disown__(self):
        self.this.disown()
        _ida_expr.disown_highlighter_cbs_t(self)
        return weakref.proxy(self)


_ida_expr.highlighter_cbs_t_swigregister(highlighter_cbs_t)


def set_header_path(path: str, add: bool) ->bool:
    """Set or append a header path. IDA looks for the include files in the appended header paths, then in the ida executable directory. 
        
@param path: list of directories to add (separated by ';') may be nullptr, in this case nothing is added
@param add: true: append. false: remove old paths.
@retval true: success
@retval false: no memory"""
    return _ida_expr.set_header_path(path, add)


def get_idc_filename(file: str) ->str:
    """Get full name of IDC file name. Search for file in list of include directories, IDCPATH directory and system directories. 
        
@param file: file name without full path
@returns nullptr is file not found. otherwise returns pointer to buf"""
    return _ida_expr.get_idc_filename(file)


def exec_system_script(file: str, complain_if_no_file: bool=True) ->bool:
    """Compile and execute "main" function from system file. 
        
@param file: file name with IDC function(s). The file will be searched using get_idc_filename().
@param complain_if_no_file: * 1: display warning if the file is not found
* 0: don't complain if file doesn't exist
@retval 1: ok, file is compiled and executed
@retval 0: failure, compilation or execution error, warning is displayed"""
    return _ida_expr.exec_system_script(file, complain_if_no_file)


CPL_DEL_MACROS = _ida_expr.CPL_DEL_MACROS
"""delete macros at the end of compilation
"""
CPL_USE_LABELS = _ida_expr.CPL_USE_LABELS
"""allow program labels in the script
"""
CPL_ONLY_SAFE = _ida_expr.CPL_ONLY_SAFE
"""allow calls of only thread-safe functions
"""


def compile_idc_snippet(func: str, text: str, resolver: 'idc_resolver_t *'=
    None, only_safe_funcs: bool=False) ->str:
    """Compile text with IDC statements. 
        
@param func: name of the function to create out of the snippet
@param text: text to compile
@param resolver: callback object to get values of undefined variables This object will be called if IDC function contains references to undefined variables. May be nullptr.
@param only_safe_funcs: if true, any calls to functions without EXTFUN_SAFE flag will lead to a compilation error.
@retval true: ok
@retval false: error, see errbuf"""
    return _ida_expr.compile_idc_snippet(func, text, resolver, only_safe_funcs)


def exec_idc_script(result: 'idc_value_t', path: str, func: str, args:
    'idc_value_t', argsnum: 'size_t') ->str:
    """Compile and execute IDC function(s) from file. 
        
@param result: ptr to idc_value_t to hold result of the function. If execution fails, this variable will contain the exception information. You may pass nullptr if you are not interested in the returned value.
@param path: text file containing text of IDC functions
@param func: function name to execute
@param args: array of parameters
@param argsnum: number of parameters to pass to 'fname' This number should be equal to number of parameters the function expects.
@retval true: ok
@retval false: error, see errbuf"""
    return _ida_expr.exec_idc_script(result, path, func, args, argsnum)


def throw_idc_exception(r: 'idc_value_t', desc: str) ->'error_t':
    """Create an idc execution exception object. This helper function can be used to return an exception from C++ code to IDC. In other words this function can be called from idc_func_t() callbacks. Sample usage: if ( !ok ) return throw_idc_exception(r, "detailed error msg"); 
        
@param r: object to hold the exception object
@param desc: exception description
@returns eExecThrow"""
    return _ida_expr.throw_idc_exception(r, desc)


class idc_values_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        _ida_expr.idc_values_t_swiginit(self, _ida_expr.new_idc_values_t(*args)
            )
    __swig_destroy__ = _ida_expr.delete_idc_values_t

    def push_back(self, *args) ->'idc_value_t &':
        return _ida_expr.idc_values_t_push_back(self, *args)

    def pop_back(self) ->None:
        return _ida_expr.idc_values_t_pop_back(self)

    def size(self) ->'size_t':
        return _ida_expr.idc_values_t_size(self)

    def empty(self) ->bool:
        return _ida_expr.idc_values_t_empty(self)

    def at(self, _idx: 'size_t') ->'idc_value_t const &':
        return _ida_expr.idc_values_t_at(self, _idx)

    def qclear(self) ->None:
        return _ida_expr.idc_values_t_qclear(self)

    def clear(self) ->None:
        return _ida_expr.idc_values_t_clear(self)

    def resize(self, *args) ->None:
        return _ida_expr.idc_values_t_resize(self, *args)

    def grow(self, *args) ->None:
        return _ida_expr.idc_values_t_grow(self, *args)

    def capacity(self) ->'size_t':
        return _ida_expr.idc_values_t_capacity(self)

    def reserve(self, cnt: 'size_t') ->None:
        return _ida_expr.idc_values_t_reserve(self, cnt)

    def truncate(self) ->None:
        return _ida_expr.idc_values_t_truncate(self)

    def swap(self, r: 'idc_values_t') ->None:
        return _ida_expr.idc_values_t_swap(self, r)

    def extract(self) ->'idc_value_t *':
        return _ida_expr.idc_values_t_extract(self)

    def inject(self, s: 'idc_value_t', len: 'size_t') ->None:
        return _ida_expr.idc_values_t_inject(self, s, len)

    def begin(self, *args) ->'qvector< idc_value_t >::const_iterator':
        return _ida_expr.idc_values_t_begin(self, *args)

    def end(self, *args) ->'qvector< idc_value_t >::const_iterator':
        return _ida_expr.idc_values_t_end(self, *args)

    def insert(self, it: 'idc_value_t', x: 'idc_value_t'
        ) ->'qvector< idc_value_t >::iterator':
        return _ida_expr.idc_values_t_insert(self, it, x)

    def erase(self, *args) ->'qvector< idc_value_t >::iterator':
        return _ida_expr.idc_values_t_erase(self, *args)

    def __len__(self) ->'size_t':
        return _ida_expr.idc_values_t___len__(self)

    def __getitem__(self, i: 'size_t') ->'idc_value_t const &':
        return _ida_expr.idc_values_t___getitem__(self, i)

    def __setitem__(self, i: 'size_t', v: 'idc_value_t') ->None:
        return _ida_expr.idc_values_t___setitem__(self, i, v)

    def append(self, x: 'idc_value_t') ->None:
        return _ida_expr.idc_values_t_append(self, x)

    def extend(self, x: 'idc_values_t') ->None:
        return _ida_expr.idc_values_t_extend(self, x)
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator


_ida_expr.idc_values_t_swigregister(idc_values_t)
try:
    import types
    import ctypes
    try:
        _IDCFUNC_CB_T = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p,
            ctypes.c_void_p)
    except:
        _IDCFUNC_CB_T = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p,
            ctypes.c_void_p)
    call_idc_func__ = ctypes.CFUNCTYPE(ctypes.c_long, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_void_p)(_ida_expr.py_get_call_idc_func())
except:

    def call_idc_func__(*args):
        warning('IDC extensions need ctypes library in order to work')
        return 0
    _IDCFUNC_CB_T = None
EXTFUN_BASE = 1
"""requires open database.
"""
"""requires open database"""
EXTFUN_NORET = 2
"""does not return. the interpreter may clean up its state before calling it. 
        """
"""does not return. the interpreter may clean up its state before calling it."""
EXTFUN_SAFE = 4
"""thread safe function. may be called from any thread. 
        """
"""thread safe function. may be called"""


class _IdcFunction(object):
    """
    Internal class that calls pyw_call_idc_func() with a context
    """

    def __init__(self, ctxptr):
        self.ctxptr = ctxptr
        self.cb = _IDCFUNC_CB_T(self)
    fp_ptr = property(lambda self: ctypes.cast(self.cb, ctypes.c_void_p).value)

    def __call__(self, args, res):
        return call_idc_func__(self.ctxptr, args, res)


__IDC_FUNC_CTXS = {}


def del_idc_func(name):
    """Delete an IDC function 
        """
    global __IDC_FUNC_CTXS
    f = __IDC_FUNC_CTXS.get(name, None)
    if f is None:
        return False
    del f.cb
    del __IDC_FUNC_CTXS[name]
    return _ida_expr.pyw_unregister_idc_func(f.ctxptr)


def add_idc_func(name, fp, args, defvals=(), flags=0):
    """Add an IDC function. This function does not modify the predefined kernel functions. Example: 
     error_t idaapi myfunc5(idc_value_t *argv, idc_value_t *res)
    
      msg("myfunc is called with arg0=%a and arg1=%s\\n", argv[0].num, argv[1].str);
      res->num = 5;     // let's return 5
      return eOk;
    
     const char myfunc5_args[] = { VT_LONG, VT_STR, 0 };
     const ext_idcfunc_t myfunc_desc = { "MyFunc5", myfunc5, myfunc5_args, nullptr, 0, EXTFUN_BASE };
    
     after this:
    
    
     there is a new IDC function which can be called like this:
     "test");


        
@returns success"""
    global __IDC_FUNC_CTXS
    f = __IDC_FUNC_CTXS.get(name, None)
    if f is not None:
        del_idc_func(name)
    args = ''.join([chr(x) for x in args])
    if len(defvals) > len(args):
        return False
    vdefvals = idc_values_t()
    if not _ida_expr.pyw_convert_defvals(vdefvals, defvals):
        return False
    ctxptr = _ida_expr.pyw_register_idc_func(name, args, fp)
    if ctxptr == 0:
        return False
    f = _IdcFunction(ctxptr)
    __IDC_FUNC_CTXS[name] = f
    return _ida_expr.py_add_idc_func(name, f.fp_ptr, args, vdefvals, flags)

```
