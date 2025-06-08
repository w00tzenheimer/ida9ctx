```python
"""High level functions that deal with the generation of the disassembled text lines.

This file also contains definitions for the syntax highlighting.
Finally there are functions that deal with anterior/posterior user-defined lines. 
    """
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_lines
else:
    import _ida_lines
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
SWIG_PYTHON_LEGACY_BOOL = _ida_lines.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi
COLOR_ON = _ida_lines.COLOR_ON
"""Escape character (ON). Followed by a color code (color_t). 
        """
COLOR_OFF = _ida_lines.COLOR_OFF
"""Escape character (OFF). Followed by a color code (color_t). 
        """
COLOR_ESC = _ida_lines.COLOR_ESC
"""Escape character (Quote next character). This is needed to output '\\1' and '\\2' characters. 
        """
COLOR_INV = _ida_lines.COLOR_INV
"""Escape character (Inverse foreground and background colors). This escape character has no corresponding COLOR_OFF. Its action continues until the next COLOR_INV or end of line. 
        """
SCOLOR_ON = _ida_lines.SCOLOR_ON
"""Escape character (ON)
"""
SCOLOR_OFF = _ida_lines.SCOLOR_OFF
"""Escape character (OFF)
"""
SCOLOR_ESC = _ida_lines.SCOLOR_ESC
"""Escape character (Quote next character)
"""
SCOLOR_INV = _ida_lines.SCOLOR_INV
"""Escape character (Inverse colors)
"""
SCOLOR_DEFAULT = _ida_lines.SCOLOR_DEFAULT
"""Default.
"""
SCOLOR_REGCMT = _ida_lines.SCOLOR_REGCMT
"""Regular comment.
"""
SCOLOR_RPTCMT = _ida_lines.SCOLOR_RPTCMT
"""Repeatable comment (defined not here)
"""
SCOLOR_AUTOCMT = _ida_lines.SCOLOR_AUTOCMT
"""Automatic comment.
"""
SCOLOR_INSN = _ida_lines.SCOLOR_INSN
"""Instruction.
"""
SCOLOR_DATNAME = _ida_lines.SCOLOR_DATNAME
"""Dummy Data Name.
"""
SCOLOR_DNAME = _ida_lines.SCOLOR_DNAME
"""Regular Data Name.
"""
SCOLOR_DEMNAME = _ida_lines.SCOLOR_DEMNAME
"""Demangled Name.
"""
SCOLOR_SYMBOL = _ida_lines.SCOLOR_SYMBOL
"""Punctuation.
"""
SCOLOR_CHAR = _ida_lines.SCOLOR_CHAR
"""Char constant in instruction.
"""
SCOLOR_STRING = _ida_lines.SCOLOR_STRING
"""String constant in instruction.
"""
SCOLOR_NUMBER = _ida_lines.SCOLOR_NUMBER
"""Numeric constant in instruction.
"""
SCOLOR_VOIDOP = _ida_lines.SCOLOR_VOIDOP
"""Void operand.
"""
SCOLOR_CREF = _ida_lines.SCOLOR_CREF
"""Code reference.
"""
SCOLOR_DREF = _ida_lines.SCOLOR_DREF
"""Data reference.
"""
SCOLOR_CREFTAIL = _ida_lines.SCOLOR_CREFTAIL
"""Code reference to tail byte.
"""
SCOLOR_DREFTAIL = _ida_lines.SCOLOR_DREFTAIL
"""Data reference to tail byte.
"""
SCOLOR_ERROR = _ida_lines.SCOLOR_ERROR
"""Error or problem.
"""
SCOLOR_PREFIX = _ida_lines.SCOLOR_PREFIX
"""Line prefix.
"""
SCOLOR_BINPREF = _ida_lines.SCOLOR_BINPREF
"""Binary line prefix bytes.
"""
SCOLOR_EXTRA = _ida_lines.SCOLOR_EXTRA
"""Extra line.
"""
SCOLOR_ALTOP = _ida_lines.SCOLOR_ALTOP
"""Alternative operand.
"""
SCOLOR_HIDNAME = _ida_lines.SCOLOR_HIDNAME
"""Hidden name.
"""
SCOLOR_LIBNAME = _ida_lines.SCOLOR_LIBNAME
"""Library function name.
"""
SCOLOR_LOCNAME = _ida_lines.SCOLOR_LOCNAME
"""Local variable name.
"""
SCOLOR_CODNAME = _ida_lines.SCOLOR_CODNAME
"""Dummy code name.
"""
SCOLOR_ASMDIR = _ida_lines.SCOLOR_ASMDIR
"""Assembler directive.
"""
SCOLOR_MACRO = _ida_lines.SCOLOR_MACRO
"""Macro.
"""
SCOLOR_DSTR = _ida_lines.SCOLOR_DSTR
"""String constant in data directive.
"""
SCOLOR_DCHAR = _ida_lines.SCOLOR_DCHAR
"""Char constant in data directive.
"""
SCOLOR_DNUM = _ida_lines.SCOLOR_DNUM
"""Numeric constant in data directive.
"""
SCOLOR_KEYWORD = _ida_lines.SCOLOR_KEYWORD
"""Keywords.
"""
SCOLOR_REG = _ida_lines.SCOLOR_REG
"""Register name.
"""
SCOLOR_IMPNAME = _ida_lines.SCOLOR_IMPNAME
"""Imported name.
"""
SCOLOR_SEGNAME = _ida_lines.SCOLOR_SEGNAME
"""Segment name.
"""
SCOLOR_UNKNAME = _ida_lines.SCOLOR_UNKNAME
"""Dummy unknown name.
"""
SCOLOR_CNAME = _ida_lines.SCOLOR_CNAME
"""Regular code name.
"""
SCOLOR_UNAME = _ida_lines.SCOLOR_UNAME
"""Regular unknown name.
"""
SCOLOR_COLLAPSED = _ida_lines.SCOLOR_COLLAPSED
"""Collapsed line.
"""
SCOLOR_ADDR = _ida_lines.SCOLOR_ADDR
"""Hidden address mark.
"""
COLOR_SELECTED = _ida_lines.COLOR_SELECTED
"""Selected.
"""
COLOR_LIBFUNC = _ida_lines.COLOR_LIBFUNC
"""Library function.
"""
COLOR_REGFUNC = _ida_lines.COLOR_REGFUNC
"""Regular function.
"""
COLOR_CODE = _ida_lines.COLOR_CODE
"""Single instruction.
"""
COLOR_DATA = _ida_lines.COLOR_DATA
"""Data bytes.
"""
COLOR_UNKNOWN = _ida_lines.COLOR_UNKNOWN
"""Unexplored byte.
"""
COLOR_EXTERN = _ida_lines.COLOR_EXTERN
"""External name definition segment.
"""
COLOR_CURITEM = _ida_lines.COLOR_CURITEM
"""Current item.
"""
COLOR_CURLINE = _ida_lines.COLOR_CURLINE
"""Current line.
"""
COLOR_HIDLINE = _ida_lines.COLOR_HIDLINE
"""Hidden line.
"""
COLOR_LUMFUNC = _ida_lines.COLOR_LUMFUNC
"""Lumina function.
"""
COLOR_BG_MAX = _ida_lines.COLOR_BG_MAX
"""Max color number.
"""


def tag_strlen(line: str) ->'ssize_t':
    """Calculate length of a colored string This function computes the length in unicode codepoints of a line 
        
@returns the number of codepoints in the line, or -1 on error"""
    return _ida_lines.tag_strlen(line)


def calc_prefix_color(ea: ida_idaapi.ea_t) ->'color_t':
    """Get prefix color for line at 'ea' 
        
@returns Line prefix colors"""
    return _ida_lines.calc_prefix_color(ea)


def calc_bg_color(ea: ida_idaapi.ea_t) ->'bgcolor_t':
    """Get background color for line at 'ea' 
        
@returns RGB color"""
    return _ida_lines.calc_bg_color(ea)


def add_sourcefile(ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t, filename: str
    ) ->bool:
    return _ida_lines.add_sourcefile(ea1, ea2, filename)


def get_sourcefile(ea: ida_idaapi.ea_t, bounds: 'range_t'=None) ->str:
    return _ida_lines.get_sourcefile(ea, bounds)


def del_sourcefile(ea: ida_idaapi.ea_t) ->bool:
    return _ida_lines.del_sourcefile(ea)


def install_user_defined_prefix(*args) ->bool:
    return _ida_lines.install_user_defined_prefix(*args)


class user_defined_prefix_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def __init__(self, *args):
        if self.__class__ == user_defined_prefix_t:
            _self = None
        else:
            _self = self
        _ida_lines.user_defined_prefix_t_swiginit(self, _ida_lines.
            new_user_defined_prefix_t(_self, *args))
    __swig_destroy__ = _ida_lines.delete_user_defined_prefix_t

    def get_user_defined_prefix(self, ea: ida_idaapi.ea_t, insn:
        'insn_t const &', lnnum: int, indent: int, line: str) ->None:
        """This callback must be overridden by the derived class. 
        
@param ea: the current address
@param insn: the current instruction. if the current item is not an instruction, then insn.itype is zero.
@param lnnum: number of the current line (each address may have several listing lines for it). 0 means the very first line for the current address.
@param indent: see explanations for gen_printf()
@param line: the line to be generated. the line usually contains color tags. this argument can be examined to decide whether to generate the prefix."""
        return _ida_lines.user_defined_prefix_t_get_user_defined_prefix(self,
            ea, insn, lnnum, indent, line)

    def __disown__(self):
        self.this.disown()
        _ida_lines.disown_user_defined_prefix_t(self)
        return weakref.proxy(self)


_ida_lines.user_defined_prefix_t_swigregister(user_defined_prefix_t)
cvar = _ida_lines.cvar
COLOR_DEFAULT = cvar.COLOR_DEFAULT
"""Default.
"""
COLOR_REGCMT = cvar.COLOR_REGCMT
"""Regular comment.
"""
COLOR_RPTCMT = cvar.COLOR_RPTCMT
"""Repeatable comment (comment defined somewhere else)
"""
COLOR_AUTOCMT = cvar.COLOR_AUTOCMT
"""Automatic comment.
"""
COLOR_INSN = cvar.COLOR_INSN
"""Instruction.
"""
COLOR_DATNAME = cvar.COLOR_DATNAME
"""Dummy Data Name.
"""
COLOR_DNAME = cvar.COLOR_DNAME
"""Regular Data Name.
"""
COLOR_DEMNAME = cvar.COLOR_DEMNAME
"""Demangled Name.
"""
COLOR_SYMBOL = cvar.COLOR_SYMBOL
"""Punctuation.
"""
COLOR_CHAR = cvar.COLOR_CHAR
"""Char constant in instruction.
"""
COLOR_STRING = cvar.COLOR_STRING
"""String constant in instruction.
"""
COLOR_NUMBER = cvar.COLOR_NUMBER
"""Numeric constant in instruction.
"""
COLOR_VOIDOP = cvar.COLOR_VOIDOP
"""Void operand.
"""
COLOR_CREF = cvar.COLOR_CREF
"""Code reference.
"""
COLOR_DREF = cvar.COLOR_DREF
"""Data reference.
"""
COLOR_CREFTAIL = cvar.COLOR_CREFTAIL
"""Code reference to tail byte.
"""
COLOR_DREFTAIL = cvar.COLOR_DREFTAIL
"""Data reference to tail byte.
"""
COLOR_ERROR = cvar.COLOR_ERROR
"""Error or problem.
"""
COLOR_PREFIX = cvar.COLOR_PREFIX
"""Line prefix.
"""
COLOR_BINPREF = cvar.COLOR_BINPREF
"""Binary line prefix bytes.
"""
COLOR_EXTRA = cvar.COLOR_EXTRA
"""Extra line.
"""
COLOR_ALTOP = cvar.COLOR_ALTOP
"""Alternative operand.
"""
COLOR_HIDNAME = cvar.COLOR_HIDNAME
"""Hidden name.
"""
COLOR_LIBNAME = cvar.COLOR_LIBNAME
"""Library function name.
"""
COLOR_LOCNAME = cvar.COLOR_LOCNAME
"""Local variable name.
"""
COLOR_CODNAME = cvar.COLOR_CODNAME
"""Dummy code name.
"""
COLOR_ASMDIR = cvar.COLOR_ASMDIR
"""Assembler directive.
"""
COLOR_MACRO = cvar.COLOR_MACRO
"""Macro.
"""
COLOR_DSTR = cvar.COLOR_DSTR
"""String constant in data directive.
"""
COLOR_DCHAR = cvar.COLOR_DCHAR
"""Char constant in data directive.
"""
COLOR_DNUM = cvar.COLOR_DNUM
"""Numeric constant in data directive.
"""
COLOR_KEYWORD = cvar.COLOR_KEYWORD
"""Keywords.
"""
COLOR_REG = cvar.COLOR_REG
"""Register name.
"""
COLOR_IMPNAME = cvar.COLOR_IMPNAME
"""Imported name.
"""
COLOR_SEGNAME = cvar.COLOR_SEGNAME
"""Segment name.
"""
COLOR_UNKNAME = cvar.COLOR_UNKNAME
"""Dummy unknown name.
"""
COLOR_CNAME = cvar.COLOR_CNAME
"""Regular code name.
"""
COLOR_UNAME = cvar.COLOR_UNAME
"""Regular unknown name.
"""
COLOR_COLLAPSED = cvar.COLOR_COLLAPSED
"""Collapsed line.
"""
COLOR_FG_MAX = cvar.COLOR_FG_MAX
"""Max color number.
"""
COLOR_ADDR = cvar.COLOR_ADDR
"""hidden address marks. the address is represented as 8digit hex number: 01234567. it doesn't have COLOR_OFF pair. NB: for 64-bit IDA, the address is 16digit. 
        """
COLOR_OPND1 = cvar.COLOR_OPND1
"""Instruction operand 1.
"""
COLOR_OPND2 = cvar.COLOR_OPND2
"""Instruction operand 2.
"""
COLOR_OPND3 = cvar.COLOR_OPND3
"""Instruction operand 3.
"""
COLOR_OPND4 = cvar.COLOR_OPND4
"""Instruction operand 4.
"""
COLOR_OPND5 = cvar.COLOR_OPND5
"""Instruction operand 5.
"""
COLOR_OPND6 = cvar.COLOR_OPND6
"""Instruction operand 6.
"""
COLOR_OPND7 = cvar.COLOR_OPND7
"""Instruction operand 7.
"""
COLOR_OPND8 = cvar.COLOR_OPND8
"""Instruction operand 8.
"""
COLOR_RESERVED1 = cvar.COLOR_RESERVED1
"""This tag is reserved for internal IDA use.
"""
COLOR_LUMINA = cvar.COLOR_LUMINA
"""Lumina-related, only for the navigation band.
"""
VEL_POST = _ida_lines.VEL_POST
"""append posterior line
"""
VEL_CMT = _ida_lines.VEL_CMT
"""append comment line
"""


def add_extra_line(*args) ->bool:
    return _ida_lines.add_extra_line(*args)


def add_extra_cmt(*args) ->bool:
    return _ida_lines.add_extra_cmt(*args)


def add_pgm_cmt(*args) ->bool:
    return _ida_lines.add_pgm_cmt(*args)


GDISMF_AS_STACK = _ida_lines.GDISMF_AS_STACK
GDISMF_ADDR_TAG = _ida_lines.GDISMF_ADDR_TAG


def generate_disasm_line(ea: ida_idaapi.ea_t, flags: int=0) ->str:
    return _ida_lines.generate_disasm_line(ea, flags)


GENDSM_FORCE_CODE = _ida_lines.GENDSM_FORCE_CODE
GENDSM_MULTI_LINE = _ida_lines.GENDSM_MULTI_LINE
GENDSM_REMOVE_TAGS = _ida_lines.GENDSM_REMOVE_TAGS


def get_first_free_extra_cmtidx(ea: ida_idaapi.ea_t, start: int) ->int:
    return _ida_lines.get_first_free_extra_cmtidx(ea, start)


def update_extra_cmt(ea: ida_idaapi.ea_t, what: int, str: str) ->bool:
    return _ida_lines.update_extra_cmt(ea, what, str)


def del_extra_cmt(ea: ida_idaapi.ea_t, what: int) ->bool:
    return _ida_lines.del_extra_cmt(ea, what)


def get_extra_cmt(ea: ida_idaapi.ea_t, what: int) ->int:
    return _ida_lines.get_extra_cmt(ea, what)


def delete_extra_cmts(ea: ida_idaapi.ea_t, what: int) ->None:
    return _ida_lines.delete_extra_cmts(ea, what)


def create_encoding_helper(*args) ->'encoder_t *':
    return _ida_lines.create_encoding_helper(*args)


def tag_remove(nonnul_instr: str) ->str:
    """Remove color escape sequences from a string. 
        
@returns length of resulting string, -1 if error"""
    return _ida_lines.tag_remove(nonnul_instr)


def tag_addr(ea: ida_idaapi.ea_t) ->str:
    """Insert an address mark into a string. 
        
@param ea: address to include"""
    return _ida_lines.tag_addr(ea)


def tag_skipcode(line: str) ->int:
    """Skip one color code. This function should be used if you are interested in color codes and want to analyze all of them. Otherwise tag_skipcodes() function is better since it will skip all colors at once. This function will skip the current color code if there is one. If the current symbol is not a color code, it will return the input. 
        
@returns moved pointer"""
    return _ida_lines.tag_skipcode(line)


def tag_skipcodes(line: str) ->int:
    """Move the pointer past all color codes. 
        
@param line: can't be nullptr
@returns moved pointer, can't be nullptr"""
    return _ida_lines.tag_skipcodes(line)


def tag_advance(line: str, cnt: int) ->int:
    """Move pointer to a 'line' to 'cnt' positions right. Take into account escape sequences. 
        
@param line: pointer to string
@param cnt: number of positions to move right
@returns moved pointer"""
    return _ida_lines.tag_advance(line, cnt)


def generate_disassembly(ea, max_lines, as_stack, notags):
    """Generate disassembly lines (many lines) and put them into a buffer

@param ea: address to generate disassembly for
@param max_lines: how many lines max to generate
@param as_stack: Display undefined items as 2/4/8 bytes
@return:
    - None on failure
    - tuple(most_important_line_number, list(lines)) : Returns a tuple containing
      the most important line number and a list of generated lines"""
    return _ida_lines.generate_disassembly(ea, max_lines, as_stack, notags)


import _ida_idaapi
import _ida_lines
COLOR_ADDR_SIZE = 16 if _ida_idaapi.BADADDR == 18446744073709551615 else 8
"""Size of a tagged address (see COLOR_ADDR)
"""
SCOLOR_FG_MAX = '('
cvar = _ida_lines.cvar
SCOLOR_OPND1 = chr(cvar.COLOR_ADDR + 1)
SCOLOR_OPND2 = chr(cvar.COLOR_ADDR + 2)
SCOLOR_OPND3 = chr(cvar.COLOR_ADDR + 3)
SCOLOR_OPND4 = chr(cvar.COLOR_ADDR + 4)
SCOLOR_OPND5 = chr(cvar.COLOR_ADDR + 5)
SCOLOR_OPND6 = chr(cvar.COLOR_ADDR + 6)
SCOLOR_UTF8 = chr(cvar.COLOR_ADDR + 10)
PALETTE_SIZE = cvar.COLOR_FG_MAX + _ida_lines.COLOR_BG_MAX


def requires_color_esc(c):
    """Is the given char a color escape character?
"""
    t = ord(c[0])
    return c >= COLOR_ON and c <= COLOR_INV


def COLSTR(str, tag):
    """
    Utility function to create a colored line
    @param str: The string
    @param tag: Color tag constant. One of SCOLOR_XXXX
    """
    return SCOLOR_ON + tag + str + SCOLOR_OFF + tag


E_PREV = cvar.E_PREV
E_NEXT = cvar.E_NEXT

```
