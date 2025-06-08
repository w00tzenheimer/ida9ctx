```python
"""Contains the ::inf structure definition and some functions common to the whole IDA project.

The ::inf structure is saved in the database and contains information specific to the current program being disassembled. Initially it is filled with values from ida.cfg.
Although it is not a good idea to change values in ::inf structure (because you will overwrite values taken from ida.cfg), you are allowed to do it if you feel it necessary. 
    """
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_ida
else:
    import _ida_ida
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
SWIG_PYTHON_LEGACY_BOOL = _ida_ida.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi
AF_FINAL = _ida_ida.AF_FINAL
"""Final pass of analysis.
"""
f_EXE_old = _ida_ida.f_EXE_old
"""MS DOS EXE File.
"""
f_COM_old = _ida_ida.f_COM_old
"""MS DOS COM File.
"""
f_BIN = _ida_ida.f_BIN
"""Binary File.
"""
f_DRV = _ida_ida.f_DRV
"""MS DOS Driver.
"""
f_WIN = _ida_ida.f_WIN
"""New Executable (NE)
"""
f_HEX = _ida_ida.f_HEX
"""Intel Hex Object File.
"""
f_MEX = _ida_ida.f_MEX
"""MOS Technology Hex Object File.
"""
f_LX = _ida_ida.f_LX
"""Linear Executable (LX)
"""
f_LE = _ida_ida.f_LE
"""Linear Executable (LE)
"""
f_NLM = _ida_ida.f_NLM
"""Netware Loadable Module (NLM)
"""
f_COFF = _ida_ida.f_COFF
"""Common Object File Format (COFF)
"""
f_PE = _ida_ida.f_PE
"""Portable Executable (PE)
"""
f_OMF = _ida_ida.f_OMF
"""Object Module Format.
"""
f_SREC = _ida_ida.f_SREC
"""Motorola SREC (S-record)
"""
f_ZIP = _ida_ida.f_ZIP
"""ZIP file (this file is never loaded to IDA database)
"""
f_OMFLIB = _ida_ida.f_OMFLIB
"""Library of OMF Modules.
"""
f_AR = _ida_ida.f_AR
"""ar library
"""
f_LOADER = _ida_ida.f_LOADER
"""file is loaded using LOADER DLL
"""
f_ELF = _ida_ida.f_ELF
"""Executable and Linkable Format (ELF)
"""
f_W32RUN = _ida_ida.f_W32RUN
"""Watcom DOS32 Extender (W32RUN)
"""
f_AOUT = _ida_ida.f_AOUT
"""Linux a.out (AOUT)
"""
f_PRC = _ida_ida.f_PRC
"""PalmPilot program file.
"""
f_EXE = _ida_ida.f_EXE
"""MS DOS EXE File.
"""
f_COM = _ida_ida.f_COM
"""MS DOS COM File.
"""
f_AIXAR = _ida_ida.f_AIXAR
"""AIX ar library.
"""
f_MACHO = _ida_ida.f_MACHO
"""Mac OS X Mach-O.
"""
f_PSXOBJ = _ida_ida.f_PSXOBJ
"""Sony Playstation PSX object file.
"""
f_MD1IMG = _ida_ida.f_MD1IMG
"""Mediatek Firmware Image.
"""


def is_filetype_like_binary(ft: 'filetype_t') ->bool:
    """Is unstructured input file?
"""
    return _ida_ida.is_filetype_like_binary(ft)


class compiler_info_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    id: 'comp_t' = property(_ida_ida.compiler_info_t_id_get, _ida_ida.
        compiler_info_t_id_set)
    """compiler id (see Compiler IDs)
"""
    cm: 'cm_t' = property(_ida_ida.compiler_info_t_cm_get, _ida_ida.
        compiler_info_t_cm_set)
    """memory model and calling convention (see CM)
"""
    size_i: 'uchar' = property(_ida_ida.compiler_info_t_size_i_get,
        _ida_ida.compiler_info_t_size_i_set)
    """sizeof(int)
"""
    size_b: 'uchar' = property(_ida_ida.compiler_info_t_size_b_get,
        _ida_ida.compiler_info_t_size_b_set)
    """sizeof(bool)
"""
    size_e: 'uchar' = property(_ida_ida.compiler_info_t_size_e_get,
        _ida_ida.compiler_info_t_size_e_set)
    """sizeof(enum)
"""
    defalign: 'uchar' = property(_ida_ida.compiler_info_t_defalign_get,
        _ida_ida.compiler_info_t_defalign_set)
    """default alignment for structures
"""
    size_s: 'uchar' = property(_ida_ida.compiler_info_t_size_s_get,
        _ida_ida.compiler_info_t_size_s_set)
    """short
"""
    size_l: 'uchar' = property(_ida_ida.compiler_info_t_size_l_get,
        _ida_ida.compiler_info_t_size_l_set)
    """long
"""
    size_ll: 'uchar' = property(_ida_ida.compiler_info_t_size_ll_get,
        _ida_ida.compiler_info_t_size_ll_set)
    """longlong
"""
    size_ldbl: 'uchar' = property(_ida_ida.compiler_info_t_size_ldbl_get,
        _ida_ida.compiler_info_t_size_ldbl_set)
    """longdouble (if different from processor_t::tbyte_size)
"""

    def __init__(self):
        _ida_ida.compiler_info_t_swiginit(self, _ida_ida.new_compiler_info_t())
    __swig_destroy__ = _ida_ida.delete_compiler_info_t


_ida_ida.compiler_info_t_swigregister(compiler_info_t)
STT_CUR = _ida_ida.STT_CUR
"""use current storage type (may be used only as a function argument)
"""
STT_VA = _ida_ida.STT_VA
"""regular storage: virtual arrays, an explicit flag for each byte
"""
STT_MM = _ida_ida.STT_MM
"""memory map: sparse storage. useful for huge objects
"""
STT_DBG = _ida_ida.STT_DBG
"""memory map: temporary debugger storage. used internally
"""
IDAINFO_TAG_SIZE = _ida_ida.IDAINFO_TAG_SIZE
"""The database parameters. This structure is kept in the ida database. It contains the essential parameters for the current program 
        """
IDAINFO_PROCNAME_SIZE = _ida_ida.IDAINFO_PROCNAME_SIZE
IDAINFO_STRLIT_PREF_SIZE = _ida_ida.IDAINFO_STRLIT_PREF_SIZE


class idainfo(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')

    def __init__(self, *args, **kwargs):
        raise AttributeError('No constructor defined')
    __repr__ = _swig_repr
    tag: 'char [3]' = property(_ida_ida.idainfo_tag_get, _ida_ida.
        idainfo_tag_set)
    """'IDA'
"""
    version: 'ushort' = property(_ida_ida.idainfo_version_get, _ida_ida.
        idainfo_version_set)
    """Version of database.
"""
    procname: 'char [16]' = property(_ida_ida.idainfo_procname_get,
        _ida_ida.idainfo_procname_set)
    """Name of the current processor (with \\0)
"""
    s_genflags: 'ushort' = property(_ida_ida.idainfo_s_genflags_get,
        _ida_ida.idainfo_s_genflags_set)
    """General idainfo flags 
        """
    database_change_count: 'uint32' = property(_ida_ida.
        idainfo_database_change_count_get, _ida_ida.
        idainfo_database_change_count_set)
    """incremented after each byte and regular segment modifications 
        """
    filetype: 'ushort' = property(_ida_ida.idainfo_filetype_get, _ida_ida.
        idainfo_filetype_set)
    """The input file type.
"""
    ostype: 'ushort' = property(_ida_ida.idainfo_ostype_get, _ida_ida.
        idainfo_ostype_set)
    """OS type the program is for bit definitions in libfuncs.hpp 
        """
    apptype: 'ushort' = property(_ida_ida.idainfo_apptype_get, _ida_ida.
        idainfo_apptype_set)
    """Application type bit definitions in libfuncs.hpp 
        """
    asmtype: 'uchar' = property(_ida_ida.idainfo_asmtype_get, _ida_ida.
        idainfo_asmtype_set)
    """target assembler number
"""
    specsegs: 'uchar' = property(_ida_ida.idainfo_specsegs_get, _ida_ida.
        idainfo_specsegs_set)
    """What format do special segments use? 0-unspecified, 4-entries are 4 bytes, 8- entries are 8 bytes.
"""
    af: 'uint32' = property(_ida_ida.idainfo_af_get, _ida_ida.idainfo_af_set)
    """Analysis flags 
        """
    af2: 'uint32' = property(_ida_ida.idainfo_af2_get, _ida_ida.idainfo_af2_set
        )
    """Analysis flags 2 
        """
    baseaddr: 'uval_t' = property(_ida_ida.idainfo_baseaddr_get, _ida_ida.
        idainfo_baseaddr_set)
    """remaining 28 bits are reserved

base address of the program (paragraphs) 
        """
    start_ss: 'sel_t' = property(_ida_ida.idainfo_start_ss_get, _ida_ida.
        idainfo_start_ss_set)
    """selector of the initial stack segment
"""
    start_cs: 'sel_t' = property(_ida_ida.idainfo_start_cs_get, _ida_ida.
        idainfo_start_cs_set)
    """selector of the segment with the main entry point
"""
    start_ip: 'ea_t' = property(_ida_ida.idainfo_start_ip_get, _ida_ida.
        idainfo_start_ip_set)
    """IP register value at the start of program execution 
        """
    start_ea: 'ea_t' = property(_ida_ida.idainfo_start_ea_get, _ida_ida.
        idainfo_start_ea_set)
    """Linear address of program entry point.
"""
    start_sp: 'ea_t' = property(_ida_ida.idainfo_start_sp_get, _ida_ida.
        idainfo_start_sp_set)
    """SP register value at the start of program execution 
        """
    main: 'ea_t' = property(_ida_ida.idainfo_main_get, _ida_ida.
        idainfo_main_set)
    """address of main()
"""
    min_ea: 'ea_t' = property(_ida_ida.idainfo_min_ea_get, _ida_ida.
        idainfo_min_ea_set)
    """current limits of program
"""
    max_ea: 'ea_t' = property(_ida_ida.idainfo_max_ea_get, _ida_ida.
        idainfo_max_ea_set)
    """maxEA is excluded
"""
    omin_ea: 'ea_t' = property(_ida_ida.idainfo_omin_ea_get, _ida_ida.
        idainfo_omin_ea_set)
    """original minEA (is set after loading the input file)
"""
    omax_ea: 'ea_t' = property(_ida_ida.idainfo_omax_ea_get, _ida_ida.
        idainfo_omax_ea_set)
    """original maxEA (is set after loading the input file)
"""
    lowoff: 'ea_t' = property(_ida_ida.idainfo_lowoff_get, _ida_ida.
        idainfo_lowoff_set)
    """Low limit for offsets (used in calculation of 'void' operands) 
        """
    highoff: 'ea_t' = property(_ida_ida.idainfo_highoff_get, _ida_ida.
        idainfo_highoff_set)
    """High limit for offsets (used in calculation of 'void' operands) 
        """
    maxref: 'uval_t' = property(_ida_ida.idainfo_maxref_get, _ida_ida.
        idainfo_maxref_set)
    """Max tail for references.
"""
    xrefnum: 'uchar' = property(_ida_ida.idainfo_xrefnum_get, _ida_ida.
        idainfo_xrefnum_set)
    """CROSS REFERENCES.

Number of references to generate in the disassembly listing 0 - xrefs won't be generated at all 
        """
    type_xrefnum: 'uchar' = property(_ida_ida.idainfo_type_xrefnum_get,
        _ida_ida.idainfo_type_xrefnum_set)
    """Number of references to generate in the struct & enum windows 0 - xrefs won't be generated at all 
        """
    refcmtnum: 'uchar' = property(_ida_ida.idainfo_refcmtnum_get, _ida_ida.
        idainfo_refcmtnum_set)
    """Number of comment lines to generate for refs to string literals or demangled names 0 - such comments won't be generated at all 
        """
    s_xrefflag: 'uchar' = property(_ida_ida.idainfo_s_xrefflag_get,
        _ida_ida.idainfo_s_xrefflag_set)
    """Xref options 
        """
    max_autoname_len: 'ushort' = property(_ida_ida.
        idainfo_max_autoname_len_get, _ida_ida.idainfo_max_autoname_len_set)
    """NAMES.

max autogenerated name length (without zero byte) 
        """
    nametype: 'char' = property(_ida_ida.idainfo_nametype_get, _ida_ida.
        idainfo_nametype_set)
    """Dummy names representation types 
        """
    short_demnames: 'uint32' = property(_ida_ida.idainfo_short_demnames_get,
        _ida_ida.idainfo_short_demnames_set)
    """short form of demangled names
"""
    long_demnames: 'uint32' = property(_ida_ida.idainfo_long_demnames_get,
        _ida_ida.idainfo_long_demnames_set)
    """long form of demangled names see demangle.h for definitions 
        """
    demnames: 'uchar' = property(_ida_ida.idainfo_demnames_get, _ida_ida.
        idainfo_demnames_set)
    """Demangled name flags 
        """
    listnames: 'uchar' = property(_ida_ida.idainfo_listnames_get, _ida_ida.
        idainfo_listnames_set)
    """Name list options 
        """
    indent: 'uchar' = property(_ida_ida.idainfo_indent_get, _ida_ida.
        idainfo_indent_set)
    """DISASSEMBLY LISTING DETAILS.

Indentation for instructions 
        """
    cmt_indent: 'uchar' = property(_ida_ida.idainfo_cmt_indent_get,
        _ida_ida.idainfo_cmt_indent_set)
    """Indentation for comments.
"""
    margin: 'ushort' = property(_ida_ida.idainfo_margin_get, _ida_ida.
        idainfo_margin_set)
    """max length of data lines
"""
    lenxref: 'ushort' = property(_ida_ida.idainfo_lenxref_get, _ida_ida.
        idainfo_lenxref_set)
    """max length of line with xrefs
"""
    outflags: 'uint32' = property(_ida_ida.idainfo_outflags_get, _ida_ida.
        idainfo_outflags_set)
    """output flags 
        """
    s_cmtflg: 'uchar' = property(_ida_ida.idainfo_s_cmtflg_get, _ida_ida.
        idainfo_s_cmtflg_set)
    """Comment options 
        """
    s_limiter: 'uchar' = property(_ida_ida.idainfo_s_limiter_get, _ida_ida.
        idainfo_s_limiter_set)
    """Delimiter options 
        """
    bin_prefix_size: 'short' = property(_ida_ida.
        idainfo_bin_prefix_size_get, _ida_ida.idainfo_bin_prefix_size_set)
    """Number of instruction bytes (opcodes) to show in line prefix.
"""
    s_prefflag: 'uchar' = property(_ida_ida.idainfo_s_prefflag_get,
        _ida_ida.idainfo_s_prefflag_set)
    """Line prefix options 
        """
    strlit_flags: 'uchar' = property(_ida_ida.idainfo_strlit_flags_get,
        _ida_ida.idainfo_strlit_flags_set)
    """STRING LITERALS.

string literal flags 
        """
    strlit_break: 'uchar' = property(_ida_ida.idainfo_strlit_break_get,
        _ida_ida.idainfo_strlit_break_set)
    """string literal line break symbol
"""
    strlit_zeroes: 'char' = property(_ida_ida.idainfo_strlit_zeroes_get,
        _ida_ida.idainfo_strlit_zeroes_set)
    """leading zeroes
"""
    strtype: 'int32' = property(_ida_ida.idainfo_strtype_get, _ida_ida.
        idainfo_strtype_set)
    """current ascii string type see nalt.hpp for string types 
        """
    strlit_pref: 'char [16]' = property(_ida_ida.idainfo_strlit_pref_get,
        _ida_ida.idainfo_strlit_pref_set)
    """prefix for string literal names
"""
    strlit_sernum: 'uval_t' = property(_ida_ida.idainfo_strlit_sernum_get,
        _ida_ida.idainfo_strlit_sernum_set)
    """serial number
"""
    datatypes: 'uval_t' = property(_ida_ida.idainfo_datatypes_get, _ida_ida
        .idainfo_datatypes_set)
    """data types allowed in data carousel
"""
    cc: 'compiler_info_t' = property(_ida_ida.idainfo_cc_get, _ida_ida.
        idainfo_cc_set)
    """COMPILER.

Target compiler 
        """
    abibits: 'uint32' = property(_ida_ida.idainfo_abibits_get, _ida_ida.
        idainfo_abibits_set)
    """ABI features. Depends on info returned by get_abi_name() Processor modules may modify them in set_compiler 
        """
    appcall_options: 'uint32' = property(_ida_ida.
        idainfo_appcall_options_get, _ida_ida.idainfo_appcall_options_set)
    """appcall options, see idd.hpp
"""

    def get_abiname(self) ->str:
        return _ida_ida.idainfo_get_abiname(self)

    def _get_lflags(self) ->int:
        return _ida_ida.idainfo__get_lflags(self)

    def _set_lflags(self, _f: int) ->None:
        return _ida_ida.idainfo__set_lflags(self, _f)
    abiname = property(get_abiname)
    lflags = property(_get_lflags, _set_lflags)
    """Misc. database flags 
        """
    minEA = ida_idaapi._make_missed_695bwcompat_property('minEA', 'min_ea',
        has_setter=True)
    maxEA = ida_idaapi._make_missed_695bwcompat_property('maxEA', 'max_ea',
        has_setter=True)
    procName = ida_idaapi._make_missed_695bwcompat_property('procName',
        'procname', has_setter=False)


_ida_ida.idainfo_swigregister(idainfo)
INFFL_AUTO = _ida_ida.INFFL_AUTO
"""Autoanalysis is enabled?
"""
INFFL_ALLASM = _ida_ida.INFFL_ALLASM
"""may use constructs not supported by the target assembler 
        """
INFFL_LOADIDC = _ida_ida.INFFL_LOADIDC
"""loading an idc file that contains database info
"""
INFFL_NOUSER = _ida_ida.INFFL_NOUSER
"""do not store user info in the database
"""
INFFL_READONLY = _ida_ida.INFFL_READONLY
"""(internal) temporary interdiction to modify the database
"""
INFFL_CHKOPS = _ida_ida.INFFL_CHKOPS
"""check manual operands? (unused)
"""
INFFL_NMOPS = _ida_ida.INFFL_NMOPS
"""allow non-matched operands? (unused)
"""
INFFL_GRAPH_VIEW = _ida_ida.INFFL_GRAPH_VIEW
"""currently using graph options ( text_options_t::graph)
"""
LFLG_PC_FPP = _ida_ida.LFLG_PC_FPP
"""decode floating point processor instructions?
"""
LFLG_PC_FLAT = _ida_ida.LFLG_PC_FLAT
"""32-bit program (or higher)?
"""
LFLG_64BIT = _ida_ida.LFLG_64BIT
"""64-bit program?
"""
LFLG_IS_DLL = _ida_ida.LFLG_IS_DLL
"""Is dynamic library?
"""
LFLG_FLAT_OFF32 = _ida_ida.LFLG_FLAT_OFF32
"""treat REF_OFF32 as 32-bit offset for 16bit segments (otherwise try SEG16:OFF16)
"""
LFLG_MSF = _ida_ida.LFLG_MSF
"""Byte order: is MSB first?
"""
LFLG_WIDE_HBF = _ida_ida.LFLG_WIDE_HBF
"""Bit order of wide bytes: high byte first? (wide bytes: processor_t::dnbits > 8) 
        """
LFLG_DBG_NOPATH = _ida_ida.LFLG_DBG_NOPATH
"""do not store input full path in debugger process options
"""
LFLG_SNAPSHOT = _ida_ida.LFLG_SNAPSHOT
"""memory snapshot was taken?
"""
LFLG_PACK = _ida_ida.LFLG_PACK
"""pack the database?
"""
LFLG_COMPRESS = _ida_ida.LFLG_COMPRESS
"""compress the database?
"""
LFLG_KERNMODE = _ida_ida.LFLG_KERNMODE
"""is kernel mode binary?
"""
LFLG_ILP32 = _ida_ida.LFLG_ILP32
"""64-bit instructions with 64-bit registers, but 32-bit pointers and address space. this bit is mutually exclusive with LFLG_64BIT 
        """
IDB_UNPACKED = _ida_ida.IDB_UNPACKED
"""leave database components unpacked
"""
IDB_PACKED = _ida_ida.IDB_PACKED
"""pack database components into .idb
"""
IDB_COMPRESSED = _ida_ida.IDB_COMPRESSED
"""compress & pack database components
"""
AF_CODE = _ida_ida.AF_CODE
"""Trace execution flow.
"""
AF_MARKCODE = _ida_ida.AF_MARKCODE
"""Mark typical code sequences as code.
"""
AF_JUMPTBL = _ida_ida.AF_JUMPTBL
"""Locate and create jump tables.
"""
AF_PURDAT = _ida_ida.AF_PURDAT
"""Control flow to data segment is ignored.
"""
AF_USED = _ida_ida.AF_USED
"""Analyze and create all xrefs.
"""
AF_UNK = _ida_ida.AF_UNK
"""Delete instructions with no xrefs.
"""
AF_PROCPTR = _ida_ida.AF_PROCPTR
"""Create function if data xref data->code32 exists.
"""
AF_PROC = _ida_ida.AF_PROC
"""Create functions if call is present.
"""
AF_FTAIL = _ida_ida.AF_FTAIL
"""Create function tails.
"""
AF_LVAR = _ida_ida.AF_LVAR
"""Create stack variables.
"""
AF_STKARG = _ida_ida.AF_STKARG
"""Propagate stack argument information.
"""
AF_REGARG = _ida_ida.AF_REGARG
"""Propagate register argument information.
"""
AF_TRACE = _ida_ida.AF_TRACE
"""Trace stack pointer.
"""
AF_VERSP = _ida_ida.AF_VERSP
"""Perform full SP-analysis. ( processor_t::verify_sp)
"""
AF_ANORET = _ida_ida.AF_ANORET
"""Perform 'no-return' analysis.
"""
AF_MEMFUNC = _ida_ida.AF_MEMFUNC
"""Try to guess member function types.
"""
AF_TRFUNC = _ida_ida.AF_TRFUNC
"""Truncate functions upon code deletion.
"""
AF_STRLIT = _ida_ida.AF_STRLIT
"""Create string literal if data xref exists.
"""
AF_CHKUNI = _ida_ida.AF_CHKUNI
"""Check for unicode strings.
"""
AF_FIXUP = _ida_ida.AF_FIXUP
"""Create offsets and segments using fixup info.
"""
AF_DREFOFF = _ida_ida.AF_DREFOFF
"""Create offset if data xref to seg32 exists.
"""
AF_IMMOFF = _ida_ida.AF_IMMOFF
"""Convert 32bit instruction operand to offset.
"""
AF_DATOFF = _ida_ida.AF_DATOFF
"""Automatically convert data to offsets.
"""
AF_FLIRT = _ida_ida.AF_FLIRT
"""Use flirt signatures.
"""
AF_SIGCMT = _ida_ida.AF_SIGCMT
"""Append a signature name comment for recognized anonymous library functions.
"""
AF_SIGMLT = _ida_ida.AF_SIGMLT
"""Allow recognition of several copies of the same function.
"""
AF_HFLIRT = _ida_ida.AF_HFLIRT
"""Automatically hide library functions.
"""
AF_JFUNC = _ida_ida.AF_JFUNC
"""Rename jump functions as j_...
"""
AF_NULLSUB = _ida_ida.AF_NULLSUB
"""Rename empty functions as nullsub_...
"""
AF_DODATA = _ida_ida.AF_DODATA
"""Coagulate data segs at the final pass.
"""
AF_DOCODE = _ida_ida.AF_DOCODE
"""Coagulate code segs at the final pass.
"""
AF2_DOEH = _ida_ida.AF2_DOEH
"""Handle EH information.
"""
AF2_DORTTI = _ida_ida.AF2_DORTTI
"""Handle RTTI information.
"""
AF2_MACRO = _ida_ida.AF2_MACRO
"""Try to combine several instructions into a macro instruction 
        """
AF2_MERGESTR = _ida_ida.AF2_MERGESTR
"""Merge string literals created using data xrefs 
        """
SW_SEGXRF = _ida_ida.SW_SEGXRF
"""show segments in xrefs?
"""
SW_XRFMRK = _ida_ida.SW_XRFMRK
"""show xref type marks?
"""
SW_XRFFNC = _ida_ida.SW_XRFFNC
"""show function offsets?
"""
SW_XRFVAL = _ida_ida.SW_XRFVAL
"""show xref values? (otherwise-"...")
"""
NM_REL_OFF = _ida_ida.NM_REL_OFF
NM_PTR_OFF = _ida_ida.NM_PTR_OFF
NM_NAM_OFF = _ida_ida.NM_NAM_OFF
NM_REL_EA = _ida_ida.NM_REL_EA
NM_PTR_EA = _ida_ida.NM_PTR_EA
NM_NAM_EA = _ida_ida.NM_NAM_EA
NM_EA = _ida_ida.NM_EA
NM_EA4 = _ida_ida.NM_EA4
NM_EA8 = _ida_ida.NM_EA8
NM_SHORT = _ida_ida.NM_SHORT
NM_SERIAL = _ida_ida.NM_SERIAL
DEMNAM_MASK = _ida_ida.DEMNAM_MASK
"""mask for name form
"""
DEMNAM_CMNT = _ida_ida.DEMNAM_CMNT
"""display demangled names as comments
"""
DEMNAM_NAME = _ida_ida.DEMNAM_NAME
"""display demangled names as regular names
"""
DEMNAM_NONE = _ida_ida.DEMNAM_NONE
"""don't display demangled names
"""
DEMNAM_GCC3 = _ida_ida.DEMNAM_GCC3
"""assume gcc3 names (valid for gnu compiler)
"""
DEMNAM_FIRST = _ida_ida.DEMNAM_FIRST
"""override type info
"""
LN_NORMAL = _ida_ida.LN_NORMAL
"""include normal names
"""
LN_PUBLIC = _ida_ida.LN_PUBLIC
"""include public names
"""
LN_AUTO = _ida_ida.LN_AUTO
"""include autogenerated names
"""
LN_WEAK = _ida_ida.LN_WEAK
"""include weak names
"""
OFLG_SHOW_VOID = _ida_ida.OFLG_SHOW_VOID
"""Display void marks?
"""
OFLG_SHOW_AUTO = _ida_ida.OFLG_SHOW_AUTO
"""Display autoanalysis indicator?
"""
OFLG_GEN_NULL = _ida_ida.OFLG_GEN_NULL
"""Generate empty lines?
"""
OFLG_SHOW_PREF = _ida_ida.OFLG_SHOW_PREF
"""Show line prefixes?
"""
OFLG_PREF_SEG = _ida_ida.OFLG_PREF_SEG
"""line prefixes with segment name?
"""
OFLG_LZERO = _ida_ida.OFLG_LZERO
"""generate leading zeroes in numbers
"""
OFLG_GEN_ORG = _ida_ida.OFLG_GEN_ORG
"""Generate 'org' directives?
"""
OFLG_GEN_ASSUME = _ida_ida.OFLG_GEN_ASSUME
"""Generate 'assume' directives?
"""
OFLG_GEN_TRYBLKS = _ida_ida.OFLG_GEN_TRYBLKS
"""Generate try/catch directives?
"""
SCF_RPTCMT = _ida_ida.SCF_RPTCMT
"""show repeatable comments?
"""
SCF_ALLCMT = _ida_ida.SCF_ALLCMT
"""comment all lines?
"""
SCF_NOCMT = _ida_ida.SCF_NOCMT
"""no comments at all
"""
SCF_LINNUM = _ida_ida.SCF_LINNUM
"""show source line numbers
"""
SCF_TESTMODE = _ida_ida.SCF_TESTMODE
"""testida.idc is running
"""
SCF_SHHID_ITEM = _ida_ida.SCF_SHHID_ITEM
"""show hidden instructions
"""
SCF_SHHID_FUNC = _ida_ida.SCF_SHHID_FUNC
"""show hidden functions
"""
SCF_SHHID_SEGM = _ida_ida.SCF_SHHID_SEGM
"""show hidden segments
"""
LMT_THIN = _ida_ida.LMT_THIN
"""thin borders
"""
LMT_THICK = _ida_ida.LMT_THICK
"""thick borders
"""
LMT_EMPTY = _ida_ida.LMT_EMPTY
"""empty lines at the end of basic blocks
"""
PREF_SEGADR = _ida_ida.PREF_SEGADR
"""show segment addresses?
"""
PREF_FNCOFF = _ida_ida.PREF_FNCOFF
"""show function offsets?
"""
PREF_STACK = _ida_ida.PREF_STACK
"""show stack pointer?
"""
PREF_PFXTRUNC = _ida_ida.PREF_PFXTRUNC
"""truncate instruction bytes if they would need more than 1 line
"""
STRF_GEN = _ida_ida.STRF_GEN
"""generate names?
"""
STRF_AUTO = _ida_ida.STRF_AUTO
"""names have 'autogenerated' bit?
"""
STRF_SERIAL = _ida_ida.STRF_SERIAL
"""generate serial names?
"""
STRF_UNICODE = _ida_ida.STRF_UNICODE
"""unicode strings are present?
"""
STRF_COMMENT = _ida_ida.STRF_COMMENT
"""generate auto comment for string references?
"""
STRF_SAVECASE = _ida_ida.STRF_SAVECASE
"""preserve case of strings for identifiers
"""
ABI_8ALIGN4 = _ida_ida.ABI_8ALIGN4
"""4 byte alignment for 8byte scalars (__int64/double) inside structures?
"""
ABI_PACK_STKARGS = _ida_ida.ABI_PACK_STKARGS
"""do not align stack arguments to stack slots
"""
ABI_BIGARG_ALIGN = _ida_ida.ABI_BIGARG_ALIGN
"""use natural type alignment for argument if the alignment exceeds native word size. (e.g. __int64 argument should be 8byte aligned on some 32bit platforms) 
        """
ABI_STACK_LDBL = _ida_ida.ABI_STACK_LDBL
"""long double arguments are passed on stack
"""
ABI_STACK_VARARGS = _ida_ida.ABI_STACK_VARARGS
"""varargs are always passed on stack (even when there are free registers)
"""
ABI_HARD_FLOAT = _ida_ida.ABI_HARD_FLOAT
"""use the floating-point register set
"""
ABI_SET_BY_USER = _ida_ida.ABI_SET_BY_USER
"""compiler/abi were set by user flag and require SETCOMP_BY_USER flag to be changed
"""
ABI_GCC_LAYOUT = _ida_ida.ABI_GCC_LAYOUT
"""use gcc layout for udts (used for mingw)
"""
ABI_MAP_STKARGS = _ida_ida.ABI_MAP_STKARGS
"""register arguments are mapped to stack area (and consume stack slots)
"""
ABI_HUGEARG_ALIGN = _ida_ida.ABI_HUGEARG_ALIGN
"""use natural type alignment for an argument even if its alignment exceeds double native word size (the default is to use double word max). e.g. if this bit is set, __int128 has 16-byte alignment. this bit is not used by ida yet 
        """
INF_VERSION = _ida_ida.INF_VERSION
INF_PROCNAME = _ida_ida.INF_PROCNAME
INF_GENFLAGS = _ida_ida.INF_GENFLAGS
INF_LFLAGS = _ida_ida.INF_LFLAGS
INF_DATABASE_CHANGE_COUNT = _ida_ida.INF_DATABASE_CHANGE_COUNT
INF_FILETYPE = _ida_ida.INF_FILETYPE
INF_OSTYPE = _ida_ida.INF_OSTYPE
INF_APPTYPE = _ida_ida.INF_APPTYPE
INF_ASMTYPE = _ida_ida.INF_ASMTYPE
INF_SPECSEGS = _ida_ida.INF_SPECSEGS
INF_AF = _ida_ida.INF_AF
INF_AF2 = _ida_ida.INF_AF2
INF_BASEADDR = _ida_ida.INF_BASEADDR
INF_START_SS = _ida_ida.INF_START_SS
INF_START_CS = _ida_ida.INF_START_CS
INF_START_IP = _ida_ida.INF_START_IP
INF_START_EA = _ida_ida.INF_START_EA
INF_START_SP = _ida_ida.INF_START_SP
INF_MAIN = _ida_ida.INF_MAIN
INF_MIN_EA = _ida_ida.INF_MIN_EA
INF_MAX_EA = _ida_ida.INF_MAX_EA
INF_OMIN_EA = _ida_ida.INF_OMIN_EA
INF_OMAX_EA = _ida_ida.INF_OMAX_EA
INF_LOWOFF = _ida_ida.INF_LOWOFF
INF_HIGHOFF = _ida_ida.INF_HIGHOFF
INF_MAXREF = _ida_ida.INF_MAXREF
INF_PRIVRANGE = _ida_ida.INF_PRIVRANGE
INF_PRIVRANGE_START_EA = _ida_ida.INF_PRIVRANGE_START_EA
INF_PRIVRANGE_END_EA = _ida_ida.INF_PRIVRANGE_END_EA
INF_NETDELTA = _ida_ida.INF_NETDELTA
INF_XREFNUM = _ida_ida.INF_XREFNUM
INF_TYPE_XREFNUM = _ida_ida.INF_TYPE_XREFNUM
INF_REFCMTNUM = _ida_ida.INF_REFCMTNUM
INF_XREFFLAG = _ida_ida.INF_XREFFLAG
INF_MAX_AUTONAME_LEN = _ida_ida.INF_MAX_AUTONAME_LEN
INF_NAMETYPE = _ida_ida.INF_NAMETYPE
INF_SHORT_DEMNAMES = _ida_ida.INF_SHORT_DEMNAMES
INF_LONG_DEMNAMES = _ida_ida.INF_LONG_DEMNAMES
INF_DEMNAMES = _ida_ida.INF_DEMNAMES
INF_LISTNAMES = _ida_ida.INF_LISTNAMES
INF_INDENT = _ida_ida.INF_INDENT
INF_CMT_INDENT = _ida_ida.INF_CMT_INDENT
INF_MARGIN = _ida_ida.INF_MARGIN
INF_LENXREF = _ida_ida.INF_LENXREF
INF_OUTFLAGS = _ida_ida.INF_OUTFLAGS
INF_CMTFLG = _ida_ida.INF_CMTFLG
INF_LIMITER = _ida_ida.INF_LIMITER
INF_BIN_PREFIX_SIZE = _ida_ida.INF_BIN_PREFIX_SIZE
INF_PREFFLAG = _ida_ida.INF_PREFFLAG
INF_STRLIT_FLAGS = _ida_ida.INF_STRLIT_FLAGS
INF_STRLIT_BREAK = _ida_ida.INF_STRLIT_BREAK
INF_STRLIT_ZEROES = _ida_ida.INF_STRLIT_ZEROES
INF_STRTYPE = _ida_ida.INF_STRTYPE
INF_STRLIT_PREF = _ida_ida.INF_STRLIT_PREF
INF_STRLIT_SERNUM = _ida_ida.INF_STRLIT_SERNUM
INF_DATATYPES = _ida_ida.INF_DATATYPES
INF_CC = _ida_ida.INF_CC
INF_CC_ID = _ida_ida.INF_CC_ID
INF_CC_CM = _ida_ida.INF_CC_CM
INF_CC_SIZE_I = _ida_ida.INF_CC_SIZE_I
INF_CC_SIZE_B = _ida_ida.INF_CC_SIZE_B
INF_CC_SIZE_E = _ida_ida.INF_CC_SIZE_E
INF_CC_DEFALIGN = _ida_ida.INF_CC_DEFALIGN
INF_CC_SIZE_S = _ida_ida.INF_CC_SIZE_S
INF_CC_SIZE_L = _ida_ida.INF_CC_SIZE_L
INF_CC_SIZE_LL = _ida_ida.INF_CC_SIZE_LL
INF_CC_SIZE_LDBL = _ida_ida.INF_CC_SIZE_LDBL
INF_ABIBITS = _ida_ida.INF_ABIBITS
INF_APPCALL_OPTIONS = _ida_ida.INF_APPCALL_OPTIONS
INF_FILE_FORMAT_NAME = _ida_ida.INF_FILE_FORMAT_NAME
"""file format name for loader modules
"""
INF_GROUPS = _ida_ida.INF_GROUPS
"""segment group information (see init_groups())
"""
INF_H_PATH = _ida_ida.INF_H_PATH
"""C header path.
"""
INF_C_MACROS = _ida_ida.INF_C_MACROS
"""C predefined macros.
"""
INF_INCLUDE = _ida_ida.INF_INCLUDE
"""assembler include file name
"""
INF_DUALOP_GRAPH = _ida_ida.INF_DUALOP_GRAPH
"""Graph text representation options.
"""
INF_DUALOP_TEXT = _ida_ida.INF_DUALOP_TEXT
"""Text text representation options.
"""
INF_MD5 = _ida_ida.INF_MD5
"""MD5 of the input file.
"""
INF_IDA_VERSION = _ida_ida.INF_IDA_VERSION
"""version of ida which created the database
"""
INF_STR_ENCODINGS = _ida_ida.INF_STR_ENCODINGS
"""a list of encodings for the program strings
"""
INF_DBG_BINPATHS = _ida_ida.INF_DBG_BINPATHS
"""unused (20 indexes)
"""
INF_SHA256 = _ida_ida.INF_SHA256
"""SHA256 of the input file.
"""
INF_ABINAME = _ida_ida.INF_ABINAME
"""ABI name (processor specific)
"""
INF_ARCHIVE_PATH = _ida_ida.INF_ARCHIVE_PATH
"""archive file path
"""
INF_PROBLEMS = _ida_ida.INF_PROBLEMS
"""problem lists
"""
INF_SELECTORS = _ida_ida.INF_SELECTORS
"""2..63 are for selector_t blob (see init_selectors())
"""
INF_NOTEPAD = _ida_ida.INF_NOTEPAD
"""notepad blob, occupies 1000 indexes (1MB of text)
"""
INF_SRCDBG_PATHS = _ida_ida.INF_SRCDBG_PATHS
"""source debug paths, occupies 20 indexes
"""
INF_SRCDBG_UNDESIRED = _ida_ida.INF_SRCDBG_UNDESIRED
"""user-closed source files, occupies 20 indexes
"""
INF_INITIAL_VERSION = _ida_ida.INF_INITIAL_VERSION
"""initial version of database
"""
INF_CTIME = _ida_ida.INF_CTIME
"""database creation timestamp
"""
INF_ELAPSED = _ida_ida.INF_ELAPSED
"""seconds database stayed open
"""
INF_NOPENS = _ida_ida.INF_NOPENS
"""how many times the database is opened
"""
INF_CRC32 = _ida_ida.INF_CRC32
"""input file crc32
"""
INF_IMAGEBASE = _ida_ida.INF_IMAGEBASE
"""image base
"""
INF_IDSNODE = _ida_ida.INF_IDSNODE
"""ids modnode id (for import_module)
"""
INF_FSIZE = _ida_ida.INF_FSIZE
"""input file size
"""
INF_OUTFILEENC = _ida_ida.INF_OUTFILEENC
"""output file encoding index
"""
INF_INPUT_FILE_PATH = _ida_ida.INF_INPUT_FILE_PATH
INF_LAST = _ida_ida.INF_LAST


def getinf_str(tag: 'inftag_t') ->str:
    """Get program specific information (a non-scalar value) 
        
@param tag: one of inftag_t constants
@returns number of bytes stored in the buffer (<0 - not defined)"""
    return _ida_ida.getinf_str(tag)


def delinf(tag: 'inftag_t') ->bool:
    """Undefine a program specific information 
        
@param tag: one of inftag_t constants
@returns success"""
    return _ida_ida.delinf(tag)


def inf_get_version() ->'ushort':
    return _ida_ida.inf_get_version()


def inf_set_version(_v: 'ushort') ->bool:
    return _ida_ida.inf_set_version(_v)


def inf_get_genflags() ->'ushort':
    return _ida_ida.inf_get_genflags()


def inf_set_genflags(_v: 'ushort') ->bool:
    return _ida_ida.inf_set_genflags(_v)


def inf_is_auto_enabled() ->bool:
    return _ida_ida.inf_is_auto_enabled()


def inf_set_auto_enabled(_v: bool=True) ->bool:
    return _ida_ida.inf_set_auto_enabled(_v)


def inf_use_allasm() ->bool:
    return _ida_ida.inf_use_allasm()


def inf_set_use_allasm(_v: bool=True) ->bool:
    return _ida_ida.inf_set_use_allasm(_v)


def inf_loading_idc() ->bool:
    return _ida_ida.inf_loading_idc()


def inf_set_loading_idc(_v: bool=True) ->bool:
    return _ida_ida.inf_set_loading_idc(_v)


def inf_no_store_user_info() ->bool:
    return _ida_ida.inf_no_store_user_info()


def inf_set_no_store_user_info(_v: bool=True) ->bool:
    return _ida_ida.inf_set_no_store_user_info(_v)


def inf_readonly_idb() ->bool:
    return _ida_ida.inf_readonly_idb()


def inf_set_readonly_idb(_v: bool=True) ->bool:
    return _ida_ida.inf_set_readonly_idb(_v)


def inf_check_manual_ops() ->bool:
    return _ida_ida.inf_check_manual_ops()


def inf_set_check_manual_ops(_v: bool=True) ->bool:
    return _ida_ida.inf_set_check_manual_ops(_v)


def inf_allow_non_matched_ops() ->bool:
    return _ida_ida.inf_allow_non_matched_ops()


def inf_set_allow_non_matched_ops(_v: bool=True) ->bool:
    return _ida_ida.inf_set_allow_non_matched_ops(_v)


def inf_is_graph_view() ->bool:
    return _ida_ida.inf_is_graph_view()


def inf_set_graph_view(_v: bool=True) ->bool:
    return _ida_ida.inf_set_graph_view(_v)


def inf_get_lflags() ->int:
    return _ida_ida.inf_get_lflags()


def inf_set_lflags(_v: int) ->bool:
    return _ida_ida.inf_set_lflags(_v)


def inf_decode_fpp() ->bool:
    return _ida_ida.inf_decode_fpp()


def inf_set_decode_fpp(_v: bool=True) ->bool:
    return _ida_ida.inf_set_decode_fpp(_v)


def inf_is_32bit_or_higher() ->bool:
    return _ida_ida.inf_is_32bit_or_higher()


def inf_is_32bit_exactly() ->bool:
    return _ida_ida.inf_is_32bit_exactly()


def inf_set_32bit(_v: bool=True) ->bool:
    return _ida_ida.inf_set_32bit(_v)


def inf_is_16bit() ->bool:
    return _ida_ida.inf_is_16bit()


def inf_is_64bit() ->bool:
    return _ida_ida.inf_is_64bit()


def inf_set_64bit(_v: bool=True) ->bool:
    return _ida_ida.inf_set_64bit(_v)


def inf_is_ilp32() ->bool:
    return _ida_ida.inf_is_ilp32()


def inf_set_ilp32(_v: bool=True) ->bool:
    return _ida_ida.inf_set_ilp32(_v)


def inf_is_dll() ->bool:
    return _ida_ida.inf_is_dll()


def inf_set_dll(_v: bool=True) ->bool:
    return _ida_ida.inf_set_dll(_v)


def inf_is_flat_off32() ->bool:
    return _ida_ida.inf_is_flat_off32()


def inf_set_flat_off32(_v: bool=True) ->bool:
    return _ida_ida.inf_set_flat_off32(_v)


def inf_is_be() ->bool:
    return _ida_ida.inf_is_be()


def inf_set_be(_v: bool=True) ->bool:
    return _ida_ida.inf_set_be(_v)


def inf_is_wide_high_byte_first() ->bool:
    return _ida_ida.inf_is_wide_high_byte_first()


def inf_set_wide_high_byte_first(_v: bool=True) ->bool:
    return _ida_ida.inf_set_wide_high_byte_first(_v)


def inf_dbg_no_store_path() ->bool:
    return _ida_ida.inf_dbg_no_store_path()


def inf_set_dbg_no_store_path(_v: bool=True) ->bool:
    return _ida_ida.inf_set_dbg_no_store_path(_v)


def inf_is_snapshot() ->bool:
    return _ida_ida.inf_is_snapshot()


def inf_set_snapshot(_v: bool=True) ->bool:
    return _ida_ida.inf_set_snapshot(_v)


def inf_pack_idb() ->bool:
    return _ida_ida.inf_pack_idb()


def inf_set_pack_idb(_v: bool=True) ->bool:
    return _ida_ida.inf_set_pack_idb(_v)


def inf_compress_idb() ->bool:
    return _ida_ida.inf_compress_idb()


def inf_set_compress_idb(_v: bool=True) ->bool:
    return _ida_ida.inf_set_compress_idb(_v)


def inf_is_kernel_mode() ->bool:
    return _ida_ida.inf_is_kernel_mode()


def inf_set_kernel_mode(_v: bool=True) ->bool:
    return _ida_ida.inf_set_kernel_mode(_v)


def inf_get_app_bitness() ->'uint':
    return _ida_ida.inf_get_app_bitness()


def inf_set_app_bitness(bitness: 'uint') ->None:
    return _ida_ida.inf_set_app_bitness(bitness)


def inf_get_database_change_count() ->int:
    return _ida_ida.inf_get_database_change_count()


def inf_set_database_change_count(_v: int) ->bool:
    return _ida_ida.inf_set_database_change_count(_v)


def inf_get_filetype() ->'filetype_t':
    return _ida_ida.inf_get_filetype()


def inf_set_filetype(_v: 'filetype_t') ->bool:
    return _ida_ida.inf_set_filetype(_v)


def inf_get_ostype() ->'ushort':
    return _ida_ida.inf_get_ostype()


def inf_set_ostype(_v: 'ushort') ->bool:
    return _ida_ida.inf_set_ostype(_v)


def inf_get_apptype() ->'ushort':
    return _ida_ida.inf_get_apptype()


def inf_set_apptype(_v: 'ushort') ->bool:
    return _ida_ida.inf_set_apptype(_v)


def inf_get_asmtype() ->'uchar':
    return _ida_ida.inf_get_asmtype()


def inf_set_asmtype(_v: 'uchar') ->bool:
    return _ida_ida.inf_set_asmtype(_v)


def inf_get_specsegs() ->'uchar':
    return _ida_ida.inf_get_specsegs()


def inf_set_specsegs(_v: 'uchar') ->bool:
    return _ida_ida.inf_set_specsegs(_v)


def inf_get_af() ->int:
    return _ida_ida.inf_get_af()


def inf_set_af(_v: int) ->bool:
    return _ida_ida.inf_set_af(_v)


def inf_trace_flow() ->bool:
    return _ida_ida.inf_trace_flow()


def inf_set_trace_flow(_v: bool=True) ->bool:
    return _ida_ida.inf_set_trace_flow(_v)


def inf_mark_code() ->bool:
    return _ida_ida.inf_mark_code()


def inf_set_mark_code(_v: bool=True) ->bool:
    return _ida_ida.inf_set_mark_code(_v)


def inf_create_jump_tables() ->bool:
    return _ida_ida.inf_create_jump_tables()


def inf_set_create_jump_tables(_v: bool=True) ->bool:
    return _ida_ida.inf_set_create_jump_tables(_v)


def inf_noflow_to_data() ->bool:
    return _ida_ida.inf_noflow_to_data()


def inf_set_noflow_to_data(_v: bool=True) ->bool:
    return _ida_ida.inf_set_noflow_to_data(_v)


def inf_create_all_xrefs() ->bool:
    return _ida_ida.inf_create_all_xrefs()


def inf_set_create_all_xrefs(_v: bool=True) ->bool:
    return _ida_ida.inf_set_create_all_xrefs(_v)


def inf_del_no_xref_insns() ->bool:
    return _ida_ida.inf_del_no_xref_insns()


def inf_set_del_no_xref_insns(_v: bool=True) ->bool:
    return _ida_ida.inf_set_del_no_xref_insns(_v)


def inf_create_func_from_ptr() ->bool:
    return _ida_ida.inf_create_func_from_ptr()


def inf_set_create_func_from_ptr(_v: bool=True) ->bool:
    return _ida_ida.inf_set_create_func_from_ptr(_v)


def inf_create_func_from_call() ->bool:
    return _ida_ida.inf_create_func_from_call()


def inf_set_create_func_from_call(_v: bool=True) ->bool:
    return _ida_ida.inf_set_create_func_from_call(_v)


def inf_create_func_tails() ->bool:
    return _ida_ida.inf_create_func_tails()


def inf_set_create_func_tails(_v: bool=True) ->bool:
    return _ida_ida.inf_set_create_func_tails(_v)


def inf_should_create_stkvars() ->bool:
    return _ida_ida.inf_should_create_stkvars()


def inf_set_should_create_stkvars(_v: bool=True) ->bool:
    return _ida_ida.inf_set_should_create_stkvars(_v)


def inf_propagate_stkargs() ->bool:
    return _ida_ida.inf_propagate_stkargs()


def inf_set_propagate_stkargs(_v: bool=True) ->bool:
    return _ida_ida.inf_set_propagate_stkargs(_v)


def inf_propagate_regargs() ->bool:
    return _ida_ida.inf_propagate_regargs()


def inf_set_propagate_regargs(_v: bool=True) ->bool:
    return _ida_ida.inf_set_propagate_regargs(_v)


def inf_should_trace_sp() ->bool:
    return _ida_ida.inf_should_trace_sp()


def inf_set_should_trace_sp(_v: bool=True) ->bool:
    return _ida_ida.inf_set_should_trace_sp(_v)


def inf_full_sp_ana() ->bool:
    return _ida_ida.inf_full_sp_ana()


def inf_set_full_sp_ana(_v: bool=True) ->bool:
    return _ida_ida.inf_set_full_sp_ana(_v)


def inf_noret_ana() ->bool:
    return _ida_ida.inf_noret_ana()


def inf_set_noret_ana(_v: bool=True) ->bool:
    return _ida_ida.inf_set_noret_ana(_v)


def inf_guess_func_type() ->bool:
    return _ida_ida.inf_guess_func_type()


def inf_set_guess_func_type(_v: bool=True) ->bool:
    return _ida_ida.inf_set_guess_func_type(_v)


def inf_truncate_on_del() ->bool:
    return _ida_ida.inf_truncate_on_del()


def inf_set_truncate_on_del(_v: bool=True) ->bool:
    return _ida_ida.inf_set_truncate_on_del(_v)


def inf_create_strlit_on_xref() ->bool:
    return _ida_ida.inf_create_strlit_on_xref()


def inf_set_create_strlit_on_xref(_v: bool=True) ->bool:
    return _ida_ida.inf_set_create_strlit_on_xref(_v)


def inf_check_unicode_strlits() ->bool:
    return _ida_ida.inf_check_unicode_strlits()


def inf_set_check_unicode_strlits(_v: bool=True) ->bool:
    return _ida_ida.inf_set_check_unicode_strlits(_v)


def inf_create_off_using_fixup() ->bool:
    return _ida_ida.inf_create_off_using_fixup()


def inf_set_create_off_using_fixup(_v: bool=True) ->bool:
    return _ida_ida.inf_set_create_off_using_fixup(_v)


def inf_create_off_on_dref() ->bool:
    return _ida_ida.inf_create_off_on_dref()


def inf_set_create_off_on_dref(_v: bool=True) ->bool:
    return _ida_ida.inf_set_create_off_on_dref(_v)


def inf_op_offset() ->bool:
    return _ida_ida.inf_op_offset()


def inf_set_op_offset(_v: bool=True) ->bool:
    return _ida_ida.inf_set_op_offset(_v)


def inf_data_offset() ->bool:
    return _ida_ida.inf_data_offset()


def inf_set_data_offset(_v: bool=True) ->bool:
    return _ida_ida.inf_set_data_offset(_v)


def inf_use_flirt() ->bool:
    return _ida_ida.inf_use_flirt()


def inf_set_use_flirt(_v: bool=True) ->bool:
    return _ida_ida.inf_set_use_flirt(_v)


def inf_append_sigcmt() ->bool:
    return _ida_ida.inf_append_sigcmt()


def inf_set_append_sigcmt(_v: bool=True) ->bool:
    return _ida_ida.inf_set_append_sigcmt(_v)


def inf_allow_sigmulti() ->bool:
    return _ida_ida.inf_allow_sigmulti()


def inf_set_allow_sigmulti(_v: bool=True) ->bool:
    return _ida_ida.inf_set_allow_sigmulti(_v)


def inf_hide_libfuncs() ->bool:
    return _ida_ida.inf_hide_libfuncs()


def inf_set_hide_libfuncs(_v: bool=True) ->bool:
    return _ida_ida.inf_set_hide_libfuncs(_v)


def inf_rename_jumpfunc() ->bool:
    return _ida_ida.inf_rename_jumpfunc()


def inf_set_rename_jumpfunc(_v: bool=True) ->bool:
    return _ida_ida.inf_set_rename_jumpfunc(_v)


def inf_rename_nullsub() ->bool:
    return _ida_ida.inf_rename_nullsub()


def inf_set_rename_nullsub(_v: bool=True) ->bool:
    return _ida_ida.inf_set_rename_nullsub(_v)


def inf_coagulate_data() ->bool:
    return _ida_ida.inf_coagulate_data()


def inf_set_coagulate_data(_v: bool=True) ->bool:
    return _ida_ida.inf_set_coagulate_data(_v)


def inf_coagulate_code() ->bool:
    return _ida_ida.inf_coagulate_code()


def inf_set_coagulate_code(_v: bool=True) ->bool:
    return _ida_ida.inf_set_coagulate_code(_v)


def inf_final_pass() ->bool:
    return _ida_ida.inf_final_pass()


def inf_set_final_pass(_v: bool=True) ->bool:
    return _ida_ida.inf_set_final_pass(_v)


def inf_get_af2() ->int:
    return _ida_ida.inf_get_af2()


def inf_set_af2(_v: int) ->bool:
    return _ida_ida.inf_set_af2(_v)


def inf_handle_eh() ->bool:
    return _ida_ida.inf_handle_eh()


def inf_set_handle_eh(_v: bool=True) ->bool:
    return _ida_ida.inf_set_handle_eh(_v)


def inf_handle_rtti() ->bool:
    return _ida_ida.inf_handle_rtti()


def inf_set_handle_rtti(_v: bool=True) ->bool:
    return _ida_ida.inf_set_handle_rtti(_v)


def inf_macros_enabled() ->bool:
    return _ida_ida.inf_macros_enabled()


def inf_set_macros_enabled(_v: bool=True) ->bool:
    return _ida_ida.inf_set_macros_enabled(_v)


def inf_merge_strlits() ->bool:
    return _ida_ida.inf_merge_strlits()


def inf_set_merge_strlits(_v: bool=True) ->bool:
    return _ida_ida.inf_set_merge_strlits(_v)


def inf_get_baseaddr() ->int:
    return _ida_ida.inf_get_baseaddr()


def inf_set_baseaddr(_v: int) ->bool:
    return _ida_ida.inf_set_baseaddr(_v)


def inf_get_start_ss() ->'sel_t':
    return _ida_ida.inf_get_start_ss()


def inf_set_start_ss(_v: 'sel_t') ->bool:
    return _ida_ida.inf_set_start_ss(_v)


def inf_get_start_cs() ->'sel_t':
    return _ida_ida.inf_get_start_cs()


def inf_set_start_cs(_v: 'sel_t') ->bool:
    return _ida_ida.inf_set_start_cs(_v)


def inf_get_start_ip() ->ida_idaapi.ea_t:
    return _ida_ida.inf_get_start_ip()


def inf_set_start_ip(_v: ida_idaapi.ea_t) ->bool:
    return _ida_ida.inf_set_start_ip(_v)


def inf_get_start_ea() ->ida_idaapi.ea_t:
    return _ida_ida.inf_get_start_ea()


def inf_set_start_ea(_v: ida_idaapi.ea_t) ->bool:
    return _ida_ida.inf_set_start_ea(_v)


def inf_get_start_sp() ->ida_idaapi.ea_t:
    return _ida_ida.inf_get_start_sp()


def inf_set_start_sp(_v: ida_idaapi.ea_t) ->bool:
    return _ida_ida.inf_set_start_sp(_v)


def inf_get_main() ->ida_idaapi.ea_t:
    return _ida_ida.inf_get_main()


def inf_set_main(_v: ida_idaapi.ea_t) ->bool:
    return _ida_ida.inf_set_main(_v)


def inf_get_min_ea() ->ida_idaapi.ea_t:
    return _ida_ida.inf_get_min_ea()


def inf_set_min_ea(_v: ida_idaapi.ea_t) ->bool:
    return _ida_ida.inf_set_min_ea(_v)


def inf_get_max_ea() ->ida_idaapi.ea_t:
    return _ida_ida.inf_get_max_ea()


def inf_set_max_ea(_v: ida_idaapi.ea_t) ->bool:
    return _ida_ida.inf_set_max_ea(_v)


def inf_get_omin_ea() ->ida_idaapi.ea_t:
    return _ida_ida.inf_get_omin_ea()


def inf_set_omin_ea(_v: ida_idaapi.ea_t) ->bool:
    return _ida_ida.inf_set_omin_ea(_v)


def inf_get_omax_ea() ->ida_idaapi.ea_t:
    return _ida_ida.inf_get_omax_ea()


def inf_set_omax_ea(_v: ida_idaapi.ea_t) ->bool:
    return _ida_ida.inf_set_omax_ea(_v)


def inf_get_lowoff() ->ida_idaapi.ea_t:
    return _ida_ida.inf_get_lowoff()


def inf_set_lowoff(_v: ida_idaapi.ea_t) ->bool:
    return _ida_ida.inf_set_lowoff(_v)


def inf_get_highoff() ->ida_idaapi.ea_t:
    return _ida_ida.inf_get_highoff()


def inf_set_highoff(_v: ida_idaapi.ea_t) ->bool:
    return _ida_ida.inf_set_highoff(_v)


def inf_get_maxref() ->int:
    return _ida_ida.inf_get_maxref()


def inf_set_maxref(_v: int) ->bool:
    return _ida_ida.inf_set_maxref(_v)


def inf_get_netdelta() ->int:
    return _ida_ida.inf_get_netdelta()


def inf_set_netdelta(_v: int) ->bool:
    return _ida_ida.inf_set_netdelta(_v)


def inf_get_xrefnum() ->'uchar':
    return _ida_ida.inf_get_xrefnum()


def inf_set_xrefnum(_v: 'uchar') ->bool:
    return _ida_ida.inf_set_xrefnum(_v)


def inf_get_type_xrefnum() ->'uchar':
    return _ida_ida.inf_get_type_xrefnum()


def inf_set_type_xrefnum(_v: 'uchar') ->bool:
    return _ida_ida.inf_set_type_xrefnum(_v)


def inf_get_refcmtnum() ->'uchar':
    return _ida_ida.inf_get_refcmtnum()


def inf_set_refcmtnum(_v: 'uchar') ->bool:
    return _ida_ida.inf_set_refcmtnum(_v)


def inf_get_xrefflag() ->'uchar':
    return _ida_ida.inf_get_xrefflag()


def inf_set_xrefflag(_v: 'uchar') ->bool:
    return _ida_ida.inf_set_xrefflag(_v)


def inf_show_xref_seg() ->bool:
    return _ida_ida.inf_show_xref_seg()


def inf_set_show_xref_seg(_v: bool=True) ->bool:
    return _ida_ida.inf_set_show_xref_seg(_v)


def inf_show_xref_tmarks() ->bool:
    return _ida_ida.inf_show_xref_tmarks()


def inf_set_show_xref_tmarks(_v: bool=True) ->bool:
    return _ida_ida.inf_set_show_xref_tmarks(_v)


def inf_show_xref_fncoff() ->bool:
    return _ida_ida.inf_show_xref_fncoff()


def inf_set_show_xref_fncoff(_v: bool=True) ->bool:
    return _ida_ida.inf_set_show_xref_fncoff(_v)


def inf_show_xref_val() ->bool:
    return _ida_ida.inf_show_xref_val()


def inf_set_show_xref_val(_v: bool=True) ->bool:
    return _ida_ida.inf_set_show_xref_val(_v)


def inf_get_max_autoname_len() ->'ushort':
    return _ida_ida.inf_get_max_autoname_len()


def inf_set_max_autoname_len(_v: 'ushort') ->bool:
    return _ida_ida.inf_set_max_autoname_len(_v)


def inf_get_nametype() ->'char':
    return _ida_ida.inf_get_nametype()


def inf_set_nametype(_v: 'char') ->bool:
    return _ida_ida.inf_set_nametype(_v)


def inf_get_short_demnames() ->int:
    return _ida_ida.inf_get_short_demnames()


def inf_set_short_demnames(_v: int) ->bool:
    return _ida_ida.inf_set_short_demnames(_v)


def inf_get_long_demnames() ->int:
    return _ida_ida.inf_get_long_demnames()


def inf_set_long_demnames(_v: int) ->bool:
    return _ida_ida.inf_set_long_demnames(_v)


def inf_get_demnames() ->'uchar':
    return _ida_ida.inf_get_demnames()


def inf_set_demnames(_v: 'uchar') ->bool:
    return _ida_ida.inf_set_demnames(_v)


def inf_get_listnames() ->'uchar':
    return _ida_ida.inf_get_listnames()


def inf_set_listnames(_v: 'uchar') ->bool:
    return _ida_ida.inf_set_listnames(_v)


def inf_get_indent() ->'uchar':
    return _ida_ida.inf_get_indent()


def inf_set_indent(_v: 'uchar') ->bool:
    return _ida_ida.inf_set_indent(_v)


def inf_get_cmt_indent() ->'uchar':
    return _ida_ida.inf_get_cmt_indent()


def inf_set_cmt_indent(_v: 'uchar') ->bool:
    return _ida_ida.inf_set_cmt_indent(_v)


def inf_get_margin() ->'ushort':
    return _ida_ida.inf_get_margin()


def inf_set_margin(_v: 'ushort') ->bool:
    return _ida_ida.inf_set_margin(_v)


def inf_get_lenxref() ->'ushort':
    return _ida_ida.inf_get_lenxref()


def inf_set_lenxref(_v: 'ushort') ->bool:
    return _ida_ida.inf_set_lenxref(_v)


def inf_get_outflags() ->int:
    return _ida_ida.inf_get_outflags()


def inf_set_outflags(_v: int) ->bool:
    return _ida_ida.inf_set_outflags(_v)


def inf_show_void() ->bool:
    return _ida_ida.inf_show_void()


def inf_set_show_void(_v: bool=True) ->bool:
    return _ida_ida.inf_set_show_void(_v)


def inf_show_auto() ->bool:
    return _ida_ida.inf_show_auto()


def inf_set_show_auto(_v: bool=True) ->bool:
    return _ida_ida.inf_set_show_auto(_v)


def inf_gen_null() ->bool:
    return _ida_ida.inf_gen_null()


def inf_set_gen_null(_v: bool=True) ->bool:
    return _ida_ida.inf_set_gen_null(_v)


def inf_show_line_pref() ->bool:
    return _ida_ida.inf_show_line_pref()


def inf_set_show_line_pref(_v: bool=True) ->bool:
    return _ida_ida.inf_set_show_line_pref(_v)


def inf_line_pref_with_seg() ->bool:
    return _ida_ida.inf_line_pref_with_seg()


def inf_set_line_pref_with_seg(_v: bool=True) ->bool:
    return _ida_ida.inf_set_line_pref_with_seg(_v)


def inf_gen_lzero() ->bool:
    return _ida_ida.inf_gen_lzero()


def inf_set_gen_lzero(_v: bool=True) ->bool:
    return _ida_ida.inf_set_gen_lzero(_v)


def inf_gen_org() ->bool:
    return _ida_ida.inf_gen_org()


def inf_set_gen_org(_v: bool=True) ->bool:
    return _ida_ida.inf_set_gen_org(_v)


def inf_gen_assume() ->bool:
    return _ida_ida.inf_gen_assume()


def inf_set_gen_assume(_v: bool=True) ->bool:
    return _ida_ida.inf_set_gen_assume(_v)


def inf_gen_tryblks() ->bool:
    return _ida_ida.inf_gen_tryblks()


def inf_set_gen_tryblks(_v: bool=True) ->bool:
    return _ida_ida.inf_set_gen_tryblks(_v)


def inf_get_cmtflg() ->'uchar':
    return _ida_ida.inf_get_cmtflg()


def inf_set_cmtflg(_v: 'uchar') ->bool:
    return _ida_ida.inf_set_cmtflg(_v)


def inf_show_repeatables() ->bool:
    return _ida_ida.inf_show_repeatables()


def inf_set_show_repeatables(_v: bool=True) ->bool:
    return _ida_ida.inf_set_show_repeatables(_v)


def inf_show_all_comments() ->bool:
    return _ida_ida.inf_show_all_comments()


def inf_set_show_all_comments(_v: bool=True) ->bool:
    return _ida_ida.inf_set_show_all_comments(_v)


def inf_hide_comments() ->bool:
    return _ida_ida.inf_hide_comments()


def inf_set_hide_comments(_v: bool=True) ->bool:
    return _ida_ida.inf_set_hide_comments(_v)


def inf_show_src_linnum() ->bool:
    return _ida_ida.inf_show_src_linnum()


def inf_set_show_src_linnum(_v: bool=True) ->bool:
    return _ida_ida.inf_set_show_src_linnum(_v)


def inf_test_mode() ->bool:
    return _ida_ida.inf_test_mode()


def inf_show_hidden_insns() ->bool:
    return _ida_ida.inf_show_hidden_insns()


def inf_set_show_hidden_insns(_v: bool=True) ->bool:
    return _ida_ida.inf_set_show_hidden_insns(_v)


def inf_show_hidden_funcs() ->bool:
    return _ida_ida.inf_show_hidden_funcs()


def inf_set_show_hidden_funcs(_v: bool=True) ->bool:
    return _ida_ida.inf_set_show_hidden_funcs(_v)


def inf_show_hidden_segms() ->bool:
    return _ida_ida.inf_show_hidden_segms()


def inf_set_show_hidden_segms(_v: bool=True) ->bool:
    return _ida_ida.inf_set_show_hidden_segms(_v)


def inf_get_limiter() ->'uchar':
    return _ida_ida.inf_get_limiter()


def inf_set_limiter(_v: 'uchar') ->bool:
    return _ida_ida.inf_set_limiter(_v)


def inf_is_limiter_thin() ->bool:
    return _ida_ida.inf_is_limiter_thin()


def inf_set_limiter_thin(_v: bool=True) ->bool:
    return _ida_ida.inf_set_limiter_thin(_v)


def inf_is_limiter_thick() ->bool:
    return _ida_ida.inf_is_limiter_thick()


def inf_set_limiter_thick(_v: bool=True) ->bool:
    return _ida_ida.inf_set_limiter_thick(_v)


def inf_is_limiter_empty() ->bool:
    return _ida_ida.inf_is_limiter_empty()


def inf_set_limiter_empty(_v: bool=True) ->bool:
    return _ida_ida.inf_set_limiter_empty(_v)


def inf_get_bin_prefix_size() ->'short':
    return _ida_ida.inf_get_bin_prefix_size()


def inf_set_bin_prefix_size(_v: 'short') ->bool:
    return _ida_ida.inf_set_bin_prefix_size(_v)


def inf_get_prefflag() ->'uchar':
    return _ida_ida.inf_get_prefflag()


def inf_set_prefflag(_v: 'uchar') ->bool:
    return _ida_ida.inf_set_prefflag(_v)


def inf_prefix_show_segaddr() ->bool:
    return _ida_ida.inf_prefix_show_segaddr()


def inf_set_prefix_show_segaddr(_v: bool=True) ->bool:
    return _ida_ida.inf_set_prefix_show_segaddr(_v)


def inf_prefix_show_funcoff() ->bool:
    return _ida_ida.inf_prefix_show_funcoff()


def inf_set_prefix_show_funcoff(_v: bool=True) ->bool:
    return _ida_ida.inf_set_prefix_show_funcoff(_v)


def inf_prefix_show_stack() ->bool:
    return _ida_ida.inf_prefix_show_stack()


def inf_set_prefix_show_stack(_v: bool=True) ->bool:
    return _ida_ida.inf_set_prefix_show_stack(_v)


def inf_prefix_truncate_opcode_bytes() ->bool:
    return _ida_ida.inf_prefix_truncate_opcode_bytes()


def inf_set_prefix_truncate_opcode_bytes(_v: bool=True) ->bool:
    return _ida_ida.inf_set_prefix_truncate_opcode_bytes(_v)


def inf_get_strlit_flags() ->'uchar':
    return _ida_ida.inf_get_strlit_flags()


def inf_set_strlit_flags(_v: 'uchar') ->bool:
    return _ida_ida.inf_set_strlit_flags(_v)


def inf_strlit_names() ->bool:
    return _ida_ida.inf_strlit_names()


def inf_set_strlit_names(_v: bool=True) ->bool:
    return _ida_ida.inf_set_strlit_names(_v)


def inf_strlit_name_bit() ->bool:
    return _ida_ida.inf_strlit_name_bit()


def inf_set_strlit_name_bit(_v: bool=True) ->bool:
    return _ida_ida.inf_set_strlit_name_bit(_v)


def inf_strlit_serial_names() ->bool:
    return _ida_ida.inf_strlit_serial_names()


def inf_set_strlit_serial_names(_v: bool=True) ->bool:
    return _ida_ida.inf_set_strlit_serial_names(_v)


def inf_unicode_strlits() ->bool:
    return _ida_ida.inf_unicode_strlits()


def inf_set_unicode_strlits(_v: bool=True) ->bool:
    return _ida_ida.inf_set_unicode_strlits(_v)


def inf_strlit_autocmt() ->bool:
    return _ida_ida.inf_strlit_autocmt()


def inf_set_strlit_autocmt(_v: bool=True) ->bool:
    return _ida_ida.inf_set_strlit_autocmt(_v)


def inf_strlit_savecase() ->bool:
    return _ida_ida.inf_strlit_savecase()


def inf_set_strlit_savecase(_v: bool=True) ->bool:
    return _ida_ida.inf_set_strlit_savecase(_v)


def inf_get_strlit_break() ->'uchar':
    return _ida_ida.inf_get_strlit_break()


def inf_set_strlit_break(_v: 'uchar') ->bool:
    return _ida_ida.inf_set_strlit_break(_v)


def inf_get_strlit_zeroes() ->'char':
    return _ida_ida.inf_get_strlit_zeroes()


def inf_set_strlit_zeroes(_v: 'char') ->bool:
    return _ida_ida.inf_set_strlit_zeroes(_v)


def inf_get_strtype() ->int:
    return _ida_ida.inf_get_strtype()


def inf_set_strtype(_v: int) ->bool:
    return _ida_ida.inf_set_strtype(_v)


def inf_get_strlit_sernum() ->int:
    return _ida_ida.inf_get_strlit_sernum()


def inf_set_strlit_sernum(_v: int) ->bool:
    return _ida_ida.inf_set_strlit_sernum(_v)


def inf_get_datatypes() ->int:
    return _ida_ida.inf_get_datatypes()


def inf_set_datatypes(_v: int) ->bool:
    return _ida_ida.inf_set_datatypes(_v)


def inf_get_abibits() ->int:
    return _ida_ida.inf_get_abibits()


def inf_set_abibits(_v: int) ->bool:
    return _ida_ida.inf_set_abibits(_v)


def inf_is_mem_aligned4() ->bool:
    return _ida_ida.inf_is_mem_aligned4()


def inf_set_mem_aligned4(_v: bool=True) ->bool:
    return _ida_ida.inf_set_mem_aligned4(_v)


def inf_pack_stkargs(*args) ->bool:
    return _ida_ida.inf_pack_stkargs(*args)


def inf_set_pack_stkargs(_v: bool=True) ->bool:
    return _ida_ida.inf_set_pack_stkargs(_v)


def inf_big_arg_align(*args) ->bool:
    return _ida_ida.inf_big_arg_align(*args)


def inf_set_big_arg_align(_v: bool=True) ->bool:
    return _ida_ida.inf_set_big_arg_align(_v)


def inf_stack_ldbl() ->bool:
    return _ida_ida.inf_stack_ldbl()


def inf_set_stack_ldbl(_v: bool=True) ->bool:
    return _ida_ida.inf_set_stack_ldbl(_v)


def inf_stack_varargs() ->bool:
    return _ida_ida.inf_stack_varargs()


def inf_set_stack_varargs(_v: bool=True) ->bool:
    return _ida_ida.inf_set_stack_varargs(_v)


def inf_is_hard_float() ->bool:
    return _ida_ida.inf_is_hard_float()


def inf_set_hard_float(_v: bool=True) ->bool:
    return _ida_ida.inf_set_hard_float(_v)


def inf_abi_set_by_user() ->bool:
    return _ida_ida.inf_abi_set_by_user()


def inf_set_abi_set_by_user(_v: bool=True) ->bool:
    return _ida_ida.inf_set_abi_set_by_user(_v)


def inf_use_gcc_layout() ->bool:
    return _ida_ida.inf_use_gcc_layout()


def inf_set_use_gcc_layout(_v: bool=True) ->bool:
    return _ida_ida.inf_set_use_gcc_layout(_v)


def inf_map_stkargs() ->bool:
    return _ida_ida.inf_map_stkargs()


def inf_set_map_stkargs(_v: bool=True) ->bool:
    return _ida_ida.inf_set_map_stkargs(_v)


def inf_huge_arg_align(*args) ->bool:
    return _ida_ida.inf_huge_arg_align(*args)


def inf_set_huge_arg_align(_v: bool=True) ->bool:
    return _ida_ida.inf_set_huge_arg_align(_v)


def inf_get_appcall_options() ->int:
    return _ida_ida.inf_get_appcall_options()


def inf_set_appcall_options(_v: int) ->bool:
    return _ida_ida.inf_set_appcall_options(_v)


def inf_get_privrange_start_ea() ->ida_idaapi.ea_t:
    return _ida_ida.inf_get_privrange_start_ea()


def inf_set_privrange_start_ea(_v: ida_idaapi.ea_t) ->bool:
    return _ida_ida.inf_set_privrange_start_ea(_v)


def inf_get_privrange_end_ea() ->ida_idaapi.ea_t:
    return _ida_ida.inf_get_privrange_end_ea()


def inf_set_privrange_end_ea(_v: ida_idaapi.ea_t) ->bool:
    return _ida_ida.inf_set_privrange_end_ea(_v)


def inf_get_cc_id() ->'comp_t':
    return _ida_ida.inf_get_cc_id()


def inf_set_cc_id(_v: 'comp_t') ->bool:
    return _ida_ida.inf_set_cc_id(_v)


def inf_get_cc_cm() ->'cm_t':
    return _ida_ida.inf_get_cc_cm()


def inf_set_cc_cm(_v: 'cm_t') ->bool:
    return _ida_ida.inf_set_cc_cm(_v)


def inf_get_cc_size_i() ->'uchar':
    return _ida_ida.inf_get_cc_size_i()


def inf_set_cc_size_i(_v: 'uchar') ->bool:
    return _ida_ida.inf_set_cc_size_i(_v)


def inf_get_cc_size_b() ->'uchar':
    return _ida_ida.inf_get_cc_size_b()


def inf_set_cc_size_b(_v: 'uchar') ->bool:
    return _ida_ida.inf_set_cc_size_b(_v)


def inf_get_cc_size_e() ->'uchar':
    return _ida_ida.inf_get_cc_size_e()


def inf_set_cc_size_e(_v: 'uchar') ->bool:
    return _ida_ida.inf_set_cc_size_e(_v)


def inf_get_cc_defalign() ->'uchar':
    return _ida_ida.inf_get_cc_defalign()


def inf_set_cc_defalign(_v: 'uchar') ->bool:
    return _ida_ida.inf_set_cc_defalign(_v)


def inf_get_cc_size_s() ->'uchar':
    return _ida_ida.inf_get_cc_size_s()


def inf_set_cc_size_s(_v: 'uchar') ->bool:
    return _ida_ida.inf_set_cc_size_s(_v)


def inf_get_cc_size_l() ->'uchar':
    return _ida_ida.inf_get_cc_size_l()


def inf_set_cc_size_l(_v: 'uchar') ->bool:
    return _ida_ida.inf_set_cc_size_l(_v)


def inf_get_cc_size_ll() ->'uchar':
    return _ida_ida.inf_get_cc_size_ll()


def inf_set_cc_size_ll(_v: 'uchar') ->bool:
    return _ida_ida.inf_set_cc_size_ll(_v)


def inf_get_cc_size_ldbl() ->'uchar':
    return _ida_ida.inf_get_cc_size_ldbl()


def inf_set_cc_size_ldbl(_v: 'uchar') ->bool:
    return _ida_ida.inf_set_cc_size_ldbl(_v)


def inf_get_procname() ->str:
    return _ida_ida.inf_get_procname()


def inf_set_procname(*args) ->bool:
    return _ida_ida.inf_set_procname(*args)


def inf_get_strlit_pref() ->str:
    return _ida_ida.inf_get_strlit_pref()


def inf_set_strlit_pref(*args) ->bool:
    return _ida_ida.inf_set_strlit_pref(*args)


def inf_get_cc(out: 'compiler_info_t') ->bool:
    return _ida_ida.inf_get_cc(out)


def inf_set_cc(_v: 'compiler_info_t') ->bool:
    return _ida_ida.inf_set_cc(_v)


def inf_set_privrange(_v: 'range_t') ->bool:
    return _ida_ida.inf_set_privrange(_v)


def inf_get_privrange(*args) ->'range_t':
    """This function has the following signatures:

    0. inf_get_privrange(out: range_t *) -> bool
    1. inf_get_privrange() -> range_t

# 0: inf_get_privrange(out: range_t *) -> bool


# 1: inf_get_privrange() -> range_t

"""
    return _ida_ida.inf_get_privrange(*args)


def inf_get_af_low() ->'ushort':
    """Get/set low/high 16bit halves of inf.af.
"""
    return _ida_ida.inf_get_af_low()


def inf_set_af_low(saf: 'ushort') ->None:
    return _ida_ida.inf_set_af_low(saf)


def inf_get_af_high() ->'ushort':
    return _ida_ida.inf_get_af_high()


def inf_set_af_high(saf2: 'ushort') ->None:
    return _ida_ida.inf_set_af_high(saf2)


def inf_get_af2_low() ->'ushort':
    """Get/set low 16bit half of inf.af2.
"""
    return _ida_ida.inf_get_af2_low()


def inf_set_af2_low(saf: 'ushort') ->None:
    return _ida_ida.inf_set_af2_low(saf)


def inf_get_pack_mode() ->int:
    return _ida_ida.inf_get_pack_mode()


def inf_set_pack_mode(pack_mode: int) ->int:
    return _ida_ida.inf_set_pack_mode(pack_mode)


def inf_inc_database_change_count(cnt: int=1) ->None:
    return _ida_ida.inf_inc_database_change_count(cnt)


def inf_get_demname_form() ->'uchar':
    """Get DEMNAM_MASK bits of #demnames.
"""
    return _ida_ida.inf_get_demname_form()


def inf_postinc_strlit_sernum(cnt: int=1) ->int:
    return _ida_ida.inf_postinc_strlit_sernum(cnt)


def inf_like_binary() ->bool:
    return _ida_ida.inf_like_binary()


UA_MAXOP = _ida_ida.UA_MAXOP
"""max number of operands allowed for an instruction
"""


def calc_default_idaplace_flags() ->int:
    """Get default disassembly line options.
"""
    return _ida_ida.calc_default_idaplace_flags()


def to_ea(reg_cs: 'sel_t', reg_ip: int) ->ida_idaapi.ea_t:
    """Convert (sel,off) value to a linear address.
"""
    return _ida_ida.to_ea(reg_cs, reg_ip)


IDB_EXT32 = _ida_ida.IDB_EXT32
IDB_EXT64 = _ida_ida.IDB_EXT64
IDB_EXT = _ida_ida.IDB_EXT


def get_dbctx_id() ->'ssize_t':
    """Get the current database context ID 
        
@returns the database context ID, or -1 if no current database"""
    return _ida_ida.get_dbctx_id()


def get_dbctx_qty() ->'size_t':
    """Get number of database contexts 
        
@returns number of database contexts"""
    return _ida_ida.get_dbctx_qty()


def switch_dbctx(idx: 'size_t') ->'dbctx_t *':
    """Switch to the database with the provided context ID 
        
@param idx: the index of the database to switch to
@returns the current dbctx_t instance or nullptr"""
    return _ida_ida.switch_dbctx(idx)


def is_database_busy() ->bool:
    """Check if the database is busy (e.g. performing some critical operations and cannot be safely accessed) 
        """
    return _ida_ida.is_database_busy()


def validate_idb(vld_flags: int=0) ->'size_t':
    """Validate the database 
        
@param vld_flags: combination of VLD_.. constants
@returns number of corrupted/fixed records"""
    return _ida_ida.validate_idb(vld_flags)


VLD_AUTO_REPAIR = _ida_ida.VLD_AUTO_REPAIR
"""automatically repair the database
"""
VLD_DIALOG = _ida_ida.VLD_DIALOG
"""ask user to repair (this bit is mutually exclusive with VLD_AUTO_REPAIR)
"""
VLD_SILENT = _ida_ida.VLD_SILENT
"""no messages to the output window
"""


def move_privrange(new_privrange_start: ida_idaapi.ea_t) ->bool:
    """Move privrange to the specified address 
        
@param new_privrange_start: new start address of the privrange
@returns success"""
    return _ida_ida.move_privrange(new_privrange_start)


class idbattr_valmap_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    value: 'uint64' = property(_ida_ida.idbattr_valmap_t_value_get,
        _ida_ida.idbattr_valmap_t_value_set)
    valname: 'char const *' = property(_ida_ida.
        idbattr_valmap_t_valname_get, _ida_ida.idbattr_valmap_t_valname_set)

    def __init__(self):
        _ida_ida.idbattr_valmap_t_swiginit(self, _ida_ida.
            new_idbattr_valmap_t())
    __swig_destroy__ = _ida_ida.delete_idbattr_valmap_t


_ida_ida.idbattr_valmap_t_swigregister(idbattr_valmap_t)


class idbattr_info_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    name: 'char const *' = property(_ida_ida.idbattr_info_t_name_get,
        _ida_ida.idbattr_info_t_name_set)
    """human-readable name
"""
    offset: 'uintptr_t' = property(_ida_ida.idbattr_info_t_offset_get,
        _ida_ida.idbattr_info_t_offset_set)
    """field position: offset within a structure (IDI_STRUCFLD) altval or supval index (IDI_NODEVAL) hashval name (IDI_ALTVAL/IDI_SUPVAL+IDI_HASH) 
        """
    width: 'size_t' = property(_ida_ida.idbattr_info_t_width_get, _ida_ida.
        idbattr_info_t_width_set)
    """field width in bytes
"""
    bitmask: 'uint64' = property(_ida_ida.idbattr_info_t_bitmask_get,
        _ida_ida.idbattr_info_t_bitmask_set)
    """mask for bitfields (0-not bitfield)
"""
    tag: 'uchar' = property(_ida_ida.idbattr_info_t_tag_get, _ida_ida.
        idbattr_info_t_tag_set)
    """tag of node value (if IDI_NODEVAL is set)
"""
    vmap: 'idbattr_valmap_t const *' = property(_ida_ida.
        idbattr_info_t_vmap_get, _ida_ida.idbattr_info_t_vmap_set)
    """array value=>name (terminated by empty element)
"""
    individual_node: 'char const *' = property(_ida_ida.
        idbattr_info_t_individual_node_get, _ida_ida.
        idbattr_info_t_individual_node_set)
    """individual node name (nullptr - use default)
"""
    idi_flags: 'uint' = property(_ida_ida.idbattr_info_t_idi_flags_get,
        _ida_ida.idbattr_info_t_idi_flags_set)
    maxsize: 'uint32' = property(_ida_ida.idbattr_info_t_maxsize_get,
        _ida_ida.idbattr_info_t_maxsize_set)
    """max bytes reserved for storage in netnode
"""

    def is_node_altval(self) ->bool:
        return _ida_ida.idbattr_info_t_is_node_altval(self)

    def is_node_supval(self) ->bool:
        return _ida_ida.idbattr_info_t_is_node_supval(self)

    def is_node_valobj(self) ->bool:
        return _ida_ida.idbattr_info_t_is_node_valobj(self)

    def is_node_blob(self) ->bool:
        return _ida_ida.idbattr_info_t_is_node_blob(self)

    def is_node_var(self) ->bool:
        return _ida_ida.idbattr_info_t_is_node_var(self)

    def is_struc_field(self) ->bool:
        return _ida_ida.idbattr_info_t_is_struc_field(self)

    def is_cstr(self) ->bool:
        return _ida_ida.idbattr_info_t_is_cstr(self)

    def is_qstring(self) ->bool:
        return _ida_ida.idbattr_info_t_is_qstring(self)

    def is_bytearray(self) ->bool:
        return _ida_ida.idbattr_info_t_is_bytearray(self)

    def is_buf_var(self) ->bool:
        return _ida_ida.idbattr_info_t_is_buf_var(self)

    def is_decimal(self) ->bool:
        return _ida_ida.idbattr_info_t_is_decimal(self)

    def is_hexadecimal(self) ->bool:
        return _ida_ida.idbattr_info_t_is_hexadecimal(self)

    def is_readonly_var(self) ->bool:
        return _ida_ida.idbattr_info_t_is_readonly_var(self)

    def is_incremented(self) ->bool:
        return _ida_ida.idbattr_info_t_is_incremented(self)

    def is_val_mapped(self) ->bool:
        return _ida_ida.idbattr_info_t_is_val_mapped(self)

    def is_hash(self) ->bool:
        return _ida_ida.idbattr_info_t_is_hash(self)

    def use_hlpstruc(self) ->bool:
        return _ida_ida.idbattr_info_t_use_hlpstruc(self)

    def is_bitmap(self) ->bool:
        return _ida_ida.idbattr_info_t_is_bitmap(self)

    def is_onoff(self) ->bool:
        return _ida_ida.idbattr_info_t_is_onoff(self)

    def is_scalar_var(self) ->bool:
        return _ida_ida.idbattr_info_t_is_scalar_var(self)

    def is_bitfield(self) ->bool:
        return _ida_ida.idbattr_info_t_is_bitfield(self)

    def is_boolean(self) ->bool:
        return _ida_ida.idbattr_info_t_is_boolean(self)

    def has_individual_node(self) ->bool:
        return _ida_ida.idbattr_info_t_has_individual_node(self)

    def str_true(self) ->str:
        return _ida_ida.idbattr_info_t_str_true(self)

    def str_false(self) ->str:
        return _ida_ida.idbattr_info_t_str_false(self)

    def ridx(self) ->'size_t':
        return _ida_ida.idbattr_info_t_ridx(self)

    def hashname(self) ->str:
        return _ida_ida.idbattr_info_t_hashname(self)

    def __lt__(self, r: 'idbattr_info_t') ->bool:
        return _ida_ida.idbattr_info_t___lt__(self, r)

    def __init__(self, name: str, offset: 'uintptr_t', width: 'size_t',
        bitmask: 'uint64'=0, tag: 'uchar'=0, idi_flags: 'uint'=0):
        _ida_ida.idbattr_info_t_swiginit(self, _ida_ida.new_idbattr_info_t(
            name, offset, width, bitmask, tag, idi_flags))
    __swig_destroy__ = _ida_ida.delete_idbattr_info_t


_ida_ida.idbattr_info_t_swigregister(idbattr_info_t)
IDI_STRUCFLD = _ida_ida.IDI_STRUCFLD
"""structure field (opposite to IDI_NODEVAL)
"""
IDI_ALTVAL = _ida_ida.IDI_ALTVAL
"""netnode: altval
"""
IDI_SUPVAL = _ida_ida.IDI_SUPVAL
"""netnode: supval
"""
IDI_VALOBJ = _ida_ida.IDI_VALOBJ
"""netnode: valobj
"""
IDI_BLOB = _ida_ida.IDI_BLOB
"""netnode: blob
"""
IDI_SCALAR = _ida_ida.IDI_SCALAR
"""scalar value (default)
"""
IDI_CSTR = _ida_ida.IDI_CSTR
"""string
"""
IDI_QSTRING = _ida_ida.IDI_QSTRING
"""qstring
"""
IDI_BYTEARRAY = _ida_ida.IDI_BYTEARRAY
"""byte array: binary representation
"""
IDI_EA_HEX = _ida_ida.IDI_EA_HEX
"""default representation: hex or "BADADDR\"
"""
IDI_DEC = _ida_ida.IDI_DEC
"""show as decimal
"""
IDI_HEX = _ida_ida.IDI_HEX
"""show as hexadecimal
"""
IDI_INC = _ida_ida.IDI_INC
"""stored value is incremented (scalars only)
"""
IDI_MAP_VAL = _ida_ida.IDI_MAP_VAL
"""apply ea2node() to value
"""
IDI_HASH = _ida_ida.IDI_HASH
"""hashed node field, hash name in offset
"""
IDI_HLPSTRUC = _ida_ida.IDI_HLPSTRUC
"""call helper for pointer to structure
"""
IDI_READONLY = _ida_ida.IDI_READONLY
"""read-only field (cannot be modified)
"""
IDI_BITMAP = _ida_ida.IDI_BITMAP
"""bitmap field: interpret bitmask as bit number
"""
IDI_ONOFF = _ida_ida.IDI_ONOFF
"""show boolean as on/off (not true/false)
"""
IDI_NOMERGE = _ida_ida.IDI_NOMERGE
"""field should not be merged as part of INF
"""
IDI_NODEVAL = _ida_ida.IDI_NODEVAL
IDI_BUFVAR = _ida_ida.IDI_BUFVAR
import sys


def __make_idainfo_bound(func, attr):

    def __func(self, *args):
        return func(*args)
    setattr(idainfo, attr, __func)


_NO_SETTER = '<nosetter>'


def __make_idainfo_accessors(attr, getter_name=None, setter_name=None):
    if getter_name is None:
        getter_name = attr
    getter = globals()['idainfo_%s' % getter_name]
    __make_idainfo_bound(getter, getter_name)
    if setter_name != _NO_SETTER:
        if setter_name is None:
            setter_name = 'set_%s' % attr
        setter = globals()['idainfo_%s' % setter_name]
        __make_idainfo_bound(setter, setter_name)


def __make_idainfo_getter(name):
    return __make_idainfo_accessors(None, getter_name=name, setter_name=
        _NO_SETTER)


idainfo_big_arg_align = inf_big_arg_align
__make_idainfo_getter('big_arg_align')
idainfo_gen_null = inf_gen_null
idainfo_set_gen_null = inf_set_gen_null
__make_idainfo_accessors('gen_null')
idainfo_gen_lzero = inf_gen_lzero
idainfo_set_gen_lzero = inf_set_gen_lzero
__make_idainfo_accessors('gen_lzero')
idainfo_gen_tryblks = inf_gen_tryblks
idainfo_set_gen_tryblks = inf_set_gen_tryblks
__make_idainfo_accessors('gen_tryblks')
idainfo_get_demname_form = inf_get_demname_form
__make_idainfo_getter('get_demname_form')
idainfo_get_pack_mode = inf_get_pack_mode
idainfo_set_pack_mode = inf_set_pack_mode
__make_idainfo_accessors(None, 'get_pack_mode', 'set_pack_mode')


def idainfo_is_32bit():
    return not inf_is_16bit()


__make_idainfo_getter('is_32bit')
idainfo_is_64bit = inf_is_64bit
idainfo_set_64bit = inf_set_64bit
__make_idainfo_accessors(None, 'is_64bit', 'set_64bit')
idainfo_is_auto_enabled = inf_is_auto_enabled
idainfo_set_auto_enabled = inf_set_auto_enabled
__make_idainfo_accessors(None, 'is_auto_enabled', 'set_auto_enabled')
idainfo_is_be = inf_is_be
idainfo_set_be = inf_set_be
__make_idainfo_accessors(None, 'is_be', 'set_be')
idainfo_is_dll = inf_is_dll
__make_idainfo_getter('is_dll')
idainfo_is_flat_off32 = inf_is_flat_off32
__make_idainfo_getter('is_flat_off32')
idainfo_is_graph_view = inf_is_graph_view
idainfo_set_graph_view = inf_set_graph_view
__make_idainfo_accessors(None, 'is_graph_view', 'set_graph_view')
idainfo_is_hard_float = inf_is_hard_float
__make_idainfo_getter('is_hard_float')
idainfo_is_kernel_mode = inf_is_kernel_mode
__make_idainfo_getter('is_kernel_mode')
idainfo_is_mem_aligned4 = inf_is_mem_aligned4
__make_idainfo_getter('is_mem_aligned4')
idainfo_is_snapshot = inf_is_snapshot
__make_idainfo_getter('is_snapshot')
idainfo_is_wide_high_byte_first = inf_is_wide_high_byte_first
idainfo_set_wide_high_byte_first = inf_set_wide_high_byte_first
__make_idainfo_accessors(None, 'is_wide_high_byte_first',
    'set_wide_high_byte_first')
idainfo_like_binary = inf_like_binary
__make_idainfo_getter('like_binary')
idainfo_line_pref_with_seg = inf_line_pref_with_seg
idainfo_set_line_pref_with_seg = inf_set_line_pref_with_seg
__make_idainfo_accessors('line_pref_with_seg')
idainfo_show_auto = inf_show_auto
idainfo_set_show_auto = inf_set_show_auto
__make_idainfo_accessors('show_auto')
idainfo_show_line_pref = inf_show_line_pref
idainfo_set_show_line_pref = inf_set_show_line_pref
__make_idainfo_accessors('show_line_pref')
idainfo_show_void = inf_show_void
idainfo_set_show_void = inf_set_show_void
__make_idainfo_accessors('show_void')
idainfo_loading_idc = inf_loading_idc
__make_idainfo_getter('loading_idc')
idainfo_map_stkargs = inf_map_stkargs
__make_idainfo_getter('map_stkargs')
idainfo_pack_stkargs = inf_pack_stkargs
__make_idainfo_getter('pack_stkargs')
idainfo_readonly_idb = inf_readonly_idb
__make_idainfo_getter('readonly_idb')
idainfo_set_store_user_info = lambda *args: not inf_set_store_user_info()
idainfo_stack_ldbl = inf_stack_ldbl
__make_idainfo_getter('stack_ldbl')
idainfo_stack_varargs = inf_stack_varargs
__make_idainfo_getter('stack_varargs')
idainfo_use_allasm = inf_use_allasm
__make_idainfo_getter('use_allasm')
idainfo_use_gcc_layout = inf_use_gcc_layout
__make_idainfo_getter('use_gcc_layout')
macros_enabled = inf_macros_enabled
should_create_stkvars = inf_should_create_stkvars
should_trace_sp = inf_should_trace_sp
show_all_comments = inf_show_all_comments
show_comments = lambda *args: not inf_hide_comments()
show_repeatables = inf_show_repeatables
inf_get_comment = inf_get_cmt_indent
inf_set_comment = inf_set_cmt_indent
idainfo_comment_get = inf_get_cmt_indent
idainfo_comment_set = inf_set_cmt_indent
__make_idainfo_accessors(None, 'is_graph_view', 'set_graph_view')


def __wrap_hooks_callback(klass, new_name, old_name, do_call):
    bkp_name = '__real_%s' % new_name

    def __wrapper(self, *args):
        rc = getattr(self, bkp_name)(*args)
        cb = getattr(self, old_name, None)
        if cb:
            rc = do_call(cb, *args)
        return rc
    new_cb = getattr(klass, new_name)
    __wrapper.__doc__ = new_cb.__doc__
    setattr(klass, bkp_name, new_cb)
    setattr(__wrapper, '__trampoline', True)
    setattr(klass, new_name, __wrapper)
    return __wrapper


def __set_module_dynattrs(modname, pdict):
    import types


    class _module_wrapper_t(types.ModuleType):

        def __init__(self, orig):
            self.orig = orig

        def __getattribute__(self, name):
            if name in pdict:
                return pdict[name][0]()
            elif name == 'orig':
                return types.ModuleType.__getattribute__(self, name)
            elif name == '__dict__':
                d = self.orig.__dict__
                d = d.copy()
                for name in pdict:
                    d[name] = pdict[name][0]()
                return d
            else:
                return getattr(self.orig, name)

        def __setattr__(self, name, value):
            if name == 'orig':
                types.ModuleType.__setattr__(self, name, value)
            else:
                return setattr(self.orig, name, value)
    sys.modules[modname] = _module_wrapper_t(sys.modules[modname])


__set_module_dynattrs(__name__, {'MAXADDR': (lambda :
    inf_get_privrange_start_ea(), None)})

```
