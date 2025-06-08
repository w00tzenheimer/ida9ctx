```python
"""Merge functionality.

NOTE: this functionality is available in IDA Teams (not IDA Pro)
There are 3 databases involved in merging: base_idb, local_db, and remote_idb.
* base_idb: the common base ancestor of 'local_db' and 'remote_db'. in the UI this database is located in the middle.
* local_idb: local database that will contain the result of the merging. in the UI this database is located on the left.
* remote_idb: remote database that will merge into local_idb. It may reside locally on the current computer, despite its name. in the UI this database is located on the right. base_idb and remote_idb are opened for reading only. base_idb may be absent, in this case a 2-way merging is performed.


Conflicts can be resolved automatically or interactively. The automatic resolving scores the conflicting blocks and takes the better one. The interactive resolving displays the full rendered contents side by side, and expects the user to select the better side for each conflict.
Since IDB files contain various kinds of information, there are many merging phases. The entire list can be found in merge.cpp. Below are just some selected examples:
* merge global database settings (inf and other global vars)
* merge segmentation and changes to the database bytes
* merge various lists: exports, imports, loaded tils, etc
* merge names, functions, function frames
* merge debugger settings, breakpoints
* merge struct/enum views
* merge local type libraries
* merge the disassembly items (i.e. the segment contents) this includes operand types, code/data separation, etc
* merge plugin specific info like decompiler types, dwarf mappings, etc


To unify UI elements of each merge phase, we use merger views:
* A view that consists of 2 or 3 panes: left (local_idb) and right (remote_idb). The common base is in the middle, if present.
* Rendering of the panes depends on the phase, different phases show different contents.
* The conflicts are highlighted by a colored background. Also, the detail pane can be consulted for additional info.
* The user can select a conflict (or a bunch of conflicts) and say "use this block".
* The user can browse the panes as he wishes. He will not be forced to handle conflicts in any particular order. However, once he finishes working with a merge handler and proceeds to the next one, he cannot go back.
* Scrolling the left pane will synchronously scroll the right pane and vice versa.
* There are the navigation commands like "go to the prev/next conflict"
* The number of remaining conflicts to resolve is printed in the "Progress" chooser.
* The user may manually modify local database inside the merger view. For that he may use the regular hotkeys. However, editing the database may lead to new conflicts, so we better restrict the available actions to some reasonable minimum. Currently, this is not implemented.


IDA works in a new "merge" mode during merging. In this mode most events are not generated. We forbid them to reduce the risk that a rogue third-party plugin that is not aware of the "merge" mode would spoil something.
For example, normally renaming a function causes a cascade of events and may lead to other database modifications. Some of them may be desired, some - not. Since there are some undesired events, it is better to stop generating them. However, some events are required to render the disassembly listing. For example, ev_ana_insn, av_out_insn. This is why some events are still generated in the "merge" mode.
To let processor modules and plugins merge their data, we introduce a new event: ev_create_merge_handlers. It is generated immediately after opening all three idbs. The interested modules should react to this event by creating new merge handlers, if they need them.
While the kernel can create arbitrary merge handlers, modules can create only the standard ones returned by:
create_nodeval_merge_handler() create_nodeval_merge_handlers() create_std_modmerge_handlers()
We do not document merge_handler_t because once a merge handler is created, it is used exclusively by the kernel.
See mergemod.hpp for more information about the merge mode for modules. 
    """
from sys import version_info as _swig_python_version_info
if __package__ or '.' in __name__:
    from . import _ida_merge
else:
    import _ida_merge
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
SWIG_PYTHON_LEGACY_BOOL = _ida_merge.SWIG_PYTHON_LEGACY_BOOL
from typing import Tuple, List, Union
import ida_idaapi
MERGE_KIND_NETNODE = _ida_merge.MERGE_KIND_NETNODE
"""netnode (no merging, to be used in idbunits)
"""
MERGE_KIND_AUTOQ = _ida_merge.MERGE_KIND_AUTOQ
"""auto queues
"""
MERGE_KIND_INF = _ida_merge.MERGE_KIND_INF
"""merge the inf variable (global settings)
"""
MERGE_KIND_ENCODINGS = _ida_merge.MERGE_KIND_ENCODINGS
"""merge encodings
"""
MERGE_KIND_ENCODINGS2 = _ida_merge.MERGE_KIND_ENCODINGS2
"""merge default encodings
"""
MERGE_KIND_SCRIPTS2 = _ida_merge.MERGE_KIND_SCRIPTS2
"""merge scripts common info
"""
MERGE_KIND_SCRIPTS = _ida_merge.MERGE_KIND_SCRIPTS
"""merge scripts
"""
MERGE_KIND_CUSTDATA = _ida_merge.MERGE_KIND_CUSTDATA
"""merge custom data type and formats
"""
MERGE_KIND_ENUMS = _ida_merge.MERGE_KIND_ENUMS
"""merge enums
"""
MERGE_KIND_STRUCTS = _ida_merge.MERGE_KIND_STRUCTS
"""merge structs (globally: add/delete structs entirely)
"""
MERGE_KIND_TILS = _ida_merge.MERGE_KIND_TILS
"""merge type libraries
"""
MERGE_KIND_TINFO = _ida_merge.MERGE_KIND_TINFO
"""merge tinfo
"""
MERGE_KIND_STRMEM = _ida_merge.MERGE_KIND_STRMEM
"""merge struct members
"""
MERGE_KIND_UDTMEM = _ida_merge.MERGE_KIND_UDTMEM
"""merge UDT members (local types)
"""
MERGE_KIND_GHSTRCMT = _ida_merge.MERGE_KIND_GHSTRCMT
"""merge ghost structure comment
"""
MERGE_KIND_STRMEMCMT = _ida_merge.MERGE_KIND_STRMEMCMT
"""merge member comments for ghost struc
"""
MERGE_KIND_SELECTORS = _ida_merge.MERGE_KIND_SELECTORS
"""merge selectors
"""
MERGE_KIND_STT = _ida_merge.MERGE_KIND_STT
"""merge flag storage types
"""
MERGE_KIND_SEGMENTS = _ida_merge.MERGE_KIND_SEGMENTS
"""merge segments
"""
MERGE_KIND_SEGGRPS = _ida_merge.MERGE_KIND_SEGGRPS
"""merge segment groups
"""
MERGE_KIND_SEGREGS = _ida_merge.MERGE_KIND_SEGREGS
"""merge segment registers
"""
MERGE_KIND_ORPHANS = _ida_merge.MERGE_KIND_ORPHANS
"""merge orphan bytes
"""
MERGE_KIND_BYTEVAL = _ida_merge.MERGE_KIND_BYTEVAL
"""merge byte values
"""
MERGE_KIND_FIXUPS = _ida_merge.MERGE_KIND_FIXUPS
"""merge fixups
"""
MERGE_KIND_MAPPING = _ida_merge.MERGE_KIND_MAPPING
"""merge manual memory mapping
"""
MERGE_KIND_EXPORTS = _ida_merge.MERGE_KIND_EXPORTS
"""merge exports
"""
MERGE_KIND_IMPORTS = _ida_merge.MERGE_KIND_IMPORTS
"""merge imports
"""
MERGE_KIND_PATCHES = _ida_merge.MERGE_KIND_PATCHES
"""merge patched bytes
"""
MERGE_KIND_FLAGS = _ida_merge.MERGE_KIND_FLAGS
"""merge flags64_t
"""
MERGE_KIND_EXTRACMT = _ida_merge.MERGE_KIND_EXTRACMT
"""merge extra next or prev lines
"""
MERGE_KIND_AFLAGS_EA = _ida_merge.MERGE_KIND_AFLAGS_EA
"""merge aflags for mapped EA
"""
MERGE_KIND_IGNOREMICRO = _ida_merge.MERGE_KIND_IGNOREMICRO
"""IM ("$ ignore micro") flags.
"""
MERGE_KIND_FILEREGIONS = _ida_merge.MERGE_KIND_FILEREGIONS
"""merge fileregions
"""
MERGE_KIND_HIDDENRANGES = _ida_merge.MERGE_KIND_HIDDENRANGES
"""merge hidden ranges
"""
MERGE_KIND_SOURCEFILES = _ida_merge.MERGE_KIND_SOURCEFILES
"""merge source files ranges
"""
MERGE_KIND_FUNC = _ida_merge.MERGE_KIND_FUNC
"""merge func info
"""
MERGE_KIND_FRAMEMGR = _ida_merge.MERGE_KIND_FRAMEMGR
"""merge frames (globally: add/delete frames entirely)
"""
MERGE_KIND_FRAME = _ida_merge.MERGE_KIND_FRAME
"""merge function frame info (frame members)
"""
MERGE_KIND_STKPNTS = _ida_merge.MERGE_KIND_STKPNTS
"""merge SP change points
"""
MERGE_KIND_FLOWS = _ida_merge.MERGE_KIND_FLOWS
"""merge flows
"""
MERGE_KIND_CREFS = _ida_merge.MERGE_KIND_CREFS
"""merge crefs
"""
MERGE_KIND_DREFS = _ida_merge.MERGE_KIND_DREFS
"""merge drefs
"""
MERGE_KIND_BPTS = _ida_merge.MERGE_KIND_BPTS
"""merge breakpoints
"""
MERGE_KIND_WATCHPOINTS = _ida_merge.MERGE_KIND_WATCHPOINTS
"""merge watchpoints
"""
MERGE_KIND_BOOKMARKS = _ida_merge.MERGE_KIND_BOOKMARKS
"""merge bookmarks
"""
MERGE_KIND_TRYBLKS = _ida_merge.MERGE_KIND_TRYBLKS
"""merge try blocks
"""
MERGE_KIND_DIRTREE = _ida_merge.MERGE_KIND_DIRTREE
"""merge std dirtrees
"""
MERGE_KIND_VFTABLES = _ida_merge.MERGE_KIND_VFTABLES
"""merge vftables
"""
MERGE_KIND_SIGNATURES = _ida_merge.MERGE_KIND_SIGNATURES
"""signatures
"""
MERGE_KIND_PROBLEMS = _ida_merge.MERGE_KIND_PROBLEMS
"""problems
"""
MERGE_KIND_UI = _ida_merge.MERGE_KIND_UI
"""UI.
"""
MERGE_KIND_DEKSTOPS = _ida_merge.MERGE_KIND_DEKSTOPS
"""dekstops
"""
MERGE_KIND_NOTEPAD = _ida_merge.MERGE_KIND_NOTEPAD
"""notepad
"""
MERGE_KIND_LOADER = _ida_merge.MERGE_KIND_LOADER
"""loader data
"""
MERGE_KIND_DEBUGGER = _ida_merge.MERGE_KIND_DEBUGGER
"""debugger data
"""
MERGE_KIND_DBG_MEMREGS = _ida_merge.MERGE_KIND_DBG_MEMREGS
"""manual memory regions (debugger)
"""
MERGE_KIND_LUMINA = _ida_merge.MERGE_KIND_LUMINA
"""lumina function metadata
"""
MERGE_KIND_LAST = _ida_merge.MERGE_KIND_LAST
"""last predefined merge handler type. please note that there can be more merge handler types, registered by plugins and processor modules. 
          """
MERGE_KIND_END = _ida_merge.MERGE_KIND_END
"""insert to the end of handler list, valid for merge_handler_params_t::insert_after 
          """
MERGE_KIND_NONE = _ida_merge.MERGE_KIND_NONE


def is_diff_merge_mode() ->bool:
    """Return TRUE if IDA is running in diff mode (MERGE_POLICY_MDIFF/MERGE_POLICY_VDIFF)
"""
    return _ida_merge.is_diff_merge_mode()


class merge_data_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')

    def __init__(self, *args, **kwargs):
        raise AttributeError('No constructor defined')
    __repr__ = _swig_repr
    dbctx_ids: 'int [3]' = property(_ida_merge.merge_data_t_dbctx_ids_get,
        _ida_merge.merge_data_t_dbctx_ids_set)
    """local, remote, base ids
"""
    nbases: 'int' = property(_ida_merge.merge_data_t_nbases_get, _ida_merge
        .merge_data_t_nbases_set)
    """number of database participating in merge process, maybe 2 or 3 
        """
    ev_handlers: 'merge_handlers_t' = property(_ida_merge.
        merge_data_t_ev_handlers_get, _ida_merge.merge_data_t_ev_handlers_set)
    """event handlers
"""
    item_block_locator: 'merge_data_t::item_block_locator_t *' = property(
        _ida_merge.merge_data_t_item_block_locator_get, _ida_merge.
        merge_data_t_item_block_locator_set)
    last_udt_related_merger: 'merge_handler_t *' = property(_ida_merge.
        merge_data_t_last_udt_related_merger_get, _ida_merge.
        merge_data_t_last_udt_related_merger_set)

    def set_dbctx_ids(self, local: int, remote: int, base: int) ->None:
        return _ida_merge.merge_data_t_set_dbctx_ids(self, local, remote, base)

    def local_id(self) ->int:
        return _ida_merge.merge_data_t_local_id(self)

    def remote_id(self) ->int:
        return _ida_merge.merge_data_t_remote_id(self)

    def base_id(self) ->int:
        return _ida_merge.merge_data_t_base_id(self)

    def add_event_handler(self, handler: 'merge_handler_t *') ->None:
        return _ida_merge.merge_data_t_add_event_handler(self, handler)

    def remove_event_handler(self, handler: 'merge_handler_t *') ->None:
        return _ida_merge.merge_data_t_remove_event_handler(self, handler)

    def get_block_head(self, idx: 'diff_source_idx_t', item_head:
        ida_idaapi.ea_t) ->ida_idaapi.ea_t:
        return _ida_merge.merge_data_t_get_block_head(self, idx, item_head)

    def setup_blocks(self, dst_idx: 'diff_source_idx_t', src_idx:
        'diff_source_idx_t', region: 'diff_range_t const &') ->bool:
        return _ida_merge.merge_data_t_setup_blocks(self, dst_idx, src_idx,
            region)

    def has_existing_node(self, nodename: str) ->bool:
        """check that node exists in any of databases
"""
        return _ida_merge.merge_data_t_has_existing_node(self, nodename)

    def map_privrange_id(self, tid: 'tid_t *', ea: ida_idaapi.ea_t, _from:
        'diff_source_idx_t', to: 'diff_source_idx_t', strict: bool=True
        ) ->bool:
        """map IDs of structures, enumerations and their members 
        
@param tid: item ID in TO database
@param ea: item ID to find counterpart
@param to: destination database index, diff_source_idx_t
@param strict: raise interr if could not map
@returns success"""
        return _ida_merge.merge_data_t_map_privrange_id(self, tid, ea,
            _from, to, strict)

    def map_tinfo(self, tif: 'tinfo_t', _from: 'diff_source_idx_t', to:
        'diff_source_idx_t', strict: bool=True) ->bool:
        """migrate type, replaces type references into FROM database to references into TO database 
        
@param tif: type to migrate, will be cleared in case of fail
@param to: destination database index, diff_source_idx_t
@param strict: raise interr if could not map
@returns success"""
        return _ida_merge.merge_data_t_map_tinfo(self, tif, _from, to, strict)

    def compare_merging_tifs(self, tif1: 'tinfo_t', diffidx1:
        'diff_source_idx_t', tif2: 'tinfo_t', diffidx2: 'diff_source_idx_t'
        ) ->int:
        """compare types from two databases 
        
@param tif1: type
@param diffidx1: database index, diff_source_idx_t
@param tif2: type
@param diffidx2: database index, diff_source_idx_t
@returns -1, 0, 1"""
        return _ida_merge.merge_data_t_compare_merging_tifs(self, tif1,
            diffidx1, tif2, diffidx2)


_ida_merge.merge_data_t_swigregister(merge_data_t)


class item_block_locator_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr

    def get_block_head(self, md: 'merge_data_t', idx: 'diff_source_idx_t',
        item_head: ida_idaapi.ea_t) ->ida_idaapi.ea_t:
        return _ida_merge.item_block_locator_t_get_block_head(self, md, idx,
            item_head)

    def setup_blocks(self, md: 'merge_data_t', _from: 'diff_source_idx_t',
        to: 'diff_source_idx_t', region: 'diff_range_t const &') ->bool:
        return _ida_merge.item_block_locator_t_setup_blocks(self, md, _from,
            to, region)
    __swig_destroy__ = _ida_merge.delete_item_block_locator_t

    def __init__(self):
        if self.__class__ == item_block_locator_t:
            _self = None
        else:
            _self = self
        _ida_merge.item_block_locator_t_swiginit(self, _ida_merge.
            new_item_block_locator_t(_self))

    def __disown__(self):
        self.this.disown()
        _ida_merge.disown_item_block_locator_t(self)
        return weakref.proxy(self)


_ida_merge.item_block_locator_t_swigregister(item_block_locator_t)


class merge_handler_params_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    md: 'merge_data_t &' = property(_ida_merge.merge_handler_params_t_md_get)
    label: 'qstring' = property(_ida_merge.merge_handler_params_t_label_get,
        _ida_merge.merge_handler_params_t_label_set)
    kind: 'merge_kind_t' = property(_ida_merge.
        merge_handler_params_t_kind_get, _ida_merge.
        merge_handler_params_t_kind_set)
    """merge handler kind merge_kind_t
"""
    insert_after: 'merge_kind_t' = property(_ida_merge.
        merge_handler_params_t_insert_after_get, _ida_merge.
        merge_handler_params_t_insert_after_set)
    """desired position inside 'handlers' merge_kind_t
"""
    mh_flags: 'uint32' = property(_ida_merge.
        merge_handler_params_t_mh_flags_get, _ida_merge.
        merge_handler_params_t_mh_flags_set)

    def __init__(self, _md: 'merge_data_t', _label: str, _kind:
        'merge_kind_t', _insert_after: 'merge_kind_t', _mh_flags: int):
        _ida_merge.merge_handler_params_t_swiginit(self, _ida_merge.
            new_merge_handler_params_t(_md, _label, _kind, _insert_after,
            _mh_flags))

    def ui_has_details(self, *args) ->bool:
        """This function has the following signatures:

    0. ui_has_details() -> bool
    1. ui_has_details(_mh_flags: int) -> bool

# 0: ui_has_details() -> bool


# 1: ui_has_details(_mh_flags: int) -> bool

Should IDA display the diffpos detail pane?

"""
        return _ida_merge.merge_handler_params_t_ui_has_details(self, *args)

    def ui_complex_details(self, *args) ->bool:
        """This function has the following signatures:

    0. ui_complex_details() -> bool
    1. ui_complex_details(_mh_flags: int) -> bool

# 0: ui_complex_details() -> bool


# 1: ui_complex_details(_mh_flags: int) -> bool

Do not display the diffpos details in the chooser. For example, the MERGE_KIND_SCRIPTS handler puts the script body as the diffpos detail. It would not be great to show them as part of the chooser. 
        
"""
        return _ida_merge.merge_handler_params_t_ui_complex_details(self, *args
            )

    def ui_complex_name(self, *args) ->bool:
        """This function has the following signatures:

    0. ui_complex_name() -> bool
    1. ui_complex_name(_mh_flags: int) -> bool

# 0: ui_complex_name() -> bool


# 1: ui_complex_name(_mh_flags: int) -> bool

It customary to create long diffpos names having many components that are separated by any 7-bit ASCII character (besides of '\\0'). In this case it is possible to instruct IDA to use this separator to create a multi-column chooser. For example the MERGE_KIND_ENUMS handler has the following diffpos name: enum_1,enum_2 If MH_UI_COMMANAME is specified, IDA will create 2 columns for these names. 
        
"""
        return _ida_merge.merge_handler_params_t_ui_complex_name(self, *args)

    def ui_split_char(self, *args) ->'char':
        """This function has the following signatures:

    0. ui_split_char() -> char
    1. ui_split_char(_mh_flags: int) -> char

# 0: ui_split_char() -> char


# 1: ui_split_char(_mh_flags: int) -> char

"""
        return _ida_merge.merge_handler_params_t_ui_split_char(self, *args)

    def ui_split_str(self, *args) ->str:
        """This function has the following signatures:

    0. ui_split_str() -> str
    1. ui_split_str(_mh_flags: int) -> str

# 0: ui_split_str() -> str


# 1: ui_split_str(_mh_flags: int) -> str

"""
        return _ida_merge.merge_handler_params_t_ui_split_str(self, *args)

    def ui_dp_shortname(self, *args) ->bool:
        """This function has the following signatures:

    0. ui_dp_shortname() -> bool
    1. ui_dp_shortname(_mh_flags: int) -> bool

# 0: ui_dp_shortname() -> bool


# 1: ui_dp_shortname(_mh_flags: int) -> bool

The detail pane shows the diffpos details for the current diffpos range as a tree-like view. In this pane the diffpos names are used as tree node names and the diffpos details as their children. Sometimes, for complex diffpos names, the first part of the name looks better than the entire name. For example, the MERGE_KIND_SEGMENTS handler has the following diffpos name: <range>,<segm1>,<segm2>,<segm3> if MH_UI_DP_SHORTNAME is specified, IDA will use <range> as a tree node name 
        
"""
        return _ida_merge.merge_handler_params_t_ui_dp_shortname(self, *args)

    def ui_linediff(self, *args) ->bool:
        """This function has the following signatures:

    0. ui_linediff() -> bool
    1. ui_linediff(_mh_flags: int) -> bool

# 0: ui_linediff() -> bool


# 1: ui_linediff(_mh_flags: int) -> bool

In detail pane IDA shows difference between diffpos details. IDA marks added or deleted detail by color. In the modified detail the changes are marked. Use this UI hint if you do not want to show the differences inside detail. 
        
"""
        return _ida_merge.merge_handler_params_t_ui_linediff(self, *args)

    def ui_indent(self, *args) ->bool:
        """This function has the following signatures:

    0. ui_indent() -> bool
    1. ui_indent(_mh_flags: int) -> bool

# 0: ui_indent() -> bool


# 1: ui_indent(_mh_flags: int) -> bool

In the ordinary situation the spaces from the both sides of diffpos name are trimmed. Use this UI hint to preserve the leading spaces. 
        
"""
        return _ida_merge.merge_handler_params_t_ui_indent(self, *args)
    __swig_destroy__ = _ida_merge.delete_merge_handler_params_t


_ida_merge.merge_handler_params_t_swigregister(merge_handler_params_t)
MH_LISTEN = _ida_merge.MH_LISTEN
"""merge handler will receive merge events
"""
MH_TERSE = _ida_merge.MH_TERSE
"""do not display equal lines in the merge results table
"""
MH_UI_NODETAILS = _ida_merge.MH_UI_NODETAILS
"""ida will not show the diffpos details
"""
MH_UI_COMPLEX = _ida_merge.MH_UI_COMPLEX
"""diffpos details won't be displayed in the diffpos chooser
"""
MH_UI_DP_NOLINEDIFF = _ida_merge.MH_UI_DP_NOLINEDIFF
"""Detail pane: do not show differences inside the line.
"""
MH_UI_DP_SHORTNAME = _ida_merge.MH_UI_DP_SHORTNAME
"""Detail pane: use the first part of a complex diffpos name as the tree node name.
"""
MH_UI_INDENT = _ida_merge.MH_UI_INDENT
"""preserve indent for diffpos name in diffpos chooser
"""
MH_UI_SPLITNAME = _ida_merge.MH_UI_SPLITNAME
"""ida will split the diffpos name by 7-bit ASCII char to create chooser columns 
        """
MH_UI_CHAR_MASK = _ida_merge.MH_UI_CHAR_MASK
"""7-bit ASCII split character
"""
MH_UI_COMMANAME = _ida_merge.MH_UI_COMMANAME
"""ida will split the diffpos name by ',' to create chooser columns
"""
MH_UI_COLONNAME = _ida_merge.MH_UI_COLONNAME
"""ida will split the diffpos name by ':' to create chooser columns
"""


class moddata_diff_helper_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    module_name: 'char const *' = property(_ida_merge.
        moddata_diff_helper_t_module_name_get, _ida_merge.
        moddata_diff_helper_t_module_name_set)
    """will be used as a prefix for field desc
"""
    netnode_name: 'char const *' = property(_ida_merge.
        moddata_diff_helper_t_netnode_name_get, _ida_merge.
        moddata_diff_helper_t_netnode_name_set)
    """name of netnode with module data attributes
"""
    fields: 'idbattr_info_t const *' = property(_ida_merge.
        moddata_diff_helper_t_fields_get, _ida_merge.
        moddata_diff_helper_t_fields_set)
    """module data attribute descriptions
"""
    nfields: 'size_t' = property(_ida_merge.
        moddata_diff_helper_t_nfields_get, _ida_merge.
        moddata_diff_helper_t_nfields_set)
    """number of descriptions
"""
    additional_mh_flags: 'uint32' = property(_ida_merge.
        moddata_diff_helper_t_additional_mh_flags_get, _ida_merge.
        moddata_diff_helper_t_additional_mh_flags_set)
    """additional merge handler flags
"""

    def __init__(self, _module_name: str, _netnode_name: str, _fields:
        'idbattr_info_t'):
        if self.__class__ == moddata_diff_helper_t:
            _self = None
        else:
            _self = self
        _ida_merge.moddata_diff_helper_t_swiginit(self, _ida_merge.
            new_moddata_diff_helper_t(_self, _module_name, _netnode_name,
            _fields))
    __swig_destroy__ = _ida_merge.delete_moddata_diff_helper_t

    def merge_starting(self, arg0: 'diff_source_idx_t', arg1: 'void *') ->None:
        return _ida_merge.moddata_diff_helper_t_merge_starting(self, arg0, arg1
            )

    def merge_ending(self, arg0: 'diff_source_idx_t', arg1: 'void *') ->None:
        return _ida_merge.moddata_diff_helper_t_merge_ending(self, arg0, arg1)

    def get_struc_ptr(self, arg0: 'merge_data_t', arg1: 'diff_source_idx_t',
        arg2: 'idbattr_info_t') ->'void *':
        return _ida_merge.moddata_diff_helper_t_get_struc_ptr(self, arg0,
            arg1, arg2)

    def print_diffpos_details(self, arg0: 'qstrvec_t *', arg1: 'idbattr_info_t'
        ) ->None:
        return _ida_merge.moddata_diff_helper_t_print_diffpos_details(self,
            arg0, arg1)

    def val2str(self, arg0: str, arg1: 'idbattr_info_t', arg2: 'uint64'
        ) ->bool:
        return _ida_merge.moddata_diff_helper_t_val2str(self, arg0, arg1, arg2)

    def str2val(self, arg0: 'uint64 *', arg1: 'idbattr_info_t', arg2: str
        ) ->bool:
        return _ida_merge.moddata_diff_helper_t_str2val(self, arg0, arg1, arg2)

    def __disown__(self):
        self.this.disown()
        _ida_merge.disown_moddata_diff_helper_t(self)
        return weakref.proxy(self)


_ida_merge.moddata_diff_helper_t_swigregister(moddata_diff_helper_t)
NDS_IS_BOOL = _ida_merge.NDS_IS_BOOL
"""boolean value
"""
NDS_IS_EA = _ida_merge.NDS_IS_EA
"""EA value.
"""
NDS_IS_RELATIVE = _ida_merge.NDS_IS_RELATIVE
"""value is relative to index (stored as delta)
"""
NDS_IS_STR = _ida_merge.NDS_IS_STR
"""string value
"""
NDS_SUPVAL = _ida_merge.NDS_SUPVAL
"""stored as netnode supvals (not scalar)
"""
NDS_BLOB = _ida_merge.NDS_BLOB
"""stored as netnode blobs
"""
NDS_EV_RANGE = _ida_merge.NDS_EV_RANGE
"""enable default handling of mev_modified_ranges, mev_deleting_segm
"""
NDS_EV_FUNC = _ida_merge.NDS_EV_FUNC
"""enable default handling of mev_added_func/mev_deleting_func
"""
NDS_MAP_IDX = _ida_merge.NDS_MAP_IDX
"""apply ea2node() to index (==NETMAP_IDX)
"""
NDS_MAP_VAL = _ida_merge.NDS_MAP_VAL
"""apply ea2node() to value. Along with NDS_INC it gives effect of NETMAP_VAL, examples: altval_ea : NDS_MAP_IDX charval : NDS_VAL8 charval_ea: NDS_MAP_IDX|NDS_VAL8 eaget : NDS_MAP_IDX|NDS_MAP_VAL|NDS_INC 
          """
NDS_VAL8 = _ida_merge.NDS_VAL8
"""use 8-bit values (==NETMAP_V8)
"""
NDS_INC = _ida_merge.NDS_INC
"""stored value is incremented (scalars only)
"""
NDS_UI_ND = _ida_merge.NDS_UI_ND
"""UI: no need to show diffpos detail pane, MH_UI_NODETAILS, make sense if merge_node_helper_t is used 
          """


class merge_node_helper_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    __swig_destroy__ = _ida_merge.delete_merge_node_helper_t

    def print_entry_name(self, arg0: 'uchar', arg1: 'nodeidx_t', arg2: 'void *'
        ) ->str:
        """print the name of the specified entry (to be used in print_diffpos_name) 
        """
        return _ida_merge.merge_node_helper_t_print_entry_name(self, arg0,
            arg1, arg2)

    def print_entry_details(self, arg0: 'qstrvec_t *', arg1: 'uchar', arg2:
        'nodeidx_t', arg3: 'void *') ->None:
        """print the details of the specified entry usually contains multiple lines, one for each attribute or detail. (to be used in print_diffpos_details) 
        """
        return _ida_merge.merge_node_helper_t_print_entry_details(self,
            arg0, arg1, arg2, arg3)

    def get_column_headers(self, arg0: 'qstrvec_t *', arg1: 'uchar', arg2:
        'void *') ->None:
        """get column headers for chooser (to be used in linear_diff_source_t::get_column_headers) 
        """
        return _ida_merge.merge_node_helper_t_get_column_headers(self, arg0,
            arg1, arg2)

    def is_mergeable(self, arg0: 'uchar', arg1: 'nodeidx_t') ->bool:
        """filter: check if we should perform merging for given record
"""
        return _ida_merge.merge_node_helper_t_is_mergeable(self, arg0, arg1)

    def get_netnode(self) ->'netnode':
        """return netnode to be used as source. If this function returns BADNODE netnode will be created using netnode name passed to create_nodeval_diff_source 
        """
        return _ida_merge.merge_node_helper_t_get_netnode(self)

    def map_scalar(self, arg0: 'nodeidx_t *', arg1: 'void *', arg2:
        'diff_source_idx_t', arg3: 'diff_source_idx_t') ->None:
        """map scalar/string/buffered value
"""
        return _ida_merge.merge_node_helper_t_map_scalar(self, arg0, arg1,
            arg2, arg3)

    def map_string(self, arg0: str, arg1: 'void *', arg2:
        'diff_source_idx_t', arg3: 'diff_source_idx_t') ->None:
        return _ida_merge.merge_node_helper_t_map_string(self, arg0, arg1,
            arg2, arg3)

    def refresh(self, arg0: 'uchar', arg1: 'void *') ->None:
        """notify helper that some data was changed in the database and internal structures (e.g. caches) should be refreshed 
        """
        return _ida_merge.merge_node_helper_t_refresh(self, arg0, arg1)

    @staticmethod
    def append_eavec(s: str, prefix: str, eas: 'eavec_t const &') ->None:
        """can be used by derived classes
"""
        return _ida_merge.merge_node_helper_t_append_eavec(s, prefix, eas)

    def __init__(self):
        if self.__class__ == merge_node_helper_t:
            _self = None
        else:
            _self = self
        _ida_merge.merge_node_helper_t_swiginit(self, _ida_merge.
            new_merge_node_helper_t(_self))

    def __disown__(self):
        self.this.disown()
        _ida_merge.disown_merge_node_helper_t(self)
        return weakref.proxy(self)


_ida_merge.merge_node_helper_t_swigregister(merge_node_helper_t)


class merge_node_info_t(object):
    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v),
        doc='The membership flag')
    __repr__ = _swig_repr
    name: 'char const *' = property(_ida_merge.merge_node_info_t_name_get,
        _ida_merge.merge_node_info_t_name_set)
    """name of the array (label)
"""
    tag: 'uchar' = property(_ida_merge.merge_node_info_t_tag_get,
        _ida_merge.merge_node_info_t_tag_set)
    """a tag used to access values in the netnode
"""
    nds_flags: 'uint32' = property(_ida_merge.
        merge_node_info_t_nds_flags_get, _ida_merge.
        merge_node_info_t_nds_flags_set)
    """node value attributes (a combination of nds_flags_t)
"""
    node_helper: 'merge_node_helper_t *' = property(_ida_merge.
        merge_node_info_t_node_helper_get, _ida_merge.
        merge_node_info_t_node_helper_set)

    def __init__(self, name: str, tag: 'uchar', nds_flags: int, node_helper:
        'merge_node_helper_t'=None):
        _ida_merge.merge_node_info_t_swiginit(self, _ida_merge.
            new_merge_node_info_t(name, tag, nds_flags, node_helper))
    __swig_destroy__ = _ida_merge.delete_merge_node_info_t


_ida_merge.merge_node_info_t_swigregister(merge_node_info_t)


def create_nodeval_merge_handler(mhp: 'merge_handler_params_t', label: str,
    nodename: str, tag: 'uchar', nds_flags: int, node_helper:
    'merge_node_helper_t'=None, skip_empty_nodes: bool=True
    ) ->'merge_handler_t *':
    """Create a merge handler for netnode scalar/string values 
        
@param mhp: merging parameters
@param label: handler short name (to be be appended to mhp.label)
@param nodename: netnode name
@param tag: a tag used to access values in the netnode
@param nds_flags: netnode value attributes (a combination of nds_flags_t)
@param skip_empty_nodes: do not create handler in case of empty netnode
@returns diff source object (normally should be attahced to a merge handler)"""
    return _ida_merge.create_nodeval_merge_handler(mhp, label, nodename,
        tag, nds_flags, node_helper, skip_empty_nodes)


def create_nodeval_merge_handlers(out: 'merge_handlers_t *', mhp:
    'merge_handler_params_t', nodename: str, valdesc: 'merge_node_info_t',
    skip_empty_nodes: bool=True) ->None:
    """Create a serie of merge handlers for netnode scalar/string values (call create_nodeval_merge_handler() for each member of VALDESC) 
        
@param out: [out] created handlers will be placed here
@param mhp: merging parameters
@param nodename: netnode name
@param valdesc: array of handler descriptions
@param skip_empty_nodes: do not create handlers for empty netnodes
@returns diff source object (normally should be attahced to a merge handler)"""
    return _ida_merge.create_nodeval_merge_handlers(out, mhp, nodename,
        valdesc, skip_empty_nodes)


def destroy_moddata_merge_handlers(data_id: int) ->None:
    return _ida_merge.destroy_moddata_merge_handlers(data_id)


def get_ea_diffpos_name(ea: ida_idaapi.ea_t) ->str:
    """Get nice name for EA diffpos 
        
@param ea: diffpos"""
    return _ida_merge.get_ea_diffpos_name(ea)

```
