```text
#ifndef __HEADER_I__
#define __HEADER_I__

%begin %{
#define PY_SSIZE_T_CLEAN 1
%}

%{
#ifndef USE_DANGEROUS_FUNCTIONS
  #define USE_DANGEROUS_FUNCTIONS 1
#endif
#include <pro.h>
#include <parsejson.hpp>
#undef DEPRECATED
#define DEPRECATED
%}

#define SWIG_PYTHON_LEGACY_BOOL 1

// Have SWiG flatten the hierarchy of types
// (instead of plain ignoring nested ones.)
%feature("flatnested");

%{
class plugin_t;
#ifdef __NT__
idaman __declspec(dllimport) plugin_t PLUGIN;
#else
extern plugin_t PLUGIN;
#endif
%}

// Auto-inserted header
// generate directors for all classes that have virtual methods
%feature("director");
// exceptions
%feature("nodirector") generic_linput64_t;
%feature("nodirector") generic_linput_t;
%feature("nodirector") place_t;
%feature("nodirector") idaplace_t;
%feature("nodirector") tiplace_t;
%feature("nodirector") qrefcnt_obj_t;
%feature("nodirector") qstring_printer_t;
%feature("nodirector") simpleline_place_t;
%feature("nodirector") structplace_t;
%feature("nodirector") qflow_chart_t;
%feature("nodirector") lowertype_helper_t;
%feature("nodirector") ida_lowertype_helper_t;
%warnfilter(473) user_lvar_visitor_t::get_info_mapping_for_saving; // Returning a pointer or reference in a director method is not recommended
// * http://swig.10945.n7.nabble.com/How-to-release-Python-GIL-td5027.html
// * http://stackoverflow.com/questions/1576737/releasing-python-gil-in-c-code
// * http://matt.eifelle.com/2007/11/23/enabling-thread-support-in-swig-and-python/
%nothread; // We don't want SWIG to release the GIL for *every* IDA API call.
// Suppress 'previous definition of XX' warnings
#pragma SWIG nowarn=302
// and others...
#pragma SWIG nowarn=312
#pragma SWIG nowarn=325
#pragma SWIG nowarn=328 // Value assigned to cb not used due to limited parsing implementation
#pragma SWIG nowarn=314
#pragma SWIG nowarn=362
#pragma SWIG nowarn=383
#pragma SWIG nowarn=389
#pragma SWIG nowarn=401
#pragma SWIG nowarn=451
#pragma SWIG nowarn=454 // Setting a pointer/reference variable may leak memory
#pragma SWIG nowarn=514 // Director base class 'x' has no virtual destructor.
#pragma SWIG nowarn=350 // operator new ignored
#pragma SWIG nowarn=394 // operator new[] ignored
#pragma SWIG nowarn=395 // operator delete[] ignored
#pragma SWIG nowarn=351 // operator delete ignored

%ignore qvector::at(size_t);
%ignore qvector::front;
%ignore qvector::back;

%ignore qlist::iterator::operator--;
%ignore qlist::const_iterator::operator--;
%ignore qlist::reverse_iterator::operator--;
%ignore qlist::const_reverse_iterator::operator--;
%ignore qlist::iterator::operator==;
%ignore qlist::const_iterator::operator==;
%ignore qlist::reverse_iterator::operator==;
%ignore qlist::const_reverse_iterator::operator==;
%ignore qlist::iterator::operator!=;
%ignore qlist::const_iterator::operator!=;
%ignore qlist::reverse_iterator::operator!=;
%ignore qlist::const_reverse_iterator::operator!=;
%ignore qlist::iterator;
%ignore qlist::const_iterator;
%ignore qlist::reverse_iterator;
%ignore qlist::const_reverse_iterator;


// To be used e.g., when a '#define' in the source code
// defines a uint32 value with the highest bit set, so that
// SWiG knows it's not a negative integer.
%define %predefine_uint32_macro(NAME, VALUE)
%rename (NAME) PY_##NAME;
%constant uint32 PY_##NAME = uint32(VALUE);
%ignore NAME;
%enddef

%define %uncomparable_elements_qvector(ELEMENT_TYPE, VECTOR_TYPE)
%ignore qvector<ELEMENT_TYPE>::operator==;
%ignore qvector<ELEMENT_TYPE>::operator!=;
%ignore qvector<ELEMENT_TYPE>::find;
%ignore qvector<ELEMENT_TYPE>::has;
%ignore qvector<ELEMENT_TYPE>::del;
%ignore qvector<ELEMENT_TYPE>::add_unique;
%template(VECTOR_TYPE) qvector<ELEMENT_TYPE>;
%enddef

%ignore bytevec_t;
%ignore qstrvec_t;
%ignore qthread_cb_t;

// Do not move this. We need to override the define from pro.h
#define CASSERT(type)

%pythoncode {
from typing import Tuple, List, Union

import ida_idaapi
}

//---------------------------------------------------------------------
%extend qvector {
  inline size_t __len__() const { return $self->size(); }

  // The fact that we are returning a const version of a reference to the
  // type is what allows SWIG to generate a wrapper for this method, that
  // will build an proper object (int, unsigned int, ...) instead
  // of a pointer. Remove the 'const', and you'll see that, in
  // SWIGINTERN PyObject *_wrap_uvalvec_t___getitem__(PyObject *SWIGUNUSEDPARM(self), PyObject *args) {
  // it will produce this:
  //    resultobj = SWIG_NewPointerObj(SWIG_as_voidptr(result), SWIGTYPE_p_unsigned_int, 0 |  0 );
  // instead of that:
  //    resultobj = SWIG_From_unsigned_SS_int(static_cast< unsigned int >(*result));
  inline const T &__getitem__(size_t i) const
  {
    if ( i >= $self->size() )
      throw std::out_of_range("out of bounds access");
    return $self->at(i);
  }

  inline void __setitem__(size_t i, const T &v)
  {
    if ( i >= $self->size() )
      throw std::out_of_range("out of bounds access");
    $self->at(i) = v;
  }

  inline void append(const T &x)
  {
    $self->push_back(x);
  }

  inline void extend(const qvector<T> &x)
  {
    $self->insert($self->end(), x.begin(), x.end());
  }

  %pythoncode {
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator
  }
}

//---------------------------------------------------------------------
%extend qlist {
  inline size_t __len__() const { return $self->size(); }

  inline const T &__getitem__(size_t i) const
  {
    if ( i >= $self->size() )
      throw std::out_of_range("out of bounds access");
    qlist<T>::const_iterator it = $self->begin();
    for ( size_t _i = 0; _i < i; ++_i )
      ++it;
    return *it;
  }

  inline void __setitem__(size_t i, const T &v)
  {
    if ( i >= $self->size() )
      throw std::out_of_range("out of bounds access");
    qlist<T>::iterator it = $self->begin();
    for ( size_t _i = 0; _i < i; ++_i )
      ++it;
    *it = v;
  }

  inline void insert(size_t i, const T &v)
  {
    if ( i > $self->size() )
      throw std::out_of_range("out of bounds access");
    qlist<T>::iterator it = $self->begin();
    for ( size_t _i = 0; _i < i; ++_i )
      ++it;
    $self->insert(it, v);
  }

  inline bool remove(const T &v)
  {
    qlist<T>::iterator it = $self->begin();
    for ( ; it != $self->end(); ++it )
    {
      if ( *it == v )
      {
        $self->erase(it);
        return true;
      }
    }
    return false;
  }

  %pythoncode {
    front = ida_idaapi._qvector_front
    back = ida_idaapi._qvector_back
    __iter__ = ida_idaapi._bounded_getitem_iterator

    def find(self, item):
        if item is not None:
            it = self.begin()
            for i in range(self.size()):
                if it.cur == item:
                    return it
                next(it)

    def index(self, item):
        if item is not None:
            it = self.begin()
            for i in range(self.size()):
                if it.cur == item:
                    return i
                next(it)

    def at(self, index):
        it = self.begin()
        for i in range(self.size()):
            if i == index:
                return it.cur
            next(it)
  }
}

%define %qlist_template(QLIST_TYPE, ELEMENT_TYPE)
// a typedef for the C++ side
%{
typedef qlist<ELEMENT_TYPE>::iterator QLIST_TYPE##_iterator;
%}
// we need a concrete type for the iterators, so SWiG properly
// generates type information, including a destructor (otherwise
// calling mylist.begin() will cause an ABORT for lack of dtor.)
class QLIST_TYPE##_iterator {};
%extend QLIST_TYPE##_iterator {
    const ELEMENT_TYPE &cur { return *(*self); }
    void __next__(void) { (*self)++; }
    bool operator==(const QLIST_TYPE##_iterator *x) const { return &(self->operator*()) == &(x->operator*()); }
    bool operator!=(const QLIST_TYPE##_iterator *x) const { return &(self->operator*()) != &(x->operator*()); }
    %pythoncode {
      next = __next__
    }
};
%extend qlist<ELEMENT_TYPE> {
    QLIST_TYPE##_iterator begin() { return self->begin(); }
    QLIST_TYPE##_iterator end(void) { return self->end(); }
    QLIST_TYPE##_iterator insert(QLIST_TYPE##_iterator p, const ELEMENT_TYPE& x) { return self->insert(p, x); }
    void erase(QLIST_TYPE##_iterator p) { self->erase(p); }
};
%ignore qlist< ELEMENT_TYPE >::insert(iterator);
%ignore qlist< ELEMENT_TYPE >::insert(iterator, const ELEMENT_TYPE &);
%ignore qlist< ELEMENT_TYPE >::insert(iterator, iterator, iterator);
%ignore qlist< ELEMENT_TYPE >::erase(iterator);
%ignore qlist< ELEMENT_TYPE >::erase(iterator, iterator);
%ignore qlist< ELEMENT_TYPE >::begin();
%ignore qlist< ELEMENT_TYPE >::begin() const;
%ignore qlist< ELEMENT_TYPE >::end();
%ignore qlist< ELEMENT_TYPE >::end() const;
%template(QLIST_TYPE) qlist<ELEMENT_TYPE>;
%enddef

#if IDAPYTHON_MODULE_hexrays
%define %ida_hexrays_wrapper_exception_catch()
    catch ( const vd_failure_t &e ) { __raise_vdf(e); SWIG_fail; }
%enddef
#else
%define %ida_hexrays_wrapper_exception_catch()%enddef
#endif

%define %exception_set_default_handlers()
%exception {
    try
    {
      set_interr_throws_t sit;
      $action
    }
    catch ( const std::bad_alloc &ba ) { __raise_ba(ba); SWIG_fail; }
    catch ( const std::out_of_range &e ) { __raise_oor(e); SWIG_fail; }
    catch ( const interr_exc_t &e ) { __raise_ie(e); SWIG_fail; }%ida_hexrays_wrapper_exception_catch()
    catch ( const Swig::DirectorException &e ) { __raise_de(e); SWIG_fail; }
    catch ( const std::exception &e ) { __raise_e(e); SWIG_fail; }
    catch ( ... ) { __raise_u(); SWIG_fail; }
}
%enddef
%exception_set_default_handlers();

// Enable C/C++ type annotations in function prototypes
%feature("python:annotations", "c");

%{
/* strnlen() arrived on OSX at v10.7. Provide it ourselves if needed. */
#ifdef __MAC__
#ifndef MAC_OS_X_VERSION_10_7
#define MAC_OS_X_VERSION_10_7 1070
#endif
#if (MAC_OS_X_VERSION_MAX_ALLOWED < MAC_OS_X_VERSION_10_7)
inline size_t strnlen(const char *s, size_t maxlen)
{
  const char *found = (const char *) memchr(s, 0, maxlen);
  return found != nullptr ? size_t(found - s) : maxlen;
}
#endif
#endif
%}

%define SWIG_DECLARE_PY_CLINKED_OBJECT(type)
%inline %{
static PyObject *type##_create()
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  return PyCapsule_New(new type(), VALID_CAPSULE_NAME, nullptr);
}
static bool type##_destroy(PyObject *py_obj)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !PyCapsule_IsValid(py_obj, VALID_CAPSULE_NAME) )
    return false;
  delete (type *)PyCapsule_GetPointer(py_obj, VALID_CAPSULE_NAME);
  return true;
}
static type *type##_get_clink(PyObject *self)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  return (type *)pyobj_get_clink(self);
}
static PyObject *type##_get_clink_ptr(PyObject *self)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  return PyLong_FromUnsignedLongLong(
          PTR2U64(pyobj_get_clink(self)));
}
%}
%enddef

// We use those special maps because SWIG wraps passed PyObject* with 'SwigPtr_PyObject' and 'SwigVar_PyObject'
// They act like autoptr and decrement the reference of the object when the scope ends
// We need to keep a reference outside SWIG and let the caller manage its references
%typemap(directorin)  PyObject * "/*%din%*/Py_XINCREF($1_name);$input = $1_name;"
%typemap(directorout) PyObject * "/*%dout%*/$result = result;Py_XINCREF($result);"

//---------------------------------------------------------------------
%define %treat_serialized_tinfo_raw_pointer_as_bytes_1(_TYPE)
%typemap(in) _TYPE *
{ // %treat_serialized_tinfo_raw_pointer_as_bytes_1 %typemap(in) _TYPE *
  if ( $input == Py_None )
    $1 = ($1_ltype) nullptr;
  else if ( PyBytes_Check($input) )
    $1 = ($1_ltype) PyBytes_AsString($input);
  else
    SWIG_exception_fail(
            SWIG_ValueError,
            "Expected bytes " "in method '" "$symname" "', argument " "$argnum"" of type 'bytes'");
}
%typemap(directorin) _TYPE *
{ // %treat_serialized_tinfo_raw_pointer_as_bytes_1 %typemap(directorin) _TYPE *
  $input = PyBytes_FromString($1 != nullptr ? (const char *) $1 : "");
}
%typemap(out) _TYPE *
{ // %treat_serialized_tinfo_raw_pointer_as_bytes_1 %typemap(out) _TYPE *
  $result = PyBytes_FromString($1 != nullptr ? (const char *) $1 : "");
}
// 'typecheck' typemaps are used for polymorphism. We want to favor
// tinfo_t wrappers at the expense of 'type_t *' ones, so we want the
// precedence for this to be very low.
%typemap(typecheck, precedence=SWIG_TYPECHECK_STRING_ARRAY) _TYPE *
{ // %treat_serialized_tinfo_raw_pointer_as_bytes_1 %typemap(typecheck) _TYPE *
  $1 = ($input == Py_None || PyBytes_Check($input)) ? 1 : 0;
}
%enddef
%define %treat_serialized_tinfo_raw_pointer_as_bytes(TYPE)
%treat_serialized_tinfo_raw_pointer_as_bytes_1(TYPE);
%treat_serialized_tinfo_raw_pointer_as_bytes_1(const TYPE);
%enddef
%treat_serialized_tinfo_raw_pointer_as_bytes(type_t);
%treat_serialized_tinfo_raw_pointer_as_bytes(p_list);

//-------------------------------------------------------------------------
// For some reason, SWIG converts char arrays by computing the size
// from the end of the array, and stops when it encounters a '\0'.
// That doesn't work for us, as our API doesn't guarantee that
// bytes past the length we are interested in will be zeroed-out.
// In other words, the following code should *never* be present
// in idaapi_include.cpp:
// -------------------------
//  while (size && (<name-of-variable>[size - 1] == '\0')) --size;
// -------------------------
//
%typemap(out) char [ANY], const char[ANY]
{
  %set_output(SWIG_FromCharPtrAndSize($1, strnlen($1, $1_dim0)));
}

%typemap(varout) char [ANY], const char[ANY]
{
  %set_output(SWIG_FromCharPtrAndSize($1, strnlen($1, $1_dim0)));
}

%apply unsigned long long { size_t }
%apply long long { ssize_t }

%define %define_netnode_tag_accessors()
%apply char { uchar tag };


%fragment("cvt_netnode_tag",
    "header",
    fragment="SWIG_AsVal_char",
    fragment="SWIG_AsVal_unsigned_SS_char")
{
  bool cvt_netnode_tag(uchar *out, PyObject *obj)
  {
    char c = '\0';
    bool ok = SWIG_AsVal_char(obj, &c) == SWIG_OK;
    if ( ok )
      *out = (uchar) c;
    else
      ok = SWIG_AsVal_unsigned_SS_char(obj, out) == SWIG_OK;
    return ok;
  }
}

%typemap(in, fragment="cvt_netnode_tag") uchar tag {
  // %typemap(in) uchar tag
  if ( !cvt_netnode_tag(&$1, $input) )
    SWIG_exception_fail(
            SWIG_ValueError,
            "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
}

%typemap(typecheck, fragment="cvt_netnode_tag") uchar tag {
  // %typemap(typecheck) uchar tag
  uchar tmp;
  $1 = cvt_netnode_tag(&tmp, $input);
}


%enddef

//---------------------------------------------------------------------
%typemap(in) tid_t[ANY] (qvector<tid_t> temp)
{
  // %typemap(in) tid_t[ANY] (qvector<tid_t> temp)
  Py_ssize_t len = PyW_PySeqToTidVec(&temp, $input, $1_dim0);
  if ( len == CIP_FAILED )
    return nullptr;

  temp.resize($1_dim0, 0); // make sure we have enough memory allocated
  $1 = temp.begin();
}

//-------------------------------------------------------------------------
%typemap(in) (const tid_t *path, int plen) (qvector<tid_t> temp)
{
  // %typemap(in) (const tid_t *path, int plen/path_len) (qvector<tid_t> temp),
  Py_ssize_t len = PyW_PySeqToTidVec(&temp, $input);
  if ( len == CIP_FAILED )
    return nullptr;

  $1 = temp.begin();
  $2 = int(temp.size());
}

//-------------------------------------------------------------------------
%typemap(typecheck, precedence=SWIG_TYPECHECK_STRING_ARRAY) const qvector<tid_t> &path
{
  // %typemap(typecheck, precedence=SWIG_TYPECHECK_STRING_ARRAY) const qvector<tid_t> &path
  $1 = PyW_IsSequenceType($input);
}

%typemap(in) (const qvector<tid_t> &path) (qvector<tid_t> temp)
{
  // %typemap(in) (const qvector<tid_t> &path)
  Py_ssize_t len = PyW_PySeqToTidVec(&temp, $input);
  if ( len == CIP_FAILED )
    return nullptr;

  $1 = &temp;
}

%{
SWIGINTERN PyObject *_maybe_cstring_result(
        PyObject *resultobj,
        const char *cstr,
        int result)
{
  Py_XDECREF(resultobj);
  if ( result <= 0 )
    Py_RETURN_NONE;
  return PyUnicode_FromString(cstr);
}

SWIGINTERN PyObject *_sized_cstring_result(
        PyObject *resultobj,
        const char *cstr,
        size_t cstrsz)
{
  Py_XDECREF(resultobj);
  return PyUnicode_FromStringAndSize(cstr, cstrsz);
}

SWIGINTERN PyObject *_maybe_sized_cstring_result(
        PyObject *resultobj,
        const char *cstr,
        size_t cstrsz,
        int result)
{
  Py_XDECREF(resultobj);
  if ( result <= 0 )
    Py_RETURN_NONE;
  return PyUnicode_FromStringAndSize(cstr, cstrsz);
}

SWIGINTERN PyObject *_maybe_cstring_result_on_charptr_using_allocated_buf(
        PyObject *resultobj,
        const char *result,
        char *buf)
{
  Py_XDECREF(resultobj);
  PyObject *out = nullptr;
  if ( result != nullptr )
  {
    out = PyUnicode_FromString(buf);
  }
  else
  {
    Py_INCREF(Py_None);
    out = Py_None;
  }
  qfree(buf);
  return out;
}

SWIGINTERN PyObject *_maybe_cstring_result_on_charptr_using_qbuf(
        PyObject *resultobj,
        const char *result,
        const qstring &buf)
{
  Py_XDECREF(resultobj);
  if ( result == nullptr )
    Py_RETURN_NONE;
  return PyUnicode_FromStringAndSize(buf.begin(), buf.length());
}

SWIGINTERN PyObject *_maybe_binary_result(
        PyObject *resultobj,
        void *buf,
        ssize_t result)
{
  Py_XDECREF(resultobj);
  if ( result <= 0 )
    Py_RETURN_NONE;
  return PyBytes_FromStringAndSize((const char *) buf, result);
}

SWIGINTERN PyObject *_sized_binary_result(
        PyObject *resultobj,
        const char *cstr,
        size_t cstrsz)
{
  Py_XDECREF(resultobj);
  return PyBytes_FromStringAndSize(cstr, cstrsz);
}

SWIGINTERN PyObject *_maybe_sized_binary_result(
        PyObject *resultobj,
        const char *cstr,
        size_t cstrsz,
        int result)
{
  Py_XDECREF(resultobj);
  if ( result <= 0 )
    Py_RETURN_NONE;
  return PyBytes_FromStringAndSize(cstr, cstrsz);
}

%}

#if defined(IDA_MODULE_NALT)
%{
#include <bytes.hpp>
SWIGINTERN PyObject *_maybe_byte_array_or_none_result(
        PyObject *resultobj,
        bool result,
        const uchar *bytes,
        size_t nbytes)
{
  Py_XDECREF(resultobj);
  if ( !result )
    Py_RETURN_NONE;
  return PyBytes_FromStringAndSize((const char *) bytes, nbytes);
}
%}
#endif



//---------------------------------------------------------------------
%define %cstring_output_maxstr_none(BUFFER_ARG, SIZE_ARG)
%typemap(default) (BUFFER_ARG, SIZE_ARG) {
    // %cstring_output_maxstr_none(BUFFER_ARG, SIZE_ARG) %typemap(default) (BUFFER_ARG, SIZE_ARG)
    $2 = MAXSTR;
 }
%typemap(in,numinputs=0) (BUFFER_ARG, SIZE_ARG) {
    // %cstring_output_maxstr_none(BUFFER_ARG, SIZE_ARG) %typemap(in,numinputs=0) (BUFFER_ARG, SIZE_ARG)
    $1 = ($1_ltype) qalloc(MAXSTR+1);
}
%typemap(argout) (BUFFER_ARG, SIZE_ARG) {
    // %cstring_output_maxstr_none(BUFFER_ARG, SIZE_ARG) %typemap(argout) (BUFFER_ARG, SIZE_ARG)
    resultobj = _maybe_cstring_result(resultobj, $1, int(result));
    qfree($1);
}
%enddef

//---------------------------------------------------------------------
%define %binary_output_or_none(BUFFER_ARG, SIZE_ARG)
%typemap(default) (BUFFER_ARG, SIZE_ARG) {
    // %binary_output_or_none(BUFFER_ARG, SIZE_ARG) %typemap(default) (BUFFER_ARG, SIZE_ARG)
    $2 = MAXSPECSIZE;
}
%typemap(in,numinputs=0) (BUFFER_ARG, SIZE_ARG) {
    // %binary_output_or_none(BUFFER_ARG, SIZE_ARG) %typemap(in,numinputs=0) (BUFFER_ARG, SIZE_ARG)
    $1 = (char *) qalloc(MAXSPECSIZE+1);
}
%typemap(argout) (BUFFER_ARG, SIZE_ARG) {
    // %binary_output_or_none(BUFFER_ARG, SIZE_ARG) %typemap(argout) (BUFFER_ARG, SIZE_ARG)
    resultobj = _maybe_binary_result(resultobj, $1, ssize_t(result));
    qfree((void *)$1);
}
%enddef

//-------------------------------------------------------------------------
// and a helper for overriding the 'argout' of some of those functions,
// that return the input char* as return code; those build on recent
// versions of Xcode (>= 9.0), and need special care
%define %cstring_output_buf_and_size_returning_charptr(BUFIDX, ...)
%typemap(argout) (__VA_ARGS__) {
    // cstring_output_buf_and_size_returning_charptr's argout
    resultobj = _maybe_cstring_result_on_charptr_using_allocated_buf(resultobj, (const char *) result, $BUFIDX);
}
%enddef

//-------------------------------------------------------------------------
// see %cstring_output_buf_and_size_returning_charptr above
%define %cstring_output_qstring_returning_charptr(BUFIDX, ...)
%typemap(argout) (__VA_ARGS__)
{
  // %cstring_output_qstring_returning_charptr typemap(argout) __VA_ARGS__
  resultobj = _maybe_cstring_result_on_charptr_using_qbuf(resultobj, (const char *) result, *$BUFIDX);
}
%enddef

//-------------------------------------------------------------------------
//                            OUT qstrvec_t
//-------------------------------------------------------------------------
%typemap(in) const qstrvec_t & (qstrvec_t temp)
{
  // %typemap(in) const qstrvec_t & (qstrvec_t temp)
  Py_ssize_t len = PyW_PySeqToStrVec(&temp, $input);
  if ( len == CIP_FAILED )
    return nullptr;

  $1 = &temp;
}
%typemap(in,numinputs=0) qstrvec_t *out (qstrvec_t temp)
{
  // %typemap(in,numinputs=0) qstrvec_t *out (qstrvec_t temp)
  $1 = &temp;
}
%typemap(argout) qstrvec_t *out
{
  // %typemap(argout) qstrvec_t *out
  Py_XDECREF(resultobj);
  resultobj = qstrvec2pylist(*($1));
}
%typemap(freearg) qstrvec_t* out
{
  // %typemap(freearg) qstrvec_t* out
  // Nothing. We certainly don't want 'temp' to be deleted.
}

// Same, but for tuple-appending
%typemap(in,numinputs=0) qstrvec_t *out_wrap_in_list_and_append (qstrvec_t temp)
{
  // %typemap(in,numinputs=0) qstrvec_t *out_wrap_in_list_and_append (qstrvec_t temp)
  $1 = &temp;
}
%typemap(argout) qstrvec_t *out_wrap_in_list_and_append
{
  // %typemap(argout) qstrvec_t *out_wrap_in_list_and_append
  PyObject *was = $result;
  $result = PyList_New(0); // Will be tuplified

  PyList_Append($result, was);
  newref_t _nl(qstrvec2pylist(*($1)));
  PyList_Append($result, _nl.o);
}
%typemap(freearg) qstrvec_t* out_wrap_in_list_and_append
{
  // %typemap(freearg) qstrvec_t* out_wrap_in_list_and_append
  // Nothing. We certainly don't want 'temp' to be deleted.
}

//-------------------------------------------------------------------------
// Director helpers
%define %hooks_director_handle_qstrvec_t_output(METHOD_NAME, STORAGE_QSTRVEC_T)
%typemap(directorout) int METHOD_NAME
{ // %typemap(directorout) int METHOD_NAME
  if ( PySequence_Check(result) )
  {
    $result = PyW_PySeqToStrVec(STORAGE_QSTRVEC_T, result);

    if ( !$result )
    {
      Swig::DirectorTypeMismatchException::raise(
        SWIG_ErrorType(SWIG_TypeError),
        "in output value of type 'qstrvec_t' in method '$symname'");
    }
  }
  else
  {
    $result = 0; // not implemented
  }
}
%enddef


//-------------------------------------------------------------------------
//          md5/sha256 hash retrieval (as hex representation)
//-------------------------------------------------------------------------
%define %byte_array_or_none(PARAM_NAME)
%typemap(in, numinputs=0) uchar PARAM_NAME[ANY] (uchar temp[$1_dim0])
{ // byte_array_or_none typemap(in, numinputs=0) uchar PARAM_NAME[ANY] (uchar temp[$1_dim0])
  $1 = temp;
}
%typemap(argout) uchar PARAM_NAME[ANY]
{ // byte_array_or_none typemap(argout) uchar PARAM_NAME[ANY]
  resultobj = _maybe_byte_array_or_none_result(resultobj, result, $1, $1_dim0);
}
%enddef
%byte_array_or_none(hash);

// Check that the argument is a callable Python object
//---------------------------------------------------------------------
%typemap(in) PyObject *pyfunc {
    if (!PyCallable_Check($input)) {
        PyErr_SetString(PyExc_TypeError, "Expected a callable object");
        return nullptr;
    }
    $1 = $input;
}
// Check that the argument is None or a callable Python object
//---------------------------------------------------------------------
%typemap(in) PyObject *pyfunc_or_none {
    if ($input != Py_None && !PyCallable_Check($input)) {
        PyErr_SetString(PyExc_TypeError, "Expected None or a callable object");
        return nullptr;
    }
    $1 = $input;
}
// Check that the argument is None or a tuple
//---------------------------------------------------------------------
%typemap(in) PyObject *tuple_or_none {
    if ($input != Py_None && !PyTuple_Check($input)) {
        PyErr_SetString(PyExc_TypeError, "Expected None or a tuple");
        return nullptr;
    }
    $1 = $input;
}
%typemap(in) ea_t
{ // %typemap(in) ea_t
  uint64 $1_temp;
  if ( !PyW_GetNumber($input, &$1_temp) )
    SWIG_exception_fail(
            SWIG_TypeError,
            "in method '" "$symname" "', argument " "$argnum"" of type 'ea_t'");
  $1 = ea_t($1_temp);
}
%typemap(in) sval_t
{ // %typemap(in) sval_t
  uint64 $1_temp;
  if ( !PyW_GetNumber($input, &$1_temp) )
    SWIG_exception_fail(
            SWIG_TypeError,
            "in method '" "$symname" "', argument " "$argnum"" of type 'sval_t'");
  $1 = sval_t($1_temp);
}
// Use PyLong_FromUnsignedLongLong, because 'long' is 4 bytes on
// windows, and thus the ea_t would be truncated at the
// PyLong_FromUnsignedLong(unsigned int) call time.
%typemap(out) ea_t "$result = PyLong_FromUnsignedLongLong($1);"

%typemap(in) qtime64_t "$1 = PyLong_AsUnsignedLongLong($input);"
%typemap(out) qtime64_t "$result = PyLong_FromUnsignedLongLong($1);"

%typemap(typecheck, precedence=SWIG_TYPECHECK_STRING_ARRAY) ea_t
{
  // %typemap(typecheck, precedence=SWIG_TYPECHECK_STRING_ARRAY) ea_t
  uint64 $1_temp;
  $1 = PyW_GetNumber($input, &$1_temp);
}

//---------------------------------------------------------------------
//                       IN/OUT qstring/bytevec_t
//---------------------------------------------------------------------
%define %bytes_container(
        REFTYPE,
        CONTAINER_TYPE,
        START_ACCESSOR,
        SIZE_ACCESSOR,
        INSTANCE_CAST,
        CHECKER,
        IN_CONVERTER,
        OUT_CONVERTER,
        ARGOUT_CONVERTER,
        ARGOUT_MAYBE_CONVERTER,
        ELTYPE_TO_REPORT1,
        ELTYPE_TO_REPORT2)
%typemap(typecheck, precedence=SWIG_TYPECHECK_POINTER) REFTYPE
{ // bytes_container REFTYPE typemap(typecheck)
  $1 = CHECKER($input) ? 1 : 0;
}
%fragment("outarg_cvt_" #CONTAINER_TYPE, "header")
{
  bool outarg_cvt_##CONTAINER_TYPE(
          CONTAINER_TYPE *out,
          PyObject *obj,
          bool can_be_none=false)
  {
    bool ok = can_be_none && obj == Py_None;
    if ( !ok )
    {
      ok = CHECKER(obj);
      if ( ok )
        IN_CONVERTER(out, obj);
    }
    return ok;
  }
}
%fragment("cvt_" #CONTAINER_TYPE, "header")
{
  int cvt_##CONTAINER_TYPE(CONTAINER_TYPE **pout, PyObject *obj, bool can_be_none=false)
  {
    CONTAINER_TYPE *out = nullptr;
    if ( can_be_none && obj == Py_None )
    {
      out = new CONTAINER_TYPE;
    }
    else if ( CHECKER(obj) )
    {
      // init properly, so ctor can't crash
      out = new CONTAINER_TYPE;
      IN_CONVERTER(out, obj);
    }
    *pout = out;
    return out != nullptr ? SWIG_NEWOBJ : SWIG_ERROR;
  }
}

%typemap(in, fragment="cvt_" #CONTAINER_TYPE) REFTYPE (int res=0)
{ // bytes_container REFTYPE, CONTAINER_TYPE typemap(in)
  res = cvt_ ## CONTAINER_TYPE(&$1, $input);
  if ( !SWIG_IsOK(res) )
    SWIG_exception_fail(
            SWIG_ValueError,
            "Expected " ELTYPE_TO_REPORT1 " " "in method '" "$symname" "', argument " "$argnum"" of type '" ELTYPE_TO_REPORT2 "'");
}

%typemap(in) const REFTYPE _type_or_none (int res=0)
{ // bytes_container REFTYPE _type_or_none, CONTAINER_TYPE typemap(in)
  res = cvt_ ## CONTAINER_TYPE(&$1, $input, /*can_be_none=*/ true);
  if ( !SWIG_IsOK(res) )
    SWIG_exception_fail(
            SWIG_ValueError,
            "Expected " ELTYPE_TO_REPORT1 " " "in method '" "$symname" "', argument " "$argnum"" of type '" ELTYPE_TO_REPORT2 "'");
}
%typemap(in) const REFTYPE _fields (int res=0)
{ // bytes_container REFTYPE _fields, CONTAINER_TYPE typemap(in)
  res = cvt_ ## CONTAINER_TYPE(&$1, $input, /*can_be_none=*/ true);
  if ( !SWIG_IsOK(res) )
    SWIG_exception_fail(
            SWIG_ValueError,
            "Expected " ELTYPE_TO_REPORT1 " " "in method '" "$symname" "', argument " "$argnum"" of type '" ELTYPE_TO_REPORT2 "'");
}
%typemap(freearg) REFTYPE
{ // bytes_container REFTYPE typemap(freearg)
  if ( SWIG_IsNewObj(res$argnum) ) delete $1;
}
%typemap(out) REFTYPE // e.g., %typemap(out) qstring*
{ // bytes_container typemap(out) REFTYPE
  $result = OUT_CONVERTER((const char *) $1->START_ACCESSOR(), $1->SIZE_ACCESSOR());
}
%typemap(out) CONTAINER_TYPE // e.g., %typemap(out) qstring
{ // bytes_container typemap(out) CONTAINER_TYPE
  $result = OUT_CONVERTER((const char *) $1.START_ACCESSOR(), $1.SIZE_ACCESSOR());
}
%typemap(varout) CONTAINER_TYPE // e.g., %typemap(varout) qstring
{ // bytes_container typemap(varout) CONTAINER_TYPE
  $result = OUT_CONVERTER((const char *) $1.START_ACCESSOR(), $1.SIZE_ACCESSOR());
}
// the following is used to turn a '... *result' output parameter,
// into an actual return value.
%typemap(in,numinputs=0) CONTAINER_TYPE *result (CONTAINER_TYPE temp)
{
  // bytes_container typemap(in,numinputs=0) CONTAINER_TYPE *result (CONTAINER_TYPE temp)
  $1 = &temp;
}
%typemap(in,numinputs=0) CONTAINER_TYPE &result (CONTAINER_TYPE temp)
{
  // bytes_container typemap(in,numinputs=0) CONTAINER_TYPE &result (CONTAINER_TYPE temp)
  $1 = &temp;
}
%typemap(argout) CONTAINER_TYPE *result
{
  // bytes_container typemap(argout) CONTAINER_TYPE *result
  resultobj = ARGOUT_MAYBE_CONVERTER(resultobj, $1->START_ACCESSOR(), $1->SIZE_ACCESSOR(), int(result));
}
%typemap(argout) CONTAINER_TYPE &result
{
  // bytes_container typemap(argout) CONTAINER_TYPE &result
  resultobj = ARGOUT_MAYBE_CONVERTER(resultobj, $1->START_ACCESSOR(), $1->SIZE_ACCESSOR(), int(result));
}
%typemap(freearg) CONTAINER_TYPE* result
{
  // bytes_container typemap(freearg) CONTAINER_TYPE *result
  // Nothing. We certainly don't want 'temp' to be deleted.
}
%typemap(freearg) CONTAINER_TYPE& result
{
  // bytes_container typemap(freearg) CONTAINER_TYPE &result
  // Nothing. We certainly don't want 'temp' to be deleted.
}
// We determine that the following parameter: "CONTAINER_TYPE *vout" has the
// following characteristics:
//   - the C function being called returns void
//   - other than that, it's the same as for the "CONTAINER_TYPE *result" parameter
//     (i.e., requires a temporary 'qstring', etc...)
//
// Re-use the 'CONTAINER_TYPE *result' typemaps, ...
%apply CONTAINER_TYPE *result { CONTAINER_TYPE *vout };
%apply CONTAINER_TYPE &result { CONTAINER_TYPE &vout };
// ...but override the argout one, so that it doesn't rely on a 'result'
%typemap(argout) (CONTAINER_TYPE *vout)
{
  // bytes_container typemap(argout) (CONTAINER_TYPE *vout)
  resultobj = ARGOUT_CONVERTER(resultobj, (const char *) $1->START_ACCESSOR(), $1->SIZE_ACCESSOR());
}
%typemap(argout) (CONTAINER_TYPE &vout)
{
  // bytes_container typemap(argout) (CONTAINER_TYPE &vout)
  resultobj = ARGOUT_CONVERTER(resultobj, (const char *) $1->START_ACCESSOR(), $1->SIZE_ACCESSOR());
}
%typemap(directorin) CONTAINER_TYPE *
{ // bytes_container typemap(directorin) CONTAINER_TYPE *
  if ( $1 != nullptr )
  {
    $input = OUT_CONVERTER($1->START_ACCESSOR(), $1->SIZE_ACCESSOR());
  }
  else
  {
    Py_INCREF(Py_None);
    $input = Py_None;
  }
}
%typemap(directorin) REFTYPE
{ // bytes_container typemap(directorin) REFTYPE
  $input = OUT_CONVERTER($1.START_ACCESSOR(), $1.SIZE_ACCESSOR());
}
%typemap(directorout) CONTAINER_TYPE
{ // bytes_container typemap(directorout) CONTAINER_TYPE
  if ( CHECKER($1) )
    IN_CONVERTER(&$result, $1);
  else
    Swig::DirectorTypeMismatchException::raise(
            SWIG_ErrorType(SWIG_TypeError),
            "in output value of type '" ELTYPE_TO_REPORT2 "' in method '$symname'");
}
%typemap(directorargout) CONTAINER_TYPE *vout
{ // bytes_container typemap(directorargout) CONTAINER_TYPE *vout
  if ( CHECKER($result) )
  {
    CONTAINER_TYPE _buf;
    if ( IN_CONVERTER(&_buf, $result) )
      vout->insert(vout->SIZE_ACCESSOR(), _buf.START_ACCESSOR(), _buf.SIZE_ACCESSOR());
  }
}
%enddef

%define %bytes_container_ptr_and_ref(
        CONTAINER_TYPE,
        START_ACCESSOR,
        SIZE_ACCESSOR,
        INSTANCE_CAST,
        CHECKER,
        IN_CONVERTER,
        OUT_CONVERTER,
        ARGOUT_CONVERTER,
        ARGOUT_MAYBE_CONVERTER,
        ELTYPE_TO_REPORT1,
        ELTYPE_TO_REPORT2)
%bytes_container(
        CONTAINER_TYPE *,
        CONTAINER_TYPE,
        START_ACCESSOR,
        SIZE_ACCESSOR,
        INSTANCE_CAST,
        CHECKER,
        IN_CONVERTER,
        OUT_CONVERTER,
        ARGOUT_CONVERTER,
        ARGOUT_MAYBE_CONVERTER,
        ELTYPE_TO_REPORT1,
        ELTYPE_TO_REPORT2);
%bytes_container(
        CONTAINER_TYPE &,
        CONTAINER_TYPE,
        START_ACCESSOR,
        SIZE_ACCESSOR,
        INSTANCE_CAST,
        CHECKER,
        IN_CONVERTER,
        OUT_CONVERTER,
        ARGOUT_CONVERTER,
        ARGOUT_MAYBE_CONVERTER,
        ELTYPE_TO_REPORT1,
        ELTYPE_TO_REPORT2);
%enddef


%bytes_container_ptr_and_ref(
        qstring,
        c_str,
        length,
        ,
        PyUnicode_Check,
        PyUnicode_as_qstring,
        PyUnicode_FromStringAndSize,
        _sized_cstring_result,
        _maybe_sized_cstring_result,
        "string",
        "str");
%bytes_container_ptr_and_ref(
        bytevec_t,
        begin,
        size,
        ,
        PyBytes_Check,
        PyBytes_as_bytevec_t,
        PyBytes_FromStringAndSize,
        _sized_binary_result,
        _maybe_sized_binary_result,
        "bytes",
        "bytes");
%bytes_container_ptr_and_ref(
        qtype,
        begin,
        length,
        (const uchar *),
        PyBytes_Check,
        PyBytes_as_qtype,
        PyBytes_FromStringAndSize,
        _sized_binary_result,
        _maybe_sized_binary_result,
        "bytes",
        "bytes");

//-------------------------------------------------------------------------
//                                insn_t
//-------------------------------------------------------------------------
%fragment("cvt_const_insn_t_ref", "header")
{
  bool convert_const_insn_t_ref(insn_t *out, PyObject *in, swig_type_info *ty)
  {
    uint64 ea;
    bool ok = PyW_GetNumber(in, &ea);
    if ( ok )
    {
      insn_t tmp;
      ok = decode_insn(&tmp, ea_t(ea)) > 0;
      if ( ok && out != nullptr )
        *out = tmp;
    }
    else
    {
      insn_t *p_insn = nullptr;
      ok = SWIG_ConvertPtr(in, (void **) &p_insn, ty, 0) >= 0 && p_insn != nullptr;
      if ( ok && out != nullptr )
        *out = *p_insn;
    }
    return ok;
  }
}

//-------------------------------------------------------------------------
%typemap(in, fragment="cvt_const_insn_t_ref") (const insn_t &) (insn_t lins)
{
  // %typemap(in) (const insn_t &)
  if ( !convert_const_insn_t_ref(&lins, $input, $1_descriptor) )
    SWIG_exception_fail(SWIG_ValueError, "Expected either an address, or a non-null ida_ua.insn_t instance");
  $1 = &lins;
}
%typemap(typecheck, precedence=SWIG_TYPECHECK_POINTER, fragment="cvt_const_insn_t_ref") const insn_t &
{ // %typemap(typecheck, precedence=SWIG_TYPECHECK_POINTER) const insn_t &
  $1 = convert_const_insn_t_ref(nullptr, $input, $1_descriptor);
}
%typemap(doc) (const insn_t &) "$1_name: an ida_ua.insn_t, or an address (C++: const insn_t &)"

//---------------------------------------------------------------------
//                      varargs (mostly kernwin.hpp)
//---------------------------------------------------------------------
// This is used for functions like warning(), info() and so on
%typemap(in) (const char *format, ...) (qstring buf)
{
    $1 = "%s";                                /* Fix format string to %s */
    PyUnicode_as_qstring(&buf, $input);            /* Get string argument */
    $2 = (void *) buf.begin();
    /* Note: we cannot rely on 'nonnul_argument_prototype' for */
    /* these, since we fiddle with the arguments number */
    if ( $2 == nullptr )
      SWIG_exception_fail(
              SWIG_ValueError,
              "invalid null pointer " "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
};

//-------------------------------------------------------------------------
// for use with insn_t, op_t wrappers
%typemap(in) (size_t ptrval)
{
  $1 = size_t(PyLong_AsUnsignedLongLong($input));
}

#ifdef SWIGWIN
typedef unsigned __int64 uint64;
typedef          __int64 int64;
#else
typedef unsigned long long uint64;
typedef          long long int64;
#endif

#ifdef __NT__
%{
CASSERT(sizeof(time_t) == sizeof(int64));
%}
typedef int64 time_t;
#else
%{
CASSERT(sizeof(time_t) == sizeof(long int));
%}
typedef long int time_t;
#endif

typedef int ui_notification_t;

#ifdef __EA64__
%apply int64  *INOUT { sval_t *value };
%apply int64  *INOUT { adiff_t *disp };
%apply uint64 *INOUT { ea_t *addr };
%apply uint64 *INPUT { ea_t *ea_ptr }; // get_debug_name
%apply uint64 *INOUT { sel_t *sel };
%apply uint64 *OUTPUT { ea_t *ea1, ea_t *ea2 }; // read_range_selection()
%apply uint64 *OUTPUT { ea_t *from, ea_t *to, asize_t *size }; // get_mapping()
%apply uint64 *OUTPUT { uval_t *value }; // get_name_value
#else
%apply int          *INOUT { sval_t  *value };
%apply int          *INOUT { adiff_t *disp };
%apply unsigned int *INOUT { ea_t *addr };
%apply unsigned int *INPUT { ea_t *ea_ptr }; // get_debug_name
%apply unsigned int *INOUT { sel_t *sel };
%apply unsigned int *OUTPUT { ea_t *ea1, ea_t *ea2 }; // read_range_selection()
%apply unsigned int *OUTPUT { ea_t *from, ea_t *to, asize_t *size }; // get_mapping()
%apply unsigned int *OUTPUT { uval_t *value }; // get_name_value
#endif

%apply long long { qoff64_t };

%apply qstring *result { qstring *out };
%apply qstring *result { qstring *out_name };
%apply qstring *result { qstring *buf };
%apply qstring *result { qstring *errbuf };
%apply int *OUTPUT { int *icon };
%apply int *OUTPUT { action_state_t *state };
%apply bool *OUTPUT { bool *checkable };
%apply bool *OUTPUT { bool *checked };
%apply bool *OUTPUT { bool *visibility };

//-------------------------------------------------------------------------
// 'errbuf' output handling can go many ways. Let's provide common helpers.
%define %make_argout_errbuf_raise_exception_when_non_empty()
%typemap(argout) (qstring *errbuf)
{
  // %typemap(argout) qstring *errbuf (from: %make_argout_errbuf_raise_exception_when_non_empty)
  if ( !$1->empty() )
  {
    if ( $result != nullptr )
      Py_XDECREF($result);
    SWIG_exception_fail(SWIG_RuntimeError, $1->c_str());
  }
}
%enddef

%define %make_argout_errbuf_raise_when_null_result()
%typemap(argout) (qstring *errbuf)
{
  // %typemap(argout) qstring *errbuf (from: %make_argout_errbuf_raise_when_null_result)
  if ( result == nullptr )
  {
    if ( $result != nullptr )
      Py_XDECREF($result);
    SWIG_exception_fail(SWIG_RuntimeError, $1->c_str());
  }
}
%enddef


//-------------------------------------------------------------------------
// The following is to be used to expose an array of items
// to IDAPython. This will not make a copy (on purpose!).
//-------------------------------------------------------------------------
//
// (Very) heavily inspired by:
// http://stackoverflow.com/questions/7713318/nested-structure-array-access-in-python-using-swig?rq=1
//
// NOTE: This should probably hold a (weak?) reference
// to the parent PyObject, because it is technically possible
// to end up with dangling pointers otherwise
// See also dynamic_wrapped_array_t
%immutable;
%inline %{
template <typename Type, size_t N>
struct wrapped_array_t {
  Type (&data)[N];
  wrapped_array_t(Type (&data)[N]) : data(data) { }
};
%}
%mutable;

%extend wrapped_array_t {
  inline size_t __len__() const { qnotused($self); return N; }

  inline const Type& __getitem__(size_t i) const {
    if ( i >= N )
      throw std::out_of_range("out of bounds access");
    return $self->data[i];
  }

  inline void __setitem__(size_t i, const Type& v) {
    if ( i >= N )
      throw std::out_of_range("out of bounds access");
    $self->data[i] = v;
  }

  inline bytevec_t _get_bytes() const {
    bytevec_t bts;
    bts.resize(N * sizeof(Type));
    memmove(bts.begin(), $self->data, bts.size());
    return bts;
  }

  inline void _set_bytes(const bytevec_t &bts) {
    if ( bts.size() > N * sizeof(Type) )
      throw std::out_of_range("out of bounds access");
    memset($self->data, 0, sizeof($self->data));
    memmove($self->data, bts.begin(), bts.size());
  }

  %pythoncode {
    __iter__ = ida_idaapi._bounded_getitem_iterator
    bytes = property(_get_bytes, _set_bytes)
  }
}

//-------------------------------------------------------------------------
// NOTE: see note for wrapped_array_t
%immutable;
%inline %{
template <typename Type>
struct dynamic_wrapped_array_t {
  Type *data;
  size_t count;
  dynamic_wrapped_array_t(Type *_data, size_t _count)
    : data(_data), count(_count) { }
};
%}
%mutable;

%extend dynamic_wrapped_array_t {
  inline size_t __len__() const { return $self->count; }

  inline const Type& __getitem__(size_t i) const {
    if ( i >= $self->count )
      throw std::out_of_range("out of bounds access");
    return $self->data[i];
  }

  inline void __setitem__(size_t i, const Type& v) {
    if ( i >= $self->count )
      throw std::out_of_range("out of bounds access");
    $self->data[i] = v;
  }

  %pythoncode {
    __iter__ = ida_idaapi._bounded_getitem_iterator
  }
}

//-------------------------------------------------------------------------
%typemap(out) tinfo_t
{
  // %typemap(out) tinfo_t
  tinfo_t *ni = new tinfo_t($1);
  til_register_python_tinfo_t_instance(ni);
  $result = SWIG_NewPointerObj(ni, $&1_descriptor, SWIG_POINTER_OWN | 0);
}
%typemap(check) tinfo_t *
{
  // %typemap(check) tinfo_t *
  if ( $1 == nullptr )
    SWIG_exception_fail(SWIG_ValueError, "invalid null reference " "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
}

%typemap(out) tinfo_t *
{
  // %typemap(out) tinfo_t *
  tinfo_t *ni = new tinfo_t(*$1);
  til_register_python_tinfo_t_instance(ni);
  $result = SWIG_NewPointerObj(ni, $1_descriptor, SWIG_POINTER_OWN | 0);
}

%typemap(newfree) tinfo_t * {
  // %typemap(newfree) tinfo_t *
  delete $1;
}

// Specialization for member `tinfo_t`'s, which we want to return as-is
%typemap(out) tinfo_t *type,
  tinfo_t *tif,
  tinfo_t *obj_type,
  tinfo_t *closure,
  tinfo_t *parent,
  tinfo_t *elem_type,
  tinfo_t *rettype,
  tinfo_t *return_type,
  tinfo_t *idb_type,
  tinfo_t *formal_type,
  tinfo_t *functype,
  tinfo_t *idb_type
{
  // %typemap(out) tinfo_t *type (specialization for member tinfo_t)
  $result = SWIG_NewPointerObj($1, $1_descriptor, 0);
}

//-------------------------------------------------------------------------
//                             udm_t *out
//-------------------------------------------------------------------------
%typemap(in,numinputs=0) udm_t *out (udm_t temp)
{
  // %typemap(in,numinputs=0) udm_t *out (udm_t temp)
  $1 = &temp;
}
%typemap(argout) udm_t *out
{
  // %typemap(argout) udm_t *out
  if ( result > -1 )
  {
    PyObject *py_udm = SWIG_NewPointerObj(new udm_t(*($1)), $1_descriptor, SWIG_POINTER_OWN | 0);
    $result = SWIG_Python_AppendOutput($result, py_udm, /*is_void=*/ 1);
  }
  else
  {
    Py_INCREF(Py_None);
    $result = SWIG_Python_AppendOutput($result, Py_None, /*is_void=*/ 1);
  }
}
%typemap(freearg) udm_t *out
{
  // %typemap(freearg) udm_t *out
  // Nothing. We certainly don't want 'temp' to be deleted.
}

//-------------------------------------------------------------------------
//                             edm_t *out
//-------------------------------------------------------------------------
%typemap(in,numinputs=0) edm_t *out (edm_t temp)
{
  // %typemap(in,numinputs=0) edm_t *out (edm_t temp)
  $1 = &temp;
}
%typemap(argout) edm_t *out
{
  // %typemap(argout) edm_t *out
  if ( result > -1 )
  {
    PyObject *py_edm = SWIG_NewPointerObj(new edm_t(*($1)), $1_descriptor, SWIG_POINTER_OWN | 0);
    $result = SWIG_Python_AppendOutput($result, py_edm, /*is_void=*/ 1);
  }
  else
  {
    Py_INCREF(Py_None);
    $result = SWIG_Python_AppendOutput($result, Py_None, /*is_void=*/ 1);
  }
}
%typemap(freearg) edm_t *out
{
  // %typemap(freearg) edm_t *out
  // Nothing. We certainly don't want 'temp' to be deleted.
}

// Convert all of these
%cstring_output_maxstr_none(char *buf, size_t bufsize);
%cstring_output_maxstr_none(char *buf, int bufsize);
%binary_output_or_none(void *buf, size_t bufsize);


// Accept single Python string for const void * + size input arguments
// For example: put_many_bytes() and patch_many_bytes()
%apply (char *STRING, int LENGTH) { (const void *buf, size_t size) };
%apply (char *STRING, int LENGTH) { (const void *buf, size_t bufsize) };
%apply (char *STRING, int LENGTH) { (const void *buf, size_t len) };
%apply (char *STRING, int LENGTH) { (const void *value, size_t length) };
%apply (char *STRING, int LENGTH) { (const void *dataptr,size_t len) };
%define %const_pointer_and_size(PTRTYPE, BUFNAME, SIZENAME, STORAGE_TYPE, CONVERTER, LENGTH_GETTER)
%typemap(in) (const PTRTYPE *BUFNAME, size_t SIZENAME) (STORAGE_TYPE tmp)
{
  // typemap(in) (const PTRTYPE *BUFNAME, size_t SIZENAME)
  if ( !CONVERTER(&tmp, $input) ) {
    %argument_fail(SWIG_ERROR, "$type", $symname, $argnum);
  }
  $1 = %reinterpret_cast(tmp.begin(), $1_ltype);
  $2 = %numeric_cast(tmp.LENGTH_GETTER(), $2_ltype);
}
%typemap(freearg) (const PTRTYPE *BUFNAME, size_t SIZENAME)
{
  // typemap(freearg) (const PTRTYPE *BUFNAME, size_t SIZENAME)
}
%typemap(directorin) (const uchar *data, size_t datlen)
{
  // typemap(directorin) (const PTRTYPE *BUFNAME, size_t SIZENAME)
  if ( $1 != nullptr )
  {
    $input = PyBytes_FromStringAndSize((const char *) $1, $2);
  }
  else
  {
    Py_INCREF(Py_None);
    $input = Py_None;
  }
}
%enddef

%define %const_void_pointer_and_size(PTRTYPE, BUFNAME, SIZENAME)
  %typemap(typecheck, precedence=SWIG_TYPECHECK_POINTER) (const PTRTYPE *BUFNAME, size_t SIZENAME)
  { // %typemap(typecheck, precedence=SWIG_TYPECHECK_POINTER) (const PTRTYPE *BUFNAME, size_t SIZENAME)
    $1 = PyBytes_Check($input) ? 1 : 0;
  }
  %const_pointer_and_size(PTRTYPE, BUFNAME, SIZENAME, bytevec_t, PyBytes_as_bytevec_t, size)
%enddef

%define %const_char_pointer_and_size(PTRTYPE, BUFNAME, SIZENAME)
  %const_pointer_and_size(PTRTYPE, BUFNAME, SIZENAME, qstring, PyUnicode_as_qstring, length)
%enddef

%const_void_pointer_and_size(void, buf, size);
%const_void_pointer_and_size(void, buf, bufsize);
%const_void_pointer_and_size(void, buf, len);
%const_void_pointer_and_size(void, value, length);
%const_void_pointer_and_size(void, dataptr, len);
%const_char_pointer_and_size(char, value, length);

%include <cstring.i>

%{
#define S2LF_EMPTY_NONE 0x1
SWIGINTERN PyObject *qstrvec2pylist(const qstrvec_t &vec, int flags=0)
{
  size_t n = vec.size();
  PyObject *py_list = PyList_New(n);
  for ( size_t i=0; i < n; ++i )
  {
    const qstring &s = vec[i];
    PyObject *o;
    if ( s.empty() && (flags & S2LF_EMPTY_NONE) == S2LF_EMPTY_NONE )
    {
      Py_INCREF(Py_None);
      o = Py_None;
    }
    else
    {
      o = PyUnicode_FromStringAndSize(s.c_str(), s.length());
    }
    PyList_SetItem(py_list, i, o);
  }
  return py_list;
}
%}

//-------------------------------------------------------------------------
// When it comes to uint64, we have been typically very tolerant and
// accept negative values as if were logical to perform C-like numbers
// 'wrapping' in Python. It's not, but bw-compat imposes that we do.
%fragment("cvt_uint64", "header")
{
  int cvt_uint64(uint64 *out, PyObject *obj)
  {
    unsigned long long ull = PyLong_AsUnsignedLongLong(obj);
    if ( PyErr_Occurred() )
    {
      PyErr_Clear();
      long long ll = PyLong_AsLongLong(obj);
      if ( PyErr_Occurred() )
      {
        PyErr_Clear();
        return SWIG_OverflowError;
      }
      ull = (unsigned long long) ll;
    }
    *out = uint64(ull);
    return SWIG_OK;
  }
}
%typemap(in, fragment="cvt_uint64") uint64 (int ecode)
{
  // %typemap(in) uint64
  ecode = cvt_uint64(&$1, $input);
  if ( !SWIG_IsOK(ecode) )
    SWIG_exception_fail(SWIG_ArgError(ecode), "in method '$symname', argument $argnum of type $1_type");
}

%typemap(typecheck, precedence=SWIG_TYPECHECK_INTEGER, fragment="cvt_uint64") uint64
{
  // %typemap(typecheck) uint64
  uint64 tmp;
  $1 = cvt_uint64(&tmp, $input) == SWIG_OK;
}

//-------------------------------------------------------------------------
%define %_uint_result_as_output(TYPE, CONVFUNC, CHECK_EXPR)
%typemap(in,numinputs=0) TYPE *result (TYPE temp = 0)
{
  // %_uint_result_as_output(TYPE, CONVFUNC, CHECK_EXPR) %typemap(in,numinputs=0) TYPE *result
  $1 = &temp;
}
%typemap(argout) TYPE *result
{
  // %_uint_result_as_output(TYPE, CONVFUNC) %typemap(argout) TYPE *result
  Py_XDECREF(resultobj);
  if ( CHECK_EXPR )
  {
    resultobj = CONVFUNC(*(TYPE *) $1);
  }
  else
  {
    Py_INCREF(Py_None);
    resultobj = Py_None;
  }
}
%enddef

//-------------------------------------------------------------------------
%define %uint_result_as_output(TYPE, CONVFUNC)
%_uint_result_as_output(TYPE, CONVFUNC, int(result) > 0);
%enddef

%uint_result_as_output(uint32, PyLong_FromUnsignedLong);
%uint_result_as_output(uint64, PyLong_FromUnsignedLongLong);
%uint_result_as_output(int64, PyLong_FromLongLong);
%apply uint32 *result { uint32 *out };
%apply uint64 *result { uint64 *out };
%apply int64 *result { int64 *out };
#ifdef __EA64__
%apply uint64 *result { ea_t *result };
#else
%apply uint32 *result { ea_t *result };
#endif
// helpers to turn result into multiple values (just %apply, renaming 'appended_ea')
%typemap(argout) ea_t *appended_ea
{
  // %typemap(argout) ea_t *appended_ea
#ifdef __EA64__
  $result = SWIG_Python_AppendOutput($result, PyLong_FromUnsignedLongLong(*($1)), /*is_void=*/ 1);
#else
  $result = SWIG_Python_AppendOutput($result, PyLong_FromUnsignedLong(*($1)), /*is_void=*/ 1);
#endif
}

//-------------------------------------------------------------------------
// Make get_any_cmt() work
%apply unsigned char *OUTPUT { color_t *cmttype };

// For get_enum_id()
%apply unsigned char *OUTPUT { uchar *serial };

// get_[first|last]_serial_enum_member() won't take serials as input; it'll be present as output
%apply unsigned char *OUTPUT { uchar *out_serial };
// get_[next|prev]_serial_enum_member() take serials as input, and have the result present as output
%apply unsigned char *INOUT { uchar *in_out_serial };

// This is meant only for the code that is defined in IDAPython,
// as SDK non-null pointers should be marked by NONNULL and handled
// automatically.
%define %pywraps_nonnul_argument_prototype(PROTO, ARGSIG)
/* first, define the typemap */
%typemap(check) (ARGSIG)
{
  if ( $1 == nullptr )
    SWIG_exception_fail(SWIG_ValueError, "invalid null pointer " "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
}
/* Then, redeclare prototype. Note that we want this prototype _only_ seen */
/* by SWiG, but not by the later compile phase: because of the defines */
/* in pro.h, 'idaapi', 'ida_export', etc... will disappear, causing */
/* VisualStudio to exit with a "same prototype, different modifiers" error. */
%inline %{
#ifndef _MSC_VER
  PROTO;
#endif
%}
%enddef


%define %numbers_list_to_values_vec_helper(VECTYPE, SWIGTYPE, PYLIST_CONVERTOR, REFTYPE)
%typemap(arginit) VECTYPE REFTYPE "VECTYPE $1_local_storage; // %numbers_list_to_values_vec(VECTYPE) %typemap(arginit) VECTYPE REFTYPE" // *MUST NOT* be within '{}'s
%typemap(in) VECTYPE REFTYPE
{ // %numbers_list_to_values_vec(VECTYPE) %typemap(in) VECTYPE REFTYPE
  if ( PySequence_Check($input) )
  {
    if ( PYLIST_CONVERTOR(&$1_local_storage, $input) < 0 )
      SWIG_fail;
    $1 = &$1_local_storage;
  }
  else
  {
    void *$1_vptr = 0;
    int res$argnum = SWIG_ConvertPtr($input, &$1_vptr, SWIGTYPE, 0 | 0);
    if ( !SWIG_IsOK(res$argnum) )
      SWIG_exception_fail(SWIG_ArgError(res$argnum), "in method '$symname', argument $argnum of type $1_type");
    $1 = reinterpret_cast<VECTYPE*>($1_vptr);
  }
}
%typecheck(SWIG_TYPECHECK_POINTER) VECTYPE REFTYPE
{
  // %numbers_list_to_values_vec(VECTYPE) %typecheck(SWIG_TYPECHECK_POINTER) VECTYPE REFTYPE
  if ( PySequence_Check($input) > 0 )
  {
    $1 = 1;
  }
  else
  {
    int res = SWIG_ConvertPtr($input, 0, SWIGTYPE, 0);
    $1 = SWIG_CheckState(res);
  }
}
%enddef

//-------------------------------------------------------------------------
// For e.g., get_idainfo_by_type()
%apply uint64 * OUTPUT { flags64_t *out_flags };
%apply size_t * OUTPUT { size_t *out_size };
%apply size_t * OUTPUT { size_t *out_alsize };
%typemap(check) size_t *out_size "*($1) = 0; // %typemap(check) size_t *out_size";
%typemap(check) size_t *out_alsize "*($1) = 0; // %typemap(check) size_t *out_alsize";
%typemap(check) flags64_t *out_flags "*($1) = 0; // %typemap(check) flags_t *out_flags";

%typemap(in,numinputs=0) opinfo_t *out_mt (opinfo_t temp) {
  // typemap(in,numinputs=0) opinfo_t *out_mt
  $1 = &temp;
}
%typemap(argout) opinfo_t *out_mt
{
  // typemap(argout) opinfo_t *out_mt
  if ( result )
  {
    PyObject *py_opinfo = SWIG_NewPointerObj(SWIG_as_voidptr(new opinfo_t(*($1))), SWIGTYPE_p_opinfo_t, SWIG_POINTER_NEW );
    $result = SWIG_Python_AppendOutput($result, py_opinfo, /*is_void=*/ 1);
  }
  else
  {
    Py_INCREF(Py_None);
    $result = SWIG_Python_AppendOutput($result, Py_None, /*is_void=*/ 1);
  }
}
%typemap(freearg) opinfo_t *out_mt
{
  // typemap(freearg) opinfo_t *out_mt
  // Nothing. We certainly don't want 'temp' to be deleted.
}

//-------------------------------------------------------------------------
%define %numbers_list_to_values_vec(VECTYPE, SWIGTYPE, PYLIST_CONVERTOR)
%numbers_list_to_values_vec_helper(VECTYPE, SWIGTYPE, PYLIST_CONVERTOR, *);
%numbers_list_to_values_vec_helper(VECTYPE, SWIGTYPE, PYLIST_CONVERTOR, &);
%enddef
#ifdef __EA64__
%numbers_list_to_values_vec(eavec_t, SWIGTYPE_p_qvectorT_unsigned_long_long_t, PyW_PySeqToEaVec);
#else
%numbers_list_to_values_vec(eavec_t, SWIGTYPE_p_qvectorT_unsigned_int_t, PyW_PySeqToEaVec);
#endif

//-------------------------------------------------------------------------
// Make sure the GIL is released, in case 'NAME' is calling execute_sync
// either directly, or indirectly
%define %calls_execute_sync(NAME)
%thread NAME;
%enddef

#ifdef TESTABLE_BUILD
#  define HOOKS_DUMP_STATE() %ignore NAME##_Hooks::dump_state;
#else
#  define HOOKS_DUMP_STATE()
#endif

%define %define_Hooks_class(NAME)
%ignore NAME##_Callback;
%ignore NAME##_Hooks::dispatch;
%ignore NAME##_Hooks::mappings;
%ignore NAME##_Hooks::mappings_size;
HOOKS_DUMP_STATE();
%enddef

%{
#include <expr.hpp>
#include <idd.hpp>
#include <ieee.h>
#include "../../../pywraps.hpp"
%}

%{
#ifdef __EA64__
#  define ea_t_SWIGTYPE_name SWIGTYPE_p_unsigned_long_long
#else
#  define ea_t_SWIGTYPE_name SWIGTYPE_p_unsigned_int
#endif

SWIGINTERN void __raise_ba(const std::bad_alloc &SWIGUNUSEDPARM(ba))
{
  PyErr_SetString(PyExc_MemoryError, "Out of memory (bad_alloc)");
}

SWIGINTERN void __raise_u()
{
  PyErr_SetString(PyExc_RuntimeError, "Unknown exception");
}

SWIGINTERN void __raise_e(const std::exception &e)
{
  const char *what = e.what();
  if ( what == nullptr || what[0] == '\0' )
  {
    __raise_u();
  }
  else
  {
    PyErr_SetString(PyExc_RuntimeError, what);
  }
}

// a setter for the 'interr_should_throw' flag. Since that flag has to be set,
// or reset possibly in the context of stack unwinding, let's leave it up to
// the compiler to make sure that it's reset as it should be using RAII.
struct set_interr_throws_t
{
  bool was;
  set_interr_throws_t() { was = set_interr_throws(true); }
  ~set_interr_throws_t() { set_interr_throws(was); }
};

SWIGINTERN void __raise_ie(const interr_exc_t &ie)
{
  qstring emsg;
  emsg.sprnt(INTERR_EXC_FMT, ie.code);
  PyErr_SetString(PyExc_RuntimeError, emsg.begin());
}

SWIGINTERN void __raise_de(const Swig::DirectorException &e)
{
  bool handled = false;
  if ( PyErr_Occurred() != nullptr )
  {
    // Add the new bits of info to the error
    PyObject *exception, *v, *tb;
    PyErr_Fetch(&exception, &v, &tb);
    if ( exception != nullptr )
    {
      PyErr_NormalizeException(&exception, &v, &tb);
      if ( exception != nullptr )
      {
        // FIXME: We retrieve the message, but not the context (i.e., the
        // stack trace.) Ideally we should perhaps swoop in our own
        // 'sys.stderr', call PyErr_Print(), retrieve the result, and
        // append that to the new exception message.
        newref_t as_str(PyObject_Str(v));
        if ( as_str != nullptr )
        {
          qstring buf;
          PyUnicode_as_qstring(&buf, as_str.o);
          buf.insert(" : ");
          buf.insert(e.getMessage());
          PyErr_SetString(PyExc_RuntimeError, buf.c_str());
          handled = true;
        }
      }
    }
  }
  if ( !handled )
    PyErr_SetString(PyExc_RuntimeError, e.getMessage());
}

SWIGINTERN void __raise_oor(const std::out_of_range &e)
{
  PyErr_SetString(PyExc_IndexError, e.what());
}

SWIGINTERN bool __chkthr()
{
  bool ok = is_main_thread();
  if ( !ok )
    PyErr_SetString(PyExc_RuntimeError, "Function can be called from the main thread only");
  return ok;
}

SWIGINTERN bool __chkreqidb()
{
  bool ok = netnode::inited();
  if ( !ok )
    PyErr_SetString(PyExc_RuntimeError, "Function requires a database");
  return ok;
}

%}

%define %force_declare_SWiG_type(NAME)
// KLUDGE: I have no idea how to force SWiG to declare a type for a module,
// unless that type is indeed used. That's why this wrapper exists..
%inline %{
inline void _kludge_force_declare_##NAME(const NAME *) {}
%}
%enddef

%define %modal_dialog_triggering_function(NAME)
%thread NAME;
%pythonprepend NAME
%{
    import ida_kernwin
    # kludge: we can't use %feature("shadow") for top-level
    # functions (see https://github.com/swig/swig/issues/980)
    # Thus we'll %pythonprepend some code, and return from it,
    # making the original code unreachable. Not pretty, but I
    # don't have anything better at the moment.
    with ida_kernwin.disabled_script_timeout_t():
        return _ida_kernwin.NAME(*args)
%}
%enddef

%include <constraints.i>

// gdl_graph_t & subclasses
%cstring_output_maxstr_none(char *iobuf, int iobufsize);

%typemap(argout) (char *iobuf, int iobufsize)
{
  // %typemap(argout) (char *iobuf, int iobufsize)
  qfree($1);
}

%typemap(directorout) char *get_node_label (qstring tmp)
{
  // %typemap(directorout) char *get_node_label (qstring tmp)
  if ( PyUnicode_as_qstring(&tmp, result) )
    ::qstrncpy(iobuf, tmp.c_str(), iobufsize);
  else
    Swig::DirectorTypeMismatchException::raise(
            SWIG_ErrorType(SWIG_TypeError),
            "in output value of type 'char *' in method '$symname'");
  $result = iobuf;
}

%fragment("call_py_testf_t", "header")
{
  bool call_py_testf_t(flags64_t flags, void *ud)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if ( PyErr_Occurred() )
      return false;
    PyObject *py_callable = (PyObject *) ud;
    QASSERT(0, PyCallable_Check(py_callable));
    newref_t py_flags(PyLong_FromUnsignedLong(flags));
    newref_t result(PyObject_CallFunctionObjArgs(py_callable, py_flags.o, nullptr));
    return result != nullptr && PyObject_IsTrue(result.o);
  }
}

%typemap(in, fragment="call_py_testf_t") (testf_t *func, void *ud)
{
  // %typemap(in, fragment="call_py_testf_t") (testf_t *func, void *ud)
  if ( !PyCallable_Check($input) )
    SWIG_exception_fail(
            SWIG_TypeError,
            "in method '" "$symname" "', argument " "$argnum"" of type 'callable'");
  $1 = call_py_testf_t;
  $2 = $input;
}

%typemap(in) (printer_t *printer)
{
  // %typemap(in) (printer_t *printer)
  if ( $input == Py_None )
  {
    $1 = nullptr;
  }
  else if ( PyBool_Check($input) )
  {
    $1 = $input == Py_True ? msg : nullptr;
  }
  else
  {
    int res = SWIG_ConvertFunctionPtr($input, (void**)(&$1), SWIGTYPE_p_f_p_q_const__char_v_______int);
    if ( !SWIG_IsOK(res) )
    {
      SWIG_exception_fail(SWIG_ArgError(res), "in method '" "parse_decls" "', argument " "3"" of type '" "printer_t *""'");
      SWIG_exception_fail(
            SWIG_TypeError,
            "in method '" "$symname" "', argument " "$argnum"" of type 'printer_t *'");
    }
  }
}

%define %define_regval_python_accessors()
%{
//-------------------------------------------------------------------------
struct _cvt_status_t
{
  PyObject *def_err_class;
  const char *def_err_string;

  qstring err_string;
  PyObject *err_class;
  bool ok;

  _cvt_status_t(PyObject *_def_err_class, const char *_def_err_string)
    : def_err_class(_def_err_class),
    def_err_string(_def_err_string),
    err_class(nullptr),
    ok(true) {}

  ~_cvt_status_t()
  {
    if ( !ok )
    {
      if ( err_class == nullptr )
      {
        err_class = def_err_class;
        err_string = def_err_string;
      }
      PyErr_SetString(err_class, err_string.c_str());
    }
  }

  qstring &failed(PyObject *_err_class)
  {
    QASSERT(30587, !ok);
    err_class = _err_class;
    return err_string;
  }
};

static PyObject *get_regval_t(
        const regval_t &rv,
        op_dtype_t dtype)
{
  PyObject *res = nullptr;
  _cvt_status_t status(PyExc_ValueError, "Conversion failed");
  if ( is_floating_dtype(dtype) )
  {
    double dbl;
    fpvalue_t fpv;
    const bytevec_t &b = rv.bytes();
    status.ok = cpu2ieee(&fpv, b.begin(), b.size()) == REAL_ERROR_OK
             && fpv.to_double(&dbl) == REAL_ERROR_OK;
    if ( status.ok )
      res = PyFloat_FromDouble(dbl);
  }
  else if ( dtype == dt_byte16 || dtype == dt_byte32 || dtype == dt_byte64 )
  {
    const bytevec_t &b = rv.bytes();
    res = PyBytes_FromStringAndSize((const char *) b.begin(), b.size());
  }
  else
  {
    if ( rv.ival <= uint64(LONG_MAX) )
      res = PyInt_FromLong(long(rv.ival));
    else
      res = PyLong_FromUnsignedLongLong((unsigned PY_LONG_LONG) rv.ival);
  }
  return res;
}

bool set_regval_t(regval_t **out, regval_t *buf, op_dtype_t dtype, PyObject *o)
{
  if ( o == Py_None )
    return false;

  int cvt = SWIG_ConvertPtr(o, (void **) out, SWIGTYPE_p_regval_t, 0);
  if ( SWIG_IsOK(cvt) && *out != nullptr )
    return true;

  struct ida_local cvt_t
  {
    static bool convert_int(regval_t *lout, PyObject *in, op_dtype_t dt)
    {
      uint64 u64 = 0;
      _cvt_status_t status(PyExc_TypeError, "Expected integer value");
      size_t nbits = 0;
      switch ( dt )
      {
        case dt_byte: nbits = 8; break;
        case dt_word: nbits = 16; break;
        default:
        case dt_dword: nbits = 32; break;
        case dt_qword: nbits = 64; break;
      }
      status.ok = PyW_GetNumber(in, &u64);
      if ( status.ok )
      {
        if ( nbits < 64 )
        {
          status.ok = u64 < (1ULL << nbits);
          if ( !status.ok )
            status.failed(PyExc_ValueError).sprnt("Integer value too large to fit in %" FMT_Z " bits", nbits);
        }
      }
      if ( status.ok )
        lout->set_int(u64);
      return status.ok;
    }

    static bool convert_float(regval_t *lout, PyObject *in, op_dtype_t dt)
    {
      _cvt_status_t status(PyExc_TypeError, "Expected float value");
      double dbl = PyFloat_AsDouble(in);
      status.ok = PyErr_Occurred() == nullptr;
      if ( status.ok )
      {
        // convert from IBM PC format to IEEE; then to the target cpu format
        uchar native[32];
        int size = get_dtype_size(dt);
        QASSERT(0, size <= sizeof(native));
        fpvalue_t fpval;
        uint16 swt = sizeof(double) / 2 - 1;
        status.ok = ieee_realcvt(&dbl, &fpval, swt) == REAL_ERROR_OK
                 && ieee2cpu(native, fpval, size) == REAL_ERROR_OK;
        if ( status.ok )
        {
          lout->set_bytes(native, size, RVT_FLOAT);
          return true;
        }
        status.failed(PyExc_ValueError).sprnt("Float conversion failed");
      }
      return false;
    }

    static bool convert_bytes(regval_t *lout, PyObject *in, op_dtype_t dt)
    {
      bytevec_t bytes;
      _cvt_status_t status(PyExc_TypeError, "Unexpected value");
      size_t needed = 0;
      switch ( dt )
      {
        case dt_byte16: needed = 16; break;
        case dt_byte32: needed = 32; break;
        case dt_byte64: needed = 64; break;
        default:
          break;
      }
      status.ok = needed > 0;
      Py_ssize_t got;
      if ( status.ok )
      {
        status.ok = false;
        if ( PyBytes_Check(in) )
        {
          char *buf;
          status.ok = PyBytes_AsStringAndSize(in, &buf, &got) >= 0 && got <= needed;
          if ( status.ok )
            bytes.append((const uchar *) buf, got);
          else
            status.failed(PyExc_ValueError).sprnt(
                    "List of bytes is too long; was expecting at most %d bytes",
                    int(needed));
        }
        else if ( PyLong_Check(in) )
        {
          uint64 u64 = 0;
          status.ok = PyW_GetNumber(in, &u64);
          if ( status.ok )
          {
            got = sizeof(u64);
            bytes.resize(got, 0);
            memcpy(bytes.begin(), &u64, got);
          }
          else
          {
            if ( PyLong_CheckExact(in) )
              goto TRY_RAW_LONG;
          }
        }
        else if ( PyLong_CheckExact(in) )
        {
TRY_RAW_LONG:
          // (possibly very long) int or long value. Apparently it's rather
          // safe to use _PyLong_AsByteArray (it's even present in 3.x)
          // https://stackoverflow.com/questions/18290507/python-extension-construct-and-inspect-large-integers-efficiently

          // /* _PyLong_AsByteArray: Convert the least-significant 8*n bits of long
          //    v to a base-256 integer, stored in array bytes.  Normally return 0,
          //    return -1 on error.
          //    If little_endian is 1/true, store the MSB at bytes[n-1] and the LSB at
          //    bytes[0]; else (little_endian is 0/false) store the MSB at bytes[0] and
          //    the LSB at bytes[n-1].
          //    If is_signed is 0/false, it's an error if v < 0; else (v >= 0) n bytes
          //    are filled and there's nothing special about bit 0x80 of the MSB.
          //    If is_signed is 1/true, bytes is filled with the 2's-complement
          //    representation of v's value.  Bit 0x80 of the MSB is the sign bit.
          //    Error returns (-1):
          //    + is_signed is 0 and v < 0.  TypeError is set in this case, and bytes
          //      isn't altered.
          //    + n isn't big enough to hold the full mathematical value of v.  For
          //      example, if is_signed is 0 and there are more digits in the v than
          //      fit in n; or if is_signed is 1, v < 0, and n is just 1 bit shy of
          //      being large enough to hold a sign bit.  OverflowError is set in this
          //      case, but bytes holds the least-significant n bytes of the true value.
          // */
          bytes.resize(needed, 0);
          status.ok = pylong_to_byte_array(
                  &bytes,
                  in,
                  /*little_endian=*/ true,
                  /*is_signed=*/ true) >= 0;
          if ( status.ok )
            got = needed;
          else
            status.failed(PyExc_ValueError).sprnt(
                    "Integer value is too large to fit in %d bytes",
                    int(needed));
        }
      }
      if ( status.ok )
      {
        if ( got < needed )
          bytes.growfill(needed - got, 0);
        lout->set_bytes(bytes);
      }
      return status.ok;
    }
  };

  bool ok = false;
  regval_t &rv = *buf;
  switch ( dtype )
  {
    case dt_byte:
    case dt_word:
    case dt_dword:
    case dt_qword:
    default:
      ok = cvt_t::convert_int(&rv, o, dtype);
      break;
    case dt_half:
    case dt_float:
    case dt_tbyte:
    case dt_double:
    case dt_ldbl:
      ok = cvt_t::convert_float(&rv, o, dtype);
      break;
    case dt_byte16:
    case dt_byte32:
    case dt_byte64:
      ok = cvt_t::convert_bytes(&rv, o, dtype);
      break;
  }
  if ( ok )
    *out = &rv;
  return ok;
}
%}
%enddef

%fragment("cvt_func_t", "header")
{
  bool cvt_func_t(func_t **out, PyObject *obj)
  {
    uint64 u64;
    if ( PyW_GetNumber(obj, &u64) )
    {
      *out = get_func(ea_t(u64));
    }
    else
    {
      void *p = 0;
      if ( !SWIG_IsOK(SWIG_ConvertPtr(obj, &p, SWIGTYPE_p_func_t, 0 | 0 )) )
        return false;
      *out = reinterpret_cast<func_t*>(p);
    }
    return true;
  }
}

// Functions accepting a `func_t *` can also derive it from an `ea_t`
%typemap(in, fragment="cvt_func_t") func_t *
{ // %typemap(in) func_t *
  if ( !cvt_func_t(&$1, $input) )
    SWIG_exception_fail(SWIG_ValueError, "in method '" "$symname" "', argument " "$argnum"" of type '" "func_t const *""' (or an address from which it can be derived)");
}


%typemap(in,numinputs=0) jvalue_t *out (jvalue_t temp)
{
  // %typemap(in,numinputs=0) jvalue_t *out (jvalue_t temp)
  $1 = &temp;
}

%typemap(argout) jvalue_t *out
{
  // %typemap(argout) jvalue_t *out
  Py_XDECREF($result);
  $result = PyW_from_jvalue_t(*$1);
}

// pattern matching of multi-argument typemaps is more strict; would not work without argument names
%define  %define_merge_handler_typemap(MNI_ARG_NAME, N_ARG_NAME)
%typemap(in,numinputs=0) (int moddata_id) { $1 = -1; }
%typemap(in,numinputs=1) (const merge_node_info2_t *MNI_ARG_NAME, size_t N_ARG_NAME) (qvector<merge_node_info2_t> temp)
{
  // %typemap(in,numinputs=1) (const merge_node_info2_t *, size_t ) (qvector<merge_node_info2_t> temp)
  if ( $input == Py_None )
  {
    $2 = 0;
    $1 = nullptr;
  }
  else
  {
    if ( !PySequence_Check($input) )
    {
      PyErr_SetString(PyExc_TypeError, "Expecting a list of `merge_node_info2_t` instances");
      return nullptr;
    }
    PyObject *s = $input;
    Py_ssize_t len = PySequence_Size(s);
    temp.reserve(len);
    for ( Py_ssize_t i = 0; i < len; ++i )
    {
      newref_t o(PySequence_GetItem(s, i));
      void *ap = 0 ;
      int cvt = SWIG_ConvertPtr(o.o, &ap, $descriptor, 0);
      if ( !SWIG_IsOK(cvt) )
        SWIG_exception_fail(
                SWIG_ArgError(cvt),
                "in method '" "$symname" "', argument " "$argnum"" consists of 'merge_node_info2_t' instances");
      temp.push_back(*reinterpret_cast<merge_node_info2_t*>(ap));
    }
    $2 = temp.size();
    $1 = temp.extract();
  }
}

%typemap(typecheck,numinputs=1) (const merge_node_info2_t *MNI_ARG_NAME, size_t N_ARG_NAME)
{
  // %typemap(typecheck,numinputs=1) (const merge_node_info2_t *, size_t )
  $1 = ($input == Py_None || PySequence_Check($input));
}
%enddef

// If the module is 'pro', don't import pro.h, or the %include
// at the beginning of pro.i won't have any effect. Same for all
// modules.
${ALL_IMPORTS}

// This is where all the collected NONNULL information coming
// from the SDK, will be injected in the form of 'check'
// typemaps.
${NONNULL_TYPEMAPS}

#endif // __HEADER_I__
// END: auto-inserted header

```
