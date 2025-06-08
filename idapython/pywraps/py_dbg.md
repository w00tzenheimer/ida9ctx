```cpp
#ifndef __PYDBG__
#define __PYDBG__

//<code(py_dbg)>

// hookgenDBG:methodsinfo_def

//-------------------------------------------------------------------------
static bool _to_reg_val(regval_t **out, regval_t *buf, const char *name, PyObject *o)
{
  register_info_t ri;
  if ( !get_dbg_reg_info(name, &ri) )
  {
    // we couldn't find the register information. This might
    // mean that we are accessing another, sub register (e.g.,
    // "eax" while the real register name is "rax".) Let's
    // assume the dtype is DWORD then
    ri.dtype = dt_dword;
  }
  return set_regval_t(out, buf, ri.dtype, o);
}

//-------------------------------------------------------------------------
static PyObject *_from_reg_val(
        const char *name,
        const regval_t &rv)
{
  register_info_t ri;
  if ( !get_dbg_reg_info(name, &ri) ) // see _to_reg_val()
    ri.dtype = dt_dword;
  return get_regval_t(rv, ri.dtype);
}
//</code(py_dbg)>

//<inline(py_dbg)>

inline void idaapi set_process_options(
        const char *path,
        const char *args,
        const char *sdir,
        const char *host,
        const char *pass,
        int port)
{
  launch_env_t envs;
  return set_process_options(path, args, &envs, sdir, host, pass, port);
}

inline void idaapi get_process_options_noenv(
        qstring *path,
        qstring *args,
        qstring *sdir,
        qstring *host,
        qstring *pass,
        int *port)
{
  launch_env_t envs;
  get_process_options(path, args, &envs, sdir, host, pass, port);
}

//-------------------------------------------------------------------------
static PyObject *py_get_manual_regions()
{
  meminfo_vec_t ranges;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  get_manual_regions(&ranges);
  SWIG_PYTHON_THREAD_END_ALLOW;
  return meminfo_vec_t_to_py(ranges);
}

//-------------------------------------------------------------------------
static bool dbg_is_loaded()
{
  return dbg != nullptr;
}

//-------------------------------------------------------------------------
static PyObject *refresh_debugger_memory()
{
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  invalidate_dbgmem_config();
  invalidate_dbgmem_contents(BADADDR, 0);

  // Ask the debugger to populate debug names
  if ( dbg != nullptr )
    dbg->suspended(true);

  // Invalidate the cache
  is_mapped(0);
  SWIG_PYTHON_THREAD_END_ALLOW;
  PYW_GIL_CHECK_LOCKED_SCOPE();
  Py_RETURN_NONE;
}

ssize_t idaapi DBG_Callback(void *ud, int notification_code, va_list va);
struct DBG_Hooks : public hooks_base_t
{
  // hookgenDBG:methodsinfo_decl

  DBG_Hooks(uint32 _flags=0, uint32 _hkcb_flags=HKCB_GLOBAL)
    : hooks_base_t("ida_dbg.DBG_Hooks", DBG_Callback, HT_DBG, _flags, _hkcb_flags) {}

  bool hook() { return hooks_base_t::hook(); }
  bool unhook() { return hooks_base_t::unhook(); }
#ifdef TESTABLE_BUILD
  PyObject *dump_state(bool assert_all_reimplemented=false) { return hooks_base_t::dump_state(mappings, mappings_size, assert_all_reimplemented); }
#endif

  // hookgenDBG:methods

  ssize_t dispatch(int code, va_list va)
  {
    ssize_t ret = 0;
    switch ( code )
    {
      // hookgenDBG:notifications
    }
    return ret;
  }

private:
  static ssize_t store_int(int rc, const debug_event_t *, int *warn)
  {
    *warn = rc;
    return 0;
  }

  static ssize_t store_int(int rc, thid_t, ea_t, int *warn)
  {
    *warn = rc;
    return 0;
  }
};

//-------------------------------------------------------------------------
ssize_t idaapi DBG_Callback(void *ud, int code, va_list va)
{
  // hookgenDBG:safecall=DBG_Hooks
}


//------------------------------------------------------------------------
static PyObject *py_list_bptgrps()
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  qstrvec_t args;
  if ( list_bptgrps(&args) == 0 )
    Py_RETURN_NONE;
  return qstrvec2pylist(args);
}

//------------------------------------------------------------------------
static ea_t py_internal_get_sreg_base(thid_t tid, int sreg_value)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  ea_t answer;
  return internal_get_sreg_base(&answer, tid, sreg_value) <= DRC_NONE
       ? BADADDR
       : answer;
}

//-------------------------------------------------------------------------
static ssize_t py_write_dbg_memory(ea_t ea, PyObject *py_buf, size_t size=size_t(-1))
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !dbg_can_query(dbg) || !PyBytes_Check(py_buf) )
    return -1;
  char *buf = nullptr;
  Py_ssize_t sz;
  if ( PyBytes_AsStringAndSize(py_buf, &buf, &sz) < 0 )
    return -1;
  if ( size == size_t(-1) )
    size = size_t(sz);
  return write_dbg_memory(ea, buf, size);
}

//-------------------------------------------------------------------------
static bool py_dbg_can_query()
{
  return dbg_can_query(dbg);
}

//-------------------------------------------------------------------------
static PyObject *py_set_reg_val(const char *regname, PyObject *value)
{
  regval_t buf;
  regval_t *ptr;
  if ( !_to_reg_val(&ptr, &buf, regname, value) )
    return nullptr;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  bool ok = set_reg_val(regname, ptr);
  SWIG_PYTHON_THREAD_END_ALLOW;
  if ( !ok )
  {
    PyErr_SetString(PyExc_Exception, "Failed to set register value");
    return nullptr;
  }
  Py_RETURN_TRUE;
}

//-------------------------------------------------------------------------
static PyObject *py_set_reg_val(thid_t tid, int regidx, PyObject *value)
{
  if ( dbg == nullptr )
  {
    PyErr_SetString(PyExc_Exception, "No debugger loaded");
    return nullptr;
  }
  if ( regidx < 0 || regidx >= dbg->nregisters )
  {
    qstring buf;
    buf.sprnt("Bad register index: %d", regidx);
    PyErr_SetString(PyExc_Exception, buf.c_str());
    return nullptr;
  }
  const register_info_t &ri = dbg->regs(regidx);
  regval_t buf;
  regval_t *ptr;
  if ( !_to_reg_val(&ptr, &buf, ri.name, value) )
    return nullptr;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  bool ok = set_reg_val(tid, regidx, ptr) > 0;
  SWIG_PYTHON_THREAD_END_ALLOW;
  return PyInt_FromLong(ok);
}

//-------------------------------------------------------------------------
static PyObject *py_request_set_reg_val(const char *regname, PyObject *o)
{
  regval_t buf;
  regval_t *ptr;
  if ( !_to_reg_val(&ptr, &buf, regname, o) )
    return nullptr;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  bool ok = request_set_reg_val(regname, ptr);
  SWIG_PYTHON_THREAD_END_ALLOW;
  if ( !ok )
  {
    PyErr_SetString(PyExc_Exception, "Failed to request set register value");
    return nullptr;
  }
  Py_RETURN_TRUE;
}

//-------------------------------------------------------------------------
static PyObject *py_get_reg_val(const char *regname)
{
  regval_t buf;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  bool ok = get_reg_val(regname, &buf);
  SWIG_PYTHON_THREAD_END_ALLOW;
  if ( !ok )
  {
    PyErr_SetString(PyExc_Exception, "Failed to retrieve register value");
    return nullptr;
  }
  return _from_reg_val(regname, buf);
}

//-------------------------------------------------------------------------
static regvals_t *py_get_reg_vals(thid_t tid, int clsmask)
{
  regvals_t *rvs = new regvals_t();
  if ( dbg != nullptr )
  {
    rvs->resize(dbg->nregisters);
    if ( get_reg_vals(tid, clsmask, rvs->begin()) != DRC_OK )
      rvs->clear();
  }
  return rvs;
}
//</inline(py_dbg)>
#endif

```
