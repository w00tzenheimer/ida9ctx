```text
Assorted notes
--------------

Wrapped functions and constants:

All the symbols from the idaapi module are listed in symbollist.txt.
Documentation for the plugin API functions functions is in the IDA
SDK header files. All function and symbol names directly translate
to the C++ counterparts. If you try to use a function that is not
wrapped yet you will get an exception like this:

 Traceback (most recent call last):
   File "<string>", line 1, in ?
 NameError: name 'foobar' is not defined

If this happens you can check the function in symbollist.txt. If it
is not included and it should be please report it to the author.


Data types:

All the C++ data types are mapped to corresponding Python data types.
For example ea_t maps to a Python integer. Complex data types (like
structures and classes) are mapped to Python classes that have the
same attributes as the original type.


Arguments and return values:

Generally all function arguments should be the same type as specified
by the original headers. Pointers to complex types (structures, classes)
are checked and must match the original declarations.

For example comment = get_func_comment("aa", 0) will raise an exception:

 Traceback (most recent call last):
   File "<string>", line 1, in ?
 TypeError: Type error. Got aa, expected _p_func_t

When calling functions that return a string in a buffer (usually with
maximum size) the buffer and size parameter is omitted. These functions
return either the result in a string or None if the call fails and returns
NULL. The output buffers are maximized at MAXSTR.

  Example: 

  C++:    get_func_name(0x1234, buf, sizeof(buf));
  Python: name = get_func_name(0x1234)

Any function that should return a char * is going to return either a
Python string (up to MAXSTR) or None.



```
