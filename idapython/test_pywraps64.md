```text
--- TEST: READ_NUM 12
 => PyW_GetNumber     : is_64: false, unsigned: 12; signed: 12; hex: 0xc
 => PyW_GetNumberAsIDC: (64-bit sval_t) unsigned: 12; signed: 12; hex: 0xc
--- TEST: READ_NUM 0xFFFF
 => PyW_GetNumber     : is_64: false, unsigned: 65535; signed: 65535; hex: 0xffff
 => PyW_GetNumberAsIDC: (64-bit sval_t) unsigned: 65535; signed: 65535; hex: 0xffff
--- TEST: READ_NUM 0xFFFFFFFF
 => PyW_GetNumber     : is_64: true, unsigned: 4294967295; signed: 4294967295; hex: 0xffffffff
 => PyW_GetNumberAsIDC: (int64) unsigned: 4294967295; signed: 4294967295; hex: 0xffffffff
--- TEST: READ_NUM 0x00000FFFFFFF
 => PyW_GetNumber     : is_64: false, unsigned: 268435455; signed: 268435455; hex: 0xfffffff
 => PyW_GetNumberAsIDC: (64-bit sval_t) unsigned: 268435455; signed: 268435455; hex: 0xfffffff
--- TEST: READ_NUM 0x0000FFFFFFFF
 => PyW_GetNumber     : is_64: true, unsigned: 4294967295; signed: 4294967295; hex: 0xffffffff
 => PyW_GetNumberAsIDC: (int64) unsigned: 4294967295; signed: 4294967295; hex: 0xffffffff
--- TEST: READ_NUM 0x0000FFFFFFFFFFFF
 => PyW_GetNumber     : is_64: true, unsigned: 281474976710655; signed: 281474976710655; hex: 0xffffffffffff
 => PyW_GetNumberAsIDC: (int64) unsigned: 281474976710655; signed: 281474976710655; hex: 0xffffffffffff
--- TEST: READ_NUM 0x0000FFFFFFFFFFFF1234
 => PyW_GetNumber     : is_64: true, unsigned: 18446744073709490740; signed: -60876; hex: 0xffffffffffff1234
 => PyW_GetNumberAsIDC: (int64) unsigned: 18446744073709490740; signed: -60876; hex: 0xffffffffffff1234
--- TEST: READ_NUM 0x00000000FFFFFFFF
 => PyW_GetNumber     : is_64: true, unsigned: 4294967295; signed: 4294967295; hex: 0xffffffff
 => PyW_GetNumberAsIDC: (int64) unsigned: 4294967295; signed: 4294967295; hex: 0xffffffff
--- TEST: READ_NUM 0x00000000FFFFFFFF1234
 => PyW_GetNumber     : is_64: true, unsigned: 281474976649780; signed: 281474976649780; hex: 0xffffffff1234
 => PyW_GetNumberAsIDC: (int64) unsigned: 281474976649780; signed: 281474976649780; hex: 0xffffffff1234
--- TEST: READ_NUM 0xFFFFFFFFFFFF0000
 => PyW_GetNumber     : is_64: true, unsigned: 18446744073709486080; signed: -65536; hex: 0xffffffffffff0000
 => PyW_GetNumberAsIDC: (int64) unsigned: 18446744073709486080; signed: -65536; hex: 0xffffffffffff0000
--- TEST: READ_NUM 0x1234FFFFFFFFFFFF0000
 => PyW_GetNumber     : Could not convert to a number
 => PyW_GetNumberAsIDC: Could not convert to an IDC value
--- TEST: READ_NUM 0xFFFFFFFF00000000
 => PyW_GetNumber     : is_64: true, unsigned: 18446744069414584320; signed: -4294967296; hex: 0xffffffff00000000
 => PyW_GetNumberAsIDC: (int64) unsigned: 18446744069414584320; signed: -4294967296; hex: 0xffffffff00000000
--- TEST: READ_NUM 0x1234FFFFFFFF00000000
 => PyW_GetNumber     : Could not convert to a number
 => PyW_GetNumberAsIDC: Could not convert to an IDC value
--- TEST: READ_NUM 0xFFFFFFFF0000
 => PyW_GetNumber     : is_64: true, unsigned: 281474976645120; signed: 281474976645120; hex: 0xffffffff0000
 => PyW_GetNumberAsIDC: (int64) unsigned: 281474976645120; signed: 281474976645120; hex: 0xffffffff0000
--- TEST: READ_NUM 0x1234FFFFFFFF0000
 => PyW_GetNumber     : is_64: true, unsigned: 1311954866448302080; signed: 1311954866448302080; hex: 0x1234ffffffff0000
 => PyW_GetNumberAsIDC: (int64) unsigned: 1311954866448302080; signed: 1311954866448302080; hex: 0x1234ffffffff0000
--- TEST: READ_NUM 0xFFFFFFFF00001234
 => PyW_GetNumber     : is_64: true, unsigned: 18446744069414588980; signed: -4294962636; hex: 0xffffffff00001234
 => PyW_GetNumberAsIDC: (int64) unsigned: 18446744069414588980; signed: -4294962636; hex: 0xffffffff00001234
--- TEST: READ_NUM -0xFFFF
 => PyW_GetNumber     : is_64: false, unsigned: 18446744073709486081; signed: -65535; hex: 0xffffffffffff0001
 => PyW_GetNumberAsIDC: (64-bit sval_t) unsigned: 18446744073709486081; signed: -65535; hex: 0xffffffffffff0001
--- TEST: READ_NUM -0xFFFFFFFF
 => PyW_GetNumber     : is_64: true, unsigned: 18446744069414584321; signed: -4294967295; hex: 0xffffffff00000001
 => PyW_GetNumberAsIDC: (int64) unsigned: 18446744069414584321; signed: -4294967295; hex: 0xffffffff00000001
--- TEST: READ_NUM -0x00000FFFFFFF
 => PyW_GetNumber     : is_64: false, unsigned: 18446744073441116161; signed: -268435455; hex: 0xfffffffff0000001
 => PyW_GetNumberAsIDC: (64-bit sval_t) unsigned: 18446744073441116161; signed: -268435455; hex: 0xfffffffff0000001
--- TEST: READ_NUM -0x0000FFFFFFFF
 => PyW_GetNumber     : is_64: true, unsigned: 18446744069414584321; signed: -4294967295; hex: 0xffffffff00000001
 => PyW_GetNumberAsIDC: (int64) unsigned: 18446744069414584321; signed: -4294967295; hex: 0xffffffff00000001
--- TEST: READ_NUM -0x0000FFFFFFFFFFFF
 => PyW_GetNumber     : is_64: true, unsigned: 18446462598732840961; signed: -281474976710655; hex: 0xffff000000000001
 => PyW_GetNumberAsIDC: (int64) unsigned: 18446462598732840961; signed: -281474976710655; hex: 0xffff000000000001
--- TEST: READ_NUM -0x0000FFFFFFFFFFFF1234
 => PyW_GetNumber     : Could not convert to a number
 => PyW_GetNumberAsIDC: Could not convert to an IDC value
--- TEST: READ_NUM -0x00000000FFFFFFFF
 => PyW_GetNumber     : is_64: true, unsigned: 18446744069414584321; signed: -4294967295; hex: 0xffffffff00000001
 => PyW_GetNumberAsIDC: (int64) unsigned: 18446744069414584321; signed: -4294967295; hex: 0xffffffff00000001
--- TEST: READ_NUM -0x00000000FFFFFFFF1234
 => PyW_GetNumber     : is_64: true, unsigned: 18446462598732901836; signed: -281474976649780; hex: 0xffff00000000edcc
 => PyW_GetNumberAsIDC: (int64) unsigned: 18446462598732901836; signed: -281474976649780; hex: 0xffff00000000edcc
--- TEST: READ_NUM -0xFFFFFFFFFFFF0000
 => PyW_GetNumber     : Could not convert to a number
 => PyW_GetNumberAsIDC: Could not convert to an IDC value
--- TEST: READ_NUM -0x1234FFFFFFFFFFFF0000
 => PyW_GetNumber     : Could not convert to a number
 => PyW_GetNumberAsIDC: Could not convert to an IDC value
--- TEST: READ_NUM -0xFFFFFFFF00000000
 => PyW_GetNumber     : Could not convert to a number
 => PyW_GetNumberAsIDC: Could not convert to an IDC value
--- TEST: READ_NUM -0x1234FFFFFFFF00000000
 => PyW_GetNumber     : Could not convert to a number
 => PyW_GetNumberAsIDC: Could not convert to an IDC value
--- TEST: READ_NUM -0x1234FFFFFFFF0000
 => PyW_GetNumber     : is_64: true, unsigned: 17134789207261249536; signed: -1311954866448302080; hex: 0xedcb000000010000
 => PyW_GetNumberAsIDC: (int64) unsigned: 17134789207261249536; signed: -1311954866448302080; hex: 0xedcb000000010000
--- TEST: READ_NUM -0xFFFFFFFF0000
 => PyW_GetNumber     : is_64: true, unsigned: 18446462598732906496; signed: -281474976645120; hex: 0xffff000000010000
 => PyW_GetNumberAsIDC: (int64) unsigned: 18446462598732906496; signed: -281474976645120; hex: 0xffff000000010000
--- TEST: READ_NUM -0xFFFFFFFF00001234
 => PyW_GetNumber     : Could not convert to a number
 => PyW_GetNumberAsIDC: Could not convert to an IDC value
--- TEST: READ_NUM "Hello"
 => PyW_GetNumber     : Could not convert to a number
 => PyW_GetNumberAsIDC: Could not convert to an IDC value
--- TEST: READ_NUM "None"
 => PyW_GetNumber     : Could not convert to a number
 => PyW_GetNumberAsIDC: Could not convert to an IDC value
--- TEST: READ_NUM True
 => PyW_GetNumber     : Could not convert to a number
 => PyW_GetNumberAsIDC: Could not convert to an IDC value

```
