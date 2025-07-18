```ini
// PDB plugin

// PDB information provider
#define PDB_PROVIDER_MSDIA  1   // use MSDIA local/remote provider
#define PDB_PROVIDER_PDBIDA 2   // use PDBIDA provider
//PDB_PROVIDER = PDB_PROVIDER_PDBIDA

// it is possible to specify the desired provider in the command line:
//      ida -Opdb:off input_file
//      ida -Opdb:msdia input_file
//      ida -Opdb:pdbida input_file

// Symbol search path
// The _NT_SYMBOL_PATH environment variable overrides this setting.
// If none of these variables is set then the default value will be used:
// "SRV*CACHEDIR*http://msdl.microsoft.com/download/symbols"
// where
//   CACHEDIR=%TEMP%\ida  for Windows
//   CACHEDIR=$TMPDIR/ida or $TMP/ida or /tmp/ida for non-Windows OSes
//
//_NT_SYMBOL_PATH = "SRV*c:\\symbols*http://symbols.mozilla.org/firefox;SRV*c:\\symbols*http://msdl.microsoft.com/download/symbols";

// Network communications while looking for PDB file can be restricted.
// Valid only for PDBIDA provider.
#define PDB_NETWORK_OFF 0   // local directories search only
#define PDB_NETWORK_PE  1   // local directories search for COFF, full search for PE
#define PDB_NETWORK_ON  2   // no restrictions
//PDB_NETWORK = PDB_NETWORK_PE

// PDBIDA is able to load MSF 7.0 PDB files only.
// MSDIA can load all PDB files, including old MSF 2.0 files.
// If you set the following option to YES, IDA will automatically switch
// to MSDIA for old files.
// Please note that under Linux/macOS the MSDIA provider requires you to configure
// the win32_remote.exe or win64_remote64.exe server because it can run only on Windows.
// It is possible to specify the desired behavior in the command line:
//      ida -Opdb:fallback input_file
//      ida -Opdb:nofallback input_file
#ifdef __NT__
PDB_MSDIA_FALLBACK = YES
#else
PDB_MSDIA_FALLBACK = NO
#endif

// remote server where win32_remote.exe or win64_remote64.exe is running
// used when loading PDB symbols on non-Windows platforms
// NB: it will be used only if there is not already an existing debugging session started
PDB_REMOTE_SERVER = "localhost";
PDB_REMOTE_PORT   = 23946
// password for the remote server
PDB_REMOTE_PASSWD = "";

```
