```ini
; This file describes the exception definitions.
; The definitions will be used for new databases.

; for each exception:
;  code    stop_at   pass_to_app  notification name      description
;
;  code is the exception code
;  stop_at is one of stop or nostop - should the debugger suspend
;          the process when the exception occurs
;  pass_to_app is one of app or mask - should the debugger pass
;          the exception to the application or not
;  notification is one of warn/log/silent
;  name    is the exception short name
;  description is the exception description displayed to the user

; Windows exceptions
.win32,bochs_win32
0xC0000005   stop mask warn EXCEPTION_ACCESS_VIOLATION         The instruction at 0x%a referenced memory at 0x%a. The memory could not be %s
0x80000002   stop mask warn EXCEPTION_DATATYPE_MISALIGNMENT    A datatype misalignment error was detected in a load or store instruction
0x80000003   stop mask warn EXCEPTION_BREAKPOINT               Software breakpoint exception
0x80000004   stop mask warn EXCEPTION_SINGLE_STEP              Single step exception
0xC000008C   stop mask warn EXCEPTION_ARRAY_BOUNDS_EXCEEDED    Array bounds exceeded
0xC000008D   stop mask warn EXCEPTION_FLT_DENORMAL_OPERAND     Floating point denormal operand
0xC000008E   stop mask warn EXCEPTION_FLT_DIVIDE_BY_ZERO       Floating point divide by zero
0xC000008F   stop mask warn EXCEPTION_FLT_INEXACT_RESULT       Floating point inexact result
0xC0000090   stop mask warn EXCEPTION_FLT_INVALID_OPERATION    Floating point invalid operation
0xC0000091   stop mask warn EXCEPTION_FLT_OVERFLOW             Floating point overflow
0xC0000092   stop mask warn EXCEPTION_FLT_STACK_CHECK          Floating point stack check
0xC0000093   stop mask warn EXCEPTION_FLT_UNDERFLOW            Floating point underflow
0xC0000094   stop mask warn EXCEPTION_INT_DIVIDE_BY_ZERO       Integer divide by zero
0xC0000095   stop mask warn EXCEPTION_INT_OVERFLOW             Integer overflow
0xC0000096   stop mask warn EXCEPTION_PRIV_INSTRUCTION         Priveleged instruction
0xC0000006   stop mask warn EXCEPTION_IN_PAGE_ERROR            The instruction at "0x%a" referenced memory at "0x%a". The required data was not placed into memory because of an I/O error status of "0x%a"
0xC000001D   stop mask warn EXCEPTION_ILLEGAL_INSTRUCTION      An attempt was made to execute an illegal instruction
0xC0000025   stop mask warn EXCEPTION_NONCONTINUABLE_EXCEPTION Windows cannot continue from this exception
0xC00000FD   stop mask warn EXCEPTION_STACK_OVERFLOW           A new guard page for the stack cannot be created (stack overflow)
0xC0000026   stop mask warn EXCEPTION_INVALID_DISPOSITION      An invalid exception disposition was returned by an exception handler
0x80000001   stop mask warn EXCEPTION_GUARD_PAGE               A page of memory that marks the end of a data structure such as a stack or an array has been accessed
0xC0000008   stop mask warn EXCEPTION_INVALID_HANDLE           An invalid HANDLE was specified
0xEEFFACE    stop mask warn EXCEPTION_BCC_FATAL                Fatal unhandled exception in the BCC compiled program
0xEEDFAE6    stop mask warn EXCEPTION_BCC_NORMAL               Unhandled exception in the BCC compiled program
0x40010005   stop mask warn DBG_CONTROL_C                      CTRL+C was input to console process
0x40010008   stop mask warn DBG_CONTROL_BREAK                  CTRL+BREAK was input to console process
0xE06D7363   stop mask warn EXCEPTION_MSC_CPLUSPLUS            Microsoft C++ exception
0xE0434F4D   stop mask warn EXCEPTION_MANAGED_NET              Managed .NET exception
0xE0434352   stop mask warn EXCEPTION_MANAGED_NET_V4           Managed .NET exception (V4+)
0x4000001E   stop mask warn EXCEPTION_WX86_SINGLE_STEP         Single step exception (x86 emulation)
0x4000001F   stop mask warn EXCEPTION_WX86_BREAKPOINT          Software breakpoint exception (x86 emulation)
0x406D1388   nostop mask log MS_VC_EXCEPTION                   SetThreadName

; Linux exceptions
.linux
1    stop mask warn SIGHUP    Hangup
2    stop mask warn SIGINT    Interrupt
3    stop mask warn SIGQUIT   Quit
4    stop mask warn SIGILL    Illegal instruction
5    stop mask warn SIGTRAP   Trace trap
6    stop mask warn SIGABRT   Abort
7    stop mask warn SIGBUS    BUS error
8    stop mask warn SIGFPE    Floating-point exception
9    stop mask warn SIGKILL   Kill unblockable
10   stop mask warn SIGUSR1   User-defined signal 1
11   stop mask warn SIGSEGV   Segmentation violation
12   stop mask warn SIGUSR2   User-defined signal 2
13   stop mask warn SIGPIPE   Broken pipe
14   stop mask warn SIGALRM   Alarm clock
15   stop mask warn SIGTERM   Termination
16   stop mask warn SIGSTKFLT Stack fault
17   stop mask warn SIGCHLD   Child status has changed
18   stop mask warn SIGCONT   Continue
19   stop mask warn SIGSTOP   Stop unblockable
20   stop mask warn SIGTSTP   Keyboard stop
21   stop mask warn SIGTTIN   Background read from tty
22   stop mask warn SIGTTOU   Background write to tty
23   stop mask warn SIGURG    Urgent condition on socket
24   stop mask warn SIGXCPU   CPU limit exceeded
25   stop mask warn SIGXFSZ   File size limit exceeded
26   stop mask warn SIGVTALRM Virtual alarm clock
27   stop mask warn SIGPROF   Profiling alarm clock
28   stop mask warn SIGWINCH  Window size change
29   stop mask warn SIGIO     I/O now possible
30   stop mask warn SIGPWR    Power failure restart
31   stop mask warn SIGSYS    Bad system call

; Mac OS X/iphone exceptions
.macosx,ios,xnu
1    stop mask warn SIGHUP       terminal line hangup
2    stop mask warn SIGINT       interrupt program
3    stop mask warn SIGQUIT      quit program
4    stop mask warn SIGILL       illegal instruction
5    stop mask warn SIGTRAP      trace trap
6    stop mask warn SIGABRT      abort program
7    stop mask warn SIGEMT       emulate instruction executed
8    stop mask warn SIGFPE       floating-point exception
9    stop mask warn SIGKILL      kill program
10   stop mask warn SIGBUS       bus error
11   stop mask warn SIGSEGV      segmentation violation
12   stop mask warn SIGSYS       non-existent system call invoked
13   stop mask warn SIGPIPE      write on a pipe with no reader
14   stop mask warn SIGALRM      real-time timer expired
15   stop mask warn SIGTERM      software termination signal
16   stop mask warn SIGURG       urgent condition present on socket
17   stop mask warn SIGSTOP      stop
18   stop mask warn SIGTSTP      stop signal generated from keyboard
19   stop mask warn SIGCONT      continue after stop
20   stop mask warn SIGCHLD      child status has changed
21   stop mask warn SIGTTIN      background read attempted from control terminal
22   stop mask warn SIGTTOU      background write attempted to control terminal
23   stop mask warn SIGIO        I/O is possible on a descriptor
24   stop mask warn SIGXCPU      cpu time limit exceeded
25   stop mask warn SIGXFSZ      file size limit exceeded
26   stop mask warn SIGVTALRM    virtual time alarm
27   stop mask warn SIGPROF      profiling timer alarm
28   stop mask warn SIGWINCH     Window size change
29   stop mask warn SIGINFO      status request from keyboard
30   stop mask warn SIGUSR1      User defined signal 1
31   stop mask warn SIGUSR2      User defined signal 2
;additional iphone exceptions
145  stop mask warn EXC_BAD_ACCESS       Bad memory access
146  stop mask warn EXC_BAD_INSTRUCTION  Bad instruction
147  stop mask warn EXC_ARITHMETIC       Arithmetic exception
148  stop mask warn EXC_EMULATION        Emulation exception
149  stop mask warn EXC_SOFTWARE         Software exception
150  stop mask warn EXC_BREAKPOINT       Breakpoint exception

; Bochs IA-32 emulator: raw exceptions
; (in addition to MS Windows exceptions defined above)
.bochs_win32
0x00          stop mask warn DIVIDE_BY_ZERO                    Divide by zero
0x01          stop mask warn SINGLE_STEP                       Single step
0x03          stop mask warn BREAKPOINT                        Breakpoint
0x04          stop mask warn INTO                              Interrupt on overflow
0x06          stop mask warn INVALID_OPCODE                    Invalid opcode
0x0C          stop mask warn STACK_EXCEPTION                   Stack exception
0x0D          stop mask warn GENERAL_PROTECTION_FAULT          General protection fault
0x0E          stop mask warn PAGE_FAULT                        Page fault at 0x%a, error code %a
0x10          stop mask warn FLOATING_POINT_ERROR              Floating point error

.gdb
; gdb signals
1   stop mask warn SIGHUP     Hangup
2   stop mask warn SIGINT     Interrupt
3   stop mask warn SIGQUIT    Quit
4   stop mask warn SIGILL     Illegal instruction
5   stop mask warn SIGTRAP    Trace/breakpoint trap
6   stop mask warn SIGABRT    Aborted
7   stop mask warn SIGEMT     Emulation trap
8   stop mask warn SIGFPE     Arithmetic exception
9   stop mask warn SIGKILL    Killed
10  stop mask warn SIGBUS     Bus error
11  stop mask warn SIGSEGV    Segmentation fault
12  stop mask warn SIGSYS     Bad system call
13  stop mask warn SIGPIPE    Broken pipe
14  stop mask warn SIGALRM    Alarm clock
15  stop mask warn SIGTERM    Terminated
16  stop mask warn SIGURG     Urgent I/O condition
17  stop mask warn SIGSTOP    Stopped (signal)
18  stop mask warn SIGTSTP    Stopped (user)
19  stop mask warn SIGCONT    Continued
20  stop mask warn SIGCHLD    Child status changed
21  stop mask warn SIGTTIN    Stopped (tty input)
22  stop mask warn SIGTTOU    Stopped (tty output)
23  stop mask warn SIGIO      I/O possible
24  stop mask warn SIGXCPU    CPU time limit exceeded
25  stop mask warn SIGXFSZ    File size limit exceeded
26  stop mask warn SIGVTALRM  Virtual timer expired
27  stop mask warn SIGPROF    Profiling timer expired
28  stop mask warn SIGWINCH   Window size changed
29  stop mask warn SIGLOST    Resource lost
30  stop mask warn SIGUSR1    User defined signal 1
31  stop mask warn SIGUSR2    User defined signal 2
32  stop mask warn SIGPWR     Power fail/restart
33  stop mask warn SIGPOLL    Pollable event occurred
34  stop mask warn SIGWIND    SIGWIND
35  stop mask warn SIGPHONE   SIGPHONE
36  stop mask warn SIGWAITING Process's LWPs are blocked
37  stop mask warn SIGLWP     Signal LWP
38  stop mask warn SIGDANGER  Swap space dangerously low
39  stop mask warn SIGGRANT   Monitor mode granted
40  stop mask warn SIGRETRACT Need to relinquish monitor mode
41  stop mask warn SIGMSG     Monitor mode data available
42  stop mask warn SIGSOUND   Sound completed
43  stop mask warn SIGSAK     Secure attention
44  stop mask warn SIGPRIO    SIGPRIO
45  stop mask warn SIG33      Real-time event 33
46  stop mask warn SIG34      Real-time event 34
47  stop mask warn SIG35      Real-time event 35
48  stop mask warn SIG36      Real-time event 36
49  stop mask warn SIG37      Real-time event 37
50  stop mask warn SIG38      Real-time event 38
51  stop mask warn SIG39      Real-time event 39
52  stop mask warn SIG40      Real-time event 40
53  stop mask warn SIG41      Real-time event 41
54  stop mask warn SIG42      Real-time event 42
55  stop mask warn SIG43      Real-time event 43
56  stop mask warn SIG44      Real-time event 44
57  stop mask warn SIG45      Real-time event 45
58  stop mask warn SIG46      Real-time event 46
59  stop mask warn SIG47      Real-time event 47
60  stop mask warn SIG48      Real-time event 48
61  stop mask warn SIG49      Real-time event 49
62  stop mask warn SIG50      Real-time event 50
63  stop mask warn SIG51      Real-time event 51
64  stop mask warn SIG52      Real-time event 52
65  stop mask warn SIG53      Real-time event 53
66  stop mask warn SIG54      Real-time event 54
67  stop mask warn SIG55      Real-time event 55
68  stop mask warn SIG56      Real-time event 56
69  stop mask warn SIG57      Real-time event 57
70  stop mask warn SIG58      Real-time event 58
71  stop mask warn SIG59      Real-time event 59
72  stop mask warn SIG60      Real-time event 60
73  stop mask warn SIG61      Real-time event 61
74  stop mask warn SIG62      Real-time event 62
75  stop mask warn SIG63      Real-time event 63
76  stop mask warn SIGCANCEL  LWP internal signal
77  stop mask warn SIG32      Real-time event 32
78  stop mask warn SIG64      Real-time event 64
79  stop mask warn SIG65      Real-time event 65
80  stop mask warn SIG66      Real-time event 66
81  stop mask warn SIG67      Real-time event 67
82  stop mask warn SIG68      Real-time event 68
83  stop mask warn SIG69      Real-time event 69
84  stop mask warn SIG70      Real-time event 70
85  stop mask warn SIG71      Real-time event 71
86  stop mask warn SIG72      Real-time event 72
87  stop mask warn SIG73      Real-time event 73
88  stop mask warn SIG74      Real-time event 74
89  stop mask warn SIG75      Real-time event 75
90  stop mask warn SIG76      Real-time event 76
91  stop mask warn SIG77      Real-time event 77
92  stop mask warn SIG78      Real-time event 78
93  stop mask warn SIG79      Real-time event 79
94  stop mask warn SIG80      Real-time event 80
95  stop mask warn SIG81      Real-time event 81
96  stop mask warn SIG82      Real-time event 82
97  stop mask warn SIG83      Real-time event 83
98  stop mask warn SIG84      Real-time event 84
99  stop mask warn SIG85      Real-time event 85
100 stop mask warn SIG86      Real-time event 86
101 stop mask warn SIG87      Real-time event 87
102 stop mask warn SIG88      Real-time event 88
103 stop mask warn SIG89      Real-time event 89
104 stop mask warn SIG90      Real-time event 90
105 stop mask warn SIG91      Real-time event 91
106 stop mask warn SIG92      Real-time event 92
107 stop mask warn SIG93      Real-time event 93
108 stop mask warn SIG94      Real-time event 94
109 stop mask warn SIG95      Real-time event 95
110 stop mask warn SIG96      Real-time event 96
111 stop mask warn SIG97      Real-time event 97
112 stop mask warn SIG98      Real-time event 98
113 stop mask warn SIG99      Real-time event 99
114 stop mask warn SIG100     Real-time event 100
115 stop mask warn SIG101     Real-time event 101
116 stop mask warn SIG102     Real-time event 102
117 stop mask warn SIG103     Real-time event 103
118 stop mask warn SIG104     Real-time event 104
119 stop mask warn SIG105     Real-time event 105
120 stop mask warn SIG106     Real-time event 106
121 stop mask warn SIG107     Real-time event 107
122 stop mask warn SIG108     Real-time event 108
123 stop mask warn SIG109     Real-time event 109
124 stop mask warn SIG110     Real-time event 110
125 stop mask warn SIG111     Real-time event 111
126 stop mask warn SIG112     Real-time event 112
127 stop mask warn SIG113     Real-time event 113
128 stop mask warn SIG114     Real-time event 114
129 stop mask warn SIG115     Real-time event 115
130 stop mask warn SIG116     Real-time event 116
131 stop mask warn SIG117     Real-time event 117
132 stop mask warn SIG118     Real-time event 118
133 stop mask warn SIG119     Real-time event 119
134 stop mask warn SIG120     Real-time event 120
135 stop mask warn SIG121     Real-time event 121
136 stop mask warn SIG122     Real-time event 122
137 stop mask warn SIG123     Real-time event 123
138 stop mask warn SIG124     Real-time event 124
139 stop mask warn SIG125     Real-time event 125
140 stop mask warn SIG126     Real-time event 126
141 stop mask warn SIG127     Real-time event 127
142 stop mask warn SIGINFO    Information request
145 stop mask warn EXC_BAD_ACCESS       Could not access memory
146 stop mask warn EXC_BAD_INSTRUCTION  Illegal instruction/operand
147 stop mask warn EXC_ARITHMETIC       Arithmetic exception
148 stop mask warn EXC_EMULATION        Emulation instruction
149 stop mask warn EXC_SOFTWARE         Software generated exception
150 stop mask warn EXC_BREAKPOINT       Breakpoint
151 stop mask warn SIGLIBRT   librt internal signal

.dalvik
1 nostop mask warn java.lang.Throwable The superclass of all errors and exceptions in the Java language

```
