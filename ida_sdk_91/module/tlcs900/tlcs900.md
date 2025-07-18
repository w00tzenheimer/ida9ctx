```ini
; The format of the input file:
; each device definition begins with a line like this:
;
;       .devicename
;
;  after it go the port definitions in this format:
;
;       portname        address
;
;  the bit definitions (optional) are represented like this:
;
;       portname.bitname  bitnumber
;
; lines beginning with a space are ignored.
; comment lines should be started with ';' character.
;
; the default device is specified at the start of the file
;
;       .default device_name
;
; all lines non conforming to the format are passed to the callback function
;
; Toshiba TLCS900 SPECIFIC LINES
;------------------------
;
; the processor definition may include the memory configuration.
; the line format is:

;       area CLASS AREA-NAME START:END
;
; where CLASS is anything, but please use one of CODE, DATA, BSS
;       START and END are addresses, the end address is not included

; Interrupt vectors are declared in the following way:

; entry NAME ADDRESS COMMENT

.default TMP93CS42A


.TMP93CS42A

; MEMORY MAP
area DATA FSR   0x0000:0x0080   Special Function Register
area DATA IRAM  0x0080:0x0880   Internal High-Speed RAM
area CODE IROM  0x8000:0x10000  Internal ROM    

; Interrupt and reset vector assignments
interrupt RESET_        0x8000   RESET
interrupt SWI1_         0x8004   SWI1
interrupt SWI2_         0x8008   SWI2
interrupt SWI3_         0x800C   SWI3
interrupt SWI4_         0x8010   SWI4
interrupt SWI5_         0x8014   SWI5
interrupt SWI6_         0x8018   SWI6
interrupt SWI7_         0x801C   SWI7
interrupt NMI_          0x8020   NMI
interrupt INTWD_        0x8024   INTWD
interrupt INT0_         0x8028   INT0
interrupt INT4_         0x802C   INT4
interrupt INT5_         0x8030   INT5
interrupt INT6_         0x8034   INT6
interrupt INT7_         0x8038   INT7
interrupt INTT0_        0x8040   INTT0
interrupt INTT1_        0x8044   INTT1
interrupt INT8_         0x8048   INT8
interrupt INT9_         0x804C   INT9
interrupt INTR4_        0x8050   INTR4
interrupt INTR5_        0x8054   INTR5
interrupt INTR6_        0x8058   INTR6
interrupt INTR7_        0x805C   INTR7
interrupt INTRX0_       0x8060   INTRX0
interrupt INTTX0_       0x8064   INTTX0
interrupt INTRX1_       0x8068   INTRX1
interrupt INTTX1_       0x806C   INTTX1
interrupt INTAD_        0x8070   INTAD


; INPUT/OUTPUT
P0              0x00    Port 0
P1              0x01    Port 1
P0CR            0x02    Port 0 Control
P1CR            0x04    Port 1 Control
P1FC            0x05    Port 1 Function
P2              0x06    Port 2
P3              0x07    Port 3
P2CR            0x08    Port 2 Control
P2FC            0x09    Port 2 Function
P3CR            0x0A    Port 3 Control
P3FC            0x0B    Port 3 Function
P4              0x0C    Port 4
P5              0x0D    Port 5
P4CR            0x0E    Port 4 Control
P4FC            0x10    Port 4 Function
P6              0x12    Port 6
P7              0x13    Port 7
P6CR            0x14    Port 6 Control
P7CR            0x15    Port 7 Control
P6FC            0x16    Port 6 Function
P7FC            0x17    Port 7 Function
P8              0x18    Port 8
P9              0x19    Port 9
P8CR            0x1A    Port 8 Control
P9CR            0x1B    Port 9 Control
P8FC            0x1C    Port 8 Function
P9FC            0x1D    Port 9 Function
PA              0x1E    Port A
PACR            0x1F    Port A Control
TRUN            0x20    Timer Control
TREG0           0x22    Timer Register 0
TREG1           0x23    Timer Register 1
TMOD            0x24    Timer Source CLK & MODE
TFFCR           0x25    Flip-Flop Control
TREG2           0x26    Timer Register 2
TREG3           0x27    Timer Register 3
P0MOD           0x28    PWM0 Mode
P1MOD           0x29    PWM1 Mode
PFFCR           0x2A    PWM Flip-Flop Control
TREG4L          0x30    Timer Register 4 Low
TREG4H          0x31    Timer Register 4 High
TREG5L          0x32    Timer Register 5 Low
TREG5H          0x33    Timer Register 5 High
CAP1L           0x34    Capture Register 1 Low
CAP1H           0x35    Capture Register 1 High
CAP2L           0x36    Capture Register 2 Low
CAP2H           0x37    Capture Register 2 High
T4MOD           0x38    Timer 4 Source CLK & Mode
T4FFCR          0x39    Timer 4 Flip-Flop Control
T45CR           0x3A    T4, T5 Control
TREG6L          0x40    Timer Register 6 Low
TREG6H          0x41    Timer Register 6 High
TREG7L          0x42    Timer Register 7 Low
TREG7H          0x43    Timer Register 7 High
CAP3L           0x44    Capture Register 3 Low
CAP3H           0x45    Capture REgister 3 High
CAP4L           0x46    Capture Register 4 Low
CAP4H           0x47    Capture Register 4 High
T5MOD           0x48    Timer 5 Source CLK & Mode
T5FFCR          0x49    Timer 5 Flip-Flip Control
SC0BUF          0x50    Serial Chanel 0 Buffer
SC0CR           0x51    Serial Chanel 0 Control
SC0MOD          0x52    Serial Chanel 0 Mode
BR0CR           0x53    Serial Chanel 0 Baud Rate
SC1BUF          0x54    Serial Chanel 1 Buffer
SC1CR           0x55    Serial Chanel 1 Control
SC1MOD          0x56    Serial Chanel 1 Mode
BR1CR           0x57    Serial Chanel 1 Baud Rate
ODE             0x58    Serial Open Drain Enable
WDMOD           0x5C    Watch Dog Timer Mode
WDCR            0x5D    Watch Dog Control Register
ADMOD1          0x5E    A/D Mode Register 1
ADMOD2          0x5F    A/D Mode Register 2
ADREG04L        0x60    A/D Result Register 0/4 Low
ADREG04H        0x61    A/D Result Register 0/4 High
ADREG15L        0x62    A/D Result Register 1 Low
ADREG15H        0x63    A/D Result Register 1 High
ADREG26L        0x64    A/D Result Register 2 Low
ADREG26H        0x65    A/D Result Register 2 High
ADREG37L        0x66    A/D Result Register 3 Low
ADREG37H        0x67    A/D Result Register 3 High
B0CS            0x68    Block 0 CS/WAIT Control Register
B1CS            0x69    Block 1 CS/WAIT Control Register
B2CS            0x6A    Block 2 CS/WAIT Control Register
CKOCR           0x6D    Clock Output Control Register
SYSCR0          0x6E    System Clock Register 0
SYSCR1          0x6F    System Clock Contol Register 1
INTE0AD         0x70    Interrupt Enable 0 & A/D
INTE45          0x71    Interrupt Enable 4/5
INTE67          0x72    Interrupt Enable 6/7
INTET10         0x73    Interrupt Enable Timer 1/0
INTE89          0x74    Interrupt Enable 8/9
INTET54         0x75    Interrupt Enable 5/4
INTET76         0x76    Interrupt Enable 7/6
INTES0          0x77    Interrupt Enable Serial 0
INTES1          0x78    Interrupt Enable Serial 1
IIMC            0x7B    Interrupt Input Mode Control
DMA0V           0x7C    DMA 0 Reauest Vector
DMA1V           0x7D    DMA 1 Request Vector
DMA2V           0x7E    DMA 2 Request Vector
DMA3V           0x7F    DMA 3 Request Vector



.TMP94CS40A

; MEMORY MAP
area DATA FSR   0x000000:0x000170       Special Function Register
area DATA IRAM  0x000400:0x000C00       Internal High-Speed RAM
area CODE IROM  0xFF0000:0x100000       Internal ROM    

; Interrupt and reset vector assignments
interrupt RESET_        0xFFFF00   RESET
interrupt SWI1_         0xFFFF04   SWI1
interrupt SWI2_         0xFFFF08   SWI2
interrupt SWI3_         0xFFFF0C   SWI3
interrupt SWI4_         0xFFFF10   SWI4
interrupt SWI5_         0xFFFF14   SWI5
interrupt SWI6_         0xFFFF18   SWI6
interrupt SWI7_         0xFFFF1C   SWI7
interrupt NMI_          0xFFFF20   NMI
interrupt INTWD_        0xFFFF24   Watch-dog Timer
interrupt INT0_         0xFFFF28   INT0
interrupt INT4_         0xFFFF2C   INT4
interrupt INT5_         0xFFFF30   INT5
interrupt INT6_         0xFFFF34   INT6
interrupt INT7_         0xFFFF38   INT7
interrupt INT8_         0xFFFF40   INT8
interrupt INT9_         0xFFFF44   INT9
interrupt INTA_         0xFFFF48   INTA
interrupt INTB_         0xFFFF4C   INTB
interrupt INTT0_        0xFFFF50   INTT0
interrupt INTT1_        0xFFFF54   INTT1
interrupt INTT2_        0xFFFF58   INTT2
interrupt INTT3_        0xFFFF5C   INTT3
interrupt INTTR4_       0xFFFF60   16-bit timer 4
interrupt INTTR5_       0xFFFF64   16-bit timer 5
interrupt INTTR6_       0xFFFF68   16-bit timer 6
interrupt INTTR7_       0xFFFF6C   16-bit timer 7
interrupt INTTR8_       0xFFFF70   16-bit timer 8
interrupt INTTR9_       0xFFFF74   16-bit timer 9
interrupt INTTRA_       0xFFFF78   16-bit timer A
interrupt INTTRB_       0xFFFF7C   16-bit timer B
interrupt INTRX0_       0xFFFF80   Serial RX 0
interrupt INTTX0_       0xFFFF84   Serial Tx 0
interrupt INTRX1_       0xFFFF88   Serial RX 1
interrupt INTTX1_       0xFFFF8C   Serial TX 1
interrupt INTAD_        0xFFFF90   AD conversion complete
interrupt INTTC0_       0xFFFF94   Micro DMA completion Ch.0
interrupt INTTC1_       0xFFFF98   Micro DMA completion Ch.1
interrupt INTTC2_       0xFFFF9C   Micro DMA completion Ch.2
interrupt INTTC3_       0xFFFFA0   Micro DMA completion Ch.3
interrupt INTTC4_       0xFFFFA4   Micro DMA completion Ch.4
interrupt INTTC5_       0xFFFFA8   Micro DMA completion Ch.5
interrupt INTTC6_       0xFFFFAC   Micro DMA completion Ch.6
interrupt INTTC7_       0xFFFFB0   Micro DMA completion Ch.7

; INPUT/OUPUT
; Warning - only i/o port register, not all!!!
P0              0x00    Port 0
P0CR            0x02    Port 0 Control
P0FC            0x03    Port 0 Function
P1              0x04    Port 1
P1CR            0x06    Port 1 Control
P1FC            0x07    Port 1 Function
P2              0x08    Port 2
P2CR            0x0A    Port 2 Control
P2FC            0x0B    Port 2 Function
P3              0x0C    Port 3
P3CR            0x0E    Port 3 Control
P3FC            0x0F    Port 3 Function
P4              0x10    Port 4
P4CR            0x12    Port 4 Control
P4FC            0x13    Port 4 Function
P5              0x14    Port 5
P5CR            0x16    Port 4 Control
P5FC            0x17    Port 4 Function
P6              0x18    Port 6
P6CR            0x1A    Port 6 Control
P6FC            0x1B    Port 6 Function
P7              0x1C    Port 7
P7CR            0x1E    Port 7 Control
P7FC            0x1F    Port 7 Function
P8              0x20    Port 8
P8CR            0x22    Port 8 Control
P8FC            0x23    Port 8 Function
PA              0x28    Port A
PAFC            0x2B    Port A Function
PB              0x2C    Port B
PBFC            0x2F    Port B Function
PC              0x30    Port C
PCCR            0x32    Port C Control
PCFC            0x33    Port C Function
PD              0x34    Port D
PDCR            0x36    Port D Control
PDFC            0x37    Port D Function
PE              0x38    Port E
PECR            0x3A    Port E Control
PEFC            0x3B    Port E Function
PF              0x3C    Port F
PFCR            0x3E    Port F Control
PFFC            0x3F    Port F Function
PG              0x40    Port G
PH              0x44    Port H
PHCR            0x46    Port H Control
PHFC            0x47    Port H Function
PZ              0x68    Port Z
PZCR            0x6A    Port Z Control

```
