```ini
;
; This file defines SFR names and bit names for Fujitsu's F2MC16L processors.
;
; This file can be configured for different devices.
; At the beginning of the file there are definitions common for all devices
; Device-specific definitions are introduced by
;
;       .devicename
;
; line. Also an optional directive
;
;       .default=devicename
;
; designates the default device name.
;

.default MB90610A

;-------------------------------
; Device specific definitions


.MB90610A
; DS07-13603-5E  http://edevice.fujitsu.com/fj/DATASHEET/e-ds/e713603.pdf
; MB90611A/MB90613A


; RAM: 1 Kbytes (MB90611A)
;      3 Kbytes (MB90613A)


; MEMORY MAP
; [MB90611A]
area DATA FSR         0x000000:0x0000C0
area DATA MEM_EXT_1   0x0000C0:0x000100
area DATA MEM_INT_1   0x000100:0x000180
area DATA RAM         0x000180:0x000380
area DATA MEM_INT_2   0x000380:0x000500
area BSS  No_access   0x000500:0x002000
area DATA MEM_EXT_2   0x002000:0x1000000

; [MB90613A]
; area DATA FSR         0x000000:0x0000C0
; area DATA MEM_EXT_1   0x0000C0:0x000100
; area DATA MEM_INT_1   0x000100:0x000180
; area DATA RAM         0x000180:0x000380
; area DATA MEM_INT_2   0x000380:0x000D00
; area BSS  No_access   0x000D00:0x002000
; area DATA MEM_EXT_2   0x002000:0x1000000


; Interrupt and reset vector assignments
interrupt __RESET       0xFFFFDC       Reset 
interrupt INT_9         0xFFFFD8       INT 9 instruction 
interrupt EXCEPT        0xFFFFD4       Exception 
interrupt EI_0          0xFFFFD0       External interrupt 0 
interrupt EI_1          0xFFFFC8       External interrupt 1 
interrupt EI_2          0xFFFFC0       External interrupt 2 
interrupt EI_3          0xFFFFB8       External interrupt 3 
interrupt EI_4          0xFFFFB0       External interrupt 4 
interrupt EI_5          0xFFFFA8       External interrupt 5 
interrupt EI_6          0xFFFFA0       External interrupt 6 
interrupt UART0_T       0xFFFF9C       UART0 - transmit complete 
interrupt EI_7          0xFFFF98       External interrupt 7 
interrupt UART1_T       0xFFFF94       UART1 - transmit complete 
interrupt PPG_0         0xFFFF90       PPG 0 
interrupt PPG_1         0xFFFF8C       PPG 1 
interrupt RTIMER0       0xFFFF88       16-bit reload timer 
interrupt RTIMER1       0xFFFF84       16-bit reload timer 
interrupt A_DC          0xFFFF80       A/DC measurement complete 
interrupt UART2_T       0xFFFF78       UART2 - transmit complete 
interrupt TTI           0xFFFF74       Timebase timer interval interrupt 
interrupt UART2_R       0xFFFF70       UART2 - receive complete 
interrupt UART1_R       0xFFFF68       UART1 - receive complete 
interrupt UART0_R       0xFFFF60       UART0 - receive complete 


; INPUT/OUTPUT PORTS
PDR1        0x000001            Port 1 data register
PDR1.PD17             7
PDR1.PD16             6
PDR1.PD15             5
PDR1.PD14             4
PDR1.PD13             3
PDR1.PD12             2
PDR1.PD11             1
PDR1.PD10             0
PDR2        0x000002            Port 2 data register
PDR2.PD27             7
PDR2.PD26             6
PDR2.PD25             5
PDR2.PD24             4
PDR2.PD23             3
PDR2.PD22             2
PDR2.PD21             1
PDR2.PD20             0
PDR3        0x000003            Port 3 data register
PDR3.PD37             7
PDR3.PD36             6
PDR3.PD35             5
PDR3.PD34             4
PDR3.PD33             3
PDR3.PD32             2
PDR3.PD31             1
PDR3.PD30             0
PDR4        0x000004            Port 4 data register
PDR4.PD47             7
PDR4.PD46             6
PDR4.PD45             5
PDR4.PD44             4
PDR4.PD43             3
PDR4.PD42             2
PDR4.PD41             1
PDR4.PD40             0
PDR5        0x000005            Port 5 data register
PDR5.PD57             7
PDR5.PD56             6
PDR5.PD55             5
PDR5.PD54             4
PDR5.PD53             3
PDR5.PD52             2
PDR5.PD51             1
PDR5.PD50             0
PDR6        0x000006            Port 6 data register
PDR6.PD67             7
PDR6.PD66             6
PDR6.PD65             5
PDR6.PD64             4
PDR6.PD63             3
PDR6.PD62             2
PDR6.PD61             1
PDR6.PD60             0
PDR7        0x000007            Port 7 data register
PDR7.PD77             7
PDR7.PD76             6
PDR7.PD75             5
PDR7.PD74             4
PDR7.PD73             3
PDR7.PD72             2
PDR7.PD71             1
PDR7.PD70             0
PDR8        0x000008            Port 8 data register
PDR8.PD87             7
PDR8.PD86             6
PDR8.PD85             5
PDR8.PD84             4
PDR8.PD83             3
PDR8.PD82             2
PDR8.PD81             1
PDR8.PD80             0
PDR9        0x000009            Port 9 data register
PDR9.PD97             7
PDR9.PD96             6
PDR9.PD95             5
PDR9.PD94             4
PDR9.PD93             3
PDR9.PD92             2
PDR9.PD91             1
PDR9.PD90             0
PDRA        0x00000A            Port A data register
PDRA.PDA7             7
PDRA.PDA6             6
PDRA.PDA5             5
PDRA.PDA4             4
PDRA.PDA3             3
PDRA.PDA2             2
PDRA.PDA1             1
DDR1        0x000011            Port 1 direction register
DDR1.DD17             7
DDR1.DD16             6
DDR1.DD15             5
DDR1.DD14             4
DDR1.DD13             3
DDR1.DD12             2
DDR1.DD11             1
DDR1.DD10             0
DDR2        0x000012            Port 2 direction register
DDR2.DD27             7
DDR2.DD26             6
DDR2.DD25             5
DDR2.DD24             4
DDR2.DD23             3
DDR2.DD22             2
DDR2.DD21             1
DDR2.DD20             0
DDR3        0x000013            Port 3 direction register
DDR3.DD37             7
DDR3.DD36             6
DDR3.DD35             5
DDR3.DD34             4
DDR3.DD33             3
DDR3.DD32             2
DDR3.DD31             1
DDR3.DD30             0
DDR4        0x000014            Port 4 direction register
DDR4.DD47             7
DDR4.DD46             6
DDR4.DD45             5
DDR4.DD44             4
DDR4.DD43             3
DDR4.DD42             2
DDR4.DD41             1
DDR4.DD40             0
DDR5        0x000015            Port 5 direction register
DDR5.DD57             7
DDR5.DD56             6
DDR5.DD55             5
DDR5.DD54             4
DDR5.DD53             3
DDR5.DD52             2
DDR5.DD51             1
DDR5.DD50             0
ADER        0x000016            Analog input enable register
ADER.ADE7             7
ADER.ADE6             6
ADER.ADE5             5
ADER.ADE4             4
ADER.ADE3             3
ADER.ADE2             2
ADER.ADE1             1
ADER.ADE0             0
DDR7        0x000017            Port 7 direction register
DDR7.DD76             6
DDR7.DD75             5
DDR7.DD74             4
DDR7.DD73             3
DDR7.DD72             2
DDR7.DD71             1
DDR7.DD70             0
DDR8        0x000018            Port 8 direction register
DDR8.DD86             6
DDR8.DD85             5
DDR8.DD84             4
DDR8.DD83             3
DDR8.DD82             2
DDR8.DD81             1
DDR8.DD80             0
DDR9        0x000019            Port 9 direction register
DDR9.DD95             5
DDR9.DD94             4
DDR9.DD93             3
DDR9.DD92             2
DDR9.DD91             1
DDR9.DD90             0
DDRA        0x00001A            Port A direction register
DDRA.DDA7             7
DDRA.DDA6             6
DDRA.DDA5             5
DDRA.DDA4             4
DDRA.DDA3             3
DDRA.DDA2             2
DDRA.DDA1             1
SMR0        0x000020            Serial mode register 0
SMR0.MD1              7
SMR0.MD0              6
SMR0.CS2              5
SMR0.CS1              4
SMR0.CS0              3
SMR0.SCKE             1
SMR0.SOE              0
SCR0        0x000021            Serial control register 0
SCR0.PEN              7
SCR0.P                6
SCR0.SBL              5
SCR0.CL               4
SCR0.AD               3
SCR0.REC              2
SCR0.RXE              1
SCR0.TXE              0
SIDR0       0x000022            Serial input data register 0 / Serial output data register 0
SIDR0.D7              7
SIDR0.D6              6
SIDR0.D5              5
SIDR0.D4              4
SIDR0.D3              3
SIDR0.D2              2
SIDR0.D1              1
SIDR0.D0              0
SSR0        0x000023            Serial status register 0
SSR0.PE               7
SSR0.ORE              6
SSR0.FRE              5
SSR0.RDRF             4
SSR0.TDRE             3
SSR0.RIE              1
SSR0.TIE              0
SMR1        0x000024            Serial mode register 1
SMR1.MD1              7
SMR1.MD0              6
SMR1.CS2              5
SMR1.CS1              4
SMR1.CS0              3
SMR1.SCKE             1
SMR1.SOE              0
SCR1        0x000025            Serial control register 1
SCR1.PEN              7
SCR1.P                6
SCR1.SBL              5
SCR1.CL               4
SCR1.AD               3
SCR1.REC              2
SCR1.RXE              1
SCR1.TXE              0
SIDR1       0x000026            Serial input data register 1 / Serial output data register 1
SIDR1.D7              7
SIDR1.D6              6
SIDR1.D5              5
SIDR1.D4              4
SIDR1.D3              3
SIDR1.D2              2
SIDR1.D1              1
SIDR1.D0              0
SSR1        0x000027            Serial status register 1
SSR1.PE               7
SSR1.ORE              6
SSR1.FRE              5
SSR1.RDRF             4
SSR1.TDRE             3
SSR1.RIE              1
SSR1.TIE              0
ENIR        0x000028            Interrupt/DTP enable register
ENIR.EN7              7
ENIR.EN6              6
ENIR.EN5              5
ENIR.EN4              4
ENIR.EN3              3
ENIR.EN2              2
ENIR.EN1              1
ENIR.EN0              0
EIRR        0x000029            Interrupt/DTP request register
EIRR.ER7              7
EIRR.ER6              6
EIRR.ER5              5
EIRR.ER4              4
EIRR.ER3              3
EIRR.ER2              2
EIRR.ER1              1
EIRR.ER0              0
ELVR        0x00002A            Interrupt level setting register
ELVR.LALB71           15
ELVR.LALB70           14
ELVR.LALB61           13
ELVR.LALB60           12
ELVR.LALB51           11
ELVR.LALB50           10
ELVR.LALB41           9
ELVR.LALB40           8
ELVR.LALB31           7
ELVR.LALB30           6
ELVR.LALB21           5
ELVR.LALB20           4
ELVR.LALB11           3
ELVR.LALB10           2
ELVR.LALB01           1
ELVR.LALB00           0
ADCS1       0x00002C            AD control status register
ADCS1.MD1             7
ADCS1.MD0             6
ADCS1.ANS2            5
ADCS1.ANS1            4
ADCS1.ANS0            3
ADCS1.ANE2            2
ADCS1.ANE1            1
ADCS1.ANE0            0
ADCS2       0x00002D            AD control status register
ADCS2.BUSY            7
ADCS2.INT             6
ADCS2.INTE            5
ADCS2.PAUS            4
ADCS2.STS1            3
ADCS2.STS0            2
ADCS2.STRT            1
ADCR12      0x00002E            AD data register
ADCR12.S10            15
ADCR12.D9             9
ADCR12.D8             8
ADCR12.D7             7
ADCR12.D6             6
ADCR12.D5             5
ADCR12.D4             4
ADCR12.D3             3
ADCR12.D2             2
ADCR12.D1             1
ADCR12.D0             0
PPGC01      0x000030            PPG0 operation mode control register
PPGC01.PEN1           15
PPGC01.PCS1           14
PPGC01.PE10           13
PPGC01.PIE1           12
PPGC01.PUF1           11
PPGC01.MD1            10
PPGC01.MD0            9
PPGC01.PEN0           7
PPGC01.PE00           5
PPGC01.PIE0           4
PPGC01.PUF0           3
PPGC01.PCM1           2
PPGC01.PCM0           1
PRL0_PRLL   0x000034            PPG0 reload register
PRL0_PRLH   0x000035            PPG0 reload register
PRL1_PRLL   0x000036            PPG1 reload register
PRL1_PRLH   0x000037            PPG1 reload register
TMCSR0      0x000038            Control status register
TMCSR0.CSL1           11
TMCSR0.CSL0           10
TMCSR0.MOD2           9
TMCSR0.MOD1           8
TMCSR0.MOD0           7
TMCSR0.OUTE           6
TMCSR0.OUTL           5
TMCSR0.RELD           4
TMCSR0.INTE           3
TMCSR0.UF             2
TMCSR0.CNTE           1
TMCSR0.TRG            0
TMR0        0x00003A            16-bit timer register / 16-bit reload register
TMCSR1      0x00003C            Control status register
TMCSR1.CSL1           11
TMCSR1.CSL0           10
TMCSR1.MOD2           9
TMCSR1.MOD1           8
TMCSR1.MOD0           7
TMCSR1.OUTE           6
TMCSR1.OUTL           5
TMCSR1.RELD           4
TMCSR1.INTE           3
TMCSR1.UF             2
TMCSR1.CNTE           1
TMCSR1.TRG            0
TMR1        0x00003E            16-bit timer register / 16-bit reload register
SMR2        0x000044            Serial mode register 2
SMR2.MD1              7
SMR2.MD0              6
SMR2.CS2              5
SMR2.CS1              4
SMR2.CS0              3
SMR2.SCKE             1
SMR2.SOE              0
SCR2        0x000045            Serial control register 2
SCR2.PEN              7
SCR2.P                6
SCR2.SBL              5
SCR2.CL               4
SCR2.AD               3
SCR2.REC              2
SCR2.RXE              1
SCR2.TXE              0
SIDR2       0x000046            Serial input data register 2 / Serial output data register 2
SIDR2.D7              7
SIDR2.D6              6
SIDR2.D5              5
SIDR2.D4              4
SIDR2.D3              3
SIDR2.D2              2
SIDR2.D1              1
SIDR2.D0              0
SSR2        0x000047            Serial status register 2
SSR2.PE               7
SSR2.ORE              6
SSR2.FRE              5
SSR2.RDRF             4
SSR2.TDRE             3
SSR2.RIE              1
SSR2.TIE              0
CSCR0       0x000048            CS control register 0
CSCR0.ACTL            3
CSCR0.OPEL            2
CSCR0.CSA1            1
CSCR0.CSA0            0
CSCR1       0x000049            CS control register 1
CSCR1.ACTL            3
CSCR1.OPEL            2
CSCR1.CSA1            1
CSCR1.CSA0            0
CSCR2       0x00004A            CS control register 2
CSCR2.ACTL            3
CSCR2.OPEL            2
CSCR2.CSA1            1
CSCR2.CSA0            0
CSCR3       0x00004B            CS control register 3
CSCR3.ACTL            3
CSCR3.OPEL            2
CSCR3.CSA1            1
CSCR3.CSA0            0
CSCR4       0x00004C            CS control register 4
CSCR4.ACTL            3
CSCR4.OPEL            2
CSCR4.CSA1            1
CSCR4.CSA0            0
CSCR5       0x00004D            CS control register 5
CSCR5.ACTL            3
CSCR5.OPEL            2
CSCR5.CSA1            1
CSCR5.CSA0            0
CSCR6       0x00004E            CS control register 6
CSCR6.ACTL            3
CSCR6.OPEL            2
CSCR6.CSA1            1
CSCR6.CSA0            0
CSCR7       0x00004F            CS control register 7
CSCR7.ACTL            3
CSCR7.OPEL            2
CSCR7.CSA1            1
CSCR7.CSA0            0
CDCR0       0x000051            UART0 (SCI) machine clock division control register
CDCR0.DIV3            3
CDCR0.DIV2            2
CDCR0.DIV1            1
CDCR0.DIV0            0
CDCR1       0x000053            UART1 (SCI) machine clock division control register
CDCR1.DIV3            3
CDCR1.DIV2            2
CDCR1.DIV1            1
CDCR1.DIV0            0
CDCR2       0x000055            UART2 (SCI) machine clock division control register
CDCR2.DIV3            3
CDCR2.DIV2            2
CDCR2.DIV1            1
CDCR2.DIV0            0
DIRR        0x00009F            Delayed interrupt generate / release register
DIRR.R0               0
LPMCR       0x0000A0            Low power consumption mode control register
LPMCR.STP             7
LPMCR.SLP             6
LPMCR.SPL             5
LPMCR.RST             4
LPMCR.CG1             2
LPMCR.CG0             1
CKSCR       0x0000A1            Clock selection register
CKSCR.MCM             6
CKSCR.WS1             5
CKSCR.WS0             4
CKSCR.MCS             2
CKSCR.CS1             1
CKSCR.CS0             0
ARSR        0x0000A5            Auto-ready function selection register
HACR        0x0000A6            External address output control register
EPCR        0x0000A7            Bus control signal selection register
WDTC        0x0000A8            Watchdog timer control register
WDTC.PONR             7
WDTC.STBR             6
WDTC.WRST             5
WDTC.ERST             4
WDTC.SRST             3
TBTC        0x0000A9            Timebase timer control register
TBTC.TBIE             4
TBTC.TBOF             3
TBTC.TBR              2
TBTC.TBC1             1
TBTC.TBC0             0
ICR00       0x0000B0            Interrupt control register 00
ICR00.S1              5
ICR00.S0              4
ICR00.ISE             3
ICR00.IL2             2
ICR00.IL1             1
ICR00.IL0             0
ICR01       0x0000B1            Interrupt control register 01
ICR01.S1              5
ICR01.S0              4
ICR01.ISE             3
ICR01.IL2             2
ICR01.IL1             1
ICR01.IL0             0
ICR02       0x0000B2            Interrupt control register 02
ICR02.S1              5
ICR02.S0              4
ICR02.ISE             3
ICR02.IL2             2
ICR02.IL1             1
ICR02.IL0             0
ICR03       0x0000B3            Interrupt control register 03
ICR03.S1              5
ICR03.S0              4
ICR03.ISE             3
ICR03.IL2             2
ICR03.IL1             1
ICR03.IL0             0
ICR04       0x0000B4            Interrupt control register 04
ICR04.S1              5
ICR04.S0              4
ICR04.ISE             3
ICR04.IL2             2
ICR04.IL1             1
ICR04.IL0             0
ICR05       0x0000B5            Interrupt control register 05
ICR05.S1              5
ICR05.S0              4
ICR05.ISE             3
ICR05.IL2             2
ICR05.IL1             1
ICR05.IL0             0
ICR06       0x0000B6            Interrupt control register 06
ICR06.S1              5
ICR06.S0              4
ICR06.ISE             3
ICR06.IL2             2
ICR06.IL1             1
ICR06.IL0             0
ICR07       0x0000B7            Interrupt control register 07
ICR07.S1              5
ICR07.S0              4
ICR07.ISE             3
ICR07.IL2             2
ICR07.IL1             1
ICR07.IL0             0
ICR08       0x0000B8            Interrupt control register 08
ICR08.S1              5
ICR08.S0              4
ICR08.ISE             3
ICR08.IL2             2
ICR08.IL1             1
ICR08.IL0             0
ICR09       0x0000B9            Interrupt control register 09
ICR09.S1              5
ICR09.S0              4
ICR09.ISE             3
ICR09.IL2             2
ICR09.IL1             1
ICR09.IL0             0
ICR10       0x0000BA            Interrupt control register 10
ICR10.S1              5
ICR10.S0              4
ICR10.ISE             3
ICR10.IL2             2
ICR10.IL1             1
ICR10.IL0             0
ICR11       0x0000BB            Interrupt control register 11
ICR11.S1              5
ICR11.S0              4
ICR11.ISE             3
ICR11.IL2             2
ICR11.IL1             1
ICR11.IL0             0
ICR12       0x0000BC            Interrupt control register 12
ICR12.S1              5
ICR12.S0              4
ICR12.ISE             3
ICR12.IL2             2
ICR12.IL1             1
ICR12.IL0             0
ICR13       0x0000BD            Interrupt control register 13
ICR13.S1              5
ICR13.S0              4
ICR13.ISE             3
ICR13.IL2             2
ICR13.IL1             1
ICR13.IL0             0
ICR14       0x0000BE            Interrupt control register 14
ICR14.S1              5
ICR14.S0              4
ICR14.ISE             3
ICR14.IL2             2
ICR14.IL1             1
ICR14.IL0             0
ICR15       0x0000BF            Interrupt control register 15
ICR15.S1              5
ICR15.S0              4
ICR15.ISE             3
ICR15.IL2             2
ICR15.IL1             1
ICR15.IL0             0



.MB90620A
; DS07-13606-1E  http://edevice.fujitsu.com/fj/DATASHEET/e-ds/e713606.pdf
; MB90622A/623A/P623A


; ROM:           32 Kbytes (MB90622A)
;                48 Kbytes (MB90623A)
; One-time PROM: 48 Kbytes (MB90P623A)
; RAM:         1.64 Kbytes (MB90622A)
;                 2 Kbytes (MB90623A/P623A)


; MEMORY MAP
; [MB90622A]
area DATA FSR           0x000000:0x0000C0
area BSS  No_access_1   0x0000C0:0x000100
area DATA RAM           0x000100:0x000780
area BSS  No_access_2   0x000780:0x008000
area DATA ROM_1         0x008000:0x010000
area BSS  No_access_3   0x010000:0xFF8000
; area DATA ROM_2_BANK_FF 0xFF8000:0x1000000

; [MB90623A/MB90P623A]
; area DATA FSR           0x000000:0x0000C0
; area BSS  No_access_1   0x0000C0:0x000100
; area DATA RAM           0x000100:0x000900
; area BSS  No_access_2   0x000900:0x004000
; area DATA ROM_1         0x004000:0x010000
; area BSS  No_access_3   0x010000:0xFF4000
; area DATA ROM_2_BANK_FF 0xFF4000:0x1000000


; Interrupt and reset vector assignments
interrupt __RESET       0xFFFFDC       Reset 
interrupt INT9          0xFFFFD8       INT9 instruction 
interrupt EXCEPT        0xFFFFD4       Exception 
interrupt EI_0          0xFFFFD0       External interrupt 0 
interrupt EI_1          0xFFFFCC       External interrupt 1 
interrupt EI_2          0xFFFFC8       External interrupt 2 
interrupt EI_3          0xFFFFC4       External interrupt 3 
interrupt EI_4          0xFFFFC0       External interrupt 4 
interrupt EI_5          0xFFFFBC       External interrupt 5 
interrupt EI_6          0xFFFFB8       External interrupt 6 
interrupt EI_7          0xFFFFB4       External interrupt 7 
interrupt ESIOI         0xFFFFB0       Extended serial I/O interface 
interrupt FT0O          0xFFFFA8       Free-run timer 0 overflow 
interrupt FT1O          0xFFFFA4       Free-run timer 1 overflow 
interrupt FT0O_CR0      0xFFFFA0       Free-run timer 0 and compare register 0 matched 
interrupt FT0O_CR1      0xFFFF9C       Free-run timer 0 and compare register 1 matched 
interrupt FT1O_CR0      0xFFFF98       Free-run timer 1 and compare register 0 matched 
interrupt FT1O_CR1      0xFFFF94       Free-run timer 1 and compare register 1 matched 
interrupt PPG_T0        0xFFFF90       PPG timer 0 
interrupt PPG_T1        0xFFFF8C       PPG timer 1 
interrupt RTIMER0       0xFFFF88       16-bit reload timer 0 
interrupt RTIMER1       0xFFFF84       16-bit reload timer 1 
interrupt RTIMER2       0xFFFF80       16-bit reload timer 2 
interrupt A_D_CMC       0xFFFF78       A/D converter measurement complete 
interrupt WATCH         0xFFFF70       Watch prescaler 
interrupt TTII          0xFFFF6C       Timebase timer interval interrupt 
interrupt UART_0        0xFFFF68       UART 0 transmission complete 
interrupt UART_1        0xFFFF60       UART 1 reception complete 
interrupt DIGM          0xFFFF54       Delayed interrupt generation module 

      
; INPUT/OUTPUT PORTS
PDR1        0x000001            Port 1 data register
PDR1.PD17             7
PDR1.PD16             6
PDR1.PD15             5
PDR1.PD14             4
PDR1.PD13             3
PDR1.PD12             2
PDR1.PD11             1
PDR1.PD10             0
PDR2        0x000002            Port 2 data register
PDR2.PD27             7
PDR2.PD26             6
PDR2.PD25             5
PDR2.PD24             4
PDR2.PD23             3
PDR2.PD22             2
PDR2.PD21             1
PDR2.PD20             0
PDR3        0x000003            Port 3 data register
PDR3.PD37             7
PDR3.PD36             6
PDR3.PD35             5
PDR3.PD34             4
PDR3.PD33             3
PDR3.PD32             2
PDR3.PD31             1
PDR3.PD30             0
PDR4        0x000004            Port 4 data register
PDR4.PD47             7
PDR4.PD46             6
PDR4.PD45             5
PDR4.PD44             4
PDR4.PD43             3
PDR4.PD42             2
PDR4.PD41             1
PDR4.PD40             0
PDR5        0x000005            Port 5 data register
PDR5.PD57             7
PDR5.PD56             6
PDR5.PD55             5
PDR5.PD54             4
PDR5.PD53             3
PDR5.PD52             2
PDR5.PD51             1
PDR5.PD50             0
PDR6        0x000006            Port 6 data register
PDR6.PD67             7
PDR6.PD66             6
PDR6.PD65             5
PDR6.PD64             4
PDR6.PD63             3
PDR6.PD62             2
PDR6.PD61             1
PDR6.PD60             0
PDR7        0x000007            Port 7 data register
PDR7.PD77             7
PDR7.PD76             6
PDR7.PD75             5
PDR7.PD74             4
PDR7.PD73             3
PDR7.PD72             2
PDR7.PD71             1
PDR7.PD70             0
DDR0        0x000010            Port 0 direction register
DDR0.DD17             7
DDR0.DD16             6
DDR0.DD15             5
DDR0.DD14             4
DDR0.DD13             3
DDR0.DD12             2
DDR0.DD11             1
DDR0.DD10             0
DDR1        0x000011            Port 1 direction register
DDR1.DD17             7
DDR1.DD16             6
DDR1.DD15             5
DDR1.DD14             4
DDR1.DD13             3
DDR1.DD12             2
DDR1.DD11             1
DDR1.DD10             0
DDR2        0x000012            Port 2 direction register
DDR2.DD27             7
DDR2.DD26             6
DDR2.DD25             5
DDR2.DD24             4
DDR2.DD23             3
DDR2.DD22             2
DDR2.DD21             1
DDR2.DD20             0
DDR3        0x000013            Port 3 direction register
DDR3.DD37             7
DDR3.DD36             6
DDR3.DD35             5
DDR3.DD34             4
DDR3.DD33             3
DDR3.DD32             2
DDR3.DD31             1
DDR3.DD30             0
DDR4        0x000014            Port 4 direction register
DDR4.DD47             7
DDR4.DD46             6
DDR4.DD45             5
DDR4.DD44             4
DDR4.DD43             3
DDR4.DD42             2
DDR4.DD41             1
DDR4.DD40             0
DDR5        0x000015            Port 5 direction register
DDR5.DD57             7
DDR5.DD56             6
DDR5.DD55             5
DDR5.DD54             4
DDR5.DD53             3
DDR5.DD52             2
DDR5.DD51             1
DDR5.DD50             0
DDR6       0x000016             Port 6 direction register
DDR6.DD57             7
DDR6.DD56             6
DDR6.DD55             5
DDR6.DD54             4
DDR6.DD53             3
DDR6.DD52             2
DDR6.DD51             1
DDR6.DD50             0
DDR7        0x000017            Port 7 direction register
DDR7.DD76             6
DDR7.DD75             5
DDR7.DD74             4
DDR7.DD73             3
DDR7.DD72             2
DDR7.DD71             1
DDR7.DD70             0
RDR0        0x00001A            Port 0 pull-up resistor setting register
RDR0.RD07             7
RDR0.RD06             6
RDR0.RD05             5
RDR0.RD04             4
RDR0.RD03             3
RDR0.RD02             2
RDR0.RD01             1
RDR0.RD00             0
RDR1        0x00001B            Port 1 pull-up resistor setting register
RDR1.RD17             7
RDR1.RD16             6
RDR1.RD15             5
RDR1.RD14             4
RDR1.RD13             3
RDR1.RD12             2
RDR1.RD11             1
RDR1.RD10             0
RDR2        0x00001C            Port 2 pull-up resistor setting register
RDR2.RD27             7
RDR2.RD26             6
RDR2.RD25             5
RDR2.RD24             4
RDR2.RD23             3
RDR2.RD22             2
RDR2.RD21             1
RDR2.RD20             0
ADER        0x00001D            Analog input enable register
ADER.ADE3             3
ADER.ADE2             2
ADER.ADE1             1
ADER.ADE0             0
CKOT        0x00001E            Clock output enable register
SMR         0x000020            Serial mode register
SMR.MD1               7
SMR.MD0               6
SMR.CS2               5
SMR.CS1               4
SMR.CS0               3
SMR.SCKE              1
SMR.SOE               0
SCR         0x000021            Serial control register
SCR.PEN               7
SCR.P                 6
SCR.SBL               5
SCR.CL                4
SCR.AD                3
SCR.REC               2
SCR.RXE               1
SCR.TXE               0
SIDR        0x000022            Serial input register / Serial output register
SIDR.D6               6
SIDR.D5               5
SIDR.D4               4
SIDR.D3               3
SIDR.D2               2
SIDR.D1               1
SIDR.D0               0
SSR         0x000023            Serial status register
SSR.PE                7
SSR.ORE               6
SSR.FRE               5
SSR.RDRF              4
SSR.TDRE              3
SSR.RIE               1
SSR.TIE               0
SMCS        0x000024            Serial mode control status register
SMCS.SMD2             15
SMCS.SMD1             14
SMCS.SMD0             13
SMCS.SIE              12
SMCS.SIR              11
SMCS.BUSY             10
SMCS.STOP             9
SMCS.STRT             8
SMCS.MODE             3
SMCS.BDS              2
SMCS.SOE              1
SMCS.SCOE             0
SDR         0x000026            Serial data register
CDCR        0x000027            Communication prescaler control register
CDCR.MD               7
CDCR.DIV3             3
CDCR.DIV2             2
CDCR.DIV1             1
CDCR.DIV0             0
ENIR        0x000028            DTP/Interrupt enable register
ENIR.EN7              7
ENIR.EN6              6
ENIR.EN5              5
ENIR.EN4              4
ENIR.EN3              3
ENIR.EN2              2
ENIR.EN1              1
ENIR.EN0              0
EIRR        0x000029            DTP/Interrupt source register
EIRR.ER7              7
EIRR.ER6              6
EIRR.ER5              5
EIRR.ER4              4
EIRR.ER3              3
EIRR.ER2              2
EIRR.ER1              1
EIRR.ER0              0
ELVR        0x00002A            Request level setting register
ELVR.LALB71           15
ELVR.LALB70           14
ELVR.LALB61           13
ELVR.LALB60           12
ELVR.LALB51           11
ELVR.LALB50           10
ELVR.LALB41           9
ELVR.LALB40           8
ELVR.LALB31           7
ELVR.LALB30           6
ELVR.LALB21           5
ELVR.LALB20           4
ELVR.LALB11           3
ELVR.LALB10           2
ELVR.LALB01           1
ELVR.LALB00           0
ADCS0       0x00002C            A/D control status register
ADCS0.MD1             7
ADCS0.MD0             6
ADCS0.ANS1            4
ADCS0.ANS0            3
ADCS0.ANE1            1
ADCS0.ANE0            0    
ADCS1       0x00002D            A/D control status register
ADCS1.BUSY            7
ADCS1.INT             6
ADCS1.INTE            5
ADCS1.PAUS            4
ADCS1.STS1            3
ADCS1.STS0            2
ADCS1.STRT            1
ADCR01      0x00002E            A/D data register
ADCR01.S10            15
ADCR01.D9             9
ADCR01.D8             8
ADCR01.D7             7
ADCR01.D6             6
ADCR01.D5             5
ADCR01.D4             4
ADCR01.D3             3
ADCR01.D2             2
ADCR01.D1             1
ADCR01.D0             0
PCSR0       0x000030            PPG0 cycle setting register
PDUT0       0x000032            PPG0 duty factor setting register
PCN0        0x000034            PPG0 control status register
PCN0.CNTE             15
PCN0.STGR             14
PCN0.MDSE             13
PCN0.RTRG             12
PCN0.CKS1             11
PCN0.CKS0             10
PCN0.PGMS             9 
PCN0.EGS1             7 
PCN0.EGS0             6 
PCN0.IREN             5 
PCN0.IRQF             4 
PCN0.IRS1             3 
PCN0.IRS0             2 
PCN0.POEN             1 
PCN0.OSEL             0 
PCSR1       0x000038            PPG1 cycle setting register
PDUT1       0x00003A            PPG1 duty factor setting register
PCN1        0x00003C            PPG1 control status register
PCN1.CNTE             15
PCN1.STGR             14
PCN1.MDSE             13
PCN1.RTRG             12
PCN1.CKS1             11
PCN1.CKS0             10
PCN1.PGMS             9 
PCN1.EGS1             7 
PCN1.EGS0             6 
PCN1.IREN             5 
PCN1.IRQF             4 
PCN1.IRS1             3 
PCN1.IRS0             2 
PCN1.POEN             1 
PCN1.OSEL             0 
TMCSR0      0x000040            Timer control status register
TMCSR0.CSL1           11
TMCSR0.CSL0           10
TMCSR0.MOD2           9
TMCSR0.MOD1           8
TMCSR0.MOD0           7
TMCSR0.OUTE           6
TMCSR0.OUTL           5
TMCSR0.RELD           4
TMCSR0.INTE           3
TMCSR0.UF             2
TMCSR0.CNTE           1
TMCSR0.TRG            0
TMR0        0x000042            16-bit timer register
TMRLR0      0x000044            16-bit reload register
TMCSR1      0x000046            Timer control status register 1
TMCSR1.CSL1           11
TMCSR1.CSL0           10
TMCSR1.MOD2           9 
TMCSR1.MOD1           8 
TMCSR1.MOD0           7 
TMCSR1.OUTE           6 
TMCSR1.OUTL           5 
TMCSR1.RELD           4 
TMCSR1.INTE           3 
TMCSR1.UF             2 
TMCSR1.CNTE           1 
TMCSR1.TRG            0 
TMR1        0x000048            16-bit timer register 1
TMRLR1      0x00004A            16-bit reload register 1
TMCSR2      0x000050            Timer control status register 2
TMCSR2.CSL1           11
TMCSR2.CSL0           10
TMCSR2.MOD2           9 
TMCSR2.MOD1           8 
TMCSR2.MOD0           7 
TMCSR2.OUTE           6 
TMCSR2.OUTL           5 
TMCSR2.RELD           4 
TMCSR2.INTE           3 
TMCSR2.UF             2 
TMCSR2.CNTE           1 
TMCSR2.TRG            0 
TMR2        0x000052            16-bit timer register 2
TMRLR2      0x000054            16-bit reload register 2
TCDT0       0x000056            Timer data register 0
TCCS0       0x000058            Timer control status register 0
TCCS0.IVF             6
TCCS0.IVFE            5
TCCS0.STOP            4
TCCS0.MODE            3
TCCS0.CLR             2
TCCS0.CLK1            1
TCCS0.CLK0            0
CCS0        0x000059            Compare control status register 0
CCS0.ICP1             7
CCS0.ICP0             6
CCS0.ICE1             5
CCS0.ICE0             4
CCS0.CST1             1
CCS0.CST0             0
TCR00       0x00005A            Timer 0 compare register 0
TCR01       0x00005C            Timer 0 compare register 1
TCDT1       0x000060            Timer data register 1
TCCS1       0x000062            Timer control status register 1
TCCS1.IVF             6
TCCS1.IVFE            5
TCCS1.STOP            4
TCCS1.MODE            3
TCCS1.CLR             2
TCCS1.CLK1            1
TCCS1.CLK0            0
CCS1        0x000063            Compare control status register 1
CCS1.ICP1             7
CCS1.ICP0             6
CCS1.ICE1             5
CCS1.ICE0             4
CCS1.CST1             1
CCS1.CST0             0
TCR10       0x000064            Timer 1 compare register 0
TCR11       0x000066            Timer 1 compare register 1
VRAM00      0x000070            LCD display data RAM
VRAM01      0x000071            LCD display data RAM
VRAM02      0x000072            LCD display data RAM
VRAM03      0x000073            LCD display data RAM
VRAM04      0x000074            LCD display data RAM
VRAM05      0x000075            LCD display data RAM
VRAM06      0x000076            LCD display data RAM
VRAM07      0x000077            LCD display data RAM
VRAM08      0x000078            LCD display data RAM
VRAM09      0x000079            LCD display data RAM
VRAM10      0x00007A            LCD display data RAM
VRAM11      0x00007B            LCD display data RAM
VRAM12      0x00007C            LCD display data RAM
VRAM13      0x00007D            LCD display data RAM
VRAM14      0x00007E            LCD display data RAM
VRAM15      0x00007F            LCD display data RAM
LCR0        0x000080            LCDC control register 0
LCR0.CSS              7
LCR0.LCEN             6
LCR0.VSEL             5
LCR0.BK               4
LCR0.MS1              3
LCR0.MS0              2
LCR0.FP1              1
LCR0.FP0              0
LCR1        0x000081            LCDC control register 1
LCR1.SEG3             3
LCR1.SEG2             2
LCR1.SEG1             1
LCR1.SEG0             0
DIRR        0x00009F            Delayed interrupt source generation / release register
DIRR.R0               0
LPMCR       0x0000A0            Low-power consumption mode control register
LPMCR.STP             7
LPMCR.SLP             6
LPMCR.SPL             5
LPMCR.RST             4
LPMCR.TMD             3
LPMCR.CG1             2
LPMCR.CG0             1
LPMCR.SSR             0
CKSCR       0x0000A1            Clock selection register
CKSCR.SCM             7
CKSCR.MCM             6
CKSCR.WS1             5
CKSCR.WS0             4
CKSCR.SCS             3
CKSCR.MCS             2
CKSCR.CS1             1
CKSCR.CS0             0
WDTC        0x0000A8            Watchdog timer control register
WDTC.PONR             7
WDTC.STBR             6
WDTC.WRST             5
WDTC.ERST             4
WDTC.SRST             3
TBTC        0x0000A9            Timebase timer control register
TBTC.TBIE             4
TBTC.TBOF             3
TBTC.TBR              2
TBTC.TBC1             1
TBTC.TBC0             0
WTC         0x0000AA            Watch timer control register
WTC.WDCS              7
WTC.SCE               6
WTC.WTIE              5
WTC.WTOF              4
WTC.WTR               3
WTC.WTC2              2
WTC.WTC1              1
WTC.WTC0              0
ICR00       0x0000B0            Interrupt control register 00
ICR00.S1              5
ICR00.S0              4
ICR00.ISE             3
ICR00.IL2             2 
ICR00.IL1             1
ICR00.IL0             0
ICR01       0x0000B1            Interrupt control register 01
ICR01.S1              5
ICR01.S0              4
ICR01.ISE             3
ICR01.IL2             2 
ICR01.IL1             1
ICR01.IL0             0
ICR02       0x0000B2            Interrupt control register 02
ICR02.S1              5
ICR02.S0              4
ICR02.ISE             3
ICR02.IL2             2 
ICR02.IL1             1
ICR02.IL0             0
ICR03       0x0000B3            Interrupt control register 03
ICR03.S1              5
ICR03.S0              4
ICR03.ISE             3
ICR03.IL2             2 
ICR03.IL1             1
ICR03.IL0             0
ICR04       0x0000B4            Interrupt control register 04
ICR04.S1              5
ICR04.S0              4
ICR04.ISE             3
ICR04.IL2             2 
ICR04.IL1             1
ICR04.IL0             0
ICR05       0x0000B5            Interrupt control register 05
ICR05.S1              5
ICR05.S0              4
ICR05.ISE             3
ICR05.IL2             2 
ICR05.IL1             1
ICR05.IL0             0
ICR06       0x0000B6            Interrupt control register 06
ICR06.S1              5
ICR06.S0              4
ICR06.ISE             3
ICR06.IL2             2 
ICR06.IL1             1
ICR06.IL0             0
ICR07       0x0000B7            Interrupt control register 07
ICR07.S1              5
ICR07.S0              4
ICR07.ISE             3
ICR07.IL2             2 
ICR07.IL1             1
ICR07.IL0             0
ICR08       0x0000B8            Interrupt control register 08
ICR08.S1              5
ICR08.S0              4
ICR08.ISE             3
ICR08.IL2             2 
ICR08.IL1             1
ICR08.IL0             0
ICR09       0x0000B9            Interrupt control register 09
ICR09.S1              5
ICR09.S0              4
ICR09.ISE             3
ICR09.IL2             2 
ICR09.IL1             1
ICR09.IL0             0
ICR10       0x0000BA            Interrupt control register 10
ICR10.S1              5
ICR10.S0              4
ICR10.ISE             3
ICR10.IL2             2 
ICR10.IL1             1
ICR10.IL0             0
ICR11       0x0000BB            Interrupt control register 11
ICR11.S1              5
ICR11.S0              4
ICR11.ISE             3
ICR11.IL2             2 
ICR11.IL1             1
ICR11.IL0             0
ICR12       0x0000BC            Interrupt control register 12
ICR12.S1              5
ICR12.S0              4
ICR12.ISE             3
ICR12.IL2             2 
ICR12.IL1             1
ICR12.IL0             0
ICR13       0x0000BD            Interrupt control register 13
ICR13.S1              5
ICR13.S0              4
ICR13.ISE             3
ICR13.IL2             2 
ICR13.IL1             1
ICR13.IL0             0
ICR14       0x0000BE            Interrupt control register 14
ICR14.S1              5
ICR14.S0              4
ICR14.ISE             3
ICR14.IL2             2 
ICR14.IL1             1
ICR14.IL0             0
ICR15       0x0000BF            Interrupt control register 15
ICR15.S1              5
ICR15.S0              4
ICR15.ISE             3
ICR15.IL2             2 
ICR15.IL1             1
ICR15.IL0             0


.MB90630A
; DS07-13601-5E  http://edevice.fujitsu.com/fj/DATASHEET/e-ds/e713601.pdf
; MB90632A/634A/P634A


; ROM:           32 Kbytes (MB90632A)
;                64 Kbytes (MB90634A)
; One-time PROM: 64 Kbytes (MB90P634A)
; RAM:            1 Kbytes (MB90632A)
;                 2 Kbytes (MB90634A)
;                 3 Kbytes (MB90P634A)


; MEMORY MAP
; [MB90632A]
area DATA FSR           0x000000:0x0000C0
area BSS  No_access_1   0x0000C0:0x000100
area DATA MEM_INT_1     0x000100:0x000180
area DATA RAM           0x000180:0x000380
area DATA MEM_INT_2     0x000380:0x000500
area BSS  No_access_2   0x000500:0x008000
area DATA ROM_1         0x008000:0x010000
area BSS  No_access_3   0x010000:0xFF8000
; area DATA ROM_2_BANK_FF 0xFF8000:0x1000000

; [MB90634A]
; area DATA FSR           0x000000:0x0000C0
; area BSS  No_access_1   0x0000C0:0x000100
; area DATA MEM_INT_1     0x000100:0x000180
; area DATA RAM           0x000180:0x000380
; area DATA MEM_INT_2     0x000380:0x000900
; area BSS  No_access_2   0x000900:0x004000
; area DATA ROM_1         0x004000:0x010000
; area BSS  No_access_3   0x010000:0xFF0000
; area DATA ROM_2_BANK_FF 0xFF0000:0x1000000

; [MB90P634A]
; area DATA FSR           0x000000:0x0000C0
; area BSS  No_access_1   0x0000C0:0x000100
; area DATA MEM_INT_1     0x000100:0x000180
; area DATA RAM           0x000180:0x000380
; area DATA MEM_INT_2     0x000380:0x000D00
; area BSS  No_access_2   0x000D00:0x004000
; area DATA ROM_1         0x004000:0x010000
; area BSS  No_access_3   0x010000:0xFF0000
; area DATA ROM_2_BANK_FF 0xFF0000:0x1000000


; Interrupt and reset vector assignments
interrupt __RESET       0xFFFFDC       Reset 
interrupt INT_9         0xFFFFD8       INT 9 instruction 
interrupt EXCEPT        0xFFFFD4       Exception 
interrupt A_D_CONV      0xFFFFD0       A/D converter 
interrupt DTP_0         0xFFFFC8       DTP 0 (External interrupt 0) 
interrupt I_O_TIMER     0xFFFFC4       16-bit free-run timer (I/O timer) overflow 
interrupt I_O_EXP1      0xFFFFC0       I/O expansion serial 1 
interrupt DTP_1         0xFFFFBC       DTP 1 (External interrupt 1) 
interrupt I_O_EXP2      0xFFFFB8       I/O expansion serial 2 
interrupt DTP_2         0xFFFFB4       DTP 2 (External interrupt 2) 
interrupt DTP_3         0xFFFFB0       DTP 3 (External interrupt 3) 
interrupt PPG_0_COUNT   0xFFFFAC       8/16-bit PPG 0 counter borrow 
interrupt U_D_COUNT_0_C 0xFFFFA8       8/16-bit U/D counter 0 compare 
interrupt U_D_COUNT_0_U 0xFFFFA4       ICR05 0000B5H 8/16-bit U/D counter 0 underflow/overflow, up/down invert 
interrupt PPG_1_COUNT   0xFFFFA0       8/16-bit PPG 1 counter borrow 
interrupt DTP_4_5       0xFFFF9C       DTP 4/5 (External interrupt 4/5) 
interrupt O_C_CH2       0xFFFF98       Output compare (channel 2) match (I/O timer) 
interrupt O_C_CH3       0xFFFF94       Output compare (channel 3) match (I/O timer) 
interrupt DTP_6         0xFFFF8C       DTP 6 (External interrupt 6) 
interrupt U_D_COUNT_1_C 0xFFFF88       8/16-bit U/D counter 1 compare 
interrupt U_D_COUNT_1_U 0xFFFF84       8/16-bit U/D counter 1 underflow/overflow, up/down invert 
interrupt I_C_CH0       0xFFFF80       Input capture (channel 0) read (I/O timer) 
interrupt I_C_CH1       0xFFFF7C       Input capture (channel 1) read (I/O timer) 
interrupt O_C_CH0       0xFFFF78       Output compare (channel 0) match (I/O timer) 
interrupt O_C_CH1       0xFFFF74       Output compare (channel 1) match (I/O timer) 
interrupt DTP_7         0xFFFF6C       DTP 7 (External interrupt 7) 
interrupt UART0_R       0xFFFF68       UART0 receive complete 
interrupt UART1_R       0xFFFF64       UART1 receive complete 
interrupt UART0_T       0xFFFF60       UART0 transmit complete 
interrupt UART1_T       0xFFFF5C       UART1 transmit complete 
interrupt RESERV        0xFFFF58       Reserved 
interrupt DELAY         0xFFFF54       Delayed interrupt 


; INPUT/OUTPUT PORTS
PDR0                 0x000000           Port 0 data register
PDR0.PD17             7
PDR0.PD16             6
PDR0.PD15             5
PDR0.PD14             4
PDR0.PD13             3
PDR0.PD12             2
PDR0.PD11             1
PDR0.PD10             0
PDR1                 0x000001           Port 1 data register
PDR1.PD17             7
PDR1.PD16             6
PDR1.PD15             5
PDR1.PD14             4
PDR1.PD13             3
PDR1.PD12             2
PDR1.PD11             1
PDR1.PD10             0
PDR2                 0x000002           Port 2 data register
PDR2.PD27             7
PDR2.PD26             6
PDR2.PD25             5
PDR2.PD24             4
PDR2.PD23             3
PDR2.PD22             2
PDR2.PD21             1
PDR2.PD20             0
PDR3                 0x000003           Port 3 data register
PDR3.PD37             7
PDR3.PD36             6
PDR3.PD35             5
PDR3.PD34             4
PDR3.PD33             3
PDR3.PD32             2
PDR3.PD31             1
PDR3.PD30             0
PDR4                 0x000004           Port 4 data register
PDR4.PD47             7
PDR4.PD46             6
PDR4.PD45             5
PDR4.PD44             4
PDR4.PD43             3
PDR4.PD42             2
PDR4.PD41             1
PDR4.PD40             0
PDR5                 0x000005           Port 5 data register
PDR5.PD57             7
PDR5.PD56             6
PDR5.PD55             5
PDR5.PD54             4
PDR5.PD53             3
PDR5.PD52             2
PDR5.PD51             1
PDR5.PD50             0
PDR6                 0x000006           Port 6 data register
PDR6.PD67             7
PDR6.PD66             6
PDR6.PD65             5
PDR6.PD64             4
PDR6.PD63             3
PDR6.PD62             2
PDR6.PD61             1
PDR6.PD60             0
PDR7                 0x000007           Port 7 data register
PDR7.PD77             7
PDR7.PD76             6
PDR7.PD75             5
PDR7.PD74             4
PDR7.PD73             3
PDR7.PD72             2
PDR7.PD71             1
PDR7.PD70             0
PDR8                 0x000008           Port 8 data register
PDR8.PD87             7
PDR8.PD86             6
PDR8.PD85             5
PDR8.PD84             4
PDR8.PD83             3
PDR8.PD82             2
PDR8.PD81             1
PDR8.PD80             0
PDR9                 0x000009           Port 9 data register
PDR9.PD97             7
PDR9.PD96             6
PDR9.PD95             5
PDR9.PD94             4
PDR9.PD93             3
PDR9.PD92             2
PDR9.PD91             1
PDR9.PD90             0
PDRA                 0x00000A           Port A data register
PDRA.PDA7             7
PDRA.PDA6             6
PDRA.PDA5             5
PDRA.PDA4             4
PDRA.PDA3             3
PDRA.PDA2             2
PDRA.PDA1             1
DDR0                 0x000010           Port 0 direction register
DDR0.DD17             7
DDR0.DD16             6
DDR0.DD15             5
DDR0.DD14             4
DDR0.DD13             3
DDR0.DD12             2
DDR0.DD11             1
DDR0.DD10             0
DDR1                 0x000011           Port 1 direction register
DDR1.DD17             7
DDR1.DD16             6
DDR1.DD15             5
DDR1.DD14             4
DDR1.DD13             3
DDR1.DD12             2
DDR1.DD11             1
DDR1.DD10             0
DDR2                 0x000012           Port 2 direction register
DDR2.DD27             7
DDR2.DD26             6
DDR2.DD25             5
DDR2.DD24             4
DDR2.DD23             3
DDR2.DD22             2
DDR2.DD21             1
DDR2.DD20             0
DDR3                 0x000013           Port 3 direction register
DDR3.DD37             7
DDR3.DD36             6
DDR3.DD35             5
DDR3.DD34             4
DDR3.DD33             3
DDR3.DD32             2
DDR3.DD31             1
DDR3.DD30             0
DDR4                 0x000014           Port 4 direction register
DDR4.DD47             7
DDR4.DD46             6
DDR4.DD45             5
DDR4.DD44             4
DDR4.DD43             3
DDR4.DD42             2
DDR4.DD41             1
DDR4.DD40             0
DDR5                 0x000015           Port 5 direction register
DDR5.DD57             7
DDR5.DD56             6
DDR5.DD55             5
DDR5.DD54             4
DDR5.DD53             3
DDR5.DD52             2
DDR5.DD51             1
DDR5.DD50             0
DDR6                 0x000016           Port 6 direction register
DDR6.DD57             7
DDR6.DD56             6
DDR6.DD55             5
DDR6.DD54             4
DDR6.DD53             3
DDR6.DD52             2
DDR6.DD51             1
DDR6.DD50             0
DDR7                 0x000017           Port 7 direction register
DDR7.DD76             6
DDR7.DD75             5
DDR7.DD74             4
DDR7.DD73             3
DDR7.DD72             2
DDR7.DD71             1
DDR7.DD70             0
DDR8                 0x000018           Port 8 direction register
DDR8.DD86             6
DDR8.DD85             5
DDR8.DD84             4
DDR8.DD83             3
DDR8.DD82             2
DDR8.DD81             1
DDR8.DD80             0
DDR9                 0x000019           Port 9 direction register
DDR9.DD95             5
DDR9.DD94             4
DDR9.DD93             3
DDR9.DD92             2
DDR9.DD91             1
DDR9.DD90             0
DDRA                 0x00001A           Port A direction register
DDRA.DDA7             7
DDRA.DDA6             6
DDRA.DDA5             5
DDRA.DDA4             4
DDRA.DDA3             3
DDRA.DDA2             2
DDRA.DDA1             1
ODR4                 0x00001B           Port 4 pin register
ODR4.OD47             7
ODR4.OD46             6
ODR4.OD45             5
ODR4.OD44             4
ODR4.OD43             3
ODR4.OD42             2
ODR4.OD41             1
ODR4.OD40             0
RDR0                 0x00001C           Port 0 resistance register
RDR0.RD07             7
RDR0.RD06             6
RDR0.RD05             5
RDR0.RD04             4
RDR0.RD03             3
RDR0.RD02             2
RDR0.RD01             1
RDR0.RD00             0
RDR1                 0x00001D           Port 1 resistance register
RDR1.RD17             7
RDR1.RD16             6
RDR1.RD15             5
RDR1.RD14             4
RDR1.RD13             3
RDR1.RD12             2
RDR1.RD11             1
RDR1.RD10             0
RDR6                 0x00001E           Port 6 resistance register
RDR6.RD27             7
RDR6.RD26             6
RDR6.RD25             5
RDR6.RD24             4
RDR6.RD23             3
RDR6.RD22             2
RDR6.RD21             1
RDR6.RD20             0
ADER                 0x00001F           Analog input enable register
ADER.ADE7             7
ADER.ADE6             6
ADER.ADE5             5
ADER.ADE4             4
ADER.ADE3             3
ADER.ADE2             2
ADER.ADE1             1
ADER.ADE0             0
SMR0                 0x000020           Serial mode register 0
SMR0.MD1              7
SMR0.MD0              6
SMR0.CS2              5
SMR0.CS1              4
SMR0.CS0              3
SMR0.SCKE             1
SMR0.SOE              0
SCR0                 0x000021           Serial control register 0
SCR0.PEN              7
SCR0.P                6
SCR0.SBL              5
SCR0.CL               4
SCR0.AD               3
SCR0.REC              2
SCR0.RXE              1
SCR0.TXE              0
SIDR0                0x000022           Serial input register / Serial output register 0
SIDR0.D7              7
SIDR0.D6              6
SIDR0.D5              5
SIDR0.D4              4
SIDR0.D3              3
SIDR0.D2              2
SIDR0.D1              1
SIDR0.D0              0
SSR0                 0x000023           Serial status register 0
SSR0.PE               7
SSR0.ORE              6
SSR0.FRE              5
SSR0.RDRF             4
SSR0.TDRE             3
SSR0.RIE              1
SSR0.TIE              0
SMCS0                0x000024           Serial mode control status register 0
SMCS0.SMD2            15
SMCS0.SMD1            14
SMCS0.SMD0            13
SMCS0.SIE             12
SMCS0.SIR             11
SMCS0.BUSY            10
SMCS0.STOP            9
SMCS0.STRT            8
SMCS0.MODE            3
SMCS0.BDS             2
SMCS0.SOE             1
SMCS0.SCOE            0
SDR0                 0x000026           Serial data register 0
CDCR                 0x000027           Clock division control register
CDCR.MD               7      
CDCR.DIV3             3
CDCR.DIV2             2
CDCR.DIV1             1
CDCR.DIV0             0
SMCS1                0x000028           Serial mode control status register 1
SMCS1.SMD2            15
SMCS1.SMD1            14
SMCS1.SMD0            13
SMCS1.SIE             12
SMCS1.SIR             11
SMCS1.BUSY            10
SMCS1.STOP            9
SMCS1.STRT            8
SMCS1.MODE            3
SMCS1.BDS             2
SMCS1.SOE             1
SMCS1.SCOE            0
SDR1                 0x00002A           Serial data register 1
ENIR                 0x000030           Interrupt/DTP enable register
ENIR.EN7              7
ENIR.EN6              6
ENIR.EN5              5
ENIR.EN4              4
ENIR.EN3              3
ENIR.EN2              2
ENIR.EN1              1
ENIR.EN0              0
EIRR                 0x000031           Interrupt/DTP source register
EIRR.ER7              7
EIRR.ER6              6
EIRR.ER5              5
EIRR.ER4              4
EIRR.ER3              3
EIRR.ER2              2
EIRR.ER1              1
EIRR.ER0              0
ELVR                 0x000032           Request level setting register
ELVR.LALB71           15
ELVR.LALB70           14
ELVR.LALB61           13
ELVR.LALB60           12
ELVR.LALB51           11
ELVR.LALB50           10
ELVR.LALB41           9
ELVR.LALB40           8
ELVR.LALB31           7
ELVR.LALB30           6
ELVR.LALB21           5
ELVR.LALB20           4
ELVR.LALB11           3
ELVR.LALB10           2
ELVR.LALB01           1
ELVR.LALB00           0
ADCS1                0x000036           Control status register
ADCS1.MD1             7
ADCS1.MD0             6
ADCS1.ANS2            5
ADCS1.ANS1            4
ADCS1.ANS0            3
ADCS1.ANE2            2
ADCS1.ANE1            1
ADCS1.ANE0            0    
ADCS2                0x000037           Control status register
ADCS2.BUSY            7
ADCS2.INT             6
ADCS2.INTE            5
ADCS2.PAUS            4
ADCS2.STS1            3
ADCS2.STS0            2
ADCS2.STRT            1
ADCR12               0x000038           Data register
DADR0                0x00003A           D/A converter data register 0
DADR1                0x00003B           D/A converter data register 1
DACR0                0x00003C           D/A control register 0
DACR0.DAE0            0
DACR1                0x00003D           D/A control register 1
DACR1.DAE1            0
CLKR                 0x00003E           Clock control register
CLKR.CKEN             3
CLKR.FRQ2             2 
CLKR.FRQ1             1
CLKR.FRQ0             0
PRL0_PRLL            0x000040           Reload register L (channel 0)
PRL0_PRLH            0x000041           Reload register H (channel 0)
PRL1_PRLL            0x000042           Reload register L (channel 1)
PRL1_PRLH            0x000043           Reload register H (channel 1)
PPGC01               0x000044           PPG0 operation mode control register
PPGC01.PEN1           15
PPGC01.PE10           13
PPGC01.PIE1           12
PPGC01.PUF1           11
PPGC01.MD1            10
PPGC01.MD0            9
PPGC01.PEN0           7
PPGC01.PE00           5
PPGC01.PIE0           4
PPGC01.PUF0           3
PPGOE                0x000046           PPG0, 1 output control register
PPGOE.PCS2            7
PPGOE.PCS1            6
PPGOE.PCS0            5
PPGOE.PCM2            4
PPGOE.PCM1            3
PPGOE.PCM0            2
PPGOE.PE11            1
PPGOE.PE01            0
OCCP0                0x000050           compare register channel 0
OCCP1                0x000052           compare register channel 1
OCCP2                0x000054           compare register channel 2
OCCP3                0x000056           compare register channel 3
OCS01                0x000058           Compare control status register channel 0/1
OCS01.CMOD            12
OCS01.OTE1            11
OCS01.OTE0            10
OCS01.OTD1            9 
OCS01.OTD0            8 
OCS01.ICP1            7 
OCS01.ICP0            6 
OCS01.ICE1            5 
OCS01.ICE0            4 
OCS01.CST1            1 
OCS01.CST0            0 
OCS23                0x00005A           Compare control status register channel 2/3
OCS23.CMOD            12
OCS23.OTE1            11
OCS23.OTE0            10
OCS23.OTD1            9 
OCS23.OTD0            8 
OCS23.ICP1            7 
OCS23.ICP0            6 
OCS23.ICE1            5 
OCS23.ICE0            4 
OCS23.CST1            1 
OCS23.CST0            0 
IPCP0                0x000060           input capture register channel 0
IPCP1                0x000062           input capture register channel 1
ICS01                0x000064           Input capture control status register
ICS01.ICP1            7
ICS01.ICP0            6
ICS01.ICE1            5
ICS01.ICE0            4
ICS01.EG11            3
ICS01.EG10            2
ICS01.EG01            1
ICS01.EG00            0
TCDT                 0x000066           timer data register
TCCS                 0x000068           Timer control status register
TCCS.IVF              6
TCCS.IVFE             5
TCCS.STOP             4
TCCS.MODE             3
TCCS.CLR              2
TCCS.CLK1             1
TCCS.CLK0             0
UCDR_UDCR0           0x000070           Up/down count register channel 0
UCDR_UDCR1           0x000071           Up/down count register channel 1
RCR                  0x000072           Reload compare register channel 0/1
CSR0                 0x000074           Counter status register channel 0
CSR0.CSTR             7
CSR0.CITE             6
CSR0.UDIE             5
CSR0.CMPF             4
CSR0.OVFF             3
CSR0.UDFF             2
CSR0.UDF              1
CSR0.UDF              0
CCR0                 0x000076           Counter control register channel 0
CCR0.M16E             15
CCR0.CDCF             14
CCR0.CFIE             13
CCR0.CLKS             12
CCR0.CMS1             11
CCR0.CMS0             10
CCR0.CES1             9
CCR0.CES0             8
CCR0.CTUT             6
CCR0.UCRE             5
CCR0.RLDE             4
CCR0.UDCC             3
CCR0.CGSC             2
CCR0.CGE1             1
CCR0.CGE0             0
CSR1                 0x000078           Counter status register channel 1
CSR1.CSTR             7
CSR1.CITE             6
CSR1.UDIE             5
CSR1.CMPF             4
CSR1.OVFF             3
CSR1.UDFF             2
CSR1.UDF              1
CSR1.UDF              0
CCR1                 0x00007A           Counter control register channel 1
CCR1.CDCF             14
CCR1.CFIE             13
CCR1.CLKS             12
CCR1.CMS1             11
CCR1.CMS0             10
CCR1.CES1             9
CCR1.CES0             8
CCR1.CTUT             6
CCR1.UCRE             5
CCR1.RLDE             4
CCR1.UDCC             3
CCR1.CGSC             2
CCR1.CGE1             1
CCR1.CGE0             0
SMR1                 0x000088           Serial mode register 1
SMR1.MD1              7
SMR1.MD0              6
SMR1.CS2              5
SMR1.CS1              4
SMR1.CS0              3
SMR1.SCKE             1
SMR1.SOE              0
SCR1                 0x000089           Serial control register 1
SCR1.PEN              7
SCR1.P                6
SCR1.SBL              5
SCR1.CL               4
SCR1.AD               3
SCR1.REC              2
SCR1.RXE              1
SCR1.TXE              0
SIDR1                0x00008A           Serial input register 1/serial output register 1
SIDR1.D6              6
SIDR1.D5              5
SIDR1.D4              4
SIDR1.D3              3
SIDR1.D2              2
SIDR1.D1              1
SIDR1.D0              0
SSR1                 0x00008B           Serial status register 1
SSR1.PE               15
SSR1.ORE              14
SSR1.FRE              13
SSR1.RDRF             12
SSR1.TDRE             11
SSR1.RIE              9
SSR1.TIE              8
DIRR                 0x00009F           Delayed interrupt generation/clear register
DIRR.R0               0
LPMCR                0x0000A0           Low-power consumption mode register
LPMCR.STP             7
LPMCR.SLP             6
LPMCR.SPL             5
LPMCR.RST             4
LPMCR.CG1             2
LPMCR.CG0             1
CKSCR                0x0000A1           Clock selection register
CKSCR.MCM             6
CKSCR.WS              4
CKSCR.MCS             2
CKSCR.CS1             1
CKSCR.CS0             0
ARSR                 0x0000A5           Auto-ready function selection register
HACR                 0x0000A6           External address output control register
ECSR                 0x0000A7           Bus control signal selection  register
WDTC                 0x0000A8           Watchdog timer control register
WDTC.PONR             7
WDTC.STBR             6
WDTC.WRST             5
WDTC.ERST             4
WDTC.SRST             3
TBTC                 0x0000A9           Timebase timer control register
TBTC.TBIE             4
TBTC.TBOF             3
TBTC.TBR              2
TBTC.TBC1             1
TBTC.TBC0             0
ICR00                0x0000B0           Interrupt control register 00
ICR00.S1              5
ICR00.S0              4
ICR00.ISE             3
ICR00.IL2             2
ICR00.IL1             1
ICR00.IL0             0
ICR01                0x0000B1           Interrupt control register 01
ICR01.S1              5
ICR01.S0              4
ICR01.ISE             3
ICR01.IL2             2
ICR01.IL1             1
ICR01.IL0             0
ICR02                0x0000B2           Interrupt control register 02
ICR02.S1              5
ICR02.S0              4
ICR02.ISE             3
ICR02.IL2             2
ICR02.IL1             1
ICR02.IL0             0
ICR03                0x0000B3           Interrupt control register 03
ICR03.S1              5
ICR03.S0              4
ICR03.ISE             3
ICR03.IL2             2
ICR03.IL1             1
ICR03.IL0             0
ICR04                0x0000B4           Interrupt control register 04
ICR04.S1              5
ICR04.S0              4
ICR04.ISE             3
ICR04.IL2             2
ICR04.IL1             1
ICR04.IL0             0
ICR05                0x0000B5           Interrupt control register 05
ICR05.S1              5
ICR05.S0              4
ICR05.ISE             3
ICR05.IL2             2
ICR05.IL1             1
ICR05.IL0             0
ICR06                0x0000B6           Interrupt control register 06
ICR06.S1              5
ICR06.S0              4
ICR06.ISE             3
ICR06.IL2             2
ICR06.IL1             1
ICR06.IL0             0
ICR07                0x0000B7           Interrupt control register 07
ICR07.S1              5
ICR07.S0              4
ICR07.ISE             3
ICR07.IL2             2
ICR07.IL1             1
ICR07.IL0             0
ICR08                0x0000B8           Interrupt control register 08
ICR08.S1              5
ICR08.S0              4
ICR08.ISE             3
ICR08.IL2             2
ICR08.IL1             1
ICR08.IL0             0
ICR09                0x0000B9           Interrupt control register 09
ICR09.S1              5
ICR09.S0              4
ICR09.ISE             3
ICR09.IL2             2
ICR09.IL1             1
ICR09.IL0             0
ICR10                0x0000BA           Interrupt control register 10
ICR10.S1              5
ICR10.S0              4
ICR10.ISE             3
ICR10.IL2             2
ICR10.IL1             1
ICR10.IL0             0
ICR11                0x0000BB           Interrupt control register 11
ICR11.S1              5
ICR11.S0              4
ICR11.ISE             3
ICR11.IL2             2
ICR11.IL1             1
ICR11.IL0             0
ICR12                0x0000BC           Interrupt control register 12
ICR12.S1              5
ICR12.S0              4
ICR12.ISE             3
ICR12.IL2             2
ICR12.IL1             1
ICR12.IL0             0
ICR13                0x0000BD           Interrupt control register 13
ICR13.S1              5
ICR13.S0              4
ICR13.ISE             3
ICR13.IL2             2
ICR13.IL1             1
ICR13.IL0             0
ICR14                0x0000BE           Interrupt control register 14
ICR14.S1              5
ICR14.S0              4
ICR14.ISE             3
ICR14.IL2             2
ICR14.IL1             1
ICR14.IL0             0
ICR15                0x0000BF           Interrupt control register 15
ICR15.S1              5
ICR15.S0              4
ICR15.ISE             3
ICR15.IL2             2
ICR15.IL1             1
ICR15.IL0             0


.MB90640A
; DS07-13608-1E  http://edevice.fujitsu.com/fj/DATASHEET/e-ds/e713608.pdf
; MB90641A/P641A


; RAM: 2 Kbytes


; MEMORY MAP
MB90641A
area DATA FSR           0x000000:0x0000C0
area DATA MEM_INT_1     0x0000C0:0x000100
area DATA RAM           0x000100:0x000900
area BSS  No_access_1   0x000900:0x004000
area DATA ROM_1         0x004000:0x00FFFF
area BSS  No_access_2   0x00FFFF:0xFF0000
; area DATA ROM_2_BANK_FF 0xFF0000:0x1000000


; Interrupt and reset vector assignments
interrupt __RESET       0xFFFFDC       Reset 
interrupt INT_9         0xFFFFD8       INT 9 instruction 
interrupt EXCEPT        0xFFFFD4       Exception 
interrupt DTP_EI_1      0xFFFFD0       DTP/external interrupt 
interrupt DTP_EI_2      0xFFFFC8       DTP/external interrupt 
interrupt DTP_EI_3      0xFFFFC0       DTP/external interrupt 
interrupt DTP_EI_4      0xFFFFB8       DTP/external interrupt 
interrupt R_TIMER_1     0xFFFFB4       16-bit reload timer 
interrupt DTP_EI_5      0xFFFFB0       DTP/external interrupt 
interrupt R_TIMER_2     0xFFFFAC       16-bit reload timer 
interrupt DTP_EI_6      0xFFFFA8       DTP/external interrupt 
interrupt R_TIMER_3     0xFFFFA4       16-bit reload timer 
interrupt DTP_EI_7      0xFFFFA0       DTP/external interrupt 
interrupt UART0_S       0xFFFF9C       UART0 - send complete 
interrupt DTP_EI_8      0xFFFF98       DTP/external interrupt 
interrupt UART1_S       0xFFFF94       UART1 - send complete 
interrupt PPG_1         0xFFFF90       8/16-bit PPG 
interrupt PPG_2         0xFFFF8C       8/16-bit PPG 
interrupt R_TIMER_4     0xFFFF88       16-bit reload timer 
interrupt R_TIMER_5     0xFFFF84       16-bit reload timer 
interrupt VACANCY_1     0xFFFF80       Vacancy 
interrupt TTII          0xFFFF74       Timebase timer interval interrupt 
interrupt VACANCY_2     0xFFFF70       Vacancy 
interrupt UART1_R       0xFFFF68       UART1 - receive complete 
interrupt UART0_R       0xFFFF60       UART0 - receive complete 
interrupt DELAY         0xFFFF54       Delayed interrupt generation module 


; INPUT/OUTPUT PORTS
PDR0                 0x000000           Port 0 data register
PDR0.PD07             7
PDR0.PD06             6
PDR0.PD05             5
PDR0.PD04             4
PDR0.PD03             3
PDR0.PD02             2
PDR0.PD01             1
PDR0.PD00             0
PDR1                 0x000001           Port 1 data register
PDR1.PD17             7
PDR1.PD16             6
PDR1.PD15             5
PDR1.PD14             4
PDR1.PD13             3
PDR1.PD12             2
PDR1.PD11             1
PDR1.PD10             0
PDR2                 0x000002           Port 2 data register
PDR2.PD27             7
PDR2.PD26             6
PDR2.PD25             5
PDR2.PD24             4
PDR2.PD23             3
PDR2.PD22             2
PDR2.PD21             1
PDR2.PD20             0
PDR3                 0x000003           Port 3 data register
PDR3.PD37             7
PDR3.PD36             6
PDR3.PD35             5
PDR3.PD34             4
PDR3.PD33             3
PDR3.PD32             2
PDR3.PD31             1
PDR3.PD30             0
PDR4                 0x000004           Port 4 data register
PDR4.PD47             7
PDR4.PD46             6
PDR4.PD45             5
PDR4.PD44             4
PDR4.PD43             3
PDR4.PD42             2
PDR4.PD41             1
PDR4.PD40             0
PDR5                 0x000005           Port 5 data register
PDR5.PD57             7
PDR5.PD56             6
PDR5.PD55             5
PDR5.PD54             4
PDR5.PD53             3
PDR5.PD52             2
PDR5.PD51             1
PDR5.PD50             0
PDR6                 0x000006           Port 6 data register
PDR6.PD67             7
PDR6.PD66             6
PDR6.PD65             5
PDR6.PD64             4
PDR6.PD63             3
PDR6.PD62             2
PDR6.PD61             1
PDR6.PD60             0
PDR7                 0x000007           Port 7 data register
PDR7.PD76             6
PDR7.PD75             5
PDR7.PD74             4
PDR7.PD73             3
PDR7.PD72             2
PDR7.PD71             1
PDR8                 0x000008           Port 8 data register
PDR8.PD86             6
PDR8.PD85             5
PDR8.PD84             4
PDR8.PD83             3
PDR8.PD82             2
PDR8.PD81             1
PDR8.PD80             0
PDR9                 0x000009           Port 9 data register
PDR9.PD95             5
PDR9.PD94             4
PDR9.PD93             3
PDR9.PD92             2
PDR9.PD91             1
PDR9.PD90             0
PDRA                 0x00000A           Port A data register
PDRA.PDA7             7
PDRA.PDA6             6
PDRA.PDA5             5
PDRA.PDA4             4
PDRA.PDA3             3
PDRA.PDA2             2
PDRA.PDA1             1
PDRA.PDA0             0
DDR0                 0x000010           Port 0 direction register
DDR0.DD07             7
DDR0.DD06             6
DDR0.DD05             5
DDR0.DD04             4
DDR0.DD03             3
DDR0.DD02             2
DDR0.DD01             1
DDR0.DD00             0
DDR1                 0x000011           Port 1 direction register
DDR1.DD17             7
DDR1.DD16             6
DDR1.DD15             5
DDR1.DD14             4
DDR1.DD13             3
DDR1.DD12             2
DDR1.DD11             1
DDR1.DD10             0
DDR2                 0x000012           Port 2 direction register
DDR2.DD27             7
DDR2.DD26             6
DDR2.DD25             5
DDR2.DD24             4
DDR2.DD23             3
DDR2.DD22             2
DDR2.DD21             1
DDR2.DD20             0
DDR3                 0x000013           Port 3 direction register
DDR3.DD37             7
DDR3.DD36             6
DDR3.DD35             5
DDR3.DD34             4
DDR3.DD33             3
DDR3.DD32             2
DDR3.DD31             1
DDR3.DD30             0
DDR4                 0x000014           Port 4 direction register
DDR4.DD47             7
DDR4.DD46             6
DDR4.DD45             5
DDR4.DD44             4
DDR4.DD43             3
DDR4.DD42             2
DDR4.DD41             1
DDR4.DD40             0
DDR5                 0x000015           Port 5 direction register
DDR5.DD57             7
DDR5.DD56             6
DDR5.DD55             5
DDR5.DD54             4
DDR5.DD53             3
DDR5.DD52             2
DDR5.DD51             1
DDR5.DD50             0
DDR6                 0x000016           Port 6 direction register
DDR6.DD67             7
DDR6.DD66             6
DDR6.DD65             5
DDR6.DD64             4
DDR6.DD63             3
DDR6.DD62             2
DDR6.DD61             1
DDR6.DD60             0
DDR7                 0x000017           Port 7 direction register
DDR7.DD76             6
DDR7.DD75             5
DDR7.DD74             4
DDR7.DD73             3
DDR7.DD72             2
DDR7.DD71             1
DDR8                 0x000018           Port 8 direction register
DDR8.DD86             6
DDR8.DD85             5
DDR8.DD84             4
DDR8.DD83             3
DDR8.DD82             2
DDR8.DD81             1
DDR8.DD80             0
DDR9                 0x000019           Port 9 direction register
DDR9.DD95             5
DDR9.DD94             4
DDR9.DD93             3
DDR9.DD92             2
DDR9.DD91             1
DDR9.DD90             0
DDRA                 0x00001A           Port A direction register
DDRA.DDA7             7
DDRA.DDA6             6
DDRA.DDA5             5
DDRA.DDA4             4
DDRA.DDA3             3
DDRA.DDA2             2
DDRA.DDA1             1
DDRA.DDA0             0
SMR0                 0x000020           Serial mode register 0
SMR0.MD1              7
SMR0.MD0              6
SMR0.CS2              5
SMR0.CS1              4
SMR0.CS0              3
SMR0.SCKE             1
SMR0.SOE              0
SCR0                 0x000021           Serial control register 0
SCR0.PEN              7
SCR0.P                6
SCR0.SBL              5
SCR0.CL               4
SCR0.AD               3
SCR0.REC              2
SCR0.RXE              1
SCR0.TXE              0
SIDR0                0x000022           Input data register 0 / output data register 0
SIDR0.D6              6
SIDR0.D5              5
SIDR0.D4              4
SIDR0.D3              3
SIDR0.D2              2
SIDR0.D1              1
SIDR0.D0              0
SSR0                 0x000023           Serial status register 0
SSR0.PE               7
SSR0.ORE              6
SSR0.FRE              5
SSR0.RDRF             4
SSR0.TDRE             3
SSR0.RIE              1
SSR0.TIE              0
SMR1                 0x000024           Serial mode register 1
SMR1.MD1              7
SMR1.MD0              6
SMR1.CS2              5
SMR1.CS1              4
SMR1.CS0              3
SMR1.SCKE             1
SMR1.SOE              0
SCR1                 0x000025           Serial control register 1
SCR1.PEN              7
SCR1.P                6
SCR1.SBL              5
SCR1.CL               4
SCR1.AD               3
SCR1.REC              2
SCR1.RXE              1
SCR1.TXE              0
SIDR1                0x000026           Input data register 1 / output data register 1
SIDR1.D6              6
SIDR1.D5              5
SIDR1.D4              4
SIDR1.D3              3
SIDR1.D2              2
SIDR1.D1              1
SIDR1.D0              0
SSR1                 0x000027           Serial status register 1
SSR1.PE               7
SSR1.ORE              6
SSR1.FRE              5
SSR1.RDRF             4
SSR1.TDRE             3
SSR1.RIE              1
SSR1.TIE              0
ENIR                 0x000028           Interrupt/DTP enable register
ENIR.EN7              7
ENIR.EN6              6
ENIR.EN5              5
ENIR.EN4              4
ENIR.EN3              3
ENIR.EN2              2
ENIR.EN1              1
ENIR.EN0              0
EIRR                 0x000029           Interrupt/DTP request register
EIRR.ER7              7
EIRR.ER6              6
EIRR.ER5              5
EIRR.ER4              4
EIRR.ER3              3
EIRR.ER2              2
EIRR.ER1              1
EIRR.ER0              0
ELVR                 0x00002A           Interrupt level setting register
ELVR.LALB71           15
ELVR.LALB70           14
ELVR.LALB61           13
ELVR.LALB60           12
ELVR.LALB51           11
ELVR.LALB50           10
ELVR.LALB41           9
ELVR.LALB40           8
ELVR.LALB31           7
ELVR.LALB30           6
ELVR.LALB21           5
ELVR.LALB20           4
ELVR.LALB11           3
ELVR.LALB10           2
ELVR.LALB01           1
ELVR.LALB00           0
PPGC01               0x000030           PPG0 operation mode control register
PPGC01.PEN1           15
PPGC01.PCS1           14
PPGC01.PE10           13
PPGC01.PIE1           12
PPGC01.PUF1           11
PPGC01.MD1            10
PPGC01.MD0            9
PPGC01.PEN0           7
PPGC01.PE00           5
PPGC01.PIE0           4
PPGC01.PUF0           3
PPGC01.PCM1           2
PPGC01.PCM0           1
PRL0_PRLL            0x000034           PPG0 reload register
PRL0_PRLH            0x000035           PPG0 reload register
PRL1_PRLL            0x000036           PPG1 reload register
PRL1_PRLH            0x000037           PPG1 reload register
TMCSR0               0x000038           Timer control status register
TMCSR0.CSL1           11
TMCSR0.CSL0           10
TMCSR0.MOD2           9
TMCSR0.MOD1           8
TMCSR0.MOD0           7
TMCSR0.OUTE           6
TMCSR0.OUTL           5
TMCSR0.RELD           4
TMCSR0.INTE           3
TMCSR0.UF             2
TMCSR0.CNTE           1
TMCSR0.TRG            0
TMR0                 0x00003A           16-bit timer register / 16-bit reload register
TMCSR1               0x00003C           Timer control status register
TMCSR1.CSL1           11
TMCSR1.CSL0           10
TMCSR1.MOD2           9
TMCSR1.MOD1           8
TMCSR1.MOD0           7
TMCSR1.OUTE           6
TMCSR1.OUTL           5
TMCSR1.RELD           4
TMCSR1.INTE           3
TMCSR1.UF             2
TMCSR1.CNTE           1
TMCSR1.TRG            0
TMR1                 0x00003E           16-bit timer register / 16-bit reload register
CSCR0                0x000048           Chip select control register 0
CSCR0.ACTL            3
CSCR0.OPEL            2
CSCR0.CSA1            1
CSCR0.CSA0            0
CSCR1                0x000049           Chip select control register 1
CSCR1.ACTL            3
CSCR1.OPEL            2
CSCR1.CSA1            1
CSCR1.CSA0            0
CSCR2                0x00004A           Chip select control register 2
CSCR2.ACTL            3
CSCR2.OPEL            2
CSCR2.CSA1            1
CSCR2.CSA0            0
CSCR3                0x00004B           Chip select control register 3
CSCR3.ACTL            3
CSCR3.OPEL            2
CSCR3.CSA1            1
CSCR3.CSA0            0
CSCR4                0x00004C           Chip select control register 4
CSCR4.ACTL            3
CSCR4.OPEL            2
CSCR4.CSA1            1
CSCR4.CSA0            0
CSCR5                0x00004D           Chip select control register 5
CSCR5.ACTL            3
CSCR5.OPEL            2
CSCR5.CSA1            1
CSCR5.CSA0            0
CSCR6                0x00004E           Chip select control register 6
CSCR6.ACTL            3
CSCR6.OPEL            2
CSCR6.CSA1            1
CSCR6.CSA0            0
CSCR7                0x00004F           Chip select control register 7
CSCR7.ACTL            3
CSCR7.OPEL            2
CSCR7.CSA1            1
CSCR7.CSA0            0
CDCR0                0x000051           UART0 (SCI) machine clock division control register
CDCR0.DIV3            3
CDCR0.DIV2            2
CDCR0.DIV1            1
CDCR0.DIV0            0
CDCR1                0x000053           UART1 (SCI) machine clock division control register
CDCR1.DIV3            3
CDCR1.DIV2            2
CDCR1.DIV1            1
CDCR1.DIV0            0
TMCSR2               0x000058           Timer control status register
TMCSR2.CSL1           11
TMCSR2.CSL0           10
TMCSR2.MOD2           9
TMCSR2.MOD1           8
TMCSR2.MOD0           7
TMCSR2.OUTE           6
TMCSR2.OUTL           5
TMCSR2.RELD           4
TMCSR2.INTE           3
TMCSR2.UF             2
TMCSR2.CNTE           1
TMCSR2.TRG            0
TMR2                 0x00005A           16-bit timer register / 16-bit reload register
TMCSR3               0x00005C           Timer control status register
TMCSR3.CSL1           11
TMCSR3.CSL0           10
TMCSR3.MOD2           9
TMCSR3.MOD1           8
TMCSR3.MOD0           7
TMCSR3.OUTE           6
TMCSR3.OUTL           5
TMCSR3.RELD           4
TMCSR3.INTE           3
TMCSR3.UF             2
TMCSR3.CNTE           1
TMCSR3.TRG            0
TMR3                 0x00005E           16-bit timer register / 16-bit reload register
TMCSR4               0x000060           Timer control status register
TMCSR4.CSL1           11
TMCSR4.CSL0           10
TMCSR4.MOD2           9
TMCSR4.MOD1           8
TMCSR4.MOD0           7
TMCSR4.OUTE           6
TMCSR4.OUTL           5
TMCSR4.RELD           4
TMCSR4.INTE           3
TMCSR4.UF             2
TMCSR4.CNTE           1
TMCSR4.TRG            0
TMR4                 0x000062           16-bit timer register / 16-bit reload register
TPCR0                0x000064           Timer pin control register
TPCR0.OTE1            7
TPCR0.CS12            6
TPCR0.CS11            5
TPCR0.CS10            4
TPCR0.OTE0            3
TPCR0.CS02            2
TPCR0.CS01            1
TPCR0.CS00            0
TPCR1                0x000065           Timer pin control register
TPCR1.OTE3            7
TPCR1.CS32            6
TPCR1.CS31            5
TPCR1.CS30            4
TPCR1.OTE2            3
TPCR1.CS22            2
TPCR1.CS21            1
TPCR1.CS20            0
TPCR2                0x000066           Timer pin control register
TPCR2.OTE4            3
TPCR2.CS42            2
TPCR2.CS41            1
TPCR2.CS40            0
ROMM                 0x00006F           ROM mirror functional selection module
DIRR                 0x00009F           Delayed interrupt generation/release register
DIRR.R0               0
LPMCR                0x0000A0           Low power consumption mode control register
LPMCR.STP             7
LPMCR.SLP             6
LPMCR.SPL             5
LPMCR.RST             4
LPMCR.CG1             2
LPMCR.CG0             1
CKSCR                0x0000A1           Clock selection register
CKSCR.MCM             6
CKSCR.WS1             5
CKSCR.WS0             4
CKSCR.MCS             2
CKSCR.CS1             1
CKSCR.CS0             0
ARSR                 0x0000A5           Auto-ready function selection register
HACR                 0x0000A6           External address output control register
ECSR                 0x0000A7           Bus control signal selection register
WDTC                 0x0000A8           Watchdog timer control register
WDTC.PONR             7
WDTC.STBR             6
WDTC.WRST             5
WDTC.ERST             4
WDTC.SRST             3
TBTC                 0x0000A9           Timebase timer control register
TBTC.TBIE             4
TBTC.TBOF             3
TBTC.TBR              2
TBTC.TBC1             1
TBTC.TBC0             0
ICR00                0x0000B0           Interrupt control register 00
ICR00.S1              5
ICR00.S0              4
ICR00.ISE             3
ICR00.IL2             2
ICR00.IL1             1
ICR00.IL0             0
ICR01                0x0000B1           Interrupt control register 01
ICR01.S1              5
ICR01.S0              4
ICR01.ISE             3
ICR01.IL2             2
ICR01.IL1             1
ICR01.IL0             0
ICR02                0x0000B2           Interrupt control register 02
ICR02.S1              5
ICR02.S0              4
ICR02.ISE             3
ICR02.IL2             2
ICR02.IL1             1
ICR02.IL0             0
ICR03                0x0000B3           Interrupt control register 03
ICR03.S1              5
ICR03.S0              4
ICR03.ISE             3
ICR03.IL2             2
ICR03.IL1             1
ICR03.IL0             0
ICR04                0x0000B4           Interrupt control register 04
ICR04.S1              5
ICR04.S0              4
ICR04.ISE             3
ICR04.IL2             2
ICR04.IL1             1
ICR04.IL0             0
ICR05                0x0000B5           Interrupt control register 05
ICR05.S1              5
ICR05.S0              4
ICR05.ISE             3
ICR05.IL2             2
ICR05.IL1             1
ICR05.IL0             0
ICR06                0x0000B6           Interrupt control register 06
ICR06.S1              5
ICR06.S0              4
ICR06.ISE             3
ICR06.IL2             2
ICR06.IL1             1
ICR06.IL0             0
ICR07                0x0000B7           Interrupt control register 07
ICR07.S1              5
ICR07.S0              4
ICR07.ISE             3
ICR07.IL2             2
ICR07.IL1             1
ICR07.IL0             0
ICR08                0x0000B8           Interrupt control register 08
ICR08.S1              5
ICR08.S0              4
ICR08.ISE             3
ICR08.IL2             2
ICR08.IL1             1
ICR08.IL0             0
ICR09                0x0000B9           Interrupt control register 09
ICR09.S1              5
ICR09.S0              4
ICR09.ISE             3
ICR09.IL2             2
ICR09.IL1             1
ICR09.IL0             0
ICR11                0x0000BB           Interrupt control register 11
ICR11.S1              5
ICR11.S0              4
ICR11.ISE             3
ICR11.IL2             2
ICR11.IL1             1
ICR11.IL0             0
ICR13                0x0000BD           Interrupt control register 13
ICR13.S1              5
ICR13.S0              4
ICR13.ISE             3
ICR13.IL2             2
ICR13.IL1             1
ICR13.IL0             0
ICR14                0x0000BE           Interrupt control register 14
ICR14.S1              5
ICR14.S0              4
ICR14.ISE             3
ICR14.IL2             2
ICR14.IL1             1
ICR14.IL0             0
ICR15                0x0000BF           Interrupt control register 15
ICR15.S1              5
ICR15.S0              4
ICR15.ISE             3
ICR15.IL2             2
ICR15.IL1             1
ICR15.IL0             0


.MB90650A
; DS07-13607-4E  http://edevice.fujitsu.com/fj/DATASHEET/e-ds/e713607.pdf
; MB90652A/653A/P653A/654A/F654A
; MB90650A.pdf, MB90650A_HM.pdf


; ROM:  64 Kbytes (MB90652A)
;      128 Kbytes (MB90653A/MB90P653A)
;      256 Kbytes (MB90654A/MB90F654A)
; RAM:   3 Kbytes (MB90652A)
;        5 Kbytes (MB90653A/MB90P653A/MB90V650A)
;        8 Kbytes (MB90654A/MB90F654A)


; MEMORY MAP
; [MB90652]
area DATA FSR           0x000000:0x0000C0
area BSS  No_access_1   0x0000C0:0x000100
area DATA RAM           0x000100:0x000D00
area BSS  No_access_2   0x000D00:0x004000
area DATA ROM_1         0x004000:0x010000       
area BSS  No_access_3   0x010000:0xFF0000
; area DATA ROM_2_BANK_FF 0xFF0000:0x1000000

; [MB90653/MB90P653]
; area DATA FSR           0x000000:0x0000C0
; area BSS  No_access_1   0x0000C0:0x000100
; area DATA RAM           0x000100:0x001500
; area BSS  No_access_2   0x001500:0x004000
; area DATA ROM_1         0x004000:0x010000
; area BSS  No_access_3   0x010000:0xFE0000
; area DATA ROM_2_BANK_FE 0xFE0000:0xFF0000
; area DATA ROM_2_BANK_FF 0xFF0000:0x1000000

; [MB90654A/MB90F654A]
; area DATA FSR           0x000000:0x0000C0
; area BSS  No_access_1   0x0000C0:0x000100
; area DATA RAM           0x000100:0x002100
; area BSS  No_access_2   0x002100:0x004000
; area DATA ROM_1         0x004000:0x010000
; area BSS  No_access_3   0x010000:0xFC0000
; area DATA ROM_2_BANK_FC 0xFC0000:0xFD0000
; area DATA ROM_2_BANK_FD 0xFD0000:0xFE0000
; area DATA ROM_2_BANK_FE 0xFE0000:0xFF0000
; area DATA ROM_2_BANK_FF 0xFF0000:0x1000000


; Interrupt and reset vector assignments
interrupt __RESET       0xFFFFDC       Reset 
interrupt INT_9         0xFFFFD8       INT 9 instruction 
interrupt EXCEPT        0xFFFFD4       Exception 
interrupt A_D_C         0xFFFFD0       A/D converter 
interrupt TTII          0xFFFFCC       Timebase timer interval interrupt 
interrupt DTP_EI_0      0xFFFFC8       DTP/external interrupt 0 (External interrupt 0) 
interrupt I_O_TIMER     0xFFFFC4       16-bit free-run timer (I/O timer) overflow 
interrupt I_O_ESI_1     0xFFFFC0       I/O extended serial interface 1 
interrupt DTP_EI_1      0xFFFFBC       DTP/external interrupt 1 (External interrupt 1) 
interrupt I_O_ESI_2     0xFFFFB8       I/O extended serial interface 2 
interrupt DTP_EI_2      0xFFFFB4       DTP/external interrupt 2 (External interrupt 2) 
interrupt DTP_EI_3      0xFFFFB0       DTP/external interrupt 3 (External interrupt 3) 
interrupt PPG_0_C       0xFFFFAC       8/16-bit PPG 0 counter borrow 
interrupt UDCT0C        0xFFFFA8       8/16-bit up/down counter/timer 0 compare 
interrupt UDCT0UOUDI    0xFFFFA4       8/16-bit up/down counter/timer 0 underflow/overflow, up/down invert 
interrupt PPG_1_C       0xFFFFA0       8/16-bit PPG 1 counter borrow 
interrupt DTP_EI_4_5    0xFFFF9C       DTP/external interrupt 4/5 (External interrupt 4/5) 
interrupt OC_CH2        0xFFFF98       Output compare (channel 2) matc       (I/O timer) 
interrupt OC_CH3        0xFFFF94       Output compare (channel 3) matc       (I/O timer) 
interrupt WATCH         0xFFFF90       Watch prescaler 
interrupt DTP_EI_6      0xFFFF8C       DTP/external interrupt 6 (External interrupt 6) 
interrupt UDCT1C        0xFFFF88       8/16-bit up/down counter/timer 1 compare 
interrupt UDCT1UOUDI    0xFFFF84       8/16-bit up/down counter/timer 1 underflow/overflow, up/down invert 
interrupt IC_CH0        0xFFFF80       Input capture (channel 0) read (I/O timer) 
interrupt IC_CH1        0xFFFF7C       Input capture (channel 1) read (I/O timer) 
interrupt OC_CH0        0xFFFF78       Output compare (channel 0) matc       (I/O timer) 
interrupt OC_CH1        0xFFFF74       Output compare (channel 1) matc       (I/O timer) 
interrupt CFM           0xFFFF70       Completion of flas       memory write/erase ? 
interrupt DTP_EI_7      0xFFFF6C       DTP/external interrupt 7 (External interrupt 7) 
interrupt UART0_R       0xFFFF68       UART0 receive complete 
interrupt UART0_T       0xFFFF60       UART0 transmit complete 
interrupt I2CI          0xFFFF58       I 2 C interface 
interrupt DELAY         0xFFFF54       Delayed interrupt generation module 


; INPUT/OUTPUT PORTS
PDR0                 0x000000           Port 0 data register
PDR0.PD07             7     Port 0 data register bit 7
PDR0.PD06             6     Port 0 data register bit 6
PDR0.PD05             5     Port 0 data register bit 5
PDR0.PD04             4     Port 0 data register bit 4
PDR0.PD03             3     Port 0 data register bit 3
PDR0.PD02             2     Port 0 data register bit 2
PDR0.PD01             1     Port 0 data register bit 1
PDR0.PD00             0     Port 0 data register bit 0
PDR1                 0x000001           Port 1 data register
PDR1.PD17             15    Port 1 data register bit 15
PDR1.PD16             14    Port 1 data register bit 14
PDR1.PD15             13    Port 1 data register bit 13
PDR1.PD14             12    Port 1 data register bit 12
PDR1.PD13             11    Port 1 data register bit 11
PDR1.PD12             10    Port 1 data register bit 10
PDR1.PD11             9     Port 1 data register bit 9 
PDR1.PD10             8     Port 1 data register bit 8 
PDR2                 0x000002           Port 2 data register
PDR2.PD27             7     Port 2 data register bit 7
PDR2.PD26             6     Port 2 data register bit 6
PDR2.PD25             5     Port 2 data register bit 5
PDR2.PD24             4     Port 2 data register bit 4
PDR2.PD23             3     Port 2 data register bit 3
PDR2.PD22             2     Port 2 data register bit 2
PDR2.PD21             1     Port 2 data register bit 1
PDR2.PD20             0     Port 2 data register bit 0
PDR3                 0x000003           Port 3 data register
PDR3.PD37             15    Port 3 data register bit 15
PDR3.PD36             14    Port 3 data register bit 14
PDR3.PD35             13    Port 3 data register bit 13
PDR3.PD34             12    Port 3 data register bit 12
PDR3.PD33             11    Port 3 data register bit 11
PDR3.PD32             10    Port 3 data register bit 10
PDR3.PD31             9     Port 3 data register bit 9 
PDR3.PD30             8     Port 3 data register bit 8 
PDR4                 0x000004           Port 4 data register
PDR4.PD47             7     Port 4 data register bit 7
PDR4.PD46             6     Port 4 data register bit 6
PDR4.PD45             5     Port 4 data register bit 5
PDR4.PD44             4     Port 4 data register bit 4
PDR4.PD43             3     Port 4 data register bit 3
PDR4.PD42             2     Port 4 data register bit 2
PDR4.PD41             1     Port 4 data register bit 1
PDR4.PD40             0     Port 4 data register bit 0
PDR5                 0x000005           Port 5 data register
PDR5.PD57             15    Port 5 data register bit 15
PDR5.PD56             14    Port 5 data register bit 14
PDR5.PD55             13    Port 5 data register bit 13
PDR5.PD54             12    Port 5 data register bit 12
PDR5.PD53             11    Port 5 data register bit 11
PDR5.PD52             10    Port 5 data register bit 10
PDR5.PD51             9     Port 5 data register bit 9 
PDR5.PD50             8     Port 5 data register bit 8 
PDR6                 0x000006           Port 6 data register
PDR6.PD67             7     Port 6 data register bit 7
PDR6.PD66             6     Port 6 data register bit 6
PDR6.PD65             5     Port 6 data register bit 5
PDR6.PD64             4     Port 6 data register bit 4
PDR6.PD63             3     Port 6 data register bit 3
PDR6.PD62             2     Port 6 data register bit 2
PDR6.PD61             1     Port 6 data register bit 1
PDR6.PD60             0     Port 6 data register bit 0
PDR7                 0x000007           Port 7 data register
PDR7.PD74             12    Port 7 data register bit 12
PDR7.PD73             11    Port 7 data register bit 11
PDR7.PD72             10    Port 7 data register bit 10
PDR7.PD71             9     Port 7 data register bit 9 
PDR7.PD70             8     Port 7 data register bit 8 
PDR8                 0x000008           Port 8 data register
PDR8.PD86             6     Port 8 data register bit 6
PDR8.PD85             5     Port 8 data register bit 5
PDR8.PD84             4     Port 8 data register bit 4
PDR8.PD83             3     Port 8 data register bit 3
PDR8.PD82             2     Port 8 data register bit 2
PDR8.PD81             1     Port 8 data register bit 1
PDR8.PD80             0     Port 8 data register bit 0
PDR9                 0x000009           Port 9 data register
PDR9.PD97             15    Port 9 data register bit 15
PDR9.PD96             14    Port 9 data register bit 14
PDR9.PD95             13    Port 9 data register bit 13
PDR9.PD94             12    Port 9 data register bit 12
PDR9.PD93             11    Port 9 data register bit 11
PDR9.PD92             10    Port 9 data register bit 10
PDR9.PD91             9     Port 9 data register bit 9 
PDR9.PD90             8     Port 9 data register bit 8 
PDRA                 0x00000A           Port A data register
PDRA.PDA2             2     Port A data register bit 2
PDRA.PDA1             1     Port A data register bit 1
PDRA.PDA0             0     Port A data register bit 0
DDR0                 0x000010           Port 0 direction register
DDR0.DD07             7     Port 0 data direction register bit 7
DDR0.DD06             6     Port 0 data direction register bit 6
DDR0.DD05             5     Port 0 data direction register bit 5
DDR0.DD04             4     Port 0 data direction register bit 4
DDR0.DD03             3     Port 0 data direction register bit 3
DDR0.DD02             2     Port 0 data direction register bit 2
DDR0.DD01             1     Port 0 data direction register bit 1
DDR0.DD00             0     Port 0 data direction register bit 0
DDR1                 0x000011           Port 1 direction register
DDR1.DD17             15    Port 1 data direction register bit 15
DDR1.DD16             14    Port 1 data direction register bit 14
DDR1.DD15             13    Port 1 data direction register bit 13
DDR1.DD14             12    Port 1 data direction register bit 12
DDR1.DD13             11    Port 1 data direction register bit 11
DDR1.DD12             10    Port 1 data direction register bit 10
DDR1.DD11             9     Port 1 data direction register bit 9 
DDR1.DD10             8     Port 1 data direction register bit 8 
DDR2                 0x000012           Port 2 direction register
DDR2.DD27             7     Port 2 data direction register bit 7
DDR2.DD26             6     Port 2 data direction register bit 6
DDR2.DD25             5     Port 2 data direction register bit 5
DDR2.DD24             4     Port 2 data direction register bit 4
DDR2.DD23             3     Port 2 data direction register bit 3
DDR2.DD22             2     Port 2 data direction register bit 2
DDR2.DD21             1     Port 2 data direction register bit 1
DDR2.DD20             0     Port 2 data direction register bit 0
DDR3                 0x000013           Port 3 direction register
DDR3.DD37             15    Port 3 data direction register bit 15
DDR3.DD36             14    Port 3 data direction register bit 14
DDR3.DD35             13    Port 3 data direction register bit 13
DDR3.DD34             12    Port 3 data direction register bit 12
DDR3.DD33             11    Port 3 data direction register bit 11
DDR3.DD32             10    Port 3 data direction register bit 10
DDR3.DD31             9     Port 3 data direction register bit 9 
DDR3.DD30             8     Port 3 data direction register bit 8 
DDR4                 0x000014           Port 4 direction register
DDR4.DD46             6     Port 4 data direction register bit 6
DDR4.DD45             5     Port 4 data direction register bit 5
DDR4.DD44             4     Port 4 data direction register bit 4
DDR4.DD43             3     Port 4 data direction register bit 3
DDR4.DD42             2     Port 4 data direction register bit 2
DDR4.DD41             1     Port 4 data direction register bit 1
DDR4.DD40             0     Port 4 data direction register bit 0
DDR5                 0x000015           Port 5 direction register
DDR5.DD57             15    Port 5 data direction register bit 15
DDR5.DD56             14    Port 5 data direction register bit 14
DDR5.DD55             13    Port 5 data direction register bit 13
DDR5.DD54             12    Port 5 data direction register bit 12
DDR5.DD53             11    Port 5 data direction register bit 11
DDR5.DD52             10    Port 5 data direction register bit 10
DDR5.DD51             9     Port 5 data direction register bit 9 
DDR5.DD50             8     Port 5 data direction register bit 8 
DDR6                 0x000016           Port 6 direction register
DDR6.DD67             7     Port 6 data direction register bit 7
DDR6.DD66             6     Port 6 data direction register bit 6
DDR6.DD65             5     Port 6 data direction register bit 5
DDR6.DD64             4     Port 6 data direction register bit 4
DDR6.DD63             3     Port 6 data direction register bit 3
DDR6.DD62             2     Port 6 data direction register bit 2
DDR6.DD61             1     Port 6 data direction register bit 1
DDR6.DD60             0     Port 6 data direction register bit 0
DDR7                 0x000017           Port 7 direction register
DDR7.DD74             12    Port 7 data direction register bit 12
DDR7.DD73             11    Port 7 data direction register bit 11
DDR8                 0x000018           Port 8 direction register
DDR8.DD86             6     Port 8 data direction register bit 6
DDR8.DD85             5     Port 8 data direction register bit 5
DDR8.DD84             4     Port 8 data direction register bit 4
DDR8.DD83             3     Port 8 data direction register bit 3
DDR8.DD82             2     Port 8 data direction register bit 2
DDR8.DD81             1     Port 8 data direction register bit 1
DDR8.DD80             0     Port 8 data direction register bit 0
DDR9                 0x000019           Port 9 direction register
DDR9.DD97             15    Port 9 data direction register bit 15
DDR9.DD96             14    Port 9 data direction register bit 14
DDR9.DD95             13    Port 9 data direction register bit 13
DDR9.DD94             12    Port 9 data direction register bit 12
DDR9.DD93             11    Port 9 data direction register bit 11
DDR9.DD92             10    Port 9 data direction register bit 10
DDR9.DD91             9     Port 9 data direction register bit 9 
DDR9.DD90             8     Port 9 data direction register bit 8 
DDRA                 0x00001A           Port A direction register
DDRA.DDA2             2     Port A data direction register bit 2
DDRA.DDA1             1     Port A data direction register bit 1
DDRA.DDA0             0     Port A data direction register bit 0
ODR4                 0x00001B           Port 4 pin register
ODR4.OD46             6
ODR4.OD45             5
ODR4.OD44             4
ODR4.OD43             3
ODR4.OD42             2
ODR4.OD41             1
ODR4.OD40             0
RDR0                 0x00001C           Port 0 resistance register
RDR0.RD07             7
RDR0.RD06             6
RDR0.RD05             5
RDR0.RD04             4
RDR0.RD03             3
RDR0.RD02             2
RDR0.RD01             1
RDR0.RD00             0
RDR1                 0x00001D           Port 1 resistance register
RDR1.RD17             7
RDR1.RD16             6
RDR1.RD15             5
RDR1.RD14             4
RDR1.RD13             3
RDR1.RD12             2
RDR1.RD11             1
RDR1.RD10             0
RDR6                 0x00001E           Port 6 resistance register
RDR6.RD67             7
RDR6.RD66             6
RDR6.RD65             5
RDR6.RD64             4
RDR6.RD63             3
RDR6.RD62             2
RDR6.RD61             1
RDR6.RD60             0
ADER                 0x00001F           Analog input enable register
ADER.ADE7             7
ADER.ADE6             6
ADER.ADE5             5
ADER.ADE4             4
ADER.ADE3             3
ADER.ADE2             2
ADER.ADE1             1
ADER.ADE0             0
SMR                  0x000020           Serial mode register 0
SMR.MD1               7     MoDe select 1
SMR.MD0               6     MoDe select 0
SMR.CS2               5     Clock Select 2
SMR.CS1               4     Clock Select 1
SMR.CS0               3     Clock Select 0
SMR.SCKE              1     SCIK Enable
SMR.SOE               0     Serial Output Enable
SCR                  0x000021           Serial control register 0
SCR.PEN               7     Parity ENable
SCR.P                 6     Parity
SCR.SBL               5     Stop bit length     
SCR.CL                4     Character length    
SCR.AD                3     Address/data        
SCR.REC               2     Receiver error clear
SCR.RXE               1     Receiver enable     
SCR.TXE               0     Transmitter enable  
SIDR                 0x000022           Serial input register / serial output register 0
SIDR.D6               6
SIDR.D5               5
SIDR.D4               4
SIDR.D3               3
SIDR.D2               2
SIDR.D1               1
SIDR.D0               0
SSR                  0x000023           Serial status register 0
SSR.PE                7     Parity error                   
SSR.ORE               6     Overrun error                  
SSR.FRE               5     Framing error                  
SSR.RDRF              4     Receiver data register full    
SSR.TDRE              3     Transmitter data register empty
SSR.RIE               1     Receiver interrupt enable      
SSR.TIE               0     Transmitter interrupt enable   
SMCS0                0x000024           Serial mode control status register 0
SMCS0.SMD2            15    Serial Shift Clock Mode 2
SMCS0.SMD1            14    Serial Shift Clock Mode 1
SMCS0.SMD0            13    Serial Shift Clock Mode 0
SMCS0.SIE             12    Serial I/O Interrupt Enable
SMCS0.SIR             11    Serial i/o Interrupt Request
SMCS0.BUSY            10
SMCS0.STOP            9     used to forcibly stop serial transfer
SMCS0.STRT            8     is used to start serial transfer
SMCS0.MODE            3     Activation Condition Select
SMCS0.BDS             2     Bit Direction Select
SMCS0.SOE             1     Serial Output Enable
SMCS0.SCOE            0     SCLK Output Enable
SDR0                 0x000026           Serial data register 0
CDCR                 0x000027           Clock division control register
CDCR.MD               15    Machine clock divide moDe select 
CDCR.DIV3             11    Divide 3
CDCR.DIV2             10    Divide 2
CDCR.DIV1             9     Divide 1
CDCR.DIV0             8     Divide 0
SMCS1                0x000028           Serial mode control status register 1
SMCS1.SMD2            15    Serial Shift Clock Mode 2
SMCS1.SMD1            14    Serial Shift Clock Mode 1
SMCS1.SMD0            13    Serial Shift Clock Mode 0
SMCS1.SIE             12    Serial I/O Interrupt Enable
SMCS1.SIR             11    Serial i/o Interrupt Request
SMCS1.BUSY            10
SMCS1.STOP            9     
SMCS1.STRT            8
SMCS1.MODE            3     Activation Condition Select
SMCS1.BDS             2     Bit Direction Select
SMCS1.SOE             1     Serial Output Enable
SMCS1.SCOE            0     SCLK Output Enable
SDR1                 0x00002A           Serial data register 1
ENIR                 0x000030           Interrupt/DTP enable register
ENIR.EN7              7
ENIR.EN6              6
ENIR.EN5              5
ENIR.EN4              4
ENIR.EN3              3
ENIR.EN2              2
ENIR.EN1              1
ENIR.EN0              0
EIRR                 0x000031           Interrupt/DTP source register
EIRR.ER7              7
EIRR.ER6              6
EIRR.ER5              5
EIRR.ER4              4
EIRR.ER3              3
EIRR.ER2              2
EIRR.ER1              1
EIRR.ER0              0
ELVR                 0x000032           Request level setting register
ELVR.LALB71           15
ELVR.LALB70           14
ELVR.LALB61           13
ELVR.LALB60           12
ELVR.LALB51           11
ELVR.LALB50           10
ELVR.LALB41           9
ELVR.LALB40           8
ELVR.LALB31           7
ELVR.LALB30           6
ELVR.LALB21           5
ELVR.LALB20           4
ELVR.LALB11           3
ELVR.LALB10           2
ELVR.LALB01           1
ELVR.LALB00           0
ADCS1                0x000036           Control status register 1
ADCS1.MD1             7
ADCS1.MD0             6
ADCS1.ANS2            5
ADCS1.ANS1            4
ADCS1.ANS0            3
ADCS1.ANE2            2
ADCS1.ANE1            1
ADCS1.ANE0            0    
ADCS2                0x000037           Control status register 2
ADCS2.BUSY            7     Busy flag and stop
ADCS2.INT             6     Interrupt
ADCS2.INTE            5     INTerrupt Enable
ADCS2.PAUS            4     a/d converter PAUSe
ADCS2.STS1            3     Start Source select 1
ADCS2.STS0            2     Start Source select 0
ADCS2.STRT            1     StaRT
ADCR12               0x000038           Data register 1/2
DADR0                0x00003A           D/A converter data register 0
DADR1                0x00003B           D/A converter data register 1
DACR0                0x00003C           D/A control register channel 0
DACR0.DAE0            0
DACR1                0x00003D           D/A control register channel 1
DACR1.DAE1            0 
CLKR                 0x00003E           Clock control register
CLKR.CKEN             3
CLKR.FRQ2             2 
CLKR.FRQ1             1
CLKR.FRQ0             0
PRL0_PRLL            0x000040           Reload register lower channel 0
PRL0_PRL             0x000041           Reload register upper channel 0
PRL1_PRLL            0x000042           Reload register lower channel 1
PRL1_PRL             0x000043           Reload register upper channel 1
PPGC01               0x000044           PPG0 operation mode control register channel 0, channel 1
PPGC01.PEN1           15    Ppg ENable
PPGC01.PE10           13    Ppg output Enable 10
PPGC01.PIE1           12    Ppg Interrupt Enable
PPGC01.PUF1           11    Ppg Underflow Flag
PPGC01.MD1            10    ppg count MoDe 1
PPGC01.MD0            9     ppg count MoDe 0
PPGC01.PEN0           7     Ppg ENable
PPGC01.PE00           5     Ppg output Enable 00
PPGC01.PIE0           4     Ppg Interrupt Enable
PPGC01.PUF0           3     Ppg Underflow Flag  
PPGOE                0x000046           PPG0, PPG1 output control register channel 0, channel 1
PPGOE.PCS2            7     Ppg Count Select 2
PPGOE.PCS1            6     Ppg Count Select 1
PPGOE.PCS0            5     Ppg Count Select 0
PPGOE.PCM2            4     Ppg Count Mode 2
PPGOE.PCM1            3     Ppg Count Mode 1
PPGOE.PCM0            2     Ppg Count Mode 0
PPGOE.PE11            1     Ppg output Enable 11
PPGOE.PE01            0     Ppg output Enable 01
OCCP0                0x000050           compare register channel 0
OCCP1                0x000052           compare register channel 1
OCCP2                0x000054           compare register channel 2
OCCP3                0x000056           compare register channel 3
OCS01                0x000058           Compare control status register channel 0/1
OCS01.CMOD            12
OCS01.OTE1            11
OCS01.OTE0            10
OCS01.OTD1            9 
OCS01.OTD0            8 
OCS01.ICP1            7 
OCS01.ICP0            6 
OCS01.ICE1            5 
OCS01.ICE0            4 
OCS01.CST1            1 
OCS01.CST0            0 
OCS23                0x00005A           Compare control status register channel 2/3
OCS23.CMOD            12
OCS23.OTE1            11
OCS23.OTE0            10
OCS23.OTD1            9 
OCS23.OTD0            8 
OCS23.ICP1            7 
OCS23.ICP0            6 
OCS23.ICE1            5 
OCS23.ICE0            4 
OCS23.CST1            1 
OCS23.CST0            0 
IPCP0                0x000060           input capture register channel 0
IPCP1                0x000062           input capture register channel 1
ICS01                0x000064           Input capture control status register
ICS01.ICP1            7     input capture interrupt flags 1
ICS01.ICP0            6     input capture interrupt flags 0
ICS01.ICE1            5     input capture interrupt enable bit 1
ICS01.ICE0            4     input capture interrupt enable bit 0
ICS01.EG11            3
ICS01.EG10            2
ICS01.EG01            1
ICS01.EG00            0
TCDT                 0x000066           timer data register
TCCS                 0x000068           Timer control status register
TCCS.IVF              6
TCCS.IVFE             5
TCCS.STOP             4
TCCS.MODE             3
TCCS.CLR              2
TCCS.CLK1             1
TCCS.CLK0             0
UDCR_UDCR0           0x000070           Up/down count register channel 0
UDCR_UDCR1           0x000071           Up/down count register channel 1
RCR                  0x000072           Reload compare register channel 0/1
CSR0                 0x000074           Counter status register channel 0
CSR0.CSTR             7     Count Start Bit
CSR0.CITE             6     Compare Interrupt Output Control Bit
CSR0.UDIE             5     Overflow/Underflow Interrupt Output Control Bit
CSR0.CMPF             4     Compare Detection Flag
CSR0.OVFF             3     Overflow Detection Flag
CSR0.UDFF             2     Underflow Detection Flag
CSR0.UDF1             1     Up/Down Flag 1
CSR0.UDF0             0     Up/Down Flag 0
CCR0                 0x000076           Counter control register channel 0
CCR0.M16E             15
CCR0.CDCF             14
CCR0.CFIE             13
CCR0.CLKS             12
CCR0.CMS1             11
CCR0.CMS0             10
CCR0.CES1             9
CCR0.CES0             8
CCR0.CTUT             6     Counter Write Bit
CCR0.UCRE             5     UDCR Clear Enable Bit
CCR0.RLDE             4     Reload Enable Bit
CCR0.UDCC             3     UDCR Clear Bit
CCR0.CGSC             2     Counter Clear/Gate Selection Bit
CCR0.CGE1             1     Counter Clear/Gate Edge Selection Bit 1
CCR0.CGE0             0     Counter Clear/Gate Edge Selection Bit 0
CSR1                 0x000078           Counter control register channel 1
CSR1.CSTR             7     Count Start Bit
CSR1.CITE             6     Compare Interrupt Output Control Bit
CSR1.UDIE             5     Overflow/Underflow Interrupt Output Control Bit
CSR1.CMPF             4     Compare Detection Flag
CSR1.OVFF             3     Overflow Detection Flag
CSR1.UDFF             2     Underflow Detection Flag
CSR1.UDF1             1     Up/Down Flag 1
CSR1.UDF0             0     Up/Down Flag 0
CCR1                 0x00007A           Counter control register channel 1
CCR1.CDCF             14
CCR1.CFIE             13
CCR1.CLKS             12
CCR1.CMS1             11
CCR1.CMS0             10
CCR1.CES1             9
CCR1.CES0             8
CCR1.CTUT             6     Counter Write Bit
CCR1.UCRE             5     UDCR Clear Enable Bit
CCR1.RLDE             4     Reload Enable Bit
CCR1.UDCC             3     UDCR Clear Bit
CCR1.CGSC             2     Counter Clear/Gate Selection Bit
CCR1.CGE1             1     Counter Clear/Gate Edge Selection Bit 1
CCR1.CGE0             0     Counter Clear/Gate Edge Selection Bit 0
IBSR                 0x000080           I2C bus status register
IBSR.BB               7     Bus Busy
IBSR.RSC              6     Repeated Start Condition
IBSR.AL               5     Arbitration Lost
IBSR.LRB              4     Last Received Bit
IBSR.TRX              3     Last Received Bit
IBSR.AAS              2     Addressed As Slave
IBSR.GCA              1     General Call Address
IBSR.FBT              0     First Byte Transfer
IBCR                 0x000081           I2C bus control register
IBCR.BER              7     Bus ERror
IBCR.BEIE             6     Bus Error Interrupt Enable
IBCR.SCC              5     Start Condition Continue
IBCR.MSS              4     Master Slave Select
IBCR.ACK              3     ACKnowledge
IBCR.GCAA             2     General Call Address Acknowledge
IBCR.INTE             1     INTerrupt Enable
IBCR.INT              0     INTerrupt
ICCR                 0x000082           I2C bus clock control register
ICCR.EN               5     ENable
ICCR.CS4              4     Clock Period Select 4
ICCR.CS3              3     Clock Period Select 3
ICCR.CS2              2     Clock Period Select 2
ICCR.CS1              1     Clock Period Select 1
ICCR.CS0              0     Clock Period Select 0
IADR                 0x000083           I2C bus address register
IADR.A6               6     Slave Address Bit 6
IADR.A5               5     Slave Address Bit 5
IADR.A4               4     Slave Address Bit 4
IADR.A3               3     Slave Address Bit 3
IADR.A2               2     Slave Address Bit 2
IADR.A1               1     Slave Address Bit 1
IADR.A0               0     Slave Address Bit 0
IDAR                 0x000084           I2C bus data register
DTMC                 0x000088           DTMF control register
DTMD                 0x000089           DTMF data register
DIRR                 0x00009F           Delayed interrupt generation/release register
DIRR.R0               0
LPMCR                0x0000A0           Low-power consumption mode control register
LPMCR.STP             7
LPMCR.SLP             6
LPMCR.SPL             5
LPMCR.RST             4
LPMCR.TMD             3
LPMCR.CG1             2
LPMCR.CG0             1
LPMCR.SSR             0
CKSCR                0x0000A1           Clock selection register
CKSCR.SCM             7
CKSCR.MCM             6
CKSCR.WS1             5
CKSCR.WS0             4
CKSCR.SCS             3
CKSCR.MCS             2
CKSCR.CS1             1
CKSCR.CS0             0
ARSR                 0x0000A5           Auto-ready function selection register
HACR                 0x0000A6           External address output control register
ECSR                 0x0000A7           Bus control signal selection register
WDTC                 0x0000A8           Watchdog timer control register
WDTC.PONR             7
WDTC.WRST             5
WDTC.ERST             4
WDTC.SRST             3
TBTC                 0x0000A9           Timebase timer control register
TBTC.TBIE             4
TBTC.TBOF             3
TBTC.TBR              2
TBTC.TBC1             1
TBTC.TBC0             0
WTC                  0x0000AA           Watch timer control register
WTC.WDCS              7
WTC.SCE               6
WTC.WTIE              5
WTC.WTOF              4
WTC.WTR               3
WTC.WTC2              2
WTC.WTC1              1
WTC.WTC0              0
ICR00                0x0000B0           Interrupt control register 00
ICR00.S1              5
ICR00.S0              4
ICR00.ISE             3
ICR00.IL2             2
ICR00.IL1             1
ICR00.IL0             0
ICR01                0x0000B1           Interrupt control register 01
ICR01.S1              5
ICR01.S0              4
ICR01.ISE             3
ICR01.IL2             2
ICR01.IL1             1
ICR01.IL0             0
ICR02                0x0000B2           Interrupt control register 02
ICR02.S1              5
ICR02.S0              4
ICR02.ISE             3
ICR02.IL2             2
ICR02.IL1             1
ICR02.IL0             0
ICR03                0x0000B3           Interrupt control register 03
ICR03.S1              5
ICR03.S0              4
ICR03.ISE             3
ICR03.IL2             2
ICR03.IL1             1
ICR03.IL0             0
ICR04                0x0000B4           Interrupt control register 04
ICR04.S1              5
ICR04.S0              4
ICR04.ISE             3
ICR04.IL2             2
ICR04.IL1             1
ICR04.IL0             0
ICR05                0x0000B5           Interrupt control register 05
ICR05.S1              5
ICR05.S0              4
ICR05.ISE             3
ICR05.IL2             2
ICR05.IL1             1
ICR05.IL0             0
ICR06                0x0000B6           Interrupt control register 06
ICR06.S1              5
ICR06.S0              4
ICR06.ISE             3
ICR06.IL2             2
ICR06.IL1             1
ICR06.IL0             0
ICR07                0x0000B7           Interrupt control register 07
ICR07.S1              5
ICR07.S0              4
ICR07.ISE             3
ICR07.IL2             2
ICR07.IL1             1
ICR07.IL0             0
ICR08                0x0000B8           Interrupt control register 08
ICR08.S1              5
ICR08.S0              4
ICR08.ISE             3
ICR08.IL2             2
ICR08.IL1             1
ICR08.IL0             0
ICR09                0x0000B9           Interrupt control register 09
ICR09.S1              5
ICR09.S0              4
ICR09.ISE             3
ICR09.IL2             2
ICR09.IL1             1
ICR09.IL0             0
ICR10                0x0000BA           Interrupt control register 10
ICR10.S1              5
ICR10.S0              4
ICR10.ISE             3
ICR10.IL2             2
ICR10.IL1             1
ICR10.IL0             0
ICR11                0x0000BB           Interrupt control register 11
ICR11.S1              5
ICR11.S0              4
ICR11.ISE             3
ICR11.IL2             2
ICR11.IL1             1
ICR11.IL0             0
ICR12                0x0000BC           Interrupt control register 12
ICR12.S1              5
ICR12.S0              4
ICR12.ISE             3
ICR12.IL2             2
ICR12.IL1             1
ICR12.IL0             0
ICR13                0x0000BD           Interrupt control register 13
ICR13.S1              5
ICR13.S0              4
ICR13.ISE             3
ICR13.IL2             2
ICR13.IL1             1
ICR13.IL0             0
ICR14                0x0000BE           Interrupt control register 14
ICR14.S1              5
ICR14.S0              4
ICR14.ISE             3
ICR14.IL2             2
ICR14.IL1             1
ICR14.IL0             0
ICR15                0x0000BF           Interrupt control register 15
ICR15.S1              5
ICR15.S0              4
ICR15.ISE             3
ICR15.IL2             2
ICR15.IL1             1
ICR15.IL0             0


.MB90660A
; DS07-13604-2E  http://edevice.fujitsu.com/fj/DATASHEET/e-ds/e713604.pdf
; MB90662A/663A/P663A


; ROM:           16 Kbytes (MB90661A)
;                32 Kbytes (MB90662A)
;                48 Kbytes (MB90663A)
; One-time PROM: 48 Kbytes (MB90P663A)
; RAM:          512 bytes  (MB90661A)
;              1.64 Kbytes (MB90662A)
;                 2 Kbytes (MB90663A/MB90P663A)


; MEMORY MAP
; [MB90662A]
area DATA FSR           0x000000:0x0000C0
area BSS  No_access_1   0x0000C0:0x000100
area DATA MEM_INT_1     0x000100:0x000180
area DATA RAM           0x000180:0x000380
area DATA MEM_INT_2     0x000380:0x000780
area BSS  No_access_2   0x000780:0x008000
area DATA ROM_1         0x008000:0x010000
area BSS  No_access_3   0x010000:0xFF8000
; area DATA ROM_2_BANK_FF 0xFF8000:0x1000000

; [MB90663A/MB90P663A]
; area DATA FSR           0x000000:0x0000C0
; area BSS  No_access_1   0x0000C0:0x000100
; area DATA MEM_INT_1     0x000100:0x000180
; area DATA RAM           0x000180:0x000380
; area DATA MEM_INT_2     0x000380:0x000900
; area BSS  No_access_2   0x000900:0x004000
; area DATA ROM_1         0x004000:0x010000
; area BSS  No_access_3   0x010000:0xFF4000
; area DATA ROM_2_BANK_FF 0xFF4000:0x1000000


; Interrupt and reset vector assignments
interrupt __RESET       0xFFFFDC       Reset 
interrupt INT9          0xFFFFD8       INT9 instruction 
interrupt EXCEPT        0xFFFFD4       Exception 
interrupt MF_TIMER      0xFFFFCC       Multi-function timer DTTI input 
interrupt EI0           0xFFFFC8       External interrupt 0 
interrupt EI4           0xFFFFC4       External interrupt 4 
interrupt MF_TIMER_TI   0xFFFFC0       Multi-function timer trigger input or zero detect 
interrupt MF_TIMER_ZD   0xFFFFB8       Multi-function timer zero detect 
interrupt MF_TIMER_O    0xFFFFB0       Multi-function timer overflow, compare clear or zero detect 
interrupt EI1           0xFFFFA8       External interrupt 1 
interrupt MF_TIMER_CM   0xFFFFA4       Multi-function timer compare match 
interrupt EI5           0xFFFFA0       External interrupt 5 
interrupt PWM_U         0xFFFF9C       PWM underflow 
interrupt EI2           0xFFFF98       External interrupt 2 
interrupt EI6           0xFFFF94       External interrupt 6 
interrupt R_TIMER0      0xFFFF90       16-bit reload timer 0 
interrupt R_TIMER1      0xFFFF8C       16-bit reload timer 1 
interrupt R_TIMER2      0xFFFF88       16-bit reload timer 2 
interrupt R_TIMER3      0xFFFF84       16-bit reload timer 3 
interrupt END_A_D_CC    0xFFFF80       End of A/D converter conversion 
interrupt T_TIMER_II    0xFFFF74       Timebase timer interval interrupt 
interrupt UART_S        0xFFFF70       UART send complete 
interrupt UART_R        0xFFFF68       UART receive complete 
interrupt EI3           0xFFFF60       External interrupt 3 
interrupt EI7           0xFFFF5C       External interrupt 7 
interrupt DELAY         0xFFFF54       Delayed interrupt generator module 


; INPUT/OUTPUT PORTS
PDR0                 0x000000           Port 0 data register
PDR0.PD07             7
PDR0.PD06             6
PDR0.PD05             5
PDR0.PD04             4
PDR0.PD03             3
PDR0.PD02             2
PDR0.PD01             1
PDR0.PD00             0
PDR1                 0x000001           Port 1 data register
PDR1.PD17             7
PDR1.PD16             6
PDR1.PD15             5
PDR1.PD14             4
PDR1.PD13             3
PDR1.PD12             2
PDR1.PD11             1
PDR1.PD10             0
PDR2                 0x000002           Port 2 data register
PDR2.PD27             7
PDR2.PD26             6
PDR2.PD25             5
PDR2.PD24             4
PDR2.PD23             3
PDR2.PD22             2
PDR2.PD21             1
PDR2.PD20             0
PDR3                 0x000003           Port 3 data register
PDR3.PD37             7
PDR3.PD36             6
PDR3.PD35             5
PDR3.PD34             4
PDR3.PD33             3
PDR3.PD32             2
PDR3.PD31             1
PDR3.PD30             0
PDR4                 0x000004           Port 4 data register
PDR4.PD47             7
PDR4.PD46             6
PDR4.PD45             5
PDR4.PD44             4
PDR4.PD43             3
PDR4.PD42             2
PDR4.PD41             1
PDR4.PD40             0
PDR5                 0x000005           Port 5 data register
PDR5.PD57             7
PDR5.PD56             6
PDR5.PD55             5
PDR5.PD54             4
PDR5.PD53             3
PDR5.PD52             2
PDR5.PD51             1
PDR5.PD50             0
PDR6                 0x000006           Port 6 data register / Port data buffer register
PDR6.PD67             7
PDR6.PD66             6
PDR6.PD65             5
PDR6.PD64             4
PDR6.PD63             3
PDR6.PD62             2
PDR6.PD61             1
PDR6.PD60             0
DDR0                 0x000010           Port 0 direction register
DDR0.DD07             7
DDR0.DD06             6
DDR0.DD05             5
DDR0.DD04             4
DDR0.DD03             3
DDR0.DD02             2
DDR0.DD01             1
DDR0.DD00             0
DDR1                 0x000011           Port 1 direction register
DDR1.DD17             7
DDR1.DD16             6
DDR1.DD15             5
DDR1.DD14             4
DDR1.DD13             3
DDR1.DD12             2
DDR1.DD11             1
DDR1.DD10             0
DDR2                 0x000012           Port 2 direction register
DDR2.DD27             7
DDR2.DD26             6
DDR2.DD25             5
DDR2.DD24             4
DDR2.DD23             3
DDR2.DD22             2
DDR2.DD21             1
DDR2.DD20             0
DDR3                 0x000013           Port 3 direction register
DDR3.DD33             3
DDR3.DD32             2
DDR3.DD31             1
DDR3.DD30             0
DDR4                 0x000014           Port 4 direction register
DDR4.DD43             3
DDR4.DD42             2
DDR4.DD41             1
DDR4.DD40             0
ADER                 0x000015           Analog input enable register
ADER.ADE7             7
ADER.ADE6             6
ADER.ADE5             5
ADER.ADE4             4
ADER.ADE3             3
ADER.ADE2             2
ADER.ADE1             1
ADER.ADE0             0
DDR6                 0x000016           Port 6 direction register
DDR6.DD66             6
DDR6.DD65             5
DDR6.DD64             4
DDR6.DD63             3
DDR6.DD62             2
DDR6.DD61             1
DDR6.DD60             0
PWMC                 0x000020           PWM operation mode control register
PWMC.PEN              7
PWMC.PCKS             6
PWMC.POE              5
PWMC.PIE              4
PWMC.PUF              3
IO_PRL_PRLL          0x000022           PWM reload register
IO_PRL_PRLH          0x000023           PWM reload register
SMR                  0x000024           Serial mode register
SMR.MD1               7
SMR.MD0               6
SMR.CS2               5
SMR.CS1               4
SMR.CS0               3
SMR.SCKE              1
SMR.SOE               0
SCR                  0x000025           Serial control register
SCR.PEN               7
SCR.P                 6
SCR.SBL               5
SCR.CL                4
SCR.AD                3
SCR.REC               2
SCR.RXE               1
SCR.TXE               0
SIDR                 0x000026           Serial input data register / Serial output data register
SIDR.D6               6
SIDR.D5               5
SIDR.D4               4
SIDR.D3               3
SIDR.D2               2
SIDR.D1               1
SIDR.D0               0
SSR                  0x000027           Serial status register
SSR.PE                7
SSR.ORE               6
SSR.FRE               5
SSR.RDRF              4
SSR.TDRE              3
SSR.RIE               1
SSR.TIE               0
ENIR                 0x000028           Interrupt enable register
ENIR.EN7              7
ENIR.EN6              6
ENIR.EN5              5
ENIR.EN4              4
ENIR.EN3              3
ENIR.EN2              2
ENIR.EN1              1
ENIR.EN0              0
EIRR                 0x000029           Interrupt source register
EIRR.ER7              7
EIRR.ER6              6
EIRR.ER5              5
EIRR.ER4              4
EIRR.ER3              3
EIRR.ER2              2
EIRR.ER1              1
EIRR.ER0              0
ELVR                 0x00002A           Request level setting register
ELVR.LALB71           15
ELVR.LALB70           14
ELVR.LALB61           13
ELVR.LALB60           12
ELVR.LALB51           11
ELVR.LALB50           10
ELVR.LALB41           9
ELVR.LALB40           8
ELVR.LALB31           7
ELVR.LALB30           6
ELVR.LALB21           5
ELVR.LALB20           4
ELVR.LALB11           3
ELVR.LALB10           2
ELVR.LALB01           1
ELVR.LALB00           0
ADCS1                0x00002C           A/D control status register
ADCS1.MD1             7
ADCS1.MD0             6
ADCS1.ANS2            5
ADCS1.ANS1            4
ADCS1.ANS0            3
ADCS1.ANE2            2
ADCS1.ANE1            1
ADCS1.ANE0            0    
ADCS2                0x00002D           A/D control status register
ADCS2.BUSY            7
ADCS2.INT             6
ADCS2.INTE            5
ADCS2.PAUS            4
ADCS2.STS1            3
ADCS2.STS0            2
ADCS2.STRT            1
ADCR12               0x00002E           A/D data register
ADCR12.S10            15
ADCR12.D9             9
ADCR12.D8             8
ADCR12.D7             7
ADCR12.D6             6
ADCR12.D5             5
ADCR12.D4             4
ADCR12.D3             3
ADCR12.D2             2
ADCR12.D1             1
ADCR12.D0             0
TMCSR0               0x000030           Control status register
TMCSR0.CSL1           11
TMCSR0.CSL0           10
TMCSR0.MOD2           9
TMCSR0.MOD1           8
TMCSR0.MOD0           7
TMCSR0.OUTL           5
TMCSR0.RELD           4
TMCSR0.INTE           3
TMCSR0.UF             2
TMCSR0.CNTE           1
TMCSR0.TRG            0
TMR0                 0x000032           16-bit timer register / 16-bit reload register
TMCSR1               0x000034           Control status register
TMCSR1.CSL1           11
TMCSR1.CSL0           10
TMCSR1.MOD2           9
TMCSR1.MOD1           8
TMCSR1.MOD0           7
TMCSR1.OUTL           5
TMCSR1.RELD           4
TMCSR1.INTE           3
TMCSR1.UF             2
TMCSR1.CNTE           1
TMCSR1.TRG            0
TMR1                 0x000036           16-bit timer register / 16-bit reload register
TMCSR2               0x000038           Control status register
TMCSR2.CSL1           11
TMCSR2.CSL0           10
TMCSR2.MOD2           9
TMCSR2.MOD1           8
TMCSR2.MOD0           7
TMCSR2.OUTL           5
TMCSR2.RELD           4
TMCSR2.INTE           3
TMCSR2.UF             2
TMCSR2.CNTE           1
TMCSR2.TRG            0
TMR2                 0x00003A           16-bit timer register / 16-bit reload register
TMCSR3               0x00003C           Control status register
TMCSR3.CSL1           11
TMCSR3.CSL0           10
TMCSR3.MOD2           9
TMCSR3.MOD1           8
TMCSR3.MOD0           7
TMCSR3.OUTL           5
TMCSR3.RELD           4
TMCSR3.INTE           3
TMCSR3.UF             2
TMCSR3.CNTE           1
TMCSR3.TRG            0
TMR3                 0x00003E           16-bit timer register / 16-bit reload register
TCSR                 0x000040           Timer control status register
TCSR.STCR             7
TCSR.IIOS             6
TCSR.TCIE             5
TCSR.TCIR             4
TCSR.TZIE             3
TCSR.TZIR             2
TCSR.TMIE             1
TCSR.TMIR             0
CICR                 0x000041           Compare interrupt control register
CICR.CIE3             7
CICR.CIE2             6
CICR.CIE1             5
CICR.CIE0             4
CICR.CIR3             3
CICR.CIR2             2
CICR.CIR1             1
CICR.CIR0             0
TMCR                 0x000042           Timer mode control register
TMCR.TMST             7
TMCR.CES1             3
TMCR.CES0             2
TMCR.TCS1             1
TMCR.TCS0             0
COER                 0x000043           Compare/data select register
COER.RTO3             3
COER.RTO2             2
COER.RTO1             1
COER.RTO0             0
CMCR                 0x000044           Compare buffer mode control register
CMCR.TREN             3
CMCR.TMSK             2
CMCR.BFS1             1
CMCR.BFS0             0
ZOCTR                0x000045           Zero detect output control register
OCTBR                0x000046           Output control buffer register
OCTBR.RO31            7
OCTBR.RO30            6
OCTBR.RO21            5
OCTBR.RO20            4
OCTBR.RO11            3
OCTBR.RO10            2
OCTBR.RO01            1
OCTBR.RO00            0
ZICR                 0x000047           Zero detect interrupt control register
ZICR.IME              7 
OCPBR0               0x000048           Output compare buffer register 0
OCPBR1               0x00004A           Output compare buffer register 1
OCPBR2               0x00004C           Output compare buffer register 2
OCPBR3               0x00004E           Output compare buffer register 3
CLRBR                0x000050           Compare clear buffer register
DTCR                 0x000052           Dead time control register
DTCR.DTIE             3
DTCR.DTIF             2
DTCR.DT1              1
DTCR.DT0              0
DTSR                 0x000053           Dead time setting register
DTCMR                0x000054           Dead time compare register
TPCR0                0x000056           Timer pin control register
TPCR0.OTE1            6
TPCR0.CS11            5
TPCR0.CS10            4
TPCR0.OTE0            2
TPCR0.CS01            1
TPCR0.CS00            0
TPCR1                0x000057           Timer pin control register
TPCR1.OTE3            7
TPCR1.CS32            6
TPCR1.CS31            5
TPCR1.CS30            4
TPCR1.OTE2            3
TPCR1.CS22            2
TPCR1.CS21            1
TPCR1.CS20            0
CDCR                 0x00005F           Machine clock division control register
CDCR.DIV3             3
CDCR.DIV2             2
CDCR.DIV1             1
CDCR.DIV0             0
DIRR                 0x00009F           Delayed interrupt source generate/cancel register
DIRR.R0               0
LPMCR                0x0000A0           Low power mode control register
LPMCR.STP             7
LPMCR.SLP             6
LPMCR.SPL             5
LPMCR.RST             4
LPMCR.CG1             2
LPMCR.CG0             1
CKSCR                0x0000A1           Clock select register
CKSCR.MCM             6
CKSCR.WS1             5
CKSCR.WS0             4
CKSCR.MCS             2
CKSCR.CS1             1
CKSCR.CS0             0
WDTC                 0x0000A8           Watchdog timer control register
WDTC.PONR             7
WDTC.WRST             5
WDTC.ERST             4
WDTC.SRST             3
TBTC                 0x0000A9           Timebase timer control register
TBTC.TBIE             4
TBTC.TBOF             3
TBTC.TBR              2
TBTC.TBC1             1
TBTC.TBC0             0
ICR00                0x0000B0           Interrupt control register 00
ICR00.S1              5
ICR00.S0              4
ICR00.ISE             3
ICR00.IL2             2
ICR00.IL1             1
ICR00.IL0             0
ICR01                0x0000B1           Interrupt control register 01
ICR01.S1              5
ICR01.S0              4
ICR01.ISE             3
ICR01.IL2             2
ICR01.IL1             1
ICR01.IL0             0
ICR02                0x0000B2           Interrupt control register 02
ICR02.S1              5
ICR02.S0              4
ICR02.ISE             3
ICR02.IL2             2
ICR02.IL1             1
ICR02.IL0             0
ICR03                0x0000B3           Interrupt control register 03
ICR03.S1              5
ICR03.S0              4
ICR03.ISE             3
ICR03.IL2             2
ICR03.IL1             1
ICR03.IL0             0
ICR04                0x0000B4           Interrupt control register 04
ICR04.S1              5
ICR04.S0              4
ICR04.ISE             3
ICR04.IL2             2
ICR04.IL1             1
ICR04.IL0             0
ICR05                0x0000B5           Interrupt control register 05
ICR05.S1              5
ICR05.S0              4
ICR05.ISE             3
ICR05.IL2             2
ICR05.IL1             1
ICR05.IL0             0
ICR06                0x0000B6           Interrupt control register 06
ICR06.S1              5
ICR06.S0              4
ICR06.ISE             3
ICR06.IL2             2
ICR06.IL1             1
ICR06.IL0             0
ICR07                0x0000B7           Interrupt control register 07
ICR07.S1              5
ICR07.S0              4
ICR07.ISE             3
ICR07.IL2             2
ICR07.IL1             1
ICR07.IL0             0
ICR08                0x0000B8           Interrupt control register 08
ICR08.S1              5
ICR08.S0              4
ICR08.ISE             3
ICR08.IL2             2
ICR08.IL1             1
ICR08.IL0             0
ICR09                0x0000B9           Interrupt control register 09
ICR09.S1              5
ICR09.S0              4
ICR09.ISE             3
ICR09.IL2             2
ICR09.IL1             1
ICR09.IL0             0
ICR10                0x0000BA           Interrupt control register 10
ICR10.S1              5
ICR10.S0              4
ICR10.ISE             3
ICR10.IL2             2
ICR10.IL1             1
ICR10.IL0             0
ICR11                0x0000BB           Interrupt control register 11
ICR11.S1              5
ICR11.S0              4
ICR11.ISE             3
ICR11.IL2             2
ICR11.IL1             1
ICR11.IL0             0
ICR12                0x0000BC           Interrupt control register 12
ICR12.S1              5
ICR12.S0              4
ICR12.ISE             3
ICR12.IL2             2
ICR12.IL1             1
ICR12.IL0             0
ICR13                0x0000BD           Interrupt control register 13
ICR13.S1              5
ICR13.S0              4
ICR13.ISE             3
ICR13.IL2             2
ICR13.IL1             1
ICR13.IL0             0
ICR14                0x0000BE           Interrupt control register 14
ICR14.S1              5
ICR14.S0              4
ICR14.ISE             3
ICR14.IL2             2
ICR14.IL1             1
ICR14.IL0             0
ICR15                0x0000BF           Interrupt control register 15
ICR15.S1              5
ICR15.S0              4
ICR15.ISE             3
ICR15.IL2             2
ICR15.IL1             1
ICR15.IL0             0


.MB90670
; http://edevice.fujitsu.com/fj/DATASHEET/e-ds/e713602.pdf
; MB90671/672/673/T673/P673


; ROM:  16 Kbytes (MB90671)
;       32 Kbytes (MB90672)
;       48 Kbytes (MB90673)
;       48 Kbytes (MB90P673)
; RAM: 640 bytes  (MB90671)
;     1.64 Kbytes (MB90672)
;        2 Kbytes (MB90673/MB90T673/MB90P673)


; MEMORY MAP
; [MB90671]
area DATA FSR           0x000000:0x0000C0
area BSS  Inhibited_1   0x0000C0:0x000100
area DATA RAM           0x000100:0x000380
area BSS  Inhibited_2   0x000380:0x00C000
area DATA ROM_1         0x00C000:0x010000
area BSS  Inhibited_3   0x010000:0xFFC000
; area DATA ROM_2_BANK_FC 0xFC0000:0xFD0000
; area DATA ROM_2_BANK_FD 0xFD0000:0xFE0000
; area DATA ROM_2_BANK_FE 0xFE0000:0xFF0000
; area DATA ROM_2_BANK_FF 0xFF0000:0x1000000

; [MB90672]
; area DATA FSR           0x000000:0x0000C0
; area BSS  Inhibited_1   0x0000C0:0x000100
; area DATA RAM           0x000100:0x000780
; area BSS  Inhibited_2   0x000780:0x008000
; area DATA ROM_1         0x008000:0x010000
; area BSS  Inhibited_3   0x010000:0xFF8000
; area DATA ROM_2_BANK_FF 0xFF8000:0x1000000

; [MB90673/MB90P673]
; area DATA FSR           0x000000:0x0000C0
; area BSS  Inhibited_1   0x0000C0:0x000100
; area DATA RAM           0x000100:0x000900
; area BSS  Inhibited_2   0x000900:0x004000
; area DATA ROM_1         0x004000:0x010000
; area BSS  Inhibited_3   0x010000:0xFF4000
; area DATA ROM_2_BANK_FF 0xFF4000:0x1000000


; Interrupt and reset vector assignments
interrupt __RESET       0xFFFFDC   Reset 
interrupt INT9          0xFFFFD8   INT9 instruction 
interrupt EXCEPT        0xFFFFD4   Exception 
interrupt DTP_EIC_CH0   0xFFFFD0   DTP/external interrupt circuit Channel 0 
interrupt DTP_EIC_CH1   0xFFFFCC   DTP/external interrupt circuit Channel 1 
interrupt DTP_EIC_CH2   0xFFFFC8   DTP/external interrupt circuit Channel 2 
interrupt DTP_EIC_CH3   0xFFFFC4   DTP/external interrupt circuit Channel 3 
interrupt OC_CH0        0xFFFFC0   Output compare Channel 0 
interrupt OC_CH1        0xFFFFBC   Output compare Channel 1 
interrupt OC_CH2        0xFFFFB8   Output compare Channel 2 
interrupt OC_CH3        0xFFFFB4   Output compare Channel 3 
interrupt OC_CH4        0xFFFFB0   Output compare Channel 4 
interrupt OC_CH5        0xFFFFAC   Output compare Channel 5 
interrupt OC_CH6        0xFFFFA8   Output compare Channel 6 
interrupt OC_CH7        0xFFFFA4   Output compare Channel 7 
interrupt F_TIMER_O     0xFFFFA0   24-bit free-run timer Overflow 
interrupt F_TIMER_IB    0xFFFF9C   24-bit free-run timer Intermediate bit 
interrupt IC_CH0        0xFFFF98   Input capture Channel 0 
interrupt IC_CH1        0xFFFF94   Input capture Channel 1 
interrupt IC_CH2        0xFFFF90   Input capture Channel 2 
interrupt IC_CH3        0xFFFF8C   Input capture Channel 3 
interrupt R_TIMER0      0xFFFF88   16-bit reload timer/8/16-bit PPG timer 0 
interrupt R_TIMER1      0xFFFF84   16-bit reload timer/8/16-bit PPG timer 1 
interrupt A_D_CMMC      0xFFFF80   8/10-bit A/D converter measure-ment complete 
interrupt WAKE_AP       0xFFFF78   Wake-up interrupt 
interrupt T_TIMER_II    0xFFFF74   Timebase timer interval interrupt 


; INPUT/OUTPUT PORTS
PDR0                 0x000000           Port 0 data register
PDR0.PD07             7
PDR0.PD06             6
PDR0.PD05             5
PDR0.PD04             4
PDR0.PD03             3
PDR0.PD02             2
PDR0.PD01             1
PDR0.PD00             0
PDR1                 0x000001           Port 1 data register
PDR1.PD17             7
PDR1.PD16             6
PDR1.PD15             5
PDR1.PD14             4
PDR1.PD13             3
PDR1.PD12             2
PDR1.PD11             1
PDR1.PD10             0
PDR2                 0x000002           Port 2 data register
PDR2.PD27             7
PDR2.PD26             6
PDR2.PD25             5
PDR2.PD24             4
PDR2.PD23             3
PDR2.PD22             2
PDR2.PD21             1
PDR2.PD20             0
PDR3                 0x000003           Port 3 data register
PDR3.PD37             7
PDR3.PD36             6
PDR3.PD35             5
PDR3.PD34             4
PDR3.PD33             3
PDR3.PD32             2
PDR3.PD31             1
PDR3.PD30             0
PDR4                 0x000004           Port 4 data register
PDR4.PD47             7
PDR4.PD46             6
PDR4.PD45             5
PDR4.PD44             4
PDR4.PD43             3
PDR4.PD42             2
PDR4.PD41             1
PDR4.PD40             0
PDR5                 0x000005           Port 5 data register
PDR5.PD57             7
PDR5.PD56             6
PDR5.PD55             5
PDR5.PD54             4
PDR5.PD53             3
PDR5.PD52             2
PDR5.PD51             1
PDR5.PD50             0
PDR6                 0x000006           Port 6 data register
PDR6.PD67             7
PDR6.PD66             6
PDR6.PD65             5
PDR6.PD64             4
PDR6.PD63             3
PDR6.PD62             2
PDR6.PD61             1
PDR6.PD60             0
PDR7                 0x000007           Port 7 data register
PDR7.PD77             7      
PDR7.PD76             6
PDR7.PD75             5
PDR7.PD74             4
PDR7.PD73             3
PDR7.PD72             2
PDR7.PD71             1
PDR7.PD70             0
PDR8                 0x000008           Port 8 data register
PDR9                 0x000009           Port 9 data register
PDRA                 0x00000A           Port A data register
PDRB                 0x00000B           Port B data register
EIFR                 0x00000F           Wake-up interrupt flag register
EIFR.WIF              0
DDR0                 0x000010           Port 0 data direction register
DDR0.DD07             7
DDR0.DD06             6
DDR0.DD05             5
DDR0.DD04             4
DDR0.DD03             3
DDR0.DD02             2
DDR0.DD01             1
DDR0.DD00             0
DDR1                 0x000011           Port 1 data direction register
DDR1.DD17             7
DDR1.DD16             6
DDR1.DD15             5
DDR1.DD14             4
DDR1.DD13             3
DDR1.DD12             2
DDR1.DD11             1
DDR1.DD10             0
DDR2                 0x000012           Port 4 data direction register
DDR2.DD27             7
DDR2.DD26             6
DDR2.DD25             5
DDR2.DD24             4
DDR2.DD23             3
DDR2.DD22             2
DDR2.DD21             1
DDR2.DD20             0
DDR3                 0x000013           Port 3 data direction register
DDR3.DD37             7
DDR3.DD36             6
DDR3.DD35             5
DDR3.DD34             4
DDR3.DD33             3
DDR3.DD32             2
DDR3.DD31             1
DDR3.DD30             0
DDR4                 0x000014           Port 4 data direction register
DDR4.DD47             7
DDR4.DD46             6
DDR4.DD45             5
DDR4.DD44             4
DDR4.DD43             3
DDR4.DD42             2
DDR4.DD41             1
DDR4.DD40             0
ADER                 0x000015           Analog input enable register
ADER.ADE7             7
ADER.ADE6             6
ADER.ADE5             5
ADER.ADE4             4
ADER.ADE3             3
ADER.ADE2             2
ADER.ADE1             1
ADER.ADE0             0
DDR6                 0x000016           Port 6 data direction register
DDR6.DD67             7
DDR6.DD66             6
DDR6.DD65             5
DDR6.DD64             4
DDR6.DD63             3
DDR6.DD62             2
DDR6.DD61             1
DDR6.DD60             0
DDR7                 0x000017           Port 7 data direction register
DDR7.DD77             7
DDR7.DD76             6
DDR7.DD75             5
DDR7.DD74             4
DDR7.DD73             3
DDR7.DD72             2
DDR7.DD71             1
DDR7.DD70             0
DDR8                 0x000018           Port 8 data direction register
DDRA                 0x00001A           Port A data direction register
DDRB                 0x00001B           Port B data direction register
EICR                 0x00001F           Wake-up interrupt enable register
UMC                  0x000020           Mode control register 0
UMC.PEN               7
UMC.SBL               6
UMC.MC1               5
UMC.MC0               4
UMC.SMDE              3
UMC.RFC               2
UMC.SCKE              1
UMC.SOE               0
USR0                 0x000021           Status register 0
USR0.RDRF             7
USR0.ORFE             6
USR0.PE               5
USR0.TDRE             4
USR0.RIE              3
USR0.TIE              2
USR0.RBF              1
USR0.TBF              0
UIDR                 0x000022           Input data register 0 / output data register 0
UIDR.D6               6
UIDR.D5               5
UIDR.D4               4
UIDR.D3               3
UIDR.D2               2
UIDR.D1               1
UIDR.D0               0
URD                  0x000023           Rate and data register 0
URD.BCH               7
URD.RC3               6
URD.RC2               5
URD.RC1               4
URD.RC0               3
URD.BCH0              2
URD.P                 1
URD.D8                0
SMR                  0x000024           Mode register 1
SMR.MD1               7
SMR.MD0               6
SMR.CS2               5
SMR.CS1               4
SMR.CS0               3
SMR.BCH               2
SMR.SCKE              1
SMR.SOE               0
SCR                  0x000025           Control register 1
SCR.PEN               7
SCR.P                 6
SCR.SBL               5
SCR.CL                4
SCR.AD                3
SCR.REC               2
SCR.RXE               1
SCR.TXE               0
SIDR                 0x000026           Input data register 1 / output data register 1
SIDR.D6               6
SIDR.D5               5
SIDR.D4               4
SIDR.D3               3
SIDR.D2               2
SIDR.D1               1
SIDR.D0               0
SSR                  0x000027           Status register 1
SSR.PE                7
SSR.ORE               6
SSR.FRE               5
SSR.RDRF              4
SSR.TDRE              3
SSR.RIE               1
SSR.TIE               0
ENIR                 0x000028           DTP/interrupt enable register
ENIR.EN3              3
ENIR.EN2              2
ENIR.EN1              1
ENIR.EN0              0
EIRR                 0x000029           DTP/interrupt factor register
EIRR.ER3              3
EIRR.ER2              2
EIRR.ER1              1
EIRR.ER0              0
ELVR                 0x00002A           Request level setting register
ELVR.LALB31           7
ELVR.LALB30           6
ELVR.LALB21           5
ELVR.LALB20           4
ELVR.LALB11           3
ELVR.LALB10           2
ELVR.LALB01           1
ELVR.LALB00           0
ADCS1                0x00002C           A/D convertor control status register
ADCS1.MD1             7
ADCS1.MD0             6
ADCS1.ANS2            5
ADCS1.ANS1            4
ADCS1.ANS0            3
ADCS1.ANE2            2
ADCS1.ANE1            1
ADCS1.ANE0            0    
ADCS2                0x00002D           A/D convertor control status reg-ister
ADCS2.BUSY            7
ADCS2.INT             6
ADCS2.INTE            5
ADCS2.PAUS            4
ADCS2.STS1            3
ADCS2.STS0            2
ADCS2.STRT            1
ADCR12               0x00002E           A/D convertor data register
ADCR12.S10            15
ADCR12.D9             9
ADCR12.D8             8
ADCR12.D7             7
ADCR12.D6             6
ADCR12.D5             5
ADCR12.D4             4
ADCR12.D3             3
ADCR12.D2             2
ADCR12.D1             1
ADCR12.D0             0
PPGC01               0x000030           PPG0/PPG1 operating mode control register
PPGC01.PEN1           15
PPGC01.PCS1           14
PPGC01.PE10           13
PPGC01.PIE1           12
PPGC01.PUF1           11
PPGC01.MD1            10
PPGC01.MD0            9
PPGC01.PEN0           7
PPGC01.PE00           5
PPGC01.PIE0           4
PPGC01.PUF0           3
PPGC01.PCM1           2
PPGC01.PCM0           1
PRL0_PRLL            0x000034           PPG0 reload register
PRL0_PRLH            0x000035           PPG0 reload register
PRL1_PRLL            0x000036           PPG1 reload register
PRL1_PRLH            0x000037           PPG1 reload register
TMCSR0               0x000038           Timer control status register 0
TMCSR0.CSL1           11
TMCSR0.CSL0           10
TMCSR0.MOD2           9
TMCSR0.MOD1           8
TMCSR0.MOD0           7
TMCSR0.OUTE           6
TMCSR0.OUTL           5
TMCSR0.RELD           4
TMCSR0.INTE           3
TMCSR0.UF             2
TMCSR0.CNTE           1
TMCSR0.TRG            0
TMR0                 0x00003A           16-bit timer register 0 / 16-bit reload register 0
TMCSR1               0x00003C           Timer control status register 1
TMCSR1.CSL1           11
TMCSR1.CSL0           10
TMCSR1.MOD2           9
TMCSR1.MOD1           8
TMCSR1.MOD0           7
TMCSR1.OUTE           6
TMCSR1.OUTL           5
TMCSR1.RELD           4
TMCSR1.INTE           3
TMCSR1.UF             2
TMCSR1.CNTE           1
TMCSR1.TRG            0
TMR1                 0x00003E           16-bit timer register 1 / 16-bit reload register 1
TCCR                 0x000050           Free-run timer control register
TCCR.PRO              8
TCCR.STP              7
TCCR.CLR              6
TCCR.IVF              5
TCCR.IVFE             4
TCCR.TIM              3
TCCR.TIME             2
TCCR.TIS1             1
TCCR.TIS0             0
ICC                  0x000052           ICU control register
ICC.EN                5
ICC.CS4               4
ICC.CS3               3
ICC.CS2               2
ICC.CS1               1
ICC.CS0               0
TCR                  0x000054           Free-run timer lower data register
CCR00                0x000058           OCU control register 00
CCR00.MD3             11
CCR00.MD2             10
CCR00.MD1             9
CCR00.MD0             8
CCR00.SEL3            7
CCR00.SEL2            6
CCR00.SEL1            5
CCR00.SEL0            4
CCR00.CPE3            3
CCR00.CPE2            2
CCR00.CPE1            1
CCR00.CPE0            0
CCR01                0x00005A           OCU control register 01
CCR01.ICE3            15
CCR01.ICE2            14
CCR01.ICE1            13
CCR01.ICE0            12
CCR01.IC3             11
CCR01.IC2             10
CCR01.IC1             9
CCR01.IC0             8
CCR01.DOT3            3
CCR01.DOT2            2
CCR01.DOT1            1
CCR01.DOT0            0
CCR10                0x00005C           OCU control register 10
CCR10.MD3             11
CCR10.MD2             10
CCR10.MD1             9
CCR10.MD0             8
CCR10.SEL3            7
CCR10.SEL2            6
CCR10.SEL1            5
CCR10.SEL0            4
CCR10.CPE3            3
CCR10.CPE2            2
CCR10.CPE1            1
CCR10.CPE0            0
CCR11                0x00005E           OCU control register 11
CCR11.ICE3            15
CCR11.ICE2            14
CCR11.ICE1            13
CCR11.ICE0            12
CCR11.IC3             11
CCR11.IC2             10
CCR11.IC1             9
CCR11.IC0             8
CCR11.DOT3            3
CCR11.DOT2            2
CCR11.DOT1            1
CCR11.DOT0            0
ICR0                 0x000060           ICU data register 0
ICR1                 0x000064           ICU data register 1
ICR2                 0x000068           ICU data register 2
ICR3                 0x00006C           ICU data register 3
CPR0                 0x000070           OCU compare data register 0
CPR1                 0x000074           OCU compare data register 1
CPR2                 0x000078           OCU compare data register 2
CPR3                 0x00007C           OCU compare data register 3
CPR4                 0x000080           OCU compare data register 4
CPR5                 0x000084           OCU compare data register 5
CPR6                 0x000088           OCU compare data register 6
CPR7                 0x00008C           OCU compare data register 7
DIRR                 0x00009F           Delayed interrupt factor generation/cancellation register
DIRR.R0               0
LPMCR                0x0000A0           Low-power consumption mode control register
LPMCR.STP             7
LPMCR.SLP             6
LPMCR.SPL             5
LPMCR.RST             4
LPMCR.CG1             2
LPMCR.CG0             1
CKSCR                0x0000A1           Clock selection register
CKSCR.MCM             6
CKSCR.WS1             5
CKSCR.WS0             4
CKSCR.MCS             2
CKSCR.CS1             1
CKSCR.CS0             0
ARSR                 0x0000A5           Automatic ready function select register
HACR                 0x0000A6           Upper address control register
EPCR                 0x0000A7           Bus control signal select register
WDTC                 0x0000A8           Watchdog timer control register
WDTC.PONR             7
WDTC.STBR             6
WDTC.WRST             5
WDTC.ERST             4
WDTC.SRST             3
TBTC                 0x0000A9           Timebase timer control register
TBTC.TBIE             4
TBTC.TBOF             3
TBTC.TBR              2
TBTC.TBC1             1
TBTC.TBC0             0
ICR00                0x0000B0           Interrupt control register 00
ICR00.S1              5
ICR00.S0              4
ICR00.ISE             3
ICR00.IL2             2
ICR00.IL1             1
ICR00.IL0             0
ICR01                0x0000B1           Interrupt control register 01
ICR01.S1              5
ICR01.S0              4
ICR01.ISE             3
ICR01.IL2             2
ICR01.IL1             1
ICR01.IL0             0
ICR02                0x0000B2           Interrupt control register 02
ICR02.S1              5
ICR02.S0              4
ICR02.ISE             3
ICR02.IL2             2
ICR02.IL1             1
ICR02.IL0             0
ICR03                0x0000B3           Interrupt control register 03
ICR03.S1              5
ICR03.S0              4
ICR03.ISE             3
ICR03.IL2             2
ICR03.IL1             1
ICR03.IL0             0
ICR04                0x0000B4           Interrupt control register 04
ICR04.S1              5
ICR04.S0              4
ICR04.ISE             3
ICR04.IL2             2
ICR04.IL1             1
ICR04.IL0             0
ICR05                0x0000B5           Interrupt control register 05
ICR05.S1              5
ICR05.S0              4
ICR05.ISE             3
ICR05.IL2             2
ICR05.IL1             1
ICR05.IL0             0
ICR06                0x0000B6           Interrupt control register 06
ICR06.S1              5
ICR06.S0              4
ICR06.ISE             3
ICR06.IL2             2
ICR06.IL1             1
ICR06.IL0             0
ICR07                0x0000B7           Interrupt control register 07
ICR07.S1              5
ICR07.S0              4
ICR07.ISE             3
ICR07.IL2             2
ICR07.IL1             1
ICR07.IL0             0
ICR08                0x0000B8           Interrupt control register 08
ICR08.S1              5
ICR08.S0              4
ICR08.ISE             3
ICR08.IL2             2
ICR08.IL1             1
ICR08.IL0             0
ICR09                0x0000B9           Interrupt control register 09
ICR09.S1              5
ICR09.S0              4
ICR09.ISE             3
ICR09.IL2             2
ICR09.IL1             1
ICR09.IL0             0
ICR10                0x0000BA           Interrupt control register 10
ICR10.S1              5
ICR10.S0              4
ICR10.ISE             3
ICR10.IL2             2
ICR10.IL1             1
ICR10.IL0             0
ICR11                0x0000BB           Interrupt control register 11
ICR11.S1              5
ICR11.S0              4
ICR11.ISE             3
ICR11.IL2             2
ICR11.IL1             1
ICR11.IL0             0
ICR12                0x0000BC           Interrupt control register 12
ICR12.S1              5
ICR12.S0              4
ICR12.ISE             3
ICR12.IL2             2
ICR12.IL1             1
ICR12.IL0             0
ICR13                0x0000BD           Interrupt control register 13
ICR13.S1              5
ICR13.S0              4
ICR13.ISE             3
ICR13.IL2             2
ICR13.IL1             1
ICR13.IL0             0
ICR14                0x0000BE           Interrupt control register 14
ICR14.S1              5
ICR14.S0              4
ICR14.ISE             3
ICR14.IL2             2
ICR14.IL1             1
ICR14.IL0             0
ICR15                0x0000BF           Interrupt control register 15
ICR15.S1              5
ICR15.S0              4
ICR15.ISE             3
ICR15.IL2             2
ICR15.IL1             1
ICR15.IL0             0


.MB90675
; http://edevice.fujitsu.com/fj/DATASHEET/e-ds/e713602.pdf
; MB90676/677/678/T678/P678


; ROM:   32 Kbytes (MB90676)
;        48 Kbytes (MB90677)
;        64 Kbytes (MB90678/MB90P678)
; RAM: 1.64 Kbytes (MB90676)
;         2 Kbytes (MB90677)
;         3 Kbytes (MB90678/MB90T678/MB90P678)
;         4 Kbytes (MB90V670)


; MEMORY MAP
; [MB90676]
area DATA FSR           0x000000:0x0000C0
area BSS  Inhibited_1   0x0000C0:0x000100
area DATA RAM           0x000100:0x000780
area BSS  Inhibited_2   0x000780:0x008000
area DATA ROM_1         0x008000:0x010000
area BSS  Inhibited_3   0x010000:0xFF8000
; area DATA ROM_2_BANK_FF 0xFF8000:0x1000000

; [MB90677]
; area DATA FSR           0x000000:0x0000C0
; area BSS  Inhibited_1   0x0000C0:0x000100
; area DATA RAM           0x000100:0x000900
; area BSS  Inhibited_2   0x000900:0x004000
; area DATA ROM_1         0x004000:0x010000
; area BSS  Inhibited_3   0x010000:0xFF4000
; area DATA ROM_2_BANK_FF 0xFF4000:0x1000000

; [MB90678/MB90P678]
; area DATA FSR           0x000000:0x0000C0
; area BSS  Inhibited_1   0x0000C0:0x000100
; area DATA RAM           0x000100:0x000D00
; area BSS  Inhibited_2   0x000D00:0x004000
; area DATA ROM_1         0x004000:0x010000
; area BSS  Inhibited_3   0x010000:0xFF0000
; area DATA ROM_2_BANK_FF 0xFF0000:0x1000000


; Interrupt and reset vector assignments
interrupt __RESET       0xFFFFDC   Reset 
interrupt INT9          0xFFFFD8   INT9 instruction 
interrupt EXCEPT        0xFFFFD4   Exception 
interrupt DTP_EIC_CH0   0xFFFFD0   DTP/external interrupt circuit Channel 0 
interrupt DTP_EIC_CH1   0xFFFFCC   DTP/external interrupt circuit Channel 1 
interrupt DTP_EIC_CH2   0xFFFFC8   DTP/external interrupt circuit Channel 2 
interrupt DTP_EIC_CH3   0xFFFFC4   DTP/external interrupt circuit Channel 3 
interrupt OC_CH0        0xFFFFC0   Output compare Channel 0 
interrupt OC_CH1        0xFFFFBC   Output compare Channel 1 
interrupt OC_CH2        0xFFFFB8   Output compare Channel 2 
interrupt OC_CH3        0xFFFFB4   Output compare Channel 3 
interrupt OC_CH4        0xFFFFB0   Output compare Channel 4 
interrupt OC_CH5        0xFFFFAC   Output compare Channel 5 
interrupt OC_CH6        0xFFFFA8   Output compare Channel 6 
interrupt OC_CH7        0xFFFFA4   Output compare Channel 7 
interrupt F_TIMER_O     0xFFFFA0   24-bit free-run timer Overflow 
interrupt F_TIMER_IB    0xFFFF9C   24-bit free-run timer Intermediate bit 
interrupt IC_CH0        0xFFFF98   Input capture Channel 0 
interrupt IC_CH1        0xFFFF94   Input capture Channel 1 
interrupt IC_CH2        0xFFFF90   Input capture Channel 2 
interrupt IC_CH3        0xFFFF8C   Input capture Channel 3 
interrupt R_TIMER0      0xFFFF88   16-bit reload timer/8/16-bit PPG timer 0 
interrupt R_TIMER1      0xFFFF84   16-bit reload timer/8/16-bit PPG timer 1 
interrupt A_D_CMMC      0xFFFF80   8/10-bit A/D converter measure-ment complete 
interrupt WAKE_AP       0xFFFF78   Wake-up interrupt 
interrupt T_TIMER_II    0xFFFF74   Timebase timer interval interrupt 


; INPUT/OUTPUT PORTS
PDR0                 0x000000           Port 0 data register
PDR0.PD07             7
PDR0.PD06             6
PDR0.PD05             5
PDR0.PD04             4
PDR0.PD03             3
PDR0.PD02             2
PDR0.PD01             1
PDR0.PD00             0
PDR1                 0x000001           Port 1 data register
PDR1.PD17             7
PDR1.PD16             6
PDR1.PD15             5
PDR1.PD14             4
PDR1.PD13             3
PDR1.PD12             2
PDR1.PD11             1
PDR1.PD10             0
PDR2                 0x000002           Port 2 data register
PDR2.PD27             7
PDR2.PD26             6
PDR2.PD25             5
PDR2.PD24             4
PDR2.PD23             3
PDR2.PD22             2
PDR2.PD21             1
PDR2.PD20             0
PDR3                 0x000003           Port 3 data register
PDR3.PD37             7
PDR3.PD36             6
PDR3.PD35             5
PDR3.PD34             4
PDR3.PD33             3
PDR3.PD32             2
PDR3.PD31             1
PDR3.PD30             0
PDR4                 0x000004           Port 4 data register
PDR4.PD47             7
PDR4.PD46             6
PDR4.PD45             5
PDR4.PD44             4
PDR4.PD43             3
PDR4.PD42             2
PDR4.PD41             1
PDR4.PD40             0
PDR5                 0x000005           Port 5 data register
PDR5.PD57             7
PDR5.PD56             6
PDR5.PD55             5
PDR5.PD54             4
PDR5.PD53             3
PDR5.PD52             2
PDR5.PD51             1
PDR5.PD50             0
PDR6                 0x000006           Port 6 data register
PDR6.PD67             7
PDR6.PD66             6
PDR6.PD65             5
PDR6.PD64             4
PDR6.PD63             3
PDR6.PD62             2
PDR6.PD61             1
PDR6.PD60             0
PDR7                 0x000007           Port 7 data register
PDR7.PD77             7      
PDR7.PD76             6
PDR7.PD75             5
PDR7.PD74             4
PDR7.PD73             3
PDR7.PD72             2
PDR7.PD71             1
PDR7.PD70             0
PDR8                 0x000008           Port 8 data register
PDR9                 0x000009           Port 9 data register
PDRA                 0x00000A           Port A data register
PDRB                 0x00000B           Port B data register
EIFR                 0x00000F           Wake-up interrupt flag register
EIFR.WIF              0
DDR0                 0x000010           Port 0 data direction register
DDR0.DD07             7
DDR0.DD06             6
DDR0.DD05             5
DDR0.DD04             4
DDR0.DD03             3
DDR0.DD02             2
DDR0.DD01             1
DDR0.DD00             0
DDR1                 0x000011           Port 1 data direction register
DDR1.DD17             7
DDR1.DD16             6
DDR1.DD15             5
DDR1.DD14             4
DDR1.DD13             3
DDR1.DD12             2
DDR1.DD11             1
DDR1.DD10             0
DDR2                 0x000012           Port 4 data direction register
DDR2.DD27             7
DDR2.DD26             6
DDR2.DD25             5
DDR2.DD24             4
DDR2.DD23             3
DDR2.DD22             2
DDR2.DD21             1
DDR2.DD20             0
DDR3                 0x000013           Port 3 data direction register
DDR3.DD37             7
DDR3.DD36             6
DDR3.DD35             5
DDR3.DD34             4
DDR3.DD33             3
DDR3.DD32             2
DDR3.DD31             1
DDR3.DD30             0
DDR4                 0x000014           Port 4 data direction register
DDR4.DD47             7
DDR4.DD46             6
DDR4.DD45             5
DDR4.DD44             4
DDR4.DD43             3
DDR4.DD42             2
DDR4.DD41             1
DDR4.DD40             0
ADER                 0x000015           Analog input enable register
ADER.ADE7             7
ADER.ADE6             6
ADER.ADE5             5
ADER.ADE4             4
ADER.ADE3             3
ADER.ADE2             2
ADER.ADE1             1
ADER.ADE0             0
DDR6                 0x000016           Port 6 data direction register
DDR6.DD67             7
DDR6.DD66             6
DDR6.DD65             5
DDR6.DD64             4
DDR6.DD63             3
DDR6.DD62             2
DDR6.DD61             1
DDR6.DD60             0
DDR7                 0x000017           Port 7 data direction register
DDR7.DD77             7
DDR7.DD76             6
DDR7.DD75             5
DDR7.DD74             4
DDR7.DD73             3
DDR7.DD72             2
DDR7.DD71             1
DDR7.DD70             0
DDR8                 0x000018           Port 8 data direction register
DDRA                 0x00001A           Port A data direction register
DDRB                 0x00001B           Port B data direction register
EICR                 0x00001F           Wake-up interrupt enable register
UMC                  0x000020           Mode control register 0
UMC.PEN               7
UMC.SBL               6
UMC.MC1               5
UMC.MC0               4
UMC.SMDE              3
UMC.RFC               2
UMC.SCKE              1
UMC.SOE               0
USR0                 0x000021           Status register 0
USR0.RDRF             7
USR0.ORFE             6
USR0.PE               5
USR0.TDRE             4
USR0.RIE              3
USR0.TIE              2
USR0.RBF              1
USR0.TBF              0
UIDR                 0x000022           Input data register 0 / output data register 0
UIDR.D6               6
UIDR.D5               5
UIDR.D4               4
UIDR.D3               3
UIDR.D2               2
UIDR.D1               1
UIDR.D0               0
URD                  0x000023           Rate and data register 0
URD.BCH               7
URD.RC3               6
URD.RC2               5
URD.RC1               4
URD.RC0               3
URD.BCH0              2
URD.P                 1
URD.D8                0
SMR                  0x000024           Mode register 1
SMR.MD1               7
SMR.MD0               6
SMR.CS2               5
SMR.CS1               4
SMR.CS0               3
SMR.BCH               2
SMR.SCKE              1
SMR.SOE               0
SCR                  0x000025           Control register 1
SCR.PEN               7
SCR.P                 6
SCR.SBL               5
SCR.CL                4
SCR.AD                3
SCR.REC               2
SCR.RXE               1
SCR.TXE               0
SIDR                 0x000026           Input data register 1 / output data register 1
SIDR.D6               6
SIDR.D5               5
SIDR.D4               4
SIDR.D3               3
SIDR.D2               2
SIDR.D1               1
SIDR.D0               0
SSR                  0x000027           Status register 1
SSR.PE                7
SSR.ORE               6
SSR.FRE               5
SSR.RDRF              4
SSR.TDRE              3
SSR.RIE               1
SSR.TIE               0
ENIR                 0x000028           DTP/interrupt enable register
ENIR.EN3              3
ENIR.EN2              2
ENIR.EN1              1
ENIR.EN0              0
EIRR                 0x000029           DTP/interrupt factor register
EIRR.ER3              3
EIRR.ER2              2
EIRR.ER1              1
EIRR.ER0              0
ELVR                 0x00002A           Request level setting register
ELVR.LALB31           7
ELVR.LALB30           6
ELVR.LALB21           5
ELVR.LALB20           4
ELVR.LALB11           3
ELVR.LALB10           2
ELVR.LALB01           1
ELVR.LALB00           0
ADCS1                0x00002C           A/D convertor control status register
ADCS1.MD1             7
ADCS1.MD0             6
ADCS1.ANS2            5
ADCS1.ANS1            4
ADCS1.ANS0            3
ADCS1.ANE2            2
ADCS1.ANE1            1
ADCS1.ANE0            0    
ADCS2                0x00002D           A/D convertor control status reg-ister
ADCS2.BUSY            7
ADCS2.INT             6
ADCS2.INTE            5
ADCS2.PAUS            4
ADCS2.STS1            3
ADCS2.STS0            2
ADCS2.STRT            1
ADCR12               0x00002E           A/D convertor data register
ADCR12.S10            15
ADCR12.D9             9
ADCR12.D8             8
ADCR12.D7             7
ADCR12.D6             6
ADCR12.D5             5
ADCR12.D4             4
ADCR12.D3             3
ADCR12.D2             2
ADCR12.D1             1
ADCR12.D0             0
PPGC01               0x000030           PPG0/PPG1 operating mode control register
PPGC01.PEN1           15
PPGC01.PCS1           14
PPGC01.PE10           13
PPGC01.PIE1           12
PPGC01.PUF1           11
PPGC01.MD1            10
PPGC01.MD0            9
PPGC01.PEN0           7
PPGC01.PE00           5
PPGC01.PIE0           4
PPGC01.PUF0           3
PPGC01.PCM1           2
PPGC01.PCM0           1
PRL0_PRLL            0x000034           PPG0 reload register
PRL0_PRLH            0x000035           PPG0 reload register
PRL1_PRLL            0x000036           PPG1 reload register
PRL1_PRLH            0x000037           PPG1 reload register
TMCSR0               0x000038           Timer control status register 0
TMCSR0.CSL1           11
TMCSR0.CSL0           10
TMCSR0.MOD2           9
TMCSR0.MOD1           8
TMCSR0.MOD0           7
TMCSR0.OUTE           6
TMCSR0.OUTL           5
TMCSR0.RELD           4
TMCSR0.INTE           3
TMCSR0.UF             2
TMCSR0.CNTE           1
TMCSR0.TRG            0
TMR0                 0x00003A           16-bit timer register 0 / 16-bit reload register 0
TMCSR1               0x00003C           Timer control status register 1
TMCSR1.CSL1           11
TMCSR1.CSL0           10
TMCSR1.MOD2           9
TMCSR1.MOD1           8
TMCSR1.MOD0           7
TMCSR1.OUTE           6
TMCSR1.OUTL           5
TMCSR1.RELD           4
TMCSR1.INTE           3
TMCSR1.UF             2
TMCSR1.CNTE           1
TMCSR1.TRG            0
TMR1                 0x00003E           16-bit timer register 1 / 16-bit reload register 1
TCCR                 0x000050           Free-run timer control register
TCCR.PRO              8
TCCR.STP              7
TCCR.CLR              6
TCCR.IVF              5
TCCR.IVFE             4
TCCR.TIM              3
TCCR.TIME             2
TCCR.TIS1             1
TCCR.TIS0             0
ICC                  0x000052           ICU control register
ICC.EN                5
ICC.CS4               4
ICC.CS3               3
ICC.CS2               2
ICC.CS1               1
ICC.CS0               0
TCR                  0x000054           Free-run timer lower data register
CCR00                0x000058           OCU control register 00
CCR00.MD3             11
CCR00.MD2             10
CCR00.MD1             9
CCR00.MD0             8
CCR00.SEL3            7
CCR00.SEL2            6
CCR00.SEL1            5
CCR00.SEL0            4
CCR00.CPE3            3
CCR00.CPE2            2
CCR00.CPE1            1
CCR00.CPE0            0
CCR01                0x00005A           OCU control register 01
CCR01.ICE3            15
CCR01.ICE2            14
CCR01.ICE1            13
CCR01.ICE0            12
CCR01.IC3             11
CCR01.IC2             10
CCR01.IC1             9
CCR01.IC0             8
CCR01.DOT3            3
CCR01.DOT2            2
CCR01.DOT1            1
CCR01.DOT0            0
CCR10                0x00005C           OCU control register 10
CCR10.MD3             11
CCR10.MD2             10
CCR10.MD1             9
CCR10.MD0             8
CCR10.SEL3            7
CCR10.SEL2            6
CCR10.SEL1            5
CCR10.SEL0            4
CCR10.CPE3            3
CCR10.CPE2            2
CCR10.CPE1            1
CCR10.CPE0            0
CCR11                0x00005E           OCU control register 11
CCR11.ICE3            15
CCR11.ICE2            14
CCR11.ICE1            13
CCR11.ICE0            12
CCR11.IC3             11
CCR11.IC2             10
CCR11.IC1             9
CCR11.IC0             8
CCR11.DOT3            3
CCR11.DOT2            2
CCR11.DOT1            1
CCR11.DOT0            0
ICR0                 0x000060           ICU data register 0
ICR1                 0x000064           ICU data register 1
ICR2                 0x000068           ICU data register 2
ICR3                 0x00006C           ICU data register 3
CPR0                 0x000070           OCU compare data register 0
CPR1                 0x000074           OCU compare data register 1
CPR2                 0x000078           OCU compare data register 2
CPR3                 0x00007C           OCU compare data register 3
CPR4                 0x000080           OCU compare data register 4
CPR5                 0x000084           OCU compare data register 5
CPR6                 0x000088           OCU compare data register 6
CPR7                 0x00008C           OCU compare data register 7
DIRR                 0x00009F           Delayed interrupt factor generation/cancellation register
DIRR.R0               0
LPMCR                0x0000A0           Low-power consumption mode control register
LPMCR.STP             7
LPMCR.SLP             6
LPMCR.SPL             5
LPMCR.RST             4
LPMCR.CG1             2
LPMCR.CG0             1
CKSCR                0x0000A1           Clock selection register
CKSCR.MCM             6
CKSCR.WS1             5
CKSCR.WS0             4
CKSCR.MCS             2
CKSCR.CS1             1
CKSCR.CS0             0
ARSR                 0x0000A5           Automatic ready function select register
HACR                 0x0000A6           Upper address control register
EPCR                 0x0000A7           Bus control signal select register
WDTC                 0x0000A8           Watchdog timer control register
WDTC.PONR             7
WDTC.STBR             6
WDTC.WRST             5
WDTC.ERST             4
WDTC.SRST             3
TBTC                 0x0000A9           Timebase timer control register
TBTC.TBIE             4
TBTC.TBOF             3
TBTC.TBR              2
TBTC.TBC1             1
TBTC.TBC0             0
ICR00                0x0000B0           Interrupt control register 00
ICR00.S1              5
ICR00.S0              4
ICR00.ISE             3
ICR00.IL2             2
ICR00.IL1             1
ICR00.IL0             0
ICR01                0x0000B1           Interrupt control register 01
ICR01.S1              5
ICR01.S0              4
ICR01.ISE             3
ICR01.IL2             2
ICR01.IL1             1
ICR01.IL0             0
ICR02                0x0000B2           Interrupt control register 02
ICR02.S1              5
ICR02.S0              4
ICR02.ISE             3
ICR02.IL2             2
ICR02.IL1             1
ICR02.IL0             0
ICR03                0x0000B3           Interrupt control register 03
ICR03.S1              5
ICR03.S0              4
ICR03.ISE             3
ICR03.IL2             2
ICR03.IL1             1
ICR03.IL0             0
ICR04                0x0000B4           Interrupt control register 04
ICR04.S1              5
ICR04.S0              4
ICR04.ISE             3
ICR04.IL2             2
ICR04.IL1             1
ICR04.IL0             0
ICR05                0x0000B5           Interrupt control register 05
ICR05.S1              5
ICR05.S0              4
ICR05.ISE             3
ICR05.IL2             2
ICR05.IL1             1
ICR05.IL0             0
ICR06                0x0000B6           Interrupt control register 06
ICR06.S1              5
ICR06.S0              4
ICR06.ISE             3
ICR06.IL2             2
ICR06.IL1             1
ICR06.IL0             0
ICR07                0x0000B7           Interrupt control register 07
ICR07.S1              5
ICR07.S0              4
ICR07.ISE             3
ICR07.IL2             2
ICR07.IL1             1
ICR07.IL0             0
ICR08                0x0000B8           Interrupt control register 08
ICR08.S1              5
ICR08.S0              4
ICR08.ISE             3
ICR08.IL2             2
ICR08.IL1             1
ICR08.IL0             0
ICR09                0x0000B9           Interrupt control register 09
ICR09.S1              5
ICR09.S0              4
ICR09.ISE             3
ICR09.IL2             2
ICR09.IL1             1
ICR09.IL0             0
ICR10                0x0000BA           Interrupt control register 10
ICR10.S1              5
ICR10.S0              4
ICR10.ISE             3
ICR10.IL2             2
ICR10.IL1             1
ICR10.IL0             0
ICR11                0x0000BB           Interrupt control register 11
ICR11.S1              5
ICR11.S0              4
ICR11.ISE             3
ICR11.IL2             2
ICR11.IL1             1
ICR11.IL0             0
ICR12                0x0000BC           Interrupt control register 12
ICR12.S1              5
ICR12.S0              4
ICR12.ISE             3
ICR12.IL2             2
ICR12.IL1             1
ICR12.IL0             0
ICR13                0x0000BD           Interrupt control register 13
ICR13.S1              5
ICR13.S0              4
ICR13.ISE             3
ICR13.IL2             2
ICR13.IL1             1
ICR13.IL0             0
ICR14                0x0000BE           Interrupt control register 14
ICR14.S1              5
ICR14.S0              4
ICR14.ISE             3
ICR14.IL2             2
ICR14.IL1             1
ICR14.IL0             0
ICR15                0x0000BF           Interrupt control register 15
ICR15.S1              5
ICR15.S0              4
ICR15.ISE             3
ICR15.IL2             2
ICR15.IL1             1
ICR15.IL0             0



```
