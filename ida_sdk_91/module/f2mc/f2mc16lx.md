```ini
;
; This file defines SFR names and bit names for Fujitsu's F2MC16LX processors.
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

.default MB90540

;-------------------------------
; Device specific definitions


.MB90420G
; DS07-13711-2E  
; MB90423GA/GB/GC/MB90F423GA/GB/GC/MB90V420G


; Flash ROM: 128 KB (MB90F423GA/MB90F423GB/MB90F423GC)
; Mask ROM:  128 KB (MB90423GA/MB90423GB/MB90423GC)
; RAM:         6 KB (MB90V420G/MB90F423GA/MB90F423GB/MB90F423GC/MB90423GA/MB90423GB/MB90423GC)


; MEMORY MAP
area DATA FSR           0x000000:0x0000C0
area BSS  No_access_1   0x0000C0:0x000100
area DATA RAM           0x000100:0x001900
area BSS  No_access_2   0x001900:0x003900
area DATA FSR_1         0x003900:0x004000
area BSS  No_access_3   0x004000:0x010000
area DATA ROM_1         0x010000:0xFE0000
area BSS  No_access_4   0xFE0000:0xFF0000
; area DATA ROM_2_BANK_FF 0xFF0000:0x1000000


; Interrupt and reset vector assignments
interrupt __RESET       0xFFFFDC   Reset 
interrupt INT9          0xFFFFD8   INT9 instruction 
interrupt EXCEPT        0xFFFFD4   Exception processing 
interrupt CAN0_RX       0xFFFFD0   CAN0 RX 
interrupt CAN0_TX_NS    0xFFFFCC   CAN0 TX/NS 
interrupt CAN1_RX       0xFFFFC8   CAN1 RX 
interrupt CAN1_TX_NS    0xFFFFC4   CAN1 TX/NS 
interrupt IC0           0xFFFFC0   Input capture 0 
interrupt DTP_CH0       0xFFFFBC   DTP/external interrupt - ch 0 detected 
interrupt R_TIMER0      0xFFFFB8   Reload timer 0 
interrupt DTP_CH1       0xFFFFB4   DTP/external interrupt - ch 1 detected 
interrupt IC1           0xFFFFB0   Input capture 1 
interrupt DTP_CH2       0xFFFFAC   DTP/external interrupt - ch 2 detected 
interrupt IC2           0xFFFFA8   Input capture 2 
interrupt DTP_CH3       0xFFFFA4   DTP/external interrupt - ch 3 detected 
interrupt IC3           0xFFFFA0   Input capture 3 
interrupt DTP_CH45      0xFFFF9C   DTP/external interrupt - ch 4/5 detected 
interrupt PPG_TIMER0    0xFFFF98   PPG timer 0 
interrupt DTP_CH67      0xFFFF94   DTP/external interrupt - ch 6/7 detected 
interrupt PPG_TIMER1    0xFFFF90   PPG timer 1 
interrupt R_TIMER1      0xFFFF8C   Reload timer 1 
interrupt PPG_TIMER2    0xFFFF88   PPG timer 2 
interrupt RTC_TIMER     0xFFFF84   Real time clock timer 
interrupt FR_TIMER_OF   0xFFFF80   Free-run timer over flow 
interrupt AD_CCE        0xFFFF7C   A/D converter conversion end 
interrupt FR_TIMER_C    0xFFFF78   Free-run timer clear 
interrupt SOUND         0xFFFF74   Sound generator 
interrupt TB_TIMER      0xFFFF70   Time base timer 
interrupt C_TIMER       0xFFFF6C   Clock timer (sub clock) 
interrupt UART_1_RX     0xFFFF68   UART 1 RX 
interrupt UART_1_TX     0xFFFF64   UART 1 TX 
interrupt UART_0_RX     0xFFFF60   UART 0 RX 
interrupt UART_0_TX     0xFFFF5C   UART 0 TX 
interrupt FLASH         0xFFFF58   Flash memory status 
interrupt DELAY         0xFFFF54   Delayed interrupt generator module 


; INPUT/OUTPUT PORTS
PDR0            0x000000       Port 0 data register 
PDR1            0x000001       Port 1 data register 
PDR3            0x000003       Port 3 data register 
PDR4            0x000004       Port 4 data register 
PDR5            0x000005       Port 5 data register 
PDR6            0x000006       Port 6 data register 
PDR7            0x000007       Port 7 data register 
PDR8            0x000008       Port 8 data register 
PDR9            0x000009       Port 9 data register 
DDR0            0x000010       Port 0 direction register 
DDR1            0x000011       Port 1 direction register 
DDR3            0x000013       Port 3 direction register 
DDR4            0x000014       Port 4 direction register 
DDR5            0x000015       Port 5 direction register 
DDR6            0x000016       Port 6 direction register 
DDR7            0x000017       Port 7 direction register 
DDR8            0x000018       Port 8 direction register 
DDR9            0x000019       Port 9 direction register 
ADER            0x00001A       Analog input enable 
ADCSL           0x000020       A/D control status register lower 
ADCSH           0x000021       A/D control status register higher 
ADCRL           0x000022       A/D data register lower 
ADCRH           0x000023       A/D data register higher 
CPCLR           0x000024       Compare clear register 
TCDT            0x000026       Timer data register 
TCCSL           0x000028       Timer control status register lower 
TCCSH           0x000029       Timer control status register higher 
PCNTL0          0x00002A       PPG0 control status register lower 
PCNTH0          0x00002B       PPG0 control status register higher 
PCNTL1          0x00002C       PPG1 control status register lower 
PCNTH1          0x00002D       PPG1 control status register higher 
PCNTL2          0x00002E       PPG2 control status register lower 
PCNTH2          0x00002F       PPG2 control status register higher 
ENIR            0x000030       External interrupt enable 
EIRR            0x000031       External interrupt request 
ELVRL           0x000032       External interrupt level lower 
ELVRH           0x000033       External interrupt level higher 
SMR0            0x000034       Serial mode register 0 
SCR0            0x000035       Serial control register 0 
SIDR0_SODR0     0x000036       Input data register 0/Output data register 0 
SSR0            0x000037       Serial status register 0 
SMR1            0x000038       Serial mode register 1 
SCR1            0x000039       Serial control register 1 
SIDR1_SODR1     0x00003A       Input data register 1/Output data register 1 
SSR1            0x00003B       Serial status register 1 
CDCR0           0x00003D       Clock division control register 0 
CWUCR           0x00003E       CAN wake-up control register 
CDCR1           0x00003F       Clock division control register 1 
TMCSR0L         0x000050       Timer control status register 0 lower 
TMCSR0H         0x000051       Timer control status register 0 high-er 
TMR0_TMRLR0     0x000052       Timer register 0/Reload register 0 
TMCSR1L         0x000054       Timer control status register 1 lower 
TMCSR1H         0x000055       Timer control status register 1 high-er 
TMR1_TMRLR1     0x000056       Timer register 1/Reload register 1 
WTCRL           0x000058       Clock timer control register lower 
WTCRH           0x000059       Clock timer control register higher 
SGCRL           0x00005A       Sound control register lower 
SGCRH           0x00005B       Sound control register higher 
SGFR            0x00005C       Frequency data register 
SGAR            0x00005D       Amplitude data register 
SGDR            0x00005E       Decrement grade register 
SGTR            0x00005F       Tone count register 
IPCP0           0x000060       Input capture register 0 
IPCP1           0x000062       Input capture register 1 
IPCP2           0x000064       Input capture register 2 
IPCP3           0x000066       Input capture register 3 
ICS01           0x000068       Input capture control status 0/1 
ICS23           0x00006A       Input capture control status 2/3 
LCRL            0x00006C       LCDC control register lower 
LCRH            0x00006D       LCDC control register higher 
LVRC            0x00006E       Low voltage detect reset control register 
ROMM            0x00006F       ROM mirror 
PWC0            0x000080       PWM control register 0 
PWC1            0x000082       PWM control register 1 
PWC2            0x000084       PWM control register 2 
PWC3            0x000086       PWM control register 3 
PACSR           0x00009E       ROM correction control register 
DIRR            0x00009F       Delay interrupt/release 
LPMCR           0x0000A0       Power saving mode 
CKSCR           0x0000A1       Clock select 
WDTC            0x0000A8       Watchdog control 
TBTC            0x0000A9       Time base timer control register 
WTC             0x0000AA       Clock timer control register 
FMCS            0x0000AE       Flash control register 
ICR00           0x0000B0       Interrupt control register 00 
ICR01           0x0000B1       Interrupt control register 01 
ICR02           0x0000B2       Interrupt control register 02 
ICR03           0x0000B3       Interrupt control register 03 
ICR04           0x0000B4       Interrupt control register 04 
ICR05           0x0000B5       Interrupt control register 05 
ICR06           0x0000B6       Interrupt control register 06 
ICR07           0x0000B7       Interrupt control register 07 
ICR08           0x0000B8       Interrupt control register 08 
ICR09           0x0000B9       Interrupt control register 09 
ICR10           0x0000BA       Interrupt control register 10 
ICR11           0x0000BB       Interrupt control register 11 
ICR12           0x0000BC       Interrupt control register 12 
ICR13           0x0000BD       Interrupt control register 13 
ICR14           0x0000BE       Interrupt control register 14 
ICR15           0x0000BF       Interrupt control register 15 
PDCR0           0x003920       PPG0 down counter register 
PCSR0           0x003922       PPG0 cycle setting register 
PDUT0           0x003924       PPG0 duty setting register 
PDCR1           0x003928       PPG1 down counter register 
PCSR1           0x00392A       PPG1 cycle setting register 
PDUT1           0x00392C       PPG1 duty setting register 
PDCR2           0x003930       PPG2 down counter register 
PCSR2           0x003932       PPG2 cycle setting register 
PDUT2           0x003934       PPG2 duty setting register 
WTBR            0x00395A       Sub second data register 
WTSR            0x00395D       Second data register 
WTMR            0x00395E       Minute data register 
WTHR            0x00395F       Hour data register 
PWC10           0x003980       PWM1 compare register 0 
PWC20           0x003982       PWM2 compare register 0 
PWS10           0x003984       PWM1 select register 0 
PWS20           0x003985       PWM2 select register 0 
PWC11           0x003988       PWM1 compare register 1 
PWC21           0x00398A       PWM2 compare register 1 
PWS11           0x00398C       PWM1 select register 1 
PWS21           0x00398D       PWM2 select register 1 
PWC12           0x003990       PWM1 compare register 2 
PWC22           0x003992       PWM2 compare register 2 
PWS12           0x003994       PWM1 select register 2 
PWS22           0x003995       PWM2 select register 2 
PWC13           0x003998       PWM1 compare register 3 
PWC23           0x00399A       PWM2 compare register 3 
PWS13           0x00399C       PWM1 select register 3 
PWS23           0x00399D       PWM2 select register 3 


.MB90425G
; DS07-13711-2E  
; MB90427GA/GB/GC/MB90428GA/GB/GC/MB90F428GA/GB/GC


; Mask ROM: 64 KB (MB90427GA/MB90427GB/MB90427GC)
;          128 KB (MB90428GA/MB90428GB/MB90428GC)
; RAM:       4 KB (MB90427GA/MB90427GB/MB90427GC)
;            6 KB (MB90428GA/MB90428GB/MB90428GC)


; MEMORY MAP
; [MB90427GA/GB/GC]
area DATA FSR           0x000000:0x0000C0
area BSS  No_access_1   0x0000C0:0x000100
area DATA RAM           0x000100:0x001100
area BSS  No_access_2   0x001100:0x003900
area DATA FSR_1         0x003900:0x004000
area BSS  No_access_3   0x004000:0x010000
area DATA ROM_1         0x010000:0xFF0000
; area DATA ROM_2_BANK_FF 0xFF0000:0x1000000

; [MB90428GA/GB/GC/MB90F428GA/GB/GC]
; area DATA FSR           0x000000:0x0000C0
; area BSS  No_access_1   0x0000C0:0x000100
; area DATA RAM           0x000100:0x001900
; area BSS  No_access_2   0x001900:0x003900
; area DATA FSR_1         0x003900:0x004000
; area BSS  No_access_3   0x004000:0x010000
; area DATA ROM_1         0x010000:0xFE0000
; area BSS  No_access_4   0xFE0000:0xFF0000
; area DATA ROM_2_BANK_FF 0xFF0000:0x1000000


; Interrupt and reset vector assignments
interrupt __RESET       0xFFFFDC   Reset 
interrupt INT9          0xFFFFD8   INT9 instruction 
interrupt EXCEPT        0xFFFFD4   Exception processing 
interrupt CAN0_RX       0xFFFFD0   CAN0 RX 
interrupt CAN0_TX_NS    0xFFFFCC   CAN0 TX/NS 
interrupt CAN1_RX       0xFFFFC8   CAN1 RX 
interrupt CAN1_TX_NS    0xFFFFC4   CAN1 TX/NS 
interrupt IC0           0xFFFFC0   Input capture 0 
interrupt DTP_CH0       0xFFFFBC   DTP/external interrupt - ch 0 detected 
interrupt R_TIMER0      0xFFFFB8   Reload timer 0 
interrupt DTP_CH1       0xFFFFB4   DTP/external interrupt - ch 1 detected 
interrupt IC1           0xFFFFB0   Input capture 1 
interrupt DTP_CH2       0xFFFFAC   DTP/external interrupt - ch 2 detected 
interrupt IC2           0xFFFFA8   Input capture 2 
interrupt DTP_CH3       0xFFFFA4   DTP/external interrupt - ch 3 detected 
interrupt IC3           0xFFFFA0   Input capture 3 
interrupt DTP_CH45      0xFFFF9C   DTP/external interrupt - ch 4/5 detected 
interrupt PPG_TIMER0    0xFFFF98   PPG timer 0 
interrupt DTP_CH67      0xFFFF94   DTP/external interrupt - ch 6/7 detected 
interrupt PPG_TIMER1    0xFFFF90   PPG timer 1 
interrupt R_TIMER1      0xFFFF8C   Reload timer 1 
interrupt PPG_TIMER2    0xFFFF88   PPG timer 2 
interrupt RTC_TIMER     0xFFFF84   Real time clock timer 
interrupt FR_TIMER_OF   0xFFFF80   Free-run timer over flow 
interrupt AD_CCE        0xFFFF7C   A/D converter conversion end 
interrupt FR_TIMER_C    0xFFFF78   Free-run timer clear 
interrupt SOUND         0xFFFF74   Sound generator 
interrupt TB_TIMER      0xFFFF70   Time base timer 
interrupt C_TIMER       0xFFFF6C   Clock timer (sub clock) 
interrupt UART_1_RX     0xFFFF68   UART 1 RX 
interrupt UART_1_TX     0xFFFF64   UART 1 TX 
interrupt UART_0_RX     0xFFFF60   UART 0 RX 
interrupt UART_0_TX     0xFFFF5C   UART 0 TX 
interrupt FLASH         0xFFFF58   Flash memory status 
interrupt DELAY         0xFFFF54   Delayed interrupt generator module 


; INPUT/OUTPUT PORTS
PDR0            0x000000       Port 0 data register 
PDR1            0x000001       Port 1 data register 
PDR3            0x000003       Port 3 data register 
PDR4            0x000004       Port 4 data register 
PDR5            0x000005       Port 5 data register 
PDR6            0x000006       Port 6 data register 
PDR7            0x000007       Port 7 data register 
PDR8            0x000008       Port 8 data register 
PDR9            0x000009       Port 9 data register 
DDR0            0x000010       Port 0 direction register 
DDR1            0x000011       Port 1 direction register 
DDR3            0x000013       Port 3 direction register 
DDR4            0x000014       Port 4 direction register 
DDR5            0x000015       Port 5 direction register 
DDR6            0x000016       Port 6 direction register 
DDR7            0x000017       Port 7 direction register 
DDR8            0x000018       Port 8 direction register 
DDR9            0x000019       Port 9 direction register 
ADER            0x00001A       Analog input enable 
ADCSL           0x000020       A/D control status register lower 
ADCSH           0x000021       A/D control status register higher 
ADCRL           0x000022       A/D data register lower 
ADCRH           0x000023       A/D data register higher 
CPCLR           0x000024       Compare clear register 
TCDT            0x000026       Timer data register 
TCCSL           0x000028       Timer control status register lower 
TCCSH           0x000029       Timer control status register higher 
PCNTL0          0x00002A       PPG0 control status register lower 
PCNTH0          0x00002B       PPG0 control status register higher 
PCNTL1          0x00002C       PPG1 control status register lower 
PCNTH1          0x00002D       PPG1 control status register higher 
PCNTL2          0x00002E       PPG2 control status register lower 
PCNTH2          0x00002F       PPG2 control status register higher 
ENIR            0x000030       External interrupt enable 
EIRR            0x000031       External interrupt request 
ELVRL           0x000032       External interrupt level lower 
ELVRH           0x000033       External interrupt level higher 
SMR0            0x000034       Serial mode register 0 
SCR0            0x000035       Serial control register 0 
SIDR0_SODR0     0x000036       Input data register 0/Output data register 0 
SSR0            0x000037       Serial status register 0 
SMR1            0x000038       Serial mode register 1 
SCR1            0x000039       Serial control register 1 
SIDR1_SODR1     0x00003A       Input data register 1/Output data register 1 
SSR1            0x00003B       Serial status register 1 
CDCR0           0x00003D       Clock division control register 0 
CWUCR           0x00003E       CAN wake-up control register 
CDCR1           0x00003F       Clock division control register 1 
TMCSR0L         0x000050       Timer control status register 0 lower 
TMCSR0H         0x000051       Timer control status register 0 high-er 
TMR0_TMRLR0     0x000052       Timer register 0/Reload register 0 
TMCSR1L         0x000054       Timer control status register 1 lower 
TMCSR1H         0x000055       Timer control status register 1 high-er 
TMR1_TMRLR1     0x000056       Timer register 1/Reload register 1 
WTCRL           0x000058       Clock timer control register lower 
WTCRH           0x000059       Clock timer control register higher 
SGCRL           0x00005A       Sound control register lower 
SGCRH           0x00005B       Sound control register higher 
SGFR            0x00005C       Frequency data register 
SGAR            0x00005D       Amplitude data register 
SGDR            0x00005E       Decrement grade register 
SGTR            0x00005F       Tone count register 
IPCP0           0x000060       Input capture register 0 
IPCP1           0x000062       Input capture register 1 
IPCP2           0x000064       Input capture register 2 
IPCP3           0x000066       Input capture register 3 
ICS01           0x000068       Input capture control status 0/1 
ICS23           0x00006A       Input capture control status 2/3 
LCRL            0x00006C       LCDC control register lower 
LCRH            0x00006D       LCDC control register higher 
LVRC            0x00006E       Low voltage detect reset control register 
ROMM            0x00006F       ROM mirror 
PWC0            0x000080       PWM control register 0 
PWC1            0x000082       PWM control register 1 
PWC2            0x000084       PWM control register 2 
PWC3            0x000086       PWM control register 3 
PACSR           0x00009E       ROM correction control register 
DIRR            0x00009F       Delay interrupt/release 
LPMCR           0x0000A0       Power saving mode 
CKSCR           0x0000A1       Clock select 
WDTC            0x0000A8       Watchdog control 
TBTC            0x0000A9       Time base timer control register 
WTC             0x0000AA       Clock timer control register 
FMCS            0x0000AE       Flash control register 
ICR00           0x0000B0       Interrupt control register 00 
ICR01           0x0000B1       Interrupt control register 01 
ICR02           0x0000B2       Interrupt control register 02 
ICR03           0x0000B3       Interrupt control register 03 
ICR04           0x0000B4       Interrupt control register 04 
ICR05           0x0000B5       Interrupt control register 05 
ICR06           0x0000B6       Interrupt control register 06 
ICR07           0x0000B7       Interrupt control register 07 
ICR08           0x0000B8       Interrupt control register 08 
ICR09           0x0000B9       Interrupt control register 09 
ICR10           0x0000BA       Interrupt control register 10 
ICR11           0x0000BB       Interrupt control register 11 
ICR12           0x0000BC       Interrupt control register 12 
ICR13           0x0000BD       Interrupt control register 13 
ICR14           0x0000BE       Interrupt control register 14 
ICR15           0x0000BF       Interrupt control register 15 
PDCR0           0x003920       PPG0 down counter register 
PCSR0           0x003922       PPG0 cycle setting register 
PDUT0           0x003924       PPG0 duty setting register 
PDCR1           0x003928       PPG1 down counter register 
PCSR1           0x00392A       PPG1 cycle setting register 
PDUT1           0x00392C       PPG1 duty setting register 
PDCR2           0x003930       PPG2 down counter register 
PCSR2           0x003932       PPG2 cycle setting register 
PDUT2           0x003934       PPG2 duty setting register 
WTBR            0x00395A       Sub second data register 
WTSR            0x00395D       Second data register 
WTMR            0x00395E       Minute data register 
WTHR            0x00395F       Hour data register 
PWC10           0x003980       PWM1 compare register 0 
PWC20           0x003982       PWM2 compare register 0 
PWS10           0x003984       PWM1 select register 0 
PWS20           0x003985       PWM2 select register 0 
PWC11           0x003988       PWM1 compare register 1 
PWC21           0x00398A       PWM2 compare register 1 
PWS11           0x00398C       PWM1 select register 1 
PWS21           0x00398D       PWM2 select register 1 
PWC12           0x003990       PWM1 compare register 2 
PWC22           0x003992       PWM2 compare register 2 
PWS12           0x003994       PWM1 select register 2 
PWS22           0x003995       PWM2 select register 2 
PWC13           0x003998       PWM1 compare register 3 
PWC23           0x00399A       PWM2 compare register 3 
PWS13           0x00399C       PWM1 select register 3 
PWS23           0x00399D       PWM2 select register 3 




.MB90440G
; DS07-13716-1E  http://edevice.fujitsu.com/fj/DATASHEET/e-ds/e713716.pdf
; MB90443G/F443G/V440G


; ROM: 128 Kbytes
; RAM:   6 Kbyte (MB90443G/MB90F443G)
;       14 Kbyte (MB90V440G)


; MEMORY MAP
; [MB90V440G]
area DATA FSR              0x000000:0x0000C0
area DATA MEM_EXT_1        0x0000C0:0x000100
area DATA RAM              0x000100:0x003900
area DATA FSR_1            0x003900:0x004000
area DATA ROM_1            0x004000:0x010000
area DATA MEM_EXT_3        0x010000:0xFC0000
area DATA ROM_2_BANK_FC    0xFC0000:0xFD0000
area DATA ROM_2_BANK_FD    0xFD0000:0xFE0000
area DATA ROM_2_BANK_FE    0xFE0000:0xFF0000
area DATA ROM_2_BANK_FF    0xFF0000:0x1000000

; [MB90F443G/MB90443G (under development)]
; area DATA FSR              0x000000:0x0000C0
; area DATA MEM_EXT_1        0x0000C0:0x000100
; area DATA RAM              0x000100:0x001900
; area DATA MEM_EXT_2        0x002000:0x003900
; area DATA FSR_1            0x003900:0x004000
; area DATA ROM_1            0x004000:0x010000
; area DATA MEM_EXT_3        0x010000:0xFE0000
; area DATA ROM_2_BANK_FE    0xFE0000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000


; Interrupt and reset vector assignments
interrupt __RESET        0xFFFFDC   Reset 
interrupt INT9           0xFFFFD8   INT9 instruction 
interrupt EXCEPT         0xFFFFD4   Exception processing 
interrupt CAN_0_R        0xFFFFD0   CAN 0 Receive 
interrupt CAN_0_T        0xFFFFCC   CAN 0 Transmit/Node status 
interrupt CAN_1_R        0xFFFFC8   CAN 1 Receive 
interrupt CAN_1_T        0xFFFFC4   CAN 1 Transmit/Node status 
interrupt INT0_INT1      0xFFFFC0   External interrupt (INT0/INT1) 
interrupt T_TIMER        0xFFFFBC   Timebase timer 
interrupt R_TIMER0       0xFFFFB8   16-bit reload timer 0 
interrupt AD_CONV        0xFFFFB4   8/10-bit A/D converter 
interrupt IO_TIMER       0xFFFFB0   Input/output timer 
interrupt INT2_INT3      0xFFFFAC   External interrupt (INT2/INT3) 
interrupt IO             0xFFFFA8   Serial I/O 
interrupt PPG_TIMER_0123 0xFFFFA4   8/16-bit PPG timer 0/1/2/3 
interrupt IC0            0xFFFFA0   Input capture 0 
interrupt INT4_INT5      0xFFFF9C   External interrupt (INT4/INT5) 
interrupt CAN_2_R        0xFFFF98   CAN 2 Receive 
interrupt CAN_2_T        0xFFFF94   CAN 2 Transmit/Node status 
interrupt INT6_INT7      0xFFFF90   External interrupt (INT6/INT7) 
interrupt M_TIMER        0xFFFF8C   Monitoring timer 
interrupt IC1            0xFFFF88   Input capture 1 
interrupt IC23           0xFFFF84   Input capture 2/3 
interrupt PPG_TIMER_4567 0xFFFF80   8/16-bit PPG timer 4/5/6/7 
interrupt OC0            0xFFFF7C   Output compare 0 
interrupt OC1            0xFFFF78   Output compare 1 
interrupt IC4_5          0xFFFF74   Input capture 4/5 
interrupt OC2_3          0xFFFF70   Output compare 2/3-input capture 6/7 
interrupt R_TIMER1       0xFFFF6C   16-bit reload timer 1 
interrupt UART0_R        0xFFFF68   UART 0 Receive 
interrupt UART0_T        0xFFFF64   UART 0 Transmit 
interrupt UART1_R        0xFFFF60   UART 1 Receive 
interrupt UART1_T        0xFFFF5C   UART 1 Transmit 
interrupt FLASH          0xFFFF58   Flash memory 
interrupt DELAY          0xFFFF54   Delayed interrupt generation module 


; INPUT/OUTPUT PORTS
PDR0            0x000000     Port 0 data register 
PDR1            0x000001     Port 1 data register 
PDR2            0x000002     Port 2 data register 
PDR3            0x000003     Port 3 data register 
PDR4            0x000004     Port 4 data register 
PDR5            0x000005     Port 5 data register 
PDR6            0x000006     Port 6 data register 
PDR7            0x000007     Port 7 data register 
PDR8            0x000008     Port 8 data register 
PDR9            0x000009     Port 9 data register 
PDRA            0x00000A     Port A data register 
PILR            0x00000B     Port input levels select register 
CANSWR          0x00000C     CAN2 RX/TX pin switching register 
Reserv00000D    0x00000D     Reserved
Reserv00000E    0x00000E     Reserved
Reserv00000F    0x00000F     Reserved
DDR0            0x000010     Port 0 direction register 
DDR1            0x000011     Port 1 direction register 
DDR2            0x000012     Port 2 direction register 
DDR3            0x000013     Port 3 direction register 
DDR4            0x000014     Port 4 direction register 
DDR5            0x000015     Port 5 direction register 
DDR6            0x000016     Port 6 direction register 
DDR7            0x000017     Port 7 direction register 
DDR8            0x000018     Port 8 direction register 
DDR9            0x000019     Port 9 direction register 
DDRA            0x00001A     Port A direction register 
ADER            0x00001B     Analog input enable register 
PUCR0           0x00001C     Port 0 pullup control register 
PUCR1           0x00001D     Port 1 pullup control register 
PUCR2           0x00001E     Port 2 pullup control register 
PUCR3           0x00001F     Port 3 pullup control register 
UMC0            0x000020     Serial mode control register 0 
USR0            0x000021     Serial status register 0 
UIDR0_UODR0     0x000022     Serial input/output data register 0 
URD0            0x000023     Rate and data register 0 
SMR1            0x000024     Serial mode register 1 
SCR1            0x000025     Serial control register 1 
SIDR1_SODR1     0x000026     Serial input/output data register 1 
SSR1            0x000027     Serial status register 1 
U1CDCR          0x000028     UART1 prescaler control register 
SES1            0x000029     Serial edge selection registor 
Reserv00002A    0x00002A     Reserved
SCDCR           0x00002B     Serial I/O prescaler 
SMCS            0x00002C     Serial mode control register 
SMCS            0x00002D     Serial mode control register 
SDR             0x00002E     Serial Data register 
SES2            0x00002F     Serial edge selection registor 2 
ENIR            0x000030     External interrupt enable register 
EIRR            0x000031     External interrupt request register 
ELVR            0x000032     External request level setting register 
ADCS0           0x000034     A/D control status register 0 
ADCS1           0x000035     A/D control status register 1 
ADCR0           0x000036     A/D data register 0 
ADCR1           0x000037     A/D data register 1 
PPGC0           0x000038     PPG0 operation mode control register 
PPGC1           0x000039     PPG1 operation mode control register 
PPG01           0x00003A     PPG0 and PPG1 clock selection register 
Reserv00003B    0x00003B     Reserved
PPGC2           0x00003C     PPG2 operation mode control register 
PPGC3           0x00003D     PPG3 operation mode control register 
PPG23           0x00003E     PPG2 and PPG3 clock selection register 
Reserv00003F    0x00003F     Reserved
PPGC4           0x000040     PPG4 operation mode control register 
PPGC5           0x000041     PPG5 operation mode control register 
PPG45           0x000042     PPG4 and PPG5 clock selection register 
Reserv000043    0x000043     Reserved
PPGC6           0x000044     PPG6 operation mode control register 
PPGC7           0x000045     PPG7 operation mode control register 
PPG67           0x000046     PPG6 and PPG7 clock selection register 
Reserv000047    0x000047     Reserved
Reserv000048    0x000048     Reserved
Reserv000049    0x000049     Reserved
Reserv00004A    0x00004A     Reserved
Reserv00004B    0x00004B     Reserved
ICS01           0x00004C     Input capture control status 0/1 
ICS23           0x00004D     Input capture control status 2/3 
ICS45           0x00004E     Input capture control status 4/5 
ICS67           0x00004F     Input capture control status 6/7 
TMCSR0          0x000050     Timer control status register 0 
TMR0_TMRLR0     0x000052     Timer register 0/reload register 0 
TMCSR1          0x000054     Timer control status register 1 
TMR1_TMRLR1     0x000056     Timer register 1/Reload register 1 
OCS0            0x000058     Output compare control status register 0 
OCS1            0x000059     Output compare control status register 1 
OCS2            0x00005A     Output compare control status register 2 
OCS3            0x00005B     Output compare control status register 3 
TCDT            0x00006C     Timer data register 
TCCS            0x00006E     Timer control status register 
ROMM            0x00006F     ROM mirror function selection register 
PACSR           0x00009E     Program address detection control status register 
DIRR            0x00009F     Delayed interrupt/release register 
LPMCR           0x0000A0     Low-power consumption mode control register 
CKSCR           0x0000A1     Clock selection register 
ARSR            0x0000A2     to A4H Prohibited area A5H Automatic ready function select register 
HACR            0x0000A6     External address output control register 
ECSR            0x0000A7     Bus control signal selection register 
WDTC            0x0000A8     Watchdog timer control register 
TBTC            0x0000A9     Time base timer control register 
WTC             0x0000AA     Watch timer control register 
FMCS            0x0000AE     Flash memory control status register (Flash only, otherwise reserved) 
ICR00           0x0000B0     Interrupt control register 00 
ICR01           0x0000B1     Interrupt control register 01 
ICR02           0x0000B2     Interrupt control register 02 
ICR03           0x0000B3     Interrupt control register 03 
ICR04           0x0000B4     Interrupt control register 04 
ICR05           0x0000B5     Interrupt control register 05 
ICR06           0x0000B6     Interrupt control register 06 
ICR07           0x0000B7     Interrupt control register 07 
ICR08           0x0000B8     Interrupt control register 08 
ICR09           0x0000B9     Interrupt control register 09 
ICR10           0x0000BA     Interrupt control register 10 
ICR11           0x0000BB     Interrupt control register 11 
ICR12           0x0000BC     Interrupt control register 12 
ICR13           0x0000BD     Interrupt control register 13 
ICR14           0x0000BE     Interrupt control register 14 
ICR15           0x0000BF     Interrupt control register 15 
PRLH0           0x003901     Reload register H 
PRLL1           0x003902     Reload register L 
PRLH1           0x003903     Reload register H 
PRLL2           0x003904     Reload register L 
PRLH2           0x003905     Reload register H 
PRLL3           0x003906     Reload register L 
PRLH3           0x003907     Reload register H 
PRLL4           0x003908     Reload register L 
PRLH4           0x003909     Reload register H 
PRLL5           0x00390A     Reload register L 
PRLH5           0x00390B     Reload register H 
PRLL6           0x00390C     Reload register L 
PRLH6           0x00390D     Reload register H 
PRLL7           0x00390E     Reload register L 
PRLH7           0x00390F     Reload register H 
Reserv003910    0x003910     Reserved
Reserv003911    0x003911     Reserved
Reserv003912    0x003912     Reserved
Reserv003913    0x003913     Reserved
Reserv003914    0x003914     Reserved
Reserv003915    0x003915     Reserved
Reserv003916    0x003916     Reserved
Reserv003917    0x003917     Reserved
IPCP0           0x003918     Input capture register 0 
IPCP1           0x00391A     Input capture register 1 
IPCP2           0x00391C     Input capture register 2 
IPCP3           0x00391E     Input capture register 3 
IPCP4           0x003920     Input capture register 4 
IPCP5           0x003922     Input capture register 5 
IPCP6           0x003924     Input capture register 6 
IPCP7           0x003926     Input capture register 7 
OCCP0           0x003928     Output compare register 0 
OCCP1           0x00392A     Output compare register 1 
OCCP2           0x00392C     Output compare register 2 
OCCP3           0x00392E     Output compare register 3 


.MB90460
; DS07-13714-1E  http://edevice.fujitsu.com/fj/DATASHEET/e-ds/e713714.pdf
; MB90462/467/F462/V460


; ROM: 64 KBytes (MB90F462/MB90462/MB90467)
; RAM:  8 KBytes (MB90V460)
;       2 KBytes (MB90F462/MB90462/MB90467)


; MEMORY MAP
; [MB90462/467/MB90F462]
area DATA FSR              0x000000:0x0000C0
area BSS  No_access_1      0x0000C0:0x000100
area DATA RAM              0x000100:0x000900
area BSS  No_access_2      0x000900:0x003FE0
area DATA FSR_1            0x003FE0:0x004000
area DATA ROM_1            0x004000:0x010000
area BSS  No_access_3      0x010000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000

; [MB90V460]
; area DATA FSR              0x000000:0x0000C0
; area BSS  No_access_1      0x0000C0:0x000100
; area DATA RAM              0x000100:0x002100
; area BSS  No_access_2      0x002100:0x003FE0
; area DATA FSR_1            0x003FE0:0x004000
; area DATA ROM_1            0x004000:0x010000
; area BSS  No_access_3      0x010000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000


; Interrupt and reset vector assignments
interrupt __RESET       0xFFFFDC   Reset 
interrupt INT9          0xFFFFD8   INT9 instruction 
interrupt EXCEPT        0xFFFFD4   Exception processing 
interrupt AD_CONV       0xFFFFD0   A/D converter conversion termination 
interrupt OC_CH0        0xFFFFCC   Output compare channel 0 match 
interrupt PWC0_TIMER    0xFFFFC8   End of measurement by PWC0 timer / PWC0 timer overflow 
interrupt PPG_TIMER0    0xFFFFC4   16-bit PPG timer 0 
interrupt OC_CH1        0xFFFFC0   Output compare channel 1 match 
interrupt PPG_TIMER1    0xFFFFBC   16-bit PPG timer 1 
interrupt OC_CH2        0xFFFFB8   Output compare channel 2 match 
interrupt R_TIMER1      0xFFFFB4   16-bit reload timer 1 underflow 
interrupt OC_CH3        0xFFFFB0   Output compare channel 3 match 
interrupt DTP_CH01      0xFFFFAC   DTP/ext. interrupt channels 0/1 detection 
interrupt OC_CH4        0xFFFFA8   Output compare channel 4 match 
interrupt DTP_CH23      0xFFFFA4   DTP/ext. interrupt channels 2/3 detection 
interrupt OC_CH5        0xFFFFA0   Output compare channel 5 match 
interrupt PWC1_TIMER    0xFFFF9C   End of measurement by PWC1 timer /PWC1 timer overflow 
interrupt DTP_CH45      0xFFFF98   DTP/ext. interrupt channels 4/5 detection 
interrupt WFS_TIMER     0xFFFF94   Waveform sequencer timer compare match / write timing 
interrupt DTP_CH67      0xFFFF90   DTP/ext. interrupt channels 6/7 detection 
interrupt WFPD          0xFFFF8C   Waveform sequencer position detect / compare interrupt 
interrupt WFG           0xFFFF88   Waveform generator 16-bit timer 0/1/2 underflow 
interrupt R_TIMER0      0xFFFF84   16-bit reload timer 0 underflow 
interrupt FR_TIMER_ZD   0xFFFF80   16-bit free-running timer zero detect 
interrupt PPG_TIMER2    0xFFFF7C   16-bit PPG timer 2 
interrupt IC_CH01       0xFFFF78   Input capture channels 0/1 
interrupt FR_TIMER_CC   0xFFFF74   16-bit free-running timer compare clear 
interrupt IC_CH23       0xFFFF70   Input capture channels 2/3 
interrupt T_TIMER       0xFFFF6C   Timebase timer 
interrupt UART1_R       0xFFFF68   UART1 receive 
interrupt UART1_S       0xFFFF64   UART1 send 
interrupt UART0_R       0xFFFF60   UART0 receive 
interrupt UART0_S       0xFFFF5C   UART0 send 
interrupt FLASH         0xFFFF58   Flash memory status 
interrupt DELAY         0xFFFF54   Delayed interrupt generator module 


; INPUT/OUTPUT PORTS
PDR0            0x000000     Port 0 data register R/W R/W Port 0 
PDR1            0x000001     Port 1 data register R/W R/W Port 1 
PDR2            0x000002     Port 2 data register R/W R/W Port 2 
PDR3            0x000003     Port 3 data register R/W R/W Port 3 
PDR4            0x000004     Port 4 data register R/W R/W Port 4 
PDR5            0x000005     Port 5 data register R/W R/W Port 5 
PDR6            0x000006     Port 6 data register R/W R/W Port 6 
PWCSL0          0x000008     PWC control status register CH0 L
PWCSH0          0x000009     PWC control status register CH0 H
PWC0            0x00000A     PWC data buffer register CH0 
DIV0            0x00000C     Divide ratio control register CH0 
DDR0            0x000010     Port 0 direction register 
DDR1            0x000011     Port 1 direction register 
DDR2            0x000012     Port 2 direction register 
DDR3            0x000013     Port 3 direction register 
DDR4            0x000014     Port 4 direction register 
DDR5            0x000015     Port 5 direction register 
DDR6            0x000016     Port 6 direction register 
ADER            0x000017     Analog input enable register 
CDCR0           0x000019     Clock division control register 0 
CDCR1           0x00001B     Clock division control register 1 
RDR0            0x00001C     Port 0 pull-up resistor setting register 
RDR1            0x00001D     Port 1 pull-up resistor setting register 
SMR0            0x000020     Serial mode register 0 
SCR0            0x000021     Serial control register 0 
SIDR0_SODR0     0x000022     Input data register 0 / output data register 0 
SSR0            0x000023     Serial status register 0 
SMR1            0x000024     Serial mode register 1 
SCR1            0x000025     Serial control register 1 
SIDR1_SODR1     0x000026     Input data register 1 / output data register 1 
SSR1            0x000027     Status register 1 
PWCSL1          0x000028     PWC control status register CH1 H
PWCSH1          0x000029     PWC control status register CH1 L
PWC1            0x00002A     PWC data buffer register CH1 
DIV1            0x00002C     Divide ratio control register CH1 
ENIR            0x000030     Interrupt / DTP enable register 
EIRR            0x000031     Interrupt / DTP cause register 
ELVRL           0x000032     Request level setting register (Lower Byte) 
ELVRH           0x000033     Request level setting register (Higher Byte) 
ADCS0           0x000034     A/D control status register 0 
ADCS1           0x000035     A/D control status register 1 
ADCR0           0x000036     A/D data register 0 
ADCR1           0x000037     A/D data register 1 
PDCR0           0x000038     PPG0 down counter register 
PCSR0           0x00003A     PPG0 period setting register 
PDUT0           0x00003C     PPG0 duty setting register 
PCNTL0          0x00003E     PPG0 control status register L
PCNTH0          0x00003F     PPG0 control status register H
PDCR1           0x000040     PPG1 down counter register 
PCSR1           0x000042     PPG1 period setting register 
PDUT1           0x000044     PPG1 duty setting register 
PCNTL1          0x000046     PPG1 control status register L
PCNTH1          0x000047     PPG1 control status register H
PDCR2           0x000048     PPG2 down counter register 
PCSR2           0x00004A     PPG2 period setting register 
PDUT2           0x00004C     PPG2 duty setting register 
PCNTL2          0x00004E     PPG2 control status register L
PCNTH2          0x00004F     PPG2 control status register H
TMRR0           0x000050     16-bit timer register 0 
TMRR1           0x000052     16-bit timer register 
TMRR2           0x000054     16-bit timer register 2 
DTCR0           0x000056     16-bit timer control register 0 
DTCR1           0x000057     16-bit timer control register 1 
DTCR2           0x000058     16-bit timer control register 2 
SIGCR           0x000059     Waveform control register 
CPCLRB_CPCLR    0x00005A     Compare clear buffer register / Compare clear register (lower) 
TCDT            0x00005C     Timer data register (lower) 
TCCSL           0x00005E     Timer control status register (lower) 
TCCSH           0x00005F     Timer control status register (upper)
IPCP0           0x000060     Input capture data register CH0 
IPCP1           0x000062     Input capture data register CH1 
IPCP2           0x000064     Input capture data register CH2 
IPCP3           0x000066     Input capture data register CH3 
PICSL01         0x000068     PPG output control / Input capture control status register 01 (lower) 
PICSH01         0x000069     PPG output control / Input capture control status register 01 (upper) 
ICSL23          0x00006A     Input capture control status register 23 (lower) 
ICSH23          0x00006B     Input capture control status register
ROMM            0x00006F     ROM mirroring function selection register 
OCCPB0_OCCP0    0x000070     Output compare buffer register / output compare register 0 
OCCPB1_OCCP1    0x000072     Output compare buffer register / output compare register 1 
OCCPB2_OCCP2    0x000074     Output compare buffer register / output compare register 2 
OCCPB3_OCCP3    0x000076     Output compare buffer register / output compare register 3 
OCCPB4_OCCP4    0x000078     Output compare buffer register / output compare register 4 
OCCPB5_OCCP5    0x00007A     Output compare buffer register / output compare register 5 
OCS0            0x00007C     Compare control register 0 
OCS1            0x00007D     Compare control register 1 
OCS2            0x00007E     Compare control register 2 
OCS3            0x00007F     Compare control register 3 
OCS4            0x000080     Compare control register 4 
OCS5            0x000081     Compare control register 5 
TMCSRL0         0x000082     Timer control status register CH0 (lower) 
TMCSRH0         0x000083     Timer control status register CH0 (upper) 
TMR0_TMRD0      0x000084     16 bit timer register CH0 / 16-bit reload register CH0 
TMCSRL1         0x000086     Timer control status register CH1 (lower) 
TMCSRH1         0x000087     Timer control status register CH1 (upper) 
TMR1_TMRD1      0x000088     16 bit timer register CH1 / 16-bit reload register CH1 
OPCLR           0x00008A     Output control lower register 
OPCUR           0x00008B     Output control upper register 
IPCLR           0x00008C     Input control lower register 
IPCUR           0x00008D     Input control upper register 
TCSR            0x00008E     Timer control status register 
NCCR            0x00008F     Noise cancellation control register 
PACSR           0x00009E     Program address detect control status register 
DIRR            0x00009F     Delayed interrupt cause / clear register 
LPMCR           0x0000A0     Low-power consumption mode register 
CKSCR           0x0000A1     Clock selection register 
WDTC            0x0000A8     Watchdog control register 
TBTC            0x0000A9     Timebase timer control register
FMCS            0x0000AE     Flash memory control status register 
ICR00           0x0000B0     Interrupt control register 00 
ICR01           0x0000B1     Interrupt control register 01 
ICR02           0x0000B2     Interrupt control register 02 
ICR03           0x0000B3     Interrupt control register 03 
ICR04           0x0000B4     Interrupt control register 04 
ICR05           0x0000B5     Interrupt control register 05 
ICR06           0x0000B6     Interrupt control register 06 
ICR07           0x0000B7     Interrupt control register 07 
ICR08           0x0000B8     Interrupt control register 08 
ICR09           0x0000B9     Interrupt control register 09 
ICR10           0x0000BA     Interrupt control register 10 
ICR11           0x0000BB     Interrupt control register 11 
ICR12           0x0000BC     Interrupt control register 12 
ICR13           0x0000BD     Interrupt control register 13 
ICR14           0x0000BE     Interrupt control register 14 
ICR15           0x0000BF     Interrupt control register 15 
OPDBR0          0x003FE0     Output data buffer register 0 
OPDBR1          0x003FE2     Output data buffer register 1 
OPDBR2          0x003FE4     Output data buffer register 2 
OPDBR3          0x003FE6     Output data buffer register 3 
OPDBR4          0x003F78     Output data buffer register 4 
OPDBR5          0x003FEA     Output data buffer register 5 
OPEBR6          0x003FEC     Output data buffer register 6 
OPEBR7          0x003FEE     Output data buffer register 7 
OPEBR8          0x003FF0     Output data buffer register 8 
OPEBR9          0x003FF2     Output data buffer register 9 
OPEBRA          0x003FF4     Output data buffer register A 
OPEBRB          0x003FF6     Output data buffer register B 
OPDR            0x003FF8     Output data register 
CPCR            0x003FFA     Compare clear register 
TMBR            0x003FFC     Timer buffer register 


.MB90470
; DS07-13712-1E  http://edevice.fujitsu.com/fj/DATASHEET/e-ds/e713712.pdf
; MB90473/474/477/478/F474L/F474H


; FLASH ROM: 256 KB (MB90F474L/MB90F474H)
; MASKROM:   128 KB (MB90473)
;            256 KB (MB90474)
; RAM:        16 KB (MB90F474L/MB90F474H/MB90474)
;             10 KB (MB90473)


; MEMORY MAP
; [MB90473]
area DATA FSR              0x000000:0x0000D0
area BSS  No_access_1      0x0000D0:0x000100
area DATA RAM              0x000100:0x002900
area BSS  No_access_2      0x002900:0x004000
area DATA ROM_1            0x004000:0x010000
area BSS  No_access_3      0x010000:0xFE0000
; area DATA ROM_2_BANK_FE    0xFE0000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000

; [MB90474/MB90F474/MB90V470]
; area DATA FSR              0x000000:0x0000D0
; area BSS  No_access_1      0x0000D0:0x000100
; area DATA RAM              0x000100:0x004000
; area DATA ROM_1            0x004000:0x010000
; area BSS  No_access_3      0x010000:0xFC0000
; area DATA ROM_2_BANK_FC    0xFC0000:0xFD0000
; area DATA ROM_2_BANK_FD    0xFD0000:0xFE0000
; area DATA ROM_2_BANK_FE    0xFE0000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000

; [MB90477/MB90478]
; area DATA FSR              0x000000:0x0000D0
; area BSS  No_access_1      0x0000D0:0x000100
; area DATA RAM              0x000100:0x002100
; area BSS  No_access_2      0x002100:0x004000
; area DATA ROM_1            0x004000:0x010000
; area BSS  No_access_3      0x010000:0xFC0000
; area DATA ROM_2_BANK_FC    0xFC0000:0xFD0000
; area DATA ROM_2_BANK_FD    0xFD0000:0xFE0000
; area DATA ROM_2_BANK_FE    0xFE0000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000


; Interrupt and reset vector assignments
interrupt __RESET       0xFFFFDC   Reset 
interrupt INT9          0xFFFFD8   INT9 instruction 
interrupt EXCEPT        0xFFFFD4   Exception 
interrupt INT0          0xFFFFD0   INT0 
interrupt INT1          0xFFFFCC   INT1 
interrupt INT2          0xFFFFC8   INT2 
interrupt INT3          0xFFFFC4   INT3 
interrupt INT4          0xFFFFC0   INT4 
interrupt INT5          0xFFFFBC   INT5 
interrupt INT6          0xFFFFB8   INT6 
interrupt INT7          0xFFFFB4   INT7 
interrupt PWC1          0xFFFFB0   PWC1 
interrupt PWC2          0xFFFFAC   PWC2 
interrupt PWC0          0xFFFFA8   PWC0 
interrupt PPG0_PPG1     0xFFFFA4   PPG0/PPG1 counter borrow 2 
interrupt PPG2_PPG3     0xFFFFA0   PPG2/PPG3 counter borrow 3 
interrupt PPG4_PPG5     0xFFFF9C   PPG4/PPG5 counter borrow 4 
interrupt UDCTC_CH01    0xFFFF98   8/16-bit up/down counter timer compare/ underflow /overflow/ amp down inversion (ch0, 1) 
interrupt IC0           0xFFFF94   Input capture (ch0) load 
interrupt IC1           0xFFFF90   Input capture (ch1) load 
interrupt OC0           0xFFFF8C   Output compare (ch0) match 
interrupt OC1           0xFFFF88   Output compare (ch1) match 
interrupt OC2           0xFFFF84   Output compare (ch2) match 
interrupt OC3           0xFFFF80   Output compare (ch3) match 
interrupt OC4           0xFFFF7C   Output compare (ch4) match 
interrupt OC5           0xFFFF78   Output compare (ch5) match 
interrupt UART_S        0xFFFF74   UART send end 
interrupt F_TIMER       0xFFFF70   16-bit free run timer/16-bit reload timer overflow 
interrupt UART_R        0xFFFF6C   UART receive end 
interrupt SIO1          0xFFFF68   SIO1 
interrupt SIO2          0xFFFF64   SIO2 
interrupt I2C           0xFFFF60   I2C interface 
interrupt AD            0xFFFF5C   A/D 
interrupt FLASH         0xFFFF58   Flash write/erase, time base timer/ clock timer) 
interrupt DELAY         0xFFFF54   Delay interrupt generator module 


; INPUT/OUTPUT PORTS
PDR0            0x000000     Port 0 data register 
PDR0.P07         7
PDR0.P06         6
PDR0.P05         5
PDR0.P04         4
PDR0.P03         3
PDR0.P02         2
PDR0.P01         1
PDR0.P00         0
PDR1            0x000001     Port 1 data register 
PDR1.P17         15
PDR1.P16         14
PDR1.P15         13
PDR1.P14         12
PDR1.P13         11
PDR1.P12         10
PDR1.P11         9
PDR1.P10         8
PDR2            0x000002     Port 2 data register 
PDR2.P27         7
PDR2.P26         6
PDR2.P25         5
PDR2.P24         4
PDR2.P23         3
PDR2.P22         2
PDR2.P21         1
PDR2.P20         0
PDR3            0x000003     Port 3 data register 
PDR3.P37         15
PDR3.P36         14
PDR3.P35         13
PDR3.P34         12
PDR3.P33         11
PDR3.P32         10
PDR3.P31         9
PDR3.P30         8
PDR4            0x000004     Port 4 data register 
PDR4.P47         7
PDR4.P46         6
PDR4.P45         5
PDR4.P44         4
PDR4.P43         3
PDR4.P42         2
PDR4.P41         1
PDR4.P40         0
PDR5            0x000005     Port 5 data register 
PDR5.P57         15
PDR5.P56         14
PDR5.P55         13
PDR5.P54         12
PDR5.P53         11
PDR5.P52         10
PDR5.P51         9
PDR5.P50         8
PDR6            0x000006     Port 6 data register 
PDR6.P67         7
PDR6.P66         6
PDR6.P65         5
PDR6.P64         4
PDR6.P63         3
PDR6.P62         2
PDR6.P61         1
PDR6.P60         0
PDR7            0x000007     Port 7 data register 
PDR7.P77         15
PDR7.P76         14
PDR7.P75         13
PDR7.P74         12
PDR7.P73         11
PDR7.P72         10
PDR7.P71         9
PDR7.P70         8
PDR8            0x000008     Port 8 data register 
PDR8.P87         7
PDR8.P86         6
PDR8.P85         5
PDR8.P84         4
PDR8.P83         3
PDR8.P82         2
PDR8.P81         1
PDR8.P80         0
PDR9            0x000009     Port 9 data register 
PDR9.P97         15
PDR9.P96         14
PDR9.P95         13
PDR9.P94         12
PDR9.P93         11
PDR9.P92         10
PDR9.P91         9
PDR9.P90         8
PDRA            0x00000A     Port A data register 
PDRA.PA3         3
PDRA.PA2         2
PDRA.PA1         1
PDRA.PA0         0
UDRE            0x00000B     Port 3 timer input enable register 
UDRE.UDE5        13
UDRE.UDE4        12
UDRE.UDE3        11
UDRE.UDE2        10
UDRE.UDE1        9
UDRE.UDE0        8
ENIR            0x00000C     Interrupt/DTP enable register 
ENIR.EN7         7
ENIR.EN6         6
ENIR.EN5         5
ENIR.EN4         4
ENIR.EN3         3
ENIR.EN2         2
ENIR.EN1         1
ENIR.EN0         0
EIRR            0x00000D     Interrupt/DTP enable register 
EIRR.ER7         15
EIRR.ER6         14
EIRR.ER5         13
EIRR.ER4         12
EIRR.ER3         11
EIRR.ER2         10
EIRR.ER1         9
EIRR.ER0         8
ELVR            0x00000E     Demand level setting register 
ELVR.LB7         15
ELVR.LA7         14
ELVR.LB6         13
ELVR.LA6         12
ELVR.LB5         11
ELVR.LA5         10
ELVR.LB4         9
ELVR.LA4         8
ELVR.LB3         7
ELVR.LA3         6
ELVR.LB2         5
ELVR.LA2         4
ELVR.LB1         3
ELVR.LA1         2
ELVR.LB0         1
ELVR.LA0         0
DDR0            0x000010     Port 0 direction register 
DDR0.P07         7
DDR0.P06         6
DDR0.P05         5
DDR0.P04         4
DDR0.P03         3
DDR0.P02         2
DDR0.P01         1
DDR0.P00         0
DDR1            0x000011     Port 1 direction register 
DDR1.P17         15
DDR1.P16         14
DDR1.P15         13
DDR1.P14         12
DDR1.P13         11
DDR1.P12         10
DDR1.P11         9
DDR1.P10         8
DDR2            0x000012     Port 2 direction register 
DDR2.P27         7
DDR2.P26         6
DDR2.P25         5
DDR2.P24         4
DDR2.P23         3
DDR2.P22         2
DDR2.P21         1
DDR2.P20         0
DDR3            0x000013     Port 3 direction register 
DDR3.P37         15
DDR3.P36         14
DDR3.P35         13
DDR3.P34         12
DDR3.P33         11
DDR3.P32         10
DDR3.P31         9
DDR3.P30         8
DDR4            0x000014     Port 4 direction register 
DDR4.P47         7
DDR4.P46         6
DDR4.P45         5
DDR4.P44         4
DDR4.P43         3
DDR4.P42         2
DDR4.P41         1
DDR4.P40         0
DDR5            0x000015     Port 5 direction register 
DDR5.P57         15
DDR5.P56         14
DDR5.P55         13
DDR5.P54         12
DDR5.P53         11
DDR5.P52         10
DDR5.P51         9
DDR5.P50         8
DDR6            0x000016     Port 6 direction register 
DDR6.P67         7
DDR6.P66         6
DDR6.P65         5
DDR6.P64         4
DDR6.P63         3
DDR6.P62         2
DDR6.P61         1
DDR6.P60         0
DDR7            0x000017     Port 7 direction register 
DDR7.P75         13
DDR7.P74         12
DDR7.P73         11
DDR7.P72         10
DDR7.P71         9
DDR7.P70         8
DDR8            0x000018     Port 8 direction register 
DDR8.P87         7
DDR8.P86         6
DDR8.P85         5
DDR8.P84         4
DDR8.P83         3
DDR8.P82         2
DDR8.P81         1
DDR8.P80         0
DDR9            0x000019     Port 9 direction register 
DDR9.P97         15
DDR9.P96         14
DDR9.P95         13
DDR9.P94         12
DDR9.P93         11
DDR9.P92         10
DDR9.P91         9
DDR9.P90         8
DDRA            0x00001A     Port A direction register 
DDRA.PA3         3
DDRA.PA2         2
DDRA.PA1         1
DDRA.PA0         0
ODR4            0x00001B     Port 4 pin register 
ODR4.OD47        15
ODR4.OD46        14
ODR4.OD45        13
ODR4.OD44        12
ODR4.OD43        11
ODR4.OD42        10
ODR4.OD41        9
ODR4.OD40        8
RDR0            0x00001C     Port 0 resistance register 
RDR0.RD07        7
RDR0.RD06        6
RDR0.RD05        5
RDR0.RD04        4
RDR0.RD03        3
RDR0.RD02        2
RDR0.RD01        1
RDR0.RD00        0
RDR1            0x00001D     Port 1 resistance register 
RDR1.RD17        15
RDR1.RD16        14
RDR1.RD15        13
RDR1.RD14        12
RDR1.RD13        11
RDR1.RD12        10
RDR1.RD11        9
RDR1.RD10        8
ODR7            0x00001E     Port 7 pin register 
ODR7.OD75        5
ODR7.OD74        4
ODR7.OD73        3
ODR7.OD72        2
ODR7.OD71        1
ODR7.OD70        0
ADER            0x00001F     Analog input enable register 
ADER.ADE7        15
ADER.ADE6        14
ADER.ADE5        13
ADER.ADE4        12
ADER.ADE3        11
ADER.ADE2        10
ADER.ADE1        9
ADER.ADE0        8
SMR0            0x000020     Serial mode register 0 
SMR0.MD1         7
SMR0.MD0         6
SMR0.CS2         5
SMR0.CS1         4
SMR0.CS0         3
SMR0.SCKE        1
SMR0.SOE         0
SCR0            0x000021     Serial control register 0 
SCR0.PEN         15
SCR0.P           14
SCR0.SBL         13
SCR0.CL          12
SCR0.A_D         11
SCR0.REC         10
SCR0.RXE         9
SCR0.TXE         8
SIDR_SODR0      0x000022     Serial input register/ serial output register 
SIDR_SODR0.D7    7
SIDR_SODR0.D6    6
SIDR_SODR0.D5    5
SIDR_SODR0.D4    4
SIDR_SODR0.D3    3
SIDR_SODR0.D2    2
SIDR_SODR0.D1    1
SIDR_SODR0.D0    0
SSR0            0x000023     Serial status register 
SSR0.PE          15
SSR0.ORE         14
SSR0.FRE         13
SSR0.RDRF        12
SSR0.TDRE        11
SSR0.BDS         10
SSR0.RIE         9
SSR0.TIE         8
Reserv000024    0x000024     Reserved
CDCR            0x000025     Clock divider control register 
CDCR.MD          15
CDCR.SRST        14
CDCR.DIV3        11
CDCR.DIV2        10
CDCR.DIV1        9
CDCR.DIV0        8
SMCS0           0x000026     Serial mode control status register 0 
SMCS0.SMD2       15
SMCS0.SMD1       14
SMCS0.SMD0       13
SMCS0.SIE        12
SMCS0.SIR        11
SMCS0.BUSY       10
SMCS0.STOP       9
SMCS0.STRT       8
SMCS0.MODE       3
SMCS0.BDS        2
SMCS0.SOE        1
SMCS0.SCOE       0
SDR0            0x000028     Serial data register 
SDR0.D7          7
SDR0.D6          6
SDR0.D5          5
SDR0.D4          4
SDR0.D3          3
SDR0.D2          2
SDR0.D1          1
SDR0.D0          0
SDCR0           0x000029     Clock divider control register 
SDCR0.MD         15
SDCR0.DIV3       11
SDCR0.DIV2       10
SDCR0.DIV1       9
SDCR0.DIV0       8
SMCS1           0x00002A     Serial mode control status register 1 
SMCS1.SMD2       15
SMCS1.SMD1       14
SMCS1.SMD0       13
SMCS1.SIE        12
SMCS1.SIR        11
SMCS1.BUSY       10
SMCS1.STOP       9
SMCS1.STRT       8
SMCS1.MODE       3
SMCS1.BDS        2
SMCS1.SOE        1
SMCS1.SCOE       0
SDR1            0x00002C     Serial data register 
SDR1.D7          7
SDR1.D6          6
SDR1.D5          5
SDR1.D4          4
SDR1.D3          3
SDR1.D2          2
SDR1.D1          1
SDR1.D0          0
SDCR1           0x00002D     Clock divider control register 
PRLL0           0x00002E     PPG reload register L (ch0) 
PRLL0.D07        7
PRLL0.D06        6
PRLL0.D05        5
PRLL0.D04        4
PRLL0.D03        3
PRLL0.D02        2
PRLL0.D01        1
PRLL0.D00        0
PRLH0           0x00002F     PPG reload register H (ch0) 
PRLH0.D15        15
PRLH0.D14        14
PRLH0.D13        13
PRLH0.D12        12
PRLH0.D11        11
PRLH0.D10        10
PRLH0.D09        9
PRLH0.D08        8
PRLL1           0x000030     PPG reload register L (ch1) 
PRLL1.D07        7
PRLL1.D06        6
PRLL1.D05        5
PRLL1.D04        4
PRLL1.D03        3
PRLL1.D02        2
PRLL1.D01        1
PRLL1.D00        0
PRLH1           0x000031     PPG reload register H (ch1) 
PRLH1.D15        15
PRLH1.D14        14
PRLH1.D13        13
PRLH1.D12        12
PRLH1.D11        11
PRLH1.D10        10
PRLH1.D09        9
PRLH1.D08        8
PRLL2           0x000032     PPG reload register L (ch2) 
PRLL2.D07        7
PRLL2.D06        6
PRLL2.D05        5
PRLL2.D04        4
PRLL2.D03        3
PRLL2.D02        2
PRLL2.D01        1
PRLL2.D00        0
PRLH2           0x000033     PPG reload register H (ch2) 
PRLH2.D15        15
PRLH2.D14        14
PRLH2.D13        13
PRLH2.D12        12
PRLH2.D11        11
PRLH2.D10        10
PRLH2.D09        9
PRLH2.D08        8
PRLL3           0x000034     PPG reload register L (ch3) 
PRLL3.D07        7
PRLL3.D06        6
PRLL3.D05        5
PRLL3.D04        4
PRLL3.D03        3
PRLL3.D02        2
PRLL3.D01        1
PRLL3.D00        0
PRLH3           0x000035     PPG reload register H (ch3) 
PRLH3.D15        15
PRLH3.D14        14
PRLH3.D13        13
PRLH3.D12        12
PRLH3.D11        11
PRLH3.D10        10
PRLH3.D09        9
PRLH3.D08        8
PRLL4           0x000036     PPG reload register L (ch4) 
PRLL4.D07        7
PRLL4.D06        6
PRLL4.D05        5
PRLL4.D04        4
PRLL4.D03        3
PRLL4.D02        2
PRLL4.D01        1
PRLL4.D00        0
PRLH4           0x000037     PPG reload register H (ch4) 
PRLH4.D15        15
PRLH4.D14        14
PRLH4.D13        13
PRLH4.D12        12
PRLH4.D11        11
PRLH4.D10        10
PRLH4.D09        9
PRLH4.D08        8
PRLL5           0x000038     PPG reload register L (ch5) 
PRLL5.D07        7
PRLL5.D06        6
PRLL5.D05        5
PRLL5.D04        4
PRLL5.D03        3
PRLL5.D02        2
PRLL5.D01        1
PRLL5.D00        0
PRLH5           0x000039     PPG reload register H (ch5) 
PRLH5.D15        15
PRLH5.D14        14
PRLH5.D13        13
PRLH5.D12        12
PRLH5.D11        11
PRLH5.D10        10
PRLH5.D09        9
PRLH5.D08        8
PPGC0           0x00003A     PPG0 operating mode control register 
PPGC0.PEN0       7
PPGC0.PE00       5
PPGC0.PIE0       4
PPGC0.PUF0       3
PPGC1           0x00003B     PPG1 operating mode control register 
PPGC1.PEN1       15
PPGC1.PE10       13
PPGC1.PIE1       12
PPGC1.PUF1       11
PPGC1.MD1        10
PPGC1.MD0        9
PPGC2           0x00003C     PPG2 operating mode control register 
PPGC2.PEN0       7
PPGC2.PE00       5
PPGC2.PIE0       4
PPGC2.PUF0       3
PPGC3           0x00003D     PPG3 operating mode control register 
PPGC3.PEN1       15
PPGC3.PE10       13
PPGC3.PIE1       12
PPGC3.PUF1       11
PPGC3.MD1        10
PPGC3.MD0        9
PPGC4           0x00003E     PPG4 operating mode control register 
PPGC4.PEN0       7
PPGC4.PE00       5
PPGC4.PIE0       4
PPGC4.PUF0       3
PPGC5           0x00003F     PPG5 operating mode control register 
PPGC5.PEN1       15
PPGC5.PE10       13
PPGC5.PIE1       12
PPGC5.PUF1       11
PPGC5.MD1        10
PPGC5.MD0        9
PPG01           0x000040     PPG0, 1 output control register 
PPG01.PCS2       7
PPG01.PCS1       6
PPG01.PCS0       5
PPG01.PCM2       4
PPG01.PCM1       3
PPG01.PCM0       2
Reserv000041    0x000041     Reserved
PPG23           0x000042     PPG2, 3 output control register 
PPG23.PCS2       7
PPG23.PCS1       6
PPG23.PCS0       5
PPG23.PCM2       4
PPG23.PCM1       3
PPG23.PCM0       2
Reserv000043    0x000043     Reserved
PPG45           0x000044     PPG4, 5 output control register 
PPG45.PCS2       7
PPG45.PCS1       6
PPG45.PCS0       5
PPG45.PCM2       4
PPG45.PCM1       3
PPG45.PCM0       2
Reserv000045    0x000045     Reserved
ADCS1           0x000046     Control status register 
ADCS1.MD1        7
ADCS1.MD0        6
ADCS1.ANS2       5
ADCS1.ANS1       4
ADCS1.ANS0       3
ADCS1.ANE2       2
ADCS1.ANE1       1
ADCS1.ANE0       0
ADCS2           0x000047     Control status register 
ADCS2.BUSY       15
ADCS2.INT        14
ADCS2.INTE       13
ADCS2.PAUS       12
ADCS2.STS1       11
ADCS2.STS0       10
ADCS2.STRT       9
ADCR1           0x000048     Data register 
ADCR1.D7         7
ADCR1.D6         6
ADCR1.D5         5
ADCR1.D4         4
ADCR1.D3         3
ADCR1.D2         2
ADCR1.D1         1
ADCR1.D0         0
ADCR2           0x000049     Data register 
ADCR2.S10        15
ADCR2.ST1        14
ADCR2.ST0        13
ADCR2.CT1        12
ADCR2.CT0        11
ADCR2.D9         9
ADCR2.D8         8
OCCP0           0x00004A     Output compare register (ch0) 
OCCP0.C15        15
OCCP0.C14        14
OCCP0.C13        13
OCCP0.C12        12
OCCP0.C11        11
OCCP0.C10        10
OCCP0.C09        9
OCCP0.C08        8
OCCP0.C07        7
OCCP0.C06        6
OCCP0.C05        5
OCCP0.C04        4
OCCP0.C03        3
OCCP0.C02        2
OCCP0.C01        1
OCCP0.C00        0
OCCP1           0x00004C     Output compare register (ch1) 
OCCP1.C15        15
OCCP1.C14        14
OCCP1.C13        13
OCCP1.C12        12
OCCP1.C11        11
OCCP1.C10        10
OCCP1.C09        9
OCCP1.C08        8
OCCP1.C07        7
OCCP1.C06        6
OCCP1.C05        5
OCCP1.C04        4
OCCP1.C03        3
OCCP1.C02        2
OCCP1.C01        1
OCCP1.C00        0
OCCP2           0x00004E     Output compare register (ch2) 
OCCP2.C15        15
OCCP2.C14        14
OCCP2.C13        13
OCCP2.C12        12
OCCP2.C11        11
OCCP2.C10        10
OCCP2.C09        9
OCCP2.C08        8
OCCP2.C07        7
OCCP2.C06        6
OCCP2.C05        5
OCCP2.C04        4
OCCP2.C03        3
OCCP2.C02        2
OCCP2.C01        1
OCCP2.C00        0
OCCP3           0x000050     Output compare register (ch3) 
OCCP3.C15        15
OCCP3.C14        14
OCCP3.C13        13
OCCP3.C12        12
OCCP3.C11        11
OCCP3.C10        10
OCCP3.C09        9
OCCP3.C08        8
OCCP3.C07        7
OCCP3.C06        6
OCCP3.C05        5
OCCP3.C04        4
OCCP3.C03        3
OCCP3.C02        2
OCCP3.C01        1
OCCP3.C00        0
OCCP4           0x000052     Output compare register (ch4) 
OCCP4.C15        15
OCCP4.C14        14
OCCP4.C13        13
OCCP4.C12        12
OCCP4.C11        11
OCCP4.C10        10
OCCP4.C09        9
OCCP4.C08        8
OCCP4.C07        7
OCCP4.C06        6
OCCP4.C05        5
OCCP4.C04        4
OCCP4.C03        3
OCCP4.C02        2
OCCP4.C01        1
OCCP4.C00        0
OCCP5           0x000054     Output compare register (ch5) 
OCCP5.C15        15
OCCP5.C14        14
OCCP5.C13        13
OCCP5.C12        12
OCCP5.C11        11
OCCP5.C10        10
OCCP5.C09        9
OCCP5.C08        8
OCCP5.C07        7
OCCP5.C06        6
OCCP5.C05        5
OCCP5.C04        4
OCCP5.C03        3
OCCP5.C02        2
OCCP5.C01        1
OCCP5.C00        0
OCS0            0x000056     Output compare control register (ch0) 
OCS0.ICPIC       7
OCS0.ICP0        6
OCS0.ICE1        5
OCS0.ICE0        4
OCS0.CST1        1
OCS0.CST0        0
OCS1            0x000057     Output compare control register (ch1) 
OCS1.CMOD        12
OCS1.OTE1        11
OCS1.OTE0        10
OCS1.OTD1        9
OCS1.OTD0        8
OCS2            0x000058     Output compare control register (ch2) 
OCS2.ICPIC       7
OCS2.ICP0        6
OCS2.ICE1        5
OCS2.ICE0        4
OCS2.CST1        1
OCS2.CST0        0
OCS3            0x000059     Output compare control register (ch3) 
OCS3.CMOD        12
OCS3.OTE1        11
OCS3.OTE0        10
OCS3.OTD1        9
OCS3.OTD0        8
OCS4            0x00005A     Output compare control register (ch4) 
OCS4.ICPIC       7
OCS4.ICP0        6
OCS4.ICE1        5
OCS4.ICE0        4
OCS4.CST1        1
OCS4.CST0        0
OCS5            0x00005B     Output compare control register (ch5) 
OCS5.CMOD        12
OCS5.OTE1        11
OCS5.OTE0        10
OCS5.OTD1        9
OCS5.OTD0        8
IPCP0           0x00005C     Input capture register (ch0) 
IPCP0.CP15       15
IPCP0.CP14       14
IPCP0.CP13       13
IPCP0.CP12       12
IPCP0.CP11       11
IPCP0.CP10       10
IPCP0.CP09       9
IPCP0.CP08       8
IPCP0.CP07       7
IPCP0.CP06       6
IPCP0.CP05       5
IPCP0.CP04       4
IPCP0.CP03       3
IPCP0.CP02       2
IPCP0.CP01       1
IPCP0.CP00       0
IPCP1           0x00005E     Input capture register (ch1) 
IPCP1.CP15       15
IPCP1.CP14       14
IPCP1.CP13       13
IPCP1.CP12       12
IPCP1.CP11       11
IPCP1.CP10       10
IPCP1.CP09       9
IPCP1.CP08       8
IPCP1.CP07       7
IPCP1.CP06       6
IPCP1.CP05       5
IPCP1.CP04       4
IPCP1.CP03       3
IPCP1.CP02       2
IPCP1.CP01       1
IPCP1.CP00       0
ICS01           0x000060     Input capture control register 
ICS01.ICP1       7
ICS01.ICP0       6
ICS01.ICE1       5
ICS01.ICE0       4
ICS01.EG11       3
ICS01.EG10       2
ICS01.EG01       1
ICS01.EG00       0
Reserv000061    0x000061     Reserved
TCDTL           0x000062     Timer data register low 
TCDTL.T07        7
TCDTL.T06        6
TCDTL.T05        5
TCDTL.T04        4
TCDTL.T03        3
TCDTL.T02        2
TCDTL.T01        1
TCDTL.T00        0
TCDTH           0x000063     Timer data register high 
TCDTH.T15        15
TCDTH.T14        14
TCDTH.T13        13
TCDTH.T12        12
TCDTH.T11        11
TCDTH.T10        10
TCDTH.T09        9
TCDTH.T08        8
TCCS            0x000064     Timer control status register 
TCCS.ECKE        15
TCCS.MSI2        12
TCCS.MSI1        11
TCCS.MSI0        10
TCCS.ICLR        9
TCCS.ICRE        8
TCCS.IVF         7
TCCS.IVFE        6
TCCS.STOP        5
TCCS.MODE        4
TCCS.SCLR        3
TCCS.CLK2        2
TCCS.CLK1        1
TCCS.CLK0        0
CPCLRL          0x000066     Compare clear register low 
CPCLRL.CL07      7
CPCLRL.CL06      6
CPCLRL.CL05      5
CPCLRL.CL04      4
CPCLRL.CL03      3
CPCLRL.CL02      2
CPCLRL.CL01      1
CPCLRL.CL00      0
CPCLRH          0x000067     Compare clear register high 
CPCLRH.CL15      15
CPCLRH.CL14      14
CPCLRH.CL13      13
CPCLRH.CL12      12
CPCLRH.CL11      11
CPCLRH.CL10      10
CPCLRH.CL09      9
CPCLRH.CL08      8
UDCR0           0x000068     Up down count register ch0 
UDCR0.D07        7
UDCR0.D06        6
UDCR0.D05        5
UDCR0.D04        4
UDCR0.D03        3
UDCR0.D02        2
UDCR0.D01        1
UDCR0.D00        0
UDCR1           0x000069     Up down count register ch1 
UDCR1.D17        15
UDCR1.D16        14
UDCR1.D15        13
UDCR1.D14        12
UDCR1.D13        11
UDCR1.D12        10
UDCR1.D11        9
UDCR1.D10        8
RCR0            0x00006A     Reload compare register ch0 
RCR0.D07         7
RCR0.D06         6
RCR0.D05         5
RCR0.D04         4
RCR0.D03         3
RCR0.D02         2
RCR0.D01         1
RCR0.D00         0
RCR1            0x00006B     Reload compare register ch1 
RCR1.D17         15
RCR1.D16         14
RCR1.D15         13
RCR1.D14         12
RCR1.D13         11
RCR1.D12         10
RCR1.D11         9
RCR1.D10         8
CCRL0           0x00006C     Counter control register low ch0 
CCRL0.UDMS       7
CCRL0.CTUT       6
CCRL0.UCRE       5
CCRL0.RLDE       4
CCRL0.UDCC       3
CCRL0.CGSC       2
CCRL0.CGE1       1
CCRL0.CGE0       0
CCRH0           0x00006D     Counter control register high ch0 
CCRH0.M16E       15
CCRH0.CDCF       14
CCRH0.CFIE       13
CCRH0.CLKS       12
CCRH0.CMS1       11
CCRH0.CMS0       10
CCRH0.CES1       9
CCRH0.CES0       8
Reserv00006E    0x00006E     Reserved
ROMM            0x00006F     ROM mirror function select register 
ROMM.MI          8
CCRL1           0x000070     Counter control register low ch1 
CCRL1.UDMS       7
CCRL1.CTUT       6
CCRL1.UCRE       5
CCRL1.RLDE       4
CCRL1.UDCC       3
CCRL1.CGSC       2
CCRL1.CGE1       1
CCRL1.CGE0       0
CCRH1           0x000071     Counter control register high ch1 
CCRH1.CDCF       14
CCRH1.CFIE       13
CCRH1.CLKS       12
CCRH1.CMS1       11
CCRH1.CMS0       10
CCRH1.CES1       9
CCRH1.CES0       8
CSR0            0x000072     Count status register ch0 
CSR0.CSTR        7
CSR0.CITE        6
CSR0.UDIE        5
CSR0.CMPF        4
CSR0.OVFF        3
CSR0.UDFF        2
CSR0.UDF1        1
CSR0.UDF0        0
Reserv000073    0x000073     Reserved
CSR1            0x000074     Count status register ch1 
CSR1.CSTR        7
CSR1.CITE        6
CSR1.UDIE        5
CSR1.CMPF        4
CSR1.OVFF        3
CSR1.UDFF        2
CSR1.UDF1        1
CSR1.UDF0        0
Reserv000075    0x000075     Reserved
PWCSR0          0x000076     PWC0 control status register 
PWCSR0.STRT      15
PWCSR0.STOP      14
PWCSR0.EDIR      13
PWCSR0.EDIE      12
PWCSR0.OVIR      11
PWCSR0.OVIE      10
PWCSR0.ERR       9
PWCSR0.CKS1      7
PWCSR0.CKS0      6
PWCSR0.PIS1      5
PWCSR0.PIS0      4
PWCSR0.S_C       3
PWCSR0.MOD2      2
PWCSR0.MOD1      1
PWCSR0.MOD0      0
PWCR0           0x000078     PWC0 data buffer register 
PWCR0.D15        15
PWCR0.D14        14
PWCR0.D13        13
PWCR0.D12        12
PWCR0.D11        11
PWCR0.D10        10
PWCR0.D9         9 
PWCR0.D8         8
PWCR0.D7         7
PWCR0.D6         6
PWCR0.D5         5
PWCR0.D4         4
PWCR0.D3         3
PWCR0.D2         2
PWCR0.D1         1
PWCR0.D0         0
PWCSR1          0x00007A     PWC1 control status register 
PWCSR1.STRT      15
PWCSR1.STOP      14
PWCSR1.EDIR      13
PWCSR1.EDIE      12
PWCSR1.OVIR      11
PWCSR1.OVIE      10
PWCSR1.ERR       9
PWCSR1.CKS1      7
PWCSR1.CKS0      6
PWCSR1.PIS1      5
PWCSR1.PIS0      4
PWCSR1.S_C       3
PWCSR1.MOD2      2
PWCSR1.MOD1      1
PWCSR1.MOD0      0
PWCR1           0x00007C     PWC1 data buffer register 
PWCR1.D15        15
PWCR1.D14        14
PWCR1.D13        13
PWCR1.D12        12
PWCR1.D11        11
PWCR1.D10        10
PWCR1.D9         9 
PWCR1.D8         8
PWCR1.D7         7
PWCR1.D6         6
PWCR1.D5         5
PWCR1.D4         4
PWCR1.D3         3
PWCR1.D2         2
PWCR1.D1         1
PWCR1.D0         0
PWCSR2          0x00007E     PWC2 control status register 
PWCSR2.STRT      15
PWCSR2.STOP      14
PWCSR2.EDIR      13
PWCSR2.EDIE      12
PWCSR2.OVIR      11
PWCSR2.OVIE      10
PWCSR2.ERR       9
PWCSR2.CKS1      7
PWCSR2.CKS0      6
PWCSR2.PIS1      5
PWCSR2.PIS0      4
PWCSR2.S_C       3
PWCSR2.MOD2      2
PWCSR2.MOD1      1
PWCSR2.MOD0      0
PWCR2           0x000080     PWC2 data buffer register 
PWCR2.D15        15
PWCR2.D14        14
PWCR2.D13        13
PWCR2.D12        12
PWCR2.D11        11
PWCR2.D10        10
PWCR2.D9         9 
PWCR2.D8         8
PWCR2.D7         7
PWCR2.D6         6
PWCR2.D5         5
PWCR2.D4         4
PWCR2.D3         3
PWCR2.D2         2
PWCR2.D1         1
PWCR2.D0         0
DIVR0           0x000082     PWC0 division ratio register 
DIVR0.DIV1       1
DIVR0.DIV0       0
Reserv000083    0x000083     Reserved
DIVR1           0x000084     PWC1 division ratio register 
DIVR1.DIV1       1
DIVR1.DIV0       0
Reserv000085    0x000085     Reserved
DIVR2           0x000086     PWC2 division ratio register 
DIVR2.DIV1       1
DIVR2.DIV0       0
Reserv000087    0x000087     Reserved
IBSR            0x000088     I2C bus status register 
IBSR.BB          7
IBSR.RSC         6
IBSR.AL          5
IBSR.LRB         4
IBSR.TRX         3
IBSR.AAS         2
IBSR.GCA         1
IBSR.FBT         0
IBCR            0x000089     I2C bus control register 
IBCR.BER         15
IBCR.BEIE        14
IBCR.SCC         13
IBCR.MSS         12
IBCR.ACK         11
IBCR.GCAA        10
IBCR.INTE        9
IBCR.INT         8
ICCR            0x00008A     I2C bus clock select register 
ICCR.EN          5
ICCR.CS4         4
ICCR.CS3         3
ICCR.CS2         2
ICCR.CS1         1
ICCR.CS0         0
IADR            0x00008B     I2C bus address register 
IADR.A6          14
IADR.A5          13
IADR.A4          12
IADR.A3          11
IADR.A2          10
IADR.A1          9
IADR.A0          8
IDAR            0x00008C     I2C bus data register 
IDAR.D7          7
IDAR.D6          6
IDAR.D5          5
IDAR.D4          4
IDAR.D3          3
IDAR.D2          2
IDAR.D1          1
IDAR.D0          0
Reserv00008D    0x00008D     Reserved
PGCSR           0x00008E     mPG control register 
PGCSR.PEN0       7
PGCSR.PE1        6
PGCSR.PE0        5
PGCSR.PMT1       4
PGCSR.PMT0       3
DSRL            0x00009C     mDMA status register 
DSRH            0x00009D     mDMA status register 
DIRR            0x00009F     Delay interrupt source generate/release register 
LPMCR           0x0000A0     Low power mode register 
LPMCR.STP        7
LPMCR.SLP        6
LPMCR.SPL        5
LPMCR.RST        4
LPMCR.TMD        3
LPMCR.CG1        2
LPMCR.CG0        1
LPMCR.SSR        0
CKSCR           0x0000A1     Clock select register 
CKSCR.SCM        15
CKSCR.MCM        14
CKSCR.WS1        13
CKSCR.WS0        12
CKSCR.SCS        11
CKSCR.MCS        10
CKSCR.CS1        9
CKSCR.CS0        8
Reserv0000A2    0x0000A2     Reserved
Reserv0000A3    0x0000A3     Reserved
DSSR            0x0000A4     mDMA stop status register 
ARSR            0x0000A5     Auto ready function select register 
HACR            0x0000A6     External address output control register 
EPCR            0x0000A7     Bus control signal control register 
WDTC            0x0000A8     Watchdog control register 
WDTC.PONR        7
WDTC.STBR        6
WDTC.WRST        5
WDTC.ERST        4
WDTC.SRST        3
WDTC.WTE         2
WDTC.WT1         1
WDTC.WT0         0
TBTC            0x0000A9     Time base timer control register 
TBTC.TBIE        12
TBTC.TBOF        11
TBTC.TBR         10
TBTC.TBC1        9
TBTC.TBC0        8
WTC             0x0000AA     Clock timer control register 
WTC.PONR         7
WTC.STBR         6
WTC.WRST         5
WTC.ERST         4
WTC.SRST         3
WTC.WTE          2
WTC.WT1          1
WTC.WT0          0
Reserv0000AB    0x0000AB     Reserved
DERL            0x0000AC     mDMA control register 
DERH            0x0000AD     mDMA control register 
FMCR            0x0000AE     Flash memory control status register 
ICR00           0x0000B0     Interrupt control register 00 
ICR01           0x0000B1     Interrupt control register 01 
ICR02           0x0000B2     Interrupt control register 02 
ICR03           0x0000B3     Interrupt control register 03 
ICR04           0x0000B4     Interrupt control register 04 
ICR05           0x0000B5     Interrupt control register 05 
ICR06           0x0000B6     Interrupt control register 06 
ICR07           0x0000B7     Interrupt control register 07 
ICR08           0x0000B8     Interrupt control register 08 
ICR09           0x0000B9     Interrupt control register 09 
ICR10           0x0000BA     Interrupt control register 10 
ICR11           0x0000BB     Interrupt control register 11 
ICR12           0x0000BC     Interrupt control register 12 
ICR13           0x0000BD     Interrupt control register 13 
ICR14           0x0000BE     Interrupt control register 14 
ICR15           0x0000BF     Interrupt control register 15 
CMR0            0x0000C0     Chip select MASK register 0 
CMR0.M7          7
CMR0.M6          6
CMR0.M5          5
CMR0.M4          4
CMR0.M3          3
CMR0.M2          2
CMR0.M1          1
CMR0.M0          0
CAR0            0x0000C1     Chip select area register 0 
CAR0.A7          15
CAR0.A6          14
CAR0.A5          13
CAR0.A4          12
CAR0.A3          11
CAR0.A2          10
CAR0.A1          9
CAR0.A0          8
CMR1            0x0000C2     Chip select MASK register 1 
CMR1.M7          7
CMR1.M6          6
CMR1.M5          5
CMR1.M4          4
CMR1.M3          3
CMR1.M2          2
CMR1.M1          1
CMR1.M0          0
CAR1            0x0000C3     Chip select area register 1 
CAR1.A7          15
CAR1.A6          14
CAR1.A5          13
CAR1.A4          12
CAR1.A3          11
CAR1.A2          10
CAR1.A1          9
CAR1.A0          8
CMR2            0x0000C4     Chip select MASK register 2 
CMR2.M7          7
CMR2.M6          6
CMR2.M5          5
CMR2.M4          4
CMR2.M3          3
CMR2.M2          2
CMR2.M1          1
CMR2.M0          0
CAR2            0x0000C5     Chip select area register 2 
CAR2.A7          15
CAR2.A6          14
CAR2.A5          13
CAR2.A4          12
CAR2.A3          11
CAR2.A2          10
CAR2.A1          9
CAR2.A0          8
CMR3            0x0000C6     Chip select MASK register 3 
CMR3.M7          7
CMR3.M6          6
CMR3.M5          5
CMR3.M4          4
CMR3.M3          3
CMR3.M2          2
CMR3.M1          1
CMR3.M0          0
CAR3            0x0000C7     Chip select area register 3 
CAR3.A7          15
CAR3.A6          14
CAR3.A5          13
CAR3.A4          12
CAR3.A3          11
CAR3.A2          10
CAR3.A1          9
CAR3.A0          8
CSCR            0x0000C8     Chip select control register 
CSCR.OPL3        3
CSCR.OPL2        2
CSCR.OPL1        1
CSCR.OPL0        0
CALR            0x0000C9     Chip select control active level register 
CALR.ACTL3       11
CALR.ACTL2       10
CALR.ACTL1       9
CALR.ACTL0       8
TMCSR           0x0000CA     Timer control status registers 
TMCSR.CSL1       11
TMCSR.CSL0       10
TMCSR.MOD2       9
TMCSR.MOD1       8
TMCSR.MOD0       7
TMCSR.OUTE       6
TMCSR.OUTL       5
TMCSR.RELD       4
TMCSR.INTE       3
TMCSR.UF         2
TMCSR.CNTE       1
TMCSR.TRG        0
TMR_TMRLR       0x0000CC     16-bit timer register 16-bit reload register 
TMR_TMRLR.D15    15
TMR_TMRLR.D14    14
TMR_TMRLR.D13    13
TMR_TMRLR.D12    12
TMR_TMRLR.D11    11
TMR_TMRLR.D10    10
TMR_TMRLR.D09    9
TMR_TMRLR.D08    8
TMR_TMRLR.D07    7
TMR_TMRLR.D06    6
TMR_TMRLR.D05    5
TMR_TMRLR.D04    4
TMR_TMRLR.D03    3
TMR_TMRLR.D02    2
TMR_TMRLR.D01    1
TMR_TMRLR.D00    0
Reserv0000CE    0x0000CE     Reserved
Reserv0000CF    0x0000CF     Reserved


.MB90495G
; DS07-13713-1E  http://edevice.fujitsu.com/fj/DATASHEET/e-ds/e713713.pdf
; MB90497G/F497G/V495G


; ROM: 64 Kbytes (MB90F497G/MB90497G)
; RAM:  2 Kbytes (MB90F497G/MB90497G)
;       6 Kbytes (MB90V495G)


; MEMORY MAP
; [MB90V495G]
area DATA FSR              0x000000:0x0000C0
area BSS  No_access_1      0x0000C0:0x000100
area DATA RAM              0x000100:0x001900
area BSS  No_access_2      0x001900:0x003800
area DATA MEM_EXT          0x003800:0x004000
area DATA ROM_1            0x004000:0x010000
area BSS  No_access_3      0x010000:0xFC0000
; area DATA ROM_2_BANK_FC    0xFC0000:0xFD0000
; area DATA ROM_2_BANK_FD    0xFD0000:0xFE0000
; area DATA ROM_2_BANK_FE    0xFE0000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000

; [MB90F497G/MB90497G]
; area DATA FSR              0x000000:0x0000C0
; area BSS  No_access_1      0x0000C0:0x000100
; area DATA RAM              0x000100:0x000900
; area DATA ROM_mirror       0x000900:0x001100
; area BSS  No_access_2      0x001100:0x003800
; area DATA MEM_EXT          0x003800:0x004000
; area DATA ROM_1            0x004000:0x010000
; area BSS  No_access_3      0x010000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000


; Interrupt and reset vector assignments
interrupt __RESET       0xFFFFDC   Reset 
interrupt INT_9         0xFFFFD8   INT 9 instruction 
interrupt EXCEPT        0xFFFFD4   Exception processing 
interrupt CAN_RX        0xFFFFD0   Can controller reception complete (RX) 
interrupt CAN_TX        0xFFFFCC   Can controller reception complete (TX) /Node status transition (NS) 
interrupt RESERV1       0xFFFFC8   Reserved 
interrupt RESERV2       0xFFFFC4   Reserved 
interrupt INT0_INT1     0xFFFFC0   External interrupt (INT0/INT1) 
interrupt T_TIMER       0xFFFFBC   Timebase timer 
interrupt R_TIMER0      0xFFFFB8   16-bit reload timer 0 
interrupt AD_CONV       0xFFFFB4   8/10-bit A/D converter 
interrupt FR_TIMER      0xFFFFB0   16-bit free-run timer overflow 
interrupt INT2_INT3     0xFFFFAC   External interrupt (INT2/INT3) 
interrupt RESERV3       0xFFFFA8   Reserved 
interrupt PPG_TIMER01   0xFFFFA4   PPG timer ch0, ch1 underflow 
interrupt IC0           0xFFFFA0   Input capture 0 load 
interrupt INT4_INT5     0xFFFF9C   External interrupt (INT4/INT5) 
interrupt IC1           0xFFFF98   Input capture 1 load 
interrupt PPG_TIMER23   0xFFFF94   PPG timer ch2, ch3 underflow 
interrupt INT6_INT7     0xFFFF90   External interrupt (INT6/INT7) 
interrupt C_TIMER       0xFFFF8C   Clock timer 
interrupt RESERV4       0xFFFF88   Reserved 
interrupt IC2           0xFFFF84   Input capture 2 load Input capture 3 load 
interrupt RESERV5       0xFFFF80   Reserved 
interrupt RESERV6       0xFFFF7C   Reserved 
interrupt RESERV7       0xFFFF78   Reserved 
interrupt RESERV8       0xFFFF74   Reserved 
interrupt RESERV9       0xFFFF70   Reserved 
interrupt R_TIMER1      0xFFFF6C   16-bit reload timer 1 
interrupt UART1_R       0xFFFF68   UART1 reception complete 
interrupt UART1_T       0xFFFF64   UART1 transmission complete 
interrupt UART0_R       0xFFFF60   UART0 reception complete 
interrupt UART0_T       0xFFFF5C   UART0 transmission complete 
interrupt FLASH         0xFFFF58   Flash memory 
interrupt DELAY         0xFFFF54   Delayed interrupt generation module 


; INPUT/OUTPUT PORTS
PDR0            0x000000     Port 0 data register 
PDR1            0x000001     Port 1 data register 
PDR2            0x000002     Port 2 data register 
PDR3            0x000003     Port 3 data register 
PDR4            0x000004     Port 4 data register 
PDR5            0x000005     Port 5 data register 
PDR6            0x000006     Port 6 data register 
RESERV000007    0x000007     reserved 
RESERV000008    0x000008     reserved 
RESERV000009    0x000009     reserved 
RESERV00000A    0x00000A     reserved 
RESERV00000B    0x00000B     reserved 
RESERV00000C    0x00000C     reserved 
RESERV00000D    0x00000D     reserved 
RESERV00000E    0x00000E     reserved 
RESERV00000F    0x00000F     reserved 
DDR0            0x000010     Port 0 direction register 
DDR1            0x000011     Port 1 direction register 
DDR2            0x000012     Port 2 direction register 
DDR3            0x000013     Port 3 direction register 
DDR4            0x000014     Port 4 direction register 
DDR5            0x000015     Port 5 direction register 
DDR6            0x000016     Port 6 direction register 
RESERV000017    0x000017     reserved 
RESERV000018    0x000018     reserved 
RESERV000019    0x000019     reserved 
RESERV00001A    0x00001A     reserved 
ADER            0x00001B     Analog input enable register 
RESERV00001C    0x00001C     reserved
RESERV00001D    0x00001D     reserved
RESERV00001E    0x00001E     reserved
RESERV00001F    0x00001F     reserved
SMR0            0x000020     Serial mode register 0 
SCR0            0x000021     Serial control register 0 
SIDR0_SODR0     0x000022     Serial input data register 0/Serial output data register 0 
SSR0            0x000023     Serial status register 0 
CDCR0           0x000024     Communication prescaler control register 0 
SES0            0x000025     Serial edge selection register 0 
SMR1            0x000026     Serial mode register 1 
SCR1            0x000027     Serial control register 1 
SIDR1_SODR1     0x000028     Serial input data register 1/Serial output data register 1 
SSR1            0x000029     Serial status register 1 
RESERV00002A    0x00002A     reserved 
CDCR1           0x00002B     Communication prescaler control register 1 
RESERV00002C    0x00002C     reserved 
RESERV00002C    0x00002C     reserved 
RESERV00002E    0x00002E     reserved 
RESERV00002F    0x00002F     reserved 
ENIR            0x000030     DTP/external interrupt enable register 
EIRR            0x000031     DTP/external interrupt condition register 
ELVR            0x000032     Detection level configuration register 
ADCS            0x000034     A/D control status register 
ADCR            0x000036     A/D data register 
RESERV000038    0x000038     reserved 
RESERV000039    0x000039     reserved 
RESERV00003A    0x00003A     reserved 
RESERV00003B    0x00003B     reserved 
RESERV00003C    0x00003C     reserved 
RESERV00003D    0x00003D     reserved 
RESERV00003E    0x00003E     reserved 
RESERV00003F    0x00003F     reserved 
PPGC0           0x000040     PPG0 operation mode control register 
PPGC1           0x000041     PPG1 operation mode control register 
PPG01           0x000042     PPG0/1 count clock selection register 
RESERV000043    0x000043     reserved 
PPGC2           0x000044     PPG2 operation mode control register 
PPGC3           0x000045     PPG3 operation mode control register 
PPG23           0x000046     PPG2/3 count clock selection register 
RESERV000047    0x000047     reserved 
RESERV000048    0x000048     reserved 
RESERV000049    0x000049     reserved 
RESERV00004A    0x00004A     reserved 
RESERV00004B    0x00004B     reserved 
RESERV00004C    0x00004C     reserved 
RESERV00004D    0x00004D     reserved 
RESERV00004E    0x00004E     reserved 
RESERV00004F    0x00004F     reserved 
IPCP0           0x000050     Input capture data register 0 
IPCP1           0x000052     Input capture data register 1 
ICS01           0x000054     Input capture control status register 
ICS23           0x000055     Input capture control status register 
TCDT            0x000056     Timer counter data register 
TCCS            0x000058     Timer counter control status register 
IPCP2           0x00005A     Input capture data register 2 
IPCP3           0x00005C     Input capture data register 3 
RESERV00005E    0x00005E     reserved 
RESERV00005F    0x00005F     reserved 
RESERV000060    0x000060     reserved 
RESERV000061    0x000061     reserved 
RESERV000062    0x000062     reserved 
RESERV000063    0x000063     reserved 
RESERV000064    0x000064     reserved 
RESERV000065    0x000065     reserved 
TMCSR0          0x000066     Timer control status register
TMCSR1          0x000068     Timer control status register
RESERV00006A    0x00006A     reserved 
RESERV00006B    0x00006B     reserved 
RESERV00006C    0x00006C     reserved 
RESERV00006D    0x00006D     reserved 
RESERV00006E    0x00006E     reserved 
ROMM            0x00006F     ROM mirror function selection register 
RESERV000070    0x000070     reserved 
RESERV000071    0x000071     reserved 
RESERV000072    0x000072     reserved 
RESERV000073    0x000073     reserved 
RESERV000074    0x000074     reserved 
RESERV000075    0x000075     reserved 
RESERV000076    0x000076     reserved 
RESERV000077    0x000077     reserved 
RESERV000078    0x000078     reserved 
RESERV000079    0x000079     reserved 
RESERV00007A    0x00007A     reserved 
RESERV00007B    0x00007B     reserved 
RESERV00007C    0x00007C     reserved 
RESERV00007D    0x00007D     reserved 
RESERV00007E    0x00007E     reserved 
RESERV00007F    0x00007F     reserved 
BVALR           0x000080     Message buffer valid register 
RESERV000081    0x000081     reserved 
TREQR           0x000082     Send request register 
RESERV000083    0x000083     reserved 
TCANR           0x000084     Send cancel register 
RESERV000085    0x000085     reserved 
TCR             0x000086     Send complete register 
RESERV000087    0x000087     reserved 
RCR             0x000088     Reception complete register 
RESERV000089    0x000089     reserved 
RRTRR           0x00008A     Reception RTR register 
RESERV00008B    0x00008B     reserved 
ROVRR           0x00008C     Reception overrun register 
RESERV00008D    0x00008D     reserved 
RIER            0x00008E     Reception complete interrupt enable register 
RESERV000090    0x000090     reserved 
RESERV000091    0x000091     reserved 
RESERV000092    0x000092     reserved 
RESERV000093    0x000093     reserved 
RESERV000094    0x000094     reserved 
RESERV000095    0x000095     reserved 
RESERV000096    0x000096     reserved 
RESERV000097    0x000097     reserved 
RESERV000098    0x000098     reserved 
RESERV000099    0x000099     reserved 
RESERV00009A    0x00009A     reserved 
RESERV00009B    0x00009B     reserved 
RESERV00009C    0x00009C     reserved 
RESERV00009D    0x00009D     reserved 
PACSR           0x00009E     Address detection control register 
DIRR            0x00009F     Delayed interrupt request generate/cancel register 
LPMCR           0x0000A0     Low power consumption mode control register 
CKSCR           0x0000A1     Clock selection register 
RESERV0000A2    0x0000A2     reserved 
RESERV0000A3    0x0000A3     reserved 
RESERV0000A4    0x0000A4     reserved 
ARSR            0x0000A5     Auto ready function selection register 
HACR            0x0000A6     High address control register 
ECSR            0x0000A7     Bus control signal selection register 
WDTC            0x0000A8     Watchdog timer control register 
TBTC            0x0000A9     Timebase timer control register 
WTC             0x0000AA     Clock timer control register 
RESERV0000AB    0x0000AB     reserved 
RESERV0000AC    0x0000AC     reserved 
RESERV0000AD    0x0000AD     reserved 
FMCS            0x0000AE     Flash memory control status register 
RESERV0000AF    0x0000AF     reserved 
ICR00           0x0000B0     Interrupt control register 00 
ICR01           0x0000B1     Interrupt control register 01 
ICR02           0x0000B2     Interrupt control register 02 
ICR03           0x0000B3     Interrupt control register 03 
ICR04           0x0000B4     Interrupt control register 04 
ICR05           0x0000B5     Interrupt control register 05 
ICR06           0x0000B6     Interrupt control register 06 
ICR07           0x0000B7     Interrupt control register 07 
ICR08           0x0000B8     Interrupt control register 08 
ICR09           0x0000B9     Interrupt control register 09 
ICR10           0x0000BA     Interrupt control register 10
ICR11           0x0000BB     Interrupt control register 11 
ICR12           0x0000BC     Interrupt control register 12 
ICR13           0x0000BD     Interrupt control register 13 
ICR14           0x0000BE     Interrupt control register 14 
ICR15           0x0000BF     Interrupt control register 15 

.MB90520
; DS07-13707-2E  http://edevice.fujitsu.com/fj/DATASHEET/e-ds/e713707.pdf
; MB90522A/523A/522B/523B/F523B/V520A


; ROM:  64 Kbytes (MB90522A/MB90522B)
;      128 Kbytes (MB90523A/MB90523B/MB90F523B)
; RAM:   4 Kbytes (MB90522A/MB90523A/MB90522B/MB90523B/MB90F523B)
;        6 Kbytes (MB90V520A)


; MEMORY MAP
; [MB90522A/B]
area DATA FSR              0x000000:0x0000C0
area BSS  No_access_1      0x0000C0:0x000100
area DATA RAM              0x000100:0x001100
area BSS  No_access_2      0x001100:0x004000
area DATA ROM_1            0x004000:0x010000
area BSS  No_access_3      0x010000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000

; [MB90523A/B/MB90F523B]
; area DATA FSR              0x000000:0x0000C0
; area BSS  No_access_1      0x0000C0:0x000100
; area DATA RAM              0x000100:0x001100
; area BSS  No_access_2      0x001100:0x004000
; area DATA ROM_1            0x004000:0x010000
; area BSS  No_access_3      0x010000:0xFE0000
; area DATA ROM_2_BANK_FE    0xFE0000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000


; Interrupt and reset vector assignments
interrupt __RESET       0xFFFFDC       Reset 
interrupt INT_9         0xFFFFD8       INT 9 instruction 
interrupt EXCEPTION     0xFFFFD4       Exception 
interrupt A_D_CONV      0xFFFFD0       8/10-bit A/D converter 
interrupt T_TIMER       0xFFFFCC       Timebase timer 
interrupt DTP0_DTP1     0xFFFFC8       DTP0/DTP1 (external interrupt 0/external interrupt 1) 
interrupt F_TIMER_0O    0xFFFFC4       16-bit freerun timer 0 overflow 
interrupt E_IO_SI1      0xFFFFC0       Extended I/O serial interface 1 
interrupt WAKEUP        0xFFFFBC       Wakeup interrupt 
interrupt E_IO_SI2      0xFFFFB8       Extended I/O serial interface 2 
interrupt DTP2_DTP3     0xFFFFB4       DTP2/DTP3 (external interrupt 2/external interrupt 3) 
interrupt PPG_TIMER0_CB 0xFFFFB0       8/16-bit PPG timer 0 counter borrow 
interrupt DTP4_DTP5     0xFFFFAC       DTP4/DTP5 (external interrupt 4/external interrupt 5) 
interrupt UD_CT_0_CM    0xFFFFA8       8/16-bit up/down counter/timer 0 compare match 
interrupt UD_CT_0O      0xFFFFA4       8/16-bit up/down counter/timer 0 overflow, up/down direction change 
interrupt PPG_TIMER1_CB 0xFFFFA0       8/16-bit PPG timer 1 counter borrow 
interrupt DTP6_DTP7     0xFFFF9C       DTP6/DTP7 (external interrupt 6/external interrupt 7) 
interrupt OC1_CH4_5M    0xFFFF98       Output compare 1 (OCU) ch.4, ch.5 match 
interrupt C_TIMER       0xFFFF94       Clock timer 
interrupt OC1_CH6_7M    0xFFFF90       Output compare 1 (OCU) ch.6, ch.7 match 
interrupt F_TIMER_1O    0xFFFF8C       16-bit freerun timer 1 overflow 
interrupt UD_CT_1_CM    0xFFFF88       8/16-bit up/down counter/timer 1 compare match 
interrupt UD_CT_1O      0xFFFF84       8/16-bit up/down counter/timer 1 overflow, up/down direction change 
interrupt IC0           0xFFFF80       Input capture 0 (ICU) capture 
interrupt IC1           0xFFFF7C       Input capture 1 (ICU) capture 
interrupt OC0_CH0M      0xFFFF78       Output compare 0 (OCU) ch.0 match 
interrupt OC0_CH1M      0xFFFF74       Output compare 0 (OCU) ch.1 match 
interrupt OC0_CH2M      0xFFFF70       Output compare 0 (OCU) ch.2 match 
interrupt OC0_CH3M      0xFFFF6C       Output compare 0 (OCU) ch.3 match 
interrupt UART_RC       0xFFFF68       UART (SCI) receive complete 
interrupt R_TIMER_0     0xFFFF64       16-bit reload timer 0 
interrupt UART_SC       0xFFFF60       UART (SCI) send complete 
interrupt R_TIMER_1     0xFFFF5C       16-bit reload timer 1
interrupt FLASH         0xFFFF58       Flash memory 
interrupt DELAY         0xFFFF54       Delayed interrupt generation module 


; INPUT/OUTPUT PORTS
PDR0                 0x000000   Port 0 data register
PDR0.P07              7
PDR0.P06              6
PDR0.P05              5
PDR0.P04              4
PDR0.P03              3
PDR0.P02              2
PDR0.P01              1
PDR0.P00              0
PDR1                 0x000001   Port 1 data register
PDR1.P17              7
PDR1.P16              6
PDR1.P15              5
PDR1.P14              4
PDR1.P13              3
PDR1.P12              2
PDR1.P11              1
PDR1.P10              0
PDR2                 0x000002   Port 2 data register
PDR2.P27              7
PDR2.P26              6
PDR2.P25              5
PDR2.P24              4
PDR2.P23              3
PDR2.P22              2
PDR2.P21              1
PDR2.P20              0
PDR3                 0x000003   Port 3 data register
PDR3.P37              7
PDR3.P36              6
PDR3.P35              5
PDR3.P34              4
PDR3.P33              3
PDR3.P32              2
PDR3.P31              1
PDR3.P30              0
PDR4                 0x000004   Port 4 data register
PDR4.P47              7
PDR4.P46              6
PDR4.P45              5
PDR4.P44              4
PDR4.P43              3
PDR4.P42              2
PDR4.P41              1
PDR4.P40              0
PDR5                 0x000005   Port 5 data register
PDR5.P54              4
PDR5.P53              3
PDR5.P52              2
PDR5.P51              1
PDR5.P50              0
PDR6                 0x000006   Port 6 data register
PDR6.P67              7      
PDR6.P66              6
PDR6.P65              5
PDR6.P64              4
PDR6.P63              3
PDR6.P62              2
PDR6.P61              1
PDR6.P60              0
PDR7                 0x000007   Port 7 data register
PDR7.P77              7      
PDR7.P76              6
PDR7.P75              5
PDR7.P74              4
PDR7.P73              3
PDR7.P72              2
PDR7.P71              1
PDR7.P70              0
PDR8                 0x000008   Port 8 data register
PDR8.P87              7      
PDR8.P86              6
PDR8.P85              5
PDR8.P84              4
PDR8.P83              3
PDR8.P82              2
PDR8.P81              1
PDR8.P80              0
PDR9                 0x000009   Port 9 data register
PDR9.P97              7      
PDR9.P96              6
PDR9.P95              5
PDR9.P94              4
PDR9.P93              3
PDR9.P92              2
PDR9.P91              1
PDR9.P90              0
PDRA                 0x00000A   Port A data register
PDRA.PA7              7
PDRA.PA6              6
PDRA.PA5              5
PDRA.PA4              4
PDRA.PA3              3
PDRA.PA2              2
PDRA.PA1              1
PDRA.PA0              0
LCDCMR               0x00000B   Port 7/COM pin selection register
LCDCMR.COM3           3
LCDCMR.COM2           2
LCDCMR.COM1           1
LCDCMR.COM0           0
OCCP4                0x00000C   OCU compare register ch.4
EIFR                 0x00000F   Wakeup interrupt flag register
EIFR.WIF              0
DDR0                 0x000010   Port 0 direction register
DDR0.D07              7
DDR0.D06              6
DDR0.D05              5
DDR0.D04              4
DDR0.D03              3
DDR0.D02              2
DDR0.D01              1
DDR0.D00              0
DDR1                 0x000011   Port 1 direction register
DDR1.D17              7
DDR1.D16              6
DDR1.D15              5
DDR1.D14              4
DDR1.D13              3
DDR1.D12              2
DDR1.D11              1
DDR1.D10              0
DDR2                 0x000012   Port 2 direction register
DDR2.D27              7
DDR2.D26              6
DDR2.D25              5
DDR2.D24              4
DDR2.D23              3
DDR2.D22              2
DDR2.D21              1
DDR2.D20              0
DDR3                 0x000013   Port 3 direction register
DDR3.D37              7
DDR3.D36              6
DDR3.D35              5
DDR3.D34              4
DDR3.D33              3
DDR3.D32              2
DDR3.D31              1
DDR3.D30              0
DDR4                 0x000014   Port 4 direction register
DDR4.D47              7
DDR4.D46              6
DDR4.D45              5
DDR4.D44              4
DDR4.D43              3
DDR4.D42              2
DDR4.D41              1
DDR4.D40              0
DDR5                 0x000015   Port 5 direction register
DDR5.D54              4
DDR5.D53              3
DDR5.D52              2
DDR5.D51              1
DDR5.D50              0
DDR6                 0x000016   Port 6 direction register
DDR6.D67              7
DDR6.D66              6
DDR6.D65              5
DDR6.D64              4
DDR6.D63              3
DDR6.D62              2
DDR6.D61              1
DDR6.D60              0
DDR7                 0x000017   Port 7 direction register
DDR7.D77              7
DDR7.D76              6
DDR7.D75              5
DDR7.D74              4
DDR7.D73              3
DDR7.D72              2
DDR7.D71              1
DDR7.D70              0
DDR8                 0x000018   Port 8 direction register
DDR8.D87              7
DDR8.D86              6
DDR8.D85              5
DDR8.D84              4
DDR8.D83              3
DDR8.D82              2
DDR8.D81              1
DDR8.D80              0
DDR9                 0x000019   Port 9 direction register
DDR9.D97              7
DDR9.D96              6
DDR9.D95              5
DDR9.D94              4
DDR9.D93              3
DDR9.D92              2
DDR9.D91              1
DDR9.D90              0
DDRA                 0x00001A   Port A direction register
DDRA.DA7              7
DDRA.DA6              6
DDRA.DA5              5
DDRA.DA4              4
DDRA.DA3              3
DDRA.DA2              2
DDRA.DA1              1
DDRA.DA0              0
ADER                 0x00001B   Analog input enable register
ADER.ADE7             7
ADER.ADE6             6
ADER.ADE5             5
ADER.ADE4             4
ADER.ADE3             3
ADER.ADE2             2
ADER.ADE1             1
ADER.ADE0             0
OCP5                 0x00001C   OCU compare register ch.5
EICR                 0x00001F   Wakeup interrupt enable register
SMR                  0x000020   Serial mode register
SMR.MD1               7
SMR.MD0               6
SMR.CS2               5
SMR.CS1               4
SMR.CS0               3
SMR.SCKE              1
SMR.SOE               0
SCR                  0x000021   Serial control register
SCR.PEN               7
SCR.P                 6
SCR.SBL               5
SCR.CL                4
SCR.AD                3
SCR.REC               2
SCR.RXE               1
SCR.TXE               0
SIDR                 0x000022   Serial input data register / Serial output data register
SIDR.D7               7
SIDR.D6               6
SIDR.D5               5
SIDR.D4               4
SIDR.D3               3
SIDR.D2               2
SIDR.D1               1
SIDR.D0               0
SSR                  0x000023   Serial status register
SSR.PE                7
SSR.ORE               6
SSR.FRE               5
SSR.RDRF              4
SSR.TDRE              3
SSR.RIE               1
SSR.TIE               0
SMCS1                0x000024   Serial mode control status register 1
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
SDR1                 0x000026   Serial data register 1
CDCR                 0x000027   Communication prescaler control register
CDCR.MD               7
CDCR.DIV3             3
CDCR.DIV2             2
CDCR.DIV1             1
CDCR.DIV0             0
SMCS2                0x000028   Serial mode control status register 2
SMCS2.SMD2            15
SMCS2.SMD1            14
SMCS2.SMD0            13
SMCS2.SIE             12
SMCS2.SIR             11
SMCS2.BUSY            10
SMCS2.STOP            9
SMCS2.STRT            8
SMCS2.MODE            3
SMCS2.BDS             2
SMCS2.SOE             1
SMCS2.SCOE            0
SDR2                 0x00002A   Serial data register 2
OCS45                0x00002C   OCU control status register ch.45
OCS45.CMOD            12
OCS45.OTE1            11
OCS45.OTE0            10
OCS45.OTD1            9
OCS45.OTD0            8
OCS45.ICP1            7
OCS45.ICP0            6
OCS45.ICE1            5
OCS45.ICE0            4
OCS45.CST1            1
OCS45.CST0            0
OCS67                0x00002E   OCU control status register ch.67
OCS67.CMOD            12
OCS67.OTE1            11
OCS67.OTE0            10
OCS67.OTD1            9
OCS67.OTD0            8
OCS67.ICP1            7
OCS67.ICP0            6
OCS67.ICE1            5
OCS67.ICE0            4
OCS67.CST1            1
OCS67.CST0            0
ENIR                 0x000030   DTP/interrupt enable register
ENIR.EN7              7     
ENIR.EN6              6     
ENIR.EN5              5     
ENIR.EN4              4     
ENIR.EN3              3     
ENIR.EN2              2
ENIR.EN1              1
ENIR.EN0              0
EIRR                 0x000031   DTP/interrupt request register
EIRR.ER7              7     
EIRR.ER6              6     
EIRR.ER5              5     
EIRR.ER4              4     
EIRR.ER3              3     
EIRR.ER2              2
EIRR.ER1              1
EIRR.ER0              0
ELVR                 0x000032   Request level setting register
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
OCCP6                0x000034   OCU compare register ch.6
ADCS1                0x000036   A/D control status register
ADCS1.MD1             7
ADCS1.MD0             6
ADCS1.ANS2            5
ADCS1.ANS1            4
ADCS1.ANS0            3
ADCS1.ANE2            2
ADCS1.ANE1            1
ADCS1.ANE0            0
ADCS2                0x000037   A/D control status register
ADCS2.BUSY            7
ADCS2.INT             6
ADCS2.INTE            5
ADCS2.PAUS            4
ADCS2.STS1            3
ADCS2.STS0            2
ADCS2.STRT0           1
ADCR1                0x000038   A/D data register
ADCR2                0x000039   A/D data register
DADR0                0x00003A   D/A converter data register ch.0
DADR1                0x00003B   D/A converter data register ch.1
DACR0                0x00003C   D/A control register 0
DACR0.DAE0            0
DACR1                0x00003D   D/A control register 1
DACR1.DAE1            0
CLKR                 0x00003E   Clock output enable register
CLKR.CKEN             3
CLKR.FRQ2             2
CLKR.FRQ1             1
CLKR.FRQ0             0
PRL0_PRLL            0x000040   PPG0 reload register L
PRL0_PRLH            0x000041   PPG0 reload register H
PRL1_PRLL            0x000042   PPG1 reload register L
PRL1_PRLH            0x000043   PPG1 reload register H
PPGC01               0x000044   PPG0 operation mode control register
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
PPGOE                0x000046   PPG0, 1 output control register
PPGOE.PCS2            7
PPGOE.PCS1            6
PPGOE.PCS0            5
PPGOE.PCM2            4
PPGOE.PCM1            3
PPGOE.PCM0            2
PPGOE.PE11            1
PPGOE.PE01            0
TMCSR0               0x000048   Timer control status register ch.0
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
TMR0                 0x00004A   16-bit timer register ch.0 / 16-bit reload register ch.0
TMCSR1               0x00004C   Timer control status register ch.1
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
TMR1                 0x00004E   16-bit timer register ch.1 / 16-bit reload register ch.1
IPCP0                0x000050   ICU data register ch.0
IPCP1                0x000052   ICU data register ch.1
ICS01                0x000054   ICU control status register
ICS01.ICP1            7
ICS01.ICP0            6
ICS01.ICE1            5
ICS01.ICE0            4
ICS01.EG11            3 
ICS01.EG10            2
ICS01.EG01            1
ICS01.EG00            0
TCDT0                0x000056   Freerun timer data register 0
TCCS0                0x000058   Freerun timer control status register 0
TCCS0.IVF             6
TCCS0.IVFE            5
TCCS0.STOP            4
TCCS0.MODE            3
TCCS0.CLR             2
TCCS0.CLK1            1
TCCS0.CLK0            0
OCCP0                0x00005A   OCU compare register ch.0
OCCP1                0x00005C   OCU compare register ch.1
OCCP2                0x00005E   OCU compare register ch.2
OCCP3                0x000060   OCU compare register ch.3
OCS01                0x000062   OCU control status register ch.0, ch.1
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
OCS23                0x000064   OCU control status register ch.2, ch.3
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
TCDT1                0x000066   Freerun timer data register 1
TCCS1                0x000068   Freerun timer control status register 1
TCCS1.IVF             6
TCCS1.IVFE            5
TCCS1.STOP            4
TCCS1.MODE            3
TCCS1.CLR             2
TCCS1.CLK1            1
TCCS1.CLK0            0
LCR0                 0x00006A   LCDC control register 0
LCR0.CSS              7
LCR0.LCEN             6
LCR0.VSEL             5
LCR0.BK               4
LCR0.MS1              3
LCR0.MS0              2
LCR0.FP1              1
LCR0.FP0              0
LCR1                 0x00006B   LCDC control register 1
LCR1.SEG5             6
LCR1.SEG4             5
LCR1.SEG3             3
LCR1.SEG2             2
LCR1.SEG1             1
LCR1.SEG0             0
OCCP7                0x00006C   OCU compare register ch.7
ROMM                 0x00006F   ROM mirror function selection register
VRAM_SEG00_01        0x000070   Data memory for LCD display
VRAM_SEG02_03        0x000071   Data memory for LCD display
VRAM_SEG04_05        0x000072   Data memory for LCD display
VRAM_SEG06_07        0x000073   Data memory for LCD display
VRAM_SEG08_09        0x000074   Data memory for LCD display
VRAM_SEG10_11        0x000075   Data memory for LCD display
VRAM_SEG12_13        0x000076   Data memory for LCD display
VRAM_SEG14_15        0x000077   Data memory for LCD display
VRAM_SEG16_17        0x000078   Data memory for LCD display
VRAM_SEG18_19        0x000079   Data memory for LCD display
VRAM_SEG20_21        0x00007A   Data memory for LCD display
VRAM_SEG22_23        0x00007B   Data memory for LCD display
VRAM_SEG24_25        0x00007C   Data memory for LCD display
VRAM_SEG26_27        0x00007D   Data memory for LCD display
VRAM_SEG28_29        0x00007E   Data memory for LCD display
VRAM_SEG30_31        0x00007F   Data memory for LCD display
UDCR_UDCR0           0x000080   Up/down count register 0
UDCR_UDCR1           0x000081   Up/down count register 1
RCR01                0x000082   Reload compare register 0/1
CSR0                 0x000084   Counter status register 0
CSR0.CSTR             7
CSR0.CITE             6
CSR0.UDIE             5
CSR0.CMPF             4
CSR0.OVFF             3
CSR0.UDFF             2
CSR0.UDF1             1
CSR0.UDF0             0
CCR0                 0x000086   Counter control register 0
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
CSR1                 0x000088   Counter status register 1
CSR1.CSTR             7
CSR1.CITE             6
CSR1.UDIE             5
CSR1.CMPF             4
CSR1.OVFF             3
CSR1.UDFF             2
CSR1.UDF1             1
CSR1.UDF0             0
CCR1                 0x00008A   Counter control register 1
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
RDR0                 0x00008C   Port 0 input pull-up resistor setup register
RDR0.RD07             7
RDR0.RD06             6
RDR0.RD05             5
RDR0.RD04             4
RDR0.RD03             3
RDR0.RD02             2
RDR0.RD01             1
RDR0.RD00             0
RDR1                 0x00008D   Port 1 input pull-up resistor setup register
RDR1.RD17             7
RDR1.RD16             6
RDR1.RD15             5
RDR1.RD14             4
RDR1.RD13             3
RDR1.RD12             2
RDR1.RD11             1
RDR1.RD10             0
RDR4                 0x00008E   Port 4 input pull-up resistor setup register
RDR4.RD47             7
RDR4.RD46             6
RDR4.RD45             5
RDR4.RD44             4
RDR4.RD43             3
RDR4.RD42             2
RDR4.RD41             1
RDR4.RD40             0
PACSR                0x00009E   Address detection control register
PACSR.AD1E            3
PACSR.AD1D            2
PACSR.AD0E            1
PACSR.AD0D            0
DIRR                 0x00009F   Delayed interrupt request output/clear register
DIRR.R0               0
LPMCR                0x0000A0   Low power consumption mode control register
LPMCR.STP             7
LPMCR.SLP             6
LPMCR.SPL             5
LPMCR.RST             4
LPMCR.TMD             3
LPMCR.CG1             2
LPMCR.CG0             1
LPMCR.SSR             0
CKSCR                0x0000A1   Clock selection register
CKSCR.SCM             7
CKSCR.MCM             6
CKSCR.WS1             5
CKSCR.WS0             4
CKSCR.SCS             3
CKSCR.MCS             2
CKSCR.CS1             1 
CKSCR.CS0             0
WDTC                 0x0000A8   Watchdog timer control register
WDTC.PONR             7
WDTC.STBR             6
WDTC.WRST             5
WDTC.ERST             4
WDTC.SRST             3
TBTC                 0x0000A9   Timebase timer control register
TBTC.TBIE             4
TBTC.TBOF             3
TBTC.TBR              2
TBTC.TBC1             1
TBTC.TBC0             0
WTC                  0x0000AA   Clock timer control register
WTC.WDCS              7
WTC.SCE               6
WTC.WTIE              5
WTC.WTOF              4
WTC.WTR               3
WTC.WTC2              2
WTC.WTC1              1
WTC.WTC0              0
FMCS                 0x0000AE   Flash memory control status register
FMCS.INTE             7
FMCS.RDYINT           6
FMCS.WE               5
FMCS.RDY              4
FMCS.LPM0             0
ICR00                0x0000B0   Interrupt control register 00
ICR00.S1              5
ICR00.S0              4
ICR00.ISE             3
ICR00.IL2             2
ICR00.IL1             1
ICR00.IL0             0
ICR01                0x0000B1   Interrupt control register 01
ICR01.S1              5
ICR01.S0              4
ICR01.ISE             3
ICR01.IL2             2
ICR01.IL1             1
ICR01.IL0             0
ICR02                0x0000B2   Interrupt control register 02
ICR02.S1              5
ICR02.S0              4
ICR02.ISE             3
ICR02.IL2             2
ICR02.IL1             1
ICR02.IL0             0
ICR03                0x0000B3   Interrupt control register 03
ICR03.S1              5
ICR03.S0              4
ICR03.ISE             3
ICR03.IL2             2
ICR03.IL1             1
ICR03.IL0             0
ICR04                0x0000B4   Interrupt control register 04
ICR04.S1              5
ICR04.S0              4
ICR04.ISE             3
ICR04.IL2             2
ICR04.IL1             1
ICR04.IL0             0
ICR05                0x0000B5   Interrupt control register 05
ICR05.S1              5
ICR05.S0              4
ICR05.ISE             3
ICR05.IL2             2
ICR05.IL1             1
ICR05.IL0             0
ICR06                0x0000B6   Interrupt control register 06
ICR06.S1              5
ICR06.S0              4
ICR06.ISE             3
ICR06.IL2             2
ICR06.IL1             1
ICR06.IL0             0
ICR07                0x0000B7   Interrupt control register 07
ICR07.S1              5
ICR07.S0              4
ICR07.ISE             3
ICR07.IL2             2
ICR07.IL1             1
ICR07.IL0             0
ICR08                0x0000B8   Interrupt control register 08
ICR08.S1              5
ICR08.S0              4
ICR08.ISE             3
ICR08.IL2             2
ICR08.IL1             1
ICR08.IL0             0
ICR09                0x0000B9   Interrupt control register 09
ICR09.S1              5
ICR09.S0              4
ICR09.ISE             3
ICR09.IL2             2
ICR09.IL1             1
ICR09.IL0             0
ICR10                0x0000BA   Interrupt control register 10
ICR10.S1              5
ICR10.S0              4
ICR10.ISE             3
ICR10.IL2             2
ICR10.IL1             1
ICR10.IL0             0
ICR11                0x0000BB   Interrupt control register 11
ICR11.S1              5
ICR11.S0              4
ICR11.ISE             3
ICR11.IL2             2
ICR11.IL1             1
ICR11.IL0             0
ICR12                0x0000BC   Interrupt control register 12
ICR12.S1              5
ICR12.S0              4
ICR12.ISE             3
ICR12.IL2             2
ICR12.IL1             1
ICR12.IL0             0
ICR13                0x0000BD   Interrupt control register 13
ICR13.S1              5
ICR13.S0              4
ICR13.ISE             3
ICR13.IL2             2
ICR13.IL1             1
ICR13.IL0             0
ICR14                0x0000BE   Interrupt control register 14
ICR14.S1              5
ICR14.S0              4
ICR14.ISE             3
ICR14.IL2             2
ICR14.IL1             1
ICR14.IL0             0
ICR15                0x0000BF   Interrupt control register 15
ICR15.S1              5
ICR15.S0              4
ICR15.ISE             3
ICR15.IL2             2
ICR15.IL1             1
ICR15.IL0             0


.MB90540
; DS07-13703-4E  http://edevice.fujitsu.com/fj/DATASHEET/e-ds/e713703.pdf
; MB90F543/V540/F543G(S)/V540G


; ROM: 128 K (MB90F543G(S))
; RAM:   6 Kbytes (MB90F543/F543G(S))


; MEMORY MAP
; [MB90V540/MB90V540G]
area DATA FSR              0x000000:0x0000C0
area DATA MEM_EXT_1        0x0000C0:0x000100
area DATA RAM              0x000100:0x002100
area DATA MEM_EXT_2        0x002100:0x003900
area DATA FSR_1            0x003900:0x004000
area DATA ROM_1            0x004000:0x010000
area DATA MEM_EXT_3        0x010000:0xFC0000
area DATA ROM_2_BANK_FC    0xFC0000:0xFD0000
area DATA ROM_2_BANK_FD    0xFD0000:0xFE0000
area DATA ROM_2_BANK_FE    0xFE0000:0xFF0000
area DATA ROM_2_BANK_FF    0xFF0000:0x1000000

; [MB90F543/MB90F543G(S)]
; area DATA FSR              0x000000:0x0000C0
; area DATA MEM_EXT_1        0x0000C0:0x000100
; area DATA RAM              0x000100:0x001900
; area DATA MEM_EXT_2        0x002000:0x003900
; area DATA FSR_1            0x003900:0x004000
; area DATA ROM_1            0x004000:0x010000
; area DATA MEM_EXT_3        0x010000:0xFE0000
; area DATA ROM_2_BANK_FE    0xFE0000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000


; Interrupt and reset vector assignments
interrupt __RESET       0xFFFFDC   Reset 
interrupt INT9          0xFFFFD8   INT9 instruction 
interrupt EXCEPT        0xFFFFD4   Exception 
interrupt CAN_0_RX      0xFFFFD0   CAN 0 RX 
interrupt CAN_0_TX_NS   0xFFFFCC   CAN 0 TX/NS 
interrupt CAN_1_RX      0xFFFFC8   CAN 1 RX 
interrupt CAN_1_TX_NS   0xFFFFC4   CAN 1 TX/NS 
interrupt INT0_INT1     0xFFFFC0   External Interrupt INT0/INT1 
interrupt TB_TIMER      0xFFFFBC   Time Base Timer 
interrupt R_TIMER       0xFFFFB8   16-bit Reload Timer 0 
interrupt A_D_CONV      0xFFFFB4   8/10-bit A/D Converter 
interrupt IO_TIMER      0xFFFFB0   I/O Timer 
interrupt INT2_INT3     0xFFFFAC   External Interrupt INT2/INT3 
interrupt I_O           0xFFFFA8   Serial I/O 
interrupt PPG_0_1       0xFFFFA4   8/16-bit PPG 0/1 
interrupt IC0           0xFFFFA0   Input Capture 0 
interrupt INT4_INT5     0xFFFF9C   External Interrupt INT4/INT5 
interrupt IC1           0xFFFF98   Input Capture 1 
interrupt PPG_2_3       0xFFFF94   8/16-bit PPG 2/3 
interrupt INT6_INT7     0xFFFF90   External Interrupt INT6/INT7 
interrupt W_TIMER       0xFFFF8C   Watch Timer 
interrupt PPG_4_5       0xFFFF88   8/16-bit PPG 4/5 
interrupt IC2_3         0xFFFF84   Input Capture 2/3 
interrupt PPG_6_7       0xFFFF80   8/16-bit PPG 6/7 
interrupt OC0           0xFFFF7C   Output Compare 0 
interrupt OC1           0xFFFF78   Output Compare 1 
interrupt IC4_5         0xFFFF74   Input Capture 4/5 
interrupt OC2_3_IC6_7   0xFFFF70   Output Compare 2/3 - Input Capture 6/7 
interrupt R_TIMER1      0xFFFF6C   16-bit Reload Timer 1 
interrupt UART_0_RX     0xFFFF68   UART 0 RX 
interrupt UART_0_TX     0xFFFF64   UART 0 TX 
interrupt UART_1_RX     0xFFFF60   UART 1 RX 
interrupt UART_1_TX     0xFFFF5C   UART 1 TX 
interrupt FLAS          0xFFFF58   Flash Memory 
interrupt DELAY         0xFFFF54   Delayed interrupt 


; INPUT/OUTPUT PORTS
PDR0                 0x000000   Port 0 data register
PDR0.P07              7
PDR0.P06              6
PDR0.P05              5
PDR0.P04              4
PDR0.P03              3
PDR0.P02              2
PDR0.P01              1
PDR0.P00              0
PDR1                 0x000001   Port 1 data register
PDR1.P17              7
PDR1.P16              6
PDR1.P15              5
PDR1.P14              4
PDR1.P13              3
PDR1.P12              2
PDR1.P11              1
PDR1.P10              0
PDR2                 0x000002   Port 2 data register
PDR2.P27              7
PDR2.P26              6
PDR2.P25              5
PDR2.P24              4
PDR2.P23              3
PDR2.P22              2
PDR2.P21              1
PDR2.P20              0
PDR3                 0x000003   Port 3 data register
PDR3.P37              7
PDR3.P36              6
PDR3.P35              5
PDR3.P34              4
PDR3.P33              3
PDR3.P32              2
PDR3.P31              1
PDR3.P30              0
PDR4                 0x000004   Port 4 data register
PDR4.P47              7
PDR4.P46              6
PDR4.P45              5
PDR4.P44              4
PDR4.P43              3
PDR4.P42              2
PDR4.P41              1
PDR4.P40              0
PDR5                 0x000005   Port 5 data register
PDR5.P57              7      
PDR5.P56              6
PDR5.P55              5
PDR5.P54              4
PDR5.P53              3
PDR5.P52              2
PDR5.P51              1
PDR5.P50              0
PDR6                 0x000006   Port 6 data register
PDR6.P67              7      
PDR6.P66              6
PDR6.P65              5
PDR6.P64              4
PDR6.P63              3
PDR6.P62              2
PDR6.P61              1
PDR6.P60              0
PDR7                 0x000007   Port 7 data register
PDR7.P77              7      
PDR7.P76              6
PDR7.P75              5
PDR7.P74              4
PDR7.P73              3
PDR7.P72              2
PDR7.P71              1
PDR7.P70              0
PDR8                 0x000008   Port 8 data register
PDR8.P87              7      
PDR8.P86              6
PDR8.P85              5
PDR8.P84              4
PDR8.P83              3
PDR8.P82              2
PDR8.P81              1
PDR8.P80              0
PDR9                 0x000009   Port 9 data register
PDR9.P97              7      
PDR9.P96              6
PDR9.P95              5
PDR9.P94              4
PDR9.P93              3
PDR9.P92              2
PDR9.P91              1
PDR9.P90              0
PDRA                 0x00000A   Port A data register
PDRA.PA0              0
DDR0                 0x000010   Port 0 direction register
DDR0.D07              7
DDR0.D06              6
DDR0.D05              5
DDR0.D04              4
DDR0.D03              3
DDR0.D02              2
DDR0.D01              1
DDR0.D00              0
DDR1                 0x000011   Port 1 direction register
DDR1.D17              7
DDR1.D16              6
DDR1.D15              5
DDR1.D14              4
DDR1.D13              3
DDR1.D12              2
DDR1.D11              1
DDR1.D10              0
DDR2                 0x000012   Port 2 direction register
DDR2.D27              7
DDR2.D26              6
DDR2.D25              5
DDR2.D24              4
DDR2.D23              3
DDR2.D22              2
DDR2.D21              1
DDR2.D20              0
DDR3                 0x000013   Port 3 direction register
DDR3.D37              7
DDR3.D36              6
DDR3.D35              5
DDR3.D34              4
DDR3.D33              3
DDR3.D32              2
DDR3.D31              1
DDR3.D30              0
DDR4                 0x000014   Port 4 direction register
DDR4.D47              7
DDR4.D46              6
DDR4.D45              5
DDR4.D44              4
DDR4.D43              3
DDR4.D42              2
DDR4.D41              1
DDR4.D40              0
DDR5                 0x000015   Port 5 direction register
DDR5.D57              7
DDR5.D56              6
DDR5.D55              5
DDR5.D54              4
DDR5.D53              3
DDR5.D52              2
DDR5.D51              1
DDR5.D50              0
DDR6                 0x000016   Port 6 direction register
DDR6.D67              7
DDR6.D66              6
DDR6.D65              5
DDR6.D64              4
DDR6.D63              3
DDR6.D62              2
DDR6.D61              1
DDR6.D60              0
DDR7                 0x000017   Port 7 direction register
DDR7.D77              7
DDR7.D76              6
DDR7.D75              5
DDR7.D74              4
DDR7.D73              3
DDR7.D72              2
DDR7.D71              1
DDR7.D70              0
DDR8                 0x000018   Port 8 direction register
DDR8.D87              7
DDR8.D86              6
DDR8.D85              5
DDR8.D84              4
DDR8.D83              3
DDR8.D82              2
DDR8.D81              1
DDR8.D80              0
DDR9                 0x000019   Port 9 direction register
DDR9.D97              7
DDR9.D96              6
DDR9.D95              5
DDR9.D94              4
DDR9.D93              3
DDR9.D92              2
DDR9.D91              1
DDR9.D90              0
DDRA                 0x00001A   Port A direction register
DDRA.DA0              0
ADER                 0x00001B   Analog Input Enable register
ADER.ADE7             7
ADER.ADE6             6
ADER.ADE5             5
ADER.ADE4             4
ADER.ADE3             3
ADER.ADE2             2
ADER.ADE1             1
ADER.ADE0             0
PUCR0                0x00001C   Port 0 Pullup control register
PUCR1                0x00001D   Port 1 Pullup control register
PUCR2                0x00001E   Port 2 Pullup control register
PUCR3                0x00001F   Port 3 Pullup control register
UMC0                 0x000020   Serial Mode Control Register 0
UMC0.PEN              7
UMC0.SBL              6
UMC0.MC1              5
UMC0.MC0              4
UMC0.SMDE             3
UMC0.RFC              2
UMC0.SCKE             1
UMC0.SOE              0
USR0                 0x000021   Serial Status Register 0
USR0.RDRF             7
USR0.ORFE             6
USR0.PE               5
USR0.TDRE             4
USR0.RIE              3
USR0.TIE              2
USR0.RBF              1
USR0.TBF              0
UIDR0                0x000022   Serial input data register 0 / Serial output data register 0
URD0                 0x000023   Rate and data register 0
SMR1                 0x000024   Serial mode register 1
SMR1.MD1              7
SMR1.MD0              6
SMR1.CS2              5
SMR1.CS1              4
SMR1.CS0              3
SMR1.SCKE             1
SMR1.SOE              0
SCR1                 0x000025   Serial control register 1
SCR1.PEN              7
SCR1.P                6
SCR1.SBL              5
SCR1.CL               4
SCR1.AD               3
SCR1.REC              2
SCR1.RXE              1
SCR1.TXE              0
SIDR1                0x000026   Serial input data register 1 / Serial output data register 1
SIDR1.D7              7
SIDR1.D6              6
SIDR1.D5              5
SIDR1.D4              4
SIDR1.D3              3
SIDR1.D2              2
SIDR1.D1              1
SIDR1.D0              0
SSR1                 0x000027   Serial status register 1
SSR1.PE               7
SSR1.ORE              6
SSR1.FRE              5
SSR1.RDRF             4
SSR1.TDRE             3
SSR1.RIE              1
SSR1.TIE              0
U1CDCR               0x000028   UART1 prescaler control register
SES1                 0x000029   Serial Edge select register
SES1.NEG              0
SCDCR                0x00002B   Serial I/O prescaler
SCDCR.NEG             0
SMCS                 0x00002C   Serial mode control register
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
SDR                  0x00002E   Serial data register
SES2                 0x00002F   Serial Edge select register
SES2.NEG              0
ENIR                 0x000030   External interrupt enable register
ENIR.EN7              7     
ENIR.EN6              6     
ENIR.EN5              5     
ENIR.EN4              4     
ENIR.EN3              3     
ENIR.EN2              2
ENIR.EN1              1
ENIR.EN0              0
EIRR                 0x000031   External interrupt request register
EIRR.ER7              7     
EIRR.ER6              6     
EIRR.ER5              5     
EIRR.ER4              4     
EIRR.ER3              3     
EIRR.ER2              2
EIRR.ER1              1
EIRR.ER0              0
ELVR                 0x000032   External interrupt level register
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
ADCS0                0x000034   A/D control status register 0
ADCS0.MD1             7
ADCS0.MD0             6
ADCS0.ANS2            5
ADCS0.ANS1            4
ADCS0.ANS0            3
ADCS0.ANE2            2
ADCS0.ANE1            1
ADCS0.ANE0            0
ADCS1                0x000035   A/D control status register 0
ADCS1.BUSY            7
ADCS1.INT             6
ADCS1.INTE            5
ADCS1.PAUS            4
ADCS1.STS1            3         
ADCS1.STS0            2
ADCR01               0x000036   A/D data register 0
ADCR01.S10            15
ADCR01.ST1            14
ADCR01.ST0            13
ADCR01.CT1            12
ADCR01.CT0            11
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
PPGC01               0x000038   PPG0/1 operation mode control register
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
PPG01                0x00003A   PPG0/1 clock selection register
PPG01.PEN1            15
PPG01.PE10            13
PPG01.PIE1            12
PPG01.PUF1            11
PPG01.MD1             10
PPG01.MD0             9
PPG01.PEN0            7
PPG01.PE00            5
PPG01.PIE0            4
PPG01.PUF0            3
PPGC23               0x00003C   PPG2/3 operation mode control register
PPGC23.PEN1           15
PPGC23.PE10           13
PPGC23.PIE1           12
PPGC23.PUF1           11
PPGC23.MD1            10
PPGC23.MD0            9
PPGC23.PEN0           7
PPGC23.PE00           5
PPGC23.PIE0           4
PPGC23.PUF0           3
PPG23                0x00003E   PPG2/3 Clock Selection Register
PPG23.PCS2            7
PPG23.PCS1            6
PPG23.PCS0            5
PPG23.PCM2            4
PPG23.PCM1            3
PPG23.PCM0            2
PPGC45               0x000040   PPG4/5 operation mode control register
PPGC45.PEN1           15
PPGC45.PE10           13
PPGC45.PIE1           12
PPGC45.PUF1           11
PPGC45.MD1            10
PPGC45.MD0            9
PPGC45.PEN0           7
PPGC45.PE00           5
PPGC45.PIE0           4
PPGC45.PUF0           3
PPG45                0x000042   PPG4/5 clock selection register
PPG45.PCS2            7
PPG45.PCS1            6
PPG45.PCS0            5
PPG45.PCM2            4
PPG45.PCM1            3
PPG45.PCM0            2
PPGC67               0x000044   PPG6/7 operation mode control register
PPGC67.PEN1           15
PPGC67.PE10           13
PPGC67.PIE1           12
PPGC67.PUF1           11
PPGC67.MD1            10
PPGC67.MD0            9
PPGC67.PEN0           7
PPGC67.PE00           5
PPGC67.PIE0           4
PPGC67.PUF0           3
PPG67                0x000046   PPG6/7 clock selection register
PPG67.PCS2            7
PPG67.PCS1            6
PPG67.PCS0            5
PPG67.PCM2            4
PPG67.PCM1            3
PPG67.PCM0            2
ICS01                0x00004C   Input capture control status register 0/1
ICS01.ICP1            7
ICS01.ICP0            6
ICS01.ICE1            5
ICS01.ICE0            4
ICS01.EG11            3 
ICS01.EG10            2
ICS01.EG01            1
ICS01.EG00            0
ICS23                0x00004D   Input capture control status register 2/3
ICS23.ICP1            7
ICS23.ICP0            6
ICS23.ICE1            5
ICS23.ICE0            4
ICS23.EG11            3 
ICS23.EG10            2
ICS23.EG01            1
ICS23.EG00            0
ICS45                0x00004E   Input capture control status register 4/5
ICS45.ICP1            7
ICS45.ICP0            6
ICS45.ICE1            5
ICS45.ICE0            4
ICS45.EG11            3 
ICS45.EG10            2
ICS45.EG01            1
ICS45.EG00            0
ICS67                0x00004F   Input capture control status register 6/7
ICS67.ICP1            7
ICS67.ICP0            6
ICS67.ICE1            5
ICS67.ICE0            4
ICS67.EG11            3 
ICS67.EG10            2
ICS67.EG01            1
ICS67.EG00            0
TMCSR0               0x000050   Timer control status register 0
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
TMR0                 0x000052   Timer register 0/reload register 0
TMCSR1               0x000054   Timer control status register 1
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
TMR1                 0x000056   Timer register 1/reload register 1
OCS01                0x000058   Output compare control status register 0/1
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
OCS23                0x00005A   Output compare control status register 2/3
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
TCDT                 0x00006C   Timer Data register
TCCS                 0x00006E   Timer Control register
TCCS.IVF              6
TCCS.IVFE             5
TCCS.STOP             4
TCCS.MODE             3
TCCS.CLR              2
TCCS.CLK1             1
TCCS.CLK0             0
ROMM                 0x00006F   ROM mirror function selection register
PACSR                0x00009E   Program address detection control status register
PACSR.AD1E            3
PACSR.AD0E            1
DIRR                 0x00009F   Delayed interrupt/release register
DIRR.R0               0
LPMCR                0x0000A0   Low-power mode control register
LPMCR.STP             7
LPMCR.SLP             6
LPMCR.SPL             5
LPMCR.RST             4
LPMCR.TMD             3
LPMCR.CG1             2
LPMCR.CG0             1
LPMCR.SSR             0
CKSCR                0x0000A1   Clock selection register
CKSCR.SCM             7
CKSCR.MCM             6
CKSCR.WS1             5
CKSCR.WS0             4
CKSCR.SCS             3
CKSCR.MCS             2
CKSCR.CS1             1 
CKSCR.CS0             0
ARSR                 0x0000A5   Automatic ready function select register
HACR                 0x0000A6   External address output control register
ECSR                 0x0000A7   Bus control signal selection register
WDTC                 0x0000A8   Watchdog Timer control register
WDTC.PONR             7
WDTC.STBR             6
WDTC.WRST             5
WDTC.ERST             4
WDTC.SRST             3
TBTC                 0x0000A9   Time Base Timer Control register
TBTC.TBIE             4
TBTC.TBOF             3
TBTC.TBR              2
TBTC.TBC1             1
TBTC.TBC0             0
WTC                  0x0000AA   Watch timer control register
WTC.WDCS              7
WTC.SCE               6
WTC.WTIE              5
WTC.WTOF              4
WTC.WTR               3
WTC.WTC2              2
WTC.WTC1              1
WTC.WTC0              0
FMCS                 0x0000AE   Flash memory control status register (Flash only, otherwise reserved)
ICR00                0x0000B0   Interrupt control register 00
ICR00.S1              5
ICR00.S0              4
ICR00.ISE             3
ICR00.IL2             2
ICR00.IL1             1
ICR00.IL0             0
ICR01                0x0000B1   Interrupt control register 01
ICR01.S1              5
ICR01.S0              4
ICR01.ISE             3
ICR01.IL2             2
ICR01.IL1             1
ICR01.IL0             0
ICR02                0x0000B2   Interrupt control register 02
ICR02.S1              5
ICR02.S0              4
ICR02.ISE             3
ICR02.IL2             2
ICR02.IL1             1
ICR02.IL0             0
ICR03                0x0000B3   Interrupt control register 03
ICR03.S1              5
ICR03.S0              4
ICR03.ISE             3
ICR03.IL2             2
ICR03.IL1             1
ICR03.IL0             0
ICR04                0x0000B4   Interrupt control register 04
ICR04.S1              5
ICR04.S0              4
ICR04.ISE             3
ICR04.IL2             2
ICR04.IL1             1
ICR04.IL0             0
ICR05                0x0000B5   Interrupt control register 05
ICR05.S1              5
ICR05.S0              4
ICR05.ISE             3
ICR05.IL2             2
ICR05.IL1             1
ICR05.IL0             0
ICR06                0x0000B6   Interrupt control register 06
ICR06.S1              5
ICR06.S0              4
ICR06.ISE             3
ICR06.IL2             2
ICR06.IL1             1
ICR06.IL0             0
ICR07                0x0000B7   Interrupt control register 07
ICR07.S1              5
ICR07.S0              4
ICR07.ISE             3
ICR07.IL2             2
ICR07.IL1             1
ICR07.IL0             0
ICR08                0x0000B8   Interrupt control register 08
ICR08.S1              5
ICR08.S0              4
ICR08.ISE             3
ICR08.IL2             2
ICR08.IL1             1
ICR08.IL0             0
ICR09                0x0000B9   Interrupt control register 09
ICR09.S1              5
ICR09.S0              4
ICR09.ISE             3
ICR09.IL2             2
ICR09.IL1             1
ICR09.IL0             0
ICR10                0x0000BA   Interrupt control register 10
ICR10.S1              5
ICR10.S0              4
ICR10.ISE             3
ICR10.IL2             2
ICR10.IL1             1
ICR10.IL0             0
ICR11                0x0000BB   Interrupt control register 11
ICR11.S1              5
ICR11.S0              4
ICR11.ISE             3
ICR11.IL2             2
ICR11.IL1             1
ICR11.IL0             0
ICR12                0x0000BC   Interrupt control register 12
ICR12.S1              5
ICR12.S0              4
ICR12.ISE             3
ICR12.IL2             2
ICR12.IL1             1
ICR12.IL0             0
ICR13                0x0000BD   Interrupt control register 13
ICR13.S1              5
ICR13.S0              4
ICR13.ISE             3
ICR13.IL2             2
ICR13.IL1             1
ICR13.IL0             0
ICR14                0x0000BE   Interrupt control register 14
ICR14.S1              5
ICR14.S0              4
ICR14.ISE             3
ICR14.IL2             2
ICR14.IL1             1
ICR14.IL0             0
ICR15                0x0000BF   Interrupt control register 15
ICR15.S1              5
ICR15.S0              4
ICR15.ISE             3
ICR15.IL2             2
ICR15.IL1             1
ICR15.IL0             0
; PADR0L      0x001FF0 Program address detection register 0 
; PADR0H      0x001FF1 Program address detection register 0 
; PADR0L      0x001FF2 Program address detection register 0 
; PADR1H      0x001FF3 Program address detection register 1 
; PADR1L      0x001FF4 Program address detection register 1 
; PADR1H      0x001FF5 Program address detection register 1 
PRLL0       0x003900 Reload L 
PRLH0       0x003901 Reload H 
PRLL1       0x003902 Reload L 
PRLH1       0x003903 Reload H 
PRLL2       0x003904 Reload L 
PRLH2       0x003905 Reload H 
PRLL3       0x003906 Reload L 
PRLH3       0x003907 Reload H 
PRLL4       0x003908 Reload L 
PRLH4       0x003909 Reload H 
PRLL5       0x00390A Reload L 
PRLH5       0x00390B Reload H 
PRLL6       0x00390C Reload L 
PRLH6       0x00390D Reload H 
PRLL7       0x00390E Reload L 
PRLH7       0x00390F Reload H 
Reserv3910  0x003910 Reserved
Reserv3911  0x003911 Reserved
Reserv3912  0x003912 Reserved
Reserv3913  0x003913 Reserved
Reserv3914  0x003914 Reserved
Reserv3915  0x003915 Reserved
Reserv3916  0x003916 Reserved
Reserv3917  0x003917 Reserved
IPCP0L      0x003918 Input Capture Register 0 
IPCP0H      0x003919 Input Capture Register 0 
IPCP1L      0x00391A Input Capture Register 1 
IPCP1H      0x00391B Input Capture Register 1 
IPCP2L      0x00391C Input Capture Register 2 
IPCP2H      0x00391D Input Capture Register 2 
IPCP3L      0x00391E Input Capture Register 3 
IPCP3H      0x00391F Input Capture Register 3 
IPCP4L      0x003920 Input Capture Register 4 
IPCP4H      0x003921 Input Capture Register 4 
IPCP5L      0x003922 Input Capture Register 5 
IPCP5H      0x003923 Input Capture Register 5 
IPCP6L      0x003924 Input Capture Register 6 
IPCP6H      0x003925 Input Capture Register 6 
IPCP7L      0x003926 Input Capture Register 7 
IPCP7H      0x003927 Input Capture Register 7 
OCCP0L      0x003928 Output Compare Register 0 
OCCP0H      0x003929 Output Compare Register 0 
OCCP1L      0x00392A Output Compare Register 1 
OCCP1H      0x00392B Output Compare Register 1 
OCCP2L      0x00392C Output Compare Register 2 
OCCP2H      0x00392D Output Compare Register 2 
OCCP3L      0x00392E Output Compare Register 3 
OCCP3H      0x00392F Output Compare Register 3 

    
.MB90545G
; DS07-13703-4E  http://edevice.fujitsu.com/fj/DATASHEET/e-ds/e713703.pdf
; MB90F549/F546G(S)/F548G(S)/F549G(S)/549G(S)/MB90548G(S)/F548GL(S)/MB90547G(S)


; ROM: 128 K (MB90F548G(S)/F548GL(S)/MB90548G(S))
;      256 K (MB90F549/F549G(S)/F546G(S)/MB90549G(S))
;       64 K (MB90547G(S))
; RAM:   4 Kbytes (MB90F548G(S)/F548GL(S)/MB90548G(S))
;        6 Kbytes (MB90F549/F549G(S)/MB90549G(S))
;        8 Kbytes (MB90F546G(S))
;        2 Kbytes (MB90547G(S))


; MEMORY MAP
; [MB90F546G(S)]
area DATA FSR              0x000000:0x0000C0
area DATA MEM_EXT_1        0x0000C0:0x000100
area DATA RAM              0x000100:0x002100
area DATA MEM_EXT_2        0x002100:0x003900
area DATA FSR_1            0x003900:0x004000
area DATA ROM_1            0x004000:0x010000
area DATA MEM_EXT_3        0x010000:0xFC0000
area DATA ROM_2_BANK_FC    0xFC0000:0xFD0000
area DATA ROM_2_BANK_FD    0xFD0000:0xFE0000
area DATA ROM_2_BANK_FE    0xFE0000:0xFF0000
area DATA ROM_2_BANK_FF    0xFF0000:0x1000000

; [MB90548G(S)/MB90F548GL(S)/MB90F548G(S)]
; area DATA FSR              0x000000:0x0000C0
; area DATA MEM_EXT_1        0x0000C0:0x000100
; area DATA RAM              0x000100:0x001100
; area DATA MEM_EXT_2        0x002000:0x003900
; area DATA FSR_1            0x003900:0x004000
; area DATA ROM_1            0x004000:0x010000
; area DATA MEM_EXT_3        0x010000:0xFE0000
; area DATA ROM_2_BANK_FE    0xFE0000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000

; [MB90F549/MB90549G(S)/MB90F549G(S)]
; area DATA FSR              0x000000:0x0000C0
; area DATA MEM_EXT_1        0x0000C0:0x000100
; area DATA RAM              0x000100:0x001900
; area DATA MEM_EXT_2        0x002100:0x003900
; area DATA FSR_1            0x003900:0x004000
; area DATA ROM_1            0x004000:0x010000
; area DATA MEM_EXT_3        0x010000:0xFC0000
; area DATA ROM_2_BANK_FC    0xFC0000:0xFD0000
; area DATA ROM_2_BANK_FD    0xFD0000:0xFE0000
; area DATA ROM_2_BANK_FE    0xFE0000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000

; [MB90547G(S)]
; area DATA FSR              0x000000:0x0000C0
; area DATA MEM_EXT_1        0x0000C0:0x000100
; area DATA RAM              0x000100:0x000900
; area DATA MEM_EXT_2        0x002000:0x003900
; area DATA FSR_1            0x003900:0x004000
; area DATA ROM_1            0x004000:0x010000
; area DATA MEM_EXT_3        0x010000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000


; Interrupt and reset vector assignments
interrupt __RESET       0xFFFFDC   Reset 
interrupt INT9          0xFFFFD8   INT9 instruction 
interrupt EXCEPT        0xFFFFD4   Exception 
interrupt CAN_0_RX      0xFFFFD0   CAN 0 RX 
interrupt CAN_0_TX_NS   0xFFFFCC   CAN 0 TX/NS 
interrupt CAN_1_RX      0xFFFFC8   CAN 1 RX 
interrupt CAN_1_TX_NS   0xFFFFC4   CAN 1 TX/NS 
interrupt INT0_INT1     0xFFFFC0   External Interrupt INT0/INT1 
interrupt TB_TIMER      0xFFFFBC   Time Base Timer 
interrupt R_TIMER       0xFFFFB8   16-bit Reload Timer 0 
interrupt A_D_CONV      0xFFFFB4   8/10-bit A/D Converter 
interrupt IO_TIMER      0xFFFFB0   I/O Timer 
interrupt INT2_INT3     0xFFFFAC   External Interrupt INT2/INT3 
interrupt I_O           0xFFFFA8   Serial I/O 
interrupt PPG_0_1       0xFFFFA4   8/16-bit PPG 0/1 
interrupt IC0           0xFFFFA0   Input Capture 0 
interrupt INT4_INT5     0xFFFF9C   External Interrupt INT4/INT5 
interrupt IC1           0xFFFF98   Input Capture 1 
interrupt PPG_2_3       0xFFFF94   8/16-bit PPG 2/3 
interrupt INT6_INT7     0xFFFF90   External Interrupt INT6/INT7 
interrupt W_TIMER       0xFFFF8C   Watch Timer 
interrupt PPG_4_5       0xFFFF88   8/16-bit PPG 4/5 
interrupt IC2_3         0xFFFF84   Input Capture 2/3 
interrupt PPG_6_7       0xFFFF80   8/16-bit PPG 6/7 
interrupt OC0           0xFFFF7C   Output Compare 0 
interrupt OC1           0xFFFF78   Output Compare 1 
interrupt IC4_5         0xFFFF74   Input Capture 4/5 
interrupt OC2_3_IC6_7   0xFFFF70   Output Compare 2/3 - Input Capture 6/7 
interrupt R_TIMER1      0xFFFF6C   16-bit Reload Timer 1 
interrupt UART_0_RX     0xFFFF68   UART 0 RX 
interrupt UART_0_TX     0xFFFF64   UART 0 TX 
interrupt UART_1_RX     0xFFFF60   UART 1 RX 
interrupt UART_1_TX     0xFFFF5C   UART 1 TX 
interrupt FLAS          0xFFFF58   Flash Memory 
interrupt DELAY         0xFFFF54   Delayed interrupt 


; INPUT/OUTPUT PORTS
PDR0                 0x000000   Port 0 data register
PDR0.P07              7
PDR0.P06              6
PDR0.P05              5
PDR0.P04              4
PDR0.P03              3
PDR0.P02              2
PDR0.P01              1
PDR0.P00              0
PDR1                 0x000001   Port 1 data register
PDR1.P17              7
PDR1.P16              6
PDR1.P15              5
PDR1.P14              4
PDR1.P13              3
PDR1.P12              2
PDR1.P11              1
PDR1.P10              0
PDR2                 0x000002   Port 2 data register
PDR2.P27              7
PDR2.P26              6
PDR2.P25              5
PDR2.P24              4
PDR2.P23              3
PDR2.P22              2
PDR2.P21              1
PDR2.P20              0
PDR3                 0x000003   Port 3 data register
PDR3.P37              7
PDR3.P36              6
PDR3.P35              5
PDR3.P34              4
PDR3.P33              3
PDR3.P32              2
PDR3.P31              1
PDR3.P30              0
PDR4                 0x000004   Port 4 data register
PDR4.P47              7
PDR4.P46              6
PDR4.P45              5
PDR4.P44              4
PDR4.P43              3
PDR4.P42              2
PDR4.P41              1
PDR4.P40              0
PDR5                 0x000005   Port 5 data register
PDR5.P57              7      
PDR5.P56              6
PDR5.P55              5
PDR5.P54              4
PDR5.P53              3
PDR5.P52              2
PDR5.P51              1
PDR5.P50              0
PDR6                 0x000006   Port 6 data register
PDR6.P67              7      
PDR6.P66              6
PDR6.P65              5
PDR6.P64              4
PDR6.P63              3
PDR6.P62              2
PDR6.P61              1
PDR6.P60              0
PDR7                 0x000007   Port 7 data register
PDR7.P77              7      
PDR7.P76              6
PDR7.P75              5
PDR7.P74              4
PDR7.P73              3
PDR7.P72              2
PDR7.P71              1
PDR7.P70              0
PDR8                 0x000008   Port 8 data register
PDR8.P87              7      
PDR8.P86              6
PDR8.P85              5
PDR8.P84              4
PDR8.P83              3
PDR8.P82              2
PDR8.P81              1
PDR8.P80              0
PDR9                 0x000009   Port 9 data register
PDR9.P97              7      
PDR9.P96              6
PDR9.P95              5
PDR9.P94              4
PDR9.P93              3
PDR9.P92              2
PDR9.P91              1
PDR9.P90              0
PDRA                 0x00000A   Port A data register
PDRA.PA0              0
DDR0                 0x000010   Port 0 direction register
DDR0.D07              7
DDR0.D06              6
DDR0.D05              5
DDR0.D04              4
DDR0.D03              3
DDR0.D02              2
DDR0.D01              1
DDR0.D00              0
DDR1                 0x000011   Port 1 direction register
DDR1.D17              7
DDR1.D16              6
DDR1.D15              5
DDR1.D14              4
DDR1.D13              3
DDR1.D12              2
DDR1.D11              1
DDR1.D10              0
DDR2                 0x000012   Port 2 direction register
DDR2.D27              7
DDR2.D26              6
DDR2.D25              5
DDR2.D24              4
DDR2.D23              3
DDR2.D22              2
DDR2.D21              1
DDR2.D20              0
DDR3                 0x000013   Port 3 direction register
DDR3.D37              7
DDR3.D36              6
DDR3.D35              5
DDR3.D34              4
DDR3.D33              3
DDR3.D32              2
DDR3.D31              1
DDR3.D30              0
DDR4                 0x000014   Port 4 direction register
DDR4.D47              7
DDR4.D46              6
DDR4.D45              5
DDR4.D44              4
DDR4.D43              3
DDR4.D42              2
DDR4.D41              1
DDR4.D40              0
DDR5                 0x000015   Port 5 direction register
DDR5.D57              7
DDR5.D56              6
DDR5.D55              5
DDR5.D54              4
DDR5.D53              3
DDR5.D52              2
DDR5.D51              1
DDR5.D50              0
DDR6                 0x000016   Port 6 direction register
DDR6.D67              7
DDR6.D66              6
DDR6.D65              5
DDR6.D64              4
DDR6.D63              3
DDR6.D62              2
DDR6.D61              1
DDR6.D60              0
DDR7                 0x000017   Port 7 direction register
DDR7.D77              7
DDR7.D76              6
DDR7.D75              5
DDR7.D74              4
DDR7.D73              3
DDR7.D72              2
DDR7.D71              1
DDR7.D70              0
DDR8                 0x000018   Port 8 direction register
DDR8.D87              7
DDR8.D86              6
DDR8.D85              5
DDR8.D84              4
DDR8.D83              3
DDR8.D82              2
DDR8.D81              1
DDR8.D80              0
DDR9                 0x000019   Port 9 direction register
DDR9.D97              7
DDR9.D96              6
DDR9.D95              5
DDR9.D94              4
DDR9.D93              3
DDR9.D92              2
DDR9.D91              1
DDR9.D90              0
DDRA                 0x00001A   Port A direction register
DDRA.DA0              0
ADER                 0x00001B   Analog Input Enable register
ADER.ADE7             7
ADER.ADE6             6
ADER.ADE5             5
ADER.ADE4             4
ADER.ADE3             3
ADER.ADE2             2
ADER.ADE1             1
ADER.ADE0             0
PUCR0                0x00001C   Port 0 Pullup control register
PUCR1                0x00001D   Port 1 Pullup control register
PUCR2                0x00001E   Port 2 Pullup control register
PUCR3                0x00001F   Port 3 Pullup control register
UMC0                 0x000020   Serial Mode Control Register 0
UMC0.PEN              7
UMC0.SBL              6
UMC0.MC1              5
UMC0.MC0              4
UMC0.SMDE             3
UMC0.RFC              2
UMC0.SCKE             1
UMC0.SOE              0
USR0                 0x000021   Serial Status Register 0
USR0.RDRF             7
USR0.ORFE             6
USR0.PE               5
USR0.TDRE             4
USR0.RIE              3
USR0.TIE              2
USR0.RBF              1
USR0.TBF              0
UIDR0                0x000022   Serial input data register 0 / Serial output data register 0
URD0                 0x000023   Rate and data register 0
SMR1                 0x000024   Serial mode register 1
SMR1.MD1              7
SMR1.MD0              6
SMR1.CS2              5
SMR1.CS1              4
SMR1.CS0              3
SMR1.SCKE             1
SMR1.SOE              0
SCR1                 0x000025   Serial control register 1
SCR1.PEN              7
SCR1.P                6
SCR1.SBL              5
SCR1.CL               4
SCR1.AD               3
SCR1.REC              2
SCR1.RXE              1
SCR1.TXE              0
SIDR1                0x000026   Serial input data register 1 / Serial output data register 1
SIDR1.D7              7
SIDR1.D6              6
SIDR1.D5              5
SIDR1.D4              4
SIDR1.D3              3
SIDR1.D2              2
SIDR1.D1              1
SIDR1.D0              0
SSR1                 0x000027   Serial status register 1
SSR1.PE               7
SSR1.ORE              6
SSR1.FRE              5
SSR1.RDRF             4
SSR1.TDRE             3
SSR1.RIE              1
SSR1.TIE              0
U1CDCR               0x000028   UART1 prescaler control register
SES1                 0x000029   Serial Edge select register
SES1.NEG              0
SCDCR                0x00002B   Serial I/O prescaler
SCDCR.NEG             0
SMCS                 0x00002C   Serial mode control register
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
SDR                  0x00002E   Serial data register
SES2                 0x00002F   Serial Edge select register
SES2.NEG              0
ENIR                 0x000030   External interrupt enable register
ENIR.EN7              7     
ENIR.EN6              6     
ENIR.EN5              5     
ENIR.EN4              4     
ENIR.EN3              3     
ENIR.EN2              2
ENIR.EN1              1
ENIR.EN0              0
EIRR                 0x000031   External interrupt request register
EIRR.ER7              7     
EIRR.ER6              6     
EIRR.ER5              5     
EIRR.ER4              4     
EIRR.ER3              3     
EIRR.ER2              2
EIRR.ER1              1
EIRR.ER0              0
ELVR                 0x000032   External interrupt level register
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
ADCS0                0x000034   A/D control status register 0
ADCS0.MD1             7
ADCS0.MD0             6
ADCS0.ANS2            5
ADCS0.ANS1            4
ADCS0.ANS0            3
ADCS0.ANE2            2
ADCS0.ANE1            1
ADCS0.ANE0            0
ADCS1                0x000035   A/D control status register 0
ADCS1.BUSY            7
ADCS1.INT             6
ADCS1.INTE            5
ADCS1.PAUS            4
ADCS1.STS1            3         
ADCS1.STS0            2
ADCR01               0x000036   A/D data register 0
ADCR01.S10            15
ADCR01.ST1            14
ADCR01.ST0            13
ADCR01.CT1            12
ADCR01.CT0            11
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
PPGC01               0x000038   PPG0/1 operation mode control register
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
PPG01                0x00003A   PPG0/1 clock selection register
PPG01.PEN1            15
PPG01.PE10            13
PPG01.PIE1            12
PPG01.PUF1            11
PPG01.MD1             10
PPG01.MD0             9
PPG01.PEN0            7
PPG01.PE00            5
PPG01.PIE0            4
PPG01.PUF0            3
PPGC23               0x00003C   PPG2/3 operation mode control register
PPGC23.PEN1           15
PPGC23.PE10           13
PPGC23.PIE1           12
PPGC23.PUF1           11
PPGC23.MD1            10
PPGC23.MD0            9
PPGC23.PEN0           7
PPGC23.PE00           5
PPGC23.PIE0           4
PPGC23.PUF0           3
PPG23                0x00003E   PPG2/3 Clock Selection Register
PPG23.PCS2            7
PPG23.PCS1            6
PPG23.PCS0            5
PPG23.PCM2            4
PPG23.PCM1            3
PPG23.PCM0            2
PPGC45               0x000040   PPG4/5 operation mode control register
PPGC45.PEN1           15
PPGC45.PE10           13
PPGC45.PIE1           12
PPGC45.PUF1           11
PPGC45.MD1            10
PPGC45.MD0            9
PPGC45.PEN0           7
PPGC45.PE00           5
PPGC45.PIE0           4
PPGC45.PUF0           3
PPG45                0x000042   PPG4/5 clock selection register
PPG45.PCS2            7
PPG45.PCS1            6
PPG45.PCS0            5
PPG45.PCM2            4
PPG45.PCM1            3
PPG45.PCM0            2
PPGC67               0x000044   PPG6/7 operation mode control register
PPGC67.PEN1           15
PPGC67.PE10           13
PPGC67.PIE1           12
PPGC67.PUF1           11
PPGC67.MD1            10
PPGC67.MD0            9
PPGC67.PEN0           7
PPGC67.PE00           5
PPGC67.PIE0           4
PPGC67.PUF0           3
PPG67                0x000046   PPG6/7 clock selection register
PPG67.PCS2            7
PPG67.PCS1            6
PPG67.PCS0            5
PPG67.PCM2            4
PPG67.PCM1            3
PPG67.PCM0            2
ICS01                0x00004C   Input capture control status register 0/1
ICS01.ICP1            7
ICS01.ICP0            6
ICS01.ICE1            5
ICS01.ICE0            4
ICS01.EG11            3 
ICS01.EG10            2
ICS01.EG01            1
ICS01.EG00            0
ICS23                0x00004D   Input capture control status register 2/3
ICS23.ICP1            7
ICS23.ICP0            6
ICS23.ICE1            5
ICS23.ICE0            4
ICS23.EG11            3 
ICS23.EG10            2
ICS23.EG01            1
ICS23.EG00            0
ICS45                0x00004E   Input capture control status register 4/5
ICS45.ICP1            7
ICS45.ICP0            6
ICS45.ICE1            5
ICS45.ICE0            4
ICS45.EG11            3 
ICS45.EG10            2
ICS45.EG01            1
ICS45.EG00            0
ICS67                0x00004F   Input capture control status register 6/7
ICS67.ICP1            7
ICS67.ICP0            6
ICS67.ICE1            5
ICS67.ICE0            4
ICS67.EG11            3 
ICS67.EG10            2
ICS67.EG01            1
ICS67.EG00            0
TMCSR0               0x000050   Timer control status register 0
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
TMR0                 0x000052   Timer register 0/reload register 0
TMCSR1               0x000054   Timer control status register 1
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
TMR1                 0x000056   Timer register 1/reload register 1
OCS01                0x000058   Output compare control status register 0/1
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
OCS23                0x00005A   Output compare control status register 2/3
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
TCDT                 0x00006C   Timer Data register
TCCS                 0x00006E   Timer Control register
TCCS.IVF              6
TCCS.IVFE             5
TCCS.STOP             4
TCCS.MODE             3
TCCS.CLR              2
TCCS.CLK1             1
TCCS.CLK0             0
ROMM                 0x00006F   ROM mirror function selection register
PACSR                0x00009E   Program address detection control status register
PACSR.AD1E            3
PACSR.AD0E            1
DIRR                 0x00009F   Delayed interrupt/release register
DIRR.R0               0
LPMCR                0x0000A0   Low-power mode control register
LPMCR.STP             7
LPMCR.SLP             6
LPMCR.SPL             5
LPMCR.RST             4
LPMCR.TMD             3
LPMCR.CG1             2
LPMCR.CG0             1
LPMCR.SSR             0
CKSCR                0x0000A1   Clock selection register
CKSCR.SCM             7
CKSCR.MCM             6
CKSCR.WS1             5
CKSCR.WS0             4
CKSCR.SCS             3
CKSCR.MCS             2
CKSCR.CS1             1 
CKSCR.CS0             0
ARSR                 0x0000A5   Automatic ready function select register
HACR                 0x0000A6   External address output control register
ECSR                 0x0000A7   Bus control signal selection register
WDTC                 0x0000A8   Watchdog Timer control register
WDTC.PONR             7
WDTC.STBR             6
WDTC.WRST             5
WDTC.ERST             4
WDTC.SRST             3
TBTC                 0x0000A9   Time Base Timer Control register
TBTC.TBIE             4
TBTC.TBOF             3
TBTC.TBR              2
TBTC.TBC1             1
TBTC.TBC0             0
WTC                  0x0000AA   Watch timer control register
WTC.WDCS              7
WTC.SCE               6
WTC.WTIE              5
WTC.WTOF              4
WTC.WTR               3
WTC.WTC2              2
WTC.WTC1              1
WTC.WTC0              0
FMCS                 0x0000AE   Flash memory control status register (Flash only, otherwise reserved)
ICR00                0x0000B0   Interrupt control register 00
ICR00.S1              5
ICR00.S0              4
ICR00.ISE             3
ICR00.IL2             2
ICR00.IL1             1
ICR00.IL0             0
ICR01                0x0000B1   Interrupt control register 01
ICR01.S1              5
ICR01.S0              4
ICR01.ISE             3
ICR01.IL2             2
ICR01.IL1             1
ICR01.IL0             0
ICR02                0x0000B2   Interrupt control register 02
ICR02.S1              5
ICR02.S0              4
ICR02.ISE             3
ICR02.IL2             2
ICR02.IL1             1
ICR02.IL0             0
ICR03                0x0000B3   Interrupt control register 03
ICR03.S1              5
ICR03.S0              4
ICR03.ISE             3
ICR03.IL2             2
ICR03.IL1             1
ICR03.IL0             0
ICR04                0x0000B4   Interrupt control register 04
ICR04.S1              5
ICR04.S0              4
ICR04.ISE             3
ICR04.IL2             2
ICR04.IL1             1
ICR04.IL0             0
ICR05                0x0000B5   Interrupt control register 05
ICR05.S1              5
ICR05.S0              4
ICR05.ISE             3
ICR05.IL2             2
ICR05.IL1             1
ICR05.IL0             0
ICR06                0x0000B6   Interrupt control register 06
ICR06.S1              5
ICR06.S0              4
ICR06.ISE             3
ICR06.IL2             2
ICR06.IL1             1
ICR06.IL0             0
ICR07                0x0000B7   Interrupt control register 07
ICR07.S1              5
ICR07.S0              4
ICR07.ISE             3
ICR07.IL2             2
ICR07.IL1             1
ICR07.IL0             0
ICR08                0x0000B8   Interrupt control register 08
ICR08.S1              5
ICR08.S0              4
ICR08.ISE             3
ICR08.IL2             2
ICR08.IL1             1
ICR08.IL0             0
ICR09                0x0000B9   Interrupt control register 09
ICR09.S1              5
ICR09.S0              4
ICR09.ISE             3
ICR09.IL2             2
ICR09.IL1             1
ICR09.IL0             0
ICR10                0x0000BA   Interrupt control register 10
ICR10.S1              5
ICR10.S0              4
ICR10.ISE             3
ICR10.IL2             2
ICR10.IL1             1
ICR10.IL0             0
ICR11                0x0000BB   Interrupt control register 11
ICR11.S1              5
ICR11.S0              4
ICR11.ISE             3
ICR11.IL2             2
ICR11.IL1             1
ICR11.IL0             0
ICR12                0x0000BC   Interrupt control register 12
ICR12.S1              5
ICR12.S0              4
ICR12.ISE             3
ICR12.IL2             2
ICR12.IL1             1
ICR12.IL0             0
ICR13                0x0000BD   Interrupt control register 13
ICR13.S1              5
ICR13.S0              4
ICR13.ISE             3
ICR13.IL2             2
ICR13.IL1             1
ICR13.IL0             0
ICR14                0x0000BE   Interrupt control register 14
ICR14.S1              5
ICR14.S0              4
ICR14.ISE             3
ICR14.IL2             2
ICR14.IL1             1
ICR14.IL0             0
ICR15                0x0000BF   Interrupt control register 15
ICR15.S1              5
ICR15.S0              4
ICR15.ISE             3
ICR15.IL2             2
ICR15.IL1             1
ICR15.IL0             0
IPCP0L               0x003918     Input Capture Register 0 
IPCP0H               0x003919     Input Capture Register 0 
IPCP1L               0x00391A     Input Capture Register 1 
IPCP1H               0x00391B     Input Capture Register 1 
IPCP2L               0x00391C     Input Capture Register 2 
IPCP2H               0x00391D     Input Capture Register 2 
IPCP3L               0x00391E     Input Capture Register 3 
IPCP3H               0x00391F     Input Capture Register 3 
IPCP4L               0x003920     Input Capture Register 4 
IPCP4H               0x003921     Input Capture Register 4 
IPCP5L               0x003922     Input Capture Register 5 
IPCP5H               0x003923     Input Capture Register 5 
IPCP6L               0x003924     Input Capture Register 6 
IPCP6H               0x003925     Input Capture Register 6 
IPCP7L               0x003926     Input Capture Register 7 
IPCP7H               0x003927     Input Capture Register 7 
OCCP0L               0x003928     Output Compare Register 0 
OCCP0H               0x003929     Output Compare Register 0 
OCCP1L               0x00392A     Output Compare Register 1 
OCCP1H               0x00392B     Output Compare Register 1 
OCCP2L               0x00392C     Output Compare Register 2 
OCCP2H               0x00392D     Output Compare Register 2 
OCCP3L               0x00392E     Output Compare Register 3 
OCCP3H               0x00392F     Output Compare Register 3 


.MB90550A
; DS07-13706-3E  http://edevice.fujitsu.com/fj/DATASHEET/e-ds/e713706.pdf
; MB90552A/552B/553A/553B/T552A/T553A/F553A/P553A


; ROM:  64 Kbytes (MB90552A/MB90552B)
;      128 Kbytes (MB90553A/MB90553B/MB90F553A/MB90P553A)
; RAM:   2 Kbytes (MB90552A/MB90552B/MB90T552A)
;        4 Kbytes (MB90553A/MB90553B/MB90F553A/MB90P553A/MB90T553A)
;        6 Kbytes (MB90V550A)


; MEMORY MAP
; [MB90552A/552B]
area DATA FSR              0x000000:0x0000C0
area BSS  No_access_1      0x0000C0:0x000100
area DATA RAM              0x000100:0x000900
area BSS  No_access_2      0x000900:0x004000
area DATA R0M_1            0x004000:0x010000
area BSS  No_access_3      0x010000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000

; [MB90553A/MB90553B/MB90F553A/MB90P553A]
; area DATA FSR              0x000000:0x0000C0
; area BSS  No_access_1      0x0000C0:0x000100
; area DATA RAM              0x000100:0x001100
; area BSS  No_access_2      0x001100:0x004000
; area DATA R0M_1            0x004000:0x010000
; area BSS  No_access_3      0x010000:0xFE0000
; area DATA ROM_2_BANK_FE    0xFE0000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000

; [MB90V550A]
; area DATA FSR              0x000000:0x0000C0
; area BSS  No_access_1      0x0000C0:0x000100
; area DATA RAM              0x000100:0x001900
; area BSS  No_access_2      0x001900:0x004000
; area DATA R0M_1            0x004000:0x010000
; area BSS  No_access_3      0x010000:0xFE0000
; area DATA ROM_2_BANK_FE    0xFE0000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000


; Interrupt and reset vector assignments
interrupt __RESET       0xFFFFDC   Reset 
interrupt INT9          0xFFFFD8   INT9 instruction 
interrupt EXCEPT        0xFFFFD4   Exception 
interrupt A_D_CONV      0xFFFFD0   A/D converter 
interrupt T_TIMER       0xFFFFCC   Timebase timer 
interrupt DTP0          0xFFFFC8   DTP0 (external interrupt 0) 
interrupt DTP4_5        0xFFFFC4   DTP4/5 (external interrupt 4/5) 
interrupt DTP1          0xFFFFC0   DTP1 (external interrupt 1) 
interrupt PPG_TIMER_0C  0xFFFFBC   8/16-bit PPG timer 0 counter borrow 
interrupt DTP2          0xFFFFB8   DTP2 (external interrupt 2) 
interrupt PPG_TIMER_1C  0xFFFFB4   8/16-bit PPG timer 1 counter borrow 
interrupt DTP3          0xFFFFB0   DTP3 (external interrupt 3) 
interrupt PPG_TIMER_2C  0xFFFFAC   8/16-bit PPG timer 2 counter borrow 
interrupt IO_SE0        0xFFFFA8   Extended I/O serial interface 0 
interrupt PPG_TIMER_3C  0xFFFFA4   8/16-bit PPG timer 3 counter borrow 
interrupt IO_SE1        0xFFFFA0   Extended I/O serial interface 1 
interrupt FT_TIMER      0xFFFF9C   16-bit free-run timer (I/O timer) overflow 
interrupt R_TIMER0      0xFFFF98   16-bit re-load timer 0 
interrupt DTP6_7        0xFFFF94   DTP6/7 (external interrupt 6/7) 
interrupt R_TIMER1      0xFFFF90   16-bit re-load timer 1 
interrupt PPG_TIMER_45C 0xFFFF8C   8/16-bit PPG timer 4/5 counter borrow 
interrupt IC_CH0        0xFFFF88   Input capture (ch.0) include (I/O timer) 
interrupt IC_CH1        0xFFFF84   Input capture (ch.1) include (I/O timer) 
interrupt IC_CH2        0xFFFF80   Input capture (ch.2) include (I/O timer) 
interrupt IC_CH3        0xFFFF7C   Input capture (ch.3) include (I/O timer) 
interrupt 0C_CH0        0xFFFF78   Output compare (ch.0) match (Output timer) 
interrupt 0C_CH1        0xFFFF74   Output compare (ch.1) match (Output timer) 
interrupt 0C_CH2        0xFFFF70   Output compare (ch.2) match (Output timer) 
interrupt 0C_CH3        0xFFFF6C   Output compare (ch.3) match (Output timer) 
interrupt UART_T        0xFFFF68   UART transmission complete 
interrupt I2C_I0        0xFFFF64   I2C interface 0 
interrupt UART0_R       0xFFFF60   UART0 reception complete 
interrupt I2C_I1        0xFFFF5C   I2C interface 1 
interrupt FLASH         0xFFFF58   Flash memory status 
interrupt DELAY         0xFFFF54   Delayed interrupt generation module 


; INPUT/OUTPUT PORTS
PDR0                 0x000000   Port 0 data register
PDR0.P07              7
PDR0.P06              6
PDR0.P05              5
PDR0.P04              4
PDR0.P03              3
PDR0.P02              2
PDR0.P01              1
PDR0.P00              0
PDR1                 0x000001   Port 1 data register
PDR1.P17              7
PDR1.P16              6
PDR1.P15              5
PDR1.P14              4
PDR1.P13              3
PDR1.P12              2
PDR1.P11              1
PDR1.P10              0
PDR2                 0x000002   Port 2 data register
PDR2.P27              7
PDR2.P26              6
PDR2.P25              5
PDR2.P24              4
PDR2.P23              3
PDR2.P22              2
PDR2.P21              1
PDR2.P20              0
PDR3                 0x000003   Port 3 data register
PDR3.P37              7
PDR3.P36              6
PDR3.P35              5
PDR3.P34              4
PDR3.P33              3
PDR3.P32              2
PDR3.P31              1
PDR3.P30              0
PDR4                 0x000004   Port 4 data register
PDR4.P47              7
PDR4.P46              6
PDR4.P45              5
PDR4.P44              4
PDR4.P43              3
PDR4.P42              2
PDR4.P41              1
PDR4.P40              0
PDR5                 0x000005   Port 5 data register
PDR5.P55              5
PDR5.P54              4
PDR5.P53              3
PDR5.P52              2
PDR5.P51              1
PDR5.P50              0
PDR6                 0x000006   Port 6 data register
PDR6.P67              7      
PDR6.P66              6
PDR6.P65              5
PDR6.P64              4
PDR6.P63              3
PDR6.P62              2
PDR6.P61              1
PDR6.P60              0
PDR7                 0x000007   Port 7 data register
PDR7.P77              7      
PDR7.P76              6
PDR7.P75              5
PDR7.P74              4
PDR7.P73              3
PDR7.P72              2
PDR7.P71              1
PDR7.P70              0
PDR8                 0x000008   Port 8 data register
PDR8.P87              7      
PDR8.P86              6
PDR8.P85              5
PDR8.P84              4
PDR8.P83              3
PDR8.P82              2
PDR8.P81              1
PDR8.P80              0
PDR9                 0x000009   Port 9 data register
PDR9.P97              7      
PDR9.P96              6
PDR9.P95              5
PDR9.P94              4
PDR9.P93              3
PDR9.P92              2
PDR9.P91              1
PDR9.P90              0
PDRA                 0x00000A   Port A data register
PDRA.PA4              4
PDRA.PA3              3
PDRA.PA2              2
PDRA.PA1              1
PDRA.PA0              0
DDR0                 0x000010   Port 0 direction register
DDR0.D07              7
DDR0.D06              6
DDR0.D05              5
DDR0.D04              4
DDR0.D03              3
DDR0.D02              2
DDR0.D01              1
DDR0.D00              0
DDR1                 0x000011   Port 1 direction register
DDR1.D17              7
DDR1.D16              6
DDR1.D15              5
DDR1.D14              4
DDR1.D13              3
DDR1.D12              2
DDR1.D11              1
DDR1.D10              0
DDR2                 0x000012   Port 2 direction register
DDR2.D27              7
DDR2.D26              6
DDR2.D25              5
DDR2.D24              4
DDR2.D23              3
DDR2.D22              2
DDR2.D21              1
DDR2.D20              0
DDR3                 0x000013   Port 3 direction register
DDR3.D37              7
DDR3.D36              6
DDR3.D35              5
DDR3.D34              4
DDR3.D33              3
DDR3.D32              2
DDR3.D31              1
DDR3.D30              0
DDR4                 0x000014   Port 4 direction register
DDR4.D47              7
DDR4.D46              6
DDR4.D45              5
DDR4.D44              4
DDR4.D43              3
DDR4.D42              2
DDR4.D41              1
DDR4.D40              0
DDR6                 0x000016   Port 6 direction register
DDR6.D67              7
DDR6.D66              6
DDR6.D65              5
DDR6.D64              4
DDR6.D63              3
DDR6.D62              2
DDR6.D61              1
DDR6.D60              0
DDR7                 0x000017   Port 7 direction register
DDR7.D77              7
DDR7.D76              6
DDR7.D75              5
DDR7.D74              4
DDR7.D73              3
DDR7.D72              2
DDR7.D71              1
DDR7.D70              0
DDR8                 0x000018   Port 8 direction register
DDR8.D87              7
DDR8.D86              6
DDR8.D85              5
DDR8.D84              4
DDR8.D83              3
DDR8.D82              2
DDR8.D81              1
DDR8.D80              0
DDR9                 0x000019   Port 9 direction register
DDR9.D97              7
DDR9.D96              6
DDR9.D95              5
DDR9.D94              4
DDR9.D93              3
DDR9.D92              2
DDR9.D91              1
DDR9.D90              0
DDRA                 0x00001A   Port A direction register
DDRA.DA4              4
DDRA.DA3              3
DDRA.DA2              2
DDRA.DA1              1
DDRA.DA0              0
ODR4                 0x00001B   Port 4 output pin register
ODR4.OD47             7
ODR4.OD46             6
ODR4.OD45             5
ODR4.OD44             4
ODR4.OD43             3
ODR4.OD42             2
ODR4.OD41             1
ODR4.OD40             0
RDR0                 0x00001C   Port 0 resistor setting register
RDR0.RD07             7
RDR0.RD06             6
RDR0.RD05             5
RDR0.RD04             4
RDR0.RD03             3
RDR0.RD02             2
RDR0.RD01             1
RDR0.RD00             0
RDR1                 0x00001D   Port 1 resistor setting register
RDR1.RD17             7
RDR1.RD16             6
RDR1.RD15             5
RDR1.RD14             4
RDR1.RD13             3
RDR1.RD12             2
RDR1.RD11             1
RDR1.RD10             0
ADER                 0x00001F   Analog input enable register
ADER.ADE7             7
ADER.ADE6             6
ADER.ADE5             5
ADER.ADE4             4
ADER.ADE3             3
ADER.ADE2             2
ADER.ADE1             1
ADER.ADE0             0
SMR                  0x000020   Serial mode register
SMR.MD1               7
SMR.MD0               6
SMR.CS2               5
SMR.CS1               4
SMR.CS0               3
SMR.SCKE              1
SMR.SOE               0
SCR                  0x000021   Serial control register
SCR.PEN               7
SCR.P                 6
SCR.SBL               5
SCR.CL                4
SCR.AD                3
SCR.REC               2
SCR.RXE               1
SCR.TXE               0
SIDR                 0x000022   Serial input data register / serial output data register
SIDR.D7               7
SIDR.D6               6
SIDR.D5               5
SIDR.D4               4
SIDR.D3               3
SIDR.D2               2
SIDR.D1               1
SIDR.D0               0
SSR                  0x000023   Serial status register
SSR.PE                7     Parity error
SSR.ORE               6     Over Run Error
SSR.FRE               5     Framing error
SSR.RDRF              4     Receiver data register full
SSR.TDRE              3     Transmitter data register empty
SSR.RIE               1     Receiver interrupt enable
SSR.TIE               0     Transmitter interrupt enable
SMCS0                0x000024   Serial mode control status
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
SDR0                 0x000026   Serial data register 0
CDCR                 0x000027   Clock frequency-divider control register
CDCR.MD               7
CDCR.DIV3             3
CDCR.DIV2             2
CDCR.DIV1             1
CDCR.DIV0             0
SMCS1                0x000028   Serial mode control status register 1
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
SDR1                 0x00002A   Serial data register 1
IBSR0                0x00002C   I2C bus status register 0
IBSR0.BB              7
IBSR0.RSC             6
IBSR0.AL              5
IBSR0.LRB             4
IBSR0.TRX             3
IBSR0.AAS             2
IBSR0.GCA             1
IBSR0.FBT             0
IBCR0                0x00002D   I2C bus control register 0
IBCR0.BER             7
IBCR0.BEIE            6
IBCR0.SCC             5
IBCR0.MSS             4
IBCR0.ACK             3
IBCR0.GCAA            2
IBCR0.INTE            1
IBCR0.INT             0
ICCR0                0x00002E   I2C bus clock select register 0
ICCR0.EN              5
ICCR0.CS4             4 
ICCR0.CS3             3
ICCR0.CS2             2
ICCR0.CS1             1
ICCR0.CS0             0
IADR0                0x00002F   I2C bus address register 0
IADR0.A6              6
IADR0.A5              5
IADR0.A4              4
IADR0.A3              3
IADR0.A2              2
IADR0.A1              1
IADR0.A0              0
IDAR0                0x000030   I2C bus data register 0
IBSR1                0x000032   I2C bus status register 1
IBSR1.BB              7
IBSR1.RSC             6
IBSR1.AL              5
IBSR1.LRB             4
IBSR1.TRX             3
IBSR1.AAS             2
IBSR1.GCA             1
IBSR1.FBT             0
IBCR1                0x000033   I2C bus control register 1
IBCR1.BER             7
IBCR1.BEIE            6
IBCR1.SCC             5
IBCR1.MSS             4
IBCR1.ACK             3
IBCR1.GCAA            2
IBCR1.INTE            1
IBCR1.INT             0
ICCR1                0x000034   I2C bus clock select register 1
ICCR1.EN              5
ICCR1.CS4             4 
ICCR1.CS3             3
ICCR1.CS2             2
ICCR1.CS1             1
ICCR1.CS0             0
IADR1                0x000035   I2C bus address register 1
IADR1.A6              6
IADR1.A5              5
IADR1.A4              4
IADR1.A3              3
IADR1.A2              2
IADR1.A1              1
IADR1.A0              0
IDAR1                0x000036   I2C bus data register 1
ISEL                 0x000037   I2C bus port select register
ISEL.SEL              0
ENIR                 0x000038   Interrupt/DTP enable register
ENIR.EN7              7     
ENIR.EN6              6     
ENIR.EN5              5     
ENIR.EN4              4     
ENIR.EN3              3     
ENIR.EN2              2
ENIR.EN1              1
ENIR.EN0              0
EIRR                 0x000039   Interrupt/DTP factor register
EIRR.ER7              7     
EIRR.ER6              6     
EIRR.ER5              5     
EIRR.ER4              4     
EIRR.ER3              3     
EIRR.ER2              2
EIRR.ER1              1
EIRR.ER0              0
ELVR                 0x00003A   Request level setting register
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
ADCS0                0x00003C   Control status register
ADCS0.MD1             7
ADCS0.MD0             6
ADCS0.ANS2            5
ADCS0.ANS1            4
ADCS0.ANS0            3
ADCS0.ANE2            2
ADCS0.ANE1            1
ADCS0.ANE0            0
ADCS1                0x00003D   Control status register
ADCS1.BUSY            7
ADCS1.INT             6
ADCS1.INTE            5
ADCS1.PAUS            4
ADCS1.STS1            3
ADCS1.STS0            2
ADCS1.STRT0           1
ADCR0                0x00003E   Data register
ADCR1                0x00003F   Data register
PRL0_PRLL            0x000040   Reload register L (ch.0)
PRL0_PRLH            0x000041   Reload register H (ch.0)
PRL1_PRLL            0x000042   Reload register L (ch.1)
PRL1_PRLH            0x000043   Reload register H (ch.1)
PPGC01               0x000044   PPG0 operating mode control register
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
PPGE1                0x000046   PPG0 and 1 output control
PPGE1.PCS2            7
PPGE1.PCS1            6
PPGE1.PCS0            5
PPGE1.PCM2            4
PPGE1.PCM1            3
PPGE1.PCM0            2
PRL2_PRLL            0x000048   Reload register L (ch.2)
PRL2_PRLH            0x000049   Reload register H (ch.2)
PRL3_PRLL            0x00004A   Reload register L (ch.3)
PRL3_PRLH            0x00004B   Reload register H (ch.3)
PPGC23               0x00004C   PPG2/3 operating mode control register
PPGC23.PEN1           15
PPGC23.PE10           13
PPGC23.PIE1           12
PPGC23.PUF1           11
PPGC23.MD1            10
PPGC23.MD0            9
PPGC23.PEN0           7
PPGC23.PE00           5
PPGC23.PIE0           4
PPGC23.PUF0           3
PPGE2                0x00004E   PPG2 and 3 output control register
PPGE2.PCS2            7
PPGE2.PCS1            6
PPGE2.PCS0            5
PPGE2.PCM2            4
PPGE2.PCM1            3
PPGE2.PCM0            2
PRL4_PRLL            0x000050   Reload register L (ch.4)
PRL4_PRLH            0x000051   Reload register H (ch.4)
PRL5_PRLL            0x000052   Reload register L (ch.5)
PRL5_PRLH            0x000053   Reload register H (ch.5)
PPGC45               0x000054   PPG4 operating mode control register
PPGC45.PEN1           15
PPGC45.PE10           13
PPGC45.PIE1           12
PPGC45.PUF1           11
PPGC45.MD1            10
PPGC45.MD0            9
PPGC45.PEN0           7
PPGC45.PE00           5
PPGC45.PIE0           4
PPGC45.PUF0           3
PPGE3                0x000056   PPG4 and 5 output control register
PPGE3.PCS2            7
PPGE3.PCS1            6
PPGE3.PCS0            5
PPGE3.PCM2            4
PPGE3.PCM1            3
PPGE3.PCM0            2
CLKR                 0x000058   Clock output enable register
CLKR.CKEN             3
CLKR.FRQ2             2
CLKR.FRQ1             1
CLKR.FRQ0             0
TMCSR0               0x00005A   Control status register 0
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
TMR0                 0x00005C   16 bit timer register 0 / 16 bit reload register 0
TMCSR1               0x00005E   Control status register 1
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
TMR1                 0x000060   16 bit timer register 1 / 16 bit reload register 1
IPCP0                0x000062   Input capture register, channel-0 bits
IPCP1                0x000064   Input capture register, channel-1 bits
IPCP2                0x000066   Input capture register, channel-2 bits
IPCP3                0x000068   Input capture register, channel-3 bits
ICS01                0x00006A   Input capture control status register
ICS01.ICP1            7
ICS01.ICP0            6
ICS01.ICE1            5
ICS01.ICE0            4
ICS01.EG11            3 
ICS01.EG10            2
ICS01.EG01            1
ICS01.EG00            0
ICS23                0x00006B   Input capture control status register
ICS23.ICP1            7
ICS23.ICP0            6
ICS23.ICE1            5
ICS23.ICE0            4
ICS23.EG11            3 
ICS23.EG10            2
ICS23.EG01            1
ICS23.EG00            0
TCDT                 0x00006C   Timer data register
TCCS                 0x00006E   Timer control status register
TCCS.IVF              6
TCCS.IVFE             5
TCCS.STOP             4
TCCS.MODE             3
TCCS.CLR              2
TCCS.CLK1             1
TCCS.CLK0             0
ROMM                 0x00006F   ROM mirroring function selection register
OCCP0                0x000070   Compare register, channel-0
OCCP1                0x000072   Compare register, channel-1
OCCP2                0x000074   Compare register, channel-2
OCCP3                0x000076   Compare register, channel-3
OCS01                0x000078   Compare control status register, channel-0/1
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
OCS23                0x00007A   Compare control status register, channel-2/3
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
PACSR                0x00009E   Program address detection control register
PACSR.AD1E            3
PACSR.AD0E            1
DIRR                 0x00009F   Delayed interrupt factor generation/cancellation register
DIRR.R0               0
LPMCR                0x0000A0   Low-power consumption mode control register
LPMCR.STP             7
LPMCR.SLP             6
LPMCR.SPL             5
LPMCR.RST             4
LPMCR.CG1             2
LPMCR.CG0             1
CKSCR                0x0000A1   Clock select register
CKSCR.SCM             7
CKSCR.MCM             6
CKSCR.WS1             5
CKSCR.WS0             4
CKSCR.SCS             3
CKSCR.MCS             2
CKSCR.CS1             1 
CKSCR.CS0             0
ARSR                 0x0000A5   Automatic ready function select register
HACR                 0x0000A6   External address output control register
ECSR                 0x0000A7   Bus control signal select register
WDTC                 0x0000A8   Watchdog timer control register
WDTC.PONR             7
WDTC.STBR             6
WDTC.WRST             5
WDTC.ERST             4
WDTC.SRST             3
TBTC                 0x0000A9   Timebase timer control register
TBTC.TBIE             4
TBTC.TBOF             3
TBTC.TBR              2
TBTC.TBC1             1
TBTC.TBC0             0
FMCS                 0x0000AE   Flash memory control status register
ICR00                0x0000B0   Interrupt control register 00
ICR00.S1              5
ICR00.S0              4
ICR00.ISE             3
ICR00.IL2             2
ICR00.IL1             1
ICR00.IL0             0
ICR01                0x0000B1   Interrupt control register 01
ICR01.S1              5
ICR01.S0              4
ICR01.ISE             3
ICR01.IL2             2
ICR01.IL1             1
ICR01.IL0             0
ICR02                0x0000B2   Interrupt control register 02
ICR02.S1              5
ICR02.S0              4
ICR02.ISE             3
ICR02.IL2             2
ICR02.IL1             1
ICR02.IL0             0
ICR03                0x0000B3   Interrupt control register 03
ICR03.S1              5
ICR03.S0              4
ICR03.ISE             3
ICR03.IL2             2
ICR03.IL1             1
ICR03.IL0             0
ICR04                0x0000B4   Interrupt control register 04
ICR04.S1              5
ICR04.S0              4
ICR04.ISE             3
ICR04.IL2             2
ICR04.IL1             1
ICR04.IL0             0
ICR05                0x0000B5   Interrupt control register 05
ICR05.S1              5
ICR05.S0              4
ICR05.ISE             3
ICR05.IL2             2
ICR05.IL1             1
ICR05.IL0             0
ICR06                0x0000B6   Interrupt control register 06
ICR06.S1              5
ICR06.S0              4
ICR06.ISE             3
ICR06.IL2             2
ICR06.IL1             1
ICR06.IL0             0
ICR07                0x0000B7   Interrupt control register 07
ICR07.S1              5
ICR07.S0              4
ICR07.ISE             3
ICR07.IL2             2
ICR07.IL1             1
ICR07.IL0             0
ICR08                0x0000B8   Interrupt control register 08
ICR08.S1              5
ICR08.S0              4
ICR08.ISE             3
ICR08.IL2             2
ICR08.IL1             1
ICR08.IL0             0
ICR09                0x0000B9   Interrupt control register 09
ICR09.S1              5
ICR09.S0              4
ICR09.ISE             3
ICR09.IL2             2
ICR09.IL1             1
ICR09.IL0             0
ICR10                0x0000BA   Interrupt control register 10
ICR10.S1              5
ICR10.S0              4
ICR10.ISE             3
ICR10.IL2             2
ICR10.IL1             1
ICR10.IL0             0
ICR11                0x0000BB   Interrupt control register 11
ICR11.S1              5
ICR11.S0              4
ICR11.ISE             3
ICR11.IL2             2
ICR11.IL1             1
ICR11.IL0             0
ICR12                0x0000BC   Interrupt control register 12
ICR12.S1              5
ICR12.S0              4
ICR12.ISE             3
ICR12.IL2             2
ICR12.IL1             1
ICR12.IL0             0
ICR13                0x0000BD   Interrupt control register 13
ICR13.S1              5
ICR13.S0              4
ICR13.ISE             3
ICR13.IL2             2
ICR13.IL1             1
ICR13.IL0             0
ICR14                0x0000BE   Interrupt control register 14
ICR14.S1              5
ICR14.S0              4
ICR14.ISE             3
ICR14.IL2             2
ICR14.IL1             1
ICR14.IL0             0
ICR15                0x0000BF   Interrupt control register 15
ICR15.S1              5
ICR15.S0              4
ICR15.ISE             3
ICR15.IL2             2
ICR15.IL1             1
ICR15.IL0             0


.MB90560
; DS07-13715-2E  http://edevice.fujitsu.com/fj/DATASHEET/e-ds/e713715.pdf
; MB90561/561A/562/562A/F562/F562B/V560


; ROM: 64 Kbytes (MB90F562/B/MB90562/A)
;      32 Kbytes (MB90561/A)
; RAM:  2 Kbytes (MB90F562/B/MB90562/A)
;       1 Kbytes (MB90561/A)
;       4 Kbytes (MB90V560)


; MEMORY MAP
; [MB90561/A]
area DATA FSR              0x000000:0x0000C0
area BSS  No_access_1      0x0000C0:0x000100
area DATA RAM              0x000100:0x000500
area BSS  No_access_2      0x000500:0x008000
area DATA ROM_1            0x008000:0x010000
area BSS  No_access_3      0x010000:0xFF8000
; area DATA ROM_2_BANK_FF    0xFF8000:0x1000000

; [MB90562/A/MB90F562/B]
; area DATA FSR              0x000000:0x0000C0
; area BSS  No_access_1      0x0000C0:0x000100
; area DATA RAM              0x000100:0x000900
; area BSS  No_access_2      0x000900:0x004000
; area DATA ROM_1            0x004000:0x010000
; area BSS  No_access_3      0x010000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000

; [MB90V560]
; area DATA FSR              0x000000:0x0000C0
; area BSS  No_access_1      0x0000C0:0x000100
; area DATA RAM              0x000100:0x001100
; area BSS  No_access_2      0x001100:0x004000
; area DATA ROM_1            0x004000:0x010000
; area BSS  No_access_3      0x010000:0xFE0000
; area DATA ROM_2_BANK_FE    0xFE0000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000


; Interrupt and reset vector assignments
interrupt __RESET       0xFFFFDC   Reset 
interrupt INT_9         0xFFFFD8   INT 9 instruction 
interrupt EXCEPT        0xFFFFD4   Exception 
interrupt A_D_CCC       0xFFFFD0   A/D converter conversion complete 
interrupt OC_CH0        0xFFFFC8   Output compare channel 0 match 
interrupt PPG_TIMER0    0xFFFFC4   8/16-bit PPG timer 0 counter borrow 
interrupt OC_CH1        0xFFFFC0   Output compare channel 1 match 
interrupt PPG_TIMER1    0xFFFFBC   8/16-bit PPG timer 1 counter borrow 
interrupt OC_CH2        0xFFFFB8   Output compare channel 2 match 
interrupt PPG_TIMER2    0xFFFFB4   8/16-bit PPG timer 2 counter borrow 
interrupt OC_CH3        0xFFFFB0   Output compare channel 3 match 
interrupt PPG_TIMER3    0xFFFFAC   8/16-bit PPG timer 3 counter borrow 
interrupt OC_CH4        0xFFFFA8   Output compare channel 4 match 
interrupt PPG_TIMER4    0xFFFFA4   8/16-bit PPG timer 4 counter borrow 
interrupt OC_CH5        0xFFFFA0   Output compare channel 5 match 
interrupt PPG_TIMER5    0xFFFF9C   8/16-bit PPG timer 5 counter borrow 
interrupt DTP_EI_CH01   0xFFFF98   DTP/external interrupt channel 0/1 detection 
interrupt DTP_EI_CH23   0xFFFF94   DTP/external interrupt channel 2/3 detection 
interrupt DTP_EI_CH45   0xFFFF90   DTP/external interrupt channel 4/5 detection 
interrupt DTP_EI_CH67   0xFFFF8C   DTP/external interrupt channel 6/7 detection 
interrupt TIMER_0_1_2   0xFFFF88   8-bit timer 0/1/2 counter borrow 
interrupt R_TIER0       0xFFFF84   16-bit reload timer 0 underflow 
interrupt F_TIMER_O     0xFFFF80   16-bit freerun timer overflow 
interrupt R_TIMER_1     0xFFFF7C   16-bit reload timer 1 underflow 
interrupt IC_CH01       0xFFFF78   Input capture channel 0/1 
interrupt F_TIMER_C     0xFFFF74   16-bit freerun timer clear 
interrupt IC_CH02_3     0xFFFF70   Input capture channel 2/3 
interrupt T_TIMER       0xFFFF6C   Timebase timer 
interrupt UART1_R       0xFFFF68   UART1 receive 
interrupt UART1_S       0xFFFF64   UART1 send 
interrupt UART0_R       0xFFFF60   UART0 receive 
interrupt UART0_S       0xFFFF5C   UART0 send 
interrupt FLASH         0xFFFF58   Flash memory status 
interrupt DELAY         0xFFFF54   Delay interrupt output module 


; INPUT/OUTPUT PORTS
PDR0                 0x000000   Port 0 data register
PDR0.P07              7
PDR0.P06              6
PDR0.P05              5
PDR0.P04              4
PDR0.P03              3
PDR0.P02              2
PDR0.P01              1
PDR0.P00              0
PDR1                 0x000001   Port 1 data register
PDR1.P17              7
PDR1.P16              6
PDR1.P15              5
PDR1.P14              4
PDR1.P13              3
PDR1.P12              2
PDR1.P11              1
PDR1.P10              0
PDR2                 0x000002   Port 2 data register
PDR2.P27              7
PDR2.P26              6
PDR2.P25              5
PDR2.P24              4
PDR2.P23              3
PDR2.P22              2
PDR2.P21              1
PDR2.P20              0
PDR3                 0x000003   Port 3 data register
PDR3.P37              7
PDR3.P36              6
PDR3.P35              5
PDR3.P34              4
PDR3.P33              3
PDR3.P32              2
PDR3.P31              1
PDR3.P30              0
PDR4                 0x000004   Port 4 data register
PDR4.P46              6
PDR4.P45              5
PDR4.P44              4
PDR4.P43              3
PDR4.P42              2
PDR4.P41              1
PDR4.P40              0
PDR5                 0x000005   Port 5 data register
PDR5.P57              7
PDR5.P56              6
PDR5.P55              5
PDR5.P54              4
PDR5.P53              3
PDR5.P52              2
PDR5.P51              1
PDR5.P50              0
PDR6                 0x000006   Port 6 data register
PDR6.P63              3
PDR6.P62              2
PDR6.P61              1
PDR6.P60              0
DDR0                 0x000010   Port 0 direction register
DDR0.D07              7
DDR0.D06              6
DDR0.D05              5
DDR0.D04              4
DDR0.D03              3
DDR0.D02              2
DDR0.D01              1
DDR0.D00              0
DDR1                 0x000011   Port 1 direction register
DDR1.D17              7
DDR1.D16              6
DDR1.D15              5
DDR1.D14              4
DDR1.D13              3
DDR1.D12              2
DDR1.D11              1
DDR1.D10              0
DDR2                 0x000012   Port 2 direction register
DDR2.D27              7
DDR2.D26              6
DDR2.D25              5
DDR2.D24              4
DDR2.D23              3
DDR2.D22              2
DDR2.D21              1
DDR2.D20              0
DDR3                 0x000013   Port 3 direction register
DDR3.D37              7
DDR3.D36              6
DDR3.D35              5
DDR3.D34              4
DDR3.D33              3
DDR3.D32              2
DDR3.D31              1
DDR3.D30              0
DDR4                 0x000014   Port 4 direction register
DDR4.D46              6
DDR4.D45              5
DDR4.D44              4
DDR4.D43              3
DDR4.D42              2
DDR4.D41              1
DDR4.D40              0
DDR5                 0x000015   Port 5 direction register
DDR5.D57              7
DDR5.D56              6
DDR5.D55              5
DDR5.D54              4
DDR5.D53              3
DDR5.D52              2
DDR5.D51              1
DDR5.D50              0
DDR6                 0x000016   Port 6 direction register
DDR6.D63              3
DDR6.D62              2
DDR6.D61              1
DDR6.D60              0
ADER                 0x000017   Analog input enable register
ADER.ADE7             7
ADER.ADE6             6
ADER.ADE5             5
ADER.ADE4             4
ADER.ADE3             3
ADER.ADE2             2
ADER.ADE1             1
ADER.ADE0             0
SMR0                 0x000020   Mode register ch0
SMR0.MD1              7
SMR0.MD0              6
SMR0.CS2              5
SMR0.CS1              4
SMR0.CS0              3
SMR0.SCKE             1
SMR0.SOE              0
SCR0                 0x000021   Control register ch0
SCR0.PEN              7
SCR0.P                6
SCR0.SBL              5
SCR0.CL               4
SCR0.AD               3
SCR0.REC              2
SCR0.RXE              1
SCR0.TXE              0
SIDR0                0x000022   Input data register ch0
SIDR0.D7              7
SIDR0.D6              6
SIDR0.D5              5
SIDR0.D4              4
SIDR0.D3              3
SIDR0.D2              2
SIDR0.D1              1
SIDR0.D0              0
SSR0                 0x000023   Status register ch0
SSR0.PE               7
SSR0.ORE              6
SSR0.FRE              5
SSR0.RDRF             4
SSR0.TDRE             3
SSR0.BDS              2
SSR0.RIE              1
SSR0.TIE              0
SMR1                 0x000024   Mode register ch1
SMR1.MD1              7
SMR1.MD0              6
SMR1.CS2              5
SMR1.CS1              4
SMR1.CS0              3
SMR1.SCKE             1
SMR1.SOE              0
SCR1                 0x000025   Control register ch1
SCR1.PEN              7
SCR1.P                6
SCR1.SBL              5
SCR1.CL               4
SCR1.AD               3
SCR1.REC              2
SCR1.RXE              1
SCR1.TXE              0
SIDR1                0x000026   Input data register ch1
SIDR1.D7              7
SIDR1.D6              6
SIDR1.D5              5
SIDR1.D4              4
SIDR1.D3              3
SIDR1.D2              2
SIDR1.D1              1
SIDR1.D0              0
SSR1                 0x000027   Status register ch1
SSR1.PE               7
SSR1.ORE              6
SSR1.FRE              5
SSR1.RDRF             4
SSR1.TDRE             3
SSR1.BDS              2
SSR1.RIE              1
SSR1.TIE              0
CDCR0                0x000029   Communication prescaler control register ch0
CDCR0.MD              7
CDCR0.DIV3            3
CDCR0.DIV2            2
CDCR0.DIV1            1
CDCR0.DIV0            0
CDCR1                0x00002B   Communication prescaler control register ch1
CDCR1.MD              7
CDCR1.DIV3            3
CDCR1.DIV2            2
CDCR1.DIV1            1
CDCR1.DIV0            0
ENIR                 0x000030   DTP/external interrupt enable register
ENIR.EN7              7     
ENIR.EN6              6     
ENIR.EN5              5     
ENIR.EN4              4     
ENIR.EN3              3     
ENIR.EN2              2
ENIR.EN1              1
ENIR.EN0              0
EIRR                 0x000031   DTP/external interrupt request register
EIRR.ER7              7     
EIRR.ER6              6     
EIRR.ER5              5     
EIRR.ER4              4     
EIRR.ER3              3     
EIRR.ER2              2
EIRR.ER1              1
EIRR.ER0              0
ELVR                 0x000032   Request level setting register
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
ADCS0                0x000034   A/D control status register (lower)
ADCS0.MD1             7
ADCS0.MD0             6
ADCS0.ANS2            5
ADCS0.ANS1            4
ADCS0.ANS0            3
ADCS0.ANE2            2
ADCS0.ANE1            1
ADCS0.ANE0            0
ADCS1                0x000035   A/D control status register (upper)
ADCS1.BUSY            7
ADCS1.INT             6
ADCS1.INTE            5
ADCS1.PAUS            4
ADCS1.STS1            3
ADCS1.STS0            2
ADCS1.STRT0           1
ADCR01               0x000036   A/D data register
ADCR01.S10            15
ADCR01.ST1            14
ADCR01.ST0            13
ADCR01.CT1            12
ADCR01.CT0            11
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
PRL0_PRLL            0x000038   PPG reload register ch0 (lower)
PRL0_PRLH            0x000039   PPG reload register ch0 (upper)
PRL1_PRLL            0x00003A   PPG reload register ch1 (lower)
PRL1_PRLH            0x00003B   PPG reload register ch1 (upper)
PPGC01               0x00003C   PPG control register ch0
PPGC01.PEN1           15
PPGC01.SST1           14
PPGC01.POE1           13
PPGC01.PIE1           12
PPGC01.PUF1           11
PPGC01.MD01           10
PPGC01.MD00           9
PPGC01.PEN0           7
PPGC01.SST0           6
PPGC01.POE0           5
PPGC01.PIE0           4
PPGC01.PUF0           3
PPGC01.POS1           2
PPGC01.POS0           1
PCS01                0x00003E   PPG clock control register ch0, ch1
PCS01.PC12            7
PCS01.PC11            6
PCS01.PC10            5
PCS01.PC02            4
PCS01.PC01            3
PCS01.PC00            2
PRL2_PRLL            0x000040   PPG reload register ch2 (lower)
PRL2_PRLH            0x000041   PPG reload register ch2 (upper)
PRL3_PRLL            0x000042   PPG reload register ch3 (lower)
PRL3_PRLH            0x000043   PPG reload register ch3 (upper)
PPGC23               0x000044   PPG control register ch2
PPGC23.PEN1           15
PPGC23.SST1           14
PPGC23.POE1           13
PPGC23.PIE1           12
PPGC23.PUF1           11
PPGC23.MD01           10
PPGC23.MD00           9
PPGC23.PEN0           7
PPGC23.SST0           6
PPGC23.POE0           5
PPGC23.PIE0           4
PPGC23.PUF0           3
PPGC23.POS1           2
PPGC23.POS0           1
PCS23                0x000046   PPG clock control register ch2, ch3
PCS23.PC12            7
PCS23.PC11            6
PCS23.PC10            5
PCS23.PC02            4
PCS23.PC01            3
PCS23.PC00            2
PRL4_PRLL            0x000048   PPG reload register ch4 (lower)
PRL4_PRLH            0x000049   PPG reload register ch4 (upper)
PRL5_PRLL            0x00004A   PPG reload register ch5 (lower)
PRL5_PRLH            0x00004B   PPG reload register ch5 (upper)
PPGC45               0x00004C   PPG control register ch4
PPGC45.PEN1           15
PPGC45.SST1           14
PPGC45.POE1           13
PPGC45.PIE1           12
PPGC45.PUF1           11
PPGC45.MD01           10
PPGC45.MD00           9
PPGC45.PEN0           7
PPGC45.SST0           6
PPGC45.POE0           5
PPGC45.PIE0           4
PPGC45.PUF0           3
PPGC45.POS1           2
PPGC45.POS0           1
PCS45                0x00004E   PPG clock control register ch4, ch5
PCS45.PC12            7
PCS45.PC11            6
PCS45.PC10            5
PCS45.PC02            4
PCS45.PC01            3
PCS45.PC00            2
TMRR0                0x000050   8-bit reload register ch0
DTCR0                0x000051   8-bit timer control register ch0
DTCR0.DMOD            7
DTCR0.GTEN            6
DTCR0.PGEN            5
DTCR0.TMIF            4
DTCR0.TMIE            3
DTCR0.TMD2            2
DTCR0.TMD1            1
DTCR0.TMD0            0
TMRR1                0x000052   8-bit reload register ch1
DTCR1                0x000053   8-bit timer control register ch1
DTCR1.DMOD            7
DTCR1.GTEN            6
DTCR1.PGEN            5
DTCR1.TMIF            4
DTCR1.TMIE            3
DTCR1.TMD2            2
DTCR1.TMD1            1
DTCR1.TMD0            0
TMRR2                0x000054   8-bit reload register ch2
DTCR2                0x000055   8-bit timer control register ch2
DTCR2.DMOD            7
DTCR2.GTEN            6
DTCR2.PGEN            5
DTCR2.TMIF            4
DTCR2.TMIE            3
DTCR2.TMD2            2
DTCR2.TMD1            1
DTCR2.TMD0            0
SIGCR                0x000056   Waveform control register
SIGCR.DTIE            7
SIGCR.DTIL            6
SIGCR.NRSL            5
SIGCR.DCK2            4
SIGCR.DCK1            3
SIGCR.DCK0            2
SIGCR.PGS1            1
SIGCR.PGS0            0
CPCLR                0x000058   Compare clear register
TCDT                 0x00005A   Timer data register
TCCS                 0x00005C   Timer control/status register
TCCS.ECKE             15
TCCS.MSI2             12
TCCS.MSI1             11
TCCS.MSI0             10
TCCS.ICLR             9
TCCS.ICRE             8
TCCS.IVF              7
TCCS.IVFE             6
TCCS.STOP             5
TCCS.MODE             4
TCCS.SCLR             3
TCCS.CLK2             2
TCCS.CLK1             1
TCCS.CLK0             0
IPCP0                0x000060   Input capture data register ch0
IPCP1                0x000062   Input capture data register ch1
IPCP2                0x000064   Input capture data register ch2
IPCP3                0x000066   Input capture data register ch3
ICS01                0x000068   Input capture control register 01
ICS01.ICP1            7
ICS01.ICP0            6
ICS01.ICE1            5
ICS01.ICE0            4
ICS01.EG11            3 
ICS01.EG10            2
ICS01.EG01            1
ICS01.EG00            0
ICS23                0x00006A   Input capture control register 23
ICS23.ICP3            7
ICS23.ICP2            6
ICS23.ICE3            5
ICS23.ICE2            4
ICS23.EG31            3
ICS23.EG30            2
ICS23.EG21            1 
ICS23.EG20            0
ROMM                 0x00006F   ROM mirror function selection register
OCCP0                0x000070   Compare register ch0
OCCP1                0x000072   Compare register ch1
OCCP2                0x000074   Compare register ch2
OCCP3                0x000076   Compare register ch3
OCCP4                0x000078   Compare register ch4
OCCP5                0x00007A   Compare register ch5
OCS01                0x00007C   Compare control register ch0/1
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
OCS23                0x00007E   Compare control register ch2/3
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
OCS45                0x000080   Compare control register ch4/5
OCS45.CMOD            12
OCS45.OTE1            11
OCS45.OTE0            10
OCS45.OTD1            9
OCS45.OTD0            8
OCS45.ICP1            7
OCS45.ICP0            6
OCS45.ICE1            5
OCS45.ICE0            4
OCS45.CST1            1
OCS45.CST0            0
TMCSR0               0x000082   Timer control status register ch0
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
TMR0                 0x000084   16-bit timer register ch0
TMCSR1               0x000086   Timer control status register ch1
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
TMR1                 0x000088   16-bit timer register ch1
RDR0                 0x00008C   Port 0 pull-up resistor setting register
RDR0.RD07             7
RDR0.RD06             6
RDR0.RD05             5
RDR0.RD04             4
RDR0.RD03             3
RDR0.RD02             2
RDR0.RD01             1
RDR0.RD00             0
RDR1                 0x00008D   Port 1 pull-up resistor setting register
RDR1.RD17             7
RDR1.RD16             6
RDR1.RD15             5
RDR1.RD14             4
RDR1.RD13             3
RDR1.RD12             2
RDR1.RD11             1
RDR1.RD10             0
PACSR                0x00009E   Program address detection control status register
PACSR.AD1E            3
PACSR.AD1D            2
PACSR.AD0E            1
PACSR.AD0D            0
DIRR                 0x00009F   Delayed interrupt request/clear register
DIRR.R0               0
LPMCR                0x0000A0   Low power consumption mode register
LPMCR.STP             7
LPMCR.SLP             6
LPMCR.SPL             5
LPMCR.RST             4
LPMCR.CG1             2
LPMCR.CG0             1
CKSCR                0x0000A1   Clock selection register
CKSCR.SCM             7
CKSCR.MCM             6
CKSCR.WS1             5
CKSCR.WS0             4
CKSCR.SCS             3
CKSCR.MCS             2
CKSCR.CS1             1 
CKSCR.CS0             0
WDTC                 0x0000A8   Watchdog control register
WDTC.PONR             7
WDTC.WRST             5
WDTC.ERST             4
WDTC.SRST             3
TBTC                 0x0000A9   Timebase timer control register
TBTC.TBIE             4
TBTC.TBOF             3
TBTC.TBR              2
TBTC.TBC1             1
TBTC.TBC0             0
ICR00                0x0000B0   Interrupt control register 00
ICR00.S1              5
ICR00.S0              4
ICR00.ISE             3
ICR00.IL2             2
ICR00.IL1             1
ICR00.IL0             0
ICR01                0x0000B1   Interrupt control register 01
ICR01.S1              5
ICR01.S0              4
ICR01.ISE             3
ICR01.IL2             2
ICR01.IL1             1
ICR01.IL0             0
ICR02                0x0000B2   Interrupt control register 02
ICR02.S1              5
ICR02.S0              4
ICR02.ISE             3
ICR02.IL2             2
ICR02.IL1             1
ICR02.IL0             0
ICR03                0x0000B3   Interrupt control register 03
ICR03.S1              5
ICR03.S0              4
ICR03.ISE             3
ICR03.IL2             2
ICR03.IL1             1
ICR03.IL0             0
ICR04                0x0000B4   Interrupt control register 04
ICR04.S1              5
ICR04.S0              4
ICR04.ISE             3
ICR04.IL2             2
ICR04.IL1             1
ICR04.IL0             0
ICR05                0x0000B5   Interrupt control register 05
ICR05.S1              5
ICR05.S0              4
ICR05.ISE             3
ICR05.IL2             2
ICR05.IL1             1
ICR05.IL0             0
ICR06                0x0000B6   Interrupt control register 06
ICR06.S1              5
ICR06.S0              4
ICR06.ISE             3
ICR06.IL2             2
ICR06.IL1             1
ICR06.IL0             0
ICR07                0x0000B7   Interrupt control register 07
ICR07.S1              5
ICR07.S0              4
ICR07.ISE             3
ICR07.IL2             2
ICR07.IL1             1
ICR07.IL0             0
ICR08                0x0000B8   Interrupt control register 08
ICR08.S1              5
ICR08.S0              4
ICR08.ISE             3
ICR08.IL2             2
ICR08.IL1             1
ICR08.IL0             0
ICR09                0x0000B9   Interrupt control register 09
ICR09.S1              5
ICR09.S0              4
ICR09.ISE             3
ICR09.IL2             2
ICR09.IL1             1
ICR09.IL0             0
ICR10                0x0000BA   Interrupt control register 10
ICR10.S1              5
ICR10.S0              4
ICR10.ISE             3
ICR10.IL2             2
ICR10.IL1             1
ICR10.IL0             0
ICR11                0x0000BB   Interrupt control register 11
ICR11.S1              5
ICR11.S0              4
ICR11.ISE             3
ICR11.IL2             2
ICR11.IL1             1
ICR11.IL0             0
ICR12                0x0000BC   Interrupt control register 12
ICR12.S1              5
ICR12.S0              4
ICR12.ISE             3
ICR12.IL2             2
ICR12.IL1             1
ICR12.IL0             0
ICR13                0x0000BD   Interrupt control register 13
ICR13.S1              5
ICR13.S0              4
ICR13.ISE             3
ICR13.IL2             2
ICR13.IL1             1
ICR13.IL0             0
ICR14                0x0000BE   Interrupt control register 14
ICR14.S1              5
ICR14.S0              4
ICR14.ISE             3
ICR14.IL2             2
ICR14.IL1             1
ICR14.IL0             0
ICR15                0x0000BF   Interrupt control register 15
ICR15.S1              5
ICR15.S0              4
ICR15.ISE             3
ICR15.IL2             2
ICR15.IL1             1
ICR15.IL0             0


.MB90565
; DS07-13715-2E  http://edevice.fujitsu.com/fj/DATASHEET/e-ds/e713715.pdf
; MB90567/568/F568


; ROM: 128 Kbytes (MB90F568/MB90568)
;       96 Kbytes (MB90567)
; RAM:   4 Kbytes (MB90F568/MB90568/MB90567)


; MEMORY MAP
; [MB90567]
area DATA FSR              0x000000:0x0000C0
area BSS  No_access_1      0x0000C0:0x000100
area DATA RAM              0x000100:0x001100
area BSS  No_access_2      0x001100:0x004000
area DATA ROM_1            0x004000:0x010000
area BSS  No_access_3      0x010000:0xFE8000
; area DATA ROM_2_BANK_FE    0xFE8000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000

; [MB90568/MB90F568]
; area DATA FSR              0x000000:0x0000C0
; area BSS  No_access_1      0x0000C0:0x000100
; area DATA RAM              0x000100:0x001100
; area BSS  No_access_2      0x001100:0x004000
; area DATA ROM_1            0x004000:0x010000
; area BSS  No_access_3      0x010000:0xFE0000
; area DATA ROM_2_BANK_FE    0xFE0000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000


; Interrupt and reset vector assignments
interrupt __RESET       0xFFFFDC   Reset 
interrupt INT_9         0xFFFFD8   INT 9 instruction 
interrupt EXCEPT        0xFFFFD4   Exception 
interrupt A_D_CCC       0xFFFFD0   A/D converter conversion complete 
interrupt OC_CH0        0xFFFFC8   Output compare channel 0 match 
interrupt PPG_TIMER0    0xFFFFC4   8/16-bit PPG timer 0 counter borrow 
interrupt OC_CH1        0xFFFFC0   Output compare channel 1 match 
interrupt PPG_TIMER1    0xFFFFBC   8/16-bit PPG timer 1 counter borrow 
interrupt OC_CH2        0xFFFFB8   Output compare channel 2 match 
interrupt PPG_TIMER2    0xFFFFB4   8/16-bit PPG timer 2 counter borrow 
interrupt OC_CH3        0xFFFFB0   Output compare channel 3 match 
interrupt PPG_TIMER3    0xFFFFAC   8/16-bit PPG timer 3 counter borrow 
interrupt OC_CH4        0xFFFFA8   Output compare channel 4 match 
interrupt PPG_TIMER4    0xFFFFA4   8/16-bit PPG timer 4 counter borrow 
interrupt OC_CH5        0xFFFFA0   Output compare channel 5 match 
interrupt PPG_TIMER5    0xFFFF9C   8/16-bit PPG timer 5 counter borrow 
interrupt DTP_EI_CH01   0xFFFF98   DTP/external interrupt channel 0/1 detection 
interrupt DTP_EI_CH23   0xFFFF94   DTP/external interrupt channel 2/3 detection 
interrupt DTP_EI_CH45   0xFFFF90   DTP/external interrupt channel 4/5 detection 
interrupt DTP_EI_CH67   0xFFFF8C   DTP/external interrupt channel 6/7 detection 
interrupt TIMER_012     0xFFFF88   8-bit timer 0/1/2 counter borrow 
interrupt R_TIMER_0     0xFFFF84   16-bit reload timer 0 underflow 
interrupt F_TIMER_O     0xFFFF80   16-bit freerun timer overflow 
interrupt R_TIMER_1     0xFFFF7C   16-bit reload timer 1 underflow 
interrupt IC_CH01       0xFFFF78   Input capture channel 0/1 
interrupt F_TIMER_C     0xFFFF74   16-bit freerun timer clear 
interrupt IC_CH023      0xFFFF70   Input capture channel 2/3 
interrupt T_TIMER       0xFFFF6C   Timebase timer 
interrupt UART1_R       0xFFFF68   UART1 receive 
interrupt UART1_S       0xFFFF64   UART1 send 
interrupt UART0_R       0xFFFF60   UART0 receive 
interrupt UART0_S       0xFFFF5C   UART0 send 
interrupt FLASH         0xFFFF58   Flash memory status 
interrupt DELAY         0xFFFF54   Delay interrupt output module 


; INPUT/OUTPUT PORTS
PDR0                 0x000000   Port 0 data register
PDR0.P07              7
PDR0.P06              6
PDR0.P05              5
PDR0.P04              4
PDR0.P03              3
PDR0.P02              2
PDR0.P01              1
PDR0.P00              0
PDR1                 0x000001   Port 1 data register
PDR1.P17              7
PDR1.P16              6
PDR1.P15              5
PDR1.P14              4
PDR1.P13              3
PDR1.P12              2
PDR1.P11              1
PDR1.P10              0
PDR2                 0x000002   Port 2 data register
PDR2.P27              7
PDR2.P26              6
PDR2.P25              5
PDR2.P24              4
PDR2.P23              3
PDR2.P22              2
PDR2.P21              1
PDR2.P20              0
PDR3                 0x000003   Port 3 data register
PDR3.P37              7
PDR3.P36              6
PDR3.P35              5
PDR3.P34              4
PDR3.P33              3
PDR3.P32              2
PDR3.P31              1
PDR3.P30              0
PDR4                 0x000004   Port 4 data register
PDR4.P46              6
PDR4.P45              5
PDR4.P44              4
PDR4.P43              3
PDR4.P42              2
PDR4.P41              1
PDR4.P40              0
PDR5                 0x000005   Port 5 data register
PDR5.P57              7
PDR5.P56              6
PDR5.P55              5
PDR5.P54              4
PDR5.P53              3
PDR5.P52              2
PDR5.P51              1
PDR5.P50              0
PDR6                 0x000006   Port 6 data register
PDR6.P63              3
PDR6.P62              2
PDR6.P61              1
PDR6.P60              0
DDR0                 0x000010   Port 0 direction register
DDR0.D07              7
DDR0.D06              6
DDR0.D05              5
DDR0.D04              4
DDR0.D03              3
DDR0.D02              2
DDR0.D01              1
DDR0.D00              0
DDR1                 0x000011   Port 1 direction register
DDR1.D17              7
DDR1.D16              6
DDR1.D15              5
DDR1.D14              4
DDR1.D13              3
DDR1.D12              2
DDR1.D11              1
DDR1.D10              0
DDR2                 0x000012   Port 2 direction register
DDR2.D27              7
DDR2.D26              6
DDR2.D25              5
DDR2.D24              4
DDR2.D23              3
DDR2.D22              2
DDR2.D21              1
DDR2.D20              0
DDR3                 0x000013   Port 3 direction register
DDR3.D37              7
DDR3.D36              6
DDR3.D35              5
DDR3.D34              4
DDR3.D33              3
DDR3.D32              2
DDR3.D31              1
DDR3.D30              0
DDR4                 0x000014   Port 4 direction register
DDR4.D46              6
DDR4.D45              5
DDR4.D44              4
DDR4.D43              3
DDR4.D42              2
DDR4.D41              1
DDR4.D40              0
DDR5                 0x000015   Port 5 direction register
DDR5.D57              7
DDR5.D56              6
DDR5.D55              5
DDR5.D54              4
DDR5.D53              3
DDR5.D52              2
DDR5.D51              1
DDR5.D50              0
DDR6                 0x000016   Port 6 direction register
DDR6.D63              3
DDR6.D62              2
DDR6.D61              1
DDR6.D60              0
ADER                 0x000017   Analog input enable register
ADER.ADE7             7
ADER.ADE6             6
ADER.ADE5             5
ADER.ADE4             4
ADER.ADE3             3
ADER.ADE2             2
ADER.ADE1             1
ADER.ADE0             0
SMR0                 0x000020   Mode register ch0
SMR0.MD1              7
SMR0.MD0              6
SMR0.CS2              5
SMR0.CS1              4
SMR0.CS0              3
SMR0.SCKE             1
SMR0.SOE              0
SCR0                 0x000021   Control register ch0
SCR0.PEN              7
SCR0.P                6
SCR0.SBL              5
SCR0.CL               4
SCR0.AD               3
SCR0.REC              2
SCR0.RXE              1
SCR0.TXE              0
SIDR0                0x000022   Input data register ch0
SIDR0.D7              7
SIDR0.D6              6
SIDR0.D5              5
SIDR0.D4              4
SIDR0.D3              3
SIDR0.D2              2
SIDR0.D1              1
SIDR0.D0              0
SSR0                 0x000023   Status register ch0
SSR0.PE               7
SSR0.ORE              6
SSR0.FRE              5
SSR0.RDRF             4
SSR0.TDRE             3
SSR0.BDS              2
SSR0.RIE              1
SSR0.TIE              0
SMR1                 0x000024   Mode register ch1
SMR1.MD1              7
SMR1.MD0              6
SMR1.CS2              5
SMR1.CS1              4
SMR1.CS0              3
SMR1.SCKE             1
SMR1.SOE              0
SCR1                 0x000025   Control register ch1
SCR1.PEN              7
SCR1.P                6
SCR1.SBL              5
SCR1.CL               4
SCR1.AD               3
SCR1.REC              2
SCR1.RXE              1
SCR1.TXE              0
SIDR1                0x000026   Input data register ch1
SIDR1.D7              7
SIDR1.D6              6
SIDR1.D5              5
SIDR1.D4              4
SIDR1.D3              3
SIDR1.D2              2
SIDR1.D1              1
SIDR1.D0              0
SSR1                 0x000027   Status register ch1
SSR1.PE               7
SSR1.ORE              6
SSR1.FRE              5
SSR1.RDRF             4
SSR1.TDRE             3
SSR1.BDS              2
SSR1.RIE              1
SSR1.TIE              0
CDCR0                0x000029   Communication prescaler control register ch0
CDCR0.MD              7
CDCR0.DIV3            3
CDCR0.DIV2            2
CDCR0.DIV1            1
CDCR0.DIV0            0
CDCR1                0x00002B   Communication prescaler control register ch1
CDCR1.MD              7
CDCR1.DIV3            3
CDCR1.DIV2            2
CDCR1.DIV1            1
CDCR1.DIV0            0
ENIR                 0x000030   DTP/external interrupt enable register
ENIR.EN7              7     
ENIR.EN6              6     
ENIR.EN5              5     
ENIR.EN4              4     
ENIR.EN3              3     
ENIR.EN2              2
ENIR.EN1              1
ENIR.EN0              0
EIRR                 0x000031   DTP/external interrupt request register
EIRR.ER7              7     
EIRR.ER6              6     
EIRR.ER5              5     
EIRR.ER4              4     
EIRR.ER3              3     
EIRR.ER2              2
EIRR.ER1              1
EIRR.ER0              0
ELVR                 0x000032   Request level setting register
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
ADCS0                0x000034   A/D control status register (lower)
ADCS0.MD1             7
ADCS0.MD0             6
ADCS0.ANS2            5
ADCS0.ANS1            4
ADCS0.ANS0            3
ADCS0.ANE2            2
ADCS0.ANE1            1
ADCS0.ANE0            0
ADCS1                0x000035   A/D control status register (upper)
ADCS1.BUSY            7
ADCS1.INT             6
ADCS1.INTE            5
ADCS1.PAUS            4
ADCS1.STS1            3
ADCS1.STS0            2
ADCS1.STRT0           1
ADCR01               0x000036   A/D data register
ADCR01.S10            15
ADCR01.ST1            14
ADCR01.ST0            13
ADCR01.CT1            12
ADCR01.CT0            11
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
PRL0_PRLL            0x000038   PPG reload register ch0 (lower)
PRL0_PRLH            0x000039   PPG reload register ch0 (upper)
PRL1_PRLL            0x00003A   PPG reload register ch1 (lower)
PRL1_PRLH            0x00003B   PPG reload register ch1 (upper)
PPGC01               0x00003C   PPG control register ch0
PPGC01.PEN1           15
PPGC01.SST1           14
PPGC01.POE1           13
PPGC01.PIE1           12
PPGC01.PUF1           11
PPGC01.MD01           10
PPGC01.MD00           9
PPGC01.PEN0           7
PPGC01.SST0           6
PPGC01.POE0           5
PPGC01.PIE0           4
PPGC01.PUF0           3
PPGC01.POS1           2
PPGC01.POS0           1
PCS01                0x00003E   PPG clock control register ch0, ch1
PCS01.PC12            7
PCS01.PC11            6
PCS01.PC10            5
PCS01.PC02            4
PCS01.PC01            3
PCS01.PC00            2
PRL2_PRLL            0x000040   PPG reload register ch2 (lower)
PRL2_PRLH            0x000041   PPG reload register ch2 (upper)
PRL3_PRLL            0x000042   PPG reload register ch3 (lower)
PRL3_PRLH            0x000043   PPG reload register ch3 (upper)
PPGC23               0x000044   PPG control register ch2
PPGC23.PEN1           15
PPGC23.SST1           14
PPGC23.POE1           13
PPGC23.PIE1           12
PPGC23.PUF1           11
PPGC23.MD01           10
PPGC23.MD00           9
PPGC23.PEN0           7
PPGC23.SST0           6
PPGC23.POE0           5
PPGC23.PIE0           4
PPGC23.PUF0           3
PPGC23.POS1           2
PPGC23.POS0           1
PCS23                0x000046   PPG clock control register ch2, ch3
PCS23.PC12            7
PCS23.PC11            6
PCS23.PC10            5
PCS23.PC02            4
PCS23.PC01            3
PCS23.PC00            2
PRL4_PRLL            0x000048   PPG reload register ch4 (lower)
PRL4_PRLH            0x000049   PPG reload register ch4 (upper)
PRL5_PRLL            0x00004A   PPG reload register ch5 (lower)
PRL5_PRLH            0x00004B   PPG reload register ch5 (upper)
PPGC45               0x00004C   PPG control register ch4
PPGC45.PEN1           15
PPGC45.SST1           14
PPGC45.POE1           13
PPGC45.PIE1           12
PPGC45.PUF1           11
PPGC45.MD01           10
PPGC45.MD00           9
PPGC45.PEN0           7
PPGC45.SST0           6
PPGC45.POE0           5
PPGC45.PIE0           4
PPGC45.PUF0           3
PPGC45.POS1           2
PPGC45.POS0           1
PCS45                0x00004E   PPG clock control register ch4, ch5
PCS45.PC12            7
PCS45.PC11            6
PCS45.PC10            5
PCS45.PC02            4
PCS45.PC01            3
PCS45.PC00            2
TMRR0                0x000050   8-bit reload register ch0
DTCR0                0x000051   8-bit timer control register ch0
DTCR0.DMOD            7
DTCR0.GTEN            6
DTCR0.PGEN            5
DTCR0.TMIF            4
DTCR0.TMIE            3
DTCR0.TMD2            2
DTCR0.TMD1            1
DTCR0.TMD0            0
TMRR1                0x000052   8-bit reload register ch1
DTCR1                0x000053   8-bit timer control register ch1
DTCR1.DMOD            7
DTCR1.GTEN            6
DTCR1.PGEN            5
DTCR1.TMIF            4
DTCR1.TMIE            3
DTCR1.TMD2            2
DTCR1.TMD1            1
DTCR1.TMD0            0
TMRR2                0x000054   8-bit reload register ch2
DTCR2                0x000055   8-bit timer control register ch2
DTCR2.DMOD            7
DTCR2.GTEN            6
DTCR2.PGEN            5
DTCR2.TMIF            4
DTCR2.TMIE            3
DTCR2.TMD2            2
DTCR2.TMD1            1
DTCR2.TMD0            0
SIGCR                0x000056   Waveform control register
SIGCR.DTIE            7
SIGCR.DTIL            6
SIGCR.NRSL            5
SIGCR.DCK2            4
SIGCR.DCK1            3
SIGCR.DCK0            2
SIGCR.PGS1            1
SIGCR.PGS0            0
CPCLR                0x000058   Compare clear register
TCDT                 0x00005A   Timer data register
TCCS                 0x00005C   Timer control/status register
TCCS.ECKE             15
TCCS.MSI2             12
TCCS.MSI1             11
TCCS.MSI0             10
TCCS.ICLR             9
TCCS.ICRE             8
TCCS.IVF              7
TCCS.IVFE             6
TCCS.STOP             5
TCCS.MODE             4
TCCS.SCLR             3
TCCS.CLK2             2
TCCS.CLK1             1
TCCS.CLK0             0
IPCP0                0x000060   Input capture data register ch0
IPCP1                0x000062   Input capture data register ch1
IPCP2                0x000064   Input capture data register ch2
IPCP3                0x000066   Input capture data register ch3
ICS01                0x000068   Input capture control register 01
ICS01.ICP1            7
ICS01.ICP0            6
ICS01.ICE1            5
ICS01.ICE0            4
ICS01.EG11            3 
ICS01.EG10            2
ICS01.EG01            1
ICS01.EG00            0
ICS23                0x00006A   Input capture control register 23
ICS23.ICP3            7
ICS23.ICP2            6
ICS23.ICE3            5
ICS23.ICE2            4
ICS23.EG31            3
ICS23.EG30            2
ICS23.EG21            1 
ICS23.EG20            0
ROMM                 0x00006F   ROM mirror function selection register
OCCP0                0x000070   Compare register ch0
OCCP1                0x000072   Compare register ch1
OCCP2                0x000074   Compare register ch2
OCCP3                0x000076   Compare register ch3
OCCP4                0x000078   Compare register ch4
OCCP5                0x00007A   Compare register ch5
OCS01                0x00007C   Compare control register ch0/1
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
OCS23                0x00007E   Compare control register ch2/3
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
OCS45                0x000080   Compare control register ch4/5
OCS45.CMOD            12
OCS45.OTE1            11
OCS45.OTE0            10
OCS45.OTD1            9
OCS45.OTD0            8
OCS45.ICP1            7
OCS45.ICP0            6
OCS45.ICE1            5
OCS45.ICE0            4
OCS45.CST1            1
OCS45.CST0            0
TMCSR0               0x000082   Timer control status register ch0
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
TMR0                 0x000084   16-bit timer register ch0
TMCSR1               0x000086   Timer control status register ch1
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
TMR1                 0x000088   16-bit timer register ch1
RDR0                 0x00008C   Port 0 pull-up resistor setting register
RDR0.RD07             7
RDR0.RD06             6
RDR0.RD05             5
RDR0.RD04             4
RDR0.RD03             3
RDR0.RD02             2
RDR0.RD01             1
RDR0.RD00             0
RDR1                 0x00008D   Port 1 pull-up resistor setting register
RDR1.RD17             7
RDR1.RD16             6
RDR1.RD15             5
RDR1.RD14             4
RDR1.RD13             3
RDR1.RD12             2
RDR1.RD11             1
RDR1.RD10             0
PACSR                0x00009E   Program address detection control status register
PACSR.AD1E            3
PACSR.AD1D            2
PACSR.AD0E            1
PACSR.AD0D            0
DIRR                 0x00009F   Delayed interrupt request/clear register
DIRR.R0               0
LPMCR                0x0000A0   Low power consumption mode register
LPMCR.STP             7
LPMCR.SLP             6
LPMCR.SPL             5
LPMCR.RST             4
LPMCR.CG1             2
LPMCR.CG0             1
CKSCR                0x0000A1   Clock selection register
CKSCR.SCM             7
CKSCR.MCM             6
CKSCR.WS1             5
CKSCR.WS0             4
CKSCR.SCS             3
CKSCR.MCS             2
CKSCR.CS1             1 
CKSCR.CS0             0
WDTC                 0x0000A8   Watchdog control register
WDTC.PONR             7
WDTC.WRST             5
WDTC.ERST             4
WDTC.SRST             3
TBTC                 0x0000A9   Timebase timer control register
TBTC.TBIE             4
TBTC.TBOF             3
TBTC.TBR              2
TBTC.TBC1             1
TBTC.TBC0             0
ICR00                0x0000B0   Interrupt control register 00
ICR00.S1              5
ICR00.S0              4
ICR00.ISE             3
ICR00.IL2             2
ICR00.IL1             1
ICR00.IL0             0
ICR01                0x0000B1   Interrupt control register 01
ICR01.S1              5
ICR01.S0              4
ICR01.ISE             3
ICR01.IL2             2
ICR01.IL1             1
ICR01.IL0             0
ICR02                0x0000B2   Interrupt control register 02
ICR02.S1              5
ICR02.S0              4
ICR02.ISE             3
ICR02.IL2             2
ICR02.IL1             1
ICR02.IL0             0
ICR03                0x0000B3   Interrupt control register 03
ICR03.S1              5
ICR03.S0              4
ICR03.ISE             3
ICR03.IL2             2
ICR03.IL1             1
ICR03.IL0             0
ICR04                0x0000B4   Interrupt control register 04
ICR04.S1              5
ICR04.S0              4
ICR04.ISE             3
ICR04.IL2             2
ICR04.IL1             1
ICR04.IL0             0
ICR05                0x0000B5   Interrupt control register 05
ICR05.S1              5
ICR05.S0              4
ICR05.ISE             3
ICR05.IL2             2
ICR05.IL1             1
ICR05.IL0             0
ICR06                0x0000B6   Interrupt control register 06
ICR06.S1              5
ICR06.S0              4
ICR06.ISE             3
ICR06.IL2             2
ICR06.IL1             1
ICR06.IL0             0
ICR07                0x0000B7   Interrupt control register 07
ICR07.S1              5
ICR07.S0              4
ICR07.ISE             3
ICR07.IL2             2
ICR07.IL1             1
ICR07.IL0             0
ICR08                0x0000B8   Interrupt control register 08
ICR08.S1              5
ICR08.S0              4
ICR08.ISE             3
ICR08.IL2             2
ICR08.IL1             1
ICR08.IL0             0
ICR09                0x0000B9   Interrupt control register 09
ICR09.S1              5
ICR09.S0              4
ICR09.ISE             3
ICR09.IL2             2
ICR09.IL1             1
ICR09.IL0             0
ICR10                0x0000BA   Interrupt control register 10
ICR10.S1              5
ICR10.S0              4
ICR10.ISE             3
ICR10.IL2             2
ICR10.IL1             1
ICR10.IL0             0
ICR11                0x0000BB   Interrupt control register 11
ICR11.S1              5
ICR11.S0              4
ICR11.ISE             3
ICR11.IL2             2
ICR11.IL1             1
ICR11.IL0             0
ICR12                0x0000BC   Interrupt control register 12
ICR12.S1              5
ICR12.S0              4
ICR12.ISE             3
ICR12.IL2             2
ICR12.IL1             1
ICR12.IL0             0
ICR13                0x0000BD   Interrupt control register 13
ICR13.S1              5
ICR13.S0              4
ICR13.ISE             3
ICR13.IL2             2
ICR13.IL1             1
ICR13.IL0             0
ICR14                0x0000BE   Interrupt control register 14
ICR14.S1              5
ICR14.S0              4
ICR14.ISE             3
ICR14.IL2             2
ICR14.IL1             1
ICR14.IL0             0
ICR15                0x0000BF   Interrupt control register 15
ICR15.S1              5
ICR15.S0              4
ICR15.ISE             3
ICR15.IL2             2
ICR15.IL1             1
ICR15.IL0             0


.MB90570
; DS07-13701-8E  http://edevice.fujitsu.com/fj/DATASHEET/e-ds/e713701.pdf
; MB90573/574/574C/F574/F574A/V570/V570A


; ROM: 128 kbytes (MB90573)
;      256 kbytes (MB90574/C/MB90F574/A)
; RAM:   6 kbytes (MB90573)
;       10 kbytes (MB90574/C/MB90F574/A/MB90V570/A)


; MEMORY MAP
; [MB90573]
area DATA FSR              0x000000:0x0000C0
area BSS  No_access_1      0x0000C0:0x000100
area DATA RAM              0x000100:0x001800
area BSS  No_access_2      0x001800:0x004000
area DATA R0M_1            0x004000:0x010000
area BSS  No_access_3      0x010000:0xFE0000
; area DATA ROM_2_BANK_FE    0xFE0000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000

; [MB90574/C/MB90F574/A]
; area DATA FSR              0x000000:0x0000C0
; area BSS  No_access_1      0x0000C0:0x000100
; area DATA RAM              0x000100:0x002900
; area BSS  No_access_2      0x002900:0x004000
; area DATA R0M_1            0x004000:0x010000
; area BSS  No_access_3      0x010000:0xFC0000
; area DATA ROM_2_BANK_FC    0xFC0000:0xFD0000
; area DATA ROM_2_BANK_FD    0xFD0000:0xFE0000
; area DATA ROM_2_BANK_FE    0xFE0000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000

; Interrupt and reset vector assignments
interrupt __RESET       0xFFFFDC   Reset 
interrupt INT9          0xFFFFD8   INT9 instruction 
interrupt EXCEPT        0xFFFFD4   Exception 
interrupt AD_CONV       0xFFFFD0   8/10-bit A/D converter 
interrupt IC0           0xFFFFCC   Input capture 0 (ICU) include 
interrupt DTP0          0xFFFFC8   DTP0 (external interrupt 0) 
interrupt IC1           0xFFFFC4   Input capture 1 (ICU) include 
interrupt OC0           0xFFFFC0   Output compare 0 (OCU) match 
interrupt OC1           0xFFFFBC   Output compare 1 (OCU) match 
interrupt OC2           0xFFFFB8   Output compare 2 (OCU) match 
interrupt OC3           0xFFFFB4   Output compare 3 (OCU) match 
interrupt IO_SI0        0xFFFFB0   Extended I/O serial interface 0 
interrupt F_TIMER       0xFFFFAC   16-bit free run timer 
interrupt IO_SI1        0xFFFFA8   Extended I/O serial interface 1 
interrupt C_TIMER       0xFFFFA4   Clock timer 
interrupt IO_SI2        0xFFFFA0   Extended I/O serial interface 2 
interrupt DTP1          0xFFFF9C   DTP1 (external interrupt 1) 
interrupt DTP2_DTP3     0xFFFF98   DTP2/DTP3 (external interrupt 2/external interrupt 3) 
interrupt PPG_TIMER_0C  0xFFFF94   8/16-bit PPG timer 0 counter borrow 
interrupt DTP4_DTP5     0xFFFF90   DTP4/DTP5 (external interrupt 4/external interrupt 5) 
interrupt PPG_TIMER_1C  0xFFFF8C   8/16-bit PPG timer 1 counter borrow 
interrupt UD_CT_0B      0xFFFF88   8/16-bit up/down counter/timer 0 borrow/overflow/inversion 
interrupt UD_CT_0C      0xFFFF84   8/16-bit up/down counter/timer 0 compare match 
interrupt UD_CT_1B      0xFFFF80   8/16-bit up/down counter/timer 1 borrow/overflow/inversion 
interrupt UD_CT_1C      0xFFFF7C   8/16-bit up/down counter/timer 1 compare match 
interrupt DTP6          0xFFFF78   DTP6 (external interrupt 6) 
interrupt T_TIMER       0xFFFF74   Timebase timer 
interrupt DTP7          0xFFFF70   DTP7 (external interrupt 7) 
interrupt I2C           0xFFFF6C   I2C interface 
interrupt UART1_R       0xFFFF68   UART1 (SCI) reception complete 
interrupt UART1_T       0xFFFF64   UART1 (SCI) transmission complete 
interrupt UART0_R       0xFFFF60   UART0 (SCI) reception complete 
interrupt UART0_T       0xFFFF5C   UART0 (SCI) transmission complete 
interrupt FLASH         0xFFFF58   Flash memory 
interrupt DELAY         0xFFFF54   Delayed interrupt generation module 


; INPUT/OUTPUT PORTS
PDR0                 0x000000   Port 0 data register
PDR0.P07              7
PDR0.P06              6
PDR0.P05              5
PDR0.P04              4
PDR0.P03              3
PDR0.P02              2
PDR0.P01              1
PDR0.P00              0
PDR1                 0x000001   Port 1 data register
PDR1.P17              7
PDR1.P16              6
PDR1.P15              5
PDR1.P14              4
PDR1.P13              3
PDR1.P12              2
PDR1.P11              1
PDR1.P10              0
PDR2                 0x000002   Port 2 data register
PDR2.P27              7
PDR2.P26              6
PDR2.P25              5
PDR2.P24              4
PDR2.P23              3
PDR2.P22              2
PDR2.P21              1
PDR2.P20              0
PDR3                 0x000003   Port 3 data register
PDR3.P37              7
PDR3.P36              6
PDR3.P35              5
PDR3.P34              4
PDR3.P33              3
PDR3.P32              2
PDR3.P31              1
PDR3.P30              0
PDR4                 0x000004   Port 4 data register
PDR4.P47              7
PDR4.P46              6
PDR4.P45              5
PDR4.P44              4
PDR4.P43              3
PDR4.P42              2
PDR4.P41              1
PDR4.P40              0
PDR5                 0x000005   Port 5 data register
PDR5.P57              7      
PDR5.P56              6
PDR5.P55              5
PDR5.P54              4
PDR5.P53              3
PDR5.P52              2
PDR5.P51              1
PDR5.P50              0
PDR6                 0x000006   Port 6 data register
PDR6.P67              7      
PDR6.P66              6
PDR6.P65              5
PDR6.P64              4
PDR6.P63              3
PDR6.P62              2
PDR6.P61              1
PDR6.P60              0
PDR7                 0x000007   Port 7 data register
PDR7.P74              4
PDR7.P73              3
PDR7.P72              2
PDR7.P71              1
PDR7.P70              0
PDR8                 0x000008   Port 8 data register
PDR8.P87              7      
PDR8.P86              6
PDR8.P85              5
PDR8.P84              4
PDR8.P83              3
PDR8.P82              2
PDR8.P81              1
PDR8.P80              0
PDR9                 0x000009   Port 9 data register
PDR9.P97              7      
PDR9.P96              6
PDR9.P95              5
PDR9.P94              4
PDR9.P93              3
PDR9.P92              2
PDR9.P91              1
PDR9.P90              0
PDRA                 0x00000A   Port A data register
PDRA.PA7              7
PDRA.PA6              6
PDRA.PA5              5
PDRA.PA4              4
PDRA.PA3              3
PDRA.PA2              2
PDRA.PA1              1
PDRA.PA0              0
PDRB                 0x00000B   Port B data register
PDRB.PB7              7
PDRB.PB6              6
PDRB.PB5              5
PDRB.PB4              4
PDRB.PB3              3
PDRB.PB2              2
PDRB.PB1              1
PDRB.PB0              0
PDRC                 0x00000C   Port C data register
PDRC.PC3              3
PDRC.PC2              2
PDRC.PC1              1
PDRC.PC0              0
DDR0                 0x000010   Port 0 direction register
DDR0.D07              7
DDR0.D06              6
DDR0.D05              5
DDR0.D04              4
DDR0.D03              3
DDR0.D02              2
DDR0.D01              1
DDR0.D00              0
DDR1                 0x000011   Port 1 direction register
DDR1.D17              7
DDR1.D16              6
DDR1.D15              5
DDR1.D14              4
DDR1.D13              3
DDR1.D12              2
DDR1.D11              1
DDR1.D10              0
DDR2                 0x000012   Port 2 direction register
DDR2.D27              7
DDR2.D26              6
DDR2.D25              5
DDR2.D24              4
DDR2.D23              3
DDR2.D22              2
DDR2.D21              1
DDR2.D20              0
DDR3                 0x000013   Port 3 direction register
DDR3.D37              7
DDR3.D36              6
DDR3.D35              5
DDR3.D34              4
DDR3.D33              3
DDR3.D32              2
DDR3.D31              1
DDR3.D30              0
DDR4                 0x000014   Port 4 direction register
DDR4.D47              7
DDR4.D46              6
DDR4.D45              5
DDR4.D44              4
DDR4.D43              3
DDR4.D42              2
DDR4.D41              1
DDR4.D40              0
DDR5                 0x000015   Port 5 direction register
DDR5.D57              7
DDR5.D56              6
DDR5.D55              5
DDR5.D54              4
DDR5.D53              3
DDR5.D52              2
DDR5.D51              1
DDR5.D50              0
DDR6                 0x000016   Port 6 direction register
DDR6.D67              7
DDR6.D66              6
DDR6.D65              5
DDR6.D64              4
DDR6.D63              3
DDR6.D62              2
DDR6.D61              1
DDR6.D60              0
DDR7                 0x000017   Port 7 direction register
DDR7.D74              4
DDR7.D73              3
DDR7.D72              2
DDR7.D71              1
DDR7.D70              0
DDR8                 0x000018   Port 8 direction register
DDR8.D87              7
DDR8.D86              6
DDR8.D85              5
DDR8.D84              4
DDR8.D83              3
DDR8.D82              2
DDR8.D81              1
DDR8.D80              0
DDR9                 0x000019   Port 9 direction register
DDR9.D97              7
DDR9.D96              6
DDR9.D95              5
DDR9.D94              4
DDR9.D93              3
DDR9.D92              2
DDR9.D91              1
DDR9.D90              0
DDRA                 0x00001A   Port A direction register
DDRA.DA7              7
DDRA.DA6              6
DDRA.DA5              5
DDRA.DA4              4
DDRA.DA3              3
DDRA.DA2              2
DDRA.DA1              1
DDRA.DA0              0
DDRB                 0x00001B   Port B direction register
DDRB.DB7              7
DDRB.DB6              6
DDRB.DB5              5
DDRB.DB4              4
DDRB.DB3              3
DDRB.DB2              2
DDRB.DB1              1
DDRB.DB0              0
DDRC                 0x00001C   Port C direction register
DDRC.DC3              3
DDRC.DC2              2
DDRC.DC1              1
DDRC.DC0              0
ODR4                 0x00001D   Port 4 output pin register
ODR4.OD47             7
ODR4.OD46             6
ODR4.OD45             5
ODR4.OD44             4
ODR4.OD43             3
ODR4.OD42             2
ODR4.OD41             1
ODR4.OD40             0
ADER                 0x00001E   Analog input enable register
ADER.ADE7             7
ADER.ADE6             6
ADER.ADE5             5
ADER.ADE4             4
ADER.ADE3             3
ADER.ADE2             2
ADER.ADE1             1
ADER.ADE0             0
SMR0                 0x000020   Serial mode register 0
SMR0.MD1              7
SMR0.MD0              6
SMR0.CS2              5
SMR0.CS1              4
SMR0.CS0              3
SMR0.SCKE             1
SMR0.SOE              0
SCR0                 0x000021   Serial control register 0
SCR0.PEN              7
SCR0.P                6
SCR0.SBL              5
SCR0.CL               4
SCR0.AD               3
SCR0.REC              2
SCR0.RXE              1
SCR0.TXE              0
SIDR0                0x000022   Serial input data register 0 / serial output data register 0
SIDR0.D7              7
SIDR0.D6              6
SIDR0.D5              5
SIDR0.D4              4
SIDR0.D3              3
SIDR0.D2              2
SIDR0.D1              1
SIDR0.D0              0
SSR0                 0x000023   Serial status register 0
SSR0.PE               7
SSR0.ORE              6
SSR0.FRE              5
SSR0.RDRF             4
SSR0.TDRE             3
SSR0.RIE              1
SSR0.TIE              0
SMR1                 0x000024   Serial mode register 1
SMR1.MD1              7
SMR1.MD0              6
SMR1.CS2              5
SMR1.CS1              4
SMR1.CS0              3
SMR1.SCKE             1
SMR1.SOE              0
SCR1                 0x000025   Serial control register 1
SCR1.PEN              7
SCR1.P                6
SCR1.SBL              5
SCR1.CL               4
SCR1.AD               3
SCR1.REC              2
SCR1.RXE              1
SCR1.TXE              0
SIDR1                0x000026   Serial input data register 1 / serial output data register 1
SIDR1.D7              7
SIDR1.D6              6
SIDR1.D5              5
SIDR1.D4              4
SIDR1.D3              3
SIDR1.D2              2
SIDR1.D1              1
SIDR1.D0              0
SSR1                 0x000027   Serial status register 1
SSR1.PE               7
SSR1.ORE              6
SSR1.FRE              5
SSR1.RDRF             4
SSR1.TDRE             3
SSR1.RIE              1
SSR1.TIE              0
CDCR0                0x000028   Communications prescaler control register 0
CDCR0.MD              7
CDCR0.DIV3            3
CDCR0.DIV2            2
CDCR0.DIV1            1
CDCR0.DIV0            0
CDCR1                0x00002A   Communications prescaler control register 1
CDCR1.MD              7
CDCR1.DIV3            3
CDCR1.DIV2            2
CDCR1.DIV1            1
CDCR1.DIV0            0
ENIR                 0x000030   DTP/interrupt enable register
ENIR.EN7              7     
ENIR.EN6              6     
ENIR.EN5              5     
ENIR.EN4              4     
ENIR.EN3              3     
ENIR.EN2              2
ENIR.EN1              1
ENIR.EN0              0
EIRR                 0x000031   DTP/interrupt factor register
EIRR.ER7              7     
EIRR.ER6              6     
EIRR.ER5              5     
EIRR.ER4              4     
EIRR.ER3              3     
EIRR.ER2              2
EIRR.ER1              1
EIRR.ER0              0
ELVR                 0x000032   Request level setting register
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
ADCS1                0x000036   A/D control status register lower digits
ADCS1.MD1             7
ADCS1.MD0             6
ADCS1.ANS2            5
ADCS1.ANS1            4
ADCS1.ANS0            3
ADCS1.ANE2            2
ADCS1.ANE1            1
ADCS1.ANE0            0
ADCS2                0x000037   A/D control status register upper digits
ADCS2.BUSY            7
ADCS2.INT             6
ADCS2.INTE            5
ADCS2.PAUS            4
ADCS2.STS1            3
ADCS2.STS0            2
ADCS2.STRT0           1
ADCR1                0x000038   A/D data register lower digits
ADCR2                0x000039   A/D data register upper digits
DADR0                0x00003A   D/A converter data register ch.0
DADR1                0x00003B   D/A converter data register ch.1
DACR0                0x00003C   D/A control register 0
DACR0.DAE0            0
DACR1                0x00003D   D/A control register 1
DACR1.DAE1            0
CLKR                 0x00003E   Clock output enable register
CLKR.CKEN             3
CLKR.FRQ2             2
CLKR.FRQ1             1
CLKR.FRQ0             0
IO_PRL0_PRLL         0x000040   PPG0 reload register L ch.0
IO_PRL0_PRLH         0x000041   PPG0 reload register H ch.0
IO_PRL1_PRLL         0x000042   PPG1 reload register L ch.1
IO_PRL1_PRLH         0x000043   PPG1 reload register H ch.1
PPGC01               0x000044   PPG0 operating mode control register ch.0/1
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
PPGOE                0x000046   PPG0 and 1 output control registers ch.0 and ch.1
PPGOE.PCS2            7
PPGOE.PCS1            6
PPGOE.PCS0            5
PPGOE.PCM2            4
PPGOE.PCM1            3
PPGOE.PCM0            2
SMCS0                0x000048   Serial mode control status register 0
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
SDR0                 0x00004A   Serial data register 0
SMCS1                0x00004C   Serial mode control status register 1
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
SDR1                 0x00004E   Serial data register 1
IPCP0                0x000050   ICU data register ch.0
IPCP1                0x000052   ICU data register ch.2
ICS01                0x000054   ICU control status register
ICS01.ICP1            7
ICS01.ICP0            6
ICS01.ICE1            5
ICS01.ICE0            4
ICS01.EG11            3 
ICS01.EG10            2
ICS01.EG01            1
ICS01.EG00            0
TCDT                 0x000056   Free run timer data register
TCCS                 0x000058   Free run timer control status register
TCCS.IVF              6
TCCS.IVFE             5
TCCS.STOP             4
TCCS.MODE             3
TCCS.CLR              2
TCCS.CLK1             1
TCCS.CLK0             0
OCCP0                0x00005A   OCU compare register ch.0
OCCP1                0x00005C   OCU compare register ch.1
OCCP2                0x00005E   OCU compare register ch.2
OCCP3                0x000060   OCU compare register ch.3
OCS01                0x000062   OCU control status register ch.0/1
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
OCS23                0x000064   OCU control status register ch.2/3
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
IBSR                 0x000068   I 2 C bus status register
IBSR.BB               7
IBSR.RSC              6
IBSR.AL               5
IBSR.LRB              4
IBSR.TRX              3
IBSR.AAS              2
IBSR.GCA              1
IBSR.FBT              0
IBCR                 0x000069   I 2 C bus control register
IBCR.BER              7
IBCR.BEIE             6
IBCR.SCC              5
IBCR.MSS              4
IBCR.ACK              3
IBCR.GCAA             2
IBCR.INTE             1
IBCR.INT              0
ICCR                 0x00006A   I 2 C bus clock control register
ICCR.EN               5
ICCR.CS4              4 
ICCR.CS3              3
ICCR.CS2              2
ICCR.CS1              1
ICCR.CS0              0
IADR                 0x00006B   I 2 C bus address register
IADR.A6               6
IADR.A5               5
IADR.A4               4
IADR.A3               3
IADR.A2               2
IADR.A1               1
IADR.A0               0
IDAR                 0x00006C   I 2 C bus data register
ROMM                 0x00006F   ROM mirroring function selection register
UDCR_UDCR0           0x000070   Up/down count register 0
UDCR_UDCR1           0x000071   Up/down count register 1
RCR                  0x000072   Reload compare register 0/1
CSR0                 0x000074   Counter status register 0
CSR0.CSTR             7
CSR0.CITE             6
CSR0.UDIE             5
CSR0.CMPF             4
CSR0.OVFF             3
CSR0.UDFF             2
CSR0.UDF1             1
CSR0.UDF0             0
CCR0                 0x000076   Counter control register 0
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
CSR1                 0x000078   Counter status register 1
CSR1.CSTR             7
CSR1.CITE             6
CSR1.UDIE             5
CSR1.CMPF             4
CSR1.OVFF             3
CSR1.UDFF             2
CSR1.UDF1             1
CSR1.UDF0             0
CCR1                 0x00007A   Counter control register 1
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
SMCS2                0x00007C   Serial mode control status register 2
SMCS2.SMD2            15
SMCS2.SMD1            14
SMCS2.SMD0            13
SMCS2.SIE             12
SMCS2.SIR             11
SMCS2.BUSY            10
SMCS2.STOP            9
SMCS2.STRT            8
SMCS2.MODE            3
SMCS2.BDS             2
SMCS2.SOE             1
SMCS2.SCOE            0
SDR2                 0x00007E   Serial data register 2
CSCR0                0x000080   Chip selection control register 0
CSCR0.ACTL            3
CSCR0.OPEL            2
CSCR0.CSA1            1
CSCR0.CSA0            0
CSCR1                0x000081   Chip selection control register 1
CSCR1.ACTL            3
CSCR1.OPEL            2
CSCR1.CSA1            1
CSCR1.CSA0            0
CSCR2                0x000082   Chip selection control register 2
CSCR2.ACTL            3
CSCR2.OPEL            2
CSCR2.CSA1            1
CSCR2.CSA0            0
CSCR3                0x000083   Chip selection control register 3
CSCR3.ACTL            3
CSCR3.OPEL            2
CSCR3.CSA1            1
CSCR3.CSA0            0
CSCR4                0x000084   Chip selection control register 4
CSCR4.ACTL            3
CSCR4.OPEL            2
CSCR4.CSA1            1
CSCR4.CSA0            0
CSCR5                0x000085   Chip selection control register 5
CSCR5.ACTL            3
CSCR5.OPEL            2
CSCR5.CSA1            1
CSCR5.CSA0            0
CSCR6                0x000086   Chip selection control register 6
CSCR6.ACTL            3
CSCR6.OPEL            2
CSCR6.CSA1            1
CSCR6.CSA0            0
CSCR7                0x000087   Chip selection control register 7
CSCR7.ACTL            3
CSCR7.OPEL            2
CSCR7.CSA1            1
CSCR7.CSA0            0
RDR0                 0x00008C   Port 0 input pull-up resistor setup register
RDR0.RD07             7
RDR0.RD06             6
RDR0.RD05             5
RDR0.RD04             4
RDR0.RD03             3
RDR0.RD02             2
RDR0.RD01             1
RDR0.RD00             0
RDR1                 0x00008D   Port 1 input pull-up resistor setup register
RDR1.RD17             7
RDR1.RD16             6
RDR1.RD15             5
RDR1.RD14             4
RDR1.RD13             3
RDR1.RD12             2
RDR1.RD11             1
RDR1.RD10             0
RDR6                 0x00008E   Port 6 input pull-up resistor setup register
RDR6.RD67             7
RDR6.RD66             6
RDR6.RD65             5
RDR6.RD64             4
RDR6.RD63             3
RDR6.RD62             2
RDR6.RD61             1
RDR6.RD60             0
PACSR                0x00009E   Program address detection control status register
PACSR.AD1E            3
PACSR.AD1D            2
PACSR.AD0E            1
PACSR.AD0D            0
DIRR                 0x00009F   Delayed interrupt factor generation/cancellation register
DIRR.R0               0
LPMCR                0x0000A0   Low-power consumption mode control register
LPMCR.STP             7
LPMCR.SLP             6
LPMCR.SPL             5
LPMCR.RST             4
LPMCR.TMD             3
LPMCR.CG1             2
LPMCR.CG0             1
LPMCR.SSR             0
CKSCR                0x0000A1   Clock select register
CKSCR.SCM             7
CKSCR.MCM             6
CKSCR.WS1             5
CKSCR.WS0             4
CKSCR.SCS             3
CKSCR.MCS             2
CKSCR.CS1             1 
CKSCR.CS0             0
ARSR                 0x0000A5   Automatic ready function select register
HACR                 0x0000A6   Upper address control register
ECSR                 0x0000A7   Bus control signal select register
WDTC                 0x0000A8   Watchdog timer control register
WDTC.PONR             7
WDTC.STBR             6
WDTC.WRST             5
WDTC.ERST             4
WDTC.SRST             3
TBTC                 0x0000A9   Timebase timer control register
TBTC.TBIE             4
TBTC.TBOF             3
TBTC.TBR              2
TBTC.TBC1             1
TBTC.TBC0             0
WTC                  0x0000AA   Clock timer control register
WTC.WDCS              7
WTC.SCE               6
WTC.WTIE              5
WTC.WTOF              4
WTC.WTR               3
WTC.WTC2              2
WTC.WTC1              1
WTC.WTC0              0
ICR00                0x0000B0   Interrupt control register 00
ICR00.S1              5
ICR00.S0              4
ICR00.ISE             3
ICR00.IL2             2
ICR00.IL1             1
ICR00.IL0             0
ICR01                0x0000B1   Interrupt control register 01
ICR01.S1              5
ICR01.S0              4
ICR01.ISE             3
ICR01.IL2             2
ICR01.IL1             1
ICR01.IL0             0
ICR02                0x0000B2   Interrupt control register 02
ICR02.S1              5
ICR02.S0              4
ICR02.ISE             3
ICR02.IL2             2
ICR02.IL1             1
ICR02.IL0             0
ICR03                0x0000B3   Interrupt control register 03
ICR03.S1              5
ICR03.S0              4
ICR03.ISE             3
ICR03.IL2             2
ICR03.IL1             1
ICR03.IL0             0
ICR04                0x0000B4   Interrupt control register 04
ICR04.S1              5
ICR04.S0              4
ICR04.ISE             3
ICR04.IL2             2
ICR04.IL1             1
ICR04.IL0             0
ICR05                0x0000B5   Interrupt control register 05
ICR05.S1              5
ICR05.S0              4
ICR05.ISE             3
ICR05.IL2             2
ICR05.IL1             1
ICR05.IL0             0
ICR06                0x0000B6   Interrupt control register 06
ICR06.S1              5
ICR06.S0              4
ICR06.ISE             3
ICR06.IL2             2
ICR06.IL1             1
ICR06.IL0             0
ICR07                0x0000B7   Interrupt control register 07
ICR07.S1              5
ICR07.S0              4
ICR07.ISE             3
ICR07.IL2             2
ICR07.IL1             1
ICR07.IL0             0
ICR08                0x0000B8   Interrupt control register 08
ICR08.S1              5
ICR08.S0              4
ICR08.ISE             3
ICR08.IL2             2
ICR08.IL1             1
ICR08.IL0             0
ICR09                0x0000B9   Interrupt control register 09
ICR09.S1              5
ICR09.S0              4
ICR09.ISE             3
ICR09.IL2             2
ICR09.IL1             1
ICR09.IL0             0
ICR10                0x0000BA   Interrupt control register 10
ICR10.S1              5
ICR10.S0              4
ICR10.ISE             3
ICR10.IL2             2
ICR10.IL1             1
ICR10.IL0             0
ICR11                0x0000BB   Interrupt control register 11
ICR11.S1              5
ICR11.S0              4
ICR11.ISE             3
ICR11.IL2             2
ICR11.IL1             1
ICR11.IL0             0
ICR12                0x0000BC   Interrupt control register 12
ICR12.S1              5
ICR12.S0              4
ICR12.ISE             3
ICR12.IL2             2
ICR12.IL1             1
ICR12.IL0             0
ICR13                0x0000BD   Interrupt control register 13
ICR13.S1              5
ICR13.S0              4
ICR13.ISE             3
ICR13.IL2             2
ICR13.IL1             1
ICR13.IL0             0
ICR14                0x0000BE   Interrupt control register 14
ICR14.S1              5
ICR14.S0              4
ICR14.ISE             3
ICR14.IL2             2
ICR14.IL1             1
ICR14.IL0             0
ICR15                0x0000BF   Interrupt control register 15
ICR15.S1              5
ICR15.S0              4
ICR15.ISE             3
ICR15.IL2             2
ICR15.IL1             1
ICR15.IL0             0


.MB90580
; DS07-13710-4E  http://edevice.fujitsu.com/fj/DATASHEET/e-ds/e713710.pdf
; MB90583C/583CA/F583C/F583CA/V580B


; ROM: 128 Kbytes (MB90583C/CA/MB90F583C/CA)
; RAM:   6 Kbytes (MB90583C/CA/MB90F583C/CA/MB90V580B)


; MEMORY MAP
area DATA FSR              0x000000:0x0000C0
area BSS  No_access_1      0x0000C0:0x000100
area DATA RAM              0x000100:0x001900
area BSS  No_access_2      0x001900:0x004000
area DATA ROM_1            0x004000:0x010000
area BSS  No_access_3      0x010000:0xFE0000
; area DATA ROM_2_BANK_FE    0xFE0000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000


; Interrupt and reset vector assignments
interrupt __RESET       0xFFFFDC   Reset 
interrupt INT9          0xFFFFD8   INT9 instruction 
interrupt EXCEPT        0xFFFFD4   Exception 
interrupt A_D_CONV      0xFFFFD0   A/D converter 
interrupt T_TIMER       0xFFFFCC   Timebase timer 
interrupt DTP0          0xFFFFC8   DTP0 (external interrupt 0) /UART3 reception complete 
interrupt DTP1          0xFFFFC4   DTP1 (external interrupt 1) /UART4 reception complete 
interrupt DTP2          0xFFFFC0   DTP2 (external interrupt 2) /UART3 transmission complete 
interrupt DTP3          0xFFFFBC   DTP3 (external interrupt 3) /UART4 transmission complete 
interrupt DTP4_7        0xFFFFB8   DTP4 to 7 (external interrupt 4 to 7) 
interrupt 0C_CH1        0xFFFFB4   Output compare (ch.1) match (I/O timer) 
interrupt UART2         0xFFFFB0   UART2 reception complete 
interrupt UART1         0xFFFFAC   UART1 reception complete 
interrupt IC_CH3        0xFFFFA8   Input capture (ch.3) include (I/O timer) 
interrupt IC_CH2        0xFFFFA4   Input capture (ch.2) include (I/O timer) 
interrupt IC_CH1        0xFFFFA0   Input capture (ch.1) include (I/O timer) 
interrupt IC_CH0        0xFFFF9C   Input capture (ch.0) include (I/O timer) 
interrupt PPG0          0xFFFF98   8/16 bit PPG0 counter borrow 
interrupt R_TIMER_20    0xFFFF94   16 bit reload timer 2 to 0 
interrupt CLOCK_P       0xFFFF90   Clock prescaler 
interrupt OC_CH0        0xFFFF8C   Output compare (ch.0) match (I/O timer) 
interrupt UART2_TC      0xFFFF88   UART2 transmission complete 
interrupt PWC_TIMER     0xFFFF84   PWC timer measurement complete / over flow 
interrupt UART1_T       0xFFFF80   UART1 transmission complete 
interrupt F_TIMER_O     0xFFFF7C   16-bit free run timer (I/O timer) over flow 
interrupt UART0_T       0xFFFF78   UART0 transmission complete 
interrupt PPG1          0xFFFF74   8/16 bit PPG1 counter borrow 
interrupt IEB_R         0xFFFF70   IEBus reception complete 
interrupt IEB_T         0xFFFF68   IEBus transmission start 
interrupt UART0_R       0xFFFF60   UART0 reception complete 
interrupt FLASH         0xFFFF58   Flash memory status 
interrupt DELAY         0xFFFF54   Delayed interrupt 


; INPUT/OUTPUT PORTS
PDR0                 0x000000   Port 0 data register
PDR0.P07              7
PDR0.P06              6
PDR0.P05              5
PDR0.P04              4
PDR0.P03              3
PDR0.P02              2
PDR0.P01              1
PDR0.P00              0
PDR1                 0x000001   Port 1 data register
PDR1.P17              7
PDR1.P16              6
PDR1.P15              5
PDR1.P14              4
PDR1.P13              3
PDR1.P12              2
PDR1.P11              1
PDR1.P10              0
PDR2                 0x000002   Port 2 data register
PDR2.P27              7
PDR2.P26              6
PDR2.P25              5
PDR2.P24              4
PDR2.P23              3
PDR2.P22              2
PDR2.P21              1
PDR2.P20              0
PDR3                 0x000003   Port 3 data register
PDR3.P37              7
PDR3.P36              6
PDR3.P35              5
PDR3.P34              4
PDR3.P33              3
PDR3.P32              2
PDR3.P31              1
PDR3.P30              0
PDR4                 0x000004   Port 4 data register
PDR4.P47              7
PDR4.P46              6
PDR4.P45              5
PDR4.P44              4
PDR4.P43              3
PDR4.P42              2
PDR4.P41              1
PDR4.P40              0
PDR5                 0x000005   Port 5 data register
PDR5.P57              7      
PDR5.P56              6
PDR5.P55              5
PDR5.P54              4
PDR5.P53              3
PDR5.P52              2
PDR5.P51              1
PDR5.P50              0
PDR6                 0x000006   Port 6 data register
PDR6.P67              7      
PDR6.P66              6
PDR6.P65              5
PDR6.P64              4
PDR6.P63              3
PDR6.P62              2
PDR6.P61              1
PDR6.P60              0
PDR7                 0x000007   Port 7 data register
PDR7.P74              4
PDR7.P73              3
PDR7.P72              2
PDR7.P71              1
PDR8                 0x000008   Port 8 data register
PDR8.P87              7      
PDR8.P86              6
PDR8.P85              5
PDR8.P84              4
PDR8.P83              3
PDR8.P82              2
PDR8.P81              1
PDR8.P80              0
PDR9                 0x000009   Port 9 data register
PDR9.P97              7      
PDR9.P96              6
PDR9.P95              5
PDR9.P94              4
PDR9.P93              3
PDR9.P92              2
PDR9.P91              1
PDR9.P90              0
PDRA                 0x00000A   Port A data register
PDRA.PA2              2
PDRA.PA1              1
PDRA.PA0              0
DDR0                 0x000010   Port 0 direction register
DDR0.D07              7
DDR0.D06              6
DDR0.D05              5
DDR0.D04              4
DDR0.D03              3
DDR0.D02              2
DDR0.D01              1
DDR0.D00              0
DDR1                 0x000011   Port 1 direction register
DDR1.D17              7
DDR1.D16              6
DDR1.D15              5
DDR1.D14              4
DDR1.D13              3
DDR1.D12              2
DDR1.D11              1
DDR1.D10              0
DDR2                 0x000012   Port 2 direction register
DDR2.D27              7
DDR2.D26              6
DDR2.D25              5
DDR2.D24              4
DDR2.D23              3
DDR2.D22              2
DDR2.D21              1
DDR2.D20              0
DDR3                 0x000013   Port 3 direction register
DDR3.D37              7
DDR3.D36              6
DDR3.D35              5
DDR3.D34              4
DDR3.D33              3
DDR3.D32              2
DDR3.D31              1
DDR3.D30              0
DDR4                 0x000014   Port 4 direction register
DDR4.D47              7
DDR4.D46              6
DDR4.D45              5
DDR4.D44              4
DDR4.D43              3
DDR4.D42              2
DDR4.D41              1
DDR4.D40              0
DDR5                 0x000015   Port 5 direction register
DDR5.D57              7
DDR5.D56              6
DDR5.D55              5
DDR5.D54              4
DDR5.D53              3
DDR5.D52              2
DDR5.D51              1
DDR5.D50              0
DDR6                 0x000016   Port 6 direction register
DDR6.D67              7
DDR6.D66              6
DDR6.D65              5
DDR6.D64              4
DDR6.D63              3
DDR6.D62              2
DDR6.D61              1
DDR6.D60              0
DDR7                 0x000017   Port 7 direction register
DDR7.P74              4
DDR7.P73              3
DDR7.P72              2
DDR7.P71              1
DDR8                 0x000018   Port 8 direction register
DDR8.D87              7
DDR8.D86              6
DDR8.D85              5
DDR8.D84              4
DDR8.D83              3
DDR8.D82              2
DDR8.D81              1
DDR8.D80              0
DDR9                 0x000019   Port 9 direction register
DDR9.D97              7
DDR9.D96              6
DDR9.D95              5
DDR9.D94              4
DDR9.D93              3
DDR9.D92              2
DDR9.D91              1
DDR9.D90              0
DDRA                 0x00001A   Port A direction register
DDRA.DA2              2
DDRA.DA1              1
DDRA.DA0              0
ODR4                 0x00001B   Port 4 output pin register
ODR4.OD47             7
ODR4.OD46             6
ODR4.OD45             5
ODR4.OD44             4
ODR4.OD43             3
ODR4.OD42             2
ODR4.OD41             1
ODR4.OD40             0
ADER                 0x00001C   Port 5 analog input enable register
ADER.ADE7             7
ADER.ADE6             6
ADER.ADE5             5
ADER.ADE4             4
ADER.ADE3             3
ADER.ADE2             2
ADER.ADE1             1
ADER.ADE0             0
SMR0                 0x000020   Serial mode register 0
SMR0.MD1              7
SMR0.MD0              6
SMR0.CS2              5
SMR0.CS1              4
SMR0.CS0              3
SMR0.SCKE             1
SMR0.SOE              0
SCR0                 0x000021   Serial control register 0
SCR0.PEN              7
SCR0.P                6
SCR0.SBL              5
SCR0.CL               4
SCR0.AD               3
SCR0.REC              2
SCR0.RXE              1
SCR0.TXE              0
SIDR0                0x000022   Serial input data register 0 / serial output data register 0
SIDR0.D7              7
SIDR0.D6              6
SIDR0.D5              5
SIDR0.D4              4
SIDR0.D3              3
SIDR0.D2              2
SIDR0.D1              1
SIDR0.D0              0
SSR0                 0x000023   Serial status register 0
SSR0.PE               7
SSR0.ORE              6
SSR0.FRE              5
SSR0.RDRF             4
SSR0.TDRE             3
SSR0.RIE              1
SSR0.TIE              0
SMR1                 0x000024   Serial mode register 1
SMR1.MD1              7
SMR1.MD0              6
SMR1.CS2              5
SMR1.CS1              4
SMR1.CS0              3
SMR1.SCKE             1
SMR1.SOE              0
SCR1                 0x000025   Serial control register 1
SCR1.PEN              7
SCR1.P                6
SCR1.SBL              5
SCR1.CL               4
SCR1.AD               3
SCR1.REC              2
SCR1.RXE              1
SCR1.TXE              0
SIDR1                0x000026   Serial input data register 1 / serial output data register 1
SIDR1.D7              7
SIDR1.D6              6
SIDR1.D5              5
SIDR1.D4              4
SIDR1.D3              3
SIDR1.D2              2
SIDR1.D1              1
SIDR1.D0              0
SSR1                 0x000027   Serial status register 1
SSR1.PE               7
SSR1.ORE              6
SSR1.FRE              5
SSR1.RDRF             4
SSR1.TDRE             3
SSR1.RIE              1
SSR1.TIE              0
SMR2                 0x000028   Serial mode register 2
SMR2.MD1              7
SMR2.MD0              6
SMR2.CS2              5
SMR2.CS1              4
SMR2.CS0              3
SMR2.SCKE             1
SMR2.SOE              0
SCR2                 0x000029   Serial control register 2
SCR2.PEN              7
SCR2.P                6
SCR2.SBL              5
SCR2.CL               4
SCR2.AD               3
SCR2.REC              2
SCR2.RXE              1
SCR2.TXE              0
SIDR2                0x00002A   Serial input data register 2 / serial output data register 2
SIDR2.D7              7
SIDR2.D6              6
SIDR2.D5              5
SIDR2.D4              4
SIDR2.D3              3
SIDR2.D2              2
SIDR2.D1              1
SIDR2.D0              0
SSR2                 0x00002B   Serial status register 2
SSR2.PE               7
SSR2.ORE              6
SSR2.FRE              5
SSR2.RDRF             4
SSR2.TDRE             3
SSR2.RIE              1
SSR2.TIE              0
CDCR0                0x00002C   Clock division control register 0
CDCR0.MD              7
CDCR0.DIV3            3
CDCR0.DIV2            2
CDCR0.DIV1            1
CDCR0.DIV0            0
CDCR1                0x00002E   Clock division control register 1
CDCR1.MD              7
CDCR1.DIV3            3
CDCR1.DIV2            2
CDCR1.DIV1            1
CDCR1.DIV0            0
ENIR                 0x000030   DTP/interrupt enable register
ENIR.EN7              7     
ENIR.EN6              6     
ENIR.EN5              5     
ENIR.EN4              4     
ENIR.EN3              3     
ENIR.EN2              2
ENIR.EN1              1
ENIR.EN0              0
EIRR                 0x000031   DTP/interrupt factor register
EIRR.ER7              7     
EIRR.ER6              6     
EIRR.ER5              5     
EIRR.ER4              4     
EIRR.ER3              3     
EIRR.ER2              2
EIRR.ER1              1
EIRR.ER0              0
ELVR                 0x000032   Request level setting register 
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
CDCR2                0x000034   Clock division control register 2
CDCR2.MD              7
CDCR2.DIV3            3
CDCR2.DIV2            2
CDCR2.DIV1            1
CDCR2.DIV0            0
ADCS1                0x000036   Control status register lower
ADCS1.MD1             7
ADCS1.MD0             6
ADCS1.ANS2            5
ADCS1.ANS1            4
ADCS1.ANS0            3
ADCS1.ANE2            2
ADCS1.ANE1            1
ADCS1.ANE0            0
ADCS2                0x000037   Control status register upper
ADCS2.BUSY            7
ADCS2.INT             6
ADCS2.INTE            5
ADCS2.PAUS            4
ADCS2.STS1            3
ADCS2.STS0            2
ADCS2.STRT0           1
ADCR1                0x000038   Data register lower
ADCR2                0x000039   Data register upper
DADR0                0x00003A   D/A converter data register 0
DADR1                0x00003B   D/A converter data register 1
DACR0                0x00003C   D/A control register 0
DACR0.DAE0            0
DACR1                0x00003D   D/A control register 1
DACR1.DAE1            0
CLKR                 0x00003E   Clock output enable register
CLKR.CKEN             3
CLKR.FRQ2             2
CLKR.FRQ1             1
CLKR.FRQ0             0
IO_PRL0_PRLL         0x000040   Reload register L (ch.0)
IO_PRL0_PRLH         0x000041   Reload register H (ch.0)
IO_PRL1_PRLL         0x000042   Reload register L (ch.1)
IO_PRL1_PRLH         0x000043   Reload register H (ch.1)
PPGC01               0x000044   PPG0 operating mode control register
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
PPGOE                0x000046   PPG0 and 1 operating output control registers
PPGOE.PCS2            7
PPGOE.PCS1            6
PPGOE.PCS0            5
PPGOE.PCM2            4
PPGOE.PCM1            3
PPGOE.PCM0            2
TMCSR0               0x000048   Timer control status register
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
TMR0                 0x00004A   16 bit timer register lower /16 bit reload register lower
TMCSR1               0x00004C   16 bit timer register / 16 bit reload register
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
TMR1                 0x00004E   16bit timer register / 16 bit reload register lower
TMCSR2               0x000050   Timer control status register
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
TMR2                 0x000052   16 bit timer register / 16 bit reload register
PWCSR                0x000054   PWC control status register
PWCSR.STRT            15
PWCSR.STOP            14
PWCSR.EDIR            13
PWCSR.EDIE            12
PWCSR.OVIR            11
PWCSR.OVIE            10
PWCSR.ERR             9
PWCSR.POUT            8
PWCSR.CSK1            7
PWCSR.CSK0            6
PWCSR.PIS1            5
PWCSR.PIS0            4
PWCSR.SC              3
PWCSR.MOD2            2
PWCSR.MOD1            1
PWCSR.MOD0            0
PWCR                 0x000056   PWC data buffer register
DIVR                 0x000058   Divide ratio control register
DIVR.DIV1             1 
DIVR.DIV0             0
OCCP0                0x00005A   Compare register ch.0
OCCP1                0x00005C   Compare register ch.1
OCS01                0x00005E   Compare control status register 0/1
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
IPCP0                0x000060   Input capture register ch.0
IPCP1                0x000062   Input capture register ch.1
IPCP2                0x000064   Input capture register ch.2
IPCP3                0x000066   Input capture register ch.3
ICS01                0x000068   Input capture control status register 01
ICS01.ICP1            7
ICS01.ICP0            6
ICS01.ICE1            5
ICS01.ICE0            4
ICS01.EG11            3 
ICS01.EG10            2
ICS01.EG01            1
ICS01.EG00            0
ICS23                0x00006A   Input capture control status register 23
ICS23.ICP1            7
ICS23.ICP0            6
ICS23.ICE1            5
ICS23.ICE0            4
ICS23.EG11            3 
ICS23.EG10            2
ICS23.EG01            1
ICS23.EG00            0
TCDT                 0x00006C   Timer data register
TCCS                 0x00006E   Timer control status register
TCCS.IVF              6
TCCS.IVFE             5
TCCS.STOP             4
TCCS.MODE             3
TCCS.CLR              2
TCCS.CLK1             1
TCCS.CLK0             0
ROMM                 0x00006F   ROM mirroring function selection register
MAW                  0x000070   Local-office address setting register
SAW                  0x000072   Slave address setting register
DEWR                 0x000074   Message length bit setting register
DCWR                 0x000075   Broadcast control bit setting register
DCWR.D3               7
DCWR.D2               6
DCWR.D1               5
DCWR.D0               4
DCWR.C3               3
DCWR.C2               2
DCWR.C1               1
DCWR.C0               0
CMR                  0x000076   Command register
CMR.MD1               15
CMR.MD0               14
CMR.PCOM              13
CMR.RIE               12
CMR.TIE               11
CMR.GOTM              10
CMR.GOTS              9
CMR.RXS               7
CMR.TXS               6
CMR.TIT1              5
CMR.TIT0              4
CMR.CS1               3
CMR.CS0               2
CMR.RDBC              1
CMR.WDBC              0
STR                  0x000078   Status register
STR.COM               15
STR.TE                14
STR.PEF               13
STR.ACK               12
STR.RIF               11
STR.TIF               10
STR.TSL               9
STR.EOD               8
STR.WDBF              7
STR.RDBF              6
STR.WDBE              5
STR.RDBE              4
STR.ST3               3
STR.ST2               2
STR.ST1               1
STR.ST0               0
LRR                  0x00007A   Lock read register
LRR.LOC               12        
LRR.LD11              11 
LRR.LD10              10 
LRR.LD9               9  
LRR.LD8               8  
LRR.LD7               7  
LRR.LD6               6  
LRR.LD5               5  
LRR.LD4               4  
LRR.LD3               3  
LRR.LD2               2  
LRR.LD1               1  
LRR.LD0               0
MAR                  0x00007C   Master address read register
DERR                 0x00007E   Message length bit read register
DCRR                 0x00007F   Broadcast control bit read register
DCRR.DO3              7
DCRR.DO2              6
DCRR.DO1              5
DCRR.DO0              4
DCRR.C3               3 
DCRR.C2               2
DCRR.C1               1
DCRR.C0               0
WDB                  0x000080   Write data buffer
RDB                  0x000081   Read data buffer
SMR3                 0x000082   Serial mode register 3
SMR3.MD1              7
SMR3.MD0              6
SMR3.CS2              5
SMR3.CS1              4
SMR3.CS0              3
SMR3.SCKE             1
SMR3.SOE              0
SCR3                 0x000083   Serial control register 3
SCR3.PEN              7
SCR3.P                6
SCR3.SBL              5
SCR3.CL               4
SCR3.AD               3
SCR3.REC              2
SCR3.RXE              1
SCR3.TXE              0
SIDR3                0x000084   Serial input register 3 / serial output register 3
SIDR3.D7              7
SIDR3.D6              6
SIDR3.D5              5
SIDR3.D4              4
SIDR3.D3              3
SIDR3.D2              2
SIDR3.D1              1
SIDR3.D0              0
SSR3                 0x000085   Serial status register 3
SSR3.PE               7
SSR3.ORE              6
SSR3.FRE              5
SSR3.RDRF             4
SSR3.TDRE             3
SSR3.RIE              1
SSR3.TIE              0
RNCR                 0x000086   PWC noise filter register
RNCR.EN               2
RNCR.SW1              1
RNCR.SW0              0
CDCR3                0x000087   Clock division control register 3
CDCR3.MD              7
CDCR3.DIV3            3
CDCR3.DIV2            2
CDCR3.DIV1            1
CDCR3.DIV0            0
SMR4                 0x000088   Serial mode register 4
SMR4.MD1              7
SMR4.MD0              6
SMR4.CS2              5
SMR4.CS1              4
SMR4.CS0              3
SMR4.SCKE             1
SMR4.SOE              0
SCR4                 0x000089   Serial control register 4
SCR4.PEN              7
SCR4.P                6
SCR4.SBL              5
SCR4.CL               4
SCR4.AD               3
SCR4.REC              2
SCR4.RXE              1
SCR4.TXE              0
SIDR4                0x00008A   Serial input register 4 / serial output register 4
SIDR4.D7              7
SIDR4.D6              6
SIDR4.D5              5
SIDR4.D4              4
SIDR4.D3              3
SIDR4.D2              2
SIDR4.D1              1
SIDR4.D0              0
SSR4                 0x00008B   Serial status register 4
SSR4.PE               7
SSR4.ORE              6
SSR4.FRE              5
SSR4.RDRF             4
SSR4.TDRE             3
SSR4.RIE              1
SSR4.TIE              0
RDR0                 0x00008C   Port 0 input pull-up resistor setup register
RDR0.RD07             7
RDR0.RD06             6
RDR0.RD05             5
RDR0.RD04             4
RDR0.RD03             3
RDR0.RD02             2
RDR0.RD01             1
RDR0.RD00             0
RDR1                 0x00008D   Port 1 input pull-up resistor setup register
RDR1.RD17             7
RDR1.RD16             6
RDR1.RD15             5
RDR1.RD14             4
RDR1.RD13             3
RDR1.RD12             2
RDR1.RD11             1
RDR1.RD10             0
RDR6                 0x00008E   Port 6 input pull-up resistor setup register
RDR6.RD67             7
RDR6.RD66             6
RDR6.RD65             5
RDR6.RD64             4
RDR6.RD63             3
RDR6.RD62             2
RDR6.RD61             1
RDR6.RD60             0
CDCR4                0x00008F   Clock division control register 4
CDCR4.MD              7
CDCR4.DIV3            3
CDCR4.DIV2            2
CDCR4.DIV1            1
CDCR4.DIV0            0
PACSR                0x00009E   Program address detection control/status register
PACSR.AD1E            3
PACSR.AD0E            1
DIRR                 0x00009F   Delayed interrupt generation/release register
DIRR.R0               0
LPMCR                0x0000A0   Low-power consumption mode control register
LPMCR.STP             7
LPMCR.SLP             6
LPMCR.SPL             5
LPMCR.RST             4
LPMCR.TMD             3
LPMCR.CG1             2
LPMCR.CG0             1
LPMCR.SSR             0
CKSCR                0x0000A1   Clock selection register
CKSCR.SCM             7
CKSCR.MCM             6
CKSCR.WS1             5
CKSCR.WS0             4
CKSCR.SCS             3
CKSCR.MCS             2
CKSCR.CS1             1 
CKSCR.CS0             0
ARSR                 0x0000A5   Auto-ready function selection register
HACR                 0x0000A6   External address output control  register
ECSR                 0x0000A7   Bus control signal selection register
WDTC                 0x0000A8   Watch dog timer control register
WDTC.PONR             7
WDTC.STBR             6
WDTC.WRST             5
WDTC.ERST             4
WDTC.SRST             3
TBTC                 0x0000A9   Time-base timer control register
TBTC.TBIE             4
TBTC.TBOF             3
TBTC.TBR              2
TBTC.TBC1             1
TBTC.TBC0             0
WTC                  0x0000AA   Clock timer control register
WTC.WDCS              7
WTC.SCE               6
WTC.WTIE              5
WTC.WTOF              4
WTC.WTR               3
WTC.WTC2              2
WTC.WTC1              1
WTC.WTC0              0
FMCS                 0x0000AE   Flash memory control status register
ICR00                0x0000B0   Interrupt control register 00
ICR00.S1              5
ICR00.S0              4
ICR00.ISE             3
ICR00.IL2             2
ICR00.IL1             1
ICR00.IL0             0
ICR01                0x0000B1   Interrupt control register 01
ICR01.S1              5
ICR01.S0              4
ICR01.ISE             3
ICR01.IL2             2
ICR01.IL1             1
ICR01.IL0             0
ICR02                0x0000B2   Interrupt control register 02
ICR02.S1              5
ICR02.S0              4
ICR02.ISE             3
ICR02.IL2             2
ICR02.IL1             1
ICR02.IL0             0
ICR03                0x0000B3   Interrupt control register 03
ICR03.S1              5
ICR03.S0              4
ICR03.ISE             3
ICR03.IL2             2
ICR03.IL1             1
ICR03.IL0             0
ICR04                0x0000B4   Interrupt control register 04
ICR04.S1              5
ICR04.S0              4
ICR04.ISE             3
ICR04.IL2             2
ICR04.IL1             1
ICR04.IL0             0
ICR05                0x0000B5   Interrupt control register 05
ICR05.S1              5
ICR05.S0              4
ICR05.ISE             3
ICR05.IL2             2
ICR05.IL1             1
ICR05.IL0             0
ICR06                0x0000B6   Interrupt control register 06
ICR06.S1              5
ICR06.S0              4
ICR06.ISE             3
ICR06.IL2             2
ICR06.IL1             1
ICR06.IL0             0
ICR07                0x0000B7   Interrupt control register 07
ICR07.S1              5
ICR07.S0              4
ICR07.ISE             3
ICR07.IL2             2
ICR07.IL1             1
ICR07.IL0             0
ICR08                0x0000B8   Interrupt control register 08
ICR08.S1              5
ICR08.S0              4
ICR08.ISE             3
ICR08.IL2             2
ICR08.IL1             1
ICR08.IL0             0
ICR09                0x0000B9   Interrupt control register 09
ICR09.S1              5
ICR09.S0              4
ICR09.ISE             3
ICR09.IL2             2
ICR09.IL1             1
ICR09.IL0             0
ICR10                0x0000BA   Interrupt control register 10
ICR10.S1              5
ICR10.S0              4
ICR10.ISE             3
ICR10.IL2             2
ICR10.IL1             1
ICR10.IL0             0
ICR11                0x0000BB   Interrupt control register 11
ICR11.S1              5
ICR11.S0              4
ICR11.ISE             3
ICR11.IL2             2
ICR11.IL1             1
ICR11.IL0             0
ICR12                0x0000BC   Interrupt control register 12
ICR12.S1              5
ICR12.S0              4
ICR12.ISE             3
ICR12.IL2             2
ICR12.IL1             1
ICR12.IL0             0
ICR13                0x0000BD   Interrupt control register 13
ICR13.S1              5
ICR13.S0              4
ICR13.ISE             3
ICR13.IL2             2
ICR13.IL1             1
ICR13.IL0             0
ICR14                0x0000BE   Interrupt control register 14
ICR14.S1              5
ICR14.S0              4
ICR14.ISE             3
ICR14.IL2             2
ICR14.IL1             1
ICR14.IL0             0
ICR15                0x0000BF   Interrupt control register 15
ICR15.S1              5
ICR15.S0              4
ICR15.ISE             3
ICR15.IL2             2
ICR15.IL1             1
ICR15.IL0             0


.MB90585
; DS07-13710-4E  http://edevice.fujitsu.com/fj/DATASHEET/e-ds/e713710.pdf
; MB90587C/587CA


; ROM:  64 Kbytes (MB90587C/CA)
; RAM:   4 Kbytes (MB90587C/CA)


; MEMORY MAP
area DATA FSR              0x000000:0x0000C0
area BSS  No_access_1      0x0000C0:0x000100
area DATA RAM              0x000100:0x001100
area BSS  No_access_2      0x001100:0x004000
area DATA ROM_1            0x004000:0x010000
area BSS  No_access_3      0x010000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000


; Interrupt and reset vector assignments
interrupt __RESET       0xFFFFDC   Reset 
interrupt INT9          0xFFFFD8   INT9 instruction 
interrupt EXCEPT        0xFFFFD4   Exception 
interrupt A_D_CONV      0xFFFFD0   A/D converter 
interrupt T_TIMER       0xFFFFCC   Timebase timer 
interrupt DTP0          0xFFFFC8   DTP0 (external interrupt 0) /UART3 reception complete 
interrupt DTP1          0xFFFFC4   DTP1 (external interrupt 1) /UART4 reception complete 
interrupt DTP2          0xFFFFC0   DTP2 (external interrupt 2) /UART3 transmission complete 
interrupt DTP3          0xFFFFBC   DTP3 (external interrupt 3) /UART4 transmission complete 
interrupt DTP4_7        0xFFFFB8   DTP4 to 7 (external interrupt 4 to 7) 
interrupt 0C_CH1        0xFFFFB4   Output compare (ch.1) match (I/O timer) 
interrupt UART2         0xFFFFB0   UART2 reception complete 
interrupt UART1         0xFFFFAC   UART1 reception complete 
interrupt IC_CH3        0xFFFFA8   Input capture (ch.3) include (I/O timer) 
interrupt IC_CH2        0xFFFFA4   Input capture (ch.2) include (I/O timer) 
interrupt IC_CH1        0xFFFFA0   Input capture (ch.1) include (I/O timer) 
interrupt IC_CH0        0xFFFF9C   Input capture (ch.0) include (I/O timer) 
interrupt PPG0          0xFFFF98   8/16 bit PPG0 counter borrow 
interrupt R_TIMER_20    0xFFFF94   16 bit reload timer 2 to 0 
interrupt CLOCK_P       0xFFFF90   Clock prescaler 
interrupt OC_CH0        0xFFFF8C   Output compare (ch.0) match (I/O timer) 
interrupt UART2_T       0xFFFF88   UART2 transmission complete 
interrupt PWC_TIMER     0xFFFF84   PWC timer measurement complete / over flow 
interrupt UART1_T       0xFFFF80   UART1 transmission complete 
interrupt F_TIMER_O     0xFFFF7C   16-bit free run timer (I/O timer) over flow 
interrupt UART0_T       0xFFFF78   UART0 transmission complete 
interrupt PPG1          0xFFFF74   8/16 bit PPG1 counter borrow 
interrupt IEB_R         0xFFFF70   IEBus reception complete 
interrupt IEB_T         0xFFFF68   IEBus transmission start 
interrupt UART0_R       0xFFFF60   UART0 reception complete 
interrupt FLASH         0xFFFF58   Flash memory status 
interrupt DELAY         0xFFFF54   Delayed interrupt 


; INPUT/OUTPUT PORTS
PDR0                 0x000000   Port 0 data register
PDR0.P07              7
PDR0.P06              6
PDR0.P05              5
PDR0.P04              4
PDR0.P03              3
PDR0.P02              2
PDR0.P01              1
PDR0.P00              0
PDR1                 0x000001   Port 1 data register
PDR1.P17              7
PDR1.P16              6
PDR1.P15              5
PDR1.P14              4
PDR1.P13              3
PDR1.P12              2
PDR1.P11              1
PDR1.P10              0
PDR2                 0x000002   Port 2 data register
PDR2.P27              7
PDR2.P26              6
PDR2.P25              5
PDR2.P24              4
PDR2.P23              3
PDR2.P22              2
PDR2.P21              1
PDR2.P20              0
PDR3                 0x000003   Port 3 data register
PDR3.P37              7
PDR3.P36              6
PDR3.P35              5
PDR3.P34              4
PDR3.P33              3
PDR3.P32              2
PDR3.P31              1
PDR3.P30              0
PDR4                 0x000004   Port 4 data register
PDR4.P47              7
PDR4.P46              6
PDR4.P45              5
PDR4.P44              4
PDR4.P43              3
PDR4.P42              2
PDR4.P41              1
PDR4.P40              0
PDR5                 0x000005   Port 5 data register
PDR5.P57              7      
PDR5.P56              6
PDR5.P55              5
PDR5.P54              4
PDR5.P53              3
PDR5.P52              2
PDR5.P51              1
PDR5.P50              0
PDR6                 0x000006   Port 6 data register
PDR6.P67              7      
PDR6.P66              6
PDR6.P65              5
PDR6.P64              4
PDR6.P63              3
PDR6.P62              2
PDR6.P61              1
PDR6.P60              0
PDR7                 0x000007   Port 7 data register
PDR7.P74              4
PDR7.P73              3
PDR7.P72              2
PDR7.P71              1
PDR8                 0x000008   Port 8 data register
PDR8.P87              7      
PDR8.P86              6
PDR8.P85              5
PDR8.P84              4
PDR8.P83              3
PDR8.P82              2
PDR8.P81              1
PDR8.P80              0
PDR9                 0x000009   Port 9 data register
PDR9.P97              7      
PDR9.P96              6
PDR9.P95              5
PDR9.P94              4
PDR9.P93              3
PDR9.P92              2
PDR9.P91              1
PDR9.P90              0
PDRA                 0x00000A   Port A data register
PDRA.PA2              2
PDRA.PA1              1
PDRA.PA0              0
DDR0                 0x000010   Port 0 direction register
DDR0.D07              7
DDR0.D06              6
DDR0.D05              5
DDR0.D04              4
DDR0.D03              3
DDR0.D02              2
DDR0.D01              1
DDR0.D00              0
DDR1                 0x000011   Port 1 direction register
DDR1.D17              7
DDR1.D16              6
DDR1.D15              5
DDR1.D14              4
DDR1.D13              3
DDR1.D12              2
DDR1.D11              1
DDR1.D10              0
DDR2                 0x000012   Port 2 direction register
DDR2.D27              7
DDR2.D26              6
DDR2.D25              5
DDR2.D24              4
DDR2.D23              3
DDR2.D22              2
DDR2.D21              1
DDR2.D20              0
DDR3                 0x000013   Port 3 direction register
DDR3.D37              7
DDR3.D36              6
DDR3.D35              5
DDR3.D34              4
DDR3.D33              3
DDR3.D32              2
DDR3.D31              1
DDR3.D30              0
DDR4                 0x000014   Port 4 direction register
DDR4.D47              7
DDR4.D46              6
DDR4.D45              5
DDR4.D44              4
DDR4.D43              3
DDR4.D42              2
DDR4.D41              1
DDR4.D40              0
DDR5                 0x000015   Port 5 direction register
DDR5.D57              7
DDR5.D56              6
DDR5.D55              5
DDR5.D54              4
DDR5.D53              3
DDR5.D52              2
DDR5.D51              1
DDR5.D50              0
DDR6                 0x000016   Port 6 direction register
DDR6.D67              7
DDR6.D66              6
DDR6.D65              5
DDR6.D64              4
DDR6.D63              3
DDR6.D62              2
DDR6.D61              1
DDR6.D60              0
DDR7                 0x000017   Port 7 direction register
DDR7.P74              4
DDR7.P73              3
DDR7.P72              2
DDR7.P71              1
DDR8                 0x000018   Port 8 direction register
DDR8.D87              7
DDR8.D86              6
DDR8.D85              5
DDR8.D84              4
DDR8.D83              3
DDR8.D82              2
DDR8.D81              1
DDR8.D80              0
DDR9                 0x000019   Port 9 direction register
DDR9.D97              7
DDR9.D96              6
DDR9.D95              5
DDR9.D94              4
DDR9.D93              3
DDR9.D92              2
DDR9.D91              1
DDR9.D90              0
DDRA                 0x00001A   Port A direction register
DDRA.DA2              2
DDRA.DA1              1
DDRA.DA0              0
ODR4                 0x00001B   Port 4 output pin register
ODR4.OD47             7
ODR4.OD46             6
ODR4.OD45             5
ODR4.OD44             4
ODR4.OD43             3
ODR4.OD42             2
ODR4.OD41             1
ODR4.OD40             0
ADER                 0x00001C   Port 5 analog input enable register
ADER.ADE7             7
ADER.ADE6             6
ADER.ADE5             5
ADER.ADE4             4
ADER.ADE3             3
ADER.ADE2             2
ADER.ADE1             1
ADER.ADE0             0
SMR0                 0x000020   Serial mode register 0
SMR0.MD1              7
SMR0.MD0              6
SMR0.CS2              5
SMR0.CS1              4
SMR0.CS0              3
SMR0.SCKE             1
SMR0.SOE              0
SCR0                 0x000021   Serial control register 0
SCR0.PEN              7
SCR0.P                6
SCR0.SBL              5
SCR0.CL               4
SCR0.AD               3
SCR0.REC              2
SCR0.RXE              1
SCR0.TXE              0
SIDR0                0x000022   Serial input data register 0 / serial output data register 0
SIDR0.D7              7
SIDR0.D6              6
SIDR0.D5              5
SIDR0.D4              4
SIDR0.D3              3
SIDR0.D2              2
SIDR0.D1              1
SIDR0.D0              0
SSR0                 0x000023   Serial status register 0
SSR0.PE               7
SSR0.ORE              6
SSR0.FRE              5
SSR0.RDRF             4
SSR0.TDRE             3
SSR0.RIE              1
SSR0.TIE              0
SMR1                 0x000024   Serial mode register 1
SMR1.MD1              7
SMR1.MD0              6
SMR1.CS2              5
SMR1.CS1              4
SMR1.CS0              3
SMR1.SCKE             1
SMR1.SOE              0
SCR1                 0x000025   Serial control register 1
SCR1.PEN              7
SCR1.P                6
SCR1.SBL              5
SCR1.CL               4
SCR1.AD               3
SCR1.REC              2
SCR1.RXE              1
SCR1.TXE              0
SIDR1                0x000026   Serial input data register 1 / serial output data register 1
SIDR1.D7              7
SIDR1.D6              6
SIDR1.D5              5
SIDR1.D4              4
SIDR1.D3              3
SIDR1.D2              2
SIDR1.D1              1
SIDR1.D0              0
SSR1                 0x000027   Serial status register 1
SSR1.PE               7
SSR1.ORE              6
SSR1.FRE              5
SSR1.RDRF             4
SSR1.TDRE             3
SSR1.RIE              1
SSR1.TIE              0
SMR2                 0x000028   Serial mode register 2
SMR2.MD1              7
SMR2.MD0              6
SMR2.CS2              5
SMR2.CS1              4
SMR2.CS0              3
SMR2.SCKE             1
SMR2.SOE              0
SCR2                 0x000029   Serial control register 2
SCR2.PEN              7
SCR2.P                6
SCR2.SBL              5
SCR2.CL               4
SCR2.AD               3
SCR2.REC              2
SCR2.RXE              1
SCR2.TXE              0
SIDR2                0x00002A   Serial input data register 2 / serial output data register 2
SIDR2.D7              7
SIDR2.D6              6
SIDR2.D5              5
SIDR2.D4              4
SIDR2.D3              3
SIDR2.D2              2
SIDR2.D1              1
SIDR2.D0              0
SSR2                 0x00002B   Serial status register 2
SSR2.PE               7
SSR2.ORE              6
SSR2.FRE              5
SSR2.RDRF             4
SSR2.TDRE             3
SSR2.RIE              1
SSR2.TIE              0
CDCR0                0x00002C   Clock division control register 0
CDCR0.MD              7
CDCR0.DIV3            3
CDCR0.DIV2            2
CDCR0.DIV1            1
CDCR0.DIV0            0
CDCR1                0x00002E   Clock division control register 1
CDCR1.MD              7
CDCR1.DIV3            3
CDCR1.DIV2            2
CDCR1.DIV1            1
CDCR1.DIV0            0
ENIR                 0x000030   DTP/interrupt enable register
ENIR.EN7              7     
ENIR.EN6              6     
ENIR.EN5              5     
ENIR.EN4              4     
ENIR.EN3              3     
ENIR.EN2              2
ENIR.EN1              1
ENIR.EN0              0
EIRR                 0x000031   DTP/interrupt factor register
EIRR.ER7              7     
EIRR.ER6              6     
EIRR.ER5              5     
EIRR.ER4              4     
EIRR.ER3              3     
EIRR.ER2              2
EIRR.ER1              1
EIRR.ER0              0
ELVR                 0x000032   Request level setting register 
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
CDCR2                0x000034   Clock division control register 2
CDCR2.MD              7
CDCR2.DIV3            3
CDCR2.DIV2            2
CDCR2.DIV1            1
CDCR2.DIV0            0
ADCS1                0x000036   Control status register lower
ADCS1.MD1             7
ADCS1.MD0             6
ADCS1.ANS2            5
ADCS1.ANS1            4
ADCS1.ANS0            3
ADCS1.ANE2            2
ADCS1.ANE1            1
ADCS1.ANE0            0
ADCS2                0x000037   Control status register upper
ADCS2.BUSY            7
ADCS2.INT             6
ADCS2.INTE            5
ADCS2.PAUS            4
ADCS2.STS1            3
ADCS2.STS0            2
ADCS2.STRT0           1
ADCR1                0x000038   Data register lower
ADCR2                0x000039   Data register upper
DADR0                0x00003A   D/A converter data register 0
DADR1                0x00003B   D/A converter data register 1
DACR0                0x00003C   D/A control register 0
DACR0.DAE0            0
DACR1                0x00003D   D/A control register 1
DACR1.DAE1            0
CLKR                 0x00003E   Clock output enable register
CLKR.CKEN             3
CLKR.FRQ2             2
CLKR.FRQ1             1
CLKR.FRQ0             0
IO_PRL0_PRLL         0x000040   Reload register L (ch.0)
IO_PRL0_PRLH         0x000041   Reload register H (ch.0)
IO_PRL1_PRLL         0x000042   Reload register L (ch.1)
IO_PRL1_PRLH         0x000043   Reload register H (ch.1)
PPGC01               0x000044   PPG0 operating mode control register
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
PPGOE                0x000046   PPG0 and 1 operating output control registers
PPGOE.PCS2            7
PPGOE.PCS1            6
PPGOE.PCS0            5
PPGOE.PCM2            4
PPGOE.PCM1            3
PPGOE.PCM0            2
TMCSR0               0x000048   Timer control status register
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
TMR0                 0x00004A   16 bit timer register lower /16 bit reload register lower
TMCSR1               0x00004C   16 bit timer register / 16 bit reload register
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
TMR1                 0x00004E   16bit timer register / 16 bit reload register lower
TMCSR2               0x000050   Timer control status register
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
TMR2                 0x000052   16 bit timer register / 16 bit reload register
PWCSR                0x000054   PWC control status register
PWCSR.STRT            15
PWCSR.STOP            14
PWCSR.EDIR            13
PWCSR.EDIE            12
PWCSR.OVIR            11
PWCSR.OVIE            10
PWCSR.ERR             9
PWCSR.POUT            8
PWCSR.CSK1            7
PWCSR.CSK0            6
PWCSR.PIS1            5
PWCSR.PIS0            4
PWCSR.SC              3
PWCSR.MOD2            2
PWCSR.MOD1            1
PWCSR.MOD0            0
PWCR                 0x000056   PWC data buffer register
DIVR                 0x000058   Divide ratio control register
DIVR.DIV1             1 
DIVR.DIV0             0
OCCP0                0x00005A   Compare register ch.0
OCCP1                0x00005C   Compare register ch.1
OCS01                0x00005E   Compare control status register 0/1
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
IPCP0                0x000060   Input capture register ch.0
IPCP1                0x000062   Input capture register ch.1
IPCP2                0x000064   Input capture register ch.2
IPCP3                0x000066   Input capture register ch.3
ICS01                0x000068   Input capture control status register 01
ICS01.ICP1            7
ICS01.ICP0            6
ICS01.ICE1            5
ICS01.ICE0            4
ICS01.EG11            3 
ICS01.EG10            2
ICS01.EG01            1
ICS01.EG00            0
ICS23                0x00006A   Input capture control status register 23
ICS23.ICP1            7
ICS23.ICP0            6
ICS23.ICE1            5
ICS23.ICE0            4
ICS23.EG11            3 
ICS23.EG10            2
ICS23.EG01            1
ICS23.EG00            0
TCDT                 0x00006C   Timer data register
TCCS                 0x00006E   Timer control status register
TCCS.IVF              6
TCCS.IVFE             5
TCCS.STOP             4
TCCS.MODE             3
TCCS.CLR              2
TCCS.CLK1             1
TCCS.CLK0             0
ROMM                 0x00006F   ROM mirroring function selection register
MAW                  0x000070   Local-office address setting register
SAW                  0x000072   Slave address setting register
DEWR                 0x000074   Message length bit setting register
DCWR                 0x000075   Broadcast control bit setting register
DCWR.D3               7
DCWR.D2               6
DCWR.D1               5
DCWR.D0               4
DCWR.C3               3
DCWR.C2               2
DCWR.C1               1
DCWR.C0               0
CMR                  0x000076   Command register
CMR.MD1               15
CMR.MD0               14
CMR.PCOM              13
CMR.RIE               12
CMR.TIE               11
CMR.GOTM              10
CMR.GOTS              9
CMR.RXS               7
CMR.TXS               6
CMR.TIT1              5
CMR.TIT0              4
CMR.CS1               3
CMR.CS0               2
CMR.RDBC              1
CMR.WDBC              0
STR                  0x000078   Status register
STR.COM               15
STR.TE                14
STR.PEF               13
STR.ACK               12
STR.RIF               11
STR.TIF               10
STR.TSL               9
STR.EOD               8
STR.WDBF              7
STR.RDBF              6
STR.WDBE              5
STR.RDBE              4
STR.ST3               3
STR.ST2               2
STR.ST1               1
STR.ST0               0
LRR                  0x00007A   Lock read register
LRR.LOC               12        
LRR.LD11              11 
LRR.LD10              10 
LRR.LD9               9  
LRR.LD8               8  
LRR.LD7               7  
LRR.LD6               6  
LRR.LD5               5  
LRR.LD4               4  
LRR.LD3               3  
LRR.LD2               2  
LRR.LD1               1  
LRR.LD0               0
MAR                  0x00007C   Master address read register
DERR                 0x00007E   Message length bit read register
DCRR                 0x00007F   Broadcast control bit read register
DCRR.DO3              7
DCRR.DO2              6
DCRR.DO1              5
DCRR.DO0              4
DCRR.C3               3 
DCRR.C2               2
DCRR.C1               1
DCRR.C0               0
WDB                  0x000080   Write data buffer
RDB                  0x000081   Read data buffer
SMR3                 0x000082   Serial mode register 3
SMR3.MD1              7
SMR3.MD0              6
SMR3.CS2              5
SMR3.CS1              4
SMR3.CS0              3
SMR3.SCKE             1
SMR3.SOE              0
SCR3                 0x000083   Serial control register 3
SCR3.PEN              7
SCR3.P                6
SCR3.SBL              5
SCR3.CL               4
SCR3.AD               3
SCR3.REC              2
SCR3.RXE              1
SCR3.TXE              0
SIDR3                0x000084   Serial input register 3 / serial output register 3
SIDR3.D7              7
SIDR3.D6              6
SIDR3.D5              5
SIDR3.D4              4
SIDR3.D3              3
SIDR3.D2              2
SIDR3.D1              1
SIDR3.D0              0
SSR3                 0x000085   Serial status register 3
SSR3.PE               7
SSR3.ORE              6
SSR3.FRE              5
SSR3.RDRF             4
SSR3.TDRE             3
SSR3.RIE              1
SSR3.TIE              0
RNCR                 0x000086   PWC noise filter register
RNCR.EN               2
RNCR.SW1              1
RNCR.SW0              0
CDCR3                0x000087   Clock division control register 3
CDCR3.MD              7
CDCR3.DIV3            3
CDCR3.DIV2            2
CDCR3.DIV1            1
CDCR3.DIV0            0
SMR4                 0x000088   Serial mode register 4
SMR4.MD1              7
SMR4.MD0              6
SMR4.CS2              5
SMR4.CS1              4
SMR4.CS0              3
SMR4.SCKE             1
SMR4.SOE              0
SCR4                 0x000089   Serial control register 4
SCR4.PEN              7
SCR4.P                6
SCR4.SBL              5
SCR4.CL               4
SCR4.AD               3
SCR4.REC              2
SCR4.RXE              1
SCR4.TXE              0
SIDR4                0x00008A   Serial input register 4 / serial output register 4
SIDR4.D7              7
SIDR4.D6              6
SIDR4.D5              5
SIDR4.D4              4
SIDR4.D3              3
SIDR4.D2              2
SIDR4.D1              1
SIDR4.D0              0
SSR4                 0x00008B   Serial status register 4
SSR4.PE               7
SSR4.ORE              6
SSR4.FRE              5
SSR4.RDRF             4
SSR4.TDRE             3
SSR4.RIE              1
SSR4.TIE              0
RDR0                 0x00008C   Port 0 input pull-up resistor setup register
RDR0.RD07             7
RDR0.RD06             6
RDR0.RD05             5
RDR0.RD04             4
RDR0.RD03             3
RDR0.RD02             2
RDR0.RD01             1
RDR0.RD00             0
RDR1                 0x00008D   Port 1 input pull-up resistor setup register
RDR1.RD17             7
RDR1.RD16             6
RDR1.RD15             5
RDR1.RD14             4
RDR1.RD13             3
RDR1.RD12             2
RDR1.RD11             1
RDR1.RD10             0
RDR6                 0x00008E   Port 6 input pull-up resistor setup register
RDR6.RD67             7
RDR6.RD66             6
RDR6.RD65             5
RDR6.RD64             4
RDR6.RD63             3
RDR6.RD62             2
RDR6.RD61             1
RDR6.RD60             0
CDCR4                0x00008F   Clock division control register 4
CDCR4.MD              7
CDCR4.DIV3            3
CDCR4.DIV2            2
CDCR4.DIV1            1
CDCR4.DIV0            0
PACSR                0x00009E   Program address detection control/status register
PACSR.AD1E            3
PACSR.AD0E            1
DIRR                 0x00009F   Delayed interrupt generation/release register
DIRR.R0               0
LPMCR                0x0000A0   Low-power consumption mode control register
LPMCR.STP             7
LPMCR.SLP             6
LPMCR.SPL             5
LPMCR.RST             4
LPMCR.TMD             3
LPMCR.CG1             2
LPMCR.CG0             1
LPMCR.SSR             0
CKSCR                0x0000A1   Clock selection register
CKSCR.SCM             7
CKSCR.MCM             6
CKSCR.WS1             5
CKSCR.WS0             4
CKSCR.SCS             3
CKSCR.MCS             2
CKSCR.CS1             1 
CKSCR.CS0             0
ARSR                 0x0000A5   Auto-ready function selection register
HACR                 0x0000A6   External address output control  register
ECSR                 0x0000A7   Bus control signal selection register
WDTC                 0x0000A8   Watch dog timer control register
WDTC.PONR             7
WDTC.STBR             6
WDTC.WRST             5
WDTC.ERST             4
WDTC.SRST             3
TBTC                 0x0000A9   Time-base timer control register
TBTC.TBIE             4
TBTC.TBOF             3
TBTC.TBR              2
TBTC.TBC1             1
TBTC.TBC0             0
WTC                  0x0000AA   Clock timer control register
WTC.WDCS              7
WTC.SCE               6
WTC.WTIE              5
WTC.WTOF              4
WTC.WTR               3
WTC.WTC2              2
WTC.WTC1              1
WTC.WTC0              0
FMCS                 0x0000AE   Flash memory control status register
ICR00                0x0000B0   Interrupt control register 00
ICR00.S1              5
ICR00.S0              4
ICR00.ISE             3
ICR00.IL2             2
ICR00.IL1             1
ICR00.IL0             0
ICR01                0x0000B1   Interrupt control register 01
ICR01.S1              5
ICR01.S0              4
ICR01.ISE             3
ICR01.IL2             2
ICR01.IL1             1
ICR01.IL0             0
ICR02                0x0000B2   Interrupt control register 02
ICR02.S1              5
ICR02.S0              4
ICR02.ISE             3
ICR02.IL2             2
ICR02.IL1             1
ICR02.IL0             0
ICR03                0x0000B3   Interrupt control register 03
ICR03.S1              5
ICR03.S0              4
ICR03.ISE             3
ICR03.IL2             2
ICR03.IL1             1
ICR03.IL0             0
ICR04                0x0000B4   Interrupt control register 04
ICR04.S1              5
ICR04.S0              4
ICR04.ISE             3
ICR04.IL2             2
ICR04.IL1             1
ICR04.IL0             0
ICR05                0x0000B5   Interrupt control register 05
ICR05.S1              5
ICR05.S0              4
ICR05.ISE             3
ICR05.IL2             2
ICR05.IL1             1
ICR05.IL0             0
ICR06                0x0000B6   Interrupt control register 06
ICR06.S1              5
ICR06.S0              4
ICR06.ISE             3
ICR06.IL2             2
ICR06.IL1             1
ICR06.IL0             0
ICR07                0x0000B7   Interrupt control register 07
ICR07.S1              5
ICR07.S0              4
ICR07.ISE             3
ICR07.IL2             2
ICR07.IL1             1
ICR07.IL0             0
ICR08                0x0000B8   Interrupt control register 08
ICR08.S1              5
ICR08.S0              4
ICR08.ISE             3
ICR08.IL2             2
ICR08.IL1             1
ICR08.IL0             0
ICR09                0x0000B9   Interrupt control register 09
ICR09.S1              5
ICR09.S0              4
ICR09.ISE             3
ICR09.IL2             2
ICR09.IL1             1
ICR09.IL0             0
ICR10                0x0000BA   Interrupt control register 10
ICR10.S1              5
ICR10.S0              4
ICR10.ISE             3
ICR10.IL2             2
ICR10.IL1             1
ICR10.IL0             0
ICR11                0x0000BB   Interrupt control register 11
ICR11.S1              5
ICR11.S0              4
ICR11.ISE             3
ICR11.IL2             2
ICR11.IL1             1
ICR11.IL0             0
ICR12                0x0000BC   Interrupt control register 12
ICR12.S1              5
ICR12.S0              4
ICR12.ISE             3
ICR12.IL2             2
ICR12.IL1             1
ICR12.IL0             0
ICR13                0x0000BD   Interrupt control register 13
ICR13.S1              5
ICR13.S0              4
ICR13.ISE             3
ICR13.IL2             2
ICR13.IL1             1
ICR13.IL0             0
ICR14                0x0000BE   Interrupt control register 14
ICR14.S1              5
ICR14.S0              4
ICR14.ISE             3
ICR14.IL2             2
ICR14.IL1             1
ICR14.IL0             0
ICR15                0x0000BF   Interrupt control register 15
ICR15.S1              5
ICR15.S0              4
ICR15.ISE             3
ICR15.IL2             2
ICR15.IL1             1
ICR15.IL0             0


.MB90590
; DS07-13704-4E  http://edevice.fujitsu.com/fj/DATASHEET/e-ds/e713704.pdf
; MB90591/F591A/594/594G/F594A/F594G/MB90V590A/V590G


; ROM: 384/256 Kbytes (MB90591/594/594G/MB90F591A/F594A/F594G)
; RAM:     8/6 Kbytes (MB90591/594/594G/MB90F591A/F594A/F594G)
;            8 Kbytes (MB90V590A/V590G)


; MEMORY MAP
; [MB90V590A/MB90V590G]
area DATA FSR              0x000000:0x0000C0
area BSS  No_access_1      0x0000C0:0x000100
area DATA RAM_1            0x000100:0x001900
area DATA FSR_1            0x001900:0x002000
area BSS  No_access_2      0x002000:0x002100
area DATA RAM_2            0x002100:0x002300
area BSS  No_access_3      0x002300:0x004000
area DATA R0M_1            0x004000:0x010000
area BSS  No_access_4      0x010000:0xF90000
area DATA ROM_2_BANK_F9    0xF90000:0xFA0000
area DATA ROM_2_BANK_FA    0xFA0000:0xFB0000
area DATA ROM_2_BANK_FB    0xFB0000:0xFC0000
area DATA ROM_2_BANK_FC    0xFC0000:0xFD0000
area DATA ROM_2_BANK_FD    0xFD0000:0xFE0000
area DATA ROM_2_BANK_FE    0xFE0000:0xFF0000
area DATA ROM_2_BANK_FF    0xFF0000:0x1000000

; [MB90594/MB90F594A/MB90594G/MB90F594G]
; area DATA FSR              0x000000:0x0000C0
; area BSS  No_access_1      0x0000C0:0x000100
; area DATA RAM_1            0x000100:0x001900
; area DATA FSR_1            0x001900:0x002000
; area BSS  No_access_2      0x002000:0x004000
; area DATA R0M_1            0x004000:0x010000
; area BSS  No_access_4      0x010000:0xFC0000
; area DATA ROM_2_BANK_FC    0xFC0000:0xFD0000
; area DATA ROM_2_BANK_FD    0xFD0000:0xFE0000
; area DATA ROM_2_BANK_FE    0xFE0000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000

; [MB90591/MB90F591A]
; area DATA FSR              0x000000:0x0000C0
; area BSS  No_access_1      0x0000C0:0x000100
; area DATA RAM_1            0x000100:0x001900
; area DATA FSR_1            0x001900:0x002000
; area BSS  No_access_2      0x002000:0x002100
; area DATA RAM_2            0x002100:0x002300
; area BSS  No_access_3      0x002300:0x004000
; area DATA R0M_1            0x004000:0x010000
; area BSS  No_access_4      0x010000:0xF90000
; area DATA ROM_2_BANK_F9    0xF90000:0xFA0000
; area DATA ROM_2_BANK_FA    0xFA0000:0xFB0000
; area DATA ROM_2_BANK_FB    0xFB0000:0xFC0000
; area BSS  No_access_5      0xFC0000:0xFD0000
; area DATA ROM_2_BANK_FD    0xFD0000:0xFE0000
; area DATA ROM_2_BANK_FE    0xFE0000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000


; Interrupt and reset vector assignments
interrupt __RESET       0xFFFFDC   Reset 
interrupt INT9          0xFFFFD8   INT9 instruction 
interrupt EXCEPT        0xFFFFD4   Exception 
interrupt TB_TIMER      0xFFFFD0   Time Base Timer 
interrupt INT0_INT7     0xFFFFCC   External Interrupt (INT0 to INT7) 
interrupt CAN_0_RX      0xFFFFC8   CAN 0 RX 
interrupt CAN_0_TX_NS   0xFFFFC4   CAN 0 TX/NS 
interrupt CAN_1_RX      0xFFFFC0   CAN 1 RX 
interrupt CAN_1_TX_NS   0xFFFFBC   CAN 1 TX/NS 
interrupt PPG_01        0xFFFFB8   8/16 bit PPG 0/1 
interrupt PPG_23        0xFFFFB4   8/16 bit PPG 2/3 
interrupt PPG_45        0xFFFFB0   8/16 bit PPG 4/5 
interrupt PPG_67        0xFFFFAC   8/16 bit PPG 6/7 
interrupt PPG_89        0xFFFFA8   8/16 bit PPG 8/9 
interrupt PPG_A_B       0xFFFFA4   8/16 bit PPG A/B 
interrupt R_TIMER0      0xFFFFA0   16-bit Reload Timer 0 
interrupt R_TIMER1      0xFFFF9C   16-bit Reload Timer 1 
interrupt IC01          0xFFFF98   Input Capture 0/1 
interrupt OC01          0xFFFF94   Output compare 0/1 
interrupt IC23          0xFFFF90   Input Capture 2/3 
interrupt OC23          0xFFFF8C   Output Compare 2/3 
interrupt IC45          0xFFFF88   Input Capture 4/5 
interrupt OC45          0xFFFF84   Output Compare 4/5 
interrupt AD_CONV       0xFFFF80   8/10 bit A/D Converter 
interrupt IO_TIMER      0xFFFF7C   I/O Timer/Watch Timer 
interrupt IO            0xFFFF78   Serial I/O 
interrupt SOUND         0xFFFF74   Sound Generator 
interrupt UART_0_RX     0xFFFF70   UART 0 RX 
interrupt UART_0_TX     0xFFFF6C   UART 0 TX 
interrupt UART_1_RX     0xFFFF68   UART 1 RX 
interrupt UART_1_TX     0xFFFF64   UART 1 TX 
interrupt UART_2_RX     0xFFFF60   UART 2 RX 
interrupt UART_2_TX     0xFFFF5C   UART 2 TX 
interrupt FLASH         0xFFFF58   Flash Memory 
interrupt DELAY         0xFFFF54   Delayed interrupt 


; INPUT/OUTPUT PORTS
PDR0                 0x000000   Port 0 Data Register
PDR0.P07              7
PDR0.P06              6
PDR0.P05              5
PDR0.P04              4
PDR0.P03              3
PDR0.P02              2
PDR0.P01              1
PDR0.P00              0
PDR1                 0x000001   Port 1 Data Register
PDR1.P17              7
PDR1.P16              6
PDR1.P15              5
PDR1.P14              4
PDR1.P13              3
PDR1.P12              2
PDR1.P11              1
PDR1.P10              0
PDR2                 0x000002   Port 2 Data Register
PDR2.P27              7
PDR2.P26              6
PDR2.P25              5
PDR2.P24              4
PDR2.P23              3
PDR2.P22              2
PDR2.P21              1
PDR2.P20              0
PDR3                 0x000003   Port 3 Data Register
PDR3.P37              7
PDR3.P36              6
PDR3.P35              5
PDR3.P34              4
PDR3.P33              3
PDR3.P32              2
PDR3.P31              1
PDR3.P30              0
PDR4                 0x000004   Port 4 Data Register
PDR4.P47              7
PDR4.P46              6
PDR4.P45              5
PDR4.P44              4
PDR4.P43              3
PDR4.P42              2
PDR4.P41              1
PDR4.P40              0
PDR5                 0x000005   Port 5 Data Register
PDR5.P57              7      
PDR5.P56              6
PDR5.P55              5
PDR5.P54              4
PDR5.P53              3
PDR5.P52              2
PDR5.P51              1
PDR5.P50              0
PDR6                 0x000006   Port 6 Data Register
PDR6.P67              7      
PDR6.P66              6
PDR6.P65              5
PDR6.P64              4
PDR6.P63              3
PDR6.P62              2
PDR6.P61              1
PDR6.P60              0
PDR7                 0x000007   Port 7 Data Register
PDR7.P77              7      
PDR7.P76              6
PDR7.P75              5
PDR7.P74              4
PDR7.P73              3
PDR7.P72              2
PDR7.P71              1
PDR7.P70              0
PDR8                 0x000008   Port 8 Data Register
PDR8.P87              7      
PDR8.P86              6
PDR8.P85              5
PDR8.P84              4
PDR8.P83              3
PDR8.P82              2
PDR8.P81              1
PDR8.P80              0
PDR9                 0x000009   Port 9 Data Register
PDR9.P95              5
PDR9.P94              4
PDR9.P93              3
PDR9.P92              2
PDR9.P91              1
PDR9.P90              0
DDR0                 0x000010   Port 0 Direction Register
DDR0.D07              7
DDR0.D06              6
DDR0.D05              5
DDR0.D04              4
DDR0.D03              3
DDR0.D02              2
DDR0.D01              1
DDR0.D00              0
DDR1                 0x000011   Port 1 Direction Register
DDR1.D17              7
DDR1.D16              6
DDR1.D15              5
DDR1.D14              4
DDR1.D13              3
DDR1.D12              2
DDR1.D11              1
DDR1.D10              0
DDR2                 0x000012   Port 2 Direction Register
DDR2.D27              7
DDR2.D26              6
DDR2.D25              5
DDR2.D24              4
DDR2.D23              3
DDR2.D22              2
DDR2.D21              1
DDR2.D20              0
DDR3                 0x000013   Port 3 Direction Register
DDR3.D37              7
DDR3.D36              6
DDR3.D35              5
DDR3.D34              4
DDR3.D33              3
DDR3.D32              2
DDR3.D31              1
DDR3.D30              0
DDR4                 0x000014   Port 4 Direction Register
DDR4.D47              7
DDR4.D46              6
DDR4.D45              5
DDR4.D44              4
DDR4.D43              3
DDR4.D42              2
DDR4.D41              1
DDR4.D40              0
DDR5                 0x000015   Port 5 Direction Register
DDR5.D57              7
DDR5.D56              6
DDR5.D55              5
DDR5.D54              4
DDR5.D53              3
DDR5.D52              2
DDR5.D51              1
DDR5.D50              0
DDR6                 0x000016   Port 6 Direction Register
DDR6.D67              7
DDR6.D66              6
DDR6.D65              5
DDR6.D64              4
DDR6.D63              3
DDR6.D62              2
DDR6.D61              1
DDR6.D60              0
DDR7                 0x000017   Port 7 Direction Register
DDR7.D77              7
DDR7.D76              6
DDR7.D75              5
DDR7.D74              4
DDR7.D73              3
DDR7.D72              2
DDR7.D71              1
DDR7.D70              0
DDR8                 0x000018   Port 8 Direction Register
DDR8.D87              7
DDR8.D86              6
DDR8.D85              5
DDR8.D84              4
DDR8.D83              3
DDR8.D82              2
DDR8.D81              1
DDR8.D80              0
DDR9                 0x000019   Port 9 Direction Register
DDR9.D95              5
DDR9.D94              4
DDR9.D93              3
DDR9.D92              2
DDR9.D91              1
DDR9.D90              0
ADER                 0x00001B   Analog Input Enable Register
ADER.ADE7             7
ADER.ADE6             6
ADER.ADE5             5
ADER.ADE4             4
ADER.ADE3             3
ADER.ADE2             2
ADER.ADE1             1
ADER.ADE0             0
UMC0                 0x000020   Serial Mode Control Register 0
UMC0.PEN              7
UMC0.SBL              6
UMC0.MC1              5
UMC0.MC0              4
UMC0.SMDE             3
UMC0.RFC              2
UMC0.SCKE             1
UMC0.SOE              0
USR0                 0x000021   Serial Status Register 0
USR0.RDRF             7
USR0.ORFE             6
USR0.PE               5
USR0.TDRE             4
USR0.RIE              3
USR0.TIE              2
USR0.RBF              1
USR0.TBF              0
UIDR0                0x000022   Serial Input/Output Data Register 0
URD0                 0x000023   Rate and Data Register 0
UMC1                 0x000024   Serial Mode Control Register 1
UMC1.PEN              7
UMC1.SBL              6
UMC1.MC1              5
UMC1.MC0              4
UMC1.SMDE             3
UMC1.RFC              2
UMC1.SCKE             1
UMC1.SOE              0
USR1                 0x000025   Serial Status Register 1
USR1.RDRF             7
USR1.ORFE             6
USR1.PE               5
USR1.TDRE             4
USR1.RIE              3
USR1.TIE              2
USR1.RBF              1
USR1.TBF              0
UIDR1                0x000026   Serial Input/Output Data Register 1
URD1                 0x000027   Rate and Data Register 1
UMC2                 0x000028   Serial Mode Control Register 2
UMC2.PEN              7
UMC2.SBL              6
UMC2.MC1              5
UMC2.MC0              4
UMC2.SMDE             3
UMC2.RFC              2
UMC2.SCKE             1
UMC2.SOE              0
USR2                 0x000029   Serial Status Register 2
USR2.RDRF             7
USR2.ORFE             6
USR2.PE               5
USR2.TDRE             4
USR2.RIE              3
USR2.TIE              2
USR2.RBF              1
USR2.TBF              0
UIDR2                0x00002A   Serial Input/Output Data Register 2
URD2                 0x00002B   Rate and Data Register 2
SMCS                 0x00002C   Serial Mode Control Register
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
SDR                  0x00002E   Serial Data Register
SES                  0x00002F   Edge Selector Register
SES.NEG               0
ENIR                 0x000030   External Interrupt Enable Register
ENIR.EN7              7     
ENIR.EN6              6     
ENIR.EN5              5     
ENIR.EN4              4     
ENIR.EN3              3     
ENIR.EN2              2
ENIR.EN1              1
ENIR.EN0              0
EIRR                 0x000031   External Interrupt Request Register
EIRR.ER7              7     
EIRR.ER6              6     
EIRR.ER5              5     
EIRR.ER4              4     
EIRR.ER3              3     
EIRR.ER2              2
EIRR.ER1              1
EIRR.ER0              0
ELVR                 0x000032   External Interrupt Level Register
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
ADCS0                0x000034   A/D Control Status Register 0
ADCS0.MD1             7
ADCS0.MD0             6
ADCS0.ANS2            5
ADCS0.ANS1            4
ADCS0.ANS0            3
ADCS0.ANE2            2
ADCS0.ANE1            1
ADCS0.ANE0            0
ADCS1                0x000035   A/D Control Status Register 1
ADCS1.BUSY            7
ADCS1.INT             6
ADCS1.INTE            5
ADCS1.PAUS            4
ADCS1.STS1            3         
ADCS1.STS0            2
ADCR01               0x000036   A/D Data Register 0/1
ADCR01.S10            15
ADCR01.ST1            14
ADCR01.ST0            13
ADCR01.CT1            12
ADCR01.CT0            11
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
PPGC01               0x000038   PPG0/1 Operation Mode Control Register
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
PPG01                0x00003A   PPG0,1 Output Pin Control Register
PPG01.PCS2            7
PPG01.PCS1            6
PPG01.PCS0            5
PPG01.PCM2            4
PPG01.PCM1            3
PPG01.PCM0            2
PPGC23               0x00003C   PPG2/3 Operation Mode Control Register
PPGC23.PEN1           15
PPGC23.PE10           13
PPGC23.PIE1           12
PPGC23.PUF1           11
PPGC23.MD1            10
PPGC23.MD0            9
PPGC23.PEN0           7
PPGC23.PE00           5
PPGC23.PIE0           4
PPGC23.PUF0           3
PPG23                0x00003E   PPG2,3 Output Pin Control Register
PPG23.PCS2            7
PPG23.PCS1            6
PPG23.PCS0            5
PPG23.PCM2            4
PPG23.PCM1            3
PPG23.PCM0            2
PPGC45               0x000040   PPG4/5 Operation Mode Control Register
PPGC45.PEN1           15
PPGC45.PE10           13
PPGC45.PIE1           12
PPGC45.PUF1           11
PPGC45.MD1            10
PPGC45.MD0            9
PPGC45.PEN0           7
PPGC45.PE00           5
PPGC45.PIE0           4
PPGC45.PUF0           3
PPG45                0x000042   PPG4,5 Output Pin Control Register
PPG45.PCS2            7
PPG45.PCS1            6
PPG45.PCS0            5
PPG45.PCM2            4
PPG45.PCM1            3
PPG45.PCM0            2
PPGC67               0x000044   PPG6/7 Operation Mode Control Register
PPGC67.PEN1           15
PPGC67.PE10           13
PPGC67.PIE1           12
PPGC67.PUF1           11
PPGC67.MD1            10
PPGC67.MD0            9
PPGC67.PEN0           7
PPGC67.PE00           5
PPGC67.PIE0           4
PPGC67.PUF0           3
PPG67                0x000046   PPG6,7 Output Pin Control Register
PPG67.PCS2            7
PPG67.PCS1            6
PPG67.PCS0            5
PPG67.PCM2            4
PPG67.PCM1            3
PPG67.PCM0            2
PPGC89               0x000048   PPG8/9 Operation Mode Control Register
PPGC89.PEN1           15
PPGC89.PE10           13
PPGC89.PIE1           12
PPGC89.PUF1           11
PPGC89.MD1            10
PPGC89.MD0            9
PPGC89.PEN0           7
PPGC89.PE00           5
PPGC89.PIE0           4
PPGC89.PUF0           3
PPG89                0x00004A   PPG8,9 Output Pin Control Register
PPG89.PCS2            7
PPG89.PCS1            6
PPG89.PCS0            5
PPG89.PCM2            4
PPG89.PCM1            3
PPG89.PCM0            2
PPGCAB               0x00004C   PPGA/B Operation Mode Control Register
PPGCAB.PEN1           15
PPGCAB.PE10           13
PPGCAB.PIE1           12
PPGCAB.PUF1           11
PPGCAB.MD1            10
PPGCAB.MD0            9
PPGCAB.PEN0           7
PPGCAB.PE00           5
PPGCAB.PIE0           4
PPGCAB.PUF0           3
PPGAB                0x00004E   PPGA,B Output Pin Control Register
PPGAB.PCS2            7
PPGAB.PCS1            6
PPGAB.PCS0            5
PPGAB.PCM2            4
PPGAB.PCM1            3
PPGAB.PCM0            2
TMCSR0               0x000050   Timer Control Status Register 0
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
TMCSR1               0x000052   Timer Control Status Register 1
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
ICS01                0x000054   Input Capture Control Status Register 0/1
ICS01.ICP1            7
ICS01.ICP0            6
ICS01.ICE1            5
ICS01.ICE0            4
ICS01.EG11            3 
ICS01.EG10            2
ICS01.EG01            1
ICS01.EG00            0
ICS23                0x000055   Input Capture Control Status Register 2/3
ICS23.ICP1            7
ICS23.ICP0            6
ICS23.ICE1            5
ICS23.ICE0            4
ICS23.EG11            3 
ICS23.EG10            2
ICS23.EG01            1
ICS23.EG00            0
ICS45                0x000056   Input Capture Control Status Register 4/5
ICS45.ICP1            7
ICS45.ICP0            6
ICS45.ICE1            5
ICS45.ICE0            4
ICS45.EG11            3 
ICS45.EG10            2
ICS45.EG01            1
ICS45.EG00            0
OCS01                0x000058   Output Compare Control Status Register 0/1
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
OCS23                0x00005A   Output Compare Control Status Register 2/3
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
OCS45                0x00005C   Output Compare Control Status Register 4/5
OCS45.CMOD            12
OCS45.OTE1            11
OCS45.OTE0            10
OCS45.OTD1            9
OCS45.OTD0            8
OCS45.ICP1            7
OCS45.ICP0            6
OCS45.ICE1            5
OCS45.ICE0            4
OCS45.CST1            1
OCS45.CST0            0
SGCR                 0x00005E   Sound Control Register
SGCR.TST              15
SGCR.BUSY             9
SGCR.DEC              8
SGCR.S1               7
SGCR.S0               6
SGCR.TONE             5
SGCR.OE2              4
SGCR.OE1              3
SGCR.INTE             2
SGCR.INT              1
SGCR.ST               0
WTCR                 0x000060   Watch Timer Control Register
WTCR.INTE3            15
WTCR.INT3             14
WTCR.INTE2            13
WTCR.INT2             12
WTCR.INTE1            11
WTCR.INT1             10
WTCR.INTE0            9
WTCR.INT0             8
WTCR.TST2             7
WTCR.TST1             6
WTCR.TST0             5
WTCR.UPDT             2
WTCR.OE               1
WTCR.ST               0
PWC0                 0x000062   PWM Control Register 0
PWC0.OE2              7
PWC0.OE1              6
PWC0.P1               5
PWC0.P0               4
PWC0.CE               3
PWC0.TST              0
PWC1                 0x000064   PWM Control Register 1
PWC1.OE2              7
PWC1.OE1              6
PWC1.P1               5
PWC1.P0               4
PWC1.CE               3
PWC1.TST              0
PWC2                 0x000066   PWM Control Register 2
PWC2.OE2              7
PWC2.OE1              6
PWC2.P1               5
PWC2.P0               4
PWC2.CE               3
PWC2.TST              0
PWC3                 0x000068   PWM Control Register 3
PWC3.OE2              7
PWC3.OE1              6
PWC3.P1               5
PWC3.P0               4
PWC3.CE               3
PWC3.TST              0
CDCR                 0x00006D   Serial IO Prescaler Register
CDCR.MD               7
CDCR.DIV3             3
CDCR.DIV2             2
CDCR.DIV1             1
CDCR.DIV0             0
TCCS                 0x00006E   Timer Control Status Register
TCCS.IVF              6
TCCS.IVFE             5
TCCS.STOP             4
TCCS.MODE             3
TCCS.CLR              2
TCCS.CLK1             1
TCCS.CLK0             0
ROMM                 0x00006F   ROM Mirror Function Select Register
PACSR                0x00009E   Program Address Detection Control Status Register
PACSR.AD1E            3
PACSR.AD0E            1
DIRR                 0x00009F   Delayed Interrupt/Release Register
DIRR.R0               0
LPMCR                0x0000A0   Low Power Mode Control Register
LPMCR.STP             7
LPMCR.SLP             6
LPMCR.SPL             5
LPMCR.RST             4
LPMCR.CG1             2
LPMCR.CG0             1
CKSCR                0x0000A1   Clock Selection Register
CKSCR.SCM             7
CKSCR.MCM             6
CKSCR.WS1             5
CKSCR.WS0             4
CKSCR.SCS             3
CKSCR.MCS             2
CKSCR.CS1             1 
CKSCR.CS0             0
WDTC                 0x0000A8   Watchdog Timer Control Register
WDTC.PONR             7
WDTC.STBR             6
WDTC.WRST             5
WDTC.ERST             4
WDTC.SRST             3
TBTC                 0x0000A9   Time Base Timer Control Register
TBTC.TBIE             4
TBTC.TBOF             3
TBTC.TBR              2
TBTC.TBC1             1
TBTC.TBC0             0
ICR00                0x0000B0   Interrupt Control Register 00
ICR00.S1              5
ICR00.S0              4
ICR00.ISE             3
ICR00.IL2             2
ICR00.IL1             1
ICR00.IL0             0
ICR01                0x0000B1   Interrupt Control Register 01
ICR01.S1              5
ICR01.S0              4
ICR01.ISE             3
ICR01.IL2             2
ICR01.IL1             1
ICR01.IL0             0
ICR02                0x0000B2   Interrupt Control Register 02
ICR02.S1              5
ICR02.S0              4
ICR02.ISE             3
ICR02.IL2             2
ICR02.IL1             1
ICR02.IL0             0
ICR03                0x0000B3   Interrupt Control Register 03
ICR03.S1              5
ICR03.S0              4
ICR03.ISE             3
ICR03.IL2             2
ICR03.IL1             1
ICR03.IL0             0
ICR04                0x0000B4   Interrupt Control Register 04
ICR04.S1              5
ICR04.S0              4
ICR04.ISE             3
ICR04.IL2             2
ICR04.IL1             1
ICR04.IL0             0
ICR05                0x0000B5   Interrupt Control Register 05
ICR05.S1              5
ICR05.S0              4
ICR05.ISE             3
ICR05.IL2             2
ICR05.IL1             1
ICR05.IL0             0
ICR06                0x0000B6   Interrupt Control Register 06
ICR06.S1              5
ICR06.S0              4
ICR06.ISE             3
ICR06.IL2             2
ICR06.IL1             1
ICR06.IL0             0
ICR07                0x0000B7   Interrupt Control Register 07
ICR07.S1              5
ICR07.S0              4
ICR07.ISE             3
ICR07.IL2             2
ICR07.IL1             1
ICR07.IL0             0
ICR08                0x0000B8   Interrupt Control Register 08
ICR08.S1              5
ICR08.S0              4
ICR08.ISE             3
ICR08.IL2             2
ICR08.IL1             1
ICR08.IL0             0
ICR09                0x0000B9   Interrupt Control Register 09
ICR09.S1              5
ICR09.S0              4
ICR09.ISE             3
ICR09.IL2             2
ICR09.IL1             1
ICR09.IL0             0
ICR10                0x0000BA   Interrupt Control Register 10
ICR10.S1              5
ICR10.S0              4
ICR10.ISE             3
ICR10.IL2             2
ICR10.IL1             1
ICR10.IL0             0
ICR11                0x0000BB   Interrupt Control Register 11
ICR11.S1              5
ICR11.S0              4
ICR11.ISE             3
ICR11.IL2             2
ICR11.IL1             1
ICR11.IL0             0
ICR12                0x0000BC   Interrupt Control Register 12
ICR12.S1              5
ICR12.S0              4
ICR12.ISE             3
ICR12.IL2             2
ICR12.IL1             1
ICR12.IL0             0
ICR13                0x0000BD   Interrupt Control Register 13
ICR13.S1              5
ICR13.S0              4
ICR13.ISE             3
ICR13.IL2             2
ICR13.IL1             1
ICR13.IL0             0
ICR14                0x0000BE   Interrupt Control Register 14
ICR14.S1              5
ICR14.S0              4
ICR14.ISE             3
ICR14.IL2             2
ICR14.IL1             1
ICR14.IL0             0
ICR15                0x0000BF   Interrupt Control Register 15
ICR15.S1              5
ICR15.S0              4
ICR15.ISE             3
ICR15.IL2             2
ICR15.IL1             1
ICR15.IL0             0
PRLL0                0x001900 Reload L Register 
PRLH0                0x001901 Reload H Register 
PRLL1                0x001902 Reload L Register 
PRLH1                0x001903 Reload H Register 
PRLL2                0x001904 Reload L Register 
PRLH2                0x001905 Reload H Register 
PRLL3                0x001906 Reload L Register 
PRLH3                0x001907 Reload H Register 
PRLL4                0x001908 Reload L Register 
PRLH4                0x001909 Reload H Register 
XPRLL5               0x00190A Reload L Register 
PRLH5                0x00190B Reload H Register 
PRLL6                0x00190C Reload L Register 
PRLH6                0x00190D Reload H Register 
PRLL7                0x00190E Reload L Register 
PRLH7                0x00190F Reload H Register 
PRLL8                0x001910 Reload L Register 
PRLH8                0x001911 Reload H Register 
PRLL9                0x001912 Reload L Register 
PRLH9                0x001913 Reload H Register 
PRLLA                0x001914 Reload L Register 
PRLHA                0x001915 Reload H Register 
PRLLB                0x001916 Reload L Register 
PRLHB                0x001917 Reload H Register 
Reserv001918         0x001918 Reserved
Reserv001919         0x001919 Reserved
Reserv00191A         0x00191A Reserved
Reserv00191B         0x00191B Reserved
Reserv00191C         0x00191C Reserved
Reserv00191D         0x00191D Reserved
Reserv00191E         0x00191E Reserved
Reserv00191F         0x00191F Reserved
IPCP0L               0x001920 Input Capture Register 0 (low-order) 
IPCP0H               0x001921 Input Capture Register 0 (high-order) 
IPCP1L               0x001922 Input Capture Register 1 (low-order) 
IPCP1H               0x001923 Input Capture Register 1 (high-order) 
IPCP2L               0x001924 Input Capture Register 2 (low-order) 
IPCP2H               0x001925 Input Capture Register 2 (high-order) 
IPCP3L               0x001926 Input Capture Register 3 (low-order) 
IPCP3H               0x001927 Input Capture Register 3 (high-order) 
IPCP4L               0x001928 Input Capture Register 4 (low-order) 
IPCP4H               0x001929 Input Capture Register 4 (high-order) 
IPCP5L               0x00192A Input Capture Register 5 (low-order) 
IPCP5H               0x00192B Input Capture Register 5 (high-order) 
Reserv00192C         0x00192C Reserved 
Reserv00192D         0x00192D Reserved 
Reserv00192E         0x00192E Reserved 
Reserv00192F         0x00192F Reserved 
OCCP0L               0x001930 Output Compare Register 0 (low-order) 
OCCP0H               0x001931 Output Compare Register 0 (high-order) 
OCCP1L               0x001932 Output Compare Register 1 (low-order) 
OCCP1H               0x001933 Output Compare Register 1 (high-order) 
OCCP2L               0x001934 Output Compare Register 2 (low-order) 
OCCP2H               0x001935 Output Compare Register 2 (high-order) 
OCCP3L               0x001936 Output Compare Register 3 (low-order) 
OCCP3H               0x001937 Output Compare Register 3 (high-order) 
OCCP4L               0x001938 Output Compare Register 4 (low-order) 
OCCP4H               0x001939 Output Compare Register 4 (high-order) 
OCCP5L               0x00193A Output Compare Register 5 (low-order) 
OCCP5H               0x00193B Output Compare Register 5 (high-order) 
Reserv00193C         0x00193C Reserved 
Reserv00193D         0x00193D Reserved 
Reserv00193E         0x00193E Reserved 
Reserv00193F         0x00193F Reserved 
TMR0_TMRLR0L         0x001940 Timer 0/Reload Register 0 (low-order) 
TMR0_TMRLR0H         0x001941 Timer 0/Reload Register 0 (high-order) 
TMR1_TMRLR1L         0x001942 Timer 1/Reload Register 1 (low-order) 
TMR1_TMRLR1H         0x001943 Timer 1/Reload Register 1 (high-order) 
TCDTL                0x001944 Timer Data Register (low-order) 
TCDTH                0x001945 Timer Data Register (high-order) 
SGFRL                0x001946 Frequency Data Register 
SGARH                0x001947 Amplitude Data Register 
SGDRL                0x001948 Decrement Grade Register 
SGTRH                0x001949 Tone Count Register 
WTBRL                0x00194A Sub-second Data Register (low-order) 
WTBRH                0x00194B Sub-second Data Register (middle-order) 
WTBRL                0x00194C Sub-second Data Register (high-order) 
WTSR                 0x00194D Second Data Register 
WTMR                 0x00194E Minute Data Register 
WTHR                 0x00194F Hour Data Register 
PWC10                0x001950 PWM1 Compare Register 0 
PWC20                0x001951 PWM2 Compare Register 0 
PWS10                0x001952 PWM1 Select Register 0 
PWS20                0x001953 PWM2 Select Register 0 
PWC11                0x001954 PWM1 Compare Register 1 
PWC21                0x001955 PWM2 Compare Register 1 
PWS11                0x001956 PWM1 Select Register 1 
PWS21                0x001957 PWM2 Select Register 1 
PWC12                0x001958 PWM1 Compare Register 2 
PWC22                0x001959 PWM2 Compare Register 2 
PWS12                0x00195A PWM1 Select Register 2 
PWS22                0x00195B PWM2 Select Register 2 
PWC13                0x00195C PWM1 Compare Register 3 
PWC23                0x00195D PWM2 Compare Register 3 
PWS13                0x00195E PWM1 Select Register 3 
PWS23                0x00195F PWM2 Select Register 3 


.MB90595G
; DS07-13705-5E  http://edevice.fujitsu.com/fj/DATASHEET/e-ds/e713705.pdf
; MB90598/598G/F598/F598G/V595/V595G


; ROM: 128 Kbytes (MB90598/MB90598G/MB90F598/F598G)
; RAM:   4 Kbytes (MB90598/MB90598G/MB90F598/F598G)
;        6 Kbytes (MB90V595/V595G)


; MEMORY MAP
; [MB90V595/MB90V595G]
area DATA FSR              0x000000:0x0000C0
area BSS  No_access_1      0x0000C0:0x000100
area DATA RAM              0x000100:0x001900
area DATA FSR_1            0x001900:0x002000
area BSS  No_access_3      0x002000:0x004000
area DATA ROM_1            0x004000:0x010000
area BSS  No_access_4      0x010000:0xFC0000
area DATA ROM_2_BANK_FC    0xFC0000:0xFD0000
area DATA ROM_2_BANK_FD    0xFD0000:0xFE0000
area DATA ROM_2_BANK_FE    0xFE0000:0xFF0000
area DATA ROM_2_BANK_FF    0xFF0000:0x1000000

; [MB90598/MB90598G (under development)/MB90F598/MB90F598G]
; area DATA FSR              0x000000:0x0000C0
; area BSS  No_access_1      0x0000C0:0x000100
; area DATA RAM              0x000100:0x001100
; area BSS  No_access_2      0x001100;0x001900
; area DATA FSR_1            0x001900:0x002000
; area BSS  No_access_3      0x002000:0x004000
; area DATA ROM_1            0x004000:0x010000
; area BSS  No_access_4      0x010000:0xFE0000
; area DATA ROM_2_BANK_FE    0xFE0000:0xFF0000
; area DATA ROM_2_BANK_FF    0xFF0000:0x1000000


; Interrupt and reset vector assignments
interrupt __RESET       0xFFFFDC   Reset 
interrupt INT9          0xFFFFD8   INT9 instruction 
interrupt EXCEPT        0xFFFFD4   Exception 
interrupt CAN_RX        0xFFFFD0   CAN RX 
interrupt CAN_TX_NS     0xFFFFCC   CAN TX/NS 
interrupt INT0_INT1     0xFFFFC8   External Interrupt (INT0/INT1) 
interrupt TB_TIMER      0xFFFFC4   Time Base Timer 
interrupt R_TIMER0      0xFFFFC0   16-bit Reload Timer 0 
interrupt AD_CONV       0xFFFFBC   8/10-bit A/D Converter 
interrupt IO_TIMER      0xFFFFB8   I/O Timer 
interrupt INT2_INT3     0xFFFFB4   External Interrupt (INT2/INT3) 
interrupt IO            0xFFFFB0   Serial I/O 
interrupt INT4_INT5     0xFFFFAC   External Interrupt (INT4/INT5) 
interrupt IC0           0xFFFFA8   Input Capture 0 
interrupt PPG_0_1       0xFFFFA4   8/16-bit PPG 0/1 
interrupt OC0           0xFFFFA0   Output Compare 0 
interrupt PPG_2_3       0xFFFF9C   8/16-bit PPG 2/3 
interrupt INT6_INT7     0xFFFF98   External Interrupt (INT6/INT7) 
interrupt IC1           0xFFFF94   Input Capture 1 
interrupt PPG_4_5       0xFFFF90   8/16-bit PPG 4/5 
interrupt OC1           0xFFFF8C   Output Compare 1 
interrupt PPG_6_7       0xFFFF88   8/16-bit PPG 6/7 
interrupt IC2           0xFFFF84   Input Capture 2 
interrupt PPG_8_9       0xFFFF80   8/16-bit PPG 8/9 
interrupt OC2           0xFFFF7C   Output Compare 2 
interrupt IC3           0xFFFF78   Input Capture 3 
interrupt PPG_A_B       0xFFFF74   8/16-bit PPG A/B 
interrupt OC3           0xFFFF70   Output Compare 3 
interrupt R_TIMER1      0xFFFF6C   16-bit Reload Timer 1 
interrupt UART_0_RX     0xFFFF68   UART 0 RX 
interrupt UART_0_TX     0xFFFF64   UART 0 TX 
interrupt UART_1_RX     0xFFFF60   UART 1 RX 
interrupt UART_1_TX     0xFFFF5C   UART 1 TX 
interrupt FLASH         0xFFFF58   Flash Memory 
interrupt DELAY         0xFFFF54   Delayed interrupt 


; INPUT/OUTPUT PORTS
PDR0                 0x000000   Port 0 Data Register
PDR0.P07              7
PDR0.P06              6
PDR0.P05              5
PDR0.P04              4
PDR0.P03              3
PDR0.P02              2
PDR0.P01              1
PDR0.P00              0
PDR1                 0x000001   Port 1 Data Register
PDR1.P17              7
PDR1.P16              6
PDR1.P15              5
PDR1.P14              4
PDR1.P13              3
PDR1.P12              2
PDR1.P11              1
PDR1.P10              0
PDR2                 0x000002   Port 2 Data Register
PDR2.P27              7
PDR2.P26              6
PDR2.P25              5
PDR2.P24              4
PDR2.P23              3
PDR2.P22              2
PDR2.P21              1
PDR2.P20              0
PDR3                 0x000003   Port 3 Data Register
PDR3.P37              7
PDR3.P36              6
PDR3.P35              5
PDR3.P34              4
PDR3.P33              3
PDR3.P32              2
PDR3.P31              1
PDR3.P30              0
PDR4                 0x000004   Port 4 Data Register
PDR4.P47              7
PDR4.P46              6
PDR4.P45              5
PDR4.P44              4
PDR4.P43              3
PDR4.P42              2
PDR4.P41              1
PDR4.P40              0
PDR5                 0x000005   Port 5 Data Register
PDR5.P57              7      
PDR5.P56              6
PDR5.P55              5
PDR5.P54              4
PDR5.P53              3
PDR5.P52              2
PDR5.P51              1
PDR5.P50              0
PDR6                 0x000006   Port 6 Data Register
PDR6.P67              7      
PDR6.P66              6
PDR6.P65              5
PDR6.P64              4
PDR6.P63              3
PDR6.P62              2
PDR6.P61              1
PDR6.P60              0
PDR7                 0x000007   Port 7 Data Register
PDR7.P77              7      
PDR7.P76              6
PDR7.P75              5
PDR7.P74              4
PDR7.P73              3
PDR7.P72              2
PDR7.P71              1
PDR7.P70              0
PDR8                 0x000008   Port 8 Data Register
PDR8.P87              7      
PDR8.P86              6
PDR8.P85              5
PDR8.P84              4
PDR8.P83              3
PDR8.P82              2
PDR8.P81              1
PDR8.P80              0
PDR9                 0x000009   Port 9 Data Register
PDR9.P95              5
PDR9.P94              4
PDR9.P93              3
PDR9.P92              2
PDR9.P91              1
PDR9.P90              0
DDR0                 0x000010   Port 0 Direction Register
DDR0.D07              7
DDR0.D06              6
DDR0.D05              5
DDR0.D04              4
DDR0.D03              3
DDR0.D02              2
DDR0.D01              1
DDR0.D00              0
DDR1                 0x000011   Port 1 Direction Register
DDR1.D17              7
DDR1.D16              6
DDR1.D15              5
DDR1.D14              4
DDR1.D13              3
DDR1.D12              2
DDR1.D11              1
DDR1.D10              0
DDR2                 0x000012   Port 2 Direction Register
DDR2.D27              7
DDR2.D26              6
DDR2.D25              5
DDR2.D24              4
DDR2.D23              3
DDR2.D22              2
DDR2.D21              1
DDR2.D20              0
DDR3                 0x000013   Port 3 Direction Register
DDR3.D37              7
DDR3.D36              6
DDR3.D35              5
DDR3.D34              4
DDR3.D33              3
DDR3.D32              2
DDR3.D31              1
DDR3.D30              0
DDR4                 0x000014   Port 4 Direction Register
DDR4.D47              7
DDR4.D46              6
DDR4.D45              5
DDR4.D44              4
DDR4.D43              3
DDR4.D42              2
DDR4.D41              1
DDR4.D40              0
DDR5                 0x000015   Port 5 Direction Register
DDR5.D57              7
DDR5.D56              6
DDR5.D55              5
DDR5.D54              4
DDR5.D53              3
DDR5.D52              2
DDR5.D51              1
DDR5.D50              0
DDR6                 0x000016   Port 6 Direction Register
DDR6.D67              7
DDR6.D66              6
DDR6.D65              5
DDR6.D64              4
DDR6.D63              3
DDR6.D62              2
DDR6.D61              1
DDR6.D60              0
DDR7                 0x000017   Port 7 Direction Register
DDR7.D77              7
DDR7.D76              6
DDR7.D75              5
DDR7.D74              4
DDR7.D73              3
DDR7.D72              2
DDR7.D71              1
DDR7.D70              0
DDR8                 0x000018   Port 8 Direction Register
DDR8.D87              7
DDR8.D86              6
DDR8.D85              5
DDR8.D84              4
DDR8.D83              3
DDR8.D82              2
DDR8.D81              1
DDR8.D80              0
DDR9                 0x000019   Port 9 Direction Register
DDR9.D95              5
DDR9.D94              4
DDR9.D93              3
DDR9.D92              2
DDR9.D91              1
DDR9.D90              0
ADER                 0x00001B   Analog Input Enable Register
ADER.ADE7             7
ADER.ADE6             6
ADER.ADE5             5
ADER.ADE4             4
ADER.ADE3             3
ADER.ADE2             2
ADER.ADE1             1
ADER.ADE0             0
UMC0                 0x000020   Serial Mode Control Register 0
UMC0.PEN              7
UMC0.SBL              6
UMC0.MC1              5
UMC0.MC0              4
UMC0.SMDE             3
UMC0.RFC              2
UMC0.SCKE             1
UMC0.SOE              0
USR0                 0x000021   Serial status Register 0
USR0.RDRF             7
USR0.ORFE             6
USR0.PE               5
USR0.TDRE             4
USR0.RIE              3
USR0.TIE              2
USR0.RBF              1
USR0.TBF              0
UIDR0                0x000022   Serial Input/Output Data Register 0
URD0                 0x000023   Rate and Data Register 0
SMR1                 0x000024   Serial Mode Register 1
SMR1.MD1              7
SMR1.MD0              6
SMR1.CS2              5
SMR1.CS1              4
SMR1.CS0              3
SMR1.SCKE             1
SMR1.SOE              0
SCR1                 0x000025   Serial Control Register 1
SCR1.PEN              7
SCR1.P                6
SCR1.SBL              5
SCR1.CL               4
SCR1.AD               3
SCR1.REC              2
SCR1.RXE              1
SCR1.TXE              0
SIDR1                0x000026   Serial Input/Output Data Register 1
SIDR1.D7              7
SIDR1.D6              6
SIDR1.D5              5
SIDR1.D4              4
SIDR1.D3              3
SIDR1.D2              2
SIDR1.D1              1
SIDR1.D0              0
SSR1                 0x000027   Serial Status Register 1
SSR1.PE               7
SSR1.ORE              6
SSR1.FRE              5
SSR1.RDRF             4
SSR1.TDRE             3
SSR1.RIE              1
SSR1.TIE              0
U1CDCR               0x000028   UART1 Prescaler Control Register
U1CDCR.MD             7
U1CDCR.DIV3           3
U1CDCR.DIV2           2
U1CDCR.DIV1           1
U1CDCR.DIV0           0
SCDCR                0x00002B   Serial IO Prescaler
SCDCR.NEG             0
SMCS                 0x00002C   Serial Mode Control Register
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
SDR                  0x00002E   Serial Data Register
SES                  0x00002F   Edge Selector
SES.NEG               0
ENIR                 0x000030   External Interrupt Enable Register
ENIR.EN7              7     
ENIR.EN6              6     
ENIR.EN5              5     
ENIR.EN4              4     
ENIR.EN3              3     
ENIR.EN2              2
ENIR.EN1              1
ENIR.EN0              0
EIRR                 0x000031   External Interrupt Request Register
EIRR.ER7              7     
EIRR.ER6              6     
EIRR.ER5              5     
EIRR.ER4              4     
EIRR.ER3              3     
EIRR.ER2              2
EIRR.ER1              1
EIRR.ER0              0
ELVR                 0x000032   External Interrupt Level Register
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
ADCS0                0x000034   A/D Control Status Register 0
ADCS0.MD1             7
ADCS0.MD0             6
ADCS0.ANS2            5
ADCS0.ANS1            4
ADCS0.ANS0            3
ADCS0.ANE2            2
ADCS0.ANE1            1
ADCS0.ANE0            0
ADCS1                0x000035   A/D Control Status Register 1
ADCS1.BUSY            7
ADCS1.INT             6
ADCS1.INTE            5
ADCS1.PAUS            4
ADCS1.STS1            3         
ADCS1.STS0            2
ADCR01               0x000036   A/D Data Register 0/1
ADCR01.S10            15
ADCR01.ST1            14
ADCR01.ST0            13
ADCR01.CT1            12
ADCR01.CT0            11
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
PPGC01               0x000038   PPG0/1 Operation Mode Control Register
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
PPG01                0x00003A   PPG0, 1 Output Pin Control Register
PPG01.PCS2            7
PPG01.PCS1            6
PPG01.PCS0            5
PPG01.PCM2            4
PPG01.PCM1            3
PPG01.PCM0            2
PPGC23               0x00003C   PPG2/3 Operation Mode Control Register
PPGC23.PEN1           15
PPGC23.PE10           13
PPGC23.PIE1           12
PPGC23.PUF1           11
PPGC23.MD1            10
PPGC23.MD0            9
PPGC23.PEN0           7
PPGC23.PE00           5
PPGC23.PIE0           4
PPGC23.PUF0           3
PPG23                0x00003E   PPG2, 3 Output Pin Control Register
PPG23.PCS2            7
PPG23.PCS1            6
PPG23.PCS0            5
PPG23.PCM2            4
PPG23.PCM1            3
PPG23.PCM0            2
PPGC45               0x000040   PPG4/5 Operation Mode Control Register
PPGC45.PEN1           15
PPGC45.PE10           13
PPGC45.PIE1           12
PPGC45.PUF1           11
PPGC45.MD1            10
PPGC45.MD0            9
PPGC45.PEN0           7
PPGC45.PE00           5
PPGC45.PIE0           4
PPGC45.PUF0           3
PPG45                0x000042   PPG4, 5 Output Pin Control Register
PPG45.PCS2            7
PPG45.PCS1            6
PPG45.PCS0            5
PPG45.PCM2            4
PPG45.PCM1            3
PPG45.PCM0            2
PPGC67               0x000044   PPG6/7 Operation Mode Control Register
PPGC67.PEN1           15
PPGC67.PE10           13
PPGC67.PIE1           12
PPGC67.PUF1           11
PPGC67.MD1            10
PPGC67.MD0            9
PPGC67.PEN0           7
PPGC67.PE00           5
PPGC67.PIE0           4
PPGC67.PUF0           3
PPG67                0x000046   PPG6, 7 Output Pin Control Register
PPG67.PCS2            7
PPG67.PCS1            6
PPG67.PCS0            5
PPG67.PCM2            4
PPG67.PCM1            3
PPG67.PCM0            2
PPGC89               0x000048   PPG8/9 Operation Mode Control Register
PPGC89.PEN1           15
PPGC89.PE10           13
PPGC89.PIE1           12
PPGC89.PUF1           11
PPGC89.MD1            10
PPGC89.MD0            9
PPGC89.PEN0           7
PPGC89.PE00           5
PPGC89.PIE0           4
PPGC89.PUF0           3
PPG89                0x00004A   PPG8, 9 Output Pin Control Register
PPG89.PCS2            7
PPG89.PCS1            6
PPG89.PCS0            5
PPG89.PCM2            4
PPG89.PCM1            3
PPG89.PCM0            2
PPGCAB               0x00004C   PPGA/B Operation Mode Control Register
PPGCAB.PEN1           15
PPGCAB.PE10           13
PPGCAB.PIE1           12
PPGCAB.PUF1           11
PPGCAB.MD1            10
PPGCAB.MD0            9
PPGCAB.PEN0           7
PPGCAB.PE00           5
PPGCAB.PIE0           4
PPGCAB.PUF0           3
PPGAB                0x00004E   PPGA, B Output Pin Control Register
PPGAB.PCS2            7
PPGAB.PCS1            6
PPGAB.PCS0            5
PPGAB.PCM2            4
PPGAB.PCM1            3
PPGAB.PCM0            2
TMCSR0               0x000050   Timer Control Status Register 0
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
TMR0                 0x000052   Timer 0/Reload Register 0
TMCSR1               0x000054   Timer Control Status Register 1
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
TMR1                 0x000056   Timer Register 1/Reload Register 1
OCS01                0x000058   Output Compare Control Status Register 0/1
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
OCS23                0x00005A   Output Compare Control Status Register 2/3
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
ICS01                0x00005C   Input Capture Control Status Register 0/1
ICS01.ICP1            7
ICS01.ICP0            6
ICS01.ICE1            5
ICS01.ICE0            4
ICS01.EG11            3 
ICS01.EG10            2
ICS01.EG01            1
ICS01.EG00            0
ICS23                0x00005D   Input Capture Control Status Register 2/3
ICS23.ICP1            7
ICS23.ICP0            6
ICS23.ICE1            5
ICS23.ICE0            4
ICS23.EG11            3 
ICS23.EG10            2
ICS23.EG01            1
ICS23.EG00            0
PWC0                 0x00005E   PWM Control Register 0
PWC0.OE2              7
PWC0.OE1              6
PWC0.P1               5
PWC0.P0               4
PWC0.CE               3
PWC0.TST              0
PWC1                 0x000060   PWM Control Register 1
PWC1.OE2              7
PWC1.OE1              6
PWC1.P1               5
PWC1.P0               4
PWC1.CE               3
PWC1.TST              0
PWC2                 0x000062   PWM Control Register 2
PWC2.OE2              7
PWC2.OE1              6
PWC2.P1               5
PWC2.P0               4
PWC2.CE               3
PWC2.TST              0
PWC3                 0x000064   PWM Control Register 3
PWC3.OE2              7
PWC3.OE1              6
PWC3.P1               5
PWC3.P0               4
PWC3.CE               3
PWC3.TST              0
TCDT                 0x000066   Timer Data Register
TCCS                 0x000068   Timer Control Status Register
TCCS.IVF              6
TCCS.IVFE             5
TCCS.STOP             4
TCCS.MODE             3
TCCS.CLR              2
TCCS.CLK1             1
TCCS.CLK0             0
ROMM                 0x00006F   ROM Mirror Function Selection Register
PWC10                0x000070   PWM1 Compare Register 0
PWC20                0x000071   PWM2 Compare Register 0
PWS10                0x000072   PWM1 Select Register 0
PWS10.P2              5 
PWS10.P1              4
PWS10.P0              3
PWS10.M2              2
PWS10.M1              1
PWS10.M0              0
PWS20                0x000073   PWM2 Select Register 0
PWS20.BS              6
PWS20.P2              5 
PWS20.P1              4
PWS20.P0              3
PWS20.M2              2
PWS20.M1              1
PWS20.M0              0
PWC11                0x000074   PWM1 Compare Register 1
PWC21                0x000075   PWM2 Compare Register 1
PWS11                0x000076   PWM1 Select Register 1
PWS11.P2              5 
PWS11.P1              4
PWS11.P0              3
PWS11.M2              2
PWS11.M1              1
PWS11.M0              0
PWS21                0x000077   PWM2 Select Register 1
PWS21.BS              6
PWS21.P2              5 
PWS21.P1              4
PWS21.P0              3
PWS21.M2              2
PWS21.M1              1
PWS21.M0              0
PWC12                0x000078   PWM1 Compare Register 2
PWC22                0x000079   PWM2 Compare Register 2
PWS12                0x00007A   PWM1 Select Register 2
PWS12.P2              5 
PWS12.P1              4
PWS12.P0              3
PWS12.M2              2
PWS12.M1              1
PWS12.M0              0
PWS22                0x00007B   PWM2 Select Register 2
PWS22.BS              6
PWS22.P2              5 
PWS22.P1              4
PWS22.P0              3
PWS22.M2              2
PWS22.M1              1
PWS22.M0              0
PWC13                0x00007C   PWM1 Compare Register 3
PWC23                0x00007D   PWM2 Compare Register 3
PWS13                0x00007E   PWM1 Select Register 3
PWS13.P2              5 
PWS13.P1              4
PWS13.P0              3
PWS13.M2              2
PWS13.M1              1
PWS13.M0              0
PWS23                0x00007F   PWM2 Select Register 3
PWS23.BS              6
PWS23.P2              5 
PWS23.P1              4
PWS23.P0              3
PWS23.M2              2
PWS23.M1              1
PWS23.M0              0
PACSR                0x00009E   Program Address Detection Control Status Register
PACSR.AD1E            3
PACSR.AD0E            1
DIRR                 0x00009F   Delayed Interrupt/Request Register
DIRR.R0               0
LPMCR                0x0000A0   Low-Power Mode Control Register
LPMCR.STP             7
LPMCR.SLP             6
LPMCR.SPL             5
LPMCR.RST             4
LPMCR.CG1             2
LPMCR.CG0             1
CKSCR                0x0000A1   Clock Selection Register
CKSCR.SCM             7
CKSCR.MCM             6
CKSCR.WS1             5
CKSCR.WS0             4
CKSCR.SCS             3
CKSCR.MCS             2
CKSCR.CS1             1 
CKSCR.CS0             0
WDTC                 0x0000A8   Watchdog Timer Control Register
WDTC.PONR             7
WDTC.STBR             6
WDTC.WRST             5
WDTC.ERST             4
WDTC.SRST             3
TBTC                 0x0000A9   Time Base Timer Control Register
TBTC.TBIE             4
TBTC.TBOF             3
TBTC.TBR              2
TBTC.TBC1             1
TBTC.TBC0             0
ICR00                0x0000B0   Interrupt Control Register 00
ICR00.S1              5
ICR00.S0              4
ICR00.ISE             3
ICR00.IL2             2
ICR00.IL1             1
ICR00.IL0             0
ICR01                0x0000B1   Interrupt Control Register 01
ICR01.S1              5
ICR01.S0              4
ICR01.ISE             3
ICR01.IL2             2
ICR01.IL1             1
ICR01.IL0             0
ICR02                0x0000B2   Interrupt Control Register 02
ICR02.S1              5
ICR02.S0              4
ICR02.ISE             3
ICR02.IL2             2
ICR02.IL1             1
ICR02.IL0             0
ICR03                0x0000B3   Interrupt Control Register 03
ICR03.S1              5
ICR03.S0              4
ICR03.ISE             3
ICR03.IL2             2
ICR03.IL1             1
ICR03.IL0             0
ICR04                0x0000B4   Interrupt Control Register 04
ICR04.S1              5
ICR04.S0              4
ICR04.ISE             3
ICR04.IL2             2
ICR04.IL1             1
ICR04.IL0             0
ICR05                0x0000B5   Interrupt Control Register 05
ICR05.S1              5
ICR05.S0              4
ICR05.ISE             3
ICR05.IL2             2
ICR05.IL1             1
ICR05.IL0             0
ICR06                0x0000B6   Interrupt Control Register 06
ICR06.S1              5
ICR06.S0              4
ICR06.ISE             3
ICR06.IL2             2
ICR06.IL1             1
ICR06.IL0             0
ICR07                0x0000B7   Interrupt Control Register 07
ICR07.S1              5
ICR07.S0              4
ICR07.ISE             3
ICR07.IL2             2
ICR07.IL1             1
ICR07.IL0             0
ICR08                0x0000B8   Interrupt Control Register 08
ICR08.S1              5
ICR08.S0              4
ICR08.ISE             3
ICR08.IL2             2
ICR08.IL1             1
ICR08.IL0             0
ICR09                0x0000B9   Interrupt Control Register 09
ICR09.S1              5
ICR09.S0              4
ICR09.ISE             3
ICR09.IL2             2
ICR09.IL1             1
ICR09.IL0             0
ICR10                0x0000BA   Interrupt Control Register 10
ICR10.S1              5
ICR10.S0              4
ICR10.ISE             3
ICR10.IL2             2
ICR10.IL1             1
ICR10.IL0             0
ICR11                0x0000BB   Interrupt Control Register 11
ICR11.S1              5
ICR11.S0              4
ICR11.ISE             3
ICR11.IL2             2
ICR11.IL1             1
ICR11.IL0             0
ICR12                0x0000BC   Interrupt Control Register 12
ICR12.S1              5
ICR12.S0              4
ICR12.ISE             3
ICR12.IL2             2
ICR12.IL1             1
ICR12.IL0             0
ICR13                0x0000BD   Interrupt Control Register 13
ICR13.S1              5
ICR13.S0              4
ICR13.ISE             3
ICR13.IL2             2
ICR13.IL1             1
ICR13.IL0             0
ICR14                0x0000BE   Interrupt Control Register 14
ICR14.S1              5
ICR14.S0              4
ICR14.ISE             3
ICR14.IL2             2
ICR14.IL1             1
ICR14.IL0             0
ICR15                0x0000BF   Interrupt Control Register 15
ICR15.S1              5
ICR15.S0              4
ICR15.ISE             3
ICR15.IL2             2
ICR15.IL1             1
ICR15.IL0             0
PRLL0                0x001900 Reload Register L 
PRLH0                0x001901 Reload Register H 
PRLL1                0x001902 Reload Register L 
PRLH1                0x001903 Reload Register H 
PRLL2                0x001904 Reload Register L 
PRLH2                0x001905 Reload Register H 
PRLL3                0x001906 Reload Register L 
PRLH3                0x001907 Reload Register H 
PRLL4                0x001908 Reload Register L 
PRLH4                0x001909 Reload Register H 
PRLL5                0x00190A Reload Register L 
PRLH5                0x00190B Reload Register H 
PRLL6                0x00190C Reload Register L 
PRLH6                0x00190D Reload Register H 
PRLL7                0x00190E Reload Register L 
PRLH7                0x00190F Reload Register H 
PRLL8                0x001910 Reload Register L 
PRLH8                0x001911 Reload Register H 
PRLL9                0x001912 Reload Register L 
PRLH9                0x001913 Reload Register H 
PRLLA                0x001914 Reload Register L 
PRLHA                0x001915 Reload Register H 
PRLLB                0x001916 Reload Register L 
PRLHB                0x001917 Reload Register H 
Reserv001918         0x001918 Reserved
Reserv001919         0x001919 Reserved
Reserv00191A         0x00191A Reserved
Reserv00191B         0x00191B Reserved
Reserv00191C         0x00191C Reserved
Reserv00191D         0x00191D Reserved
Reserv00191E         0x00191E Reserved
Reserv00191F         0x00191F Reserved
IPCP0L               0x001920 Input Capture Register 0 (low-order) 
IPCP0H               0x001921 Input Capture Register 0 (high-order) 
IPCP1L               0x001922 Input Capture Register 1 (low-order) 
IPCP1H               0x001923 Input Capture Register 1 (high-order) 
IPCP2L               0x001924 Input Capture Register 2 (low-order) 
IPCP2H               0x001925 Input Capture Register 2 (high-order) 
IPCP3L               0x001926 Input Capture Register 3 (low-order) 
IPCP3H               0x001927 Input Capture Register 3 (high-order) 
OCCP0L               0x001928 Output Compare Register 0 (low-order) 
OCCP0H               0x001929 Output Compare Register 0 (high-order) 
OCCP1L               0x00192A Output Compare Register 1 (low-order) 
OCCP1H               0x00192B Output Compare Register 1 (high-order) 
OCCP2L               0x00192C Output Compare Register 2 (low-order) 
OCCP2H               0x00192D Output Compare Register 2 (high-order) 
OCCP3L               0x00192E Output Compare Register 3 (low-order) 
OCCP3H               0x00192F Output Compare Register 3 (high-order) 

    


```
