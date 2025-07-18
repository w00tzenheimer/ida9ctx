```ini

; http://edevice.fujitsu.com/fj/MANUAL/MANUALl/allliste.html#WEB6

.default FR30

DUMMY   0xdeadbeef  Dummy port

;.FR20  documentation under preparation...

.FR30

interrupt RESET     0x000FFFFC   Reset
; 0x000FFFF8     Reserved for system
; 0x000FFFF4     Reserved for system
; 0x000FFFF0     Reserved for system
; 0x000FFFEC     Reserved for system
; 0x000FFFE8     Reserved for system
; 0x000FFFE4     Reserved for system
; 0x000FFFE0     Reserved for system
; 0x000FFFDC     Reserved for system
; 0x000FFFD8     Reserved for system
; 0x000FFFD4     Reserved for system
; 0x000FFFD0     Reserved for system
; 0x000FFFCC     Reserved for system
; 0x000FFFC8     Reserved for system
interrupt UIE 0x000FFFC4         Undefined instruction exception
interrupt NMI 0x000FFFC0         NMI request
interrupt EI0 0x000FFFBC         External 0
interrupt EI1 0x000FFFB8         External 1
interrupt EI2 0x000FFFB4         External 2
interrupt EI3 0x000FFFB0         External 3
interrupt UARTR0 0x000FFFAC      UART 0 reception complete
interrupt UARTR1 0x000FFFA8      UART 1 reception complete
interrupt UARTR2 0x000FFFA4      UART 2 reception complete
interrupt UARTT0 0x000FFFA0      UART 0 transmission complete
interrupt UARTT1 0x000FFF9C      UART 1 transmission complete
interrupt UARTT2 0x000FFF98      UART 2 transmission complete
interrupt DMAC0 0x000FFF94       DMAC 0 (end or error)
interrupt DMAC1 0x000FFF90       DMAC 1 (end or error)
interrupt DMAC2 0x000FFF8C       DMAC 2 (end or error)
interrupt DMAC3 0x000FFF88       DMAC 3 (end or error)
interrupt DMAC4 0x000FFF84       DMAC 4 (end or error)
interrupt DMAC5 0x000FFF80       DMAC 5 (end or error)
interrupt DMAC6 0x000FFF7C       DMAC 6 (end or error)
interrupt DMAC7 0x000FFF78       DMAC 7 (end or error)
interrupt AD 0x000FFF74  A/D (successive approximation)
interrupt RLTIM0 0x000FFF70      Reload timer 0
interrupt RLTIM1 0x000FFF6C      Reload timer 1
interrupt RLTIM2 0x000FFF68      Reload timer 2
interrupt PWM0 0x000FFF64        PWM 0
interrupt PWM1 0x000FFF60        PWM 1
interrupt PWM2 0x000FFF5C        PWM 2
interrupt PWM3 0x000FFF58        PWM 3
interrupt UTIMER0 0x000FFF54     U-TIMER 0
interrupt UTIMER1 0x000FFF50     U-TIMER 1
interrupt UTIMER2 0x000FFF4C     U-TIMER 2
interrupt EI4 0x000FFF48         External 4
interrupt EI5 0x000FFF44         External 5
interrupt EI6 0x000FFF40         External 6
interrupt EI7 0x000FFF3C         External 7
interrupt DSPSI 0x000FFF38       DSP macro software interrupt
interrupt DSPOI 0x000FFF34       DSP macro offset interrupt
; 0x000FFF30     Reserved for system
; 0x000FFF2C     Reserved for system
; 0x000FFF28     Reserved for system
; 0x000FFF24     Reserved for system
; 0x000FFF20     Reserved for system
; 0x000FFF1C     Reserved for system
; 0x000FFF18     Reserved for system
; 0x000FFF14     Reserved for systemword
; 0x000FFF10     Reserved for system
; 0x000FFF0C     Reserved for system
; 0x000FFF08     Reserved for system
; 0x000FFF04     Reserved for system
interrupt DIS 0x000FFF00         Delayed ressource
; 0x000FFEFC     Reserved for system (used by REALOS)
; 0x000FFEF8     Reserved for system (used by REALOS)
interrupt INT 0x000FFEF4         For INT instruction

.FR50

interrupt RESET 0x000FFFFC Reset
interrupt MVEC 0x000FFFF8 Mode vector
;0x000FFFF4 System reserved
;0x000FFFF0 System reserved
;0x000FFFEC System reserved
;0x000FFFE8 System reserved
;0x000FFFE4 System reserved
interrupt COPTRAP 0x000FFFE0 Co-processor fault trap *4
interrupt COPETRAP 0x000FFFDC Co-processor error trap *4
interrupt INTE 0x000FFFD8 INTE instruction *4
interrupt IBE 0x000FFFD4 Instruction break exception *4
interrupt OBT 0x000FFFD0 Operand break trap *4
interrupt STT 0x000FFFCC Step trace trap *4
interrupt NMI 0x000FFFC8 NMI (tool)*4
interrupt UIE 0x000FFFC4 Undefined instruction exception
interrupt NMI_REQ 0x000FFFC0 NMI request
interrupt EI0 0x000FFFBC External Interrupt 0
interrupt EI1 0x000FFFB8 External Interrupt 1
interrupt EI2 0x000FFFB4 External Interrupt 2
interrupt EI3 0x000FFFB0 External Interrupt 3
interrupt EI4 0x000FFFAC External Interrupt 4
interrupt EI5 0x000FFFA8 External Interrupt 5
interrupt EI6 0x000FFFA4 External Interrupt 6
interrupt EI7 0x000FFFA0 External Interrupt 7
interrupt RLTIM0 0x000FFF9C Reload Timer 0
interrupt RLTIM1 0x000FFF98 Reload Timer 1
interrupt RLTIM2 0x000FFF94 Reload Timer 2
interrupt CAN0RX 0x000FFF90 CAN 0 RX
interrupt CAN0TX 0x000FFF8C CAN 0 TX/NS
interrupt CAN1RX 0x000FFF88 CAN 1 RX
interrupt CAN1TX 0x000FFF84 CAN 1 TX/NS
interrupt CAN2RX 0x000FFF80 CAN 2 RX
interrupt CAN2TX 0x000FFF7C CAN 2 TX/NS
interrupt CAN3RX 0x000FFF78 CAN 3 RX *5
interrupt CAN3TX 0x000FFF74 CAN 3 TX/NS *5
interrupt PPG01 0x000FFF70 PPG 0/1
interrupt PPG23 0x000FFF6C PPG 2/3
interrupt PPG45 0x000FFF68 PPG 4/5
interrupt PPG67 0x000FFF64 PPG 6/7
interrupt RLTIM3 0x000FFF60 Reload Timer 3
interrupt RLTIM4 0x000FFF5C Reload Timer 4
interrupt RLTIM5 0x000FFF58 Reload Timer 5
interrupt ICU01 0x000FFF54 ICU 0/1
interrupt OCU01 0x000FFF50 OCU 0/1
interrupt ICU23 0x000FFF4C ICU 2/3
interrupt OCU23 0x000FFF48 OCU 2/3
interrupt ADC 0x000FFF44 ADC
interrupt TO 0x000FFF40 Timebase Overflow
interrupt FRC0 0x000FFF3C Free Running Counter 0
interrupt FRC1 0x000FFF38 Free Running Counter 1
interrupt SIO0 0x000FFF34 SIO 0 *6
interrupt SIO1 0x000FFF30 SIO 1 *6
interrupt SG 0x000FFF2C Sound Generator
interrupt UART0RX 0x000FFF28 UART 0 RX
interrupt UART0TX 0x000FFF24 UART 0 TX
interrupt UART1RX 0x000FFF20 UART 1 RX
interrupt UART1TX 0x000FFF1C UART 1 TX
interrupt UART2RX 0x000FFF18 UART 2 RX
interrupt UART3TX 0x000FFF14 UART 2 TX
interrupt I2C 0x000FFF10 I2C
interrupt ACMP 0x000FFF0C Alarm Comparator
interrupt RTC 0x000FFF08 RTC (Watchtimer) / Calibration Unit
interrupt DMA 0x000FFF04 DMA
interrupt DIAB 0x000FFF00 Delayed activation bit
;0x000FFEFC System reserved *3
;0x000FFEF8 System reserved *3
interrupt SECVEC 0x000FFEF4 Security vector
;0x000FFEF0 System reserved
;0x000FFEEC System reserved
;0x000FFEE8 System reserved
;0x000FFEE4 System reserved
;0x000FFEE0 System reserved
;0x000FFEDC System reserved
;0x000FFED8 System reserved
;0x000FFED4 System reserved
;0x000FFED0 System reserved
;0x000FFECC System reserved
;0x000FFEC8 System reserved
;0x000FFEC4 System reserved
;0x000FFEC0 System reserved
interrupt INT0 0x000FFEBC Used by the INT instruction.
interrupt INT1 0x000FFC00 Used by the INT instruction.

.FR65E

interrupt RESET     0x000FFFFC   Reset
interrupt MVEC      0x000FFFF8   Mode vector
;         0x000FFFF4   Reserved for system
;         0x000FFFF0   Reserved for system
;         0x000FFFEC   Reserved for system
;         0x000FFFE8   Reserved for system
;         0x000FFFE4   Reserved for system
interrupt COPTRAP   0x000FFFE0   No-coprocessor trap
interrupt COPETRAP  0x000FFFDC   Coprocessor error trap
interrupt INTE      0x000FFFD8   INTE instruction
interrupt IBE       0x000FFFD4   Instruction break exception
interrupt OBT       0x000FFFD0   Operand break trap
interrupt STT       0x000FFFCC   Step trace trap
interrupt NMI       0x000FFFC8   NMI request (tool)
interrupt UIE       0x000FFFC4   Undefined instruction exception
interrupt NMIREQ    0x000FFFC0   NMI request
interrupt EI0       0x000FFFBC   External Interrupt 0
interrupt EI1       0x000FFFB8   External Interrupt 1
interrupt EI2       0x000FFFB4   External Interrupt 2
interrupt EI3       0x000FFFB0   External Interrupt 3
interrupt EI4       0x000FFFAC   External Interrupt 4
interrupt EI5       0x000FFFA8   External Interrupt 5
interrupt EI6       0x000FFFA4   External Interrupt 6
interrupt EI7       0x000FFFA0   External Interrupt 7
interrupt RLTIM0    0x000FFF9C   Reload Timer 0
interrupt RLTIM1    0x000FFF98   Reload Timer 1
interrupt RLTIM2    0x000FFF94   Reload Timer 2
interrupt UARTR0    0x000FFF90   UART0 (reception completed)
interrupt UARTR1    0x000FFF8C   UART1 (reception completed)
interrupt UARTR2    0x000FFF88   UART2 (reception completed)
interrupt UARTT0    0x000FFF84   UART0 (transmission completed)
interrupt UARTT1    0x000FFF80   UART1 (transmission completed)
interrupt UARTT2    0x000FFF7C   UART2 (transmission completed)
interrupt DMAC0     0x000FFF78   DMAC0 (end, error)
interrupt DMAC1     0x000FFF74   DMAC1 (end, error)
interrupt DMAC2     0x000FFF70   DMAC2 (end, error)
interrupt DMAC3     0x000FFF6C   DMAC3 (end, error)
interrupt DMAC4     0x000FFF68   DMAC4 (end, error)
interrupt AD        0x000FFF64   A/D
interrupt I2C       0x000FFF60   I2C
;         0x000FFF5C   Reserved for system
;         0x000FFF58   Reserved for system
;         0x000FFF54   Reserved for system
;         0x000FFF50   Reserved for system
interrupt UTIMER0   0x000FFF4C   U-TIMER0
interrupt UTIMER1   0x000FFF48   U-TIMER1
interrupt UTIMER2   0x000FFF44   U-TIMER2
interrupt TBTO      0x000FFF40   Time base timer overflow
;         0x000FFF3C   Reserved for system
;         0x000FFF38   Reserved for system
;         0x000FFF34   Reserved for system
;         0x000FFF30   Reserved for system
;         0x000FFF2C   Reserved for system
;         0x000FFF28   Reserved for system
;         0x000FFF24   Reserved for system
;         0x000FFF20   Reserved for system
;         0x000FFF1C   Reserved for system
;         0x000FFF18   Reserved for system
;         0x000FFF14   Reserved for system
;         0x000FFF10   Reserved for system
;         0x000FFF0C   Reserved for system
;         0x000FFF08   Reserved for system
;         0x000FFF04   Reserved for system
interrupt DISB      0x000FFF00   Delayed source bit
;         0x000FFEFC   Reserved for system (used by REALOS)
;         0x000FFEF8   Reserved for system (used by REALOS)
;         0x000FFEF4   Reserved for system
;         0x000FFEF0   Reserved for system
;         0x000FFEEC   Reserved for system
;         0x000FFEE8   Reserved for system
;         0x000FFEE4   Reserved for system
;         0x000FFEE0   Reserved for system
;         0x000FFEDC   Reserved for system
;         0x000FFED8   Reserved for system
;         0x000FFED4   Reserved for system
;         0x000FFED0   Reserved for system
;         0x000FFECC   Reserved for system
;         0x000FFEC8   Reserved for system
;         0x000FFEC4   Reserved for system
;         0x000FFEC0   Reserved for system
interrupt INT0      0x000FFEBC   Used in INT instruction
interrupt INT1      0x000FFC00   Used in INT instruction


```
