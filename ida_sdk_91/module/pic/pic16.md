```ini
;
; This file defines SFR names and bit names for Microchip's PIC 16 bit processors.
;
; This file can be configured for different devices.
; At the beginning of the file there are definitions common for all devices
; Device-specific definitions are introduced by
;
;       .devicename
;
; line. Also an optional directive
;
;       .default devicename
;
; designates the default device name.
;

.default 18F2520

; common FSR definitions

TOSU             0xFFF
TOSH             0xFFE
TOSL             0xFFD
STKPTR           0xFFC
STKPTR.STKFUL        7
STKPTR.STKUNF        6
STKPTR.SP4           4
STKPTR.SP3           3
STKPTR.SP2           2
STKPTR.SP1           1
STKPTR.SP0           0
PCLATU           0xFFB
PCLATH           0xFFA
PCL              0xFF9
TBLPTRU          0xFF8
TBLPTRH          0xFF7
TBLPTRL          0xFF6
TABLAT           0xFF5
PRODH            0xFF4
PRODL            0xFF3
INTCON           0xFF2
INTCON.GIE_GIEH      7
INTCON.PEIE_GIEL     6
INTCON.TMR0IE        5
INTCON.INT0IE        4
INTCON.RBIE          3
INTCON.TMR0IF        2
INTCON.INT0IF        1
INTCON.RBIF          0
INTCON2          0xFF1
INTCON2.RBPU         7
INTCON2.INTEDG0      6
INTCON2.INTEDG1      5
INTCON2.INTEDG2      4
INTCON2.TMR0IP       2
INTCON2.RBIP         0
INTCON3          0xFF0
INTCON3.INT2IP       7
INTCON3.INT1IP       6
INTCON3.INT2IE       4
INTCON3.INT1IE       3
INTCON3.INT2IF       1
INTCON3.INT1IF       0
INDF0            0xFEF
POSTINC0         0xFEE
POSTDEC0         0xFED
PREINC0          0xFEC
PLUSW0           0xFEB
FSR0H            0xFEA
FSR0L            0xFE9
WREG             0xFE8
INDF1            0xFE7
POSTINC1         0xFE6
POSTDEC1         0xFE5
PREINC1          0xFE4
PLUSW1           0xFE3
FSR1H            0xFE2
FSR1L            0xFE1
BSR              0xFE0
INDF2            0xFDF
POSTINC2         0xFDE
POSTDEC2         0xFDD
PREINC2          0xFDC
PLUSW2           0xFDB
FSR2H            0xFDA
FSR2L            0xFD9
STATUS           0xFD8
STATUS.N             4
STATUS.OV            3
STATUS.Z             2
STATUS.DC            1
STATUS.C             0
TMR0H            0xFD7
TMR0L            0xFD6
T0CON            0xFD5
T0CON.TMR0ON         7
T0CON.T08BIT         6
T0CON.T0CS           5
T0CON.T0SE           4
T0CON.PSA            3
T0CON.T0PS2          2
T0CON.T0PS1          1
T0CON.T0PS0          0
OSCCON           0xFD3
OSCCON.IDLEN         7
OSCCON.IRCF2         6
OSCCON.IRCF1         5
OSCCON.IRCF0         4
OSCCON.OSTS          3
OSCCON.IOFS          2
OSCCON.SCS1          1
OSCCON.SCS0          0
HLVDCON          0xFD2
HLVDCON.VDIRMAG      7
HLVDCON.IRVST        5
HLVDCON.HLVDEN       4
HLVDCON.HLVDL3       3
HLVDCON.HLVDL2       2
HLVDCON.HLVDL1       1
HLVDCON.HLVDL0       0
WDTCON           0xFD1
WDTCON.SWDTEN        0
RCON             0xFD0
RCON.IPEN            7
RCON.SBOREN          6
RCON.RI              4
RCON.TO              3
RCON.PD              2
RCON.POR             1
RCON.BOR             0
TMR1H            0xFCF
TMR1L            0xFCE
T1CON            0xFCD
T1CON.RD16           7
T1CON.T1RUN          6
T1CON.T1CKPS1        5
T1CON.T1CKPS0        4
T1CON.T1OSCEN        3
T1CON.T1SYNC         2
T1CON.TMR1CS         1
T1CON.TMR1ON         0
TMR2             0xFCC
PR2              0xFCB
T2CON            0xFCA
T2CON.T2OUTPS3       6
T2CON.T2OUTPS2       5
T2CON.T2OUTPS1       4
T2CON.T2OUTPS0       3
T2CON.TMR2ON         2
T2CON.T2CKPS1        1
T2CON.T2CKPS0        0
SSPBUF           0xFC9
SSPADD           0xFC8
SSPSTAT          0xFC7
SSPSTAT.SMP          7
SSPSTAT.CKE          6
SSPSTAT.D_A          5
SSPSTAT.P            4
SSPSTAT.S            3
SSPSTAT.R_W          2
SSPSTAT.UA           1
SSPSTAT.BF           0
SSPCON1          0xFC6
SSPCON1.WCOL         7
SSPCON1.SSPOV        6
SSPCON1.SSPEN        5
SSPCON1.CKP          4
SSPCON1.SSPM3        3
SSPCON1.SSPM2        2
SSPCON1.SSPM1        1
SSPCON1.SSPM0        0
SSPCON2          0xFC5
SSPCON2.GCEN         7
SSPCON2.ACKSTAT      6
SSPCON2.ACKDT        5
SSPCON2.ACKEN        4
SSPCON2.RCEN         3
SSPCON2.PEN          2
SSPCON2.RSEN         1
SSPCON2.SEN          0
ADRESH           0xFC4
ADRESL           0xFC3
ADCON0           0xFC2
ADCON0.CHS3          5
ADCON0.CHS2          4
ADCON0.CHS1          3
ADCON0.CHS0          2
ADCON0.GO_DONE       1
ADCON0.ADON          0
ADCON1           0xFC1
ADCON1.VCFG1         5
ADCON1.VCFG0         4
ADCON1.PCFG3         3
ADCON1.PCFG2         2
ADCON1.PCFG1         1
ADCON1.PCFG0         0
ADCON2           0xFC0
ADCON2.ADFM          7
ADCON2.ACQT2         5
ADCON2.ACQT1         4
ADCON2.ACQT0         3
ADCON2.ADCS2         2
ADCON2.ADCS1         1
ADCON2.ADCS0         0
CCPR1H           0xFBF
CCPR1L           0xFBE
CCP1CON          0xFBD
CCP1CON.P1M1         7
CCP1CON.P1M0         6
CCP1CON.DC1B1        5
CCP1CON.DC1B0        4
CCP1CON.CCP1M3       3
CCP1CON.CCP1M2       2
CCP1CON.CCP1M1       1
CCP1CON.CCP1M0       0
CCPR2H           0xFBC
CCPR2L           0xFBB
CCP2CON          0xFBA
CCP2CON.DC2B1        5
CCP2CON.DC2B0        4
CCP2CON.CCP2M3       3
CCP2CON.CCP2M2       2
CCP2CON.CCP2M1       1
CCP2CON.CCP2M0       0
BAUDCON          0xFB8
BAUDCON.ABDOVF       7
BAUDCON.RCIDL        6
BAUDCON.SCKP         4
BAUDCON.BRG16        3
BAUDCON.WUE          1
BAUDCON.ABDEN        0
PWM1CON          0xFB7
PWM1CON.PRSEN        7
PWM1CON.PDC6         6
PWM1CON.PDC5         5
PWM1CON.PDC4         4
PWM1CON.PDC3         3
PWM1CON.PDC2         2
PWM1CON.PDC1         1
PWM1CON.PDC0         0
ECCP1AS          0xFB6
ECCP1AS.ECCPASE      7
ECCP1AS.ECCPAS2      6
ECCP1AS.ECCPAS1      5
ECCP1AS.ECCPAS0      4
ECCP1AS.PSSAC1       3
ECCP1AS.PSSAC0       2
ECCP1AS.PSSBD1       1
ECCP1AS.PSSBD0       0
CVRCON           0xFB5
CVRCON.CVREN         7
CVRCON.CVROE         6
CVRCON.CVRR          5
CVRCON.CVRSS         4
CVRCON.CVR3          3
CVRCON.CVR2          2
CVRCON.CVR1          1
CVRCON.CVR0          0
CMCON            0xFB4
CMCON.C2OUT          7
CMCON.C1OUT          6
CMCON.C2INV          5
CMCON.C1INV          4
CMCON.CIS            3
CMCON.CM2            2
CMCON.CM1            1
CMCON.CM0            0
TMR3H            0xFB3
TMR3L            0xFB2
T3CON            0xFB1
T3CON.RD16           7
T3CON.T3CCP2         6
T3CON.T3CKPS1        5
T3CON.T3CKPS0        4
T3CON.T3CCP1         3
T3CON.T3SYNC         2
T3CON.TMR3CS         1
T3CON.TMR3ON         0
SPBRGH           0xFB0
SPBRG            0xFAF
RCREG            0xFAE
TXREG            0xFAD
TXSTA            0xFAC
TXSTA.CSRC           7
TXSTA.TX9            6
TXSTA.TXEN           5
TXSTA.SYNC           4
TXSTA.SENDB          3
TXSTA.BRGH           2
TXSTA.TRMT           1
TXSTA.TX9D           0
RCSTA            0xFAB
RCSTA.SPEN           7
RCSTA.RX9            6
RCSTA.SREN           5
RCSTA.CREN           4
RCSTA.ADDEN          3
RCSTA.FERR           2
RCSTA.OERR           1
RCSTA.RX9D           0
EEADRH           0xFAA
EEADR            0xFA9
EEDATA           0xFA8
EECON2           0xFA7
EECON1           0xFA6
EECON1.EEPGD         7
EECON1.CFGS          6
EECON1.FREE          4
EECON1.WRERR         3
EECON1.WREN          2
EECON1.WR            1
EECON1.RD            0
IPR3             0xFA5
PIR3             0xFA4
PIE3             0xFA3
IPR2             0xFA2
IPR2.OSCFIP          7
IPR2.CMIP            6
IPR2.EEIP            4
IPR2.BCLIP           3
IPR2.HLVDIP          2
IPR2.TMR3IP          1
IPR2.CCP2IP          0
PIR2             0xFA1
PIR2.OSCFIF          7
PIR2.CMIF            6
PIR2.EEIF            4
PIR2.BCLIF           3
PIR2.HLVDIF          2
PIR2.TMR3IF          1
PIR2.CCP2IF          0
PIE2             0xFA0
PIE2.OSCFIE          7
PIE2.CMIE            6
PIE2.EEIE            4
PIE2.BCLIE           3
PIE2.HLVDIE          2
PIE2.TMR3IE          1
PIE2.CCP2IE          0
IPR1             0xF9F
IPR1.PSPIP           7
IPR1.ADIP            6
IPR1.RCIP            5
IPR1.TXIP            4
IPR1.SSPIP           3
IPR1.CCP1IP          2
IPR1.TMR2IP          1
IPR1.TMR1IP          0
PIR1             0xF9E
PIR1.PSPIF           7
PIR1.ADIF            6
PIR1.RCIF            5
PIR1.TXIF            4
PIR1.SSPIF           3
PIR1.CCP1IF          2
PIR1.TMR2IF          1
PIR1.TMR1IF          0
PIE1             0xF9D
PIE1.PSPIE           7
PIE1.ADIE            6
PIE1.RCIE            5
PIE1.TXIE            4
PIE1.SSPIE           3
PIE1.CCP1IE          2
PIE1.TMR2IE          1
PIE1.TMR1IE          0
MEMCON           0xF9C
OSCTUNE          0xF9B
OSCTUNE.INTSRC       7
OSCTUNE.PLLEN        6
OSCTUNE.TUN4         4
OSCTUNE.TUN3         3
OSCTUNE.TUN2         2
OSCTUNE.TUN1         1
OSCTUNE.TUN0         0
TRISJ            0xF9A
TRISH            0xF99
TRISG            0xF98
TRISF            0xF97
TRISE            0xF96
TRISE.IBF            7
TRISE.OBF            6
TRISE.IBOV           5
TRISE.PSPMODE        4
TRISE.TRISE2         2
TRISE.TRISE1         1
TRISE.TRISE0         0
TRISD            0xF95
TRISC            0xF94
TRISB            0xF93
TRISA            0xF92
LATJ             0xF91
LATH             0xF90
LATG             0xF8F
LATF             0xF8E
LATE             0xF8D
LATD             0xF8C
LATC             0xF8B
LATB             0xF8A
LATA             0xF89
PORTJ            0xF88
PORTH            0xF87
PORTG            0xF86
PORTF            0xF85
PORTE            0xF84
PORTE.RE3            3
PORTE.RE2            2
PORTE.RE1            1
PORTE.RE0            0
PORTD            0xF83
PORTD.RD7            7
PORTD.RD6            6
PORTD.RD5            5
PORTD.RD4            4
PORTD.RD3            3
PORTD.RD2            2
PORTD.RD1            1
PORTD.RD0            0
PORTC            0xF82
PORTC.RC7            7
PORTC.RC6            6
PORTC.RC5            5
PORTC.RC4            4
PORTC.RC3            3
PORTC.RC2            2
PORTC.RC1            1
PORTC.RC0            0
PORTB            0xF81
PORTB.RB7            7
PORTB.RB6            6
PORTB.RB5            5
PORTB.RB4            4
PORTB.RB3            3
PORTB.RB2            2
PORTB.RB1            1
PORTB.RB0            0
PORTA            0xF80
PORTA.RA7            7
PORTA.RA6            6
PORTA.RA5            5
PORTA.RA4            4
PORTA.RA3            3
PORTA.RA2            2
PORTA.RA1            1
PORTA.RA0            0

; Interrupt and reset vector assignments
entry RESET      0x0000     RESET
entry HI_ISR     0x0008     High-Priority Interrupt
entry LO_ISR     0x0018     Low-Priority Interrupt

; http://ww1.microchip.com/downloads/en/DeviceDoc/39631a.pdf
; PIC18F2420/2520/4420/4520

.18F2520

; MEMORY MAP
area CODE ROM  0x0000:0x8000  On-chip Program Memory
area DATA RAM  0x0000:0x0600  SRAM Data Memory
area DATA FSR_ 0x0F80:0x1000  Function Special Registers

; http://ww1.microchip.com/downloads/en/DeviceDoc/39626e.pdf
; PIC18F2525/2620/4525/4620

.18F2525

; MEMORY MAP
area CODE ROM  0x0000:0x6000  On-chip Program Memory
area DATA RAM  0x0000:0x0F80  SRAM Data Memory
area DATA FSR_ 0x0F80:0x1000  Function Special Registers

.18F4525

; MEMORY MAP
area CODE ROM  0x0000:0x6000  On-chip Program Memory
area DATA RAM  0x0000:0x0F80  SRAM Data Memory
area DATA FSR_ 0x0F80:0x1000  Function Special Registers

.18F2620

; MEMORY MAP
area CODE ROM  0x0000:0x8000  On-chip Program Memory
area DATA RAM  0x0000:0x0F80  SRAM Data Memory
area DATA FSR_ 0x0F80:0x1000  Function Special Registers

.18F4620

; MEMORY MAP
area CODE ROM  0x0000:0x10000  On-chip Program Memory
area DATA RAM  0x0000:0x0F80  SRAM Data Memory
area DATA FSR_ 0x0F80:0x1000  Function Special Registers

.18F2455

; MEMORY MAP
area CODE ROM  0x0000:0xC000  On-chip Program Memory
area DATA RAM  0x0000:0x0800  SRAM Data Memory
area DATA FSR_ 0x0F80:0x1000  Function Special Registers

.18F2550

; MEMORY MAP
area CODE ROM  0x0000:0x10000  On-chip Program Memory
area DATA RAM  0x0000:0x0800  SRAM Data Memory
area DATA FSR_ 0x0F80:0x1000  Function Special Registers

.18F4455

; MEMORY MAP
area CODE ROM  0x0000:0xC000  On-chip Program Memory
area DATA RAM  0x0000:0x0800  SRAM Data Memory
area DATA FSR_ 0x0F80:0x1000  Function Special Registers

.18F4550

; MEMORY MAP
area CODE ROM  0x0000:0x10000  On-chip Program Memory
area DATA RAM  0x0000:0x0800  SRAM Data Memory
area DATA FSR_ 0x0F80:0x1000  Function Special Registers

; http://ww1.microchip.com/downloads/en/DeviceDoc/39761c.pdf
; PIC18F2682/2685/4682/4685

.18F2682

; MEMORY MAP
area CODE ROM  0x0000:0x14000  On-chip Program Memory
area DATA RAM  0x0000:0x0D00   SRAM Data Memory
area DATA FSR_ 0x0D00:0x1000   Function Special Registers

.18F2685

; MEMORY MAP
area CODE ROM  0x0000:0x18000  On-chip Program Memory
area DATA RAM  0x0000:0x0D00   SRAM Data Memory
area DATA FSR_ 0x0D00:0x1000   Function Special Registers

.18F4682

; MEMORY MAP
area CODE ROM  0x0000:0x14000  On-chip Program Memory
area DATA RAM  0x0000:0x0D00   SRAM Data Memory
area DATA FSR_ 0x0D00:0x1000   Function Special Registers

.18F4685

; MEMORY MAP
area CODE ROM  0x0000:0x18000  On-chip Program Memory
area DATA RAM  0x0000:0x0D00   SRAM Data Memory
area DATA FSR_ 0x0D00:0x1000   Function Special Registers

; http://ww1.microchip.com/downloads/en/DeviceDoc/39646c.pdf
; PIC18F6527/18F6622/18F6627/18F6722/18F8527/18F8622/18F8627/18F8722

.18F6722

; MEMORY MAP
area CODE ROM  0x0000:0x200000  On-chip Program Memory
area DATA RAM  0x0000:0x0F60    SRAM Data Memory
area DATA FSR_ 0x0F60:0x1000    Function Special Registers

.18F8722

; MEMORY MAP
area CODE ROM  0x0000:0x200000  On-chip Program Memory
area DATA RAM  0x0000:0x0F60    SRAM Data Memory
area DATA FSR_ 0x0F60:0x1000    Function Special Registers

.18F6627

; MEMORY MAP
area CODE ROM  0x0000:0x180000  On-chip Program Memory
area DATA RAM  0x0000:0x0F60    SRAM Data Memory
area DATA FSR_ 0x0F60:0x1000    Function Special Registers

.18F8627

; MEMORY MAP
area CODE ROM  0x0000:0x180000  On-chip Program Memory
area DATA RAM  0x0000:0x0F60    SRAM Data Memory
area DATA FSR_ 0x0F60:0x1000    Function Special Registers

.18F6622

; MEMORY MAP
area CODE ROM  0x0000:0x10000   On-chip Program Memory
area DATA RAM  0x0000:0x0F60    SRAM Data Memory
area DATA FSR_ 0x0F60:0x1000    Function Special Registers

.18F8622

; MEMORY MAP
area CODE ROM  0x0000:0x10000   On-chip Program Memory
area DATA RAM  0x0000:0x0F60    SRAM Data Memory
area DATA FSR_ 0x0F60:0x1000    Function Special Registers

.18F6527

; MEMORY MAP
area CODE ROM  0x0000:0xC000    On-chip Program Memory
area DATA RAM  0x0000:0x0F60    SRAM Data Memory
area DATA FSR_ 0x0F60:0x1000    Function Special Registers

.18F8527

; MEMORY MAP
area CODE ROM  0x0000:0xC000    On-chip Program Memory
area DATA RAM  0x0000:0x0F60    SRAM Data Memory
area DATA FSR_ 0x0F60:0x1000    Function Special Registers

; http://ww1.microchip.com/downloads/en/DeviceDoc/30491c.pdf
; PIC18F6585/8585/6680/8680

.18F6585

; MEMORY MAP
area CODE ROM    0x0000:0xC000    On-chip Program Memory
area DATA RAM    0x0000:0x0D00    SRAM Data Memory
area DATA CANFSR 0x0D00:0x0F60    Function Special Registers
area DATA FSR_   0x0F60:0x1000    Function Special Registers

.18F8585

; MEMORY MAP
area CODE ROM    0x0000:0xC000    On-chip Program Memory
area DATA RAM    0x0000:0x0D00    SRAM Data Memory
area DATA CANFSR 0x0D00:0x0F60    Function Special Registers
area DATA FSR_   0x0F60:0x1000    Function Special Registers

.18F6680

; MEMORY MAP
area CODE ROM    0x0000:0x10000   On-chip Program Memory
area DATA RAM    0x0000:0x0D00    SRAM Data Memory
area DATA CANFSR 0x0D00:0x0F60    Function Special Registers
area DATA FSR_   0x0F60:0x1000    Function Special Registers

.18F8680

; MEMORY MAP
area CODE ROM    0x0000:0x10000   On-chip Program Memory
area DATA RAM    0x0000:0x0D00    SRAM Data Memory
area DATA CANFSR 0x0D00:0x0F60    Function Special Registers
area DATA FSR_   0x0F60:0x1000    Function Special Registers

```
