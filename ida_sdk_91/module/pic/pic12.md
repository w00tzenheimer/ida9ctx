```ini
;
; This file defines SFR names and bit names for Microchip's PIC 12 bit processors.
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
;
; It is allowed to have several mappings for the same port. For example:
;
; STATUS     0x03
; STATUS     0x83
; STATUS     0x103
; STATUS     0x183
;
; In this case IDA will redirect all memory references to the first definition.
; (all references to 0x83, 0x103, 0x183 will be rerouted to 0x03)
;

.default 12CE519

.12C508
; http://www.microchip.com/download/lit/pline/picmicro/families/12c5xx/40139e.pdf
; PIC12C5xx.pdf


; MEMORY MAP
area DATA FSR_           0x0000:0x0020
area CODE MEM_Program    0x0020:0x0200   On-chip Program Memory


; Interrupt and reset vector assignments
entry RESET      0x0000     RESET


; INPUT/OUTPUT PORTS
INDF            0x0000   Uses contents of FSR to address data memory (not a physical register)
TMR0            0x0001   8-bit real-time clock/counter
PCL             0x0002   Low order 8 bits of Program Counter register
STATUS          0x0003   STATUS REGISTER
STATUS.GPWUF     7   GPIO reset bit
STATUS.PA0       5   Program page preselect bits
STATUS.TO        4   Time-out bit
STATUS.PD        3   Power-down bit
STATUS.Z         2   Zero bit
STATUS.DC        1   Digit carry/borrow bit (for ADDWF and SUBWF instructions)
STATUS.C         0   Carry/borrow bit (for ADDWF, SUBWF and RRF, RLF instructions)
FSR             0x0004   Indirect data memory address pointer
OSCCAL          0x0005   Oscillator Calibration register
OSCCAL.CAL3      7   Calibration 3
OSCCAL.CAL2      6   Calibration 2
OSCCAL.CAL1      5   Calibration 1
OSCCAL.CAL0      4   Calibration 0
GPIO            0x0006   GPIO register
GPIO.GP5         5
GPIO.GP4         4
GPIO.GP3         3
GPIO.GP2         2
GPIO.GP1         1
GPIO.GP0         0
R0              0x0007   General Purpose Register 0
R1              0x0008   General Purpose Register 1
R2              0x0009   General Purpose Register 2
R3              0x000A   General Purpose Register 3
R4              0x000B   General Purpose Register 4
R5              0x000C   General Purpose Register 5
R6              0x000D   General Purpose Register 6
R7              0x000E   General Purpose Register 7
R8              0x000F   General Purpose Register 8
R9              0x0010   General Purpose Register 9
R10             0x0011   General Purpose Register 10
R11             0x0012   General Purpose Register 11
R12             0x0013   General Purpose Register 12
R13             0x0014   General Purpose Register 13
R14             0x0015   General Purpose Register 14
R15             0x0016   General Purpose Register 15
R16             0x0017   General Purpose Register 16
R17             0x0018   General Purpose Register 17
R18             0x0019   General Purpose Register 18
R19             0x001A   General Purpose Register 19
R20             0x001B   General Purpose Register 20
R21             0x001C   General Purpose Register 21
R22             0x001D   General Purpose Register 22
R23             0x001E   General Purpose Register 23
R24             0x001F   General Purpose Register 24


.12C508A
; http://www.microchip.com/download/lit/pline/picmicro/families/12c5xx/40139e.pdf
; PIC12C5xx.pdf


; MEMORY MAP
area DATA FSR_           0x0000:0x0020
area CODE MEM_Program    0x0020:0x0200   On-chip Program Memory


; Interrupt and reset vector assignments
entry RESET      0x0000     RESET


; INPUT/OUTPUT PORTS
INDF            0x0000   Uses contents of FSR to address data memory (not a physical register)
TMR0            0x0001   8-bit real-time clock/counter
PCL             0x0002   Low order 8 bits of Program Counter register
STATUS          0x0003   STATUS REGISTER
STATUS.GPWUF     7   GPIO reset bit
STATUS.PA0       5   Program page preselect bits
STATUS.TO        4   Time-out bit
STATUS.PD        3   Power-down bit
STATUS.Z         2   Zero bit
STATUS.DC        1   Digit carry/borrow bit (for ADDWF and SUBWF instructions)
STATUS.C         0   Carry/borrow bit (for ADDWF, SUBWF and RRF, RLF instructions)
FSR             0x0004   Indirect data memory address pointer
OSCCAL          0x0005   Oscillator Calibration register
OSCCAL.CAL3      7   Calibration 3
OSCCAL.CAL2      6   Calibration 2
OSCCAL.CAL1      5   Calibration 1
OSCCAL.CAL0      4   Calibration 0
GPIO            0x0006   GPIO register
GPIO.GP5         5
GPIO.GP4         4
GPIO.GP3         3
GPIO.GP2         2
GPIO.GP1         1
GPIO.GP0         0
R0              0x0007   General Purpose Register 0
R1              0x0008   General Purpose Register 1
R2              0x0009   General Purpose Register 2
R3              0x000A   General Purpose Register 3
R4              0x000B   General Purpose Register 4
R5              0x000C   General Purpose Register 5
R6              0x000D   General Purpose Register 6
R7              0x000E   General Purpose Register 7
R8              0x000F   General Purpose Register 8
R9              0x0010   General Purpose Register 9
R10             0x0011   General Purpose Register 10
R11             0x0012   General Purpose Register 11
R12             0x0013   General Purpose Register 12
R13             0x0014   General Purpose Register 13
R14             0x0015   General Purpose Register 14
R15             0x0016   General Purpose Register 15
R16             0x0017   General Purpose Register 16
R17             0x0018   General Purpose Register 17
R18             0x0019   General Purpose Register 18
R19             0x001A   General Purpose Register 19
R20             0x001B   General Purpose Register 20
R21             0x001C   General Purpose Register 21
R22             0x001D   General Purpose Register 22
R23             0x001E   General Purpose Register 23
R24             0x001F   General Purpose Register 24


.12C509
; http://www.microchip.com/download/lit/pline/picmicro/families/12c5xx/40139e.pdf
; PIC12C5xx.pdf


; MEMORY MAP
; BANK_0
area DATA FSR_           0x0000:0x0020
area CODE MEM_Program    0x0020:0x0400   On-chip Program Memory

; BANK_1
; area DATA FSR_           0x0020:0x0040
; area CODE MEM_Program    0x0040:0x0400   On-chip Program Memory


; Interrupt and reset vector assignments
entry RESET      0x0000     RESET


; INPUT/OUTPUT PORTS
; BANK0 (0x0000:0x0020)
BANK0:INDF            0x0000   Uses contents of FSR to address data memory (not a physical register)
BANK0:TMR0            0x0001   8-bit real-time clock/counter
BANK0:PCL             0x0002   Low order 8 bits of Program Counter register
BANK0:STATUS          0x0003   STATUS REGISTER
BANK0:STATUS.GPWUF     7   GPIO reset bit
BANK0:STATUS.PA0       5   Program page preselect bits
BANK0:STATUS.TO        4   Time-out bit
BANK0:STATUS.PD        3   Power-down bit
BANK0:STATUS.Z         2   Zero bit
BANK0:STATUS.DC        1   Digit carry/borrow bit (for ADDWF and SUBWF instructions)
BANK0:STATUS.C         0   Carry/borrow bit (for ADDWF, SUBWF and RRF, RLF instructions)
BANK0:FSR             0x0004   Indirect data memory address pointer
BANK0:OSCCAL          0x0005   Oscillator Calibration register
BANK0:OSCCAL.CAL3      7   Calibration 3
BANK0:OSCCAL.CAL2      6   Calibration 2
BANK0:OSCCAL.CAL1      5   Calibration 1
BANK0:OSCCAL.CAL0      4   Calibration 0
BANK0:GPIO            0x0006   GPIO register
BANK0:GPIO.GP5         5
BANK0:GPIO.GP4         4
BANK0:GPIO.GP3         3
BANK0:GPIO.GP2         2
BANK0:GPIO.GP1         1
BANK0:GPIO.GP0         0
BANK0:R0              0x0007   General Purpose Register 0  (Bank 0)
BANK0:R1              0x0008   General Purpose Register 1  (Bank 0)
BANK0:R2              0x0009   General Purpose Register 2  (Bank 0)
BANK0:R3              0x000A   General Purpose Register 3  (Bank 0)
BANK0:R4              0x000B   General Purpose Register 4  (Bank 0)
BANK0:R5              0x000C   General Purpose Register 5  (Bank 0)
BANK0:R6              0x000D   General Purpose Register 6  (Bank 0)
BANK0:R7              0x000E   General Purpose Register 7  (Bank 0)
BANK0:R8              0x000F   General Purpose Register 8  (Bank 0)
BANK0:R9              0x0010   General Purpose Register 9  (Bank 0)
BANK0:R10             0x0011   General Purpose Register 10  (Bank 0)
BANK0:R11             0x0012   General Purpose Register 11  (Bank 0)
BANK0:R12             0x0013   General Purpose Register 12  (Bank 0)
BANK0:R13             0x0014   General Purpose Register 13  (Bank 0)
BANK0:R14             0x0015   General Purpose Register 14  (Bank 0)
BANK0:R15             0x0016   General Purpose Register 15  (Bank 0)
BANK0:R16             0x0017   General Purpose Register 16  (Bank 0)
BANK0:R17             0x0018   General Purpose Register 17  (Bank 0)
BANK0:R18             0x0019   General Purpose Register 18  (Bank 0)
BANK0:R19             0x001A   General Purpose Register 19  (Bank 0)
BANK0:R20             0x001B   General Purpose Register 20  (Bank 0)
BANK0:R21             0x001C   General Purpose Register 21  (Bank 0)
BANK0:R22             0x001D   General Purpose Register 22  (Bank 0)
BANK0:R23             0x001E   General Purpose Register 23  (Bank 0)
BANK0:R24             0x001F   General Purpose Register 24  (Bank 0)

; BANK1 (0x0020:0x0040)
BANK1:INDF            0x0020   Uses contents of FSR to address data memory (not a physical register)
BANK1:TMR0            0x0021   8-bit real-time clock/counter
BANK1:PCL             0x0022   Low order 8 bits of Program Counter register
BANK1:STATUS          0x0023   STATUS REGISTER
BANK1:STATUS.GPWUF     7   GPIO reset bit
BANK1:STATUS.PA0       5   Program page preselect bits
BANK1:STATUS.TO        4   Time-out bit
BANK1:STATUS.PD        3   Power-down bit
BANK1:STATUS.Z         2   Zero bit
BANK1:STATUS.DC        1   Digit carry/borrow bit (for ADDWF and SUBWF instructions)
BANK1:STATUS.C         0   Carry/borrow bit (for ADDWF, SUBWF and RRF, RLF instructions)
BANK1:FSR             0x0024   Indirect data memory address pointer
BANK1:OSCCAL          0x0025   Oscillator Calibration register
BANK1:OSCCAL.CAL3      7   Calibration 3
BANK1:OSCCAL.CAL2      6   Calibration 2
BANK1:OSCCAL.CAL1      5   Calibration 1
BANK1:OSCCAL.CAL0      4   Calibration 0
BANK1:GPIO            0x0026   GPIO register
BANK1:GPIO.GP5         5
BANK1:GPIO.GP4         4
BANK1:GPIO.GP3         3
BANK1:GPIO.GP2         2
BANK1:GPIO.GP1         1
BANK1:GPIO.GP0         0
BANK1:R0              0x0027   General Purpose Register 0
BANK1:R1              0x0028   General Purpose Register 1
BANK1:R2              0x0029   General Purpose Register 2
BANK1:R3              0x002A   General Purpose Register 3
BANK1:R4              0x002B   General Purpose Register 4
BANK1:R5              0x002C   General Purpose Register 5
BANK1:R6              0x002D   General Purpose Register 6
BANK1:R7              0x002E   General Purpose Register 7
BANK1:R8              0x002F   General Purpose Register 8
BANK1:R25             0x0030   General Purpose Register 25
BANK1:R26             0x0031   General Purpose Register 26
BANK1:R27             0x0032   General Purpose Register 27
BANK1:R28             0x0033   General Purpose Register 28
BANK1:R29             0x0034   General Purpose Register 29
BANK1:R30             0x0035   General Purpose Register 30
BANK1:R31             0x0036   General Purpose Register 31
BANK1:R32             0x0037   General Purpose Register 32
BANK1:R33             0x0038   General Purpose Register 33
BANK1:R34             0x0039   General Purpose Register 34
BANK1:R35             0x003A   General Purpose Register 35
BANK1:R36             0x003B   General Purpose Register 36
BANK1:R37             0x003C   General Purpose Register 37
BANK1:R38             0x003D   General Purpose Register 38
BANK1:R39             0x003E   General Purpose Register 39
BANK1:R40             0x003F   General Purpose Register 40


.12C509A
; http://www.microchip.com/download/lit/pline/picmicro/families/12c5xx/40139e.pdf
; PIC12C5xx.pdf


; MEMORY MAP
; BANK_0
area DATA FSR_           0x0000:0x0020
area CODE MEM_Program    0x0020:0x0400   On-chip Program Memory

; BANK_1
; area DATA FSR_           0x0020:0x0040
; area CODE MEM_Program    0x0040:0x0400   On-chip Program Memory


; Interrupt and reset vector assignments
entry RESET      0x0000     RESET


; INPUT/OUTPUT PORTS
; BANK_0 (0x0000:0x0020)
BANK0:INDF            0x0000   Uses contents of FSR to address data memory (not a physical register)
BANK0:TMR0            0x0001   8-bit real-time clock/counter
BANK0:PCL             0x0002   Low order 8 bits of Program Counter register
BANK0:STATUS          0x0003   STATUS REGISTER
BANK0:STATUS.GPWUF     7   GPIO reset bit
BANK0:STATUS.PA0       5   Program page preselect bits
BANK0:STATUS.TO        4   Time-out bit
BANK0:STATUS.PD        3   Power-down bit
BANK0:STATUS.Z         2   Zero bit
BANK0:STATUS.DC        1   Digit carry/borrow bit (for ADDWF and SUBWF instructions)
BANK0:STATUS.C         0   Carry/borrow bit (for ADDWF, SUBWF and RRF, RLF instructions)
BANK0:FSR             0x0004   Indirect data memory address pointer
BANK0:OSCCAL          0x0005   Oscillator Calibration register
BANK0:OSCCAL.CAL3      7   Calibration 3
BANK0:OSCCAL.CAL2      6   Calibration 2
BANK0:OSCCAL.CAL1      5   Calibration 1
BANK0:OSCCAL.CAL0      4   Calibration 0
BANK0:GPIO            0x0006   GPIO register
BANK0:GPIO.GP5         5
BANK0:GPIO.GP4         4
BANK0:GPIO.GP3         3
BANK0:GPIO.GP2         2
BANK0:GPIO.GP1         1
BANK0:GPIO.GP0         0
BANK0:R0              0x0007   General Purpose Register 0
BANK0:R1              0x0008   General Purpose Register 1
BANK0:R2              0x0009   General Purpose Register 2
BANK0:R3              0x000A   General Purpose Register 3
BANK0:R4              0x000B   General Purpose Register 4
BANK0:R5              0x000C   General Purpose Register 5
BANK0:R6              0x000D   General Purpose Register 6
BANK0:R7              0x000E   General Purpose Register 7
BANK0:R8              0x000F   General Purpose Register 8
BANK0:R9              0x0010   General Purpose Register 9
BANK0:R10             0x0011   General Purpose Register 10
BANK0:R11             0x0012   General Purpose Register 11
BANK0:R12             0x0013   General Purpose Register 12
BANK0:R13             0x0014   General Purpose Register 13
BANK0:R14             0x0015   General Purpose Register 14
BANK0:R15             0x0016   General Purpose Register 15
BANK0:R16             0x0017   General Purpose Register 16
BANK0:R17             0x0018   General Purpose Register 17
BANK0:R18             0x0019   General Purpose Register 18
BANK0:R19             0x001A   General Purpose Register 19
BANK0:R20             0x001B   General Purpose Register 20
BANK0:R21             0x001C   General Purpose Register 21
BANK0:R22             0x001D   General Purpose Register 22
BANK0:R23             0x001E   General Purpose Register 23
BANK0:R24             0x001F   General Purpose Register 24

; BANK_1 (0x0020:0x0040)
BANK1:INDF            0x0020   Uses contents of FSR to address data memory (not a physical register)
BANK1:TMR0            0x0021   8-bit real-time clock/counter
BANK1:PCL             0x0022   Low order 8 bits of Program Counter register
BANK1:STATUS          0x0023   STATUS REGISTER
BANK1:STATUS.GPWUF     7   GPIO reset bit
BANK1:STATUS.PA0       5   Program page preselect bits
BANK1:STATUS.TO        4   Time-out bit
BANK1:STATUS.PD        3   Power-down bit
BANK1:STATUS.Z         2   Zero bit
BANK1:STATUS.DC        1   Digit carry/borrow bit (for ADDWF and SUBWF instructions)
BANK1:STATUS.C         0   Carry/borrow bit (for ADDWF, SUBWF and RRF, RLF instructions)
BANK1:FSR             0x0024   Indirect data memory address pointer
BANK1:OSCCAL          0x0025   Oscillator Calibration register
BANK1:OSCCAL.CAL3      7   Calibration 3
BANK1:OSCCAL.CAL2      6   Calibration 2
BANK1:OSCCAL.CAL1      5   Calibration 1
BANK1:OSCCAL.CAL0      4   Calibration 0
BANK1:GPIO            0x0026   GPIO register
BANK1:GPIO.GP5         5
BANK1:GPIO.GP4         4
BANK1:GPIO.GP3         3
BANK1:GPIO.GP2         2
BANK1:GPIO.GP1         1
BANK1:GPIO.GP0         0
BANK1:R0              0x0027   General Purpose Register 0
BANK1:R1              0x0028   General Purpose Register 1
BANK1:R2              0x0029   General Purpose Register 2
BANK1:R3              0x002A   General Purpose Register 3
BANK1:R4              0x002B   General Purpose Register 4
BANK1:R5              0x002C   General Purpose Register 5
BANK1:R6              0x002D   General Purpose Register 6
BANK1:R7              0x002E   General Purpose Register 7
BANK1:R8              0x002F   General Purpose Register 8
BANK1:R25             0x0030   General Purpose Register 25
BANK1:R26             0x0031   General Purpose Register 26
BANK1:R27             0x0032   General Purpose Register 27
BANK1:R28             0x0033   General Purpose Register 28
BANK1:R29             0x0034   General Purpose Register 29
BANK1:R30             0x0035   General Purpose Register 30
BANK1:R31             0x0036   General Purpose Register 31
BANK1:R32             0x0037   General Purpose Register 32
BANK1:R33             0x0038   General Purpose Register 33
BANK1:R34             0x0039   General Purpose Register 34
BANK1:R35             0x003A   General Purpose Register 35
BANK1:R36             0x003B   General Purpose Register 36
BANK1:R37             0x003C   General Purpose Register 37
BANK1:R38             0x003D   General Purpose Register 38
BANK1:R39             0x003E   General Purpose Register 39
BANK1:R40             0x003F   General Purpose Register 40


.12CE518
; http://www.microchip.com/download/lit/pline/picmicro/families/12c5xx/40139e.pdf
; PIC12C5xx.pdf


; MEMORY MAP
area DATA FSR_           0x0000:0x0020
area CODE MEM_Program    0x0020:0x0200   On-chip Program Memory


; Interrupt and reset vector assignments
entry RESET      0x0000     RESET


; INPUT/OUTPUT PORTS
INDF            0x0000   Uses contents of FSR to address data memory (not a physical register)
TMR0            0x0001   8-bit real-time clock/counter
PCL             0x0002   Low order 8 bits of Program Counter register
STATUS          0x0003   STATUS REGISTER
STATUS.GPWUF     7   GPIO reset bit
STATUS.PA0       5   Program page preselect bits
STATUS.TO        4   Time-out bit
STATUS.PD        3   Power-down bit
STATUS.Z         2   Zero bit
STATUS.DC        1   Digit carry/borrow bit (for ADDWF and SUBWF instructions)
STATUS.C         0   Carry/borrow bit (for ADDWF, SUBWF and RRF, RLF instructions)
FSR             0x0004   Indirect data memory address pointer
OSCCAL          0x0005   Oscillator Calibration register
OSCCAL.CAL3      7   Calibration 3
OSCCAL.CAL2      6   Calibration 2
OSCCAL.CAL1      5   Calibration 1
OSCCAL.CAL0      4   Calibration 0
GPIO            0x0006   GPIO register
GPIO.GP5         5
GPIO.GP4         4
GPIO.GP3         3
GPIO.GP2         2
GPIO.GP1         1
GPIO.GP0         0
R0              0x0007   General Purpose Register 0
R1              0x0008   General Purpose Register 1
R2              0x0009   General Purpose Register 2
R3              0x000A   General Purpose Register 3
R4              0x000B   General Purpose Register 4
R5              0x000C   General Purpose Register 5
R6              0x000D   General Purpose Register 6
R7              0x000E   General Purpose Register 7
R8              0x000F   General Purpose Register 8
R9              0x0010   General Purpose Register 9
R10             0x0011   General Purpose Register 10
R11             0x0012   General Purpose Register 11
R12             0x0013   General Purpose Register 12
R13             0x0014   General Purpose Register 13
R14             0x0015   General Purpose Register 14
R15             0x0016   General Purpose Register 15
R16             0x0017   General Purpose Register 16
R17             0x0018   General Purpose Register 17
R18             0x0019   General Purpose Register 18
R19             0x001A   General Purpose Register 19
R20             0x001B   General Purpose Register 20
R21             0x001C   General Purpose Register 21
R22             0x001D   General Purpose Register 22
R23             0x001E   General Purpose Register 23
R24             0x001F   General Purpose Register 24


.12CE519
; http://www.microchip.com/download/lit/pline/picmicro/families/12c5xx/40139e.pdf
; PIC12C5xx.pdf


; MEMORY MAP
; BANK_0
area DATA FSR_           0x0000:0x0020
area CODE MEM_Program    0x0020:0x0400   On-chip Program Memory

; BANK_1
; area DATA FSR_           0x0020:0x0040
; area CODE MEM_Program    0x0040:0x0400   On-chip Program Memory


; Interrupt and reset vector assignments
entry RESET      0x0000     RESET


; INPUT/OUTPUT PORTS
; BANK_0 (0x0000:0x0020)
BANK0:INDF            0x0000   Uses contents of FSR to address data memory (not a physical register)
BANK0:TMR0            0x0001   8-bit real-time clock/counter
BANK0:PCL             0x0002   Low order 8 bits of Program Counter register
BANK0:STATUS          0x0003   STATUS REGISTER
BANK0:STATUS.GPWUF     7   GPIO reset bit
BANK0:STATUS.PA0       5   Program page preselect bits
BANK0:STATUS.TO        4   Time-out bit
BANK0:STATUS.PD        3   Power-down bit
BANK0:STATUS.Z         2   Zero bit
BANK0:STATUS.DC        1   Digit carry/borrow bit (for ADDWF and SUBWF instructions)
BANK0:STATUS.C         0   Carry/borrow bit (for ADDWF, SUBWF and RRF, RLF instructions)
BANK0:FSR             0x0004   Indirect data memory address pointer
BANK0:OSCCAL          0x0005   Oscillator Calibration register
BANK0:OSCCAL.CAL3      7   Calibration 3
BANK0:OSCCAL.CAL2      6   Calibration 2
BANK0:OSCCAL.CAL1      5   Calibration 1
BANK0:OSCCAL.CAL0      4   Calibration 0
BANK0:GPIO            0x0006   GPIO register
BANK0:GPIO.GP5         5
BANK0:GPIO.GP4         4
BANK0:GPIO.GP3         3
BANK0:GPIO.GP2         2
BANK0:GPIO.GP1         1
BANK0:GPIO.GP0         0
BANK0:R0              0x0007   General Purpose Register 0
BANK0:R1              0x0008   General Purpose Register 1
BANK0:R2              0x0009   General Purpose Register 2
BANK0:R3              0x000A   General Purpose Register 3
BANK0:R4              0x000B   General Purpose Register 4
BANK0:R5              0x000C   General Purpose Register 5
BANK0:R6              0x000D   General Purpose Register 6
BANK0:R7              0x000E   General Purpose Register 7
BANK0:R8              0x000F   General Purpose Register 8
BANK0:R9              0x0010   General Purpose Register 9
BANK0:R10             0x0011   General Purpose Register 10
BANK0:R11             0x0012   General Purpose Register 11
BANK0:R12             0x0013   General Purpose Register 12
BANK0:R13             0x0014   General Purpose Register 13
BANK0:R14             0x0015   General Purpose Register 14
BANK0:R15             0x0016   General Purpose Register 15
BANK0:R16             0x0017   General Purpose Register 16
BANK0:R17             0x0018   General Purpose Register 17
BANK0:R18             0x0019   General Purpose Register 18
BANK0:R19             0x001A   General Purpose Register 19
BANK0:R20             0x001B   General Purpose Register 20
BANK0:R21             0x001C   General Purpose Register 21
BANK0:R22             0x001D   General Purpose Register 22
BANK0:R23             0x001E   General Purpose Register 23
BANK0:R24             0x001F   General Purpose Register 24

; BANK_1 (0x0020:0x0040)
BANK1:INDF            0x0020   Uses contents of FSR to address data memory (not a physical register)
BANK1:TMR0            0x0021   8-bit real-time clock/counter
BANK1:PCL             0x0022   Low order 8 bits of Program Counter register
BANK1:STATUS          0x0023   STATUS REGISTER
BANK1:STATUS.GPWUF     7   GPIO reset bit
BANK1:STATUS.PA0       5   Program page preselect bits
BANK1:STATUS.TO        4   Time-out bit
BANK1:STATUS.PD        3   Power-down bit
BANK1:STATUS.Z         2   Zero bit
BANK1:STATUS.DC        1   Digit carry/borrow bit (for ADDWF and SUBWF instructions)
BANK1:STATUS.C         0   Carry/borrow bit (for ADDWF, SUBWF and RRF, RLF instructions)
BANK1:FSR             0x0024   Indirect data memory address pointer
BANK1:OSCCAL          0x0025   Oscillator Calibration register
BANK1:OSCCAL.CAL3      7   Calibration 3
BANK1:OSCCAL.CAL2      6   Calibration 2
BANK1:OSCCAL.CAL1      5   Calibration 1
BANK1:OSCCAL.CAL0      4   Calibration 0
BANK1:GPIO            0x0026   GPIO register
BANK1:GPIO.GP5         5
BANK1:GPIO.GP4         4
BANK1:GPIO.GP3         3
BANK1:GPIO.GP2         2
BANK1:GPIO.GP1         1
BANK1:GPIO.GP0         0
BANK1:R0              0x0027   General Purpose Register 0
BANK1:R1              0x0028   General Purpose Register 1
BANK1:R2              0x0029   General Purpose Register 2
BANK1:R3              0x002A   General Purpose Register 3
BANK1:R4              0x002B   General Purpose Register 4
BANK1:R5              0x002C   General Purpose Register 5
BANK1:R6              0x002D   General Purpose Register 6
BANK1:R7              0x002E   General Purpose Register 7
BANK1:R8              0x002F   General Purpose Register 8
BANK1:R25             0x0030   General Purpose Register 25
BANK1:R26             0x0031   General Purpose Register 26
BANK1:R27             0x0032   General Purpose Register 27
BANK1:R28             0x0033   General Purpose Register 28
BANK1:R29             0x0034   General Purpose Register 29
BANK1:R30             0x0035   General Purpose Register 30
BANK1:R31             0x0036   General Purpose Register 31
BANK1:R32             0x0037   General Purpose Register 32
BANK1:R33             0x0038   General Purpose Register 33
BANK1:R34             0x0039   General Purpose Register 34
BANK1:R35             0x003A   General Purpose Register 35
BANK1:R36             0x003B   General Purpose Register 36
BANK1:R37             0x003C   General Purpose Register 37
BANK1:R38             0x003D   General Purpose Register 38
BANK1:R39             0x003E   General Purpose Register 39
BANK1:R40             0x003F   General Purpose Register 40


.12CR509A
; http://www.microchip.com/download/lit/pline/picmicro/families/12c5xx/40139e.pdf
; PIC12C5xx.pdf


; MEMORY MAP
; BANK_0
area DATA FSR_           0x0000:0x0020
area CODE MEM_Program    0x0020:0x0400   On-chip Program Memory

; BANK_1
; area DATA FSR_           0x0020:0x0040
; area CODE MEM_Program    0x0040:0x0400   On-chip Program Memory


; Interrupt and reset vector assignments
entry RESET      0x0000     RESET


; INPUT/OUTPUT PORTS
; BANK_0 (0x0000:0x0020)
BANK0:INDF            0x0000   Uses contents of FSR to address data memory (not a physical register)
BANK0:TMR0            0x0001   8-bit real-time clock/counter
BANK0:PCL             0x0002   Low order 8 bits of Program Counter register
BANK0:STATUS          0x0003   STATUS REGISTER
BANK0:STATUS.GPWUF     7   GPIO reset bit
BANK0:STATUS.PA0       5   Program page preselect bits
BANK0:STATUS.TO        4   Time-out bit
BANK0:STATUS.PD        3   Power-down bit
BANK0:STATUS.Z         2   Zero bit
BANK0:STATUS.DC        1   Digit carry/borrow bit (for ADDWF and SUBWF instructions)
BANK0:STATUS.C         0   Carry/borrow bit (for ADDWF, SUBWF and RRF, RLF instructions)
BANK0:FSR             0x0004   Indirect data memory address pointer
BANK0:OSCCAL          0x0005   Oscillator Calibration register
BANK0:OSCCAL.CAL3      7   Calibration 3
BANK0:OSCCAL.CAL2      6   Calibration 2
BANK0:OSCCAL.CAL1      5   Calibration 1
BANK0:OSCCAL.CAL0      4   Calibration 0
BANK0:GPIO            0x0006   GPIO register
BANK0:GPIO.GP5         5
BANK0:GPIO.GP4         4
BANK0:GPIO.GP3         3
BANK0:GPIO.GP2         2
BANK0:GPIO.GP1         1
BANK0:GPIO.GP0         0
BANK0:R0              0x0007   General Purpose Register 0
BANK0:R1              0x0008   General Purpose Register 1
BANK0:R2              0x0009   General Purpose Register 2
BANK0:R3              0x000A   General Purpose Register 3
BANK0:R4              0x000B   General Purpose Register 4
BANK0:R5              0x000C   General Purpose Register 5
BANK0:R6              0x000D   General Purpose Register 6
BANK0:R7              0x000E   General Purpose Register 7
BANK0:R8              0x000F   General Purpose Register 8
BANK0:R9              0x0010   General Purpose Register 9
BANK0:R10             0x0011   General Purpose Register 10
BANK0:R11             0x0012   General Purpose Register 11
BANK0:R12             0x0013   General Purpose Register 12
BANK0:R13             0x0014   General Purpose Register 13
BANK0:R14             0x0015   General Purpose Register 14
BANK0:R15             0x0016   General Purpose Register 15
BANK0:R16             0x0017   General Purpose Register 16
BANK0:R17             0x0018   General Purpose Register 17
BANK0:R18             0x0019   General Purpose Register 18
BANK0:R19             0x001A   General Purpose Register 19
BANK0:R20             0x001B   General Purpose Register 20
BANK0:R21             0x001C   General Purpose Register 21
BANK0:R22             0x001D   General Purpose Register 22
BANK0:R23             0x001E   General Purpose Register 23
BANK0:R24             0x001F   General Purpose Register 24

; BANK_1 (0x0020:0x0040)
BANK1:INDF            0x0020   Uses contents of FSR to address data memory (not a physical register)
BANK1:TMR0            0x0021   8-bit real-time clock/counter
BANK1:PCL             0x0022   Low order 8 bits of Program Counter register
BANK1:STATUS          0x0023   STATUS REGISTER
BANK1:STATUS.GPWUF     7   GPIO reset bit
BANK1:STATUS.PA0       5   Program page preselect bits
BANK1:STATUS.TO        4   Time-out bit
BANK1:STATUS.PD        3   Power-down bit
BANK1:STATUS.Z         2   Zero bit
BANK1:STATUS.DC        1   Digit carry/borrow bit (for ADDWF and SUBWF instructions)
BANK1:STATUS.C         0   Carry/borrow bit (for ADDWF, SUBWF and RRF, RLF instructions)
BANK1:FSR             0x0024   Indirect data memory address pointer
BANK1:OSCCAL          0x0025   Oscillator Calibration register
BANK1:OSCCAL.CAL3      7   Calibration 3
BANK1:OSCCAL.CAL2      6   Calibration 2
BANK1:OSCCAL.CAL1      5   Calibration 1
BANK1:OSCCAL.CAL0      4   Calibration 0
BANK1:GPIO            0x0026   GPIO register
BANK1:GPIO.GP5         5
BANK1:GPIO.GP4         4
BANK1:GPIO.GP3         3
BANK1:GPIO.GP2         2
BANK1:GPIO.GP1         1
BANK1:GPIO.GP0         0
BANK1:R0              0x0027   General Purpose Register 0
BANK1:R1              0x0028   General Purpose Register 1
BANK1:R2              0x0029   General Purpose Register 2
BANK1:R3              0x002A   General Purpose Register 3
BANK1:R4              0x002B   General Purpose Register 4
BANK1:R5              0x002C   General Purpose Register 5
BANK1:R6              0x002D   General Purpose Register 6
BANK1:R7              0x002E   General Purpose Register 7
BANK1:R8              0x002F   General Purpose Register 8
BANK1:R25             0x0030   General Purpose Register 25
BANK1:R26             0x0031   General Purpose Register 26
BANK1:R27             0x0032   General Purpose Register 27
BANK1:R28             0x0033   General Purpose Register 28
BANK1:R29             0x0034   General Purpose Register 29
BANK1:R30             0x0035   General Purpose Register 30
BANK1:R31             0x0036   General Purpose Register 31
BANK1:R32             0x0037   General Purpose Register 32
BANK1:R33             0x0038   General Purpose Register 33
BANK1:R34             0x0039   General Purpose Register 34
BANK1:R35             0x003A   General Purpose Register 35
BANK1:R36             0x003B   General Purpose Register 36
BANK1:R37             0x003C   General Purpose Register 37
BANK1:R38             0x003D   General Purpose Register 38
BANK1:R39             0x003E   General Purpose Register 39
BANK1:R40             0x003F   General Purpose Register 40


.12C671
; http://www.microchip.com/download/lit/pline/picmicro/families/12c67x/30561b.pdf
; PIC12C67x.pdf


; MEMORY MAP
; BANK_0
area DATA FSR_           0x0000:0x0020
area DATA Gen_Purp       0x0020:0x0080   General Purpose Register
area CODE MEM_Program    0x0080:0x0400   On-chip Program Memory


; BANK_1
; area DATA FSR_           0x0080:0x00A0
; area DATA Gen_Purp_0     0x00A0:0x00C0   General Purpose Register 0
; area BSS  RESERVED       0x00C0:0x00F0
; area DATA Gen_Purp_1     0x00F0:0x0100   General Purpose Register 1 (Mapped in Bank 0)
; area CODE MEM_Program    0x0100:0x0400   Mapped in Bank 0


; Interrupt and reset vector assignments
entry RESET      0x0000     RESET


; INPUT/OUTPUT PORTS
; BANK_0 (0x0000:0x0080)
BANK0:INDF            0x0000   INDF
BANK0:TMR0              0x0001   Timer0 module's register
BANK0:PCL             0x0002   Program Counter's (PC) Least Significant Byte
BANK0:STATUS          0x0003   STATUS REGISTER
BANK0:STATUS.IRP       7   Register Bank Select bit
BANK0:STATUS.RP1       6   Register Bank Select bit 1
BANK0:STATUS.RP0       5   Register Bank Select bit 0
BANK0:STATUS.TO        4   Time-out bit
BANK0:STATUS.PD        3   Power-down bit
BANK0:STATUS.Z         2   Zero bit
BANK0:STATUS.DC        1   Digit Carry/borrow bit
BANK0:STATUS.C         0   Carry/borrow bit
BANK0:FSR             0x0004   Indirect data memory address pointer
BANK0:GPIO            0x0005   GPIO REGISTER
BANK0:GPIO.SCL         7
BANK0:GPIO.SDA         6
BANK0:GPIO.GP5         5
BANK0:GPIO.GP4         4
BANK0:GPIO.GP3         3
BANK0:GPIO.GP2         2
BANK0:GPIO.GP1         1
BANK0:GPIO.GP0         0
BANK0:RESERVED0006    0x0006   RESERVED
BANK0:RESERVED0007    0x0007   RESERVED
BANK0:RESERVED0008    0x0008   RESERVED
BANK0:RESERVED0009    0x0009   RESERVED
BANK0:PCLATH          0x000A   PCLATH REGISTER
BANK0:PCLATH.PCLATH4   4
BANK0:PCLATH.PCLATH3   3
BANK0:PCLATH.PCLATH2   2
BANK0:PCLATH.PCLATH1   1
BANK0:PCLATH.PCLATH0   0
BANK0:INTCON          0x000B   INTCON REGISTER
BANK0:INTCON.GIE       7   Global Interrupt Enable bit
BANK0:INTCON.PEIE      6   Peripheral Interrupt Enable bit
BANK0:INTCON.T0IE      5   TMR0 Overflow Interrupt Enable bit
BANK0:INTCON.INTE      4   INT External Interrupt Enable bit
BANK0:INTCON.GPIE      3   GPIO Interrupt on Change Enable bit
BANK0:INTCON.T0IF      2   TMR0 Overflow Interrupt Flag bit
BANK0:INTCON.INTF      1   INT External Interrupt Flag bit
BANK0:INTCON.GPIF      0   GPIO Interrupt on Change Flag bit
BANK0:PIR1            0x000C   PIR1 REGISTER
BANK0:PIR1.ADIF        6   A/D Converter Interrupt Flag bit
BANK0:RESERVED000D    0x000D   RESERVED
BANK0:RESERVED000E    0x000E   RESERVED
BANK0:RESERVED000F    0x000F   RESERVED
BANK0:RESERVED0010    0x0010   RESERVED
BANK0:RESERVED0011    0x0011   RESERVED
BANK0:RESERVED0012    0x0012   RESERVED
BANK0:RESERVED0013    0x0013   RESERVED
BANK0:RESERVED0014    0x0014   RESERVED
BANK0:RESERVED0015    0x0015   RESERVED
BANK0:RESERVED0016    0x0016   RESERVED
BANK0:RESERVED0017    0x0017   RESERVED
BANK0:RESERVED0018    0x0018   RESERVED
BANK0:RESERVED0019    0x0019   RESERVED
BANK0:RESERVED001A    0x001A   RESERVED
BANK0:RESERVED001B    0x001B   RESERVED
BANK0:RESERVED001C    0x001C   RESERVED
BANK0:RESERVED001D    0x001D   RESERVED
BANK0:ADRES           0x001E   A/D Result Register
BANK0:ADCON0          0x001F   ADCON0 REGISTER
BANK0:ADCON0.ADCS1     7   A/D Conversion Clock Select bit 1
BANK0:ADCON0.ADCS0     6   A/D Conversion Clock Select bit 0
BANK0:ADCON0.CHS1      4   Analog Channel Select bit 1
BANK0:ADCON0.CHS0      3   Analog Channel Select bit 0
BANK0:ADCON0.GO_DONE   2   A/D Conversion Status bit
BANK0:ADCON0.ADON      0   A/D on bit

; BANK_1 (0x0080:0x0100)
BANK1:INDF            0x0080   INDF REGISTER
BANK1:OPTION          0x0081   OPTION REGISTER
BANK1:OPTION.GPPU      7   Weak Pull-up Enable
BANK1:OPTION.INTEDG    6   Interrupt Edge
BANK1:OPTION.T0CS      5   TMR0 Clock Source Select bit
BANK1:OPTION.T0SE      4   TMR0 Source Edge Select bit
BANK1:OPTION.PSA       3   Prescaler Assignment bit
BANK1:OPTION.PS2       2   Prescaler Rate Select bit 2
BANK1:OPTION.PS1       1   Prescaler Rate Select bit 1
BANK1:OPTION.PS0       0   Prescaler Rate Select bit 0
BANK1:PCL             0x0082   Program Counter's (PC) Least Significant Byte
BANK1:STATUS          0x0083   STATUS REGISTER
BANK1:STATUS.IRP       7   Register Bank Select bit
BANK1:STATUS.RP1       6   Register Bank Select bit 1
BANK1:STATUS.RP0       5   Register Bank Select bit 0
BANK1:STATUS.TO        4   Time-out bit
BANK1:STATUS.PD        3   Power-down bit
BANK1:STATUS.Z         2   Zero bit
BANK1:STATUS.DC        1   Digit Carry/borrow bit
BANK1:STATUS.C         0   Carry/borrow bit
BANK1:FSR             0x0084   Indirect data memory address pointer
BANK1:TRIS            0x0085   TRIS REGISTER
BANK1:TRIS.TRIS5       5
BANK1:TRIS.TRIS4       4
BANK1:TRIS.TRIS3       3
BANK1:TRIS.TRIS2       2
BANK1:TRIS.TRIS1       1
BANK1:TRIS.TRIS0       0
BANK1:RESERVED0086    0x0086   RESERVED
BANK1:RESERVED0087    0x0087   RESERVED
BANK1:RESERVED0088    0x0088   RESERVED
BANK1:RESERVED0089    0x0089   RESERVED
BANK1:PCLATH          0x008A   PCLATH REGISTER
BANK1:PCLATH.PCLATH4   4
BANK1:PCLATH.PCLATH3   3
BANK1:PCLATH.PCLATH2   2
BANK1:PCLATH.PCLATH1   1
BANK1:PCLATH.PCLATH0   0
BANK1:INTCON          0x008B   INTCON REGISTER
BANK1:INTCON.GIE       7   Global Interrupt Enable bit
BANK1:INTCON.PEIE      6   Peripheral Interrupt Enable bit
BANK1:INTCON.T0IE      5   TMR0 Overflow Interrupt Enable bit
BANK1:INTCON.INTE      4   INT External Interrupt Enable bit
BANK1:INTCON.GPIE      3   GPIO Interrupt on Change Enable bit
BANK1:INTCON.T0IF      2   TMR0 Overflow Interrupt Flag bit
BANK1:INTCON.INTF      1   INT External Interrupt Flag bit
BANK1:INTCON.GPIF      0   GPIO Interrupt on Change Flag bit
BANK1:PIE1            0x008C   PIE1 REGISTER
BANK1:PIE1.ADIE        6   A/D Converter Interrupt Enable bit
BANK1:RESERVED008D    0x008D   RESERVED
BANK1:PCON            0x008E   PCON REGISTER
BANK1:PCON.POR         1   Power-on Reset Status bit
BANK1:OSCCAL          0x008F   OSCCAL REGISTER
BANK1:OSCCAL.CAL3      7   Fine Calibration 3
BANK1:OSCCAL.CAL2      6   Fine Calibration 2
BANK1:OSCCAL.CAL1      5   Fine Calibration 1
BANK1:OSCCAL.CAL0      4   Fine Calibration 0
BANK1:OSCCAL.CALFST    3   Calibration Fast
BANK1:OSCCAL.CALSLW    2   Calibration Slow
BANK1:RESERVED0090    0x0090   RESERVED
BANK1:RESERVED0091    0x0091   RESERVED
BANK1:RESERVED0092    0x0092   RESERVED
BANK1:RESERVED0093    0x0093   RESERVED
BANK1:RESERVED0094    0x0094   RESERVED
BANK1:RESERVED0095    0x0095   RESERVED
BANK1:RESERVED0096    0x0096   RESERVED
BANK1:RESERVED0097    0x0097   RESERVED
BANK1:RESERVED0098    0x0098   RESERVED
BANK1:RESERVED0099    0x0099   RESERVED
BANK1:RESERVED009A    0x009A   RESERVED
BANK1:RESERVED009B    0x009B   RESERVED
BANK1:RESERVED009C    0x009C   RESERVED
BANK1:RESERVED009D    0x009D   RESERVED
BANK1:RESERVED009E    0x009E   RESERVED
BANK1:ADCON1          0x009F   ADCON1 REGISTER
BANK1:ADCON1.PCFG2     2   A/D Port Configuration Control bit 2
BANK1:ADCON1.PCFG1     1   A/D Port Configuration Control bit 1
BANK1:ADCON1.PCFG0     0   A/D Port Configuration Control bit 0


.12C672
; http://www.microchip.com/download/lit/pline/picmicro/families/12c67x/30561b.pdf
; PIC12C67x.pdf


; MEMORY MAP
; BANK_0
area DATA FSR_           0x0000:0x0020
area DATA Gen_Purp       0x0020:0x0080   General Purpose Register
area CODE MEM_Program    0x0080:0x0800   On-chip Program Memory


; BANK_1
; area DATA FSR_           0x0080:0x00A0
; area DATA Gen_Purp       0x00A0:0x00C0   General Purpose Register
; area BSS  RESERVED       0x00C0:0x00F0
; area DATA Gen_Purp_1     0x00F0:0x0100   General Purpose Register 1 (Mapped in Bank 0)
; area CODE MEM_Program    0x0100:0x0800   Mapped in Bank 0


; Interrupt and reset vector assignments
entry RESET      0x0000     RESET


; INPUT/OUTPUT PORTS
; BANK_0 (0x0000:0x0080)
BANK0:INDF            0x0000   INDF
BANK0:TMR0              0x0001   Timer0 module's register
BANK0:PCL             0x0002   Program Counter's (PC) Least Significant Byte
BANK0:STATUS          0x0003   STATUS REGISTER
BANK0:STATUS.IRP       7   Register Bank Select bit
BANK0:STATUS.RP1       6   Register Bank Select bit 1
BANK0:STATUS.RP0       5   Register Bank Select bit 0
BANK0:STATUS.TO        4   Time-out bit
BANK0:STATUS.PD        3   Power-down bit
BANK0:STATUS.Z         2   Zero bit
BANK0:STATUS.DC        1   Digit Carry/borrow bit
BANK0:STATUS.C         0   Carry/borrow bit
BANK0:FSR             0x0004   Indirect data memory address pointer
BANK0:GPIO            0x0005   GPIO REGISTER
BANK0:GPIO.SCL         7
BANK0:GPIO.SDA         6
BANK0:GPIO.GP5         5
BANK0:GPIO.GP4         4
BANK0:GPIO.GP3         3
BANK0:GPIO.GP2         2
BANK0:GPIO.GP1         1
BANK0:GPIO.GP0         0
BANK0:RESERVED0006    0x0006   RESERVED
BANK0:RESERVED0007    0x0007   RESERVED
BANK0:RESERVED0008    0x0008   RESERVED
BANK0:RESERVED0009    0x0009   RESERVED
BANK0:PCLATH          0x000A   PCLATH REGISTER
BANK0:PCLATH.PCLATH4   4
BANK0:PCLATH.PCLATH3   3
BANK0:PCLATH.PCLATH2   2
BANK0:PCLATH.PCLATH1   1
BANK0:PCLATH.PCLATH0   0
BANK0:INTCON          0x000B   INTCON REGISTER
BANK0:INTCON.GIE       7   Global Interrupt Enable bit
BANK0:INTCON.PEIE      6   Peripheral Interrupt Enable bit
BANK0:INTCON.T0IE      5   TMR0 Overflow Interrupt Enable bit
BANK0:INTCON.INTE      4   INT External Interrupt Enable bit
BANK0:INTCON.GPIE      3   GPIO Interrupt on Change Enable bit
BANK0:INTCON.T0IF      2   TMR0 Overflow Interrupt Flag bit
BANK0:INTCON.INTF      1   INT External Interrupt Flag bit
BANK0:INTCON.GPIF      0   GPIO Interrupt on Change Flag bit
BANK0:PIR1            0x000C   PIR1 REGISTER
BANK0:PIR1.ADIF        6   A/D Converter Interrupt Flag bit
BANK0:RESERVED000D    0x000D   RESERVED
BANK0:RESERVED000E    0x000E   RESERVED
BANK0:RESERVED000F    0x000F   RESERVED
BANK0:RESERVED0010    0x0010   RESERVED
BANK0:RESERVED0011    0x0011   RESERVED
BANK0:RESERVED0012    0x0012   RESERVED
BANK0:RESERVED0013    0x0013   RESERVED
BANK0:RESERVED0014    0x0014   RESERVED
BANK0:RESERVED0015    0x0015   RESERVED
BANK0:RESERVED0016    0x0016   RESERVED
BANK0:RESERVED0017    0x0017   RESERVED
BANK0:RESERVED0018    0x0018   RESERVED
BANK0:RESERVED0019    0x0019   RESERVED
BANK0:RESERVED001A    0x001A   RESERVED
BANK0:RESERVED001B    0x001B   RESERVED
BANK0:RESERVED001C    0x001C   RESERVED
BANK0:RESERVED001D    0x001D   RESERVED
BANK0:ADRES           0x001E   A/D Result Register
BANK0:ADCON0          0x001F   ADCON0 REGISTER
BANK0:ADCON0.ADCS1     7   A/D Conversion Clock Select bit 1
BANK0:ADCON0.ADCS0     6   A/D Conversion Clock Select bit 0
BANK0:ADCON0.CHS1      4   Analog Channel Select bit 1
BANK0:ADCON0.CHS0      3   Analog Channel Select bit 0
BANK0:ADCON0.GO_DONE   2   A/D Conversion Status bit
BANK0:ADCON0.ADON      0   A/D on bit

; BANK_1 (0x0080:0x0100)
BANK1:INDF            0x0080   INDF REGISTER
BANK1:OPTION          0x0081   OPTION REGISTER
BANK1:OPTION.GPPU      7   Weak Pull-up Enable
BANK1:OPTION.INTEDG    6   Interrupt Edge
BANK1:OPTION.T0CS      5   TMR0 Clock Source Select bit
BANK1:OPTION.T0SE      4   TMR0 Source Edge Select bit
BANK1:OPTION.PSA       3   Prescaler Assignment bit
BANK1:OPTION.PS2       2   Prescaler Rate Select bit 2
BANK1:OPTION.PS1       1   Prescaler Rate Select bit 1
BANK1:OPTION.PS0       0   Prescaler Rate Select bit 0
BANK1:PCL             0x0082   Program Counter's (PC) Least Significant Byte
BANK1:STATUS          0x0083   STATUS REGISTER
BANK1:STATUS.IRP       7   Register Bank Select bit
BANK1:STATUS.RP1       6   Register Bank Select bit 1
BANK1:STATUS.RP0       5   Register Bank Select bit 0
BANK1:STATUS.TO        4   Time-out bit
BANK1:STATUS.PD        3   Power-down bit
BANK1:STATUS.Z         2   Zero bit
BANK1:STATUS.DC        1   Digit Carry/borrow bit
BANK1:STATUS.C         0   Carry/borrow bit
BANK1:FSR             0x0084   Indirect data memory address pointer
BANK1:TRIS            0x0085   TRIS REGISTER
BANK1:TRIS.TRIS5       5
BANK1:TRIS.TRIS4       4
BANK1:TRIS.TRIS3       3
BANK1:TRIS.TRIS2       2
BANK1:TRIS.TRIS1       1
BANK1:TRIS.TRIS0       0
BANK1:RESERVED0086    0x0086   RESERVED
BANK1:RESERVED0087    0x0087   RESERVED
BANK1:RESERVED0088    0x0088   RESERVED
BANK1:RESERVED0089    0x0089   RESERVED
BANK1:PCLATH          0x008A   PCLATH REGISTER
BANK1:PCLATH.PCLATH4   4
BANK1:PCLATH.PCLATH3   3
BANK1:PCLATH.PCLATH2   2
BANK1:PCLATH.PCLATH1   1
BANK1:PCLATH.PCLATH0   0
BANK1:INTCON          0x008B   INTCON REGISTER
BANK1:INTCON.GIE       7   Global Interrupt Enable bit
BANK1:INTCON.PEIE      6   Peripheral Interrupt Enable bit
BANK1:INTCON.T0IE      5   TMR0 Overflow Interrupt Enable bit
BANK1:INTCON.INTE      4   INT External Interrupt Enable bit
BANK1:INTCON.GPIE      3   GPIO Interrupt on Change Enable bit
BANK1:INTCON.T0IF      2   TMR0 Overflow Interrupt Flag bit
BANK1:INTCON.INTF      1   INT External Interrupt Flag bit
BANK1:INTCON.GPIF      0   GPIO Interrupt on Change Flag bit
BANK1:PIE1            0x008C   PIE1 REGISTER
BANK1:PIE1.ADIE        6   A/D Converter Interrupt Enable bit
BANK1:RESERVED008D    0x008D   RESERVED
BANK1:PCON            0x008E   PCON REGISTER
BANK1:PCON.POR         1   Power-on Reset Status bit
BANK1:OSCCAL          0x008F   OSCCAL REGISTER
BANK1:OSCCAL.CAL3      7   Fine Calibration 3
BANK1:OSCCAL.CAL2      6   Fine Calibration 2
BANK1:OSCCAL.CAL1      5   Fine Calibration 1
BANK1:OSCCAL.CAL0      4   Fine Calibration 0
BANK1:OSCCAL.CALFST    3   Calibration Fast
BANK1:OSCCAL.CALSLW    2   Calibration Slow
BANK1:RESERVED0090    0x0090   RESERVED
BANK1:RESERVED0091    0x0091   RESERVED
BANK1:RESERVED0092    0x0092   RESERVED
BANK1:RESERVED0093    0x0093   RESERVED
BANK1:RESERVED0094    0x0094   RESERVED
BANK1:RESERVED0095    0x0095   RESERVED
BANK1:RESERVED0096    0x0096   RESERVED
BANK1:RESERVED0097    0x0097   RESERVED
BANK1:RESERVED0098    0x0098   RESERVED
BANK1:RESERVED0099    0x0099   RESERVED
BANK1:RESERVED009A    0x009A   RESERVED
BANK1:RESERVED009B    0x009B   RESERVED
BANK1:RESERVED009C    0x009C   RESERVED
BANK1:RESERVED009D    0x009D   RESERVED
BANK1:RESERVED009E    0x009E   RESERVED
BANK1:ADCON1          0x009F   ADCON1 REGISTER
BANK1:ADCON1.PCFG2     2   A/D Port Configuration Control bit 2
BANK1:ADCON1.PCFG1     1   A/D Port Configuration Control bit 1
BANK1:ADCON1.PCFG0     0   A/D Port Configuration Control bit 0


.12CE673
; http://www.microchip.com/download/lit/pline/picmicro/families/12c67x/30561b.pdf
; PIC12C67x.pdf


; MEMORY MAP
; BANK_0
area DATA FSR_           0x0000:0x0020
area DATA Gen_Purp       0x0020:0x0080   General Purpose Register
area CODE MEM_Program    0x0080:0x0400   On-chip Program Memory


; BANK_1
; area DATA FSR_           0x0080:0x00A0
; area DATA Gen_Purp       0x00A0:0x00C0   General Purpose Register
; area BSS  RESERVED       0x00C0:0x00F0
; area DATA Gen_Purp_1     0x00F0:0x0100   General Purpose Register 1 (Mapped in Bank 0)
; area CODE MEM_Program    0x0100:0x0400   Mapped in Bank 0


; Interrupt and reset vector assignments
entry RESET      0x0000     RESET


; INPUT/OUTPUT PORTS
; BANK_0 (0x0000:0x0080)
BANK0:INDF            0x0000   INDF REGISTER
BANK0:TMR0            0x0001   Timer0 module's register
BANK0:PCL             0x0002   Program Counter's (PC) Least Significant Byte
BANK0:STATUS          0x0003   STATUS REGISTER
BANK0:STATUS.IRP       7   Register Bank Select bit
BANK0:STATUS.RP1       6   Register Bank Select bit 1
BANK0:STATUS.RP0       5   Register Bank Select bit 0
BANK0:STATUS.TO        4   Time-out bit
BANK0:STATUS.PD        3   Power-down bit
BANK0:STATUS.Z         2   Zero bit
BANK0:STATUS.DC        1   Digit Carry/borrow bit
BANK0:STATUS.C         0   Carry/borrow bit
BANK0:FSR             0x0004   Indirect data memory address pointer
BANK0:GPIO            0x0005   GPIO REGISTER
BANK0:GPIO.SCL         7
BANK0:GPIO.SDA         6
BANK0:GPIO.GP5         5
BANK0:GPIO.GP4         4
BANK0:GPIO.GP3         3
BANK0:GPIO.GP2         2
BANK0:GPIO.GP1         1
BANK0:GPIO.GP0         0
BANK0:RESERVED0006    0x0006   RESERVED
BANK0:RESERVED0007    0x0007   RESERVED
BANK0:RESERVED0008    0x0008   RESERVED
BANK0:RESERVED0009    0x0009   RESERVED
BANK0:PCLATH          0x000A   PCLATH REGISTER
BANK0:PCLATH.PCLATH4   4
BANK0:PCLATH.PCLATH3   3
BANK0:PCLATH.PCLATH2   2
BANK0:PCLATH.PCLATH1   1
BANK0:PCLATH.PCLATH0   0
BANK0:INTCON          0x000B   INTCON REGISTER
BANK0:INTCON.GIE       7   Global Interrupt Enable bit
BANK0:INTCON.PEIE      6   Peripheral Interrupt Enable bit
BANK0:INTCON.T0IE      5   TMR0 Overflow Interrupt Enable bit
BANK0:INTCON.INTE      4   INT External Interrupt Enable bit
BANK0:INTCON.GPIE      3   GPIO Interrupt on Change Enable bit
BANK0:INTCON.T0IF      2   TMR0 Overflow Interrupt Flag bit
BANK0:INTCON.INTF      1   INT External Interrupt Flag bit
BANK0:INTCON.GPIF      0   GPIO Interrupt on Change Flag bit
BANK0:PIR1            0x000C   PIR1 REGISTER
BANK0:PIR1.ADIF        6   A/D Converter Interrupt Flag bit
BANK0:RESERVED000D    0x000D   RESERVED
BANK0:RESERVED000E    0x000E   RESERVED
BANK0:RESERVED000F    0x000F   RESERVED
BANK0:RESERVED0010    0x0010   RESERVED
BANK0:RESERVED0011    0x0011   RESERVED
BANK0:RESERVED0012    0x0012   RESERVED
BANK0:RESERVED0013    0x0013   RESERVED
BANK0:RESERVED0014    0x0014   RESERVED
BANK0:RESERVED0015    0x0015   RESERVED
BANK0:RESERVED0016    0x0016   RESERVED
BANK0:RESERVED0017    0x0017   RESERVED
BANK0:RESERVED0018    0x0018   RESERVED
BANK0:RESERVED0019    0x0019   RESERVED
BANK0:RESERVED001A    0x001A   RESERVED
BANK0:RESERVED001B    0x001B   RESERVED
BANK0:RESERVED001C    0x001C   RESERVED
BANK0:RESERVED001D    0x001D   RESERVED
BANK0:ADRES           0x001E   A/D Result Register
BANK0:ADCON0          0x001F   ADCON0 REGISTER
BANK0:ADCON0.ADCS1     7   A/D Conversion Clock Select bit 1
BANK0:ADCON0.ADCS0     6   A/D Conversion Clock Select bit 0
BANK0:ADCON0.CHS1      4   Analog Channel Select bit 1
BANK0:ADCON0.CHS0      3   Analog Channel Select bit 0
BANK0:ADCON0.GO_DONE   2   A/D Conversion Status bit
BANK0:ADCON0.ADON      0   A/D on bit

; BANK_1 (0x0080:0x0100)
BANK1:INDF            0x0080   INDF REGISTER
BANK1:OPTION          0x0081   OPTION REGISTER
BANK1:OPTION.GPPU      7   Weak Pull-up Enable
BANK1:OPTION.INTEDG    6   Interrupt Edge
BANK1:OPTION.T0CS      5   TMR0 Clock Source Select bit
BANK1:OPTION.T0SE      4   TMR0 Source Edge Select bit
BANK1:OPTION.PSA       3   Prescaler Assignment bit
BANK1:OPTION.PS2       2   Prescaler Rate Select bit 2
BANK1:OPTION.PS1       1   Prescaler Rate Select bit 1
BANK1:OPTION.PS0       0   Prescaler Rate Select bit 0
BANK1:PCL             0x0082   Program Counter's (PC) Least Significant Byte
BANK1:STATUS          0x0083   STATUS REGISTER
BANK1:STATUS.IRP       7   Register Bank Select bit
BANK1:STATUS.RP1       6   Register Bank Select bit 1
BANK1:STATUS.RP0       5   Register Bank Select bit 0
BANK1:STATUS.TO        4   Time-out bit
BANK1:STATUS.PD        3   Power-down bit
BANK1:STATUS.Z         2   Zero bit
BANK1:STATUS.DC        1   Digit Carry/borrow bit
BANK1:STATUS.C         0   Carry/borrow bit
BANK1:FSR             0x0084   Indirect data memory address pointer
BANK1:TRIS            0x0085   TRIS REGISTER
BANK1:TRIS.TRIS5       5
BANK1:TRIS.TRIS4       4
BANK1:TRIS.TRIS3       3
BANK1:TRIS.TRIS2       2
BANK1:TRIS.TRIS1       1
BANK1:TRIS.TRIS0       0
BANK1:RESERVED0086    0x0086   RESERVED
BANK1:RESERVED0087    0x0087   RESERVED
BANK1:RESERVED0088    0x0088   RESERVED
BANK1:RESERVED0089    0x0089   RESERVED
BANK1:PCLATH          0x008A   PCLATH REGISTER
BANK1:PCLATH.PCLATH4   4
BANK1:PCLATH.PCLATH3   3
BANK1:PCLATH.PCLATH2   2
BANK1:PCLATH.PCLATH1   1
BANK1:PCLATH.PCLATH0   0
BANK1:INTCON          0x008B   INTCON REGISTER
BANK1:INTCON.GIE       7   Global Interrupt Enable bit
BANK1:INTCON.PEIE      6   Peripheral Interrupt Enable bit
BANK1:INTCON.T0IE      5   TMR0 Overflow Interrupt Enable bit
BANK1:INTCON.INTE      4   INT External Interrupt Enable bit
BANK1:INTCON.GPIE      3   GPIO Interrupt on Change Enable bit
BANK1:INTCON.T0IF      2   TMR0 Overflow Interrupt Flag bit
BANK1:INTCON.INTF      1   INT External Interrupt Flag bit
BANK1:INTCON.GPIF      0   GPIO Interrupt on Change Flag bit
BANK1:PIE1            0x008C   PIE1 REGISTER
BANK1:PIE1.ADIE        6   A/D Converter Interrupt Enable bit
BANK1:RESERVED008D    0x008D   RESERVED
BANK1:PCON            0x008E   PCON REGISTER
BANK1:PCON.POR         1   Power-on Reset Status bit
BANK1:OSCCAL          0x008F   OSCCAL REGISTER
BANK1:OSCCAL.CAL3      7   Fine Calibration 3
BANK1:OSCCAL.CAL2      6   Fine Calibration 2
BANK1:OSCCAL.CAL1      5   Fine Calibration 1
BANK1:OSCCAL.CAL0      4   Fine Calibration 0
BANK1:OSCCAL.CALFST    3   Calibration Fast
BANK1:OSCCAL.CALSLW    2   Calibration Slow
BANK1:RESERVED0090    0x0090   RESERVED
BANK1:RESERVED0091    0x0091   RESERVED
BANK1:RESERVED0092    0x0092   RESERVED
BANK1:RESERVED0093    0x0093   RESERVED
BANK1:RESERVED0094    0x0094   RESERVED
BANK1:RESERVED0095    0x0095   RESERVED
BANK1:RESERVED0096    0x0096   RESERVED
BANK1:RESERVED0097    0x0097   RESERVED
BANK1:RESERVED0098    0x0098   RESERVED
BANK1:RESERVED0099    0x0099   RESERVED
BANK1:RESERVED009A    0x009A   RESERVED
BANK1:RESERVED009B    0x009B   RESERVED
BANK1:RESERVED009C    0x009C   RESERVED
BANK1:RESERVED009D    0x009D   RESERVED
BANK1:RESERVED009E    0x009E   RESERVED
BANK1:ADCON1          0x009F   ADCON1 REGISTER
BANK1:ADCON1.PCFG2     2   A/D Port Configuration Control bit 2
BANK1:ADCON1.PCFG1     1   A/D Port Configuration Control bit 1
BANK1:ADCON1.PCFG0     0   A/D Port Configuration Control bit 0


.12CE674
; http://www.microchip.com/download/lit/pline/picmicro/families/12c67x/30561b.pdf
; PIC12C67x.pdf


; MEMORY MAP
; BANK_0
area DATA FSR_           0x0000:0x0020
area DATA Gen_Purp       0x0020:0x0080   General Purpose Register
area CODE MEM_Program    0x0080:0x0800   On-chip Program Memory


; BANK_1
; area DATA FSR_           0x0080:0x00A0
; area DATA Gen_Purp       0x00A0:0x00C0   General Purpose Register
; area BSS  RESERVED       0x00C0:0x00F0
; area DATA Gen_Purp_1     0x00F0:0x0100   General Purpose Register 1 (Mapped in Bank 0)
; area CODE MEM_Program    0x0100:0x0800   Mapped in Bank 0


; Interrupt and reset vector assignments
entry RESET      0x0000     RESET


; INPUT/OUTPUT PORTS
; BANK_0 (0x0000:0x0080)
BANK0:INDF            0x0000   INDF REGISTER
BANK0:TMR0            0x0001   Timer0 module's register
BANK0:PCL             0x0002   Program Counter's (PC) Least Significant Byte
BANK0:STATUS          0x0003   STATUS REGISTER
BANK0:STATUS.IRP       7   Register Bank Select bit
BANK0:STATUS.RP1       6   Register Bank Select bit 1
BANK0:STATUS.RP0       5   Register Bank Select bit 0
BANK0:STATUS.TO        4   Time-out bit
BANK0:STATUS.PD        3   Power-down bit
BANK0:STATUS.Z         2   Zero bit
BANK0:STATUS.DC        1   Digit Carry/borrow bit
BANK0:STATUS.C         0   Carry/borrow bit
BANK0:FSR             0x0004   Indirect data memory address pointer
BANK0:GPIO            0x0005   GPIO REGISTER
BANK0:GPIO.SCL         7
BANK0:GPIO.SDA         6
BANK0:GPIO.GP5         5
BANK0:GPIO.GP4         4
BANK0:GPIO.GP3         3
BANK0:GPIO.GP2         2
BANK0:GPIO.GP1         1
BANK0:GPIO.GP0         0
BANK0:RESERVED0006    0x0006   RESERVED
BANK0:RESERVED0007    0x0007   RESERVED
BANK0:RESERVED0008    0x0008   RESERVED
BANK0:RESERVED0009    0x0009   RESERVED
BANK0:PCLATH          0x000A   PCLATH REGISTER
BANK0:PCLATH.PCLATH4   4
BANK0:PCLATH.PCLATH3   3
BANK0:PCLATH.PCLATH2   2
BANK0:PCLATH.PCLATH1   1
BANK0:PCLATH.PCLATH0   0
BANK0:INTCON          0x000B   INTCON REGISTER
BANK0:INTCON.GIE       7   Global Interrupt Enable bit
BANK0:INTCON.PEIE      6   Peripheral Interrupt Enable bit
BANK0:INTCON.T0IE      5   TMR0 Overflow Interrupt Enable bit
BANK0:INTCON.INTE      4   INT External Interrupt Enable bit
BANK0:INTCON.GPIE      3   GPIO Interrupt on Change Enable bit
BANK0:INTCON.T0IF      2   TMR0 Overflow Interrupt Flag bit
BANK0:INTCON.INTF      1   INT External Interrupt Flag bit
BANK0:INTCON.GPIF      0   GPIO Interrupt on Change Flag bit
BANK0:PIR1            0x000C   PIR1 REGISTER
BANK0:PIR1.ADIF        6   A/D Converter Interrupt Flag bit
BANK0:RESERVED000D    0x000D   RESERVED
BANK0:RESERVED000E    0x000E   RESERVED
BANK0:RESERVED000F    0x000F   RESERVED
BANK0:RESERVED0010    0x0010   RESERVED
BANK0:RESERVED0011    0x0011   RESERVED
BANK0:RESERVED0012    0x0012   RESERVED
BANK0:RESERVED0013    0x0013   RESERVED
BANK0:RESERVED0014    0x0014   RESERVED
BANK0:RESERVED0015    0x0015   RESERVED
BANK0:RESERVED0016    0x0016   RESERVED
BANK0:RESERVED0017    0x0017   RESERVED
BANK0:RESERVED0018    0x0018   RESERVED
BANK0:RESERVED0019    0x0019   RESERVED
BANK0:RESERVED001A    0x001A   RESERVED
BANK0:RESERVED001B    0x001B   RESERVED
BANK0:RESERVED001C    0x001C   RESERVED
BANK0:RESERVED001D    0x001D   RESERVED
BANK0:ADRES           0x001E   A/D Result Register
BANK0:ADCON0          0x001F   ADCON0 REGISTER
BANK0:ADCON0.ADCS1     7   A/D Conversion Clock Select bit 1
BANK0:ADCON0.ADCS0     6   A/D Conversion Clock Select bit 0
BANK0:ADCON0.CHS1      4   Analog Channel Select bit 1
BANK0:ADCON0.CHS0      3   Analog Channel Select bit 0
BANK0:ADCON0.GO_DONE   2   A/D Conversion Status bit
BANK0:ADCON0.ADON      0   A/D on bit

; BANK_1 (0x0080:0x0100)
BANK1:INDF            0x0080   INDF REGISTER
BANK1:OPTION          0x0081   OPTION REGISTER
BANK1:OPTION.GPPU      7   Weak Pull-up Enable
BANK1:OPTION.INTEDG    6   Interrupt Edge
BANK1:OPTION.T0CS      5   TMR0 Clock Source Select bit
BANK1:OPTION.T0SE      4   TMR0 Source Edge Select bit
BANK1:OPTION.PSA       3   Prescaler Assignment bit
BANK1:OPTION.PS2       2   Prescaler Rate Select bit 2
BANK1:OPTION.PS1       1   Prescaler Rate Select bit 1
BANK1:OPTION.PS0       0   Prescaler Rate Select bit 0
BANK1:PCL             0x0082   Program Counter's (PC) Least Significant Byte
BANK1:STATUS          0x0083   STATUS REGISTER
BANK1:STATUS.IRP       7   Register Bank Select bit
BANK1:STATUS.RP1       6   Register Bank Select bit 1
BANK1:STATUS.RP0       5   Register Bank Select bit 0
BANK1:STATUS.TO        4   Time-out bit
BANK1:STATUS.PD        3   Power-down bit
BANK1:STATUS.Z         2   Zero bit
BANK1:STATUS.DC        1   Digit Carry/borrow bit
BANK1:STATUS.C         0   Carry/borrow bit
BANK1:FSR             0x0084   Indirect data memory address pointer
BANK1:TRIS            0x0085   TRIS REGISTER
BANK1:TRIS.TRIS5       5
BANK1:TRIS.TRIS4       4
BANK1:TRIS.TRIS3       3
BANK1:TRIS.TRIS2       2
BANK1:TRIS.TRIS1       1
BANK1:TRIS.TRIS0       0
BANK1:RESERVED0086    0x0086   RESERVED
BANK1:RESERVED0087    0x0087   RESERVED
BANK1:RESERVED0088    0x0088   RESERVED
BANK1:RESERVED0089    0x0089   RESERVED
BANK1:PCLATH          0x008A   PCLATH REGISTER
BANK1:PCLATH.PCLATH4   4
BANK1:PCLATH.PCLATH3   3
BANK1:PCLATH.PCLATH2   2
BANK1:PCLATH.PCLATH1   1
BANK1:PCLATH.PCLATH0   0
BANK1:INTCON          0x008B   INTCON REGISTER
BANK1:INTCON.GIE       7   Global Interrupt Enable bit
BANK1:INTCON.PEIE      6   Peripheral Interrupt Enable bit
BANK1:INTCON.T0IE      5   TMR0 Overflow Interrupt Enable bit
BANK1:INTCON.INTE      4   INT External Interrupt Enable bit
BANK1:INTCON.GPIE      3   GPIO Interrupt on Change Enable bit
BANK1:INTCON.T0IF      2   TMR0 Overflow Interrupt Flag bit
BANK1:INTCON.INTF      1   INT External Interrupt Flag bit
BANK1:INTCON.GPIF      0   GPIO Interrupt on Change Flag bit
BANK1:PIE1            0x008C   PIE1 REGISTER
BANK1:PIE1.ADIE        6   A/D Converter Interrupt Enable bit
BANK1:RESERVED008D    0x008D   RESERVED
BANK1:PCON            0x008E   PCON REGISTER
BANK1:PCON.POR         1   Power-on Reset Status bit
BANK1:OSCCAL          0x008F   OSCCAL REGISTER
BANK1:OSCCAL.CAL3      7   Fine Calibration 3
BANK1:OSCCAL.CAL2      6   Fine Calibration 2
BANK1:OSCCAL.CAL1      5   Fine Calibration 1
BANK1:OSCCAL.CAL0      4   Fine Calibration 0
BANK1:OSCCAL.CALFST    3   Calibration Fast
BANK1:OSCCAL.CALSLW    2   Calibration Slow
BANK1:RESERVED0090    0x0090   RESERVED
BANK1:RESERVED0091    0x0091   RESERVED
BANK1:RESERVED0092    0x0092   RESERVED
BANK1:RESERVED0093    0x0093   RESERVED
BANK1:RESERVED0094    0x0094   RESERVED
BANK1:RESERVED0095    0x0095   RESERVED
BANK1:RESERVED0096    0x0096   RESERVED
BANK1:RESERVED0097    0x0097   RESERVED
BANK1:RESERVED0098    0x0098   RESERVED
BANK1:RESERVED0099    0x0099   RESERVED
BANK1:RESERVED009A    0x009A   RESERVED
BANK1:RESERVED009B    0x009B   RESERVED
BANK1:RESERVED009C    0x009C   RESERVED
BANK1:RESERVED009D    0x009D   RESERVED
BANK1:RESERVED009E    0x009E   RESERVED
BANK1:ADCON1          0x009F   ADCON1 REGISTER
BANK1:ADCON1.PCFG2     2   A/D Port Configuration Control bit 2
BANK1:ADCON1.PCFG1     1   A/D Port Configuration Control bit 1
BANK1:ADCON1.PCFG0     0   A/D Port Configuration Control bit 0


.16C54
; http://www.microchip.com/download/lit/pline/picmicro/families/16c5x/30453d.pdf
; PIC16C5X.pdf


; MEMORY MAP
area DATA FSR_           0x0000:0x0007
area DATA Gen_Purp       0x0007:0x0020   General Purpose Register
area CODE MEM_Program0   0x0020:0x01FF   On-chip Program Memory (Page 0)


; Interrupt and reset vector assignments
entry RESET      0x01FF     RESET


; INPUT/OUTPUT PORTS
INDF            0x0000   INDF (not a physical register)
TMR0            0x0001   Timer0 Module Register
PCL             0x0002   Low order 8 bits of PC
STATUS          0x0003   STATUS REGISTER
STATUS.PA1       6   Program page preselect bit 1
STATUS.PA0       5   Program page preselect bit 0
STATUS.TO        4   Time-out bit
STATUS.PD        3   Power-down bit
STATUS.Z         2   Zero bit
STATUS.DC        1   Digit carry/borrow bit
STATUS.C         0   Carry/borrow bit
FSR             0x0004   Indirect data memory address pointer
PORTA           0x0005   PORTA REGISTER
PORTA.RA3        3   PORTA bit 3
PORTA.RA2        2   PORTA bit 2
PORTA.RA1        1   PORTA bit 1
PORTA.RA0        0   PORTA bit 0
PORTB           0x0006   PORTB REGISTER
PORTB.RB7        7   PORTB bit 7
PORTB.RB6        6   PORTB bit 6
PORTB.RB5        5   PORTB bit 5
PORTB.RB4        4   PORTB bit 4
PORTB.RB3        3   PORTB bit 3
PORTB.RB2        2   PORTB bit 2
PORTB.RB1        1   PORTB bit 1
PORTB.RB0        0   PORTB bit 0


.16C55
; http://www.microchip.com/download/lit/pline/picmicro/families/16c5x/30453d.pdf
; PIC16C5X.pdf


; MEMORY MAP
area DATA FSR_           0x0000:0x0008
area DATA Gen_Purp       0x0008:0x0020   General Purpose Register
area CODE MEM_Program0   0x0020:0x01FF   On-chip Program Memory (Page 0)


; Interrupt and reset vector assignments
entry RESET      0x01FF     RESET


; INPUT/OUTPUT PORTS
INDF            0x0000   INDF (not a physical register)
TMR0            0x0001   Timer0 Module Register
PCL             0x0002   Low order 8 bits of PC
STATUS          0x0003   STATUS REGISTER
STATUS.PA1       6   Program page preselect bit 1
STATUS.PA0       5   Program page preselect bit 0
STATUS.TO        4   Time-out bit
STATUS.PD        3   Power-down bit
STATUS.Z         2   Zero bit
STATUS.DC        1   Digit carry/borrow bit
STATUS.C         0   Carry/borrow bit
FSR             0x0004   Indirect data memory address pointer
PORTA           0x0005   PORTA REGISTER
PORTA.RA3        3   PORTA bit 3
PORTA.RA2        2   PORTA bit 2
PORTA.RA1        1   PORTA bit 1
PORTA.RA0        0   PORTA bit 0
PORTB           0x0006   PORTB REGISTER
PORTB.RB7        7   PORTB bit 7
PORTB.RB6        6   PORTB bit 6
PORTB.RB5        5   PORTB bit 5
PORTB.RB4        4   PORTB bit 4
PORTB.RB3        3   PORTB bit 3
PORTB.RB2        2   PORTB bit 2
PORTB.RB1        1   PORTB bit 1
PORTB.RB0        0   PORTB bit 0
PORTC           0x0007   PORTC REGISTER
PORTC.RC7        7   PORTC bit 7
PORTC.RC6        6   PORTC bit 6
PORTC.RC5        5   PORTC bit 5
PORTC.RC4        4   PORTC bit 4
PORTC.RC3        3   PORTC bit 3
PORTC.RC2        2   PORTC bit 2
PORTC.RC1        1   PORTC bit 1
PORTC.RC0        0   PORTC bit 0


.16C56
; http://www.microchip.com/download/lit/pline/picmicro/families/16c5x/30453d.pdf
; PIC16C5X.pdf


; MEMORY MAP
area DATA FSR_           0x0000:0x0007
area DATA Gen_Purp       0x0007:0x0020   General Purpose Register
area CODE MEM_Program0   0x0020:0x0200   On-chip Program Memory (Page 0)
area CODE MEM_Program1   0x0200:0x03FF   On-chip Program Memory (Page 1)


; Interrupt and reset vector assignments
entry RESET      0x03FF     RESET


; INPUT/OUTPUT PORTS
INDF            0x0000   INDF (not a physical register)
TMR0            0x0001   Timer0 Module Register
PCL             0x0002   Low order 8 bits of PC
STATUS          0x0003   STATUS REGISTER
STATUS.PA1       6   Program page preselect bit 1
STATUS.PA0       5   Program page preselect bit 0
STATUS.TO        4   Time-out bit
STATUS.PD        3   Power-down bit
STATUS.Z         2   Zero bit
STATUS.DC        1   Digit carry/borrow bit
STATUS.C         0   Carry/borrow bit
FSR             0x0004   Indirect data memory address pointer
PORTA           0x0005   PORTA REGISTER
PORTA.RA3        3   PORTA bit 3
PORTA.RA2        2   PORTA bit 2
PORTA.RA1        1   PORTA bit 1
PORTA.RA0        0   PORTA bit 0
PORTB           0x0006   PORTB REGISTER
PORTB.RB7        7   PORTB bit 7
PORTB.RB6        6   PORTB bit 6
PORTB.RB5        5   PORTB bit 5
PORTB.RB4        4   PORTB bit 4
PORTB.RB3        3   PORTB bit 3
PORTB.RB2        2   PORTB bit 2
PORTB.RB1        1   PORTB bit 1
PORTB.RB0        0   PORTB bit 0


.16C57
; http://www.microchip.com/download/lit/pline/picmicro/families/16c5x/30453d.pdf
; PIC16C5X.pdf


; MEMORY MAP
; BANK_0
area DATA FSR_           0x0000:0x0008
area DATA Gen_Purp       0x0008:0x0020   General Purpose Register
area CODE MEM_Program0   0x0020:0x0200   On-chip Program Memory (Page 0)
area CODE MEM_Program1   0x0200:0x0400   On-chip Program Memory (Page 1)
area CODE MEM_Program2   0x0400:0x0600   On-chip Program Memory (Page 2)
area CODE MEM_Program3   0x0600:0x07FF   On-chip Program Memory (Page 3)

; BANK_1
; area DATA FSR_           0x0020:0x0028
; area DATA Gen_Purp       0x0028:0x0040   General Purpose Register
; area CODE MEM_Program0   0x0040:0x0200   On-chip Program Memory (Page 0)
; area CODE MEM_Program1   0x0200:0x0400   On-chip Program Memory (Page 1)
; area CODE MEM_Program2   0x0400:0x0600   On-chip Program Memory (Page 2)
; area CODE MEM_Program3   0x0600:0x07FF   On-chip Program Memory (Page 3)

; BANK_2
; area DATA FSR_           0x0040:0x0048
; area DATA Gen_Purp       0x0048:0x0060   General Purpose Register
; area CODE MEM_Program0   0x0060:0x0200   On-chip Program Memory (Page 0)
; area CODE MEM_Program1   0x0200:0x0400   On-chip Program Memory (Page 1)
; area CODE MEM_Program2   0x0400:0x0600   On-chip Program Memory (Page 2)
; area CODE MEM_Program3   0x0600:0x07FF   On-chip Program Memory (Page 3)

; BANK_3
; area DATA FSR_           0x0060:0x0068
; area DATA Gen_Purp       0x0068:0x0080   General Purpose Register
; area CODE MEM_Program0   0x0080:0x0200   On-chip Program Memory (Page 0)
; area CODE MEM_Program1   0x0200:0x0400   On-chip Program Memory (Page 1)
; area CODE MEM_Program2   0x0400:0x0600   On-chip Program Memory (Page 2)
; area CODE MEM_Program3   0x0600:0x07FF   On-chip Program Memory (Page 3)


; Interrupt and reset vector assignments
entry RESET      0x07FF     RESET


; INPUT/OUTPUT PORTS
; BANK0 (0x0000:0x0020)
BANK0:INDF            0x0000   INDF (not a physical register)
BANK0:TMR0            0x0001   Timer0 Module Register
BANK0:PCL             0x0002   Low order 8 bits of PC
BANK0:STATUS          0x0003   STATUS REGISTER
BANK0:STATUS.PA1       6   Program page preselect bit 1
BANK0:STATUS.PA0       5   Program page preselect bit 0
BANK0:STATUS.TO        4   Time-out bit
BANK0:STATUS.PD        3   Power-down bit
BANK0:STATUS.Z         2   Zero bit
BANK0:STATUS.DC        1   Digit carry/borrow bit
BANK0:STATUS.C         0   Carry/borrow bit
BANK0:FSR             0x0004   Indirect data memory address pointer
BANK0:PORTA           0x0005   PORTA REGISTER
BANK0:PORTA.RA3        3   PORTA bit 3
BANK0:PORTA.RA2        2   PORTA bit 2
BANK0:PORTA.RA1        1   PORTA bit 1
BANK0:PORTA.RA0        0   PORTA bit 0
BANK0:PORTB           0x0006   PORTB REGISTER
BANK0:PORTB.RB7        7   PORTB bit 7
BANK0:PORTB.RB6        6   PORTB bit 6
BANK0:PORTB.RB5        5   PORTB bit 5
BANK0:PORTB.RB4        4   PORTB bit 4
BANK0:PORTB.RB3        3   PORTB bit 3
BANK0:PORTB.RB2        2   PORTB bit 2
BANK0:PORTB.RB1        1   PORTB bit 1
BANK0:PORTB.RB0        0   PORTB bit 0
BANK0:PORTC           0x0007   PORTC REGISTER
BANK0:PORTC.RC7        7   PORTC bit 7
BANK0:PORTC.RC6        6   PORTC bit 6
BANK0:PORTC.RC5        5   PORTC bit 5
BANK0:PORTC.RC4        4   PORTC bit 4
BANK0:PORTC.RC3        3   PORTC bit 3
BANK0:PORTC.RC2        2   PORTC bit 2
BANK0:PORTC.RC1        1   PORTC bit 1
BANK0:PORTC.RC0        0   PORTC bit 0

; BANK1 (0x0020:0x0040)
BANK1:INDF            0x0020   INDF (not a physical register)
BANK1:TMR0            0x0021   Timer0 Module Register
BANK1:PCL             0x0022   Low order 8 bits of PC
BANK1:STATUS          0x0023   STATUS REGISTER
BANK1:STATUS.PA1       6   Program page preselect bit 1
BANK1:STATUS.PA0       5   Program page preselect bit 0
BANK1:STATUS.TO        4   Time-out bit
BANK1:STATUS.PD        3   Power-down bit
BANK1:STATUS.Z         2   Zero bit
BANK1:STATUS.DC        1   Digit carry/borrow bit
BANK1:STATUS.C         0   Carry/borrow bit
BANK1:FSR             0x0024   Indirect data memory address pointer
BANK1:PORTA           0x0025   PORTA REGISTER
BANK1:PORTA.RA3        3   PORTA bit 3
BANK1:PORTA.RA2        2   PORTA bit 2
BANK1:PORTA.RA1        1   PORTA bit 1
BANK1:PORTA.RA0        0   PORTA bit 0
BANK1:PORTB           0x0026   PORTB REGISTER
BANK1:PORTB.RB7        7   PORTB bit 7
BANK1:PORTB.RB6        6   PORTB bit 6
BANK1:PORTB.RB5        5   PORTB bit 5
BANK1:PORTB.RB4        4   PORTB bit 4
BANK1:PORTB.RB3        3   PORTB bit 3
BANK1:PORTB.RB2        2   PORTB bit 2
BANK1:PORTB.RB1        1   PORTB bit 1
BANK1:PORTB.RB0        0   PORTB bit 0
BANK1:PORTC           0x0027   PORTC REGISTER
BANK1:PORTC.RC7        7   PORTC bit 7
BANK1:PORTC.RC6        6   PORTC bit 6
BANK1:PORTC.RC5        5   PORTC bit 5
BANK1:PORTC.RC4        4   PORTC bit 4
BANK1:PORTC.RC3        3   PORTC bit 3
BANK1:PORTC.RC2        2   PORTC bit 2
BANK1:PORTC.RC1        1   PORTC bit 1
BANK1:PORTC.RC0        0   PORTC bit 0

; BANK2 (0x0040:0x0060)
BANK2:INDF            0x0040   INDF (not a physical register)
BANK2:TMR0            0x0041   Timer0 Module Register
BANK2:PCL             0x0042   Low order 8 bits of PC
BANK2:STATUS          0x0043   STATUS REGISTER
BANK2:STATUS.PA1       6   Program page preselect bit 1
BANK2:STATUS.PA0       5   Program page preselect bit 0
BANK2:STATUS.TO        4   Time-out bit
BANK2:STATUS.PD        3   Power-down bit
BANK2:STATUS.Z         2   Zero bit
BANK2:STATUS.DC        1   Digit carry/borrow bit
BANK2:STATUS.C         0   Carry/borrow bit
BANK2:FSR             0x0044   Indirect data memory address pointer
BANK2:PORTA           0x0045   PORTA REGISTER
BANK2:PORTA.RA3        3   PORTA bit 3
BANK2:PORTA.RA2        2   PORTA bit 2
BANK2:PORTA.RA1        1   PORTA bit 1
BANK2:PORTA.RA0        0   PORTA bit 0
BANK2:PORTB           0x0046   PORTB REGISTER
BANK2:PORTB.RB7        7   PORTB bit 7
BANK2:PORTB.RB6        6   PORTB bit 6
BANK2:PORTB.RB5        5   PORTB bit 5
BANK2:PORTB.RB4        4   PORTB bit 4
BANK2:PORTB.RB3        3   PORTB bit 3
BANK2:PORTB.RB2        2   PORTB bit 2
BANK2:PORTB.RB1        1   PORTB bit 1
BANK2:PORTB.RB0        0   PORTB bit 0
BANK2:PORTC           0x0047   PORTC REGISTER
BANK2:PORTC.RC7        7   PORTC bit 7
BANK2:PORTC.RC6        6   PORTC bit 6
BANK2:PORTC.RC5        5   PORTC bit 5
BANK2:PORTC.RC4        4   PORTC bit 4
BANK2:PORTC.RC3        3   PORTC bit 3
BANK2:PORTC.RC2        2   PORTC bit 2
BANK2:PORTC.RC1        1   PORTC bit 1
BANK2:PORTC.RC0        0   PORTC bit 0

; BANK3 (0x0060:0x0080)
BANK3:INDF            0x0060   INDF (not a physical register)
BANK3:TMR0            0x0061   Timer0 Module Register
BANK3:PCL             0x0062   Low order 8 bits of PC
BANK3:STATUS          0x0063   STATUS REGISTER
BANK3:STATUS.PA1       6   Program page preselect bit 1
BANK3:STATUS.PA0       5   Program page preselect bit 0
BANK3:STATUS.TO        4   Time-out bit
BANK3:STATUS.PD        3   Power-down bit
BANK3:STATUS.Z         2   Zero bit
BANK3:STATUS.DC        1   Digit carry/borrow bit
BANK3:STATUS.C         0   Carry/borrow bit
BANK3:FSR             0x0064   Indirect data memory address pointer
BANK3:PORTA           0x0065   PORTA REGISTER
BANK3:PORTA.RA3        3   PORTA bit 3
BANK3:PORTA.RA2        2   PORTA bit 2
BANK3:PORTA.RA1        1   PORTA bit 1
BANK3:PORTA.RA0        0   PORTA bit 0
BANK3:PORTB           0x0066   PORTB REGISTER
BANK3:PORTB.RB7        7   PORTB bit 7
BANK3:PORTB.RB6        6   PORTB bit 6
BANK3:PORTB.RB5        5   PORTB bit 5
BANK3:PORTB.RB4        4   PORTB bit 4
BANK3:PORTB.RB3        3   PORTB bit 3
BANK3:PORTB.RB2        2   PORTB bit 2
BANK3:PORTB.RB1        1   PORTB bit 1
BANK3:PORTB.RB0        0   PORTB bit 0
BANK3:PORTC           0x0067   PORTC REGISTER
BANK3:PORTC.RC7        7   PORTC bit 7
BANK3:PORTC.RC6        6   PORTC bit 6
BANK3:PORTC.RC5        5   PORTC bit 5
BANK3:PORTC.RC4        4   PORTC bit 4
BANK3:PORTC.RC3        3   PORTC bit 3
BANK3:PORTC.RC2        2   PORTC bit 2
BANK3:PORTC.RC1        1   PORTC bit 1
BANK3:PORTC.RC0        0   PORTC bit 0


.16C58
; http://www.microchip.com/download/lit/pline/picmicro/families/16c5x/30453d.pdf
; PIC16C5X.pdf


; MEMORY MAP
; BANK_0
area DATA FSR_           0x0000:0x0007
area DATA Gen_Purp       0x0007:0x0020   General Purpose Register
area CODE MEM_Program0   0x0020:0x0200   On-chip Program Memory (Page 0)
area CODE MEM_Program1   0x0200:0x0400   On-chip Program Memory (Page 1)
area CODE MEM_Program2   0x0400:0x0600   On-chip Program Memory (Page 2)
area CODE MEM_Program3   0x0600:0x07FF   On-chip Program Memory (Page 3)

; BANK_1
; area DATA FSR_           0x0020:0x0027
; area DATA Gen_Purp       0x0027:0x0040   General Purpose Register
; area CODE MEM_Program0   0x0040:0x0200   On-chip Program Memory (Page 0)
; area CODE MEM_Program1   0x0200:0x0400   On-chip Program Memory (Page 1)
; area CODE MEM_Program2   0x0400:0x0600   On-chip Program Memory (Page 2)
; area CODE MEM_Program3   0x0600:0x07FF   On-chip Program Memory (Page 3)

; BANK_2
; area DATA FSR_           0x0040:0x0047
; area DATA Gen_Purp       0x0047:0x0060   General Purpose Register
; area CODE MEM_Program0   0x0060:0x0200   On-chip Program Memory (Page 0)
; area CODE MEM_Program1   0x0200:0x0400   On-chip Program Memory (Page 1)
; area CODE MEM_Program2   0x0400:0x0600   On-chip Program Memory (Page 2)
; area CODE MEM_Program3   0x0600:0x07FF   On-chip Program Memory (Page 3)

; BANK_3
; area DATA FSR_           0x0060:0x0067
; area DATA Gen_Purp       0x0067:0x0080   General Purpose Register
; area CODE MEM_Program0   0x0080:0x0200   On-chip Program Memory (Page 0)
; area CODE MEM_Program1   0x0200:0x0400   On-chip Program Memory (Page 1)
; area CODE MEM_Program2   0x0400:0x0600   On-chip Program Memory (Page 2)
; area CODE MEM_Program3   0x0600:0x07FF   On-chip Program Memory (Page 3)


; Interrupt and reset vector assignments
entry RESET      0x07FF     RESET


; INPUT/OUTPUT PORTS
; BANK0 (0x0000:0x0020)
BANK0:INDF            0x0000   INDF (not a physical register)
BANK0:TMR0            0x0001   Timer0 Module Register
BANK0:PCL             0x0002   Low order 8 bits of PC
BANK0:STATUS          0x0003   STATUS REGISTER
BANK0:STATUS.PA1       6   Program page preselect bit 1
BANK0:STATUS.PA0       5   Program page preselect bit 0
BANK0:STATUS.TO        4   Time-out bit
BANK0:STATUS.PD        3   Power-down bit
BANK0:STATUS.Z         2   Zero bit
BANK0:STATUS.DC        1   Digit carry/borrow bit
BANK0:STATUS.C         0   Carry/borrow bit
BANK0:FSR             0x0004   Indirect data memory address pointer
BANK0:PORTA           0x0005   PORTA REGISTER
BANK0:PORTA.RA3        3   PORTA bit 3
BANK0:PORTA.RA2        2   PORTA bit 2
BANK0:PORTA.RA1        1   PORTA bit 1
BANK0:PORTA.RA0        0   PORTA bit 0
BANK0:PORTB           0x0006   PORTB REGISTER
BANK0:PORTB.RB7        7   PORTB bit 7
BANK0:PORTB.RB6        6   PORTB bit 6
BANK0:PORTB.RB5        5   PORTB bit 5
BANK0:PORTB.RB4        4   PORTB bit 4
BANK0:PORTB.RB3        3   PORTB bit 3
BANK0:PORTB.RB2        2   PORTB bit 2
BANK0:PORTB.RB1        1   PORTB bit 1
BANK0:PORTB.RB0        0   PORTB bit 0

; BANK1 (0x0020:0x0040)
BANK1:INDF            0x0020   INDF (not a physical register)
BANK1:TMR0            0x0021   Timer0 Module Register
BANK1:PCL             0x0022   Low order 8 bits of PC
BANK1:STATUS          0x0023   STATUS REGISTER
BANK1:STATUS.PA1       6   Program page preselect bit 1
BANK1:STATUS.PA0       5   Program page preselect bit 0
BANK1:STATUS.TO        4   Time-out bit
BANK1:STATUS.PD        3   Power-down bit
BANK1:STATUS.Z         2   Zero bit
BANK1:STATUS.DC        1   Digit carry/borrow bit
BANK1:STATUS.C         0   Carry/borrow bit
BANK1:FSR             0x0024   Indirect data memory address pointer
BANK1:PORTA           0x0025   PORTA REGISTER
BANK1:PORTA.RA3        3   PORTA bit 3
BANK1:PORTA.RA2        2   PORTA bit 2
BANK1:PORTA.RA1        1   PORTA bit 1
BANK1:PORTA.RA0        0   PORTA bit 0
BANK1:PORTB           0x0026   PORTB REGISTER
BANK1:PORTB.RB7        7   PORTB bit 7
BANK1:PORTB.RB6        6   PORTB bit 6
BANK1:PORTB.RB5        5   PORTB bit 5
BANK1:PORTB.RB4        4   PORTB bit 4
BANK1:PORTB.RB3        3   PORTB bit 3
BANK1:PORTB.RB2        2   PORTB bit 2
BANK1:PORTB.RB1        1   PORTB bit 1
BANK1:PORTB.RB0        0   PORTB bit 0

; BANK2 (0x0040:0x0060)
BANK2:INDF            0x0040   INDF (not a physical register)
BANK2:TMR0            0x0041   Timer0 Module Register
BANK2:PCL             0x0042   Low order 8 bits of PC
BANK2:STATUS          0x0043   STATUS REGISTER
BANK2:STATUS.PA1       6   Program page preselect bit 1
BANK2:STATUS.PA0       5   Program page preselect bit 0
BANK2:STATUS.TO        4   Time-out bit
BANK2:STATUS.PD        3   Power-down bit
BANK2:STATUS.Z         2   Zero bit
BANK2:STATUS.DC        1   Digit carry/borrow bit
BANK2:STATUS.C         0   Carry/borrow bit
BANK2:FSR             0x0044   Indirect data memory address pointer
BANK2:PORTA           0x0045   PORTA REGISTER
BANK2:PORTA.RA3        3   PORTA bit 3
BANK2:PORTA.RA2        2   PORTA bit 2
BANK2:PORTA.RA1        1   PORTA bit 1
BANK2:PORTA.RA0        0   PORTA bit 0
BANK2:PORTB           0x0046   PORTB REGISTER
BANK2:PORTB.RB7        7   PORTB bit 7
BANK2:PORTB.RB6        6   PORTB bit 6
BANK2:PORTB.RB5        5   PORTB bit 5
BANK2:PORTB.RB4        4   PORTB bit 4
BANK2:PORTB.RB3        3   PORTB bit 3
BANK2:PORTB.RB2        2   PORTB bit 2
BANK2:PORTB.RB1        1   PORTB bit 1
BANK2:PORTB.RB0        0   PORTB bit 0

; BANK3 (0x0060:0x0080)
BANK3:INDF            0x0060   INDF (not a physical register)
BANK3:TMR0            0x0061   Timer0 Module Register
BANK3:PCL             0x0062   Low order 8 bits of PC
BANK3:STATUS          0x0063   STATUS REGISTER
BANK3:STATUS.PA1       6   Program page preselect bit 1
BANK3:STATUS.PA0       5   Program page preselect bit 0
BANK3:STATUS.TO        4   Time-out bit
BANK3:STATUS.PD        3   Power-down bit
BANK3:STATUS.Z         2   Zero bit
BANK3:STATUS.DC        1   Digit carry/borrow bit
BANK3:STATUS.C         0   Carry/borrow bit
BANK3:FSR             0x0064   Indirect data memory address pointer
BANK3:PORTA           0x0065   PORTA REGISTER
BANK3:PORTA.RA3        3   PORTA bit 3
BANK3:PORTA.RA2        2   PORTA bit 2
BANK3:PORTA.RA1        1   PORTA bit 1
BANK3:PORTA.RA0        0   PORTA bit 0
BANK3:PORTB           0x0066   PORTB REGISTER
BANK3:PORTB.RB7        7   PORTB bit 7
BANK3:PORTB.RB6        6   PORTB bit 6
BANK3:PORTB.RB5        5   PORTB bit 5
BANK3:PORTB.RB4        4   PORTB bit 4
BANK3:PORTB.RB3        3   PORTB bit 3
BANK3:PORTB.RB2        2   PORTB bit 2
BANK3:PORTB.RB1        1   PORTB bit 1
BANK3:PORTB.RB0        0   PORTB bit 0


.16CR54
; http://www.microchip.com/download/lit/pline/picmicro/families/16c5x/30453d.pdf
; PIC16C5X.pdf


; MEMORY MAP
area DATA FSR_           0x0000:0x0007
area DATA Gen_Purp       0x0007:0x0020   General Purpose Register
area CODE MEM_Program0   0x0020:0x01FF   On-chip Program Memory (Page 0)


; Interrupt and reset vector assignments
entry RESET      0x01FF     RESET


; INPUT/OUTPUT PORTS
INDF            0x0000   INDF (not a physical register)
TMR0            0x0001   Timer0 Module Register
PCL             0x0002   Low order 8 bits of PC
STATUS          0x0003   STATUS REGISTER
STATUS.PA1       6   Program page preselect bit 1
STATUS.PA0       5   Program page preselect bit 0
STATUS.TO        4   Time-out bit
STATUS.PD        3   Power-down bit
STATUS.Z         2   Zero bit
STATUS.DC        1   Digit carry/borrow bit
STATUS.C         0   Carry/borrow bit
FSR             0x0004   Indirect data memory address pointer
PORTA           0x0005   PORTA REGISTER
PORTA.RA3        3   PORTA bit 3
PORTA.RA2        2   PORTA bit 2
PORTA.RA1        1   PORTA bit 1
PORTA.RA0        0   PORTA bit 0
PORTB           0x0006   PORTB REGISTER
PORTB.RB7        7   PORTB bit 7
PORTB.RB6        6   PORTB bit 6
PORTB.RB5        5   PORTB bit 5
PORTB.RB4        4   PORTB bit 4
PORTB.RB3        3   PORTB bit 3
PORTB.RB2        2   PORTB bit 2
PORTB.RB1        1   PORTB bit 1
PORTB.RB0        0   PORTB bit 0


.16CR56
; http://www.microchip.com/download/lit/pline/picmicro/families/16c5x/30453d.pdf
; PIC16C5X.pdf


; MEMORY MAP
area DATA FSR_           0x0000:0x0007
area DATA Gen_Purp       0x0007:0x0020   General Purpose Register
area CODE MEM_Program0   0x0020:0x0200   On-chip Program Memory (Page 0)
area CODE MEM_Program1   0x0200:0x03FF   On-chip Program Memory (Page 1)


; Interrupt and reset vector assignments
entry RESET      0x03FF     RESET


; INPUT/OUTPUT PORTS
INDF            0x0000   INDF (not a physical register)
TMR0            0x0001   Timer0 Module Register
PCL             0x0002   Low order 8 bits of PC
STATUS          0x0003   STATUS REGISTER
STATUS.PA1       6   Program page preselect bit 1
STATUS.PA0       5   Program page preselect bit 0
STATUS.TO        4   Time-out bit
STATUS.PD        3   Power-down bit
STATUS.Z         2   Zero bit
STATUS.DC        1   Digit carry/borrow bit
STATUS.C         0   Carry/borrow bit
FSR             0x0004   Indirect data memory address pointer
PORTA           0x0005   PORTA REGISTER
PORTA.RA3        3   PORTA bit 3
PORTA.RA2        2   PORTA bit 2
PORTA.RA1        1   PORTA bit 1
PORTA.RA0        0   PORTA bit 0
PORTB           0x0006   PORTB REGISTER
PORTB.RB7        7   PORTB bit 7
PORTB.RB6        6   PORTB bit 6
PORTB.RB5        5   PORTB bit 5
PORTB.RB4        4   PORTB bit 4
PORTB.RB3        3   PORTB bit 3
PORTB.RB2        2   PORTB bit 2
PORTB.RB1        1   PORTB bit 1
PORTB.RB0        0   PORTB bit 0


.16CR57
; http://www.microchip.com/download/lit/pline/picmicro/families/16c5x/30453d.pdf
; PIC16C5X.pdf


; MEMORY MAP
; BANK_0
area DATA FSR_           0x0000:0x0008
area DATA Gen_Purp       0x0008:0x0020   General Purpose Register
area CODE MEM_Program0   0x0020:0x0200   On-chip Program Memory (Page 0)
area CODE MEM_Program1   0x0200:0x0400   On-chip Program Memory (Page 1)
area CODE MEM_Program2   0x0400:0x0600   On-chip Program Memory (Page 2)
area CODE MEM_Program3   0x0600:0x07FF   On-chip Program Memory (Page 3)

; BANK_1
; area DATA FSR_           0x0020:0x0028
; area DATA Gen_Purp       0x0028:0x0040   General Purpose Register
; area CODE MEM_Program0   0x0040:0x0200   On-chip Program Memory (Page 0)
; area CODE MEM_Program1   0x0200:0x0400   On-chip Program Memory (Page 1)
; area CODE MEM_Program2   0x0400:0x0600   On-chip Program Memory (Page 2)
; area CODE MEM_Program3   0x0600:0x07FF   On-chip Program Memory (Page 3)

; BANK_2
; area DATA FSR_           0x0040:0x0048
; area DATA Gen_Purp       0x0048:0x0060   General Purpose Register
; area CODE MEM_Program0   0x0060:0x0200   On-chip Program Memory (Page 0)
; area CODE MEM_Program1   0x0200:0x0400   On-chip Program Memory (Page 1)
; area CODE MEM_Program2   0x0400:0x0600   On-chip Program Memory (Page 2)
; area CODE MEM_Program3   0x0600:0x07FF   On-chip Program Memory (Page 3)

; BANK_3
; area DATA FSR_           0x0060:0x0068
; area DATA Gen_Purp       0x0068:0x0080   General Purpose Register
; area CODE MEM_Program0   0x0080:0x0200   On-chip Program Memory (Page 0)
; area CODE MEM_Program1   0x0200:0x0400   On-chip Program Memory (Page 1)
; area CODE MEM_Program2   0x0400:0x0600   On-chip Program Memory (Page 2)
; area CODE MEM_Program3   0x0600:0x07FF   On-chip Program Memory (Page 3)


; Interrupt and reset vector assignments
entry RESET      0x07FF     RESET


; INPUT/OUTPUT PORTS
; BANK0 (0x0000:0x0020)
BANK0:INDF            0x0000   INDF (not a physical register)
BANK0:TMR0            0x0001   Timer0 Module Register
BANK0:PCL             0x0002   Low order 8 bits of PC
BANK0:STATUS          0x0003   STATUS REGISTER
BANK0:STATUS.PA1       6   Program page preselect bit 1
BANK0:STATUS.PA0       5   Program page preselect bit 0
BANK0:STATUS.TO        4   Time-out bit
BANK0:STATUS.PD        3   Power-down bit
BANK0:STATUS.Z         2   Zero bit
BANK0:STATUS.DC        1   Digit carry/borrow bit
BANK0:STATUS.C         0   Carry/borrow bit
BANK0:FSR             0x0004   Indirect data memory address pointer
BANK0:PORTA           0x0005   PORTA REGISTER
BANK0:PORTA.RA3        3   PORTA bit 3
BANK0:PORTA.RA2        2   PORTA bit 2
BANK0:PORTA.RA1        1   PORTA bit 1
BANK0:PORTA.RA0        0   PORTA bit 0
BANK0:PORTB           0x0006   PORTB REGISTER
BANK0:PORTB.RB7        7   PORTB bit 7
BANK0:PORTB.RB6        6   PORTB bit 6
BANK0:PORTB.RB5        5   PORTB bit 5
BANK0:PORTB.RB4        4   PORTB bit 4
BANK0:PORTB.RB3        3   PORTB bit 3
BANK0:PORTB.RB2        2   PORTB bit 2
BANK0:PORTB.RB1        1   PORTB bit 1
BANK0:PORTB.RB0        0   PORTB bit 0
BANK0:PORTC           0x0007   PORTC REGISTER
BANK0:PORTC.RC7        7   PORTC bit 7
BANK0:PORTC.RC6        6   PORTC bit 6
BANK0:PORTC.RC5        5   PORTC bit 5
BANK0:PORTC.RC4        4   PORTC bit 4
BANK0:PORTC.RC3        3   PORTC bit 3
BANK0:PORTC.RC2        2   PORTC bit 2
BANK0:PORTC.RC1        1   PORTC bit 1
BANK0:PORTC.RC0        0   PORTC bit 0

; BANK1 (0x0020:0x0040)
BANK1:INDF            0x0020   INDF (not a physical register)
BANK1:TMR0            0x0021   Timer0 Module Register
BANK1:PCL             0x0022   Low order 8 bits of PC
BANK1:STATUS          0x0023   STATUS REGISTER
BANK1:STATUS.PA1       6   Program page preselect bit 1
BANK1:STATUS.PA0       5   Program page preselect bit 0
BANK1:STATUS.TO        4   Time-out bit
BANK1:STATUS.PD        3   Power-down bit
BANK1:STATUS.Z         2   Zero bit
BANK1:STATUS.DC        1   Digit carry/borrow bit
BANK1:STATUS.C         0   Carry/borrow bit
BANK1:FSR             0x0024   Indirect data memory address pointer
BANK1:PORTA           0x0025   PORTA REGISTER
BANK1:PORTA.RA3        3   PORTA bit 3
BANK1:PORTA.RA2        2   PORTA bit 2
BANK1:PORTA.RA1        1   PORTA bit 1
BANK1:PORTA.RA0        0   PORTA bit 0
BANK1:PORTB           0x0026   PORTB REGISTER
BANK1:PORTB.RB7        7   PORTB bit 7
BANK1:PORTB.RB6        6   PORTB bit 6
BANK1:PORTB.RB5        5   PORTB bit 5
BANK1:PORTB.RB4        4   PORTB bit 4
BANK1:PORTB.RB3        3   PORTB bit 3
BANK1:PORTB.RB2        2   PORTB bit 2
BANK1:PORTB.RB1        1   PORTB bit 1
BANK1:PORTB.RB0        0   PORTB bit 0
BANK1:PORTC           0x0027   PORTC REGISTER
BANK1:PORTC.RC7        7   PORTC bit 7
BANK1:PORTC.RC6        6   PORTC bit 6
BANK1:PORTC.RC5        5   PORTC bit 5
BANK1:PORTC.RC4        4   PORTC bit 4
BANK1:PORTC.RC3        3   PORTC bit 3
BANK1:PORTC.RC2        2   PORTC bit 2
BANK1:PORTC.RC1        1   PORTC bit 1
BANK1:PORTC.RC0        0   PORTC bit 0

; BANK2 (0x0040:0x0060)
BANK2:INDF            0x0040   INDF (not a physical register)
BANK2:TMR0            0x0041   Timer0 Module Register
BANK2:PCL             0x0042   Low order 8 bits of PC
BANK2:STATUS          0x0043   STATUS REGISTER
BANK2:STATUS.PA1       6   Program page preselect bit 1
BANK2:STATUS.PA0       5   Program page preselect bit 0
BANK2:STATUS.TO        4   Time-out bit
BANK2:STATUS.PD        3   Power-down bit
BANK2:STATUS.Z         2   Zero bit
BANK2:STATUS.DC        1   Digit carry/borrow bit
BANK2:STATUS.C         0   Carry/borrow bit
BANK2:FSR             0x0044   Indirect data memory address pointer
BANK2:PORTA           0x0045   PORTA REGISTER
BANK2:PORTA.RA3        3   PORTA bit 3
BANK2:PORTA.RA2        2   PORTA bit 2
BANK2:PORTA.RA1        1   PORTA bit 1
BANK2:PORTA.RA0        0   PORTA bit 0
BANK2:PORTB           0x0046   PORTB REGISTER
BANK2:PORTB.RB7        7   PORTB bit 7
BANK2:PORTB.RB6        6   PORTB bit 6
BANK2:PORTB.RB5        5   PORTB bit 5
BANK2:PORTB.RB4        4   PORTB bit 4
BANK2:PORTB.RB3        3   PORTB bit 3
BANK2:PORTB.RB2        2   PORTB bit 2
BANK2:PORTB.RB1        1   PORTB bit 1
BANK2:PORTB.RB0        0   PORTB bit 0
BANK2:PORTC           0x0047   PORTC REGISTER
BANK2:PORTC.RC7        7   PORTC bit 7
BANK2:PORTC.RC6        6   PORTC bit 6
BANK2:PORTC.RC5        5   PORTC bit 5
BANK2:PORTC.RC4        4   PORTC bit 4
BANK2:PORTC.RC3        3   PORTC bit 3
BANK2:PORTC.RC2        2   PORTC bit 2
BANK2:PORTC.RC1        1   PORTC bit 1
BANK2:PORTC.RC0        0   PORTC bit 0

; BANK3 (0x0060:0x0080)
BANK3:INDF            0x0060   INDF (not a physical register)
BANK3:TMR0            0x0061   Timer0 Module Register
BANK3:PCL             0x0062   Low order 8 bits of PC
BANK3:STATUS          0x0063   STATUS REGISTER
BANK3:STATUS.PA1       6   Program page preselect bit 1
BANK3:STATUS.PA0       5   Program page preselect bit 0
BANK3:STATUS.TO        4   Time-out bit
BANK3:STATUS.PD        3   Power-down bit
BANK3:STATUS.Z         2   Zero bit
BANK3:STATUS.DC        1   Digit carry/borrow bit
BANK3:STATUS.C         0   Carry/borrow bit
BANK3:FSR             0x0064   Indirect data memory address pointer
BANK3:PORTA           0x0065   PORTA REGISTER
BANK3:PORTA.RA3        3   PORTA bit 3
BANK3:PORTA.RA2        2   PORTA bit 2
BANK3:PORTA.RA1        1   PORTA bit 1
BANK3:PORTA.RA0        0   PORTA bit 0
BANK3:PORTB           0x0066   PORTB REGISTER
BANK3:PORTB.RB7        7   PORTB bit 7
BANK3:PORTB.RB6        6   PORTB bit 6
BANK3:PORTB.RB5        5   PORTB bit 5
BANK3:PORTB.RB4        4   PORTB bit 4
BANK3:PORTB.RB3        3   PORTB bit 3
BANK3:PORTB.RB2        2   PORTB bit 2
BANK3:PORTB.RB1        1   PORTB bit 1
BANK3:PORTB.RB0        0   PORTB bit 0
BANK3:PORTC           0x0067   PORTC REGISTER
BANK3:PORTC.RC7        7   PORTC bit 7
BANK3:PORTC.RC6        6   PORTC bit 6
BANK3:PORTC.RC5        5   PORTC bit 5
BANK3:PORTC.RC4        4   PORTC bit 4
BANK3:PORTC.RC3        3   PORTC bit 3
BANK3:PORTC.RC2        2   PORTC bit 2
BANK3:PORTC.RC1        1   PORTC bit 1
BANK3:PORTC.RC0        0   PORTC bit 0


.16CR58
; http://www.microchip.com/download/lit/pline/picmicro/families/16c5x/30453d.pdf
; PIC16C5X.pdf


; MEMORY MAP
; BANK_0
area DATA FSR_           0x0000:0x0007
area DATA Gen_Purp       0x0007:0x0020   General Purpose Register
area CODE MEM_Program0   0x0020:0x0200   On-chip Program Memory (Page 0)
area CODE MEM_Program1   0x0200:0x0400   On-chip Program Memory (Page 1)
area CODE MEM_Program2   0x0400:0x0600   On-chip Program Memory (Page 2)
area CODE MEM_Program3   0x0600:0x07FF   On-chip Program Memory (Page 3)

; BANK_1
; area DATA FSR_           0x0020:0x0027
; area DATA Gen_Purp       0x0027:0x0040   General Purpose Register
; area CODE MEM_Program0   0x0040:0x0200   On-chip Program Memory (Page 0)
; area CODE MEM_Program1   0x0200:0x0400   On-chip Program Memory (Page 1)
; area CODE MEM_Program2   0x0400:0x0600   On-chip Program Memory (Page 2)
; area CODE MEM_Program3   0x0600:0x07FF   On-chip Program Memory (Page 3)

; BANK_2
; area DATA FSR_           0x0040:0x0047
; area DATA Gen_Purp       0x0047:0x0060   General Purpose Register
; area CODE MEM_Program0   0x0060:0x0200   On-chip Program Memory (Page 0)
; area CODE MEM_Program1   0x0200:0x0400   On-chip Program Memory (Page 1)
; area CODE MEM_Program2   0x0400:0x0600   On-chip Program Memory (Page 2)
; area CODE MEM_Program3   0x0600:0x07FF   On-chip Program Memory (Page 3)

; BANK_3
; area DATA FSR_           0x0060:0x0067
; area DATA Gen_Purp       0x0067:0x0080   General Purpose Register
; area CODE MEM_Program0   0x0080:0x0200   On-chip Program Memory (Page 0)
; area CODE MEM_Program1   0x0200:0x0400   On-chip Program Memory (Page 1)
; area CODE MEM_Program2   0x0400:0x0600   On-chip Program Memory (Page 2)
; area CODE MEM_Program3   0x0600:0x07FF   On-chip Program Memory (Page 3)


; Interrupt and reset vector assignments
entry RESET      0x07FF     RESET


; INPUT/OUTPUT PORTS
; BANK0 (0x0000:0x0020)
BANK0:INDF            0x0000   INDF (not a physical register)
BANK0:TMR0            0x0001   Timer0 Module Register
BANK0:PCL             0x0002   Low order 8 bits of PC
BANK0:STATUS          0x0003   STATUS REGISTER
BANK0:STATUS.PA1       6   Program page preselect bit 1
BANK0:STATUS.PA0       5   Program page preselect bit 0
BANK0:STATUS.TO        4   Time-out bit
BANK0:STATUS.PD        3   Power-down bit
BANK0:STATUS.Z         2   Zero bit
BANK0:STATUS.DC        1   Digit carry/borrow bit
BANK0:STATUS.C         0   Carry/borrow bit
BANK0:FSR             0x0004   Indirect data memory address pointer
BANK0:PORTA           0x0005   PORTA REGISTER
BANK0:PORTA.RA3        3   PORTA bit 3
BANK0:PORTA.RA2        2   PORTA bit 2
BANK0:PORTA.RA1        1   PORTA bit 1
BANK0:PORTA.RA0        0   PORTA bit 0
BANK0:PORTB           0x0006   PORTB REGISTER
BANK0:PORTB.RB7        7   PORTB bit 7
BANK0:PORTB.RB6        6   PORTB bit 6
BANK0:PORTB.RB5        5   PORTB bit 5
BANK0:PORTB.RB4        4   PORTB bit 4
BANK0:PORTB.RB3        3   PORTB bit 3
BANK0:PORTB.RB2        2   PORTB bit 2
BANK0:PORTB.RB1        1   PORTB bit 1
BANK0:PORTB.RB0        0   PORTB bit 0

; BANK1  (0x0020:0x0040)
BANK1:INDF            0x0020   INDF (not a physical register)
BANK1:TMR0            0x0021   Timer0 Module Register
BANK1:PCL             0x0022   Low order 8 bits of PC
BANK1:STATUS          0x0023   STATUS REGISTER
BANK1:STATUS.PA1       6   Program page preselect bit 1
BANK1:STATUS.PA0       5   Program page preselect bit 0
BANK1:STATUS.TO        4   Time-out bit
BANK1:STATUS.PD        3   Power-down bit
BANK1:STATUS.Z         2   Zero bit
BANK1:STATUS.DC        1   Digit carry/borrow bit
BANK1:STATUS.C         0   Carry/borrow bit
BANK1:FSR             0x0024   Indirect data memory address pointer
BANK1:PORTA           0x0025   PORTA REGISTER
BANK1:PORTA.RA3        3   PORTA bit 3
BANK1:PORTA.RA2        2   PORTA bit 2
BANK1:PORTA.RA1        1   PORTA bit 1
BANK1:PORTA.RA0        0   PORTA bit 0
BANK1:PORTB           0x0026   PORTB REGISTER
BANK1:PORTB.RB7        7   PORTB bit 7
BANK1:PORTB.RB6        6   PORTB bit 6
BANK1:PORTB.RB5        5   PORTB bit 5
BANK1:PORTB.RB4        4   PORTB bit 4
BANK1:PORTB.RB3        3   PORTB bit 3
BANK1:PORTB.RB2        2   PORTB bit 2
BANK1:PORTB.RB1        1   PORTB bit 1
BANK1:PORTB.RB0        0   PORTB bit 0

; BANK2 (0x0040:0x0060)
BANK2:INDF            0x0040   INDF (not a physical register)
BANK2:TMR0            0x0041   Timer0 Module Register
BANK2:PCL             0x0042   Low order 8 bits of PC
BANK2:STATUS          0x0043   STATUS REGISTER
BANK2:STATUS.PA1       6   Program page preselect bit 1
BANK2:STATUS.PA0       5   Program page preselect bit 0
BANK2:STATUS.TO        4   Time-out bit
BANK2:STATUS.PD        3   Power-down bit
BANK2:STATUS.Z         2   Zero bit
BANK2:STATUS.DC        1   Digit carry/borrow bit
BANK2:STATUS.C         0   Carry/borrow bit
BANK2:FSR             0x0044   Indirect data memory address pointer
BANK2:PORTA           0x0045   PORTA REGISTER
BANK2:PORTA.RA3        3   PORTA bit 3
BANK2:PORTA.RA2        2   PORTA bit 2
BANK2:PORTA.RA1        1   PORTA bit 1
BANK2:PORTA.RA0        0   PORTA bit 0
BANK2:PORTB           0x0046   PORTB REGISTER
BANK2:PORTB.RB7        7   PORTB bit 7
BANK2:PORTB.RB6        6   PORTB bit 6
BANK2:PORTB.RB5        5   PORTB bit 5
BANK2:PORTB.RB4        4   PORTB bit 4
BANK2:PORTB.RB3        3   PORTB bit 3
BANK2:PORTB.RB2        2   PORTB bit 2
BANK2:PORTB.RB1        1   PORTB bit 1
BANK2:PORTB.RB0        0   PORTB bit 0

; BANK3 (0x0060:0x0080)
BANK3:INDF            0x0060   INDF (not a physical register)
BANK3:TMR0            0x0061   Timer0 Module Register
BANK3:PCL             0x0062   Low order 8 bits of PC
BANK3:STATUS          0x0063   STATUS REGISTER
BANK3:STATUS.PA1       6   Program page preselect bit 1
BANK3:STATUS.PA0       5   Program page preselect bit 0
BANK3:STATUS.TO        4   Time-out bit
BANK3:STATUS.PD        3   Power-down bit
BANK3:STATUS.Z         2   Zero bit
BANK3:STATUS.DC        1   Digit carry/borrow bit
BANK3:STATUS.C         0   Carry/borrow bit
BANK3:FSR             0x0064   Indirect data memory address pointer
BANK3:PORTA           0x0065   PORTA REGISTER
BANK3:PORTA.RA3        3   PORTA bit 3
BANK3:PORTA.RA2        2   PORTA bit 2
BANK3:PORTA.RA1        1   PORTA bit 1
BANK3:PORTA.RA0        0   PORTA bit 0
BANK3:PORTB           0x0066   PORTB REGISTER
BANK3:PORTB.RB7        7   PORTB bit 7
BANK3:PORTB.RB6        6   PORTB bit 6
BANK3:PORTB.RB5        5   PORTB bit 5
BANK3:PORTB.RB4        4   PORTB bit 4
BANK3:PORTB.RB3        3   PORTB bit 3
BANK3:PORTB.RB2        2   PORTB bit 2
BANK3:PORTB.RB1        1   PORTB bit 1
BANK3:PORTB.RB0        0   PORTB bit 0


```
