```ini

;       This file describes the standard addresses for Motorola DSP566xx

.default 56600

entry HRESET               0x0000       Hardware RESET
entry STKERR               0x0002       Stack Error
entry ILLEGAL              0x0004       Illegal Instruction
entry DEBUG                0x0006       Debug Request Interrupt
entry TRAP                 0x0008       Trap
entry NMI                  0x000A       Non-Maskable Interrupt
entry IRQA                 0x0010       IRQA
entry IRQB                 0x0012       IRQB
entry IRQC                 0x0014       IRQC
entry IRQD                 0x0016       IRQD
entry DMA0                 0x0018       DMA Channel 0
entry DMA1                 0x001A       DMA Channel 1
entry DMA2                 0x001C       DMA Channel 2
entry DMA3                 0x001E       DMA Channel 3
entry DMA4                 0x0020       DMA Channel 4
entry DMA5                 0x0022       DMA Channel 5

IPRC  0xFFFF Interrupt Priority Register-Core
IPRP  0xFFFE Interrupt Priority Register Peripheral
PCTL0 0xFFFD PLL Control Register 0
PCTL1 0xFFFC PLL Control Register 1
OGDB  0xFFFB ONCE GDB Register
BCR   0xFFFA Bus Control Register
IDR   0xFFF9 ID Register
PAR0  0xFFF8 Patch 0 Register
PAR1  0xFFF7 Patch 1 Register
PAR2  0xFFF6 Patch 2 Register
PAR3  0xFFF5 Patch 3 Register
BPMRG 0xFFF4 BPMRG (24 bits)
BPMRL 0xFFF3 BPMRL (16 bits)
BPMRH 0xFFF2 BPMRH (16 bits)

XMEMSIZE = 0x10000
YMEMSIZE = 0x10000

.56600

; no .56600 specific parameters are specified yet



```
