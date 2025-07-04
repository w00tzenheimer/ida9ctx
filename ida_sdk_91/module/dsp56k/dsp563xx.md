```ini

;       This file describes the standard addresses for Motorola DSP563xx

.default 56301

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
entry TIMER0CMP            0x0024       TIMER 0 compare
entry TIMER0OWL            0x0026       TIMER 0 overflow
entry TIMER1CMP            0x0028       TIMER 1 compare
entry TIMER1OWL            0x002A       TIMER 1 overflow
entry TIMER2CMP            0x002C       TIMER 2 compare
entry TIMER2OWL            0x002E       TIMER 2 overflow
entry ESSI0Rxd             0x0030       ESSI0 receive data
entry ESSI0RxdwExcept      0x0032       ESSI0 receive data with exception status
entry ESSI0RxdLL           0x0034       ESSI0 receive last slot
entry ESSI0Txd             0x0036       ESSI0 transmit data
entry ESSI0TxdwExcept      0x0038       ESSI0 transmit data with exception status
entry ESSI0TxdLL           0x003A       ESSI0 transmit last slot
entry ESSI1Rxd             0x0040       ESSI1 receive data
entry ESSI1RxdwExcept      0x0042       ESSI1 receive data with exception status
entry ESSI1RxdLL           0x0044       ESSI1 receive last slot
entry ESSI1Txd             0x0046       ESSI1 transmit data
entry ESSI1TxdwExcept      0x0048       ESSI1 transmit data with exception status
entry ESSI1TxdLL           0x004A       ESSI1 transmit last slot
entry SCIRxData            0x0050       SCI receive data
entry SCIRxDatawExcept     0x0052       SCI receive data with exception status
entry SCITxData            0x0054       SCI transmit data
entry SCIidle              0x0056       SCI idle line
entry SCItimer             0x0058       SCI timer
entry HostPCITransTerm     0x0060       Host PCI transaction termination
entry HostPCITransAbort    0x0062       Host PCI transaction abort
entry HostPCIP_error       0x0064       Host PCI parity error
entry HostPCITransCompl    0x0066       Host PCI transfer complete
entry HostPCIMasterRcvReq  0x0068       Host PCI master receive request
entry HostSlaveRcvReq      0x006A       Host slave receive request
entry HostPCIMasterTrxReq  0x006C       Host PCI master transmit request
entry HostSlaveTrxReq      0x006E       Host slave transmit request
entry HostPCIMasterAddrReq 0x0070       Host PCI master address request
entry HostCommand          0x0072       Host command

IPRC     0xFFFFFF
IPRP     0xFFFFFE
PLLCTL   0xFFFFFD
OGDB     0xFFFFFC
BCR      0xFFFFFB
DCR      0xFFFFFA
AAR0     0xFFFFF9
AAR1     0xFFFFF8
AAR2     0xFFFFF7
AAR3     0xFFFFF6
IDR      0xFFFFF5
DSTR     0xFFFFF4
DOR0     0xFFFFF3
DOR1     0xFFFFF2
DOR2     0xFFFFF1
DOR3     0xFFFFF0
DSR0     0xFFFFEF
DDR0     0xFFFFEE
DCO0     0xFFFFED
DCR0     0xFFFFEC
DSR1     0xFFFFEB
DDR1     0xFFFFEA
DCO1     0xFFFFE9
DCR1     0xFFFFE8
DSR2     0xFFFFE7
DDR2     0xFFFFE6
DCO2     0xFFFFE5
DCR2     0xFFFFE4
DSR3     0xFFFFE3
DDR3     0xFFFFE2
DCO3     0xFFFFE1
DCR3     0xFFFFE0
DSR4     0xFFFFDF
DDR4     0xFFFFDE
DCO4     0xFFFFDD
DCR4     0xFFFFDC
DSR5     0xFFFFDB
DDR5     0xFFFFDA
DCO5     0xFFFFD9
DCR5     0xFFFFD8
DATH     0xFFFFCF
DIRH     0xFFFFCE
DTXS     0xFFFFCD
DTXM     0xFFFFCC
DRXR     0xFFFFCB
DPSR     0xFFFFCA
DSR      0xFFFFC9
DPAR     0xFFFFC8
DPMC     0xFFFFC7
DPCR     0xFFFFC6
DCTR     0xFFFFC5
PCRC     0xFFFFBF
PRRC     0xFFFFBE
PDRC     0xFFFFBD
TX00     0xFFFFBC
TX01     0xFFFFBB
TX02     0xFFFFBA
TSR0     0xFFFFB9
RX0      0xFFFFB8
SSISR0   0xFFFFB7
CRB0     0xFFFFB6
CRA0     0xFFFFB5
TSMA0    0xFFFFB4
TSMB0    0xFFFFB3
RSMA0    0xFFFFB2
RSMB0    0xFFFFB1
PCRD     0xFFFFAF
PRRD     0xFFFFAE
PDRD     0xFFFFAD
TX10     0xFFFFAC
TX11     0xFFFFAB
TX12     0xFFFFAA
TSR1     0xFFFFA9
RX1      0xFFFFA8
SSISR1   0xFFFFA7
CRB1     0xFFFFA6
CRA1     0xFFFFA5
TSMA1    0xFFFFA4
TSMB1    0xFFFFA3
RSMA1    0xFFFFA2
RSMB1    0xFFFFA1
PCRE     0xFFFF9F
PRRE     0xFFFF9E
PDRE     0xFFFF9D
SCR      0xFFFF9C
SCCR     0xFFFF9B
SRXH     0xFFFF9A
SRXM     0xFFFF99
SRXL     0xFFFF98
STXH     0xFFFF97
STXM     0xFFFF96
STXL     0xFFFF95
STXA     0xFFFF94
SSR      0xFFFF93
TCSR0    0xFFFF8F
TLR0     0xFFFF8E
TCPR0    0xFFFF8D
TCR0     0xFFFF8C
TCSR1    0xFFFF8B
TLR1     0xFFFF8A
TCPR1    0xFFFF89
TCR1     0xFFFF88
TCSR2    0xFFFF87
TLR2     0xFFFF86
TCPR2    0xFFFF85
TCR2     0xFFFF84
TPLR     0xFFFF83
TPCR     0xFFFF82

.56301

XMEMSIZE = 0x20000
YMEMSIZE = 0x20000


```
