```ini

;       This file describes the standard addresses for Motorola DSP561xx

.default 561xx

entry HRESET          0x0000  Hardware RESET
entry ILLEGAL         0x0002  Illegal Instruction
entry STACKERROR      0x0004  Stack Error
entry SWI             0x0008  Software Interrupt
entry IRQA            0x000A  IRQA
entry IRQB            0x000C  IRQB
entry SSI0RxwExcept   0x0010  SSI0 Receive Data with Exception
entry SSI0Rx          0x0012  SSI0 Receive Data
entry SSI0TxwExcept   0x0014  SSI0 Transmit Data with Exception
entry SSI0Tx          0x0016  SSI0 Transmit Data
entry SSI1RxwExcept   0x0018  SSI1 Receive Data with Exception
entry SSI1Rx          0x001A  SSI1 Receive Data
entry SSI1TxwExcept   0x001C  SSI1 Transmit Data with Exception
entry SSI1Tx          0x001E  SSI1 Transmit Data
entry TimerOVF        0x0020  Timer Overflow
entry TimerCMP        0x0022  Timer Compare
entry HostDMARx       0x0024  Host DMA Receive Data
entry HostDMATx       0x0026  Host DMA Transmit Data
entry HostRx          0x0028  Host Receive Data
entry HostTx          0x002A  Host Transmit Data
entry HostCMD         0x002C  Host Command (default)
entry CodecTxRx       0x002E  Codec Receive/Transmit

.561xx
PBC             0xFFC0
PCC             0xFFC1
PBDD            0xFFC2
PCDD            0xFFC3
HCR             0xFFC4
COCR            0xFFC8
CRASSI0 0xFFD0
CRBSSI0 0xFFD1
CRASSI1 0xFFD8
CRBSSI1 0xFFD9
PLCR            0xFFDC
BCR             0xFFDE
IPR             0xFFDF
PBD             0xFFE2
PCD             0xFFE3
HSR             0xFFE4
HTXRX           0xFFE5
COSR            0xFFE9
CRXTX           0xFFEA
TCR             0xFFEC
TCTR            0xFFED
TCPR            0xFFEE
TPR             0xFFEF
SRSSI0  0xFFF0
TXRXSSI0        0xFFF1
RSMA0           0xFFF2
RSMB0           0xFFF3
TSMA0           0xFFF4
TSMB0           0xFFF5
SRSSI1  0xFFF8
TXRXSSI1        0xFFF9
RSMA1           0xFFFA
RSMB1           0xFFFB
TSMA1           0xFFFC
TSMB1           0xFFFD

```
