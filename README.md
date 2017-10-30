# Medtronic-6xx
Medtronic 6xx 802.15.4 musings

Serial numbers of devices available on request.

SPI configuration options for the CC2430 from the datasheet are:

⦁	USART0		MI,MO,SS,C P0/2,3,4,5	pins 13,14,15,16	

⦁	USART0 alt2	MI,MO,SS,C P1/4,5,2,3	pins 4,3,6,5

⦁	USART1		MI,MO,SS,C P0/5,4,2,3	pins 16,15,13,14

⦁	USART1 alt2	MI,MO,SS,C P1/7,6,4,5	pins 1,2,4,3 	

Pins 4 & 6 joined by trace on PCB eliminates  USART0 alt2 configuration

Saleae Logic8 logic analyser connections:

ch	0,1,2,3,4

pin	1,2,3,4,5

Confirmed that valid SPI data seen with USART1 alt2 configuration

Using TI Sniffer with CC2531 USB dongle revealed Zigbee traffic on channel 0x17 (2465MHz)

Tests performed:

1 	autoconnect from pump to CNL24

2 	disconnect pump from CNL24

2a	delete pump from CNL24

3	manual connect CNL24

4	disconnect from CNL24

5	autoconnect CNL24

remote bolus of 0.1U, 0.5U, 1.0U and 5.0U

All of this was captured on channel 0x17



