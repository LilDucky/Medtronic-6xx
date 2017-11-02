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

Second batch of testing - two pumps powered up. Pump for first tests moved from channel 0x17 to 0x14 and new pump was on 0x17

Also captured 2 instances of the CNL SPI bus during power up (once from charging and once from power button)



Excel worksheet uploaded to reformat hex dumps from the packet captures.

paste hex dump into sheet1 and run the packetize macro. results are in sheet 2. not perfect but a good start
