// PSD (TI RF Packet Sniffer Format) to PCAP Converter
// Version 1.0.0
// This program takes in a PSD file and converts it to PCAP format for use in programs like Wireshark.
// Copyright (C) 2010 Torrey M. Bievenour

//  This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//  This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
//    See the GNU General Public License for more details.
//  You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 
// PSD_2_PCAP_Convert.cpp : Defines the entry point for the console application.
// Convert to C to avoid using C++ libraries.
 
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
 
// const int PSD_Packet_Size = 151;
 
#pragma pack (1)
struct PSD_Packet_s
{
        uint8_t Information;
        uint32_t Number;
        uint64_t Timestamp;
        uint16_t Length;
        unsigned char Remainder[136]; // Based on fixed record size of 151 bytes
};

#pragma pack (1)
struct PCAP_Packet_Header_s
{
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t incl_len;
        uint32_t orig_len;
};
 
uint64_t endian_swap64(uint64_t x)
{
        return (x>>56) |
               ((x<<40) & 0x00FF000000000000) |
               ((x<<24) & 0x0000FF0000000000) |
               ((x<<8) &  0x000000FF00000000) |
               ((x>>8) &  0x00000000FF000000) |
               ((x>>24) & 0x0000000000FF0000) |
               ((x>>40) & 0x000000000000FF00) |
               (x<<56);
}
 
uint32_t endian_swap32(uint32_t x)
{
        return (x>>24) |
               ((x<<8) & 0x00FF0000) |
               ((x>>8) & 0x0000FF00) |
               (x<<24);
}
 
int main(int argc, char* argv[])
{

        if(argc != 3)
        {
               printf("The function requires exactly two arguments, an input and an output file.\n");
               return 1;
        }
        printf("Input File: %s\nOutput File: %s\n", argv[1], argv[2]);
 
        int inFile = open(argv[1], O_RDONLY);
        if(inFile > 0)
        {
               struct PSD_Packet_s inPacket; // Incoming PSD packet
               struct PCAP_Packet_Header_s outPacket; // Outgoing PCAP packet header

               int outFile = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
               if(outFile > 0)
               {  // Write global header
                       uint32_t pcapMagicNumber = 0xa1b2c3d4; // Native byte ordering
                       uint16_t pcapVersionMajor = 2; // Current version is 2.4
                       uint16_t pcapVersionMinor = 4;
                       int32_t pcapThisZone = 0;    // GMT
                       uint32_t pcapSigFigs = 0;    // Zero value for sig figs as standard
                       uint32_t pcapSnapLen = 128;  // Max Zigbee packet length
                       uint32_t pcapNetwork = 0xC3; // Ethernet = 1, 802 Networks = 6, From Wireshark sample PCAP = 0xC3
                       write(outFile, &pcapMagicNumber, sizeof(pcapMagicNumber));
                       write(outFile, &pcapVersionMajor, sizeof(pcapVersionMajor));
                       write(outFile, &pcapVersionMinor, sizeof(pcapVersionMinor));
                       write(outFile, &pcapThisZone, sizeof(pcapThisZone));
                       write(outFile, &pcapSigFigs, sizeof(pcapSigFigs));
                       write(outFile, &pcapSnapLen, sizeof(pcapSnapLen));
                       write(outFile, &pcapNetwork, sizeof(pcapNetwork));
               }
               else
               {
                       printf("Unable to open output file.\n");
                       close(inFile);
                       return 3;
               }
 
               while(read(inFile, &inPacket, sizeof(inPacket)) == sizeof(inPacket))
               {
                        // Length of incoming actual packet data
                        uint8_t inPacketDataLength = inPacket.Length;
 
                        unsigned char* data;
                        // Check Intformation byte to see if length includes FCS.
                        if(inPacket.Information & 0x01 == 0) {
                                inPacketDataLength += 2; // Add FCS to packet length
                                data = inPacket.Remainder;
                        } else {
                                // first byte contains data length
                                data = &inPacket.Remainder[1];
                        }
                               
                        if(inPacketDataLength > 137)
                        {
                                printf("Packet length is too big %d !!!\n", inPacketDataLength);
                                inPacketDataLength = 137;
                        }
        
                        printf("PacketInfo: %02x\tNumber: %04x\tTS: %lu\tLength: %04x\n"
                                "\t <STARTREMAIN>%p<ENDREMAIN>"
                                "<STARTDATA>%x<ENDDATA>%x"
                                "<STARTFCS>%x%x<ENDFCS>\n",
                                inPacket.Information,
                                inPacket.Number,
                                inPacket.Timestamp,
                                inPacketDataLength,
                                inPacket.Remainder,
                                inPacket.Remainder[0],
                                inPacket.Remainder[inPacketDataLength - 3],
                                inPacket.Remainder[inPacketDataLength - 2],  // FCS1
                                inPacket.Remainder[inPacketDataLength - 1]); // FCS2
        
                        // Write packet header
                        uint64_t timestamp = inPacket.Timestamp / 32;
                        outPacket.ts_sec = timestamp / 1000000; // Convert to integer seconds
                        outPacket.ts_usec = timestamp - ((uint64_t)outPacket.ts_sec * 1000000); // Pick up remainder
                        outPacket.incl_len = inPacketDataLength-1; // Get data length as included (include FCS)
                        outPacket.orig_len = inPacketDataLength-1; // Get data length as original (include FCS)
                        printf ("usec %i\n", outPacket.ts_usec);
                        write(outFile, &outPacket, sizeof(outPacket));
                        // Write packet data
                        write(outFile, data, inPacketDataLength -1);
               }
               close(inFile);
               close(outFile);
        }
        else
        {
               printf("Unable to open input file.");
               return 2;
        }
        return 0;
}