package main

import (
        "fmt"
        "github.com/google/gopacket"
        "github.com/google/gopacket/pcap"
)

/*

This example shows creating a custom BPF in opcode that can be loaded into memory
This custom example takes consideration of VT-TAG, Nested VLAN tag (upto 3)
VLAN tags, then find the correct place for IPv4 or IPv6 and filters on the src/dst given
You'd need to continue to the Transport layer and check for ports etc. 

to create your filter use
https://www.systutorials.com/docs/linux/man/8-bpfc/

put your opcode into a txt file (its just easier) and compile
bpfc  -i bpf_opcode.txt -V -p

http://medium.com/@cjoudrey/capturing-http-packets-the-hard-way-b9c799bfb6

I don't seem to be able to jump backwards it errors, only forwards in code.
Although the compiler allows backwards, the filter fails to be created
*/


var ip [10]uint32
var port [10]uint32

func main() {
        ip[0] = uint32(127<<24 + 0<<16 + 0<<8 + 1)
        port[0] = uint32(5060)
        fmt.Printf("Listening for: IP %x, port %x\n", ip, port)


        handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
        if err != nil {
                panic(err)
        }
        bpfInstructions := []pcap.BPFInstruction{
                // Start pointer at 0 and read EthType
                { 0x1, 0, 0, 0x00000000 },
                { 0x48, 0, 0, 0x0000000c },
                // Check the EthType for VT-Tag
                { 0x15, 0, 4, 0x00008926 },
                { 0x87, 0, 0, 0x00000000 },
                { 0x4, 0, 0, 0x00000006 },
                { 0x7, 0, 0, 0x00000000 },
                { 0x48, 0, 0, 0x0000000c },
                // Check EthType for Nested VLAN tag
// you need to think more before commenting out
                { 0x15, 0, 14, 0x00009100 },
                { 0x87, 0, 0, 0x00000000 },
                { 0x4, 0, 0, 0x00000004 },
                { 0x7, 0, 0, 0x00000000 },
                { 0x48, 0, 0, 0x0000000c },
                // Check EthType for Nested VLAN tag 
                { 0x15, 0, 9, 0x00009100 },
                { 0x87, 0, 0, 0x00000000 },
                { 0x4, 0, 0, 0x00000004 },
                { 0x7, 0, 0, 0x00000000 },
                { 0x48, 0, 0, 0x0000000c },
                // Check EthType for Nested VLAN tag
                { 0x15, 0, 4, 0x00009100 },
                { 0x87, 0, 0, 0x00000000 },
                { 0x4, 0, 0, 0x00000004 },
                { 0x7, 0, 0, 0x00000000 },
                { 0x48, 0, 0, 0x0000000c },
                // Check EthType for VLAN tag
                { 0x15, 0, 4, 0x00008100 },
                { 0x87, 0, 0, 0x00000000 },
                { 0x4, 0, 0, 0x00000004 },
                { 0x7, 0, 0, 0x00000000 },
                { 0x48, 0, 0, 0x0000000c },
                // Check EthType for IPv4
                { 0x15, 1, 0, 0x00000800 },
                { 0x6, 0, 0, 0x00000000 },
                // Check the IP header for IPv4
                { 0x50, 0, 0, 0x0000000e },
                { 0x54, 0, 0, 0x000000f0 },
                { 0x15, 1, 0, 0x00000040 },
                { 0x6, 0, 0, 0x00000000 },
                // Move pointer to Network Layer
                { 0x87, 0, 0, 0x00000000 },
                { 0x4, 0, 0, 0x0000000e },
                { 0x7, 0, 0, 0x00000000 },
                // Check for UDP or TCP
                { 0x50, 0, 0, 0x00000009 },
                { 0x15, 2, 0, 0x00000011 },
                { 0x15, 1, 0, 0x00000006 },
                { 0x6, 0, 0, 0x00000000 },
                // Filter for the IPv4 Src Addr
//think more before commenting out
                { 0x40, 0, 0, 0x0000000c },
                { 0x15, 21, 0, ip[9] },
                { 0x15, 20, 0, ip[8] },
                { 0x15, 19, 0, ip[7] },
                { 0x15, 18, 0, ip[6] },
                { 0x15, 17, 0, ip[5] },
                { 0x15, 16, 0, ip[4] },
                { 0x15, 15, 0, ip[3] },
                { 0x15, 14, 0, ip[2] },
                { 0x15, 13, 0, ip[1] },
                { 0x15, 12, 0, ip[0] },
                // Filter for the IPv4 Dst Addr
                { 0x40, 0, 0, 0x00000010 },
                { 0x15, 10, 0, ip[9] },
                { 0x15, 9, 0, ip[8] },
                { 0x15, 8, 0, ip[7] },
                { 0x15, 7, 0, ip[6] },
                { 0x15, 6, 0, ip[5] },
                { 0x15, 5, 0, ip[4] },
                { 0x15, 4, 0, ip[3] },
                { 0x15, 3, 0, ip[2] },
                { 0x15, 2, 0, ip[1] },
                { 0x15, 1, 0, ip[0] },
                { 0x6, 0, 0, 0x00000000 },
                // Move pointer to Transport layer
                { 0x50, 0, 0, 0x00000000 },
                { 0x54, 0, 0, 0x0000000f },
                { 0x24, 0, 0, 0x00000004 },
                { 0xc, 0, 0, 0x00000000 },
                { 0x7, 0, 0, 0x00000000 },
                // Check the SrcPorts
                { 0x48, 0, 0, 0x00000000 },
//                { 0x15, 10, 0, port[9] },
//                { 0x15, 9, 0, port[8] },
//                { 0x15, 8, 0, port[7] },
//                { 0x15, 7, 0, port[6] },
//                { 0x15, 6, 0, port[5] },
//                { 0x15, 5, 0, port[4] },
//                { 0x15, 4, 0, port[3] },
//                { 0x15, 3, 0, port[2] },
//                { 0x15, 2, 0, port[1] },
                { 0x15, 1, 0, port[0] },
                { 0x5, 0, 0, 0x00000001 },
                { 0x6, 0, 0, 0xffffffff },
                // Check the DstPorts
                { 0x48, 0, 0, 0x00000002 },
//                { 0x15, 10, 0, port[9] },
//                { 0x15, 9, 0, port[8] },
//                { 0x15, 8, 0, port[7] },
//                { 0x15, 7, 0, port[6] },
//                { 0x15, 6, 0, port[5] },
//                { 0x15, 5, 0, port[4] },
//                { 0x15, 4, 0, port[3] },
//                { 0x15, 3, 0, port[2] },
//                { 0x15, 2, 0, port[1] },
                { 0x15, 1, 0, port[0] },
                { 0x6, 0, 0, 0x00000000 },
                { 0x6, 0, 0, 0xffffffff },
        }

if err := handle.SetBPFInstructionFilter(bpfInstructions); err != nil {
                panic(err)
        }

        packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
        for packet := range packetSource.Packets() {
                fmt.Printf("%s", packet.Dump())
        }
}
