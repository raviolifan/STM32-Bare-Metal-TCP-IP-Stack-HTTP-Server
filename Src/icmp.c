/**
 ******************************************************************************
 * @file    icmp.c
 * @brief   Internet Control Message Protocol (ICMP) implementation.
 *
 * Implements ICMP packet processing, including support for ICMP Echo
 * Request reception and ICMP Echo Reply generation.
 *
 ******************************************************************************
 */

/******************************************************************************
 * Includes
 ******************************************************************************/
#include "icmp.h"
#include "debug.h"
#include "main.h"
#include "ethernet_frame.h"
#include <string.h>
#include "ethernet_driver.h"
#include "checksum.h"
#include "ipv4.h"
#include "network_config.h"
/******************************************************************************
 * Private Types
 ******************************************************************************/

/* Private structures */
typedef struct
{
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint16_t identifier;
	uint16_t sequenceNumber;
} ICMPHeader;

/******************************************************************************
 * Private Constants
 ******************************************************************************/

/* Static configuration tables */
#define ETH_RX_BUFFER_SIZE 		1524
/******************************************************************************
 * Private Variables
 ******************************************************************************/

/* Runtime state */
static uint8_t replyBuffer[ETH_RX_BUFFER_SIZE];
/******************************************************************************
 * Private Function Prototypes
 ******************************************************************************/

/* Print ICMP packet information. */
static void icmpPrintPacket(const ICMPHeader *header);

/**
 * Creates a reply by copying the received packet, swapping the Ethernet and
 * IPv4 source/destination addresses, updating the ICMP type field, and
 * transmitting the modified frame.
 */
static void icmpSendEchoReply(EthernetFrame *frame);

/******************************************************************************
 * Private Functions
 ******************************************************************************/

/**
 * @brief Print ICMP packet information.
 *
 * @param header Pointer to the ICMP header.
 */
static void icmpPrintPacket(const ICMPHeader *header)
{
    debugPrint("\r\n===== ICMP Packet =====\r\n");

    /* Display ICMP header fields. */
    debugPrintf("Type        : %u\r\n", header->type);

    debugPrintf("Code        : %u\r\n", header->code);

    debugPrintf("Identifier  : 0x%04X\r\n",
                 __builtin_bswap16(header->identifier));

    debugPrintf("Sequence    : %u\r\n",
                 __builtin_bswap16(header->sequenceNumber));

}

/**
 * @brief Generate and transmit an ICMP Echo Reply.
 *
 * Creates a reply by copying the received packet, swapping the Ethernet and
 * IPv4 source/destination addresses, updating the ICMP type field, and
 * transmitting the modified frame.
 *
 * @param frame Pointer to the received Ethernet frame.
 */
static void icmpSendEchoReply(EthernetFrame *frame)
{
    IPv4Header *ip =
        (IPv4Header *)((uint8_t *)frame->packet + sizeof(EthernetHeader));

    uint16_t icmpLength =
        ipv4GetTotalLength(ip) - ipv4GetHeaderLength(ip);

    ICMPHeader *icmp =
        (ICMPHeader *)((uint8_t *)ip + ipv4GetHeaderLength(ip));

    /* Copy ICMP packet into transmit buffer */
    memcpy(replyBuffer,
           icmp,
           icmpLength);

    ICMPHeader *reply = (ICMPHeader *)replyBuffer;

    /* Convert Echo Request into Echo Reply */
    reply->type = ICMP_TYPE_ECHO_REPLY;

    /* Recompute checksum */
    reply->checksum = 0;

    reply->checksum =
        __builtin_bswap16(
            checksumCompute(reply, icmpLength));

    uint32_t destinationIp =
        ipToUint32((uint8_t *)&ip->sourceAddress);

    debugPrintf("ICMP Length   : %u\r\n", icmpLength);
    debugPrintf("ICMP Checksum : %04X\r\n",
                __builtin_bswap16(reply->checksum));

    ipv4SendPacket(destinationIp,
                   IP_PROTOCOL_ICMP,
                   reply,
                   icmpLength,
                   64);
}

/******************************************************************************
 * Public Functions
 ******************************************************************************/

/**
 * @brief Process a received ICMP packet.
 *
 * Parses the ICMP header contained within an IPv4 packet. If the packet is an
 * ICMP Echo Request, an Echo Reply is generated and transmitted.
 *
 * @param frame Pointer to the received Ethernet frame.
 * @param ipHeader Pointer to the IPv4 header.
 */
void icmpReceivePacket(EthernetFrame *frame, const IPv4Header *ipHeader)
{
	uint8_t ipHeaderLength;

	ICMPHeader *icmpHeader;

	/* Determine the size of the IPv4 header. */
	ipHeaderLength = (ipHeader->versionIhl & 0x0F) * 4;

	/* Locate the ICMP header immediately following the IPv4 header. */
	icmpHeader = (ICMPHeader *)((uint8_t *)ipHeader + ipHeaderLength);

	/* Display packet information for debugging. */
	icmpPrintPacket(icmpHeader);

	/* Respond only to ICMP Echo Requests (ping). */
	if (icmpHeader->type == ICMP_TYPE_ECHO_REQUEST)
	{
	    icmpSendEchoReply(frame);
	}
}
