/**
 ******************************************************************************
 * @file    ipv4.c
 * @brief   Internet Protocol Version 4 (IPv4) implementation.
 *
 * Implements IPv4 packet parsing, header validation, packet debugging,
 * and dispatching of IPv4 payloads to the appropriate transport-layer
 * protocol handler.
 *
 ******************************************************************************
 */

/******************************************************************************
 * Includes
 ******************************************************************************/
#include "ipv4.h"
#include "main.h"
#include "debug.h"
#include "ethernet_frame.h"
#include "icmp.h"
#include "udp.h"
#include "checksum.h"
#include "ethernet_driver.h"
#include <string.h>
#include "arp.h"
#include "network_config.h"
#include "tcp.h"
/******************************************************************************
 * Private Types
 ******************************************************************************/

/******************************************************************************
 * Private Constants
 ******************************************************************************/

/* Static configuration tables */

/******************************************************************************
 * Private Variables
 ******************************************************************************/

/* Runtime state */

/******************************************************************************
 * Private Function Prototypes
 ******************************************************************************/

/* Print the IPv4 header fields. */
static void ipv4PrintHeader(const IPv4Header *header);

/* Dispatch the packet to the appropriate transport-layer protocol. */
static void ipv4DispatchProtocol(EthernetFrame *frame, const IPv4Header *header);

/* Retrieve the IPv4 version. */
static uint8_t ipv4GetVersion(const IPv4Header *header);

/* Retrieve the Time-To-Live (TTL) value. */
static uint8_t ipv4GetTTL(const IPv4Header *header);

/* Convert an IPv4 protocol number to a string. */
static const char *ipv4ProtocolToString(uint8_t protocol);

/* Print an IPv4 address in dotted-decimal format. */
static void ipv4PrintAddress(const uint8_t *address);

static void ethernetBuildHeader(
    EthernetHeader *header,
    const uint8_t destination[6],
    const uint8_t source[6],
    uint16_t etherType);
/******************************************************************************
 * Private Functions
 ******************************************************************************/

/**
 * @brief Print the contents of an IPv4 header.
 *
 * Displays the decoded IPv4 header fields for debugging, including the
 * version, header length, total length, time-to-live, protocol, and
 * source and destination IP addresses.
 *
 * @param header Pointer to the IPv4 header.
 */
static void ipv4PrintHeader(const IPv4Header *header)
{
	debugPrint("===== IPv4 Packet =====\r\n");

	debugPrintf("Version		: %u\r\n",
	            ipv4GetVersion(header));

	debugPrintf("Header Length   : %u\r\n",
	            ipv4GetHeaderLength(header));

	debugPrintf("Total Length    : %u bytes\r\n",
	            ipv4GetTotalLength(header));


	debugPrintf("TTL		: %u\r\n",
			ipv4GetTTL(header));


	debugPrintf("Protocol	: %s\r\n",
	            ipv4ProtocolToString(header->protocol));

	debugPrint("Source IP      	: ");
	ipv4PrintAddress((const uint8_t *)&header->sourceAddress);
	debugPrint("\r\n");

	debugPrint("Destination IP 	: ");
	ipv4PrintAddress((const uint8_t *)&header->destinationAddress);
	debugPrint("\r\n");
}

/**
 * @brief Dispatch an IPv4 packet to the appropriate transport protocol.
 *
 * Routes the packet based on the IPv4 Protocol field.
 *
 * @param frame Pointer to the received Ethernet frame.
 * @param header Pointer to the IPv4 header.
 */
static void ipv4DispatchProtocol(EthernetFrame *frame, const IPv4Header *header)
{
	switch(header->protocol)
	{
	case IP_PROTOCOL_ICMP:
	{
		icmpReceivePacket(frame, header);
		break;
	}
	case IP_PROTOCOL_TCP:
	{
		tcpReceivePacket(frame, header);
		break;
	}
	case IP_PROTOCOL_UDP:
	{
		udpReceivePacket(frame, header);
		break;
	}
	default:
	{
		debugPrintf("Unknown Protocol %u\r\n", header->protocol);
		break;
	}
	}
}

/**
 * @brief Extract the IPv4 version field.
 *
 * @param header Pointer to the IPv4 header.
 *
 * @return IPv4 version number.
 */
static uint8_t ipv4GetVersion(const IPv4Header *header)
{
	return header->versionIhl >> 4;
}


/**
 * @brief Retrieve the IPv4 Time-To-Live value.
 *
 * @param header Pointer to the IPv4 header.
 *
 * @return TTL value.
 */
static uint8_t ipv4GetTTL(const IPv4Header *header)
{
	return (header->ttl);
}

/**
 * @brief Convert an IPv4 protocol number to a printable string.
 *
 * @param protocol IPv4 protocol identifier.
 *
 * @return Protocol name.
 */
static const char *ipv4ProtocolToString(uint8_t protocol)
{
	switch(protocol)
	{
	case IP_PROTOCOL_ICMP: return "ICMP";
	case IP_PROTOCOL_TCP : return "TCP";
	case IP_PROTOCOL_UDP : return "UDP";
	default:			   return "Unknown";
	}
}

/**
 * @brief Print an IPv4 address in dotted-decimal notation.
 *
 * @param address Pointer to the 4-byte IPv4 address.
 */
static void ipv4PrintAddress(const uint8_t *address)
{
	debugPrintf("%u.%u.%u.%u",
				address[0],
				address[1],
				address[2],
				address[3]);
}

static void ethernetBuildHeader(
    EthernetHeader *header,
    const uint8_t destination[6],
    const uint8_t source[6],
    uint16_t etherType)
{
    memcpy(header->destination,
           destination,
           ETH_MAC_LENGTH);

    memcpy(header->source,
           source,
           ETH_MAC_LENGTH);

    header->etherType = __builtin_bswap16(etherType);
}
/******************************************************************************
 * Public Functions
 ******************************************************************************/

/**
 * @brief Receive and process an IPv4 packet.
 *
 * Validates the IPv4 version, displays the header contents for debugging,
 * and dispatches the packet to the appropriate transport-layer protocol.
 *
 * @param frame Pointer to the received Ethernet frame.
 */
void ipv4ReceiveFrame(EthernetFrame *frame)
{
	/* Locate the IPv4 header immediately after the Ethernet header. */
	IPv4Header *header =
	    (IPv4Header *)((uint8_t *)frame->packet + sizeof(EthernetHeader));

	arpUpdateCache(
	    ipToUint32((uint8_t *)&header->sourceAddress),
	    frame->header->source);

	/* Verify the packet is IPv4. */
	if ((header->versionIhl >> 4) != 4)
	{
		debugPrint("Invalid IPv4 Version\r\n");
		return;
	}

	/* Display IPv4 header information. */
	ipv4PrintHeader(header);

	/* Pass the payload to the appropriate transport-layer protocol. */
	ipv4DispatchProtocol(frame, header);
}

/**
 * @brief Calculate the IPv4 header length in bytes.
 *
 * @param header Pointer to the IPv4 header.
 *
 * @return Header length in bytes.
 */
uint8_t ipv4GetHeaderLength(const IPv4Header *header)
{
	return (header->versionIhl & 0x0F) * 4;
}

/**
 * @brief Retrieve the total IPv4 packet length.
 *
 * Converts the field from network byte order to host byte order.
 *
 * @param header Pointer to the IPv4 header.
 *
 * @return Total packet length in bytes.
 */
uint16_t ipv4GetTotalLength(const IPv4Header *header)
{
	return __builtin_bswap16(header->totalLength);
}


HAL_StatusTypeDef ipv4SendPacket(uint32_t destinationIp,
								 uint8_t protocol,
								 const void *payload,
								 uint16_t payloadLength,
								 uint8_t ttl)
{
    static IPv4TransmitFrame frame;

    uint8_t destinationMac[ETH_MAC_LENGTH];

    if (!arpLookup(destinationIp, destinationMac))
    {
        return HAL_ERROR;
    }

    /* Build Ethernet Header */

    ethernetBuildHeader(&frame.ethernet,
                        destinationMac,
						LOCAL_MAC_ADDRESS,
                        ETHERTYPE_IPV4);

    /* Build IPv4 Header */

    frame.ipv4.versionIhl     = 0x45;
    frame.ipv4.dscpEcn  = 0;
    frame.ipv4.totalLength    = __builtin_bswap16(sizeof(IPv4Header) + payloadLength);
    frame.ipv4.identification = 0;
    frame.ipv4.flagsFragmentOffset  = 0;
    frame.ipv4.ttl     = ttl;
    frame.ipv4.protocol       = protocol;
    frame.ipv4.headerChecksum = 0;

    frame.ipv4.sourceAddress      = __builtin_bswap32(ipToUint32(LOCAL_IP_ADDRESS));
    frame.ipv4.destinationAddress = __builtin_bswap32(destinationIp);

    /* Compute checksum */

    frame.ipv4.headerChecksum =
        __builtin_bswap16(
            checksumCompute(&frame.ipv4,
                            sizeof(IPv4Header)));

    /* Copy payload */

    memcpy(frame.payload,
           payload,
           payloadLength);

    /* Transmit */
    return ethernetTransmit(
            &frame,
            sizeof(EthernetHeader) +
            sizeof(IPv4Header) +
            payloadLength);
}
