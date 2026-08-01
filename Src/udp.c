/**
 ******************************************************************************
 * @file    udp.c
 * @brief   User Datagram Protocol (UDP) implementation.
 *
 * Implements UDP packet transmission and reception, checksum generation
 * and verification, packet dispatching, and a simple UDP echo server.
 *
 ******************************************************************************
 */

/******************************************************************************
 * Includes
 ******************************************************************************/
#include "udp.h"
#include "ethernet_frame.h"
#include "ipv4.h"
#include "debug.h"
#include <string.h>
#include "checksum.h"
#include "network_config.h"
#include "arp.h"

/******************************************************************************
 * Private Constants
 ******************************************************************************/

/** Size of the temporary buffer used for UDP checksum calculation. */
#define UDP_CHECKSUM_BUFFER_SIZE 1600U

/** UDP port used by the built-in echo server. */
#define UDP_PORT_ECHO 5000U
/******************************************************************************
 * Private Types
 ******************************************************************************/

/**
 * @brief UDP transmit packet.
 *
 * Contains a UDP header followed by the packet payload used for
 * packet transmission.
 */
typedef struct
{
    UDPHeader header;
    uint8_t payload[1472];

} UDPTransmitPacket;

/******************************************************************************
 * Private Variables
 ******************************************************************************/

/******************************************************************************
 * Private Function Prototypes
 ******************************************************************************/

/**
 * @brief Compute the UDP checksum.
 *
 * Calculates the UDP checksum using the IPv4 pseudo header,
 * UDP header, and payload.
 *
 * @param sourceIp Source IPv4 address.
 * @param destinationIp Destination IPv4 address.
 * @param udp Pointer to the UDP packet.
 *
 * @return Computed UDP checksum.
 */
static uint16_t udpComputeChecksum(uint32_t sourceIp,
								   uint32_t destinationIp,
								   const UDPHeader *udp);

/**
 * @brief Dispatch a received UDP packet.
 *
 * Routes a UDP packet to the appropriate application handler
 * based on its destination port.
 *
 * @param ipHeader Pointer to the IPv4 header.
 * @param udp Pointer to the UDP header.
 * @param payload Pointer to the UDP payload.
 * @param payloadLength Length of the UDP payload.
 */
static void udpDispatch(const IPv4Header *ipHeader,
                        const UDPHeader *udp,
                        const uint8_t *payload,
                        uint16_t payloadLength);
/**
 * @brief UDP echo server.
 *
 * Echoes the received UDP payload back to the sender.
 *
 * @param ipHeader Pointer to the IPv4 header.
 * @param udp Pointer to the UDP header.
 * @param payload Pointer to the received payload.
 * @param payloadLength Length of the payload.
 */
static void udpEchoServer(const IPv4Header *ipHeader,
                          const UDPHeader *udp,
                          const uint8_t *payload,
                          uint16_t payloadLength);
/******************************************************************************
 * Private Functions
 ******************************************************************************/
/**
 * @brief Compute the UDP checksum.
 *
 * Builds the IPv4 pseudo header together with the UDP header and
 * payload, then computes the one's complement checksum.
 *
 * @param sourceIp Source IPv4 address.
 * @param destinationIp Destination IPv4 address.
 * @param udp Pointer to the UDP packet.
 *
 * @return Computed UDP checksum, or zero if the packet is invalid.
 */
static uint16_t udpComputeChecksum(uint32_t sourceIp,
								   uint32_t destinationIp,
								   const UDPHeader *udp)
{
	 UDPPseudoHeader pseudo;

	 pseudo.sourceIp 	  	= sourceIp;

	 pseudo.destinationIp 	= destinationIp;

	 pseudo.zero 			= 0;

	 pseudo.protocol 		= IP_PROTOCOL_UDP;

	 uint16_t udpLength =
	     __builtin_bswap16(udp->length);

	 pseudo.udpLength = udp->length;

	 static uint8_t buffer[UDP_CHECKSUM_BUFFER_SIZE];

	 /* Check the buffer size */
	 if ((sizeof(UDPPseudoHeader) +
	      udpLength) > UDP_CHECKSUM_BUFFER_SIZE)
	 {
	     return 0;
	 }

	 /* Validate the UDP length */
	 if (udpLength < sizeof(UDPHeader))
	 {
	     return 0;
	 }

	uint16_t offset = 0;

	UDPHeader tempHeader = *udp;

	tempHeader.checksum = 0;

	/* Pseudo Header */
	memcpy(&buffer[offset],
		   &pseudo,
		   sizeof(pseudo));

	offset += sizeof(pseudo);

	/* UDP Header */
	memcpy(&buffer[offset],
	       &tempHeader,
	       sizeof(tempHeader));

	offset += sizeof(tempHeader);

	/* Payload */
	const uint8_t *payload =
	    (const uint8_t *)udp + sizeof(UDPHeader);

	memcpy(&buffer[offset],
	       payload,
	       udpLength - sizeof(UDPHeader));

	offset += udpLength - sizeof(UDPHeader);

	if (offset & 1U)
	{
	    buffer[offset++] = 0;
	}

	return checksumCompute(buffer, offset);
}

/**
 * @brief Dispatch a received UDP packet.
 *
 * Invokes the application associated with the packet's
 * destination port.
 *
 * @param ipHeader Pointer to the IPv4 header.
 * @param udp Pointer to the UDP header.
 * @param payload Pointer to the UDP payload.
 * @param payloadLength Length of the UDP payload.
 */
static void udpDispatch(const IPv4Header *ipHeader,
                        const UDPHeader *udp,
                        const uint8_t *payload,
                        uint16_t payloadLength)
{
    uint16_t destinationPort =
        __builtin_bswap16(udp->destinationPort);

    switch (destinationPort)
    {
        case UDP_PORT_ECHO:

            udpEchoServer(ipHeader,
                          udp,
                          payload,
                          payloadLength);

            break;

        default:

            debugPrintf("No UDP handler for port %u\r\n",
                        destinationPort);

            break;
    }
}

/**
 * @brief Process a UDP echo request.
 *
 * Sends the received payload back to the original sender.
 *
 * @param ipHeader Pointer to the IPv4 header.
 * @param udp Pointer to the UDP header.
 * @param payload Pointer to the UDP payload.
 * @param payloadLength Length of the UDP payload.
 */
static void udpEchoServer(const IPv4Header *ipHeader,
                          const UDPHeader *udp,
                          const uint8_t *payload,
                          uint16_t payloadLength)
{
	uint16_t sourcePort =
	    __builtin_bswap16(udp->sourcePort);

	uint16_t destinationPort =
	    __builtin_bswap16(udp->destinationPort);

	uint32_t sourceIp =
	    ipToUint32((uint8_t *)&ipHeader->sourceAddress);

	udpSendPacket(destinationPort,
	              sourcePort,
	              sourceIp,
	              payload,
	              payloadLength);
}
/******************************************************************************
 * Public Functions
 ******************************************************************************/

/**
 * @brief Process a received UDP packet.
 *
 * Parses a UDP packet carried within an IPv4 packet, verifies its
 * checksum, and dispatches it to the appropriate application.
 *
 * @param frame Pointer to the received Ethernet frame.
 * @param ipHeader Pointer to the IPv4 header.
 */
 void udpReceivePacket(EthernetFrame *frame, const IPv4Header *ipHeader)
 {
	 uint8_t *udpHeaderPtr = (uint8_t *)ipHeader + ipv4GetHeaderLength(ipHeader);

	 UDPHeader *udp = (UDPHeader *)udpHeaderPtr;

	 debugPrint("\r\n===== UDP =====\r\n");

	 debugPrintf("Source Port      : %u\r\n",
	             __builtin_bswap16(udp->sourcePort));

	 debugPrintf("Destination Port : %u\r\n",
	             __builtin_bswap16(udp->destinationPort));

	 debugPrintf("Length           : %u\r\n",
	             __builtin_bswap16(udp->length));

	 debugPrintf("Checksum         : 0x%04X\r\n",
	             __builtin_bswap16(udp->checksum));

	 uint8_t *udpPayload =
	     (uint8_t *)udp + sizeof(UDPHeader);

	 uint16_t udpLength = __builtin_bswap16(udp->length);

	 if (udpLength < sizeof(UDPHeader))
	 {
		 debugPrint("Invalid UDP length\r\n");
		 return;
	 }

	 /* Extract payload */
	 uint16_t payloadLength =
	     __builtin_bswap16(udp->length) - sizeof(UDPHeader);

	 /* Print contents as text*/
	 debugPrint("Payload: ");

	 for (uint16_t i = 0; i < payloadLength; i++)
	 {
	     debugPrintf("%c", udpPayload[i]);
	 }

	 debugPrint("\r\n");
	 debugPrint("checksum start\r\n");

	 uint16_t calculated =
	     udpComputeChecksum(ipHeader->sourceAddress,
	                        ipHeader->destinationAddress,
	                        udp);

	 debugPrint("checksum complete\r\n");

	 uint16_t received =
	     __builtin_bswap16(udp->checksum);

	 /* Echo only valid packets */
	 if (calculated == received)
	 {
	     debugPrint("UDP Checksum: VALID\r\n");

	     udpDispatch(ipHeader,
	                 udp,
	                 udpPayload,
	                 payloadLength);
	 }
	 else
	 {
	     debugPrintf("UDP Checksum: INVALID "
	                 "(Calculated = 0x%04X, "
	                 "Received = 0x%04X)\r\n",
	                 calculated,
	                 received);
	 }
 }

 /**
  * @brief Transmit a UDP packet.
  *
  * Builds a UDP packet, computes its checksum, and transmits it
  * using the IPv4 layer.
  *
  * @param sourcePort UDP source port.
  * @param destinationPort UDP destination port.
  * @param destinationIp Destination IPv4 address.
  * @param payload Pointer to the payload data.
  * @param payloadLength Payload length in bytes.
  *
  * @return HAL_OK if the packet was transmitted successfully.
  * @return HAL_ERROR otherwise.
  */
 HAL_StatusTypeDef udpSendPacket(uint16_t sourcePort,
                                 uint16_t destinationPort,
                                 uint32_t destinationIp,
                                 const void *payload,
                                 uint16_t payloadLength)
 {
     static UDPTransmitPacket packet;

     /* Build UDP header */
     packet.header.sourcePort =
         __builtin_bswap16(sourcePort);

     packet.header.destinationPort =
         __builtin_bswap16(destinationPort);

     packet.header.length =
         __builtin_bswap16(sizeof(UDPHeader) + payloadLength);

     /* Copy payload */
     memcpy(packet.payload,
            payload,
            payloadLength);

     /* Disable checksum for now */
     packet.header.checksum = 0;

     packet.header.checksum =
         __builtin_bswap16(
             udpComputeChecksum(
                 __builtin_bswap32(ipToUint32(LOCAL_IP_ADDRESS)),
                 __builtin_bswap32(destinationIp),
                 &packet.header));

	 HAL_StatusTypeDef status;

	 status = ipv4SendPacket(destinationIp,
							 IP_PROTOCOL_UDP,
							 &packet,
							 sizeof(UDPHeader) + payloadLength,
							 64);

	 debugPrintf("IPv4 Send Status = %d\r\n", status);

	 return status;
 }

 /**
  * @brief Send a test UDP packet.
  *
  * Transmits a fixed test message to verify UDP communication.
  */
 void udpTest(void)
 {
     static const char message[] = "Hello UDP";

     udpSendPacket(
         5000,                           // Source port
         5001,                           // Destination port
         ipToUint32((uint8_t[]){192,168,7,204}),
         message,
         sizeof(message) - 1);
 }
