/**
 ******************************************************************************
 * @file    udp.h
 * @brief   User Datagram Protocol (UDP) interface.
 *
 * Provides data structures and functions for processing UDP packets
 * received over IPv4.
 *
 ******************************************************************************
 */

#ifndef UDP_H
#define UDP_H

#include <stdint.h>
#include "ethernet_frame.h"
#include "ipv4.h"
#include "main.h"
/******************************************************************************
 * Public Macros
 ******************************************************************************/


/******************************************************************************
 * Public Types
 ******************************************************************************/

#pragma pack(push, 1)

/**
 * @brief UDP header.
 *
 * Represents the header of a UDP datagram.
 */
typedef struct
{
	uint16_t sourcePort;
	uint16_t destinationPort;
	uint16_t length;
	uint16_t checksum;

} UDPHeader;

#pragma pack(pop)

#pragma pack(push, 1)

/**
 * @brief UDP pseudo-header used for checksum calculation.
 *
 * This structure is not transmitted on the network. It is constructed
 * temporarily when calculating or verifying the UDP checksum.
 */
typedef struct
{
    uint32_t sourceIp;
    uint32_t destinationIp;

    uint8_t zero;
    uint8_t protocol;
    uint16_t udpLength;

} UDPPseudoHeader;

#pragma pack(pop)
/******************************************************************************
 * Public Functions
 ******************************************************************************/

/**
 * @brief Process a received UDP packet.
 *
 * Parses a UDP packet contained within an IPv4 packet, verifies its
 * checksum, and dispatches it to the appropriate application handler.
 *
 * @param frame Pointer to the received Ethernet frame.
 * @param ipHeader Pointer to the IPv4 header.
 */
void udpReceivePacket(EthernetFrame *frame, const IPv4Header *ipHeader);

/**
 * @brief Transmit a UDP packet.
 *
 * Builds a UDP packet, computes its checksum, and transmits it
 * through the IPv4 layer.
 *
 * @param sourcePort UDP source port.
 * @param destinationPort UDP destination port.
 * @param destinationIp Destination IPv4 address.
 * @param payload Pointer to the payload data.
 * @param payloadLength Length of the payload in bytes.
 *
 * @return HAL_OK if the packet was transmitted successfully.
 * @return HAL_ERROR otherwise.
 */
HAL_StatusTypeDef udpSendPacket(uint16_t sourcePort,
                                uint16_t destinationPort,
                                uint32_t destinationIp,
                                const void *payload,
                                uint16_t payloadLength);

/**
 * @brief Transmit a UDP test packet.
 *
 * Sends a fixed test message to a predefined destination for
 * verifying UDP communication.
 */
void udpTest(void);

#endif
