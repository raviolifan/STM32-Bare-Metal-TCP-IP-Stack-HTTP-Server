/**
 ******************************************************************************
 * @file    ipv4.h
 * @brief   Internet Protocol Version 4 (IPv4) interface.
 *
 * Provides data structures and functions for processing IPv4 packets.
 * Supports parsing IPv4 headers and dispatching packets to the appropriate
 * transport-layer protocol handler.
 *
 ******************************************************************************
 */

#ifndef IPV4_H
#define IPV4_H

#include <stdint.h>
#include "ethernet_frame.h"
#include "main.h"
/******************************************************************************
 * Public Types
 ******************************************************************************/

#pragma pack(push, 1)

/**
 * @brief IPv4 packet header.
 *
 * Represents the header of an IPv4 packet carried within an Ethernet frame.
 */
typedef struct
{
    uint8_t  versionIhl;             /**< Version and header length. */
    uint8_t  dscpEcn;                /**< DSCP and ECN fields. */
    uint16_t totalLength;            /**< Total IPv4 packet length. */
    uint16_t identification;         /**< Packet identification field. */
    uint16_t flagsFragmentOffset;    /**< Fragmentation flags and offset. */
    uint8_t  ttl;                    /**< Time-To-Live value. */
    uint8_t  protocol;               /**< Encapsulated transport protocol. */
    uint16_t headerChecksum;         /**< IPv4 header checksum. */
    uint32_t sourceAddress;          /**< Source IPv4 address. */
    uint32_t destinationAddress;     /**< Destination IPv4 address. */
} IPv4Header;

#pragma pack(pop)

typedef struct
{
    EthernetHeader ethernet;
    IPv4Header ipv4;
    uint8_t payload[1500];

} IPv4TransmitFrame;

/******************************************************************************
 * Public Macros
 ******************************************************************************/

/* IPv4 protocol numbers. */
#define IP_PROTOCOL_ICMP	1
#define IP_PROTOCOL_UDP 	17
/******************************************************************************
 * Public Functions
 ******************************************************************************/

/**
 * @brief Process a received IPv4 Ethernet frame.
 *
 * Validates the IPv4 header, displays packet information for debugging,
 * and dispatches the payload to the appropriate transport-layer protocol
 * handler.
 *
 * @param frame Pointer to the received Ethernet frame.
 */
void ipv4ReceiveFrame(EthernetFrame *frame);

/**
 * @brief Retrieve the IPv4 header length.
 *
 * Returns the length of the IPv4 header in bytes.
 *
 * @param header Pointer to the IPv4 header.
 *
 * @return IPv4 header length in bytes.
 */
uint8_t ipv4GetHeaderLength(const IPv4Header *header);

/**
 * @brief Retrieve the total IPv4 packet length.
 *
 * Converts the field from network byte order to host byte order.
 *
 * @param header Pointer to the IPv4 header.
 *
 * @return Total packet length in bytes.
 */
uint16_t ipv4GetTotalLength(const IPv4Header *header);

HAL_StatusTypeDef ipv4SendPacket(uint32_t destinationIp,
								 uint8_t protocol,
								 const void *payload,
								 uint16_t payloadLength,
								 uint8_t ttl);
#endif
