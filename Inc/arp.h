/**
 ******************************************************************************
 * @file    arp.h
 * @brief   Address Resolution Protocol (ARP) interface.
 *
 * Provides functions and data structures for processing ARP packets.
 * Supports receiving ARP requests and transmitting ARP replies for the
 * embedded Ethernet stack.
 *
 ******************************************************************************
 */

#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include "ethernet_driver.h"
#include "ethernet_frame.h"
#include <stdbool.h>
/******************************************************************************
 * Public Macros
 ******************************************************************************/

/* ARP operations. */
#define ARP_REQUEST        1
#define ARP_REPLY          2

/* Supported hardware and protocol types. */
#define ARP_HW_ETHERNET    1
#define ARP_PROTO_IPV4     0x0800

/* IPv4 address length in bytes. */
#define ARP_IP_LENGTH 	   4

#define ARP_CACHE_SIZE 8

/******************************************************************************
 * Public Types
 ******************************************************************************/

#pragma pack(push,1)

/**
 * @brief ARP packet format.
 *
 * Represents the payload of an Ethernet frame with EtherType 0x0806.
 */
typedef struct
{
	uint16_t hardwareType;
	uint16_t protocolType;
	uint8_t hardwareLength;
	uint8_t protocolLength;
	uint16_t operation;

	uint8_t senderMac[ETH_MAC_LENGTH];
	uint8_t senderIp[ARP_IP_LENGTH];

	uint8_t targetMac[ETH_MAC_LENGTH];
	uint8_t targetIp[ARP_IP_LENGTH];
} ArpPacket;

#pragma pack(pop)

/**
 * @brief Complete Ethernet ARP frame.
 *
 * Combines the Ethernet header and ARP packet into a single
 * transmit/receive frame.
 */
typedef struct
{
	EthernetHeader ethernet;
	ArpPacket arp;

} ArpFrame;


typedef struct
{
    uint32_t ipAddress;
    uint8_t macAddress[6];
    bool valid;

} ARPCacheEntry;
/******************************************************************************
 * Public Functions
 ******************************************************************************/

/**
 * @brief Process a received ARP packet.
 *
 * Decodes and displays the contents of a received ARP request or reply.
 *
 * @param arp Pointer to the received ARP packet.
 */
bool arpReceive(const ArpPacket *arp);

/**
 * @brief Transmit an ARP reply.
 *
 * Constructs and transmits an ARP reply in response to a received
 * ARP request addressed to the local device.
 *
 * @param rxHeader Pointer to the received Ethernet header.
 * @param request  Pointer to the received ARP request.
 */
void arpSendReply(EthernetHeader *rxHeader,
		 	 	   ArpPacket *request);

/**
 * @brief Process a received Ethernet frame containing an ARP packet.
 *
 * Locates the ARP payload within the Ethernet frame, processes the
 * received ARP packet, and generates an ARP reply when the request
 * targets the local device.
 *
 * @param frame Pointer to the received Ethernet frame.
 */
void arpReceiveFrame(EthernetFrame *frame);

bool arpLookup(uint32_t ipAddress,
               uint8_t macAddress[ETH_MAC_LENGTH]);


void arpUpdateCache(uint32_t ipAddress,
                    const uint8_t macAddress[ETH_MAC_LENGTH]);

#endif
