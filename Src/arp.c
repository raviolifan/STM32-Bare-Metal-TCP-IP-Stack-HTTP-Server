/**
 ******************************************************************************
 * @file    arp.c
 * @brief   Address Resolution Protocol (ARP) implementation.
 *
 * Implements ARP packet processing and ARP reply generation for the
 * embedded Ethernet stack.
 *
 ******************************************************************************
 */

/******************************************************************************
 * Includes
 ******************************************************************************/
#include <string.h>
#include "arp.h"
#include "debug.h"
#include "main.h"
#include "ethernet_frame.h"
#include "ethernet_driver.h"
#include "main.h"
#include <stdbool.h>
#include "network_config.h"
/******************************************************************************
 * Private Types
 ******************************************************************************/

/******************************************************************************
 * Private Constants
 ******************************************************************************/

/******************************************************************************
 * Private Variables
 ******************************************************************************/

static ARPCacheEntry arpCache[ARP_CACHE_SIZE];
/******************************************************************************
 * Private Function Prototypes
 ******************************************************************************/
void arpPrintCache(void);
static uint32_t arpIpToUint32(const uint8_t ip[4]);

/******************************************************************************
 * Private Functions
 ******************************************************************************/
void arpPrintCache(void)
{
    debugPrint("\r\n===== ARP Cache =====\r\n");

    for (uint32_t i = 0; i < ARP_CACHE_SIZE; i++)
    {
        if (!arpCache[i].valid)
        {
            debugPrintf("%lu: <empty>\r\n", i);
            continue;
        }

        uint32_t ip = arpCache[i].ipAddress;

        debugPrintf("%lu:\r\n", i);
        debugPrintf("IP  : %lu.%lu.%lu.%lu\r\n",
            (ip >> 24) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF,
            ip & 0xFF);

        debugPrintf("MAC : %02X:%02X:%02X:%02X:%02X:%02X\r\n\r\n",
            arpCache[i].macAddress[0],
            arpCache[i].macAddress[1],
            arpCache[i].macAddress[2],
            arpCache[i].macAddress[3],
            arpCache[i].macAddress[4],
            arpCache[i].macAddress[5]);
    }
}

static uint32_t arpIpToUint32(const uint8_t ip[4])
{
    return ((uint32_t)ip[0] << 24) |
           ((uint32_t)ip[1] << 16) |
           ((uint32_t)ip[2] << 8)  |
            (uint32_t)ip[3];
}
/******************************************************************************
 * Public Functions
 ******************************************************************************/

/**
 * @brief Process a received ARP packet.
 *
 * Displays the contents of a received ARP packet for debugging.
 *
 * @param arp Pointer to the received ARP packet.
 */
 bool arpReceive(const ArpPacket *arp)
 {
	if (__builtin_bswap16(arp->hardwareType) != ARP_HW_ETHERNET)
	{
		return false;
	}

	if (__builtin_bswap16(arp->protocolType) != ARP_PROTO_IPV4)
	{
		return false;
	}

	if (arp->hardwareLength != ETH_MAC_LENGTH)
	{
		return false;
	}

	if (arp->protocolLength != ARP_IP_LENGTH)
	{
		return false;
	}

//	 debugPrint("\r\n==== ARP Packet =====\r\n");
//
//	 debugPrintf("Operation: %u\r\n",
//			 __builtin_bswap16(arp->operation));
//
//	 debugPrintf("Sender IP: %u.%u.%u.%u\r\n",
//			 arp->senderIp[0],
//			 arp->senderIp[1],
//			 arp->senderIp[2],
//			 arp->senderIp[3]);
//
//	 debugPrintf("Target IP: %u.%u.%u.%u\r\n",
//			 arp->targetIp[0],
//			 arp->targetIp[1],
//			 arp->targetIp[2],
//			 arp->targetIp[3]);

	return true;
 }

 /**
  * @brief Construct and transmit an ARP reply.
  *
  * Verifies that the received ARP request targets the local device,
  * constructs an ARP reply using the received Ethernet and ARP
  * information, and transmits the completed frame.
  *
  * @param rxHeader Pointer to the received Ethernet header.
  * @param request Pointer to the received ARP request.
  */
 void arpSendReply(EthernetHeader *rxHeader,
		 	 	   ArpPacket *request)
 {
	 static ArpFrame reply;

	 /* Verify the ARP request is for this device. */
	 if (memcmp(request->targetIp, LOCAL_IP_ADDRESS, 4) != 0)
	 {
	     return;
	 }

	 /* Build Ethernet header. */
	 memcpy(reply.ethernet.destination,
			 rxHeader->source,
			 ETH_MAC_LENGTH);

	 memcpy(reply.ethernet.source,
			 LOCAL_MAC_ADDRESS,
			 ETH_MAC_LENGTH);


	 reply.ethernet.etherType 	= __builtin_bswap16(ETHERTYPE_ARP);

	 reply.arp.hardwareType 	= __builtin_bswap16(ARP_HW_ETHERNET);
	 reply.arp.protocolType 	= __builtin_bswap16(ARP_PROTO_IPV4);

	 reply.arp.hardwareLength	= ETH_MAC_LENGTH;
	 reply.arp.protocolLength 	= ARP_IP_LENGTH;

	 reply.arp.operation 		= __builtin_bswap16(ARP_REPLY);

	 /* Build ARP packet. */
	 memcpy(reply.arp.senderMac,
			 LOCAL_MAC_ADDRESS,
			 ETH_MAC_LENGTH);

	 memcpy(reply.arp.senderIp,
			 LOCAL_IP_ADDRESS,
			 ARP_IP_LENGTH);

	 memcpy(reply.arp.targetMac,
			 request->senderMac,
			 ETH_MAC_LENGTH);

	 memcpy(reply.arp.targetIp,
			 request->senderIp,
			 ARP_IP_LENGTH);

	 debugPrint("\r\n===== ARP Reply =====\r\n");

	 /* Print packet contents */
	 debugPrintf("Operation: %u\r\n",
	             __builtin_bswap16(reply.arp.operation));

	 debugPrint("Sender MAC: ");
	 printMac(reply.arp.senderMac);

	 debugPrint("Target MAC: ");
	 printMac(reply.arp.targetMac);

	 debugPrintf("Sender IP: %u.%u.%u.%u\r\n",
	         reply.arp.senderIp[0],
	         reply.arp.senderIp[1],
	         reply.arp.senderIp[2],
	         reply.arp.senderIp[3]);

	 debugPrintf("Target IP: %u.%u.%u.%u\r\n",
	         reply.arp.targetIp[0],
	         reply.arp.targetIp[1],
	         reply.arp.targetIp[2],
	         reply.arp.targetIp[3]);

	 debugPrint("Destination MAC: ");
	 printMac(reply.ethernet.destination);

	 debugPrint("Source MAC: ");
	 printMac(reply.ethernet.source);

	 /* Transmit ARP reply. */
	 if (ethernetTransmit(&reply, sizeof(reply)) == HAL_OK)
	 {
		 debugPrint("ARP Reply Sent!\r\n");
	 }
	 else
	 {
		 debugPrint("ARP Reply Failed!\r\n");
	 }
 }

 /**
  * @brief Process a received Ethernet frame containing an ARP packet.
  *
  * Locates the ARP payload, displays the received packet for debugging,
  * processes the packet contents, and transmits an ARP reply when the
  * request targets the local device.
  *
  * @param frame Pointer to the received Ethernet frame.
  */
void arpReceiveFrame(EthernetFrame *frame)
{
    debugPrint("ARP\r\n");

    /* Locate the ARP payload following the Ethernet header. */
    uint8_t *payload =
    		(uint8_t *)frame->packet + sizeof(EthernetHeader);

    ArpPacket *arp = (ArpPacket *)payload;

//    /* Display the raw ARP packet for debugging. */
//    for (int i = 0; i < sizeof(ArpPacket); i++)
//    {
//        debugPrintf("%02X ",
//            ((uint8_t*)arp)[i]);
//
//        if((i+1)%16==0)
//            debugPrint("\r\n");
//    }

    /* Decode and display the ARP packet. */
    if (!arpReceive(arp))
    {
        return;
    }

    uint32_t senderIp = arpIpToUint32(arp->senderIp);

    arpUpdateCache(senderIp,
                   arp->senderMac);

    arpPrintCache();

    /* Generate an ARP reply if the request is for this device. */
    arpSendReply(frame->header, arp);
}

bool arpLookup(uint32_t ipAddress,
               uint8_t macAddress[ETH_MAC_LENGTH])
{
    for (uint32_t i = 0; i < ARP_CACHE_SIZE; i++)
    {
        if (arpCache[i].valid &&
            arpCache[i].ipAddress == ipAddress)
        {
            memcpy(macAddress,
                   arpCache[i].macAddress,
                   sizeof(arpCache[i].macAddress));

            return true;
        }
    }

    return false;
}

void arpUpdateCache(uint32_t ipAddress,
                    const uint8_t macAddress[ETH_MAC_LENGTH])
{
    /* Update existing entry */

    for (uint32_t i = 0; i < ARP_CACHE_SIZE; i++)
    {
        if (arpCache[i].valid &&
            arpCache[i].ipAddress == ipAddress)
        {
            memcpy(arpCache[i].macAddress,
                   macAddress,
                   ETH_MAC_LENGTH);

            return;
        }
    }

    /* Insert into first free slot */

    for (uint32_t i = 0; i < ARP_CACHE_SIZE; i++)
    {
        if (!arpCache[i].valid)
        {
            arpCache[i].ipAddress = ipAddress;

            memcpy(arpCache[i].macAddress,
                   macAddress,
				   ETH_MAC_LENGTH);

            arpCache[i].valid = true;

            return;
        }
    }

    /* Cache full.
       Replace entry 0 for now. */

    arpCache[0].ipAddress = ipAddress;

    memcpy(arpCache[0].macAddress,
           macAddress,
		   ETH_MAC_LENGTH);

    arpCache[0].valid = true;
}
