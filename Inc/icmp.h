/**
 ******************************************************************************
 * @file    icmp.h
 * @brief   Internet Control Message Protocol (ICMP) interface.
 *
 * Provides functions for processing ICMP packets received over IPv4,
 * including support for ICMP Echo Request and Echo Reply messages.
 *
 ******************************************************************************
 */

#ifndef ICMP_H
#define ICMP_H

#include "ipv4.h"
#include "ethernet_frame.h"
/******************************************************************************
 * Public Types
 ******************************************************************************/


/******************************************************************************
 * Public Macros
 ******************************************************************************/

/* ICMP message types. */
#define ICMP_TYPE_ECHO_REPLY 	0
#define ICMP_TYPE_ECHO_REQUEST	8

/******************************************************************************
 * Public Functions
 ******************************************************************************/

/**
 * @brief Process a received ICMP packet.
 *
 * Parses the ICMP header contained within an IPv4 packet. If the packet is
 * an ICMP Echo Request, an ICMP Echo Reply is generated and transmitted.
 *
 * @param frame Pointer to the received Ethernet frame.
 * @param ipHeader Pointer to the IPv4 header.
 */
void icmpReceivePacket(EthernetFrame *frame, const IPv4Header *ipHeader);


#endif
