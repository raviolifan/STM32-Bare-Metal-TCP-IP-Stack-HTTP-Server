/**
 ******************************************************************************
 * @file    network_config.h
 * @brief   Network configuration interface.
 *
 * Provides the local network configuration parameters used by the
 * networking stack, including the device MAC address, IPv4 address,
 * and helper functions for IP address manipulation.
 *
 ******************************************************************************
 */

#ifndef NETWORK_CONFIG_H
#define NETWORK_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

/******************************************************************************
 * Public Macros
 ******************************************************************************/

/** Length of an Ethernet MAC address in bytes. */
#define LOCAL_MAC_LENGTH 6

/** Length of an IPv4 address in bytes. */
#define LOCAL_IP_LENGTH  4

/******************************************************************************
 * Public Types
 ******************************************************************************/


/******************************************************************************
 * Public Variables
 ******************************************************************************/

/**
 * @brief Local Ethernet MAC address.
 *
 * Unique hardware address assigned to the STM32 Ethernet interface.
 */
extern const uint8_t LOCAL_MAC_ADDRESS[LOCAL_MAC_LENGTH];

/**
 * @brief Local IPv4 address.
 *
 * Static IPv4 address assigned to the STM32 device.
 */
extern const uint8_t LOCAL_IP_ADDRESS[LOCAL_IP_LENGTH];

/******************************************************************************
 * Public Functions
 ******************************************************************************/

/**
 * @brief Convert an IPv4 address to a 32-bit integer.
 *
 * Packs a four-byte IPv4 address into a single 32-bit value using
 * network byte order.
 *
 * @param ip Pointer to a 4-byte IPv4 address.
 *
 * @return 32-bit representation of the IPv4 address.
 */
uint32_t ipToUint32(const uint8_t ip[4]);

#endif
