/**
 ******************************************************************************
 * @file    checksum.h
 * @brief   Internet checksum interface.
 *
 * Provides functions for calculating the standard 16-bit Internet checksum
 * used by IPv4, ICMP, UDP, and TCP.
 *
 ******************************************************************************
 */

#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stdint.h>

/******************************************************************************
 * Public Macros
 ******************************************************************************/



/******************************************************************************
 * Public Types
 ******************************************************************************/



/******************************************************************************
 * Public Functions
 ******************************************************************************/

/**
 * @brief Compute the Internet checksum.
 *
 * Calculates the one's-complement checksum over a block of data.
 *
 * @param data Pointer to the data buffer.
 * @param length Length of the buffer in bytes.
 *
 * @return 16-bit Internet checksum.
 */
uint16_t checksumCompute(const void *data, uint16_t length);

uint32_t checksumAccumulate(const void *data, uint16_t length);

uint16_t checksumFinalize(uint32_t sum);

#endif
