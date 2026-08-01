/**
 ******************************************************************************
 * @file    driver.c
 * @brief   Driver implementation.
 ******************************************************************************
 */

/******************************************************************************
 * Includes
 ******************************************************************************/
#include "checksum.h"

#include "stm32h5xx_hal.h"

/******************************************************************************
 * Private Constants
 ******************************************************************************/

/******************************************************************************
 * Private Types
 ******************************************************************************/

/******************************************************************************
 * Private Variables
 ******************************************************************************/


/******************************************************************************
 * Private Function Prototypes
 ******************************************************************************/

/******************************************************************************
 * Private Functions
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
 uint16_t checksumCompute(const void *data, uint16_t length)
 {
	 const uint8_t *bytes = data;
	 uint32_t sum = 0;

	 /* Add every 16-bit words */
	 while (length > 1)
	 {
		 uint16_t word = ((uint16_t)bytes[0] << 8) | (uint16_t)bytes[1];

		 sum += word;

		 bytes += 2;
		 length -= 2;
	 }

	 /* Add final odd byte if necessary */
	 if (length == 1)
	 {
		 sum += (uint16_t)bytes[0] << 8;
	 }

	 /* Fold carriers until only 16 bits remain */
	 while (sum >> 16)
	 {
		 sum = (sum & 0xFFFF) + (sum >> 16);
	 }

	 /* Return one's complement*/
	 return (uint16_t)~sum;
 }


