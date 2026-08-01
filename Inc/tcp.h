/**
 ******************************************************************************
 * @file    tcp.h
 * @brief   Transmission Control Protocol (TCP) interface.
 *
 * Defines the TCP protocol data structures, connection state machine,
 * protocol flags, and public APIs for transmitting and receiving
 * TCP packets.
 *
 ******************************************************************************
 */

#ifndef TCP_H
#define TCP_H

#include "ethernet_frame.h"
#include "ipv4.h"
#include <stdint.h>

/******************************************************************************
 * Public Macros
 ******************************************************************************/

/** IPv4 protocol number assigned to TCP. */
#define IP_PROTOCOL_TCP          6U

/** TCP FIN (Finish) flag. */
#define TCP_FLAG_FIN             0x0001

/** TCP SYN (Synchronize) flag. */
#define TCP_FLAG_SYN             0x0002

/** TCP RST (Reset) flag. */
#define TCP_FLAG_RST             0x0004

/** TCP PSH (Push) flag. */
#define TCP_FLAG_PSH             0x0008

/** TCP ACK (Acknowledgement) flag. */
#define TCP_FLAG_ACK             0x0010

/** TCP URG (Urgent) flag. */
#define TCP_FLAG_URG             0x0020

/** TCP ECE (ECN Echo) flag. */
#define TCP_FLAG_ECE             0x0040

/** TCP CWR (Congestion Window Reduced) flag. */
#define TCP_FLAG_CWR             0x0080

/******************************************************************************
 * Public Types
 ******************************************************************************/

/**
 * @brief TCP header.
 *
 * Represents the fixed 20-byte TCP header contained within
 * a TCP segment.
 */
typedef struct __attribute__((packed))
{
    uint16_t sourcePort;
    uint16_t destinationPort;

    uint32_t sequenceNumber;
    uint32_t acknowledgementNumber;

    uint16_t dataOffsetFlags;

    uint16_t windowSize;

    uint16_t checksum;

    uint16_t urgentPointer;

} TCPHeader;

/**
 * @brief TCP connection states.
 *
 * Represents the current state of a TCP connection.
 */
typedef enum
{
    TCP_STATE_CLOSED,

    TCP_STATE_LISTEN,

    TCP_STATE_SYN_RECEIVED,

    TCP_STATE_ESTABLISHED,

    TCP_STATE_FIN_WAIT,

    TCP_STATE_CLOSE_WAIT

} TCPState;

/**
 * @brief TCP connection information.
 *
 * Stores the state and parameters associated with an active
 * TCP connection.
 */
typedef struct
{
    TCPState state;

    uint32_t localSequence;

    uint32_t remoteSequence;

    uint32_t acknowledgement;

    uint32_t remoteIp;

    uint16_t localPort;

    uint16_t remotePort;

} TCPConnection;

/******************************************************************************
 * Public Functions
 ******************************************************************************/

/**
 * @brief Process a received TCP packet.
 *
 * Parses a TCP segment carried within an IPv4 packet and
 * processes it according to the current TCP connection state.
 *
 * @param frame Pointer to the received Ethernet frame.
 * @param ipv4Header Pointer to the IPv4 header.
 */
void tcpReceivePacket(EthernetFrame *frame,
                      const IPv4Header *ipv4Header);

/**
 * @brief Transmit a TCP packet.
 *
 * Builds a TCP segment using the specified connection
 * parameters, computes the TCP checksum, and transmits it
 * through the IPv4 layer.
 *
 * @param connection Pointer to the TCP connection.
 * @param flags TCP flags to include in the transmitted segment.
 * @param payload Pointer to the payload data.
 * @param payloadLength Length of the payload in bytes.
 *
 * @return HAL_OK if the packet was transmitted successfully.
 * @return HAL_ERROR otherwise.
 */
HAL_StatusTypeDef tcpSendPacket(
    TCPConnection *connection,
    uint16_t flags,
    const void *payload,
    uint16_t payloadLength);

#endif
