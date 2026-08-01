/**
 ******************************************************************************
 * @file    tcp.c
 * @brief   Transmission Control Protocol (TCP) implementation.
 *
 * Implements TCP segment transmission and reception, checksum generation
 * and verification, connection management, and a simple HTTP server.
 *
 ******************************************************************************
 */

/******************************************************************************
 * Includes
 ******************************************************************************/
#include "tcp.h"
#include "debug.h"
#include "ipv4.h"
#include "stdbool.h"
#include <string.h>
#include "network_config.h"
#include "checksum.h"
/******************************************************************************
 * Private Constants
 ******************************************************************************/

/**
 * @brief HTTP response returned by the embedded web server.
 */
static const char httpResponse[] =
"HTTP/1.1 200 OK\r\n"
"Content-Type: text/html\r\n"
"Connection: close\r\n"
"Content-Length: 44\r\n"
"\r\n"
"<html><body>Hello STM32!</body></html>";

/******************************************************************************
 * Private Types
 ******************************************************************************/

/**
 * @brief Active TCP connection.
 *
 * Stores the current connection state and protocol variables for the
 * embedded TCP server.
 */
typedef struct __attribute__((packed))
{
    uint32_t sourceAddress;
    uint32_t destinationAddress;

    uint8_t  zero;
    uint8_t  protocol;

    uint16_t tcpLength;

} TCPPseudoHeader;


/******************************************************************************
 * Private Variables
 ******************************************************************************/

/**
 * @brief Active TCP connection.
 *
 * Stores the current connection state and protocol variables for the
 * embedded TCP server.
 */
static TCPConnection connection =
{
    .state = TCP_STATE_LISTEN
};
/******************************************************************************
 * Private Function Prototypes
 ******************************************************************************/
/**
 * @brief Print TCP flags.
 *
 * Displays the decoded TCP control flags for debugging.
 *
 * @param flags TCP flag field.
 */
static void tcpPrintFlags(uint16_t flags);

/**
 * @brief Verify the TCP checksum.
 *
 * Computes the checksum of a received TCP segment and compares it
 * against the received checksum.
 *
 * @param ipv4Header Pointer to the IPv4 header.
 * @param tcp Pointer to the TCP header.
 * @param payloadLength TCP payload length.
 *
 * @return true if the checksum is valid.
 * @return false otherwise.
 */
static bool tcpVerifyChecksum(const IPv4Header *ipv4Header,
							  const TCPHeader *tcp,
							  uint16_t payloadLength);

/**
 * @brief Print a TCP header.
 *
 * Displays all decoded TCP header fields for debugging.
 *
 * @param sourcePort Source TCP port.
 * @param destinationPort Destination TCP port.
 * @param sequenceNumber TCP sequence number.
 * @param acknowledgementNumber TCP acknowledgement number.
 * @param headerLength TCP header length in bytes.
 * @param windowSize TCP receive window.
 * @param checksum TCP checksum.
 * @param urgentPointer TCP urgent pointer.
 * @param payloadLength TCP payload length.
 * @param flags TCP control flags.
 * @param options Pointer to TCP options.
 * @param optionsLength Length of TCP options.
 */
static void tcpPrintHeader(
    uint16_t sourcePort,
    uint16_t destinationPort,
    uint32_t sequenceNumber,
    uint32_t acknowledgementNumber,
    uint8_t headerLength,
    uint16_t windowSize,
    uint16_t checksum,
    uint16_t urgentPointer,
    uint16_t payloadLength,
    uint16_t flags,
    const uint8_t *options,
    uint8_t optionsLength);

/**
 * @brief Handle the LISTEN state.
 *
 * Processes incoming SYN packets and begins the TCP three-way handshake.
 *
 * @param ipv4Header Pointer to the IPv4 header.
 * @param sourcePort Source TCP port.
 * @param destinationPort Destination TCP port.
 * @param sequenceNumber Remote sequence number.
 * @param flags TCP control flags.
 */
static void tcpHandleListenState(const IPv4Header *ipv4Header,
                                 uint16_t sourcePort,
                                 uint16_t destinationPort,
                                 uint32_t sequenceNumber,
                                 uint16_t flags);

/**
 * @brief Handle the SYN_RECEIVED state.
 *
 * Processes the final ACK of the TCP three-way handshake.
 *
 * @param flags TCP control flags.
 */
static void tcpHandleSynReceivedState(uint16_t flags);

/**
 * @brief Handle the ESTABLISHED state.
 *
 * Processes received TCP payload data and generates the HTTP response.
 *
 * @param sequenceNumber Remote sequence number.
 * @param tcp Pointer to the TCP header.
 * @param payloadLength Length of the received payload.
 */
static void tcpHandleEstablishedState(uint32_t sequenceNumber,
                                      const TCPHeader *tcp,
                                      uint16_t payloadLength);

/**
 * @brief Print TCP connection information.
 *
 * Displays the current connection state and protocol variables.
 *
 * @param connection Pointer to the TCP connection.
 */
static void tcpPrintConnection(const TCPConnection *connection);

/**
 * @brief Build a TCP header.
 *
 * Populates a TCP header using the current connection state.
 *
 * @param tcp Pointer to the TCP header.
 * @param connection Pointer to the TCP connection.
 * @param flags TCP control flags.
 */
static void tcpBuildHeader(TCPHeader *tcp,
                           const TCPConnection *connection,
                           uint16_t flags);

/**
 * @brief Compute the TCP checksum.
 *
 * Computes the TCP checksum using the IPv4 pseudo header,
 * TCP header, TCP options, and payload.
 *
 * @param sourceIp Source IPv4 address.
 * @param destinationIp Destination IPv4 address.
 * @param tcp Pointer to the TCP header.
 * @param tcpHeaderLength TCP header length.
 * @param payload Pointer to the payload.
 * @param payloadLength Payload length.
 *
 * @return Computed TCP checksum.
 */
static uint16_t tcpComputeChecksum(uint32_t sourceIp,
								   uint32_t destinationIp,
								   const TCPHeader *tcp,
								   uint16_t tcpHeaderLength,
								   const void *payload,
								   uint16_t payloadLength);

/******************************************************************************
 * Private Functions
 ******************************************************************************/

/**
 * @brief Process a received TCP segment.
 *
 * Parses a TCP segment contained within an IPv4 packet, verifies its
 * checksum, updates the TCP connection state machine, and processes
 * any received application data.
 *
 * @param frame Pointer to the received Ethernet frame.
 * @param ipv4Header Pointer to the IPv4 header.
 */
static void tcpPrintFlags(uint16_t flags)
{
	debugPrint("Flags:\r\n");

	if(flags & TCP_FLAG_FIN)
	    debugPrint("  FIN\r\n");

	if(flags & TCP_FLAG_SYN)
	    debugPrint("  SYN\r\n");

	if(flags & TCP_FLAG_RST)
	    debugPrint("  RST\r\n");

	if(flags & TCP_FLAG_PSH)
	    debugPrint("  PSH\r\n");

	if(flags & TCP_FLAG_ACK)
	    debugPrint("  ACK\r\n");

	if(flags & TCP_FLAG_URG)
	    debugPrint("  URG\r\n");

	if(flags & TCP_FLAG_ECE)
	    debugPrint("  ECE\r\n");

	if(flags & TCP_FLAG_CWR)
	    debugPrint("  CWR\r\n");
}

/**
 * @brief Transmit a TCP segment.
 *
 * Builds a TCP segment using the supplied connection parameters,
 * computes its checksum, and transmits it through the IPv4 layer.
 *
 * @param connection Pointer to the TCP connection.
 * @param flags TCP control flags.
 * @param payload Pointer to the payload data.
 * @param payloadLength Length of the payload in bytes.
 *
 * @return HAL_OK if the segment was transmitted successfully.
 * @return HAL_ERROR otherwise.
 */
static uint16_t tcpComputeChecksum(uint32_t sourceIp,
								   uint32_t destinationIp,
								   const TCPHeader *tcp,
								   uint16_t tcpHeaderLength,
								   const void *payload,
								   uint16_t payloadLength)
{
    TCPPseudoHeader pseudo;

    pseudo.sourceAddress = sourceIp;
    pseudo.destinationAddress = destinationIp;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_TCP;
    pseudo.tcpLength =
        __builtin_bswap16(tcpHeaderLength + payloadLength);

    uint16_t checksumLength =
        sizeof(TCPPseudoHeader) +
        tcpHeaderLength +
        payloadLength;

    uint8_t checksumBuffer[sizeof(TCPPseudoHeader) +
                           tcpHeaderLength +
                           payloadLength];

    uint8_t *ptr = checksumBuffer;

    uint8_t headerCopy[tcpHeaderLength];

    memcpy(headerCopy, tcp, tcpHeaderLength);

    TCPHeader *temp = (TCPHeader *)headerCopy;

    temp->checksum = 0;

    memcpy(ptr, &pseudo, sizeof(TCPPseudoHeader));
    ptr += sizeof(TCPPseudoHeader);

    memcpy(ptr, temp, tcpHeaderLength);
    ptr += tcpHeaderLength;

    if (payloadLength > 0)
    {
        memcpy(ptr, payload, payloadLength);
    }

    return checksumCompute(checksumBuffer, checksumLength);
}

/**
 * @brief Verify a received TCP checksum.
 *
 * Recomputes the checksum for a received TCP segment and compares
 * it with the checksum contained in the TCP header.
 *
 * @param ipv4Header Pointer to the IPv4 header.
 * @param tcp Pointer to the TCP header.
 * @param payloadLength Length of the TCP payload in bytes.
 *
 * @return true if the checksum is valid.
 * @return false otherwise.
 */
static bool tcpVerifyChecksum(const IPv4Header *ipv4Header,
							  const TCPHeader *tcp,
							  uint16_t payloadLength)
{
	uint16_t receivedChecksum =
	    __builtin_bswap16(tcp->checksum);

	uint16_t dataOffsetFlags =
	    __builtin_bswap16(tcp->dataOffsetFlags);

	uint16_t tcpHeaderLength =
	    ((dataOffsetFlags >> 12) & 0x0F) * 4;

	uint8_t *payload =
	    (uint8_t *)tcp + tcpHeaderLength;

	uint16_t calculated =
	    tcpComputeChecksum(
	        ipv4Header->sourceAddress,
	        ipv4Header->destinationAddress,
	        tcp,
	        tcpHeaderLength,
	        payload,
	        payloadLength);

	return receivedChecksum == calculated;
}

/**
 * @brief Print a TCP header.
 *
 * Displays the decoded contents of a TCP header for debugging.
 *
 * @param sourcePort Source TCP port.
 * @param destinationPort Destination TCP port.
 * @param sequenceNumber TCP sequence number.
 * @param acknowledgementNumber TCP acknowledgement number.
 * @param headerLength TCP header length in bytes.
 * @param windowSize Advertised receive window.
 * @param checksum TCP checksum.
 * @param urgentPointer TCP urgent pointer.
 * @param payloadLength TCP payload length.
 * @param flags TCP control flags.
 * @param options Pointer to the TCP options.
 * @param optionsLength Length of the TCP options in bytes.
 */
static void tcpPrintHeader(
    uint16_t sourcePort,
    uint16_t destinationPort,
    uint32_t sequenceNumber,
    uint32_t acknowledgementNumber,
    uint8_t headerLength,
    uint16_t windowSize,
    uint16_t checksum,
    uint16_t urgentPointer,
    uint16_t payloadLength,
    uint16_t flags,
    const uint8_t *options,
    uint8_t optionsLength)
{
	 debugPrint("\r\n===== TCP =====\r\n");

	 debugPrintf("Source Port      : %u\r\n", sourcePort);

	 debugPrintf("Destination Port : %u\r\n", destinationPort);

	 debugPrintf("Sequence Number  : %lu\r\n",
	             (unsigned long)sequenceNumber);

	 debugPrintf("Acknowledgement  : %lu\r\n",
	             (unsigned long)acknowledgementNumber);

	 debugPrintf("Header Length    : %u bytes\r\n",
	             headerLength);

	 debugPrintf("Window Size      : %u\r\n", windowSize);

	 debugPrintf("Checksum         : 0x%04X\r\n", checksum);

	 debugPrintf("Urgent Pointer   : %u\r\n", urgentPointer);

	 debugPrintf("Payload Length   : %u bytes\r\n", payloadLength);

	 tcpPrintFlags(flags);

	 if (optionsLength > 0)
	 {
	     debugPrint("TCP Options:\r\n");

	     for (uint8_t i = 0; i < optionsLength; i++)
	     {
	         debugPrintf("%02X ", options[i]);

	         if (((i + 1) % 16) == 0)
	         {
	             debugPrint("\r\n");
	         }
	     }

	     debugPrint("\r\n");
	 }
}

/**
 * @brief Handle the LISTEN state.
 *
 * Processes an incoming SYN segment and initiates the TCP
 * three-way handshake.
 *
 * @param ipv4Header Pointer to the IPv4 header.
 * @param sourcePort Source TCP port.
 * @param destinationPort Destination TCP port.
 * @param sequenceNumber Remote sequence number.
 * @param flags TCP control flags.
 */
static void tcpHandleListenState(const IPv4Header *ipv4Header,
                                 uint16_t sourcePort,
                                 uint16_t destinationPort,
                                 uint32_t sequenceNumber,
                                 uint16_t flags)
{
	if ((flags & TCP_FLAG_SYN) &&
	    !(flags & TCP_FLAG_ACK))
	{
	    debugPrint("Received SYN\r\n");

	    connection.remoteIp =
	        __builtin_bswap32(ipv4Header->sourceAddress);

	    connection.remotePort = sourcePort;

	    connection.localPort = destinationPort;

	    connection.remoteSequence = sequenceNumber;

	    connection.acknowledgement = sequenceNumber + 1;

	    connection.localSequence = 1000;

	    connection.state = TCP_STATE_SYN_RECEIVED;

	    debugPrint("TCP State -> SYN_RECEIVED\r\n");

	    tcpPrintConnection(&connection);

	    tcpSendPacket(&connection,
	                  TCP_FLAG_SYN | TCP_FLAG_ACK,
	                  NULL,
	                  0);

	    connection.localSequence++;
	}
}

/**
 * @brief Handle the SYN_RECEIVED state.
 *
 * Processes the final ACK of the TCP three-way handshake and
 * transitions the connection to the ESTABLISHED state.
 *
 * @param flags TCP control flags.
 */
static void tcpHandleSynReceivedState(uint16_t flags)
{
    if ((flags & TCP_FLAG_ACK) &&
        !(flags & TCP_FLAG_SYN))
    {
        debugPrint("TCP connection established!\r\n");

        connection.state = TCP_STATE_ESTABLISHED;
    }
}

/**
 * @brief Handle the ESTABLISHED state.
 *
 * Processes received application data, updates sequence and
 * acknowledgement numbers, and transmits the HTTP response.
 *
 * @param sequenceNumber Remote TCP sequence number.
 * @param tcp Pointer to the TCP header.
 * @param payloadLength Length of the received payload.
 */
static void tcpHandleEstablishedState(uint32_t sequenceNumber,
                                      const TCPHeader *tcp,
                                      uint16_t payloadLength)
{
    if (payloadLength == 0)
    {
        return;
    }

    uint16_t dataOffsetFlags =
        __builtin_bswap16(tcp->dataOffsetFlags);

    uint16_t tcpHeaderLength =
        ((dataOffsetFlags >> 12) & 0x0F) * 4;

    const uint8_t *payload =
        (const uint8_t *)tcp + tcpHeaderLength;

    connection.remoteSequence = sequenceNumber;

    connection.acknowledgement =
        sequenceNumber + payloadLength;

    debugPrint("\r\n===== HTTP Request =====\r\n");

    for (uint16_t i = 0; i < payloadLength; i++)
    {
    	debugPrintf("%c", payload[i]);
    }

    debugPrint("\r\n");

    tcpSendPacket(&connection,
                  TCP_FLAG_ACK | TCP_FLAG_PSH,
                  httpResponse,
                  strlen(httpResponse));

    connection.localSequence += strlen(httpResponse);
}

/**
 * @brief Print TCP connection information.
 *
 * Displays the current TCP connection state and protocol
 * variables for debugging.
 *
 * @param connection Pointer to the TCP connection.
 */
static void tcpPrintConnection(const TCPConnection *connection)
{
    debugPrint("\r\n===== TCP Connection =====\r\n");

    debugPrintf("State          : %u\r\n", connection->state);

    debugPrintf("Remote IP      : %u.%u.%u.%u\r\n",
                (connection->remoteIp >> 24) & 0xFF,
                (connection->remoteIp >> 16) & 0xFF,
                (connection->remoteIp >> 8) & 0xFF,
                 connection->remoteIp & 0xFF);

    debugPrintf("Local Port     : %u\r\n", connection->localPort);
    debugPrintf("Remote Port    : %u\r\n", connection->remotePort);

    debugPrintf("Local Seq      : %lu\r\n",
                (unsigned long)connection->localSequence);

    debugPrintf("Remote Seq     : %lu\r\n",
                (unsigned long)connection->remoteSequence);

    debugPrintf("Ack Number     : %lu\r\n",
                (unsigned long)connection->acknowledgement);
}

/**
 * @brief Build a TCP header.
 *
 * Populates a TCP header using the current connection
 * parameters and the specified TCP flags.
 *
 * @param tcp Pointer to the TCP header.
 * @param connection Pointer to the TCP connection.
 * @param flags TCP control flags.
 */
static void tcpBuildHeader(TCPHeader *tcp,
                           const TCPConnection *connection,
                           uint16_t flags)
{
    memset(tcp, 0, sizeof(TCPHeader));

    tcp->sourcePort =
        __builtin_bswap16(connection->localPort);

    tcp->destinationPort =
        __builtin_bswap16(connection->remotePort);

    tcp->sequenceNumber =
        __builtin_bswap32(connection->localSequence);

    tcp->acknowledgementNumber =
        __builtin_bswap32(connection->acknowledgement);

    /* 20-byte TCP header = 5 words */
    uint16_t dataOffset = 5;

    tcp->dataOffsetFlags =
        __builtin_bswap16((dataOffset << 12) | flags);

    tcp->windowSize =
        __builtin_bswap16(65535);

    tcp->checksum = 0;

    tcp->urgentPointer = 0;
}

/******************************************************************************
 * Public Functions
 ******************************************************************************/

/**
 * @brief Process a received TCP segment.
 *
 * Parses a TCP segment contained within an IPv4 packet,
 * verifies its checksum, and processes it according to the
 * current TCP connection state.
 *
 * @param frame Pointer to the received Ethernet frame.
 * @param ipv4Header Pointer to the IPv4 header.
 */
void tcpReceivePacket(EthernetFrame *frame,
                      const IPv4Header *ipv4Header)
{
	 (void)frame;

    uint8_t ipv4HeaderLength = (ipv4Header->versionIhl & 0x0F) * 4;

    /* Locate the TCP header following the IPv4 header. */
    TCPHeader *tcp =
        (TCPHeader *)((uint8_t *)ipv4Header + ipv4HeaderLength);

    uint16_t sourcePort =
        __builtin_bswap16(tcp->sourcePort);

    uint16_t destinationPort =
        __builtin_bswap16(tcp->destinationPort);

    uint32_t sequenceNumber =
        __builtin_bswap32(tcp->sequenceNumber);

    uint32_t acknowledgementNumber =
        __builtin_bswap32(tcp->acknowledgementNumber);

    uint16_t dataOffsetFlags =
        __builtin_bswap16(tcp->dataOffsetFlags);

    uint16_t windowSize =
        __builtin_bswap16(tcp->windowSize);

    uint16_t checksum =
        __builtin_bswap16(tcp->checksum);

    uint16_t urgentPointer =
        __builtin_bswap16(tcp->urgentPointer);

    /* Extract the TCP header length from the data offset field. */
    uint8_t tcpHeaderLength =
        ((dataOffsetFlags >> 12) & 0x0F) * 4;

    uint16_t flags = dataOffsetFlags & 0x01FF;

    uint8_t optionsLength = tcpHeaderLength - sizeof(TCPHeader);

    /* Determine the length of the TCP payload. */
    uint16_t payloadLength =
        __builtin_bswap16(ipv4Header->totalLength)
        - ipv4HeaderLength
        - tcpHeaderLength;

    /* Drop packets with an invalid checksum. */
	if (!tcpVerifyChecksum(ipv4Header, tcp, payloadLength))
	{
		debugPrint("TCP checksum FAILED\r\n");
		return;
	}

	debugPrint("TCP checksum VALID\r\n");

    uint8_t *options = NULL;

    if (optionsLength > 0)
    {
        options = (uint8_t *)tcp + sizeof(TCPHeader);
    }

    tcpPrintHeader(sourcePort,
                   destinationPort,
                   sequenceNumber,
                   acknowledgementNumber,
                   tcpHeaderLength,
                   windowSize,
                   checksum,
                   urgentPointer,
                   payloadLength,
                   flags,
                   options,
                   optionsLength);

    /* Process the segment according to the current TCP connection state. */
    switch (connection.state)
    {
        case TCP_STATE_LISTEN:
        {
            tcpHandleListenState(ipv4Header,
                                 sourcePort,
                                 destinationPort,
                                 sequenceNumber,
                                 flags);
            break;
        }
        case TCP_STATE_SYN_RECEIVED:
        {
            tcpHandleSynReceivedState(flags);
            break;
        }
        case TCP_STATE_ESTABLISHED:
        {
        	tcpHandleEstablishedState(sequenceNumber,
        	                          tcp,
        	                          payloadLength);
            break;
        }
        default:
        {
            break;
        }
    }
}

/**
 * @brief Transmit a TCP segment.
 *
 * Builds a TCP segment, computes its checksum, and transmits
 * it through the IPv4 layer.
 *
 * @param connection Pointer to the TCP connection.
 * @param flags TCP control flags.
 * @param payload Pointer to the payload data.
 * @param payloadLength Length of the payload in bytes.
 *
 * @return HAL_OK if the segment was transmitted successfully.
 * @return HAL_ERROR otherwise.
 */
HAL_StatusTypeDef tcpSendPacket(
	    TCPConnection *connection,
	    uint16_t flags,
	    const void *payload,
	    uint16_t payloadLength)
{
	/* Build the TCP header. */
	TCPHeader tcpHeader;

	tcpBuildHeader(&tcpHeader,
	               connection,
	               flags);

	/* Compute the TCP checksum over the pseudo header,
	 * TCP header, and payload.
	 */
	tcpHeader.checksum =
	    tcpComputeChecksum(
	        __builtin_bswap32(ipToUint32(LOCAL_IP_ADDRESS)),
	        __builtin_bswap32(connection->remoteIp),
	        &tcpHeader,
		    sizeof(TCPHeader),
	        payload,
	        payloadLength);

	uint16_t tcpLength =
	    sizeof(TCPHeader) + payloadLength;

	uint8_t txBuffer[sizeof(TCPHeader) + payloadLength];

	/* Assemble the TCP segment. */
	memcpy(txBuffer,
	       &tcpHeader,
	       sizeof(TCPHeader));

	/* Copy the payload, if present. */
	if (payloadLength > 0)
	{
	    memcpy(txBuffer + sizeof(TCPHeader),
	           payload,
	           payloadLength);
	}

	/* Transmit the segment using IPv4. */
	return ipv4SendPacket(
	    connection->remoteIp,
	    IP_PROTOCOL_TCP,
	    txBuffer,
	    tcpLength,
	    64);
}


