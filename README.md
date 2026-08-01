# STM32 NUCLEO-H563ZI Bare-Metal TCP/IP Stack & HTTP Server

## Overview

This project implements a **bare-metal TCP/IP networking stack** for the **STM32 NUCLEO-H563ZI** without using LwIP or any third-party networking libraries.

Built on top of a custom Ethernet driver, the project progressively implements the core Internet protocols required to communicate with standard network devices and host a simple embedded HTTP server.

The stack was developed from the protocol specifications and verified using **Wireshark**, allowing each layer to be tested independently before integrating the complete networking stack.

---

## Foundation

This project builds upon my previous project:

**STM32 NUCLEO-H563ZI Bare-Metal Ethernet Driver**

> Replace this with your GitHub repository link:

```text
https://github.com/<username>/stm32-baremetal-ethernet-driver
```

The Ethernet driver provides:

- Ethernet MAC initialization
- PHY communication
- DMA descriptor management
- Ethernet frame transmission
- Ethernet frame reception

This project extends that driver by implementing the higher layers of the networking stack.

---

## Features

### Ethernet

- Ethernet frame transmission
- Ethernet frame reception
- Ethernet frame parsing
- MAC address handling

### Address Resolution Protocol (ARP)

- ARP request processing
- ARP reply generation
- Dynamic ARP cache
- Automatic MAC address learning

### IPv4

- IPv4 packet transmission
- IPv4 packet reception
- Header parsing
- Header checksum verification

### Internet Control Message Protocol (ICMP)

- Echo Request processing
- Echo Reply generation
- Ping support

### User Datagram Protocol (UDP)

- UDP packet transmission
- UDP packet reception
- UDP checksum generation
- UDP checksum verification
- UDP echo server

### Transmission Control Protocol (TCP)

- TCP three-way handshake
- TCP checksum generation
- TCP checksum verification
- TCP state machine
- Sequence number management
- Acknowledgement tracking
- TCP options parsing

### HTTP

- Embedded HTTP server
- HTTP GET request processing
- HTML response generation

---

## Project Structure

```text
Application
│
├── Ethernet
│
├── ARP
│
├── IPv4
│
├── ICMP
│
├── UDP
│
├── TCP
│
└── HTTP Server
```

---

## Technologies Used

- STM32 NUCLEO-H563ZI
- STM32CubeIDE
- STM32 HAL
- RMII Ethernet
- LAN8742 PHY
- Wireshark
- Tera Term

---
## Hardware

### Development Board

- STM32 NUCLEO-H563ZI
- STM32H563ZI Microcontroller
- Integrated ST-LINK debugger
- On-board LAN8742 Ethernet PHY

### Interfaces

#### Ethernet (RMII)

| Signal | STM32 Pin |
|---------|-----------|
| REF_CLK | PA1 |
| MDIO | PA2 |
| CRS_DV | PA7 |
| TXD1 | PB15 |
| MDC | PC1 |
| RXD0 | PC4 |
| RXD1 | PC5 |
| TX_EN | PG11 |
| TXD0 | PG13 |

#### UART Debug Console

| Signal | STM32 Pin |
|---------|-----------|
| USART3 TX | PD8 |
| USART3 RX | PD9 |

### Network Configuration

- Static IP Address: **192.168.7.250**
- RMII Ethernet Interface
- LAN8742 PHY

## Networking Stack

```text
Application
      │
     HTTP
      │
     TCP
      │
     UDP
      │
     ICMP
      │
     IPv4
      │
     ARP
      │
   Ethernet
      │
     RMII
      │
LAN8742 PHY
```
## Testing the Stack

The networking stack can be validated incrementally using standard networking tools.

### ICMP (Ping)

Verify IPv4 connectivity by sending an ICMP Echo Request:

```bash
ping 192.168.7.250
```

Expected result:

```text
Reply from 192.168.7.250: bytes=32 time<1ms TTL=64
```

---

### HTTP Server

Open the embedded web server using a browser:

```text
http://192.168.7.250
```

Or using `curl`:

```bash
curl http://192.168.7.250
```

Expected response:

```html
<html><body>Hello STM32!</body></html>
```

---


The server is accessible from any device on the local network using the configured static IP address.

---

## What I Learned

Throughout this project I gained experience implementing networking protocols directly from their specifications, including:

- Ethernet frame formats
- ARP protocol operation
- IPv4 packet construction
- Internet checksums
- UDP communication
- TCP connection establishment
- TCP sequence and acknowledgement numbers
- TCP state machines
- HTTP request and response handling
- Packet analysis using Wireshark
- Embedded network debugging

---

## Future Improvements

- TCP connection termination (FIN/ACK)
- Multiple simultaneous TCP connections
- HTTP request parsing
- Dynamic web pages
- DHCP client
- DNS client
- Socket abstraction layer
- HTTPS/TLS support

---

## Repository Contents

- Ethernet driver
- ARP implementation
- IPv4 implementation
- ICMP implementation
- UDP implementation
- TCP implementation
- Embedded HTTP server
- Debug utilities

---
## Challenges

Developing the networking stack from scratch required solving problems at every protocol layer while working within the constraints of an embedded system.

Some of the most significant challenges included:

- Configuring the STM32 Ethernet peripheral and RMII interface without using LwIP.
- Learning the Ethernet MAC, DMA descriptor architecture, and packet buffer management.
- Bringing up the LAN8742 PHY, including initialization, link detection, and auto-negotiation.
- Verifying Ethernet frame transmission and reception using Wireshark.
- Implementing Internet checksum algorithms for IPv4, UDP, and TCP, including the TCP and UDP pseudo headers.
- Building and parsing Ethernet, ARP, IPv4, UDP, and TCP headers directly from their protocol specifications.
- Managing TCP sequence numbers, acknowledgement numbers, and the TCP three-way handshake.
- Designing a TCP state machine for connection establishment and HTTP data transfer.
- Debugging packet formatting, endianness (network byte order), and checksum validation failures.
- Comparing captured packets against protocol specifications to identify implementation errors.
- Diagnosing a HardFault caused by stack exhaustion after allocating a 1600-byte temporary buffer inside the UDP checksum routine. The issue was resolved by moving the buffer to static storage, reducing stack usage and reinforcing the importance of understanding embedded memory layout.
- Incrementally validating each protocol layer before implementing the next, ensuring a stable foundation for the complete networking stack.

## License

This project is provided for educational purposes.