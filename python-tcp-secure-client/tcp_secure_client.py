#!/usr/bin/env python

#******************************************************************************
# File Name:   tcp_secure_client.py
#
# Description: A simple python based secure TCP client.
# The server sends LED ON/OFF commands to the connected TCP client
# and receives acknowledgement from the client.
#
#******************************************************************************
# Copyright 2019-2024, Cypress Semiconductor Corporation (an Infineon company) or
# an affiliate of Cypress Semiconductor Corporation.  All rights reserved.
#
# This software, including source code, documentation and related
# materials ("Software") is owned by Cypress Semiconductor Corporation
# or one of its affiliates ("Cypress") and is protected by and subject to
# worldwide patent protection (United States and foreign),
# United States copyright laws and international treaty provisions.
# Therefore, you may use this Software only as provided in the license
# agreement accompanying the software package from which you
# obtained this Software ("EULA").
# If no EULA applies, Cypress hereby grants you a personal, non-exclusive,
# non-transferable license to copy, modify, and compile the Software
# source code solely for use in connection with Cypress's
# integrated circuit products.  Any reproduction, modification, translation,
# compilation, or representation of this Software except as specified
# above is prohibited without the express written permission of Cypress.
#
# Disclaimer: THIS SOFTWARE IS PROVIDED AS-IS, WITH NO WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, NONINFRINGEMENT, IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. Cypress
# reserves the right to make changes to the Software without notice. Cypress
# does not assume any liability arising out of the application or use of the
# Software or any product or circuit described in the Software. Cypress does
# not authorize its products for use in any products where a malfunction or
# failure of the Cypress product may reasonably be expected to result in
# significant property damage, injury or death ("High Risk Product"). By
# including Cypress's product in a High Risk Product, the manufacturer
# of such system or application assumes all risk of such use and in doing
# so agrees to indemnify Cypress against all liability.
#******************************************************************************/

import socket
import ssl
import sys

# IP details for the TCP server
DEFAULT_PORT = 50007                         # Port of the TCP server
arguments = len(sys.argv) - 1

if ((arguments == 2) and sys.argv[1] == "ipv4"):
    print("================================================================================")
    print("TCP Secure Client (IPv4 addressing mode)")
    print("================================================================================")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
elif((arguments == 2) and sys.argv[1] == "ipv6"):
    print("================================================================================")
    print("TCP Secure Client (IPv6 addressing mode)")
    print("================================================================================")
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
else:
    print("\nInvalid inputs. From the command line, enter IP address type (ipv6 or ipv4) followed by server IP address")
    print("For example:")
    print("If you are using IPv4 addressing mode, enter the command as:")
    print("python tcp_secure_client ipv4 <IPv4 Address>")
    print("If you are using IPv6 addressing mode, enter the command as:")
    print("python tcp_secure_client ipv6 <IPv6 Address>")
    sys.exit(1)

DEFAULT_IP = sys.argv[2]

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_cert_chain(certfile="client.crt", keyfile="client.key")
context.load_verify_locations(cafile="root_ca.crt")
ssl_sock = context.wrap_socket(s, server_hostname="myServer")

ssl_sock.connect((DEFAULT_IP, DEFAULT_PORT))
print("Connected to TCP Server (IP Address: ", DEFAULT_IP, "Port: ", DEFAULT_PORT, " )")

try:
    while True:
        print("================================================================================")
        data = ssl_sock.read();
        print("Message from Server:")
        if data.decode('utf-8') == '0':
            print("LED OFF")
            message = 'LED OFF ACK'
            ssl_sock.write(message.encode('utf-8'))
        if data.decode('utf-8') == '1':
            print("LED ON")
            message = 'LED ON ACK'
            ssl_sock.write(message.encode('utf-8'))
        print("Acknowledgement sent to secure TCP server")

except KeyboardInterrupt:
    ssl_sock.close()
    s.close()
    print("\nConnection Closed")
    sys.exit(1)

# [] END OF FILE
