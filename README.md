# Secure IoT Control System (Arduino Nano 33 IoT)

## Overview

Secure IoT Control System is a cybersecurity-focused embedded project that demonstrates authenticated remote control of an IoT device using ECDSA digital signatures and SHA-256 hashing.

The project is built around an Arduino Nano 33 IoT acting as a TCP server that accepts JSON-based commands over Wi-Fi. Before any command is executed, the device verifies the authenticity and integrity of the received message using elliptic curve cryptography.

The implementation also serves as a software emulation of a Secure Element (ATECC608A), allowing experimentation with secure authentication mechanisms without requiring dedicated cryptographic hardware.

---

## Project Goals

- Demonstrate secure command authentication in IoT environments.
- Implement ECDSA-based authorization on a resource-constrained microcontroller.
- Verify message integrity using SHA-256.
- Emulate selected Secure Element functionalities in software.
- Analyze limitations of software-based key protection compared to hardware-backed security.

---

## Hardware Setup

The prototype was implemented using an Arduino Nano 33 IoT platform featuring:

- SAMD21 ARM Cortex-M0+ microcontroller
- NINA Wi-Fi module
- Built-in LED used as a controlled actuator

<img width="5647" height="2655" alt="20250610_192751(1)" src="https://github.com/user-attachments/assets/bd7348d9-928e-48f3-9c79-d3280cd60d71" />

---

## System Architecture

The project consists of three main components:

### 1. Arduino Firmware

The Arduino device:

- Connects to a Wi-Fi network.
- Starts a TCP server on port 6668.
- Receives JSON commands.
- Computes SHA-256 hashes.
- Verifies ECDSA signatures.
- Executes commands only after successful authentication.

### 2. Key Generation Utility

`generate_client_keys.py`

Responsible for:

- Generating an ECDSA key pair using the secp256r1 curve.
- Exporting the private key for the client.
- Exporting the public key used by the Arduino for signature verification.

### 3. Signed TCP Client

`iot_signed_client.py`

Responsible for:

- Loading the client private key.
- Signing commands using ECDSA.
- Sending authenticated JSON requests.
- Receiving and displaying responses from the Arduino device.

---

## Repository Structure

```text
Secure-IoT-Control-System/
│
├── secure_iot.ino
├── generate_client_keys.py
├── iot_signed_client.py
├── README.md
│
└── images/
    ├── hardware_setup.jpg
    └── communication_sequence.png
```

---

## Communication Protocol

Communication is performed using TCP and JSON messages.

### Request Format

```json
{
  "command": "led_on",
  "signature": "<ECDSA_SIGNATURE_HEX>"
}
```

### Supported Commands

| Command | Description |
|----------|-------------|
| led_on | Turn built-in LED on |
| led_off | Turn built-in LED off |
| status | Return current LED state |
| get_pubkey | Return Arduino public key |

### Communication Sequence

The following diagram illustrates the communication process between the Python client and the Arduino device.

<img width="539" height="753" alt="Zrzut ekranu 2026-06-02 195540" src="https://github.com/user-attachments/assets/9dc9b845-c1be-4543-92a9-4935872672d5" />

### Protocol Flow

1. Client establishes a TCP connection to the Arduino.
2. Client serializes the command into deterministic JSON.
3. SHA-256 hash of the JSON message is computed.
4. The hash is signed using the client's ECDSA private key.
5. The signature is attached to the JSON payload.
6. The signed request is transmitted to the Arduino.
7. Arduino removes the signature field.
8. Arduino recomputes the SHA-256 hash.
9. Arduino verifies the ECDSA signature using the stored client public key.
10. If verification succeeds, the command is executed.
11. Arduino returns a JSON response and closes the connection.

---

## Security Features

### ECDSA Authentication

Only clients possessing the correct private key can generate valid signatures.

Implemented using:

- Curve: secp256r1 (NIST P-256)
- Library: micro-ecc

### SHA-256 Integrity Verification

A custom embedded SHA-256 implementation is included directly in the firmware.

Implemented functions:

- sha256_init()
- sha256_update()
- sha256_final()

### Trusted Public Key Model

The Arduino firmware contains a trusted client public key used as the root of trust for all incoming requests.

### Timeout Protection

Connections that remain inactive for more than two seconds are automatically terminated to reduce resource exhaustion risks.

---

## Secure Element Emulation

This project emulates selected functionalities typically provided by a hardware Secure Element such as the ATECC608A.

### Emulated Properties

- ECDSA key pair generation
- Digital signature verification
- Restricted cryptographic interface
- Authentication-based command execution

### Limitations Compared to Real Secure Elements

- Private keys are stored in MCU memory.
- No tamper-resistant hardware protection.
- Keys may be extracted through firmware analysis.
- No hardware random number generator.
- No physical attack resistance.

---

## Requirements

### Hardware

- Arduino Nano 33 IoT

### Software

- Arduino IDE or PlatformIO
- Python 3

### Arduino Libraries

- WiFiNINA
- ArduinoJson
- micro-ecc

### Python Libraries

```bash
pip install ecdsa
```

---

## Setup

### 1. Generate Client Keys

```bash
python generate_client_keys.py
```

Generated files:

```text
client_priv.hex
client_pub.hex
```

The generated public key must be embedded into the Arduino firmware as the trusted client public key.

### 2. Configure Wi-Fi

Update the firmware with your Wi-Fi credentials:

```cpp
char ssid[] = "YOUR_WIFI";
char pass[] = "YOUR_PASSWORD";
```

### 3. Upload Firmware

Compile and upload the Arduino sketch.

### 4. Run the Client

Example commands:

```bash
python iot_signed_client.py led_on
```

```bash
python iot_signed_client.py led_off
```

```bash
python iot_signed_client.py status
```

```bash
python iot_signed_client.py get_pubkey
```

---

## Example Security Workflow

```text
generate_client_keys.py
            │
            ▼
     ECDSA Key Pair
            │
            ▼
   iot_signed_client.py
            │
            ▼
 SHA-256 + ECDSA Signature
            │
            ▼
      TCP / JSON Request
            │
            ▼
    Arduino Nano 33 IoT
            │
            ▼
   Signature Verification
            │
            ▼
     Command Execution
```

---

## Security Insights

This project demonstrates:

- Public-key authentication for IoT devices.
- Embedded cryptography on constrained hardware.
- Secure command authorization using digital signatures.
- The importance of Secure Elements in real-world deployments.
- The differences between software-based and hardware-backed key protection.

---

## Future Improvements

- Integration with a physical ATECC608A Secure Element.
- TLS-encrypted communication.
- Replay attack protection using nonces or timestamps.
- Multiple trusted client support.
- Secure key provisioning process.
- MQTT integration.
- Hardware-backed key storage.

---

## Technologies Used

- Arduino Nano 33 IoT
- C++
- Python
- TCP/IP
- JSON
- SHA-256
- ECDSA
- secp256r1 (NIST P-256)
- WiFiNINA
- ArduinoJson
- micro-ecc

---

## About

This project was developed to explore secure communication mechanisms in embedded IoT systems and to demonstrate how digital signatures can be used to authenticate remote commands on resource-constrained devices.

The implementation combines embedded programming, networking, and applied cryptography while highlighting the role of Secure Elements in modern IoT security architectures.
