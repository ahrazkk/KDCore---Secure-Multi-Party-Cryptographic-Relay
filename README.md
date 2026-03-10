# KDCORE: Secure Multi-Party Cryptographic Relay

## 📝 Overview
**KDCORE** is a distributed, multi-client secure communication system built in Java. It utilizes a centralized **Key Distribution Center (KDC)** to orchestrate a hybrid cryptographic protocol. 

By combining asymmetric cryptography (**RSA**) for secure handshakes and symmetric block ciphers (**AES**) for high-throughput message encryption, the system ensures:
* **End-to-End Confidentiality**
* **Data Integrity**
* **Non-Repudiation**
* **Resilience** against network-level replay attacks.

---

## 🏗️ System Architecture
The network topology consists of a central **KDC** acting as a trusted third-party server and message relay, handling concurrent connections from multiple authenticated clients.

### 1. Hybrid Key Distribution Protocol
The system avoids the overhead of encrypting every chat message asymmetrically by using a multi-phase key distribution model:
* **Master Keys (Symmetric):** Unique to each client-server pair, established securely via an RSA handshake.
* **Group Key ($K_s$):** A unified AES session key distributed to all authenticated participants by the KDC, enabling seamless multi-party decryption without redundant encryption cycles.

### 2. Message Authentication & Relay
Instead of peer-to-peer routing, clients transmit encrypted payloads to the KDC. The KDC acts as a **blind relay**, forwarding the ciphertexts to all intended recipients. The KDC cannot spoof messages because it lacks the clients' private RSA keys required for digital signatures.

---

## 🔐 Technical Implementation

### Phase 1: Authenticated Handshake (RSA)
To prevent Man-in-the-Middle (MitM) attacks, the initial connection relies on **2048-bit RSA** cryptography and cryptographic nonces.
1. **Exchange:** Client and KDC exchange Public Keys.
2. **Challenge:** KDC generates a random Nonce ($N_K$), encrypts it with the Client's Public Key, and transmits it.
3. **Verification:** Client decrypts the Nonce, appends its own Nonce ($N_C$), encrypts the payload with the KDC's Public Key, and returns it.
4. **Master Key:** Upon verification, the KDC generates a unique Master Key, encrypts it with the Client's Public Key, and distributes it.

### Phase 2: Group Key Distribution (AES)
Once the secure channel is established:
* The KDC generates a global **Group Session Key ($K_s$)**.
* The KDC truncates the Master Key to exactly 16 bytes to construct an `AES SecretKeySpec`.
* The $K_s$ is encrypted using the AES cipher and distributed to the network.

### Phase 3: Secure Chat & Non-Repudiation
Every message undergoes a two-step security process:
* **Confidentiality:** Message, sender ID, and timestamp are encrypted using the shared AES Group Key ($K_s$).
* **Integrity & Authenticity:** The plaintext is hashed and digitally signed using **SHA256withRSA** and the sender's Private Key.

---

## 🛡️ Replay Attack Prevention
To combat network flooding and packet interception, KDCORE implements strict **temporal validation**:
1. A timestamp is injected into every AES-encrypted payload.
2. The client manages a state variable for the last received timestamp.
3. If a decrypted packet's timestamp is older than the last received message, the packet is **dropped** as a detected replay attack.

---

## 💻 Tech Stack & Dependencies
* **Language:** Java SE (JDK 8+)
* **Networking:** `java.net.Socket`, `java.net.ServerSocket`, `java.io.ObjectOutputStream`
* **Cryptography Algorithms:**
    * **Asymmetric:** RSA (2048-bit KeyPairGenerator)
    * **Symmetric:** AES (`javax.crypto.Cipher`, `SecretKeySpec`)
    * **Hashing & Signatures:** SHA256withRSA (`java.security.Signature`)

---

## 🚀 Getting Started
Execution
To simulate the secure network, instantiate the KDC server before the clients. Open four separate terminal instances:

Terminal 1 (Start KDC Relay):

Bash
java KDC
Terminal 2, 3, and 4 (Connect Clients):

Bash
java ClientA
java ClientB
java ClientC
👨‍💻 Author
Ahraz Kibria Computer Engineering (Software Engineering) Toronto Metropolitan University

### Prerequisites
* Java Development Kit (JDK) installed and configured in your system environment variables.

### Build Instructions
Clone the repository and compile the Java source files:
```bash
git clone [https://github.com/yourusername/KDCORE.git](https://github.com/yourusername/KDCORE.git)
cd KDCORE
javac KDC.java ClientA.java ClientB.java ClientC.java
