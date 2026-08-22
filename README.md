# Legacy SSL/TLS Demo — RSA Key Exchange (intentionally vulnerable)

A demo of the older approach to TLS, from before RSA key exchange was dropped in favor of Diffie-Hellman variants (DHE/ECDHE). The client generates a symmetric AES key, encrypts it with the server's RSA public key, and signs it with its own private key to prove its identity.

## How it works

1. The client generates a symmetric AES key.
2. It encrypts the key with the server's RSA public key.
3. It signs the encrypted key with its own private key (proof of identity).
4. The server verifies the signature, decrypts the AES key with its RSA private key, and uses it for further communication.

## Known vulnerabilities (intentional, for demonstration purposes)

1. **AES key derived from a hardcoded password in the source code** — the symmetric key is generated from a fixed string written directly into the code. Even though that key gets encrypted with the server's RSA public key before being sent over the network, the transport encryption doesn't actually help — anyone who reads the source code (and on GitHub, that's everyone) already knows the exact value the key is derived from.

2. **No forward secrecy** — since the AES key is encrypted with the server's long-term RSA public key, compromising that one RSA private key in the future (a leak, a hack) allows retroactive decryption of ALL previously captured sessions. This is the main reason modern TLS dropped plain RSA key exchange in favor of (E)DHE variants, where temporary keys are generated per session and discarded right after use — so compromising the long-term key doesn't put past sessions at risk.

3. **"Harvest now, decrypt later" — the quantum computing threat** — independent of the classical compromise risk, an attacker can record all encrypted traffic today and store it, waiting for quantum computers to mature enough for Shor's algorithm to efficiently break RSA (by factoring the modulus). Worth noting: even switching to (E)DHE (classical Diffie-Hellman) isn't resistant to this scenario, since DH also relies on the discrete logarithm problem, which Shor's algorithm solves just as efficiently. The only resistant approach is post-quantum cryptography (e.g., Kyber, used in the companion post-quantum TLS demo project) — see that project for comparison.

## Trust model

Same as the post-quantum TLS demo project — client and server public keys are loaded from local disk, shared in advance (key pinning), not through a formal PKI/CA setup. See that project's README for the limitations of this approach — they apply here too.

## What's next

The next project in this series replaces RSA key exchange with Diffie-Hellman parameter exchange, addressing the lack of forward secrecy described above.

## Running it

Keys are loaded from relative paths inside a `keys/` folder at the project root. Generate your own RSA and signing (digital signature) keys before running the client and server.

```bash
# Run the server
java Server

# Run the client (in a separate terminal)
java Client
```