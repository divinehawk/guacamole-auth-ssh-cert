# guacamole-auth-ssh-cert

An Apache Guacamole extension that automatically signs and injects short-lived, per-connection OpenSSH certificates on every session launch. No persisted private keys, no external subprocesses, and zero SSH key reuse across connections.

---

## Features

- **Per-Connect Provisioning:** Generates fresh Ed25519 key pairs and OpenSSH user certificates dynamically on every `connect()` call rather than once per login.
- **Pure Java Signing:** Operates entirely in-process using native JDK cryptography and Apache MINA SSHD without shelling out to `ssh-keygen`.
- **UI Integration:** Dynamically injects an *Additional Principals* field into connection management pages across both new and existing database-backed connections.

---

## Prerequisites & Compatibility

| Component | Required Version |
| :--- | :--- |
| **Apache Guacamole** | `1.6.0` or higher |
| **Java SDK** | JDK 17+ |
| **Build Tool** | Apache Maven 3.8+ |

---

## Configuration (`guacamole.properties`)

Add the following configuration properties to your `guacamole.properties` file:

```properties
# Path to your SSH Certificate Authority keypair (required)
ssh-cert-ca-key: /etc/guacamole/ssh-ca/ca_key

# Certificate lifetime (in seconds) (optional, default: 300)
ssh-cert-ttl-seconds: 300

# Mapping file for identity-to-principal translation (optional)
ssh-cert-principals-file: /etc/guacamole/ssh-principals.conf

# Key type ssh-ed25519 or ssh-rsa (optional)
ssh-cert-key-type: ssh-ed25519
