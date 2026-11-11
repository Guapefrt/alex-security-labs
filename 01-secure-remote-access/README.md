# Secure Remote Linux Access Lab

## Objective

Build a secure remote administration path to my personal Arch Linux laptop without exposing SSH directly to the public Internet or normal home LAN.

## Lab Environment

- Arch Linux
- Linux Zen kernel
- OpenSSH
- Tailscale
- nftables
- Termius on iPhone
- Nmap
- Wireshark

## Architecture

```text
iPhone / 5G
     |
     v
Termius
     |
     | SSH + ED25519
     v
Tailscale
     |
     v
tailscale0
     |
     v
nftables
     |
     | TCP/22 allowed via Tailscale
     v
OpenSSH
     |
     v
Arch Linux
```

## Security Design

The goal was to allow remote administration while minimizing the exposure of the SSH service.

### SSH Authentication

OpenSSH was configured with:

```text
PubkeyAuthentication yes
PasswordAuthentication no
PermitRootLogin no
```

This means:

- Remote password authentication is disabled.
- SSH authentication uses an ED25519 key pair.
- Direct SSH login as root is disabled.
- Administrative actions still require local sudo authentication.

## Network Access Control

SSH access is intended to use the private Tailscale interface.

```text
Home LAN
     |
     | TCP/22
     v
nftables
     |
     X
  BLOCKED
```

While remote administration follows:

```text
iPhone
     |
     | 5G
     v
Tailscale
     |
     v
tailscale0
     |
     | TCP/22
     v
OpenSSH
     |
     v
Arch Linux
```

No SSH port forwarding was configured on the home router.

## Validation

### Nmap

The normal LAN interface was tested with Nmap.

Result:

```text
22/tcp filtered ssh
```

This demonstrated that the SSH daemon could still be running locally while network filtering prevented TCP/22 access through the normal LAN path.

### OpenSSH Logs

Authentication logs confirmed successful public-key authentication:

```text
Accepted publickey for alex
```

The connection used an ED25519 SSH key rather than password authentication.

### Tailscale

Remote connectivity was tested from an iPhone using cellular data rather than the home Wi-Fi network.

The test path was:

```text
iPhone / 5G
     |
     v
Tailscale
     |
     v
Arch Linux
```

A new SSH session successfully connected through the laptop's Tailscale address.

### Wireshark

Traffic was captured on the `tailscale0` interface.

The TCP connection showed the standard three-way handshake:

```text
Client                         Server

SYN ------------------------->

    <---------------- SYN/ACK

ACK ------------------------->
```

After TCP establishment, Wireshark showed SSH protocol negotiation followed by encrypted application traffic.

The capture demonstrated an important distinction:

```text
Network visibility:
- Source and destination IP
- TCP ports
- Connection state
- Packet size
- Timing
- SSH negotiation

Encrypted SSH content:
- Shell commands
- Passwords
- Terminal output content
```
			
## Security Lessons

### 1. Listening does not always mean reachable

A service may be listening on a local TCP port while a firewall prevents access from a specific network path.

### 2. Public-key authentication reduces password exposure

ED25519 public-key authentication allows SSH password authentication to be disabled.

### 3. Network segmentation reduces attack surface

SSH access was restricted to the private Tailscale path instead of being intentionally exposed through the normal LAN or router port forwarding.

### 4. Network and endpoint telemetry provide different context

Wireshark showed the network connection and TCP behavior.

OpenSSH logs showed additional endpoint context such as:

- User
- Authentication method
- Remote address
- Successful public-key authentication

Combining network and endpoint telemetry provides a much clearer security picture.

## What I Learned

This lab helped me understand how several security controls work together rather than independently:

```text
Identity
   |
   v
ED25519 authentication
   |
   v
Private connectivity
   |
   v
Tailscale
   |
   v
Network enforcement
   |
   v
nftables
   |
   v
Service
   |
   v
OpenSSH
```

The most important lesson was that secure remote access is not created by one tool. It comes from combining authentication, network controls, encryption, logging, and validation.
