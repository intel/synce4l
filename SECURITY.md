# Security Policy
Intel is committed to rapidly addressing security vulnerabilities affecting our
customers and providing clear guidance on the solution, impact, severity and
mitigation.

## Reporting a Vulnerability
Please report any security vulnerabilities in this project
[utilizing the guidelines here](https://www.intel.com/content/www/us/en/security-center/vulnerability-handling-guidelines.html).

# Threat model
An introduction to the security caveats that shall be known by the application
users.

## Required access level
synce4l application must be run by the privileged user due to following reasons:
- the synce4l service requires access to the Layer 2 sockets,
- hardware configuration capabilities are used by the synce4l service.

By default synce4l binary is installed (make install) to the Linux sbin
directory (usr/local/sbin/).

## Malicious neighbor
synce4l implements Synchronous Ethernet protocol as specified by ITU-T
Recommendation G.8264. Part of protocol describes the processing of Ethernet
Synchronization Messaging Channel (ESMC) Layer 2 network frames, as well as
acting on them, in the way where the Network Interface Card PHY's clock is
fed with best quality clock signal chosen from all the signal clocks available
on the NIC.
If a host is configured to use a network recovered clock signals - basically if
any network interfaces are specified in config file - then, a peer neighbor
connected with one of such network interfaces can potentially send a malicious
ESMC frame, which can impact the SyncE source selection algorithm and start
procedure of changing the source of the PHY's clock signal.

In general this will never cause a full denial of network service, but SyncE was
designed as an aid to the time-sensitive services, thus such malicious neighbor
attack might have an impact on those services.

A possible prevention of such behavior is to allow only DNU QL on a port which
is not expected to be a valid clock signal source. If the neighbor port is
supposed to be a part of selection algorithm, the user shall also secure a
neighbor host in the way that malicious ESMC frames are not ever possible.

## Configuration file
NOTE: The safe place for storing configuration file is critical from security
perspective.
Configuration files shall be kept in the safe place (i.e., /etc/synce.conf),
this way any regular user is not able to modify or symlink the original
configuration file with a malicious configuration file.

### Configuration for usage based on Linux System Commands
In Linux System Command use case the user provides set of Linux System Commands
which are executed in order to interact with the SyncE capable hardware. If the
regular user could alter the configuration file it would be possible to execute
malicious commands with privileged user access rights.

### Configuration for usage based on Linux DPLL Subsystem
In general, this mode is safe from the security perspective. The interaction
with the Linux DPLL subsystem also requires privileged access rights.
But the need for safe storage of the synce4l configuration file persist, it is
still possible that malicious configuration file would try to use `Linux System
Command` approach instead, with attacker's provided system commands.

## synce4l External API
With the release of 1.0.1 it is possible to alter a running instance of synce4l.
The API allows:
- get current QL (and extended QL) of device controlled by synce4l,
- set QL (and extended QL) of an external source.

The API is accessible through the AF_UNIX socket, which is using temporary
file. Each separated instance of synce4l shall have own file specified a
[global] config item `smc_socket_path` (within a configuration file), as the
file is created and cleaned during synce4l lifetime.

While the file exist, an external application can communicate with the synce4l
instance and submit API allowed commands. The commands may have impact on the
current state of hardware configuration, thus external application must also be
run by the privileged user.
