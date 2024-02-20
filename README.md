# Table of contents

1. Introduction
2. Compilation
3. Installation
4. Usage
5. Config
6. External API

---

## 1\. Introduction

`synce4l` is a software implementation of Synchronous Ethernet (SyncE) according
to ITU-T Recommendation G.8264. The design goal is to provide logic to supported
hardware by processing Ethernet Synchronization Messaging Channel (ESMC) and
control Ethernet Equipment Clock (EEC) on Network Card Interface (NIC).

Application can operate in two mutually exclusive input modes: line or external.
Both modes are described in next paragraphs.

The best source selection is done according to ITU-T Recommendations G.781 and
G.8264. Two network options are supported: option 1 and option 2.

Table showing priority of quality levels (QLs) in option 1 networks:
| Quality Level | Priority* | SSM | Extended SSM** |
| ------------- | --------- | --- | -------------- |
| ePRTC         | 0         | 0x2 | 0x21           |
| PRTC          | 1         | 0x2 | 0x20           |
| PRC           | 2         | 0x2 | 0xFF           |
| SSU-A         | 3         | 0x4 | 0xFF           |
| SSU-B         | 4         | 0x8 | 0xFF           |
| EEC1          | 5         | 0xB | 0xFF           |

Table showing priority of quality levels (QLs) in option 2 networks:
| Quality Level | Priority* | SSM | Extended SSM** |
| ------------- | --------- | --- | -------------- |
| ePRTC         | 0         | 0x1 | 0x21           |
| PRTC          | 1         | 0x1 | 0x20           |
| PRS           | 2         | 0x1 | 0xFF           |
| STU           | 3         | 0x0 | 0xFF           |
| ST2           | 4         | 0x7 | 0xFF           |
| TNC           | 5         | 0x4 | 0xFF           |
| ST3E          | 6         | 0xD | 0xFF           |
| EEC2          | 7         | 0xA | 0xFF           |
| PROV          | 8         | 0xE | 0xFF           |

> *Remark:* *Lower number means higher priority

> *Remark:* **If extended SSM is not enabled, it's implicitly assumed as `0xFF`



Incoming SyncE frames are processed and best clock source is
extracted from the link having the best quality level.
`synce4l` configures such "best quality" port as a source to recover clock
for EEC. The recovered QL is broadcasted to all other interfaces then.
`synce4l` can use external 1PPS source attached (GPS or other generator).
which will participate in best source selection algorithm for EEC.

---

## 2\. Compilation

With introduction of support for Linux dpll subsystem it is required to
have linbl3-devel package (or equivalent) installed during compilation.

Makefile rules are included in `Makefile` and compilation is done using
the command:
```
make synce4l
```

---

## 3\. Installation

Use `make install` target to install `synce4l` in a system.

---

## 4\. Usage

Use `-h` command line argument to print the help page:
```
$? ./synce4l -h
usage: synce4l [options]

 ...

 Other Options

 -f [file] read configuration from 'file'
           (config file takes precedence over command line arguments)
 -l [num]  set the logging level to 'num'
           (0: least detailed, 7: most detailed)
 -m        print messages to stdout
 -q        do not print messages to the syslog
 -v        print synce4l version and exit
 -h        print this message and exit
```

> *Remark:* `synce4l` requires root privileges since it opens raw sockets.

---

## 5\. Config

### Configuration file contains three sections:

- global,
- device,
- port.

### Global section

This section starts with `[global]` keyword, consist of configuration items
related to a running synce4l instance.

| Parameter            | Default               | Valid values | Description                                                     |
| -------------------- | --------------------- | ------------ | --------------------------------------------------------------- |
| `logging_level`      | `6`                   | `0-7`        | Minimum log level required to appear in a log.                  |
| `message_tag`        | None                  | string       | Tag reported in a log.                                          |
| `poll_interval_msec` | 20                    | 0-500        | Sleep time between subsequent SyncE clock polls                 |
| `smc_socket_path`    | `/tmp/synce4l_socket` | string       | Full path to socket file for external application communication |
| `use_syslog`         | `1`                   | `0`, `1`     | Set to 1 if `syslog` should be used.                            |
| `verbose`            | `0`                   | `0`, `1`     | Set to 1 to log extra information.                              |

### Device section

This section specifies the configuration of a one logical device e.g. 'synce1'.
The name is defined by the user. The name has no impact for any functionality
except traces.
The name must be enclosed in extra angle bracket when defining new device
section e.g. [<synce1>].
All ports defined by port sections after the device section will create one
SyncE device (until next device section).

| Parameter               | Default | Valid values       | Description                                                                                                                                                     |
| ----------------------- | ------- | ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `extended_tlv`          | `0`     | `0`, `1`           | Set to 1 to enable extended QL.                                                                                                                                 |
| `network_option`        | `1`     | `1`, `2`           | Network option according to T-REC-G.8264. All devices in SyncE domain should have the same option configured.                                                   |
| `recover_time`          | `60`    | `10-720`           | Seconds indicating the minimum time to recover from the QL-failed state on the port.                                                                            |
| `get_eec_state_cmd`     | None    | string             | Shell command which will be executed by synce4l to acquire current state of a SyncE EEC on the device. The command shall output current state of EEC to stdout. |
| `eec_holdover_value`    | None    | string             | Value expected on stdout stream when EEC is in HOLDOVER state, after calling command defined in get_eec_state_cmd                                               |
| `eec_locked_ho_value`   | None    | string             | Value expected on stdout stream when EEC is in LOCKED HOLDOVER state, after calling command defined in get_eec_state_cmd                                        |
| `eec_locked_value`      | None    | string             | Value expected on stdout stream when EEC is in LOCKED state, after calling command defined in get_eec_state_cmd                                                 |
| `eec_freerun_value`     | None    | string             | Value expected on stdout stream when EEC is in FREERUN state, after calling command defined in get_eec_state_cmd                                                |
| `eec_invalid_value`     | None    | string             | Value expected on stdout stream when EEC is in INVALID state, after calling command defined in get_eec_state_cmd                                                |
| `clock_id`              | None    | `0-MAX(u64)`       | Required when Linux dpll subsystem shall be used to control EEC, it refers to clock_id value of EEC type dpll in the system                                     |
| `module_name`           | None    | string             | Required when Linux dpll subsystem shall be used to control EEC, it refers to name of kernel module that registered the dpll device in the system               |
| `dnu_prio`              | 0xf     | `0-0xffff`         | Required for Autmatic mode dpll device when Linux dpll subsystem is used. Value of priority which shall be set for input pins, when the source is marked as DNU |

### Port section

Any other section not starting with `<` (e.g. [eth0]) is the port section.
Multiple port sections are allowed. Each port participates in SyncE
communication.

| Parameter                   | Default | Valid values | Description                                                                                                                                                                       |
| --------------------------- | ------- | ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tx_heartbeat_msec`         | `1000`  | `100-3000`   | Interval between consecutive SyncE frame transmissions (1000ms is recommended).                                                                                                   |
| `rx_heartbeat_msec`         | `50`    | `10-500`     | Interval between consecutive SyncE socket polls (frame receive).                                                                                                                  |
| `recover_clock_enable_cmd`  | None    | string       | Shell command which enables PHY port pointed by this Port section as a source of frequency for the SyncE EEC on this device (required only in "internal_input" mode).             |
| `recover_clock_disable_cmd` | None    | string       | Shell command which disables PHY port pointed by this Port section as a source of frequency for the SyncE EEC on this device (required only in "internal_input" mode).            |
| `allowed_qls`               | None    | string       | List of hex values containing allowed SSM QLs separated by comma (`,`), other received ones would be discarded - if parameter is not provided, all QLs will be accepted.          |
| `allowed_ext_qls`           | None    | string       | List of hex values containing allowed extended SSM QLs separated by comma (`,`), other received ones would be discarded - if parameter is not provided, all QLs will be accepted. |

> *Remark:* Please do not use backslashes in config file in 'string' fields - for example do not use it like this: `"/sys/kernel/debug/ice/0000\:5e\:00\.0/cgu_state"`

### External source section

Any other section not starting with `{` (e.g. {SMA1}) is the external source section.
Multiple external source sections are allowed. Each external source participates in
best source selection algorithm for EEC

| Parameter                   | Default | Valid values       | Description                                                                                                                                           |
| --------------------------- | ------- | ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `input_QL`                  | `0`     | `0-15`, `0x0-0xF`  | Quality Level (QL) for "external input" mode.                                                                                                         |
| `input_ext_QL`              | `0`     | `0-255`,`0x0-0xFF` | Extended Quality Level for "external input" mode.                                                                                                     |
| `external_enable_cmd`       | None    | string             | Shell command which enables external clock source pointed by this external source section as a source of frequency for the SyncE EEC on this device.  |
| `external_disable_cmd`      | None    | string             | Shell command which disables external clock source pointed by this external source section as a source of frequency for the SyncE EEC on this device. |
| `board_label`               | None    | string             | Used for Linux dpll subsystem based configuration. A label of a pin associated with the external EEC input in Linux dpll subsytem.                    |
| `panel_label`               | None    | string             | Used for Linux dpll subsystem based configuration. A label of a pin associated with the external EEC input in Linux dpll subsytem.                    |
| `package_label`             | None    | string             | Used for Linux dpll subsystem based configuration. A label of a pin associated with the external EEC input in Linux dpll subsytem.                    |

> *Remark:* When dpll subsystem is used, a value of `board_label`, `panel_label` or `package_label` shall be provided, depending on a type of label that given input has registered in Linux dpll subsystem.

### Config example

Command based config
```
[global]
logging_level              7
use_syslog                 0
verbose                    1
message_tag                [synce4l]
smc_socket_path            /tmp/synce4l_socket

[<synce1>]
network_option             1
extended_tlv               1
recover_time               20
eec_get_state_cmd          cat /sys/class/net/eth0/device/dpll_0_state
eec_holdover_value         4
eec_locked_ho_value        3
eec_locked_value           2
eec_freerun_value          1
eec_invalid_value          0

[eth0]
tx_heartbeat_msec          1000
rx_heartbeat_msec          500
recover_clock_enable_cmd   echo 1 0 > /sys/class/net/eth0/device/phy/synce
recover_clock_disable_cmd  echo 0 0 > /sys/class/net/eth0/device/phy/synce
allowed_qls                0x2,0x4,0x8
allowed_ext_qls            0x20,0x21

[{SMA1}]
external_enable_cmd        echo 2 1 > /sys/class/net/enp1s0f0/device/ptp/ptp*/pins/SMA1
external_disable_cmd       echo 0 1 > /sys/class/net/enp1s0f0/device/ptp/ptp*/pins/SMA1
input_QL                   0x2
input_ext_QL               0x20

```


Linux dpll based config
```
[global]
logging_level              7
use_syslog                 0
verbose                    1
message_tag                [synce4l]
smc_socket_path            /tmp/synce4l_socket

[<synce1>]
network_option             1
extended_tlv               1
recover_time               20
clock_id                   0xaabbccffffccbbaa
module_name                ice

[eth0]
tx_heartbeat_msec          1000
rx_heartbeat_msec          500
allowed_qls                0x2,0x4,0x8
allowed_ext_qls            0x20,0x21

[{SMA1}]
board_label                SMA1
input_QL                   0x2
input_ext_QL               0x20

```

---

## 6\. External API

The Synce4l API facilitates communication with the Synce4l running application using an AF_UNIX socket.
Messages are exchanged as a list of TLV messages (Type-Length-Value) over the socket.
The TLV structure is defined in `synce_external_api.h` as the following:

## TLV Structure

### Enum: synce_manager_type

Defines different message types for the Synce Manager.

- `MSG_DEV_NAME`   (1): Device name.
- `MSG_SRC_NAME`   (2): External clock source name.
- `MSG_ERR_MSG`    (3): Error messgae returned from synce4l.
- `MSG_GET_QL`     (4): Get QL of devide.
- `MSG_GET_EXT_QL` (5): Get extended QL of device.
- `MSG_SET_QL`     (6): Set QL of external clock source.
- `MSG_SET_EXT_QL` (7): Set extended QL of external clock source.
- `MSG_END_MARKER` (8): End marker.

### Struct: synce_manager_tlv

Represents a TLV (Type-Length-Value) message.

- `type` (uint16_t): Enum value from `synce_manager_type`.
- `length` (uint16_t): Length of the value field in bytes.
- `value` (void*): Data of the given length.

## Communication

Communication is achieved by packing the `synce_manager_tlv` structure and sending it as a byte stream to the AF_UNIX socket.
Last TLV of any stream shall use the type `MSG_END_MARKER`.
Returned byte stream from synce4l will use same TLV format, and will end by TLV with `MSG_END_MARKER` type.

### Command and response example

Below is command example for getting the QL of device `synce1`.
Command is constructed from 3 TLVs:
1. Type `MSG_DEV_NAME` with length `6` and value `synce1`
2. Type `MSG_GET_QL` with length `0` and null value
3. Type `MSG_END_MARKER` with length `0` and null value

| TYPE  | LEN   | VALUE             || TYPE  | LEN   || TYPE  | LEN   |
|---------------------------------------------------------------------|
| DEV   | 6     | s  y  n  c  e  1  || GET   | 0     || END   | 0     |
| 01 00 | 06 00 | 73 79 6E 63 65 31 || 04 00 | 00 00 || 08 00 | 00 00 |

Example response from synce4l. Device `synce1` has QL = 2
Response is constructed from 3 TLVs:
1. Type `MSG_DEV_NAME` with length `6` and value `synce1`
2. Type `MSG_GET_QL` with length `1` and value `2`
3. Type `MSG_END_MARKER` with length `0` and null value

| TYPE  | LEN   | VALUE             || TYPE  | LEN   | VALUE || TYPE  | LEN   |
|-----------------------------------------------------------------------------|
| DEV   | 6     | s  y  n  c  e  1  || GET   | 1     | 2     || END   | 0     |
| 01 00 | 06 00 | 73 79 6E 63 65 31 || 04 00 | 01 00 | 02    || 08 00 | 00    |

---
