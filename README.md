
# Instructions: snmp-agent-app

# Overview

The `snmp-agent-app` includes:

- A CLI version to run the program to create an SNMP agent through command lines.

---

# Prerequisite

- [Linux prerequisite](./instructions/README_LINUX.md)

---

# Installation

To run the application, create a folder in which the `snmp-agent-app`  will be installed, then run the following command using the terminal.

```bash
git clone https://github.com/yacth/snmp-agent-app.git
```

## CLI application

!!**WORKS ONLY ON LINUX FOR NOW**!!

To run the CLI application, follow the instructions:

1. Open the terminal  into the `path/to/snmp-agent-app` folder.
2. Run the command `xmake` to build the project.
3. Run the command `xmake run` to run the agent.

Open another terminal:

1. To get the `UINT32` data run the following command `snmpget -v3 -l noAuthNoPriv -u unsecureUser 127.0.0.1:4700 1.3.6.1.4.1.57.6.1.2.1.0`
2. To get the `FLOAT32` data run the following command `snmpget -v3 -l noAuthNoPriv -u unsecureUser 127.0.0.1:4700 1.3.6.1.4.1.57.6.1.2.2.0`
3. To get the array of `FLOAT32` data run the following command `snmpget -v3 -l noAuthNoPriv -u unsecureUser 127.0.0.1:4700 1.3.6.1.4.1.57.6.1.2.3.0`

Note that the ENDIANESS is inverted, for example if we have the following HEX string : `66 E6 F6 42`, depending on the system the ENDIANESS might need to be inverted to `42 F6 E6 66`. 
We can retreive `123.45` with `42 F6 E6 66` on the following website https://gregstoll.com/~gregstoll/floattohex/

