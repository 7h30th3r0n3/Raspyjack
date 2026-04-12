# -*- coding: utf-8 -*-
# http://web.archive.org/web/20140718071917/http://multivax.com/last_question.html

"""
Get the MAC address of remote hosts or network interfaces.

It provides a platform-independent interface to get the MAC addresses of:

- System network interfaces (by interface name)
- Remote hosts on the local network (by IPv4/IPv6 address or hostname)

It provides one function: ``get_mac_address()``

.. code-block:: python
   :caption: Examples

    from getmac import get_mac_address
    eth_mac = get_mac_address(interface="eth0")
    win_mac = get_mac_address(interface="Ethernet 3")
    ip_mac = get_mac_address(ip="192.168.0.1")
    ip6_mac = get_mac_address(ip6="::1")
    host_mac = get_mac_address(hostname="localhost")
    updated_mac = get_mac_address(ip="10.0.0.1", network_request=True)

"""
import ctypes
import logging
import os
import platform
import re
import shlex
import socket
import struct
import sys
import traceback
import warnings
from subprocess import CalledProcessError, check_output

try:  # Python 3
    from subprocess import DEVNULL  # type: ignore
except ImportError:  # Python 2
    DEVNULL = open(os.devnull, "wb")  # type: ignore

# Used for mypy (a data type analysis tool)
# If you're copying the code, this section can be safely removed
try:
    from typing import TYPE_CHECKING

    if TYPE_CHECKING:
        from typing import Dict, List, Optional, Set, Tuple, Type, Union
except ImportError:
    pass

# Configure logging
log = logging.getLogger("getmac")  # type: logging.Logger
if not log.handlers:
    log.addHandler(logging.NullHandler())

__version__ = "0.9.5"

PY2 = sys.version_info[0] == 2  # type: bool

# Configurable settings
DEBUG = 0  # type: int
PORT = 55555  # type: int

# Monkeypatch shutil.which for python 2.7 (TODO(python3): remove shutilwhich.py)
if PY2:
    from .shutilwhich import which
else:
    from shutil import which

# Platform identifiers
if PY2:
    _UNAME = platform.uname()  # type: Tuple[str, str, str, str, str, str]
    _SYST = _UNAME[0]  # type: str
else:
    _UNAME = platform.uname()  # type: platform.uname_result
    _SYST = _UNAME.system  # type: str
if _SYST == "Java":
    try:
        import java.lang

        _SYST = str(java.lang.System.getProperty("os.name"))
    except ImportError:
        _java_err_msg = "Can't determine OS: couldn't import java.lang on Jython"
        log.critical(_java_err_msg)
        warnings.warn(_java_err_msg, RuntimeWarning)

WINDOWS = _SYST == "Windows"  # type: bool
DARWIN = _SYST == "Darwin"  # type: bool

OPENBSD = _SYST == "OpenBSD"  # type: bool
FREEBSD = _SYST == "FreeBSD"  # type: bool
NETBSD = _SYST == "NetBSD"  # type: bool
SOLARIS = _SYST == "SunOS"  # type: bool

# Not including Darwin or Solaris as a "BSD"
BSD = OPENBSD or FREEBSD or NETBSD  # type: bool

# Windows Subsystem for Linux (WSL)
WSL = False  # type: bool
LINUX = False  # type: bool
if _SYST == "Linux":
    if "Microsoft" in platform.version():
        WSL = True
    else:
        LINUX = True

# NOTE: "Linux" methods apply to Android without modifications
# If there's Android-specific stuff then we can add a platform
# identifier for it.
ANDROID = (
    hasattr(sys, "getandroidapilevel") or "ANDROID_STORAGE" in os.environ
)  # type: bool

# Generic platform identifier used for filtering methods
PLATFORM = _SYST.lower()  # type: str
if PLATFORM == "linux" and "Microsoft" in platform.version():
    PLATFORM = "wsl"

# User-configurable override to force a specific platform
# This will change to a function argument in 1.0.0
OVERRIDE_PLATFORM = ""  # type: str

# Force a specific method to be used for all lookups
# Used for debugging and testing
FORCE_METHOD = ""  # type: str

# Get and cache the configured system PATH on import
# The process environment does not change after a process is started
PATH = os.environ.get("PATH", os.defpath).split(os.pathsep)  # type: List[str]
if not WINDOWS:
    PATH.extend(("/sbin", "/usr/sbin"))
else:
    # TODO: Prevent edge case on Windows where our script "getmac.exe"
    #   gets added to the path ahead of the actual Windows getmac.exe
    #   This just handles case where it's in a virtualenv, won't work /w global scripts
    PATH = [p for p in PATH if "\\getmac\\Scripts" not in p]
# Build the str after modifications are made
PATH_STR = os.pathsep.join(PATH)  # type: str

# Use a copy of the environment so we don't
# modify the process's current environment.
ENV = dict(os.environ)  # type: Dict[str, str]
ENV["LC_ALL"] = "C"  # Ensure ASCII output so we parse correctly

# Constants
IP4 = 0
IP6 = 1
INTERFACE = 2
HOSTNAME = 3

MAC_RE_COLON = r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"
MAC_RE_DASH = r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})"
# On OSX, some MACs in arp output may have a single digit instead of two
# Examples: "18:4f:32:5a:64:5", "14:cc:20:1a:99:0"
# This can also happen on other platforms, like Solaris
MAC_RE_SHORT = r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})"

# Ensure we only log the Python 2 warning once
WARNED_UNSUPPORTED_PYTHONS = False

# Cache of commands that have been checked for existence by check_command()
CHECK_COMMAND_CACHE = {}  # type: Dict[str, bool]


def check_command(command):
    # type: (str) -> bool
    if command not in CHECK_COMMAND_CACHE:
        CHECK_COMMAND_CACHE[command] = bool(which(command, path=PATH_STR))
    return CHECK_COMMAND_CACHE[command]


def check_path(filepath):
    # type: (str) -> bool
    return os.path.exists(filepath) and os.access(filepath, os.R_OK)


def _clean_mac(mac):
    # type: (Optional[str]) -> Optional[str]
    """Check and format a string result to be lowercase colon-separated MAC."""
    if mac is None:
        return None

    # Handle cases where it's bytes (which are the same as str in PY2)
    mac = str(mac)
    if not PY2:  # Strip bytestring conversion artifacts
        # TODO(python3): check for bytes and decode instead of this weird hack
        for garbage_string in ["b'", "'", "\\n", "\\r"]:
            mac = mac.replace(garbage_string, "")

    # Remove trailing whitespace, make lowercase, remove spaces,
    # and replace dashes '-' with colons ':'.
    mac = mac.strip().lower().replace(" ", "").replace("-", ":")

    # Fix cases where there are no colons
    if ":" not in mac and len(mac) == 12:
        log.debug("Adding colons to MAC %s", mac)
        mac = ":".join(mac[i : i + 2] for i in range(0, len(mac), 2))

    # Pad single-character octets with a leading zero (e.g. Darwin's ARP output)
    elif len(mac) < 17:
        log.debug(
            "Length of MAC %s is %d, padding single-character octets with zeros",
            mac,
            len(mac),
        )
        parts = mac.split(":")
        new_mac = []
        for part in parts:
            if len(part) == 1:
                new_mac.append("0" + part)
            else:
                new_mac.append(part)
        mac = ":".join(new_mac)

    # MAC address should ALWAYS be 17 characters before being returned
    if len(mac) != 17:
        log.warning("MAC address %s is not 17 characters long!", mac)
        mac = None
    elif mac.count(":") != 5:
        log.warning("MAC address %s is missing colon (':') characters", mac)
        mac = None
    return mac


def _read_file(filepath):
    # type: (str) -> Optional[str]
    try:
        with open(filepath) as f:
            return f.read()
    # This is IOError on Python 2.7
    except (OSError, IOError):  # noqa: B014
        log.debug("Could not find file: '%s'", filepath)
        return None


def _search(regex, text, group_index=0, flags=0):
    # type: (str, str, int, int) -> Optional[str]
    if not text:
        if DEBUG:
            log.debug("No text to _search()")
        return None

    match = re.search(regex, text, flags)
    if match:
        return match.groups()[group_index]

    return None


def _popen(command, args):
    # type: (str, str) -> str
    for directory in PATH:
        executable = os.path.join(directory, command)
        if (
            os.path.exists(executable)
            and os.access(executable, os.F_OK | os.X_OK)
            and not os.path.isdir(executable)
        ):
            break
    else:
        executable = command

    if DEBUG >= 3:
        log.debug("Running: '%s %s'", executable, args)

    return _call_proc(executable, args)


def _call_proc(executable, args):
    # type: (str, str) -> str
    if WINDOWS:
        cmd = executable + " " + args  # type: ignore
    else:
        cmd = [executable] + shlex.split(args)  # type: ignore

    output = check_output(cmd, stderr=DEVNULL, env=ENV)

    if DEBUG >= 4:
        log.debug("Output from '%s' command: %s", executable, str(output))

    if not PY2 and isinstance(output, bytes):
        return str(output, "utf-8")
    else:
        return str(output)


def _uuid_convert(mac):
    # type: (int) -> str
    return ":".join(("%012X" % mac)[i : i + 2] for i in range(0, 12, 2))


def _fetch_ip_using_dns():
    # type: () -> str
    """
    Determines the IP address of the default network interface.

    Sends a UDP packet to Cloudflare's DNS (``1.1.1.1``), which should go through
    the default interface. This populates the source address of the socket,
    which we then inspect and return.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("1.1.1.1", 53))
    ip = s.getsockname()[0]
    s.close()  # NOTE: sockets don't have context manager in 2.7 :(
    return ip


class Method:
    #: Valid platform identifier strings
    VALID_PLATFORM_NAMES = {
        "android",
        "darwin",
        "linux",
        "windows",
        "wsl",
        "openbsd",
        "freebsd",
        "sunos",
        "other",
    }

    #: Platforms supported by a method
    platforms = set()  # type: Set[str]

    #: The type of method, e.g. does it get the MAC of a interface?
    #: Allowed values: {ip, ip4, ip6, iface, default_iface}
    method_type = ""  # type: str

    #: If the method makes a network request as part of the check
    network_request = False  # type: bool

    #: Marks the method as unable to be used, e.g. if there was a runtime
    #: error indicating the method won't work on the current platform.
    unusable = False  # type: bool

    def test(self):  # type: () -> bool  # noqa: T484
        """Low-impact test that the method is feasible, e.g. command exists."""
        pass  # pragma: no cover

    # TODO: automatically clean MAC on return
    def get(self, arg):  # type: (str) -> Optional[str]
        """
        Core logic of the method that performs the lookup.

        .. warning::
           If the method itself fails to function an exception will be raised!
           (for instance, if some command arguments are invalid, or there's an
           internal error with the command, or a bug in the code).

        Args:
            arg (str): What the method should get, such as an IP address
                or interface name. In the case of default_iface methods,
                this is not used and defaults to an empty string.

        Returns:
            Lowercase colon-separated MAC address, or None if one could
            not be found.
        """
        pass  # pragma: no cover

    @classmethod
    def __str__(cls):  # type: () -> str
        return cls.__name__


# TODO(python3): do we want to keep this around? It calls 3 commands and is
#   quite inefficient. We should just take the methods and use directly.
class UuidArpGetNode(Method):
    platforms = {"linux", "darwin", "sunos", "other"}
    method_type = "ip"

    def test(self):  # type: () -> bool
        try:
            from uuid import _arp_getnode  # type: ignore

            return True
        except Exception:
            return False

    def get(self, arg):  # type: (str) -> Optional[str]
        from uuid import _arp_getnode  # type: ignore

        backup = socket.gethostbyname
        try:
            socket.gethostbyname = lambda x: arg  # noqa: F841
            mac1 = _arp_getnode()
            if mac1 is not None:
                mac1 = _uuid_convert(mac1)
                mac2 = _arp_getnode()
                mac2 = _uuid_convert(mac2)
                if mac1 == mac2:
                    return mac1
        except Exception:
            raise
        finally:
            socket.gethostbyname = backup

        return None


class ArpFile(Method):
    platforms = {"linux"}
    method_type = "ip4"
    _path = os.environ.get("ARP_PATH", "/proc/net/arp")  # type: str

    def test(self):  # type: () -> bool
        return check_path(self._path)

    def get(self, arg):  # type: (str) -> Optional[str]
        if not arg:
            return None

        data = _read_file(self._path)

        if data is None:
            self.unusable = True
            return None

        if data is not None and len(data) > 1:
            # Need a space, otherwise a search for 192.168.16.2
            # will match 192.168.16.254 if it comes first!
            return _search(re.escape(arg) + r" .+" + MAC_RE_COLON, data)

        return None


class ArpFreebsd(Method):
    platforms = {"freebsd"}
    method_type = "ip"

    def test(self):  # type: () -> bool
        return check_command("arp")

    def get(self, arg):  # type: (str) -> Optional[str]
        regex = r"\(" + re.escape(arg) + r"\)\s+at\s+" + MAC_RE_COLON
        return _search(regex, _popen("arp", arg))


class ArpOpenbsd(Method):
    platforms = {"openbsd"}
    method_type = "ip"
    _regex = r"[ ]+" + MAC_RE_COLON  # type: str

    def test(self):  # type: () -> bool
        return check_command("arp")

    def get(self, arg):  # type: (str) -> Optional[str]
        return _search(re.escape(arg) + self._regex, _popen("arp", "-an"))


class ArpVariousArgs(Method):
    platforms = {"linux", "darwin", "freebsd", "sunos", "other"}
    method_type = "ip"
    _regex_std = r"\)\s+at\s+" + MAC_RE_COLON  # type: str
    _regex_darwin = r"\)\s+at\s+" + MAC_RE_SHORT  # type: str
    _args = (
        ("", True),  # "arp 192.168.1.1"
        # Linux
        ("-an", False),  # "arp -an"
        ("-an", True),  # "arp -an 192.168.1.1"
        # Darwin, WSL, Linux distros???
        ("-a", False),  # "arp -a"
        ("-a", True),  # "arp -a 192.168.1.1"
    )
    _args_tested = False  # type: bool
    _good_pair = ()  # type: Union[Tuple, Tuple[str, bool]]

    def test(self):  # type: () -> bool
        return check_command("arp")

    def get(self, arg):  # type: (str) -> Optional[str]
        if not arg:
            return None

        # Ensure output from testing command on first call isn't wasted
        command_output = ""

        # Test which arguments are valid to the command
        # This will NOT test which regex is valid
        if not self._args_tested:
            for pair_to_test in self._args:
                try:
                    cmd_args = [pair_to_test[0]]

                    # if True, then include IP as a command argument
                    if pair_to_test[1]:
                        cmd_args.append(arg)

                    command_output = _popen("arp", " ".join(cmd_args))
                    self._good_pair = pair_to_test
                    break
                except CalledProcessError as ex:
                    if DEBUG:
                        log.debug(
                            "ArpVariousArgs pair test failed for (%s, %s): %s",
                            pair_to_test[0],
                            pair_to_test[1],
                            str(ex),
                        )

            if not self._good_pair:
                self.unusable = True
                return None
            self._args_tested = True

        if not command_output:
            # if True, then include IP as a command argument
            cmd_args = [self._good_pair[0]]

            if self._good_pair[1]:
                cmd_args.append(arg)

            command_output = _popen("arp", " ".join(cmd_args))

        escaped = re.escape(arg)
        _good_regex = (
            self._regex_darwin if DARWIN or SOLARIS else self._regex_std
        )  # type: str
        return _search(r"\(" + escaped + _good_regex, command_output)


class ArpExe(Method):
    """
    Query the Windows ARP table using ``arp.exe`` to find the MAC address of a remote host.
    This only works for IPv4, since the ARP table is IPv4-only.

    Microsoft Documentation: `arp <https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/arp>`
    """  # noqa: E501

    platforms = {"windows", "wsl"}
    method_type = "ip4"

    def test(self):  # type: () -> bool
        # NOTE: specifying "arp.exe" instead of "arp" lets this work
        # seamlessly on WSL1 as well. On WSL2 it doesn't matter, since
        # it's basically just a Linux VM with some lipstick.
        return check_command("arp.exe")

    def get(self, arg):  # type: (str) -> Optional[str]
        return _search(MAC_RE_DASH, _popen("arp.exe", "-a %s" % arg))


class ArpingHost(Method):
    """
    Use ``arping`` command to determine the MAC of a host.

    Supports three variants of ``arping``

    - "habets" arping by Thomas Habets
        (`GitHub <https://github.com/ThomasHabets/arping>`__)
        On Debian-based distros, ``apt install arping`` will install
        Habets arping.
    - "iputils" arping, from the ``iputils-arping``
        `package <https://packages.debian.org/sid/iputils-arping>`__
    - "busybox" arping, included with BusyBox (a small executable "distro")
        (`further reading <https://boxmatrix.info/wiki/Property:arping>`__)

    BusyBox's arping quite similar to iputils-arping. The arguments for
    our purposes are the same, and the output is also the same.
    There's even a TODO in busybox's arping code referencing iputils arping.
    There are several differences:
    - The return code from bad arguments is 1, not 2 like for iputils-arping
    - The MAC address in output is lowercase (vs. uppercase in iputils-arping)

    This was a pain to obtain samples for busybox on Windows. I recommend
    using WSL and arping'ing the Docker gateway (for WSL2 distros).
    NOTE: it must be run as root using ``sudo busybox arping``.
    """

    platforms = {"linux", "darwin"}
    method_type = "ip4"
    network_request = True
    _is_iputils = True  # type: bool
    _habets_args = "-r -C 1 -c 1 %s"  # type: str
    _iputils_args = "-f -c 1 %s"  # type: str

    def test(self):  # type: () -> bool
        return check_command("arping")

    def get(self, arg):  # type: (str) -> Optional[str]
        # If busybox or iputils, this will just work, and if host ping fails,
        # then it'll exit with code 1 and this function will return None.
        #
        # If it's Habets, then it'll exit code 1 and have "invalid option"
        # and/or the help message in the output.
        # In the case of Habets, set self._is_iputils to False,
        # then re-try with Habets args.
        try:
            if self._is_iputils:
                command_output = _popen("arping", self._iputils_args % arg)
                if command_output:
                    return _search(
                        r" from %s \[(%s)\]" % (re.escape(arg), MAC_RE_COLON),
                        command_output,
                    )
            else:
                return self._call_habets(arg)
        except CalledProcessError as ex:
            if ex.output and self._is_iputils:
                if not PY2 and isinstance(ex.output, bytes):
                    output = str(ex.output, "utf-8").lower()
                else:
                    output = str(ex.output).lower()

                if "habets" in output or "invalid option" in output:
                    if DEBUG:
                        log.debug("Falling back to Habets arping")
                    self._is_iputils = False
                    try:
                        return self._call_habets(arg)
                    except CalledProcessError:
                        pass

        return None

    def _call_habets(self, arg):  # type: (str) -> Optional[str]
        command_output = _popen("arping", self._habets_args % arg)
        if command_output:
            return command_output.strip()
        else:
            return None


class CtypesHost(Method):
    """
    Uses ``SendARP`` from the Windows ``Iphlpapi`` to get the MAC address
    of a remote IPv4 host.

    Microsoft Documentation: `SendARP function (iphlpapi.h) <https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-sendarp>`__
    """  # noqa: E501

    platforms = {"windows"}
    method_type = "ip4"
    network_request = True

    def test(self):  # type: () -> bool
        try:
            return ctypes.windll.wsock32.inet_addr(b"127.0.0.1") > 0  # noqa: T484
        except Exception:
            return False

    def get(self, arg):  # type: (str) -> Optional[str]
        if not PY2:  # Convert to bytes on Python 3+ (Fixes GitHub issue #7)
            arg = arg.encode()  # type: ignore

        try:
            inetaddr = ctypes.windll.wsock32.inet_addr(arg)  # type: ignore
            if inetaddr in (0, -1):
                raise Exception
        except Exception:
            # TODO: this assumes failure is due to arg being a hostname
            #   We should be explicit about only accepting ipv4 addresses
            #   and handle any hostname resolution in calling code
            hostip = socket.gethostbyname(arg)
            inetaddr = ctypes.windll.wsock32.inet_addr(hostip)  # type: ignore

        buffer = ctypes.c_buffer(6)
        addlen = ctypes.c_ulong(ctypes.sizeof(buffer))

        # https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-sendarp
        send_arp = ctypes.windll.Iphlpapi.SendARP  # type: ignore
        if send_arp(inetaddr, 0, ctypes.byref(buffer), ctypes.byref(addlen)) != 0:
            return None

        # Convert binary data into a string.
        macaddr = ""
        for intval in struct.unpack("BBBBBB", buffer):  # type: ignore
            if intval > 15:
                replacestr = "0x"
            else:
                replacestr = "x"
            macaddr = "".join([macaddr, hex(intval).replace(replacestr, "")])

        return macaddr


class IpNeighborShow(Method):
    platforms = {"linux", "other"}
    method_type = "ip"  # IPv6 and IPv4

    def test(self):  # type: () -> bool
        return check_command("ip")

    def get(self, arg):  # type: (str) -> Optional[str]
        output = _popen("ip", "neighbor show %s" % arg)
        if not output:
            return None

        try:
            # NOTE: the space prevents accidental matching of partial IPs
            return (
                output.partition(arg + " ")[2].partition("lladdr")[2].strip().split()[0]
            )
        except IndexError as ex:
            log.debug("IpNeighborShow failed with exception: %s", str(ex))
            return None


class SysIfaceFile(Method):
    platforms = {"linux", "wsl"}
    method_type = "iface"
    _path = "/sys/class/net/"  # type: str

    def test(self):  # type: () -> bool
        # Imperfect, but should work well enough
        return check_path(self._path)

    def get(self, arg):  # type: (str) -> Optional[str]
        data = _read_file(self._path + arg + "/address")

        # NOTE: if "/sys/class/net/" exists, but interface file doesn't,
        # then that means the interface doesn't exist
        # Sometimes this can be empty or a single newline character
        return None if data is not None and len(data) < 17 else data


class UuidLanscan(Method):
    platforms = {"other"}
    method_type = "iface"

    def test(self):  # type: () -> bool
        try:
            from uuid import _find_mac  # noqa: T484

            return check_command("lanscan")
        except Exception:
            return False

    def get(self, arg):  # type: (str) -> Optional[str]
        from uuid import _find_mac  # type: ignore

        if not PY2:
            arg = bytes(arg, "utf-8")  # type: ignore

        mac = _find_mac("lanscan", "-ai", [arg], lambda i: 0)

        if mac:
            return _uuid_convert(mac)

        return None


class FcntlIface(Method):
    platforms = {"linux", "wsl"}
    method_type = "iface"

    def test(self):  # type: () -> bool
        try:
            import fcntl

            return True
        except Exception:  # Broad except to handle unknown effects
            return False

    def get(self, arg):  # type: (str) -> Optional[str]
        import fcntl

        if not PY2:
            arg = arg.encode()  # type: ignore

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # 0x8927 = SIOCGIFADDR
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack("256s", arg[:15]))

        if PY2:
            return ":".join(["%02x" % ord(char) for char in info[18:24]])
        else:
            return ":".join(["%02x" % ord(chr(char)) for char in info[18:24]])


class GetmacExe(Method):
    """
    Uses Windows-builtin ``getmac.exe`` to get a interface's MAC address.

    Microsoft Documentation: `getmac <https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/getmac>`__
    """  # noqa: E501

    platforms = {"windows"}
    method_type = "iface"
    _regexes = [
        # Connection Name
        (r"\r\n", r".*" + MAC_RE_DASH + r".*\r\n"),
        # Network Adapter (the human-readable name)
        (r"\r\n.*", r".*" + MAC_RE_DASH + r".*\r\n"),
    ]  # type: List[Tuple[str, str]]
    _champ = ()  # type: Union[tuple, Tuple[str, str]]

    def test(self):  # type: () -> bool
        # NOTE: the scripts from this library (getmac) are excluded from the
        # path used for checking variables, in getmac.getmac.PATH (defined
        # at the top of this file). Otherwise, this would get messy quickly :)
        return check_command("getmac.exe")

    def get(self, arg):  # type: (str) -> Optional[str]
        try:
            # /nh: Suppresses table headers
            # /v:  Verbose
            command_output = _popen("getmac.exe", "/NH /V")
        except CalledProcessError as ex:
            # This shouldn't cause an exception if it's valid command
            log.error("getmac.exe failed, marking unusable. Exception: %s", str(ex))
            self.unusable = True
            return None

        if self._champ:
            return _search(self._champ[0] + arg + self._champ[1], command_output)

        for pair in self._regexes:
            result = _search(pair[0] + arg + pair[1], command_output)
            if result:
                self._champ = pair
                return result

        return None


class IpconfigExe(Method):
    """
    Uses ``ipconfig.exe`` to find interface MAC addresses on Windows.

    This is generally pretty reliable and works across a wide array of
    versions and releases. I'm not sure if it works pre-XP though.

    Microsoft Documentation: `ipconfig <https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ipconfig>`__
    """  # noqa: E501

    platforms = {"windows"}
    method_type = "iface"
    _regex = (
        r"(?:\n?[^\n]*){1,8}Physical Address[ .:]+" + MAC_RE_DASH + r"\r\n"
    )  # type: str

    def test(self):  # type: () -> bool
        return check_command("ipconfig.exe")

    def get(self, arg):  # type: (str) -> Optional[str]
        return _search(arg + self._regex, _popen("ipconfig.exe", "/all"))


class WmicExe(Method):
    """
    Use ``wmic.exe`` on Windows to find the MAC address of a network interface.

    Microsoft Documentation: `wmic <https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wmic>`__

    .. warning::
       WMIC is deprecated as of Windows 10 21H1. This method may not work on
       Windows 11 and may stop working at some point on Windows 10 (unlikely,
       but possible).
    """  # noqa: E501

    platforms = {"windows"}
    method_type = "iface"

    def test(self):  # type: () -> bool
        return check_command("wmic.exe")

    def get(self, arg):  # type: (str) -> Optional[str]
        command_output = _popen(
            "wmic.exe",
            'nic where "NetConnectionID = \'%s\'" get "MACAddress" /value' % arg,
        )

        # Negative: "No Instance(s) Available"
        # Positive: "MACAddress=00:FF:E7:78:95:A0"
        # NOTE: .partition() always returns 3 parts,
        # therefore it won't cause an IndexError
        return command_output.strip().partition("=")[2]


class DarwinNetworksetupIface(Method):
    """
    Use ``networksetup`` on MacOS (Darwin) to get the MAC address of a specific interface.

    I think that this is or was a BSD utility, but I haven't seen it on other BSDs
    (FreeBSD, OpenBSD, etc.). So, I'm treating it as a Darwin-specific utility
    until further notice. If you know otherwise, please open a PR :)

    If the command is present, it should always work, though naturally that is contingent
    upon the whims of Apple in newer MacOS releases.

    Man page: `networksetup (8) <https://www.manpagez.com/man/8/networksetup/>`__
    """

    platforms = {"darwin"}
    method_type = "iface"

    def test(self):  # type: () -> bool
        return check_command("networksetup")

    def get(self, arg):  # type: (str) -> Optional[str]
        command_output = _popen("networksetup", "-getmacaddress %s" % arg)
        return _search(MAC_RE_COLON, command_output)


# This only took 15-20 hours of throwing my brain against a wall multiple times
# over the span of 1-2 years to figure out. It works for almost all conceivable
# output from "ifconfig", and probably netstat too. It can probably be made more
# efficient by someone who actually knows how to write regex.
# [: ]\s?(?:flags=|\s).*?(?:(?:\w+[: ]\s?flags=)|\s(?:ether|address|HWaddr|hwaddr|lladdr)[ :]?\s?([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}))  # noqa: E501
IFCONFIG_REGEX = (
    r"[: ]\s?(?:flags=|\s).*?(?:"
    r"(?:\w+[: ]\s?flags=)|"  # Prevent interfaces w/o a MAC from matching
    r"\s(?:ether|address|HWaddr|hwaddr|lladdr)[ :]?\s?"  # Handle various prefixes
    r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}))"  # Match the MAC
)


def _parse_ifconfig(iface, command_output):
    # type: (str, str) -> Optional[str]
    if not iface or not command_output:
        return None

    # Sanity check on input e.g. if user does "eth0:" as argument
    iface = iface.strip(":")

    # "(?:^|\s)": prevent an input of "h0" from matching on "eth0"
    search_re = r"(?:^|\s)" + iface + IFCONFIG_REGEX

    return _search(search_re, command_output, flags=re.DOTALL)


class IfconfigWithIfaceArg(Method):
    """
    ``ifconfig`` command with the interface name as an argument
    (e.g. ``ifconfig eth0``).
    """

    platforms = {"linux", "wsl", "freebsd", "openbsd", "other"}
    method_type = "iface"

    def test(self):  # type: () -> bool
        return check_command("ifconfig")

    def get(self, arg):  # type: (str) -> Optional[str]
        try:
            command_output = _popen("ifconfig", arg)
        except CalledProcessError as err:
            # Return code of 1 means interface doesn't exist
            if err.returncode == 1:
                return None
            else:
                raise err  # this will cause another method to be used

        return _parse_ifconfig(arg, command_output)


# TODO: combine this with IfconfigWithArg/IfconfigNoArg
#       (need to do live testing on Darwin)
class IfconfigEther(Method):
    platforms = {"darwin"}
    method_type = "iface"
    _tested_arg = False  # type: bool
    _iface_arg = False  # type: bool

    def test(self):  # type: () -> bool
        return check_command("ifconfig")

    def get(self, arg):  # type: (str) -> Optional[str]
        # Check if this version of "ifconfig" accepts an interface argument
        command_output = ""

        if not self._tested_arg:
            try:
                command_output = _popen("ifconfig", arg)
                self._iface_arg = True
            except CalledProcessError:
                self._iface_arg = False
            self._tested_arg = True

        if self._iface_arg and not command_output:  # Don't repeat work on first run
            command_output = _popen("ifconfig", arg)
        else:
            command_output = _popen("ifconfig", "")

        return _parse_ifconfig(arg, command_output)


# TODO: create new methods, IfconfigNoArgs and IfconfigVariousArgs
# TODO: unit tests
class IfconfigOther(Method):
    """
    Wild 'Shot in the Dark' attempt at ``ifconfig`` for unknown platforms.
    """

    platforms = {"linux", "other"}
    method_type = "iface"
    # "-av": Tru64 system?
    _args = (
        ("", (r"(?::| ).*?\sether\s", r"(?::| ).*?\sHWaddr\s")),
        ("-a", r".*?HWaddr\s"),
        ("-v", r".*?HWaddr\s"),
        ("-av", r".*?Ether\s"),
    )
    _args_tested = False  # type: bool
    _good_pair = []  # type: List[Union[str, Tuple[str, str]]]

    def test(self):  # type: () -> bool
        return check_command("ifconfig")

    def get(self, arg):  # type: (str) -> Optional[str]
        if not arg:
            return None

        # Cache output from testing command so first call isn't wasted
        command_output = ""

        # Test which arguments are valid to the command
        if not self._args_tested:
            for pair_to_test in self._args:
                try:
                    command_output = _popen("ifconfig", pair_to_test[0])
                    self._good_pair = list(pair_to_test)  # noqa: T484
                    if isinstance(self._good_pair[1], str):
                        self._good_pair[1] += MAC_RE_COLON
                    break
                except CalledProcessError as ex:
                    if DEBUG:
                        log.debug(
                            "IfconfigOther pair test failed for (%s, %s): %s",
                            pair_to_test[0],
                            pair_to_test[1],
                            str(ex),
                        )

            if not self._good_pair:
                self.unusable = True
                return None

            self._args_tested = True

        if not command_output and isinstance(self._good_pair[0], str):
            command_output = _popen("ifconfig", self._good_pair[0])

        # Handle the two possible search terms
        if isinstance(self._good_pair[1], tuple):
            for term in self._good_pair[1]:
                regex = term + MAC_RE_COLON
                result = _search(re.escape(arg) + regex, command_output)

                if result:
                    # changes type from tuple to str, so the else statement
                    # will be hit on the next call to this method
                    self._good_pair[1] = regex
                    return result
            return None
        else:
            return _search(re.escape(arg) + self._good_pair[1], command_output)


class NetstatIface(Method):
    platforms = {"linux", "wsl", "other"}
    method_type = "iface"

    # ".*?": non-greedy
    # https://docs.python.org/3/howto/regex.html#greedy-versus-non-greedy
    _regexes = [
        r": .*?ether " + MAC_RE_COLON,
        r": .*?HWaddr " + MAC_RE_COLON,
        # Ubuntu 12.04 and other older kernels
        r" .*?Link encap:Ethernet  HWaddr " + MAC_RE_COLON,
    ]  # type: List[str]
    _working_regex = ""  # type: str

    def test(self):  # type: () -> bool
        return check_command("netstat")

    # TODO: consolidate the parsing logic between IfconfigOther and netstat
    def get(self, arg):  # type: (str) -> Optional[str]
        # NOTE: netstat and ifconfig pull from the same kernel source and
        # therefore have the same output format on the same platform.
        command_output = _popen("netstat", "-iae")
        if not command_output:
            log.warning("no netstat output, marking unusable")
            self.unusable = True
            return None

        if self._working_regex:
            # Use regex that worked previously. This can still return None in
            # the case of interface not existing, but at least it's a bit faster.
            return _search(arg + self._working_regex, command_output, flags=re.DOTALL)

        # See if either regex matches
        for regex in self._regexes:
            result = _search(arg + regex, command_output, flags=re.DOTALL)
            if result:
                self._working_regex = regex
                return result

        return None


# TODO: Add to IpLinkIface
# TODO: New method for "ip addr"? (this would be useful for CentOS and others as a fallback)
# (r"state UP.*\n.*ether " + MAC_RE_COLON, 0, "ip", ["link","addr"]),
# (r"wlan.*\n.*ether " + MAC_RE_COLON, 0, "ip", ["link","addr"]),
# (r"ether " + MAC_RE_COLON, 0, "ip", ["link","addr"]),
# _regexes = (
#     r".*\n.*link/ether " + MAC_RE_COLON,
#     # Android 6.0.1+ (and likely other platforms as well)
#     r"state UP.*\n.*ether " + MAC_RE_COLON,
#     r"wlan.*\n.*ether " + MAC_RE_COLON,
#     r"ether " + MAC_RE_COLON,
# )  # type: Tuple[str, str, str, str]


class IpLinkIface(Method):
    platforms = {"linux", "wsl", "android", "other"}
    method_type = "iface"
    _regex = r".*\n.*link/ether " + MAC_RE_COLON  # type: str
    _tested_arg = False  # type: bool
    _iface_arg = False  # type: bool

    def test(self):  # type: () -> bool
        return check_command("ip")

    def get(self, arg):  # type: (str) -> Optional[str]
        # Check if this version of "ip link" accepts an interface argument
        # Not accepting one is a quirk of older versions of 'iproute2'
        # TODO: is it "ip link <arg>" on some platforms and "ip link show <arg>" on others?
        command_output = ""

        if not self._tested_arg:
            try:
                command_output = _popen("ip", "link show " + arg)
                self._iface_arg = True
            except CalledProcessError as err:
                # Output: 'Command "eth0" is unknown, try "ip link help"'
                if err.returncode != 255:
                    raise err
            self._tested_arg = True

        if self._iface_arg:
            if not command_output:  # Don't repeat work on first run
                command_output = _popen("ip", "link show " + arg)
            return _search(arg + self._regex, command_output)
        else:
            # TODO: improve this regex to not need extra portion for no arg
            command_output = _popen("ip", "link")
            return _search(arg + r":" + self._regex, command_output)


class DefaultIfaceLinuxRouteFile(Method):
    """
    Get the default interface by parsing the ``/proc/net/route`` file.

    This is the same source as the ``route`` command, however it's much
    faster to read this file than to call ``route``. If it fails for whatever
    reason, we can fall back on the system commands (e.g for a platform that
    has a route command, but doesn't use ``/proc``, such as BSD-based platforms).
    """

    platforms = {"linux", "wsl"}
    method_type = "default_iface"

    def test(self):  # type: () -> bool
        return check_path("/proc/net/route")

    def get(self, arg=""):  # type: (str) -> Optional[str]
        data = _read_file("/proc/net/route")

        if data is not None and len(data) > 1:
            for line in data.split("\n")[1:-1]:
                line = line.strip()
                if not line:
                    continue

                # Some have tab separators, some have spaces
                if "\t" in line:
                    sep = "\t"
                else:
                    sep = "    "

                iface_name, dest = line.split(sep)[:2]

                if dest == "00000000":
                    return iface_name

            if DEBUG:
                log.debug(
                    "Failed to find default interface in data from "
                    "'/proc/net/route', no destination of '00000000' was found"
                )
        elif DEBUG:
            log.warning("No data from /proc/net/route")

        return None


class DefaultIfaceRouteCommand(Method):
    platforms = {"linux", "wsl", "other"}
    method_type = "default_iface"

    def test(self):  # type: () -> bool
        return check_command("route")

    def get(self, arg=""):  # type: (str) -> Optional[str]
        output = _popen("route", "-n")

        try:
            return output.partition("0.0.0.0")[2].partition("\n")[0].split()[-1]
        except IndexError as ex:  # index errors means no default route in output?
            log.debug("DefaultIfaceRouteCommand failed for %s: %s", arg, str(ex))
            return None


class DefaultIfaceRouteGetCommand(Method):
    platforms = {"darwin", "freebsd", "other"}
    method_type = "default_iface"

    def test(self):  # type: () -> bool
        return check_command("route")

    def get(self, arg=""):  # type: (str) -> Optional[str]
        output = _popen("route", "get default")

        if not output:
            return None

        try:
            return output.partition("interface: ")[2].strip().split()[0].strip()
        except IndexError as ex:
            log.debug("DefaultIfaceRouteCommand failed for %s: %s", arg, str(ex))
            return None


class DefaultIfaceIpRoute(Method):
    # NOTE: this is slightly faster than "route" since
    # there is less output than "route -n"
    platforms = {"linux", "wsl", "other"}
    method_type = "default_iface"

    def test(self):  # type: () -> bool
        return check_command("ip")

    def get(self, arg=""):  # type: (str) -> Optional[str]
        output = _popen("ip", "route list 0/0")

        if not output:
            if DEBUG:
                log.debug("DefaultIfaceIpRoute failed: no output")
            return None

        return output.partition("dev")[2].partition("proto")[0].strip()


class DefaultIfaceOpenBsd(Method):
    platforms = {"openbsd"}
    method_type = "default_iface"

    def test(self):  # type: () -> bool
        return check_command("route")

    def get(self, arg=""):  # type: (str) -> Optional[str]
        output = _popen("route", "-nq show -inet -gateway -priority 1")
        return output.partition("127.0.0.1")[0].strip().rpartition(" ")[2]


class DefaultIfaceFreeBsd(Method):
    platforms = {"freebsd"}
    method_type = "default_iface"

    def test(self):  # type: () -> bool
        return check_command("netstat")

    def get(self, arg=""):  # type: (str) -> Optional[str]
        output = _popen("netstat", "-r")
        return _search(r"default[ ]+\S+[ ]+\S+[ ]+(\S+)[\r\n]+", output)


# TODO: order methods by effectiveness/reliability
#   Use a class attribute maybe? e.g. "score", then sort by score in cache
METHODS = [
    # NOTE: CtypesHost is faster than ArpExe because of sub-process startup times :)
    CtypesHost,
    ArpFile,
    ArpingHost,
    SysIfaceFile,
    FcntlIface,
    UuidLanscan,
    GetmacExe,
    IpconfigExe,
    WmicExe,
    ArpExe,
    DarwinNetworksetupIface,
    ArpFreebsd,
    ArpOpenbsd,
    IfconfigWithIfaceArg,
    IfconfigEther,
    IfconfigOther,
    IpLinkIface,
    NetstatIface,
    IpNeighborShow,
    ArpVariousArgs,
    UuidArpGetNode,
    DefaultIfaceLinuxRouteFile,
    DefaultIfaceIpRoute,
    DefaultIfaceRouteCommand,
    DefaultIfaceRouteGetCommand,
    DefaultIfaceOpenBsd,
    DefaultIfaceFreeBsd,
]  # type: List[Type[Method]]

# Primary method to use for a given method type
METHOD_CACHE = {
    "ip4": None,
    "ip6": None,
    "iface": None,
    "default_iface": None,
}  # type: Dict[str, Optional[Method]]


# Order of methods is determined by:
#   Platform + version
#   Performance (file read > command)
#   Reliability (how well I know/understand the command to work)
FALLBACK_CACHE = {
    "ip4": [],
    "ip6": [],
    "iface": [],
    "default_iface": [],
}  # type: Dict[str, List[Method]]


DEFAULT_IFACE = ""  # type: str


def get_method_by_name(method_name):
    # type: (str) -> Optional[Type[Method]]
    for method in METHODS:
        if method.__name__.lower() == method_name.lower():
            return method

    return None


def get_instance_from_cache(method_type, method_name):
    # type: (str, str) -> Optional[Method]
    """
    Get the class for a named Method from the caches.

    METHOD_CACHE is checked first, and if that fails,
    then any entries in FALLBACK_CACHE are checked.
    If both fail, None is returned.

    Args:
        method_type: method type to initialize the cache for.
            Allowed values are:  ``ip4`` | ``ip6`` | ``iface`` | ``default_iface``
    """

    if str(METHOD_CACHE[method_type]) == method_name:
        return METHOD_CACHE[method_type]

    for f_meth in FALLBACK_CACHE[method_type]:
        if str(f_meth) == method_name:
            return f_meth

    return None


def _swap_method_fallback(method_type, swap_with):
    # type: (str, str) -> bool
    if str(METHOD_CACHE[method_type]) == swap_with:
        return True

    found = None  # type: Optional[Method]
    for f_meth in FALLBACK_CACHE[method_type]:
        if str(f_meth) == swap_with:
            found = f_meth
            break

    if not found:
        return False

    curr = METHOD_CACHE[method_type]
    FALLBACK_CACHE[method_type].remove(found)
    METHOD_CACHE[method_type] = found
    FALLBACK_CACHE[method_type].insert(0, curr)  # noqa: T484

    return True


def _warn_critical(err_msg):
    # type: (str) -> None
    log.critical(err_msg)
    warnings.warn(
        "%s. NOTICE: this warning will likely turn into a raised exception in getmac 1.0.0!"
        % err_msg,
        RuntimeWarning,
    )


def initialize_method_cache(
    method_type, network_request=True
):  # type: (str, bool) -> bool
    """
    Initialize the method cache for the given method type.

    Args:
        method_type: method type to initialize the cache for.
            Allowed values are:  ``ip4`` | ``ip6`` | ``iface`` | ``default_iface``
        network_request: if methods that make network requests should be included
            (those methods that have the attribute ``network_request`` set to ``True``)
    """
    if METHOD_CACHE.get(method_type):
        if DEBUG:
            log.debug(
                "Method cache already initialized for method type '%s'", method_type
            )
        return True

    log.debug("Initializing '%s' method cache (platform: '%s')", method_type, PLATFORM)

    if OVERRIDE_PLATFORM:
        log.warning(
            "Platform override is set, using '%s' as platform "
            "instead of detected platform '%s'",
            OVERRIDE_PLATFORM,
            PLATFORM,
        )
        platform = OVERRIDE_PLATFORM
    else:
        platform = PLATFORM

    if DEBUG >= 4:
        meth_strs = ", ".join(m.__name__ for m in METHODS)  # type: str
        log.debug("%d methods available: %s", len(METHODS), meth_strs)

    # Filter methods by the type of MAC we're looking for, such as "ip"
    # for remote host methods or "iface" for local interface methods.
    type_methods = [
        method
        for method in METHODS
        if (method.method_type != "ip" and method.method_type == method_type)
        # Methods with a type of "ip" can handle both IPv4 and IPv6
        or (method.method_type == "ip" and method_type in ["ip4", "ip6"])
    ]  # type: List[Type[Method]]

    if not type_methods:
        _warn_critical("No valid methods matching MAC type '%s'" % method_type)
        return False

    if DEBUG >= 2:
        type_strs = ", ".join(tm.__name__ for tm in type_methods)  # type: str
        log.debug(
            "%d type-filtered methods for '%s': %s",
            len(type_methods),
            method_type,
            type_strs,
        )

    # Filter methods by the platform we're running on
    platform_methods = [
        method for method in type_methods if platform in method.platforms
    ]  # type: List[Type[Method]]

    if not platform_methods:
        # If there isn't a method for the current platform,
        # then fallback to the generic platform "other".
        warn_msg = (
            "No methods for platform '%s'! Your system may not be supported. "
            "Falling back to platform 'other'." % platform
        )
        log.warning(warn_msg)
        warnings.warn(warn_msg, RuntimeWarning)
        platform_methods = [
            method for method in type_methods if "other" in method.platforms
        ]

    if DEBUG >= 2:
        plat_strs = ", ".join(pm.__name__ for pm in platform_methods)  # type: str
        log.debug(
            "%d platform-filtered methods for '%s' (method_type='%s'): %s",
            len(platform_methods),
            platform,
            method_type,
            plat_strs,
        )

    if not platform_methods:
        _warn_critical(
            "No valid methods found for MAC type '%s' and platform '%s'"
            % (method_type, platform)
        )
        return False

    filtered_methods = platform_methods  # type: List[Type[Method]]

    # If network_request is False, then remove any methods that have network_request=True
    if not network_request:
        filtered_methods = [m for m in platform_methods if not m.network_request]

    # Determine which methods work on the current system
    tested_methods = []  # type: List[Method]

    for method_class in filtered_methods:
        method_instance = method_class()  # type: Method
        try:
            test_result = method_instance.test()  # type: bool
        except Exception:
            test_result = False
        if test_result:
            tested_methods.append(method_instance)
            # First successful test goes in the cache
            if not METHOD_CACHE[method_type]:
                METHOD_CACHE[method_type] = method_instance
        elif DEBUG:
            log.debug("Test failed for method '%s'", str(method_instance))

    if not tested_methods:
        _warn_critical(
            "All %d '%s' methods failed to test!" % (len(filtered_methods), method_type)
        )
        return False

    if DEBUG >= 2:
        tested_strs = ", ".join(str(ts) for ts in tested_methods)  # type: str
        log.debug(
            "%d tested methods for '%s': %s",
            len(tested_methods),
            method_type,
            tested_strs,
        )

    # Populate fallback cache with all the tested methods, minus the currently active method
    if METHOD_CACHE[method_type] and METHOD_CACHE[method_type] in tested_methods:
        tested_methods.remove(METHOD_CACHE[method_type])  # noqa: T484

    FALLBACK_CACHE[method_type] = tested_methods

    if DEBUG:
        log.debug(
            "Current method cache: %s",
            str({k: str(v) for k, v in METHOD_CACHE.items()}),
        )
        log.debug(
            "Current fallback cache: %s",
            str({k: str(v) for k, v in FALLBACK_CACHE.items()}),
        )
    log.debug("Finished initializing '%s' method cache", method_type)

    return True


def _remove_unusable(method, method_type):  # type: (Method, str) -> Optional[Method]
    if not FALLBACK_CACHE[method_type]:
        log.warning("No fallback method for unusable method '%s'!", str(method))
        METHOD_CACHE[method_type] = None
    else:
        METHOD_CACHE[method_type] = FALLBACK_CACHE[method_type].pop(0)
        log.warning(
            "Falling back to '%s' for unusable method '%s'",
            str(METHOD_CACHE[method_type]),
            str(method),
        )

    return METHOD_CACHE[method_type]


def _attempt_method_get(
    method, method_type, arg
):  # type: (Method, str, str) -> Optional[str]
    """
    Attempt to use methods, and if they fail, fallback to the next method in the cache.
    """
    if not METHOD_CACHE[method_type] and not FALLBACK_CACHE[method_type]:
        _warn_critical("No usable methods found for MAC type '%s'" % method_type)
        return None

    if DEBUG:
        log.debug(
            "Attempting get() (method='%s', method_type='%s', arg='%s')",
            str(method),
            method_type,
            arg,
        )

    result = None
    try:
        result = method.get(arg)
    except CalledProcessError as ex:
        # Don't mark return code 1 on a process as unusable!
        #   Example of return code 1 on ifconfig from WSL:
        #     Blake:goesc$ ifconfig eth8
        #     eth8: error fetching interface information: Device not found
        #     Blake:goesc$ echo $?
        #     1
        # Methods where an exit code of 1 makes it invalid should handle the
        # CalledProcessError, inspect the return code, and set self.unusable = True
        if ex.returncode != 1:
            log.warning(
                "Cached Method '%s' failed for '%s' lookup with process exit "
                "code '%d' != 1, marking unusable. Exception: %s",
                str(method),
                method_type,
                ex.returncode,
                str(ex),
            )
            method.unusable = True
    except Exception as ex:
        log.warning(
            "Cached Method '%s' failed for '%s' lookup with unhandled exception: %s",
            str(method),
            method_type,
            str(ex),
        )
        method.unusable = True

    # When an unhandled exception occurs (or exit code other than 1), remove
    # the method from the cache and reinitialize with next candidate.
    if not result and method.unusable:
        new_method = _remove_unusable(method, method_type)

        if not new_method:
            return None

        return _attempt_method_get(new_method, method_type, arg)

    return result


def get_by_method(method_type, arg="", network_request=True):
    # type: (str, str, bool) -> Optional[str]
    """
    Query for a MAC using a specific method.

    Args:
        method_type: the type of lookup being performed.
            Allowed values are: ``ip4``, ``ip6``, ``iface``, ``default_iface``
        arg: Argument to pass to the method, e.g. an interface name or IP address
        network_request: if methods that make network requests should be included
            (those methods that have the attribute ``network_request`` set to ``True``)
    """
    if not arg and method_type != "default_iface":
        log.error("Empty arg for method '%s' (raw value: %s)", method_type, repr(arg))
        return None

    if FORCE_METHOD:
        log.warning(
            "Forcing method '%s' to be used for '%s' lookup (arg: '%s')",
            FORCE_METHOD,
            method_type,
            arg,
        )

        forced_method = get_method_by_name(FORCE_METHOD)

        if not forced_method:
            log.error("Invalid FORCE_METHOD method name '%s'", FORCE_METHOD)
            return None

        return forced_method().get(arg)

    method = METHOD_CACHE.get(method_type)  # type: Optional[Method]

    if not method:
        # Initialize the cache if it hasn't been already
        if not initialize_method_cache(method_type, network_request):
            log.error(
                "Failed to initialize method cache for method '%s' (arg: '%s')",
                method_type,
                arg,
            )
            return None

        method = METHOD_CACHE[method_type]

    if not method:
        log.error(
            "Initialization failed for method '%s'. It may not be supported "
            "on this platform or another issue occurred.",
            method_type,
        )
        return None

    # TODO: add a "net_ok" argument, check network_request attribute
    #   on method in CACHE, if not then keep checking for method in
    #   FALLBACK_CACHE that has network_request.
    result = _attempt_method_get(method, method_type, arg)

    # Log normal get() failures if debugging is enabled
    if DEBUG and not result:
        log.debug("Method '%s' failed for '%s' lookup", str(method), method_type)

    return result


def get_mac_address(  # noqa: C901
    interface=None, ip=None, ip6=None, hostname=None, network_request=True
):
    # type: (Optional[str], Optional[str], Optional[str], Optional[str], bool) -> Optional[str]
    """
    Get an Unicast IEEE 802 MAC-48 address from a local interface or remote host.

    Only ONE of the first four arguments may be used
    (``interface``,``ip``, ``ip6``, or ``hostname``).
    If none of the arguments are selected, the default network interface for
    the system will be used.

    .. warning::
       In getmac 1.0.0, exceptions will be raised if the method cache initialization fails
       (in other words, if there are no valid methods found for the type of MAC requested).

    .. warning::
       You MUST provide :class:`str` typed arguments, REGARDLESS of Python version

    .. note::
       ``"localhost"`` or ``"127.0.0.1"`` will always return ``"00:00:00:00:00:00"``

    .. note::
       It is assumed that you are using Ethernet or Wi-Fi. While other protocols
       such as Bluetooth may work, this has not been tested and should not be
       relied upon. If you need this functionality, please open an issue
       (or better yet, a Pull Request ;))!

    .. note::
       Exceptions raised by methods are handled silently and returned as :obj:`None`.

    Args:
        interface (str): Name of a local network interface (e.g "Ethernet 3", "eth0", "ens32")
        ip (str): Canonical dotted decimal IPv4 address of a remote host (e.g ``192.168.0.1``)
        ip6 (str): Canonical shortened IPv6 address of a remote host (e.g ``ff02::1:ffe7:7f19``)
        hostname (str): DNS hostname of a remote host (e.g "router1.mycorp.com", "localhost")
        network_request (bool): If network requests should be made when attempting to find the
            MAC of a remote host. If the ``arping`` command is available, this will be used.
            If not, a UDP packet will be sent to the remote host to populate
            the ARP/NDP tables for IPv4/IPv6. The port this packet is sent to can
            be configured using the module variable ``getmac.PORT``.

    Returns:
        Lowercase colon-separated MAC address, or :obj:`None` if one could not be
        found or there was an error.
    """  # noqa: E501

    if DEBUG:
        import timeit

        start_time = timeit.default_timer()

    if PY2 or (sys.version_info[0] == 3 and sys.version_info[1] < 7):
        global WARNED_UNSUPPORTED_PYTHONS
        if not WARNED_UNSUPPORTED_PYTHONS:
            warning_string = (
                "Support for Python versions < 3.7 is deprecated and will be "
                "removed in getmac 1.0.0. If you are stuck on an unsupported "
                "Python, considor loosely pinning the version of this package "
                'in your dependency list, e.g. "getmac<1.0.0" or "getmac~=0.9.0".'
            )
            warnings.warn(warning_string, DeprecationWarning)
            log.warning(warning_string)  # Ensure it appears in any logs
            WARNED_UNSUPPORTED_PYTHONS = True

    if (hostname and hostname == "localhost") or (ip and ip == "127.0.0.1"):
        return "00:00:00:00:00:00"

    # Resolve hostname to an IP address
    if hostname:
        # Exceptions will be handled silently and returned as a None
        try:
            # TODO: can this return a IPv6 address? If so, handle that!
            ip = socket.gethostbyname(hostname)
        except Exception as ex:
            log.error("Could not resolve hostname '%s': %s", hostname, ex)
            if DEBUG:
                log.debug(traceback.format_exc())
            return None

    if ip6:
        if not socket.has_ipv6:
            log.error(
                "Cannot get the MAC address of a IPv6 host: "
                "IPv6 is not supported on this system"
            )
            return None
        elif ":" not in ip6:
            log.error("Invalid IPv6 address (no ':'): %s", ip6)
            return None

    mac = None

    if network_request and (ip or ip6):
        send_udp_packet = True  # type: bool

        # If IPv4, use ArpingHost or CtypesHost if they're available instead
        # of populating the ARP table. This provides more reliable results
        # and a ARP packet is lower impact than a UDP packet.
        if ip:
            if not METHOD_CACHE["ip4"]:
                initialize_method_cache("ip4", network_request)

            # If ArpFile succeeds, just use that, since it's
            # significantly faster than arping (file read vs.
            # spawning a process).
            if not FORCE_METHOD or FORCE_METHOD.lower() == "arpfile":
                af_meth = get_instance_from_cache("ip4", "ArpFile")
                if af_meth:
                    mac = _attempt_method_get(af_meth, "ip4", ip)

            # TODO: add tests for this logic (arpfile => fallback)
            # This seems to be a common course of GitHub issues,
            # so fixing it for good and adding robust tests is
            # probably a good idea.

            if not mac:
                for arp_meth in ["CtypesHost", "ArpingHost"]:
                    if FORCE_METHOD and FORCE_METHOD.lower() != arp_meth:
                        continue

                    if arp_meth == str(METHOD_CACHE["ip4"]):
                        send_udp_packet = False
                        break
                    elif any(
                        arp_meth == str(x) for x in FALLBACK_CACHE["ip4"]
                    ) and _swap_method_fallback("ip4", arp_meth):
                        send_udp_packet = False
                        break

        # Populate the ARP table by sending an empty UDP packet to a high port
        if send_udp_packet and not mac:
            if DEBUG:
                log.debug(
                    "Attempting to populate ARP table with UDP packet to %s:%d",
                    ip if ip else ip6,
                    PORT,
                )

            if ip:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

            try:
                if ip:
                    sock.sendto(b"", (ip, PORT))
                else:
                    sock.sendto(b"", (ip6, PORT))
            except Exception:
                log.error("Failed to send ARP table population packet")
                if DEBUG:
                    log.debug(traceback.format_exc())
            finally:
                sock.close()
        elif DEBUG:
            log.debug(
                "Not sending UDP packet, using network request method '%s' instead",
                str(METHOD_CACHE["ip4"]),
            )

    # Setup the address hunt based on the arguments specified
    if not mac:
        if ip6:
            mac = get_by_method("ip6", ip6)
        elif ip:
            mac = get_by_method("ip4", ip)
        elif interface:
            mac = get_by_method("iface", interface)
        else:  # Default to searching for interface
            # Default to finding MAC of the interface with the default route
            if WINDOWS and network_request:
                default_iface_ip = _fetch_ip_using_dns()
                mac = get_by_method("ip4", default_iface_ip)
            elif WINDOWS:
                # TODO: implement proper default interface detection on windows
                #   (add a Method subclass to implement DefaultIface on Windows)
                mac = get_by_method("iface", "Ethernet")
            else:
                global DEFAULT_IFACE

                if not DEFAULT_IFACE:
                    DEFAULT_IFACE = get_by_method("default_iface")  # noqa: T484

                    if DEFAULT_IFACE:
                        DEFAULT_IFACE = str(DEFAULT_IFACE).strip()

                    # TODO: better fallback if default iface lookup fails
                    if not DEFAULT_IFACE and BSD:
                        DEFAULT_IFACE = "em0"
                    elif not DEFAULT_IFACE and DARWIN:  # OSX, maybe?
                        DEFAULT_IFACE = "en0"
                    elif not DEFAULT_IFACE:
                        DEFAULT_IFACE = "eth0"

                mac = get_by_method("iface", DEFAULT_IFACE)

                # TODO: hack to fallback to loopback if lookup fails
                if not mac:
                    mac = get_by_method("iface", "lo")

    log.debug("Raw MAC found: %s", mac)

    # Log how long it took
    if DEBUG:
        duration = timeit.default_timer() - start_time
        log.debug("getmac took %.4f seconds", duration)

    return _clean_mac(mac)
