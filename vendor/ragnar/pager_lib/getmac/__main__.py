#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import argparse
import logging
import sys

from . import getmac


def main():  # type: () -> None
    parser = argparse.ArgumentParser(
        "getmac",
        description="Get the MAC address of system network "
        "interfaces or remote hosts on the LAN",
    )
    parser.add_argument(
        "--version", action="version", version="getmac %s" % getmac.__version__
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable output messages"
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="count",
        help="Enable debugging output. Add characters to "
        "increase verbosity of output, e.g. '-dd'.",
    )
    parser.add_argument(
        "-N",
        "--no-net",
        "--no-network-requests",
        action="store_true",
        dest="NO_NET",
        help="Do not use arping or send a UDP packet to refresh the ARP table",
    )
    parser.add_argument(
        "--override-port",
        type=int,
        metavar="PORT",
        help="Override the default UDP port used to refresh the ARP table "
        "if network requests are enabled and arping is unavailable",
    )
    parser.add_argument(
        "--override-platform",
        type=str,
        default=None,
        metavar="PLATFORM",
        help="Override the platform detection with the given value "
        "(e.g. 'linux', 'windows', 'freebsd', etc.'). "
        "Any values returned by platform.system() are valid.",
    )
    parser.add_argument(
        "--force-method",
        type=str,
        default=None,
        metavar="METHOD",
        help="Force a specific method to be used, e.g. 'IpNeighborShow'. "
        "This will be used regardless of it's method type or platform "
        "compatibility, and Method.test() will NOT be checked!",
    )

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument(
        "-i",
        "--interface",
        type=str,
        default=None,
        help="Name of a network interface on the system",
    )
    group.add_argument(
        "-4", "--ip", type=str, default=None, help="IPv4 address of a remote host"
    )
    group.add_argument(
        "-6", "--ip6", type=str, default=None, help="IPv6 address of a remote host"
    )
    group.add_argument(
        "-n", "--hostname", type=str, default=None, help="Hostname of a remote host"
    )

    args = parser.parse_args()

    if args.debug or args.verbose:
        logging.basicConfig(
            format="%(levelname)-8s %(message)s", level=logging.INFO, stream=sys.stderr
        )

    if args.debug:
        getmac.DEBUG = args.debug

    if args.override_port:
        port = int(args.override_port)
        getmac.log.debug(
            "Using UDP port %d (overriding the default port %d)", port, getmac.PORT
        )
        getmac.PORT = port

    if args.override_platform:
        getmac.OVERRIDE_PLATFORM = args.override_platform.strip().lower()

    if args.force_method:
        getmac.FORCE_METHOD = args.force_method.strip().lower()

    mac = getmac.get_mac_address(
        interface=args.interface,
        ip=args.ip,
        ip6=args.ip6,
        hostname=args.hostname,
        network_request=not args.NO_NET,
    )

    if mac is not None:
        print(mac)  # noqa: T001, T201
        sys.exit(0)  # Exit success!
    else:
        sys.exit(1)  # Exit with error since it failed to find a MAC


if __name__ == "__main__":
    main()
