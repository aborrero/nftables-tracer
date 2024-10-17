#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import subprocess
import sys
import signal
import re
import os

from functools import lru_cache

FAMILY = "inet"
TABLE_NAME = "nftables-tracer"
CHAIN_NAME = "nftables-tracer"
CHAIN_DEFINITION = "{ type filter hook prerouting priority raw - 1 \\; }"
TRACE = "nftrace set 1"
MONITOR = "nft monitor trace"

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"
RESET = "\033[0m"

NEXT_COLOR = BLUE


def run(command):
    """Runs an nft command."""
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"ERROR: {sys.argv[0]}: {e}")
        sys.exit(1)


def create_nftables_table_chain_rule(rule_str):
    run(f"nft add table {FAMILY} {TABLE_NAME}")
    run(f"nft add chain {FAMILY} {TABLE_NAME} {CHAIN_NAME} {CHAIN_DEFINITION}")
    run(f"nft add rule {FAMILY} {TABLE_NAME} {CHAIN_NAME} {rule_str} {TRACE} counter")


def remove_nftables_table_chain():
    run(f"nft delete table {FAMILY} {TABLE_NAME}")


def signal_handler(sig, frame):
    remove_nftables_table_chain()
    sys.exit(0)


TRACE_COLORS = [
    BLUE,
    MAGENTA,
    CYAN,
    WHITE,
]

TRACE_COLORS_LEN = len(TRACE_COLORS)

trace_id_color_idx = 0


@lru_cache(maxsize=TRACE_COLORS_LEN * 2)
def get_trace_id_color(trace_id):
    global trace_id_color_idx

    color = TRACE_COLORS[trace_id_color_idx]
    trace_id_color_idx = trace_id_color_idx + 1
    if trace_id_color_idx == TRACE_COLORS_LEN:
        trace_id_color_idx = 0

    return color


def verdict_color(verdict: str):
    if "accept" in verdict or "continue" in verdict:
        return GREEN
    return RED


def colorize(line):
    ret = line

    match = re.match(r"^trace id \S+ \S+ \S+ \S+ packet:", ret)
    if match:
        colored_packet = f"{YELLOW}packet:{RESET}"
        ret = ret.replace("packet:", colored_packet)

    match = re.search(r"^(trace id) (\S+)", ret)
    if match:
        trace_id = match.group(2)
        color = get_trace_id_color(trace_id)

        colored_trace_id = f"{color}{match.group(1)} {trace_id}{RESET}"
        colored_trace_id_line = ret.replace(match.group(0), colored_trace_id)
        ret = colored_trace_id_line

    match = re.search(r"(verdict \S+)$", ret)
    if match:
        colored_verdict = f"{verdict_color(match.group(0))}{match.group(0)}{RESET}"
        ret = ret.replace(match.group(0), colored_verdict)

    match = re.search(r"(policy \S+)$", ret)
    if match:
        colored_verdict = f"{verdict_color(match.group(0))}{match.group(0)}{RESET}"
        ret = ret.replace(match.group(0), colored_verdict)

    return ret


def is_own_trace(line: str) -> bool:
    if re.match(rf"^trace id \S+ {FAMILY} {TABLE_NAME} {CHAIN_NAME}", line):
        return True
    return False


def monitor(show_all: bool, no_colors: bool) -> None:
    try:
        process = subprocess.Popen(
            MONITOR,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"ERROR: {e}")
        return

    if not process.stdout:
        print(f"ERROR: proccess for '{MONITOR}' yielded nothing in stdout")
        return

    try:
        for line in process.stdout:
            line = line.strip()
            if not show_all and is_own_trace(line):
                continue

            if no_colors:
                print(line)
            else:
                print(colorize(line))
    except KeyboardInterrupt:
        print("Process interrupted.")
    finally:
        process.stdout.close()
        process.wait()


def main():
    parser = argparse.ArgumentParser(
        description="a helper tool to trace nftables rulesets"
    )

    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="show all trace events, including the ones by this very tool",
        default=False,
    )
    parser.add_argument(
        "-c", "--no-colors", action="store_true", help="disable colors", default=False
    )
    parser.add_argument(
        "nftables_rule_match",
        type=str,
        help="nftables rule match to filter trace events",
        nargs="?",
        default="meta nfproto ipv6",
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        print(f"ERROR: {sys.argv[0]}: root required")
        sys.exit(2)

    rule_string = args.nftables_rule_match

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    create_nftables_table_chain_rule(rule_string)
    monitor(args.all, args.no_colors)

    print("Press Ctrl+C to exit and clean up the nftables table and chain.")
    signal.pause()


if __name__ == "__main__":
    main()
