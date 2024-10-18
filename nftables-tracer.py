#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import signal
import subprocess
import sys
import re
import os

from contextlib import contextmanager
from functools import lru_cache
from typing import Any


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


def run(command: str) -> None:
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"ERROR: {sys.argv[0]}: {e}")
        sys.exit(1)


@contextmanager
def nftables_tracer_table_and_chain(rule_str: str) -> Any:
    run(f"nft add table {FAMILY} {TABLE_NAME}")
    run(f"nft add chain {FAMILY} {TABLE_NAME} {CHAIN_NAME} {CHAIN_DEFINITION}")
    run(f"nft add rule {FAMILY} {TABLE_NAME} {CHAIN_NAME} {rule_str} {TRACE} counter")

    def cleanup():
        run(f"nft delete table {FAMILY} {TABLE_NAME}")

    try:
        yield
    finally:
        cleanup()


TRACE_COLORS = [
    BLUE,
    MAGENTA,
    CYAN,
    WHITE,
]

TRACE_COLORS_LEN = len(TRACE_COLORS)

trace_id_color_idx = 0


@lru_cache(maxsize=TRACE_COLORS_LEN * 2)
def get_trace_id_color(trace_id: str) -> str:
    global trace_id_color_idx

    color = TRACE_COLORS[trace_id_color_idx]
    trace_id_color_idx = trace_id_color_idx + 1
    if trace_id_color_idx == TRACE_COLORS_LEN:
        trace_id_color_idx = 0

    return color


def verdict_color(verdict: str) -> str:
    if "accept" in verdict or "continue" in verdict:
        return GREEN
    return RED


def colorize(line: str) -> str:
    match = re.match(r"^trace id \S+ \S+ \S+ \S+ packet:", line)
    if match:
        colored_packet = f"{YELLOW}packet:{RESET}"
        line = line.replace("packet:", colored_packet)

    match = re.search(r"^(trace id) (\S+)", line)
    if match:
        trace_id = match.group(2)
        color = get_trace_id_color(trace_id)

        colored_trace_id = f"{color}{match.group(0)}{RESET}"
        line = line.replace(match.group(0), colored_trace_id)

    match = re.search(r"(\(?verdict \S+)$", line)
    if match:
        color = verdict_color(match.group(0))
        colored_verdict = f"{color}{match.group(0)}{RESET}"
        line = line.replace(match.group(0), colored_verdict)

    match = re.search(r"(policy \S+)$", line)
    if match:
        color = verdict_color(match.group(0))
        colored_verdict = f"{color}{match.group(0)}{RESET}"
        line = line.replace(match.group(0), colored_verdict)

    return line


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
    finally:
        process.stdout.close()
        process.wait()


def main() -> None:
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
        default="",
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        print(f"ERROR: {sys.argv[0]}: root required")
        sys.exit(2)

    rule_string = args.nftables_rule_match

    def signal_handler(sig, frame):
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    with nftables_tracer_table_and_chain(rule_string):
        monitor(args.all, args.no_colors)


if __name__ == "__main__":
    main()
