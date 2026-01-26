#!/usr/bin/env python3
"""Generates system log events on a SEL RTAC."""
import argparse
from time import sleep

from peat import initialize_peat
from peat.modules.sel.sel_http import SELHTTP

initialize_peat({"VERBOSE": False, "DEBUG": False})

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--ip", type=str, required=True)
parser.add_argument("-u", "--user", type=str, required=True)
parser.add_argument("-p", "--password", type=str, required=True)
parser.add_argument("--iterations", type=int, required=True)
parser.add_argument("--sleep-for", type=float, default=2.0)
args = parser.parse_args()

print(f"Running {args.iterations} iterations for {args.ip}")
for i in range(args.iterations):
    with SELHTTP(ip=args.ip) as http:
        res = http.login_rtac(user=args.user, passwd=args.password)
        if not res:
            print("login failed")
    sleep(float(args.sleep_for))
print("Done")
