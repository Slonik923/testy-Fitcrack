#!/usr/bin/env python3
"""
Application which imitates hashcat
uses hashcat parser for parsing arguments
Depending on arguments prints to stdout and log file whole content of one file

usage:
    Copy to same folder as runner and rename to hashcat binary name
    For example: hashcat64.bin
    Depends on runner expectations
    Example unix command:
    cp hashcat_mock.py hashcat64.bin
"""
import sys

import config
from hashcat_parsers import get_initial_parser
from fc_test_library import AttackModes

try:
    args = get_initial_parser().parse_known_args()
except:
    # TODO:
    args = None
    exit(-42)

known = args[0]
file_out = None
if known.b:
    if known.error:
        file_out = open(config.in_files["runner"]["hc_error"])
    elif known.warning:
        file_out = open(config.in_files["runner"]["hc_bench_out_warning"])
    else:
        file_out = open(config.in_files["runner"]["hc_bench_out"])
elif known.a is None:
    print("ERROR!!!")
    file_out = open(config.in_files["runner"]["hc_error"])

elif known.a == AttackModes.mask.value:
    if known.error:
        file_out = open(config.in_files["runner"]["hc_error"])
    elif known.found:
        file_out = open(config.in_files["runner"]["hc_mask_out_found"])
    else:
        file_out = open(config.in_files["runner"]["hc_mask_out_not_found"])

elif known.a == AttackModes.dictionary.value:
    if known.error:
        file_out = open(config.in_files["runner"]["hc_error"])
    elif known.found:
        file_out = open(config.in_files["runner"]["hc_dict_out_found"])
    else:
        file_out = open(config.in_files["runner"]["hc_dict_out_not_found"])

elif known.a == AttackModes.combination.value:
    if known.error:
        file_out = open(config.in_files["runner"]["hc_error"])
    elif known.found:
        file_out = open(config.in_files["runner"]["hc_comb_out_found"])
    else:
        file_out = open(config.in_files["runner"]["hc_comb_out_not_found"])

else:
    print("ERROR!!!")
    file_out = open(config.in_files["runner"]["hc_error"])

# log whole content of file_out to log
to_print = file_out.read()
with open("stub_log", "w") as stub_out:
    stub_out.write(to_print)

# same content of file_out prints to stdout for runner
print(to_print)
file_out.close()

# TODO: time in hashcat benchmark

# make file for test_runner file with arguments
command_log = open(config.runner["command_log"], "w")
command_log.write(" ".join(sys.argv))
command_log.close()

# hashcat exits with value other than 0 and 1 when error occurred
if known.error:
    exit(-1)

# hashcat exits with 0 only if password was found, 1 when password was not found
if not known.found:
    exit(1)
    

