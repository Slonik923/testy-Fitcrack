import platform
import re
import subprocess
import unittest
from decimal import Decimal
from enum import Enum
from subprocess import call

import psutil

import config

unittest.TestLoader.sortTestMethodsUsing = None


class PackageStatus(Enum):
    ready = 0
    finished = 1
    exhausted = 2
    malformed = 3
    timeout = 4
    running = 10
    validating = 11
    finishing = 12


class HostStatus(Enum):
    benchmark = 0
    normal = 1
    validation = 2
    done = 3
    error = 4


class AttackModes(Enum):
    dictionary = 0  # dictionary == straight -> 1 dictionary and could have rules
    combination = 1  # 2 dictionaries and could have left and right rule
    mask = 3  # brute-force == mask


class AttackModesShort(Enum):
    dict = 0
    comb = 1
    brute = 3


server_subsystems = ["sample_work_generator", "sample_assimilator",
                     "sample_bitwise_validator", "file_deleter", "feeder", "transitioner"]


def make_run_only(tested_module):
    """
    Starts all daemons if project is running, if not starts whole project
    kills all subsystems except tested  module
    :param tested_module: string with name of server module
    :return:
    """
    if is_project_running():
        start_daemons()
    else:
        start_project()

    kill_all_modules_except(tested_module)


def is_running(module):
    """

    :param module: string with subsystem name
    :return: True if subsystem is running
    """
    running = get_running_modules()
    if module in running:
        return True

    return False


def get_running_modules():
    """

    :return: list of running modules or empty list if project is not running
    """
    result = []
    if not is_project_running():
        return result

    for proc in psutil.process_iter():
        if proc.name() in server_subsystems:
            result.append(proc.name())

    return result


def is_project_running():
    """
    Calls boinc utility status and reads output
    :return: True if project is running
    """
    out = subprocess.check_output("bin/status", cwd=config.project["home"],
                                  stderr=subprocess.STDOUT, universal_newlines=True, shell=True,
                                  timeout=15)
    pattern = re.compile("BOINC is ENABLED")
    if pattern.match(out):
        return True

    return False


def kill_all_modules_except(*args):
    """
    Kills all modules except those that were sent as arguments
    :param args: module names
    :return:
    """
    print("Killing all modules except:")
    for arg in args:
        print(arg)

    for proc in psutil.process_iter():
        if proc.name() in server_subsystems:
            if proc.name() not in args:
                print("Killing: " + proc.name())
                proc.kill()


def get_server_info():
    server_info = {
        "work_generator": False,
        "assimilator": False,
        "bitwise_validator": False,
        "file_deleter": False,
        "feeder": False,
        "transitioner": False
    }

    for proc in psutil.process_iter():
        i = 0
        for subsystem in server_subsystems:
            i += 1
            if proc.name() == subsystem:
                keys = server_info.keys()
                server_info[list(keys)[i]] = True

    # TODO: cpu, platform
    info = {
        "subsystems": server_info,
        "server_stats": {
            "platform": platform.platform(),
            "cpu": platform.processor()
        }
    }

    return info


def start_daemons():
    """
    If project is running starts all daemons (modules)
    :return:
    """
    print("starting daemons and running tasks")
    call([config.project["home"] + "bin/start", "-c", "-v"])


def start_project():
    """
    Starts whole projects and all daemons (modules)
    :return:
    """
    print("Starting project")
    call([config.project["home"] + "bin/start"])


def stop_project():
    """
    Stop all daemons (modules) and whole project
    :return:
    """
    print("Stopping project")
    call([config.project["home"] + "bin/stop"])


class FitcrackTLVConfig:
    """
    Class for manipulation with Fitcrack TLV config files
    """

    @classmethod
    def create(cls, mode=None, attack_mode=None, hash_type=None, name=None,
               mask=None, hc_keyspace=None, start_index=None):
        if attack_mode is not None and not isinstance(attack_mode, AttackModes):
            raise ValueError("attack_mode need to be instance of AttackModes Enum")

        o = cls()
        o.mode = mode
        if attack_mode is not None:
            o.attack = AttackModesShort(attack_mode.value).name
            o.attack_mode = attack_mode.value
        o.hash_type = hash_type
        o.name = name
        o.mask = mask
        o.hc_keyspace = hc_keyspace
        o.start_index = start_index

        return o

    @classmethod
    def from_string(cls, string):
        o = cls()
        for line in string.split("\n"):
            if len(line) == 0:
                continue

            stripped_line = line.strip("|||")
            values = stripped_line.split("|")
            if len(values) != 4:
                raise ValueError("Config line malformed: " + line)
            name = values[0]
            _ = values[1]   # type
            length = int(values[2])
            val = values[3]
            if len(val) != length:
                raise ValueError("value length is wrong:" + line)
            if hasattr(o, name):
                print(o)
                raise ValueError(values[0] + " is already present in this object")
            if isint(val):
                setattr(o, name, int(val))
            else:
                setattr(o, name, val)

        print("from_string:", o)
        return o

    def __str__(self):
        res = ""
        if hasattr(self, "mode") and self.mode is not None:
            res = "|||mode|String|1|" + self.mode + "|||\n"
        if hasattr(self, "attack") and self.attack is not None:
            res += "|||attack|String|" + str(len(self.attack)) + "|" + self.attack + "|||\n"
        if hasattr(self, "attack_mode") and self.attack_mode is not None:
            res += "|||attack_mode|UInt|1|" + str(self.attack_mode) + "|||\n"
        if hasattr(self, "hash_type") and self.hash_type is not None:
            res += "|||hash_type|UInt|" + str(len(str(self.hash_type))) + "|" + str(
                self.hash_type) + "|||\n"
        if hasattr(self, "name") and self.name is not None:
            res += "|||name|String|" + str(len(self.name)) + "|" + str(self.name) + "|||\n"
        if hasattr(self, "mask") and self.mask is not None:
            res += "|||mask|String|" + str(len(self.mask)) + "|" + str(self.mask) + "|||\n"
        if hasattr(self, "hc_keyspace") and self.hc_keyspace is not None:
            res += "|||hc_keyspace|BigUInt|" + str(len(str(self.hc_keyspace))) + "|" + str(
                self.hc_keyspace) + "|||\n"
        if hasattr(self, "start_index") and self.start_index is not None:
            res += "|||start_index|BigUInt|" + str(len(str(self.start_index))) + "|" + str(
                self.start_index) + "|||\n"

        return res

    def to_file(self, filename):
        with open(filename, "w") as file:
            file.write(str(self))


class RunnerOutput:
    """
    Class with manipulation with runner output files
    """

    def __init__(self, string):
        lines = string.split("\n")
        self.mode = str(lines[0])
        self.status_code = int(lines[1])

        if self.mode == "b":
            if self.status_code == 0:
                self.power = int(lines[2])
                self.cracking_time = Decimal(lines[3])
            else:
                self.exit_code = int(lines[2])
                self.exit_info = str(lines[3])
        elif self.mode == "n":
            if self.status_code == 0:
                self.password = str(lines[2])
                self.cracking_time = Decimal(lines[3])
            elif self.status_code == 1:
                self.cracking_time = Decimal(lines[2])
            else:
                self.exit_code = int(lines[2])
                self.exit_info = str(lines[3])


def isint(value):
    try:
        int(value)
        return True
    except ValueError:
        return False
