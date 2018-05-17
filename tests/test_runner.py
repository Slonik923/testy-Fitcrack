#!/usr/bin/python3
import argparse
import os
import subprocess
import sys
import unittest

import config
import hashcat_parsers
from fc_test_library import AttackModes, FitcrackTLVConfig, RunnerOutput


class TestRunner(unittest.TestCase):
    """
    Class for testing Fitcrack runner
    """
    @classmethod
    def setUpClass(cls):
        runner = config.runner["path"] + config.runner["bin"]
        hashcat = config.runner["hashcat"]
        # checks for runner binary
        if not os.path.isfile(runner):
            print(runner, "needs to be in the same directory as tests")
            exit(1)

        # checks for hashcat binary (hashcat mock)
        if not os.path.isfile(hashcat):
            print(hashcat, "not found")
            print("You need to copy hashcat_mock.py and rename the copy to", hashcat)
            print("You also need to set", hashcat, "as executable")
            exit(1)

        # these are default files used by Runner and hashcat
        # file with hash
        if not os.path.isfile("data"):
            with open("data", "w") as f:
                f.write(config.runner["test_hash"])

        # dictionary files used in both dictionary and combination attack
        if not os.path.isfile("dict1"):
            with open("dict1", "w") as f:
                f.write("a")

        # dictionary file used in combination attack
        if not os.path.isfile("dict2"):
            with open("dict2", "w") as f:
                f.write("b")

        cls.delete_all()

    def setUp(self):
        # clear additional options
        open(config.runner["local.conf"], "w").close()

    def tearDown(self):
        self.delete_all()

    @staticmethod
    def delete_all():
        """
        Deletes log and output files of both hashcat stub and runner
        """
        if os.path.isfile(config.runner["stderr"]):
            os.remove(config.runner["stderr"])

        if os.path.isfile("config"):
            os.remove("config")

        if os.path.isfile("out"):
            os.remove("out")

        if os.path.isfile("runner_command"):
            os.remove("runner_command")

    def test_benchmark_ok(self):
        self.setup_benchmark()

        ret = self.call_runner()
        self.assertEqual(0, ret, "Runner return value")

        runner_command, out = self.verify_output_files()

        self.verify_parse_benchmark(runner_command)

        output = RunnerOutput(out)
        self.verify_output_benchmark_ok(output)

    def test_benchmark_error(self):
        self.setup_benchmark(error=True)

        ret = self.call_runner()
        self.assertEqual(0, ret, "Runner return value")

        runner_command, out = self.verify_output_files()

        self.verify_parse_benchmark(runner_command)

        output = RunnerOutput(out)
        self.verify_output_benchmark_error(output)

    def test_benchmark_warning(self):
        self.setup_benchmark(warning=True)

        ret = self.call_runner()
        self.assertEqual(0, ret, "Runner return value")

        runner_command, out = self.verify_output_files()

        self.verify_parse_benchmark(runner_command)

        output = RunnerOutput(out)
        self.verify_output_benchmark_ok(output)

    def test_mask_found(self):
        self.setup_normal(AttackModes.mask, found=True, mask="?d?d?d?d")

        ret = self.call_runner()
        self.assertEqual(0, ret, "Runner return value")

        runner_command, out = self.verify_output_files()
        self.verify_parse_normal(runner_command, hash_type=0, mode=AttackModes.mask)

        output = RunnerOutput(out)
        self.verify_output_normal(output, found=True)

    def test_mask_not_found(self):
        self.setup_normal(AttackModes.mask, mask="?d?d?d?d")

        ret = self.call_runner()
        self.assertEqual(0, ret, "Runner return value")

        runner_command, out = self.verify_output_files()
        self.verify_parse_normal(runner_command, hash_type=0, mode=AttackModes.mask)

        output = RunnerOutput(out)
        self.verify_output_normal(output)

    def test_mask_error(self):
        self.setup_normal(AttackModes.mask, mask="?d?d?d?d", error=True)

        ret = self.call_runner()
        self.assertEqual(0, ret, "Runner return value")

        runner_command, out = self.verify_output_files()
        self.verify_parse_normal(runner_command, hash_type=0, mode=AttackModes.mask)

        output = RunnerOutput(out)
        self.verify_output_normal(output, error=True)

    def test_combination_found(self):
        self.setup_normal(AttackModes.combination, found=True)

        ret = self.call_runner()
        self.assertEqual(0, ret, "Runner return value")

        runner_command, out = self.verify_output_files()
        self.verify_parse_normal(runner_command, hash_type=0, mode=AttackModes.combination)

        output = RunnerOutput(out)
        self.verify_output_normal(output, found=True)

    def test_combination_not_found(self):
        self.setup_normal(AttackModes.combination)

        ret = self.call_runner()
        self.assertEqual(0, ret, "Runner return value")

        runner_command, out = self.verify_output_files()
        self.verify_parse_normal(runner_command, hash_type=0, mode=AttackModes.combination)

        output = RunnerOutput(out)
        self.verify_output_normal(output)

    def test_combination_error(self):
        self.setup_normal(AttackModes.combination, error=True)

        ret = self.call_runner()
        self.assertEqual(0, ret, "Runner return value")

        runner_command, out = self.verify_output_files()
        self.verify_parse_normal(runner_command, hash_type=0, mode=AttackModes.combination)

        output = RunnerOutput(out)
        self.verify_output_normal(output, error=True)

    def test_dictionary_found(self):
        self.setup_normal(AttackModes.dictionary, found=True)

        ret = self.call_runner()
        self.assertEqual(0, ret, "Runner return value")

        runner_command, out = self.verify_output_files()
        self.verify_parse_normal(runner_command, hash_type=0, mode=AttackModes.dictionary)

        output = RunnerOutput(out)
        self.verify_output_normal(output, found=True)

    def test_dictionary_not_found(self):
        self.setup_normal(AttackModes.dictionary)

        ret = self.call_runner()
        self.assertEqual(0, ret, "Runner return value")

        runner_command, out = self.verify_output_files()
        self.verify_parse_normal(runner_command, hash_type=0, mode=AttackModes.dictionary)

        output = RunnerOutput(out)
        self.verify_output_normal(output)

    def test_dictionary_error(self):
        self.setup_normal(AttackModes.dictionary, error=True)

        ret = self.call_runner()
        self.assertEqual(0, ret, "Runner return value")

        runner_command, out = self.verify_output_files()
        self.verify_parse_normal(runner_command, hash_type=0, mode=AttackModes.dictionary)

        output = RunnerOutput(out)
        self.verify_output_normal(output, error=True)

    @staticmethod
    def call_runner():
        ret = subprocess.call(config.runner["path"] + config.runner["bin"], stdout=sys.stdout)

        return ret

    def verify_output_files(self):
        """
        Verify if all output files was created
        :return:
        """
        try:
            with open(config.runner["command_log"], "r") as f:
                # this log file is needed for parsing arguments passed to hashcat
                runner_command = f.read()
        except FileNotFoundError:
            self.fail("There is no file with hashcat arguments")

        try:
            with open("out", "r") as f:
                out = f.read()
        except FileNotFoundError:
            self.fail("Runner didn't create output file")

        return runner_command, out

    def verify_parse_benchmark(self, hashcat_args):
        """
        
        :param hashcat_args: string with arguments for hashcat
        :return: 
        """
        try:
            # initial_parse() returns a tuple of parsed and not known arguments
            args = hashcat_parsers.initial_parse(hashcat_args)[0]
        except argparse.ArgumentError:
            self.fail("Parsing arguments for benchmark failed")

        self.assertTrue(args.b, "Runner didn't specified -b argument")
        self.assertIsNotNone(args.m, "Runner didn't specified hash type (-m)")
        self.assertTrue(args.force, "Runner didn't specified --force argument")
        self.assertTrue(args.machine_readable, "Runner didn't specified --force argument")

    def verify_parse_normal(self, hashcat_args, hash_type, mode):
        """
        Parses hashcat arguments depending on attack mode
        :param hashcat_args: string with hascat arguments from runner
        :param hash_type:
        :param mode: attack mode
        :return:
        """
        if isinstance(mode, AttackModes):
            mode = mode.value

        try:
            args = hashcat_parsers.initial_parse(hashcat_args)
        except argparse.ArgumentError as err:
            self.fail("Hashcat argument error:" + str(err))

        # initial_parse() returns a tuple of parsed and not known arguments
        initial_args = args[0]
        not_parsed_args = args[1][1:]
        self.assertIsNotNone(initial_args.m, "Runner didn't specified hash type (-m)")
        self.assertEqual(hash_type, initial_args.m, "Bad hash type")
        self.assertIsNotNone(initial_args.a, "Runner didn't specified attack mode (-a)")
        self.assertEqual(mode, initial_args.a, "Bad attack mode")
        self.assertTrue(initial_args.force, "Runner didn't specified --force argument")
        self.assertTrue(initial_args.machine_readable, "Runner didn't specified --force argument")

        try:
            if initial_args.a == AttackModes.mask.value:
                hashcat_parsers.parse_mask_attack(not_parsed_args)
            elif initial_args.a == AttackModes.dictionary.value:
                hashcat_parsers.parse_dict_attack(not_parsed_args)
            elif initial_args.a == AttackModes.combination.value:
                hashcat_parsers.parse_comb_attack(not_parsed_args)
            else:
                raise FileNotFoundError("did not recognized attack mode")
        except FileNotFoundError as err:
            self.fail("Error while parsing hashcat arguments:" + str(err))
        except SystemExit:
            self.fail("Hashcat argument error")

    @staticmethod
    def setup_benchmark(error=False, warning=False, hash_type=0):
        """
        Creates config file for benchmark and add error or warning flag
        :param error: should error flag be set
        :param warning: should warning flag be set
        :param hash_type: benchmark for hash type
        :return:
        """
        conf = FitcrackTLVConfig.create(mode="b", hash_type=hash_type)
        conf.to_file("config")

        if error:
            TestRunner.add_error_flag()

        elif warning:
            TestRunner.add_warning_flag()

    @staticmethod
    def setup_normal(attack, found=False, error=False, hash_type=0, mask=""):
        """
        Creates config file for normal task depenping on attack mode and hash type
        If set, raises one of error or found flag
        :param mask:
        :param attack: attack mode
        :param found: password was found?
        :param error: error occurred?
        :param hash_type:
        :return:
        """
        conf = FitcrackTLVConfig.create(mode="n", attack_mode=attack, hash_type=hash_type,
                                        mask=mask)
        conf.to_file("config")

        if found:
            TestRunner.add_found_flag()

        elif error:
            TestRunner.add_error_flag()

    def verify_output_benchmark_ok(self, output):
        """
        Verify output object
        :param output: should be RunnerOutput object
        :return:
        """
        self.assertIsNotNone(output, "Runner didn't create output file")
        self.assertIsNotNone(output.mode, "Runner didn't specified mode")
        self.assertEqual(output.mode, "b", "Not benchmark mode")
        self.assertIsNotNone(output.status_code, "Runner didn't specified status code")
        self.assertEqual(output.status_code, 0, "Status code")
        self.assertIsNotNone(output.power, "Runner didn't specified cracking speed")
        self.assertGreater(output.power, 0)
        self.assertIsNotNone(output.cracking_time, "Runner didn't specified cracking time")

    def verify_output_benchmark_error(self, output):
        self.assertIsNotNone(output, "Runner didn't create output file")
        self.assertIsNotNone(output.mode, "Runner didn't specified mode")
        self.assertEqual(output.mode, "b", "Benchmark mode")
        self.assertIsNotNone(output.status_code, "Runner didn't specified status code")
        self.assertNotEqual(output.status_code, 0, "Status code")
        self.assertIsNotNone(output.exit_code, "Runner didn't specified exit code")
        self.assertNotEqual(output.exit_code, 0)
        self.assertIsNotNone(output.exit_info, "Runner didn't specified exit info")

    def verify_output_normal(self, output, found=False, error=False):
        """
        Verifies output object of normal attack depending if password was found or error occurred
        :param output:
        :param found: password was found
        :param error: error occurred
        :return:
        """
        if found and error:
            raise ValueError("found password, but failed?")

        self.assertIsNotNone(output, "Runner didn't create output file")
        self.assertIsNotNone(output.mode, "Runner didn't specified mode")
        self.assertEqual(output.mode, "n", "Not normal mode")
        self.assertIsNotNone(output.status_code, "Runner didn't specified status code")
        if found:
            self.assertEqual(output.status_code, 0, "Status code")
            self.assertIsNotNone(output.password, "Runner didn't specified password")
            self.assertIsNotNone(output.cracking_time, "Runner didn't specified cracking time")
            # TODO: password
        elif error:
            self.assertGreater(output.status_code, 1, "Status code should be bigger than 1")
            self.assertIsNotNone(output.exit_code, "Runner didn't specified exit code")
            self.assertGreater(output.exit_code, 0, "Exit code should be bigger than 0")
            self.assertIsNotNone(output.exit_info, "Runner didn't specified exit code")
        else:  # not found
            self.assertEqual(output.status_code, 1, "Status code")
            self.assertIsNotNone(output.cracking_time, "Runner didn't specified cracking time")

    @staticmethod
    def add_error_flag():
        """
        Writes to local.conf file argument, that tells stub hashcat to output error message
        :return:
        """
        with open(config.runner["local.conf"], "w") as f:
            f.write("--error")

    @staticmethod
    def add_warning_flag():
        """
        Writes to local.conf file argument, that tells stub hashcat to output message with warning
        :return:
        """
        with open(config.runner["local.conf"], "w") as f:
            f.write("--warning")

    @staticmethod
    def add_found_flag():
        """
        Writes to local.conf file argument, that tells stub hashcat to output message with password
        :return:
        """
        with open(config.runner["local.conf"], "w") as f:
            f.write("--found")


# runs all tests in this file if file is run as normal python script
if __name__ == '__main__':
    sys.stdout = open('test_runner_output.txt', 'w')
    unittest.main(verbosity=3)
