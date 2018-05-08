import argparse
import os


class ArgumentParserError(Exception):
    """Dummy exception class"""
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ArgumentParserError(message)


def get_initial_parser():
    """
    Sets attributes for benchmark parser
    :return: benchmark parser
    """
    bench_parser = Parser(description='Hashcat stub benchmark', add_help=False)
    bench_parser.add_argument("--force", action="store_true")
    bench_parser.add_argument("--machine-readable", action="store_true")
    bench_parser.add_argument("-b", action="store_true")
    bench_parser.add_argument("-m", type=int)
    bench_parser.add_argument("-a", type=int)
    bench_parser.add_argument("--error", action="store_true")
    bench_parser.add_argument("--warning", action="store_true")
    bench_parser.add_argument("--found", action="store_true")

    return bench_parser


def get_normal_parser():
    """
    Sets attributes for normal task parser
    :return: normal parser
    """
    normal_parser = Parser(description='Hashcat stub normal', add_help=False)
    normal_parser.add_argument("--machine-status", action="store_true")
    normal_parser.add_argument("--status", action="store_true")
    normal_parser.add_argument("--status-timer", type=int)
    normal_parser.add_argument("--outfile-format", type=int)
    normal_parser.add_argument("--markov-disable", action="store_true")
    normal_parser.add_argument("--restore-disable", action="store_true")
    normal_parser.add_argument("--potfile-disable", action="store_true")
    normal_parser.add_argument("--logfile-disable", action="store_true")
    normal_parser.add_argument("--gpu-temp-disable", action="store_true")
    normal_parser.add_argument("--quiet", action="store_true")
    normal_parser.add_argument("data", type=os.path.isfile)

    return normal_parser


def initial_parse(args):
    """
    Parses known arguments with initial (benchmark) parser
    :param args:
    :return: tuple with namespace object containing known arguments
    and list containing unknown (not parsed) arguments
    """
    parser = get_initial_parser()
    return parser.parse_known_args(args.split())


def parse_mask_attack(args):
    """
    Adds argument mask to parser and parses args
    :param args: list of arguments
    :return: namespace object with arguments
    """
    parser = get_normal_parser()
    parser.add_argument("mask", type=str)

    return parser.parse_args(args)


def parse_dict_attack(args):
    """
    Adds dict1 argument to normal attack parser and parses args
    :param args: list of arguments
    :return: namespace object with arguments
    """
    parser = get_normal_parser()
    parser.add_argument("dict1", type=os.path.isfile)

    return parser.parse_args(args)


def parse_comb_attack(args):
    """
    Adds dict1 and dict2 arguments to normal attack parser and parses args
    :param args: list of arguments
    :return: namespace object with arguments
    """
    parser = get_normal_parser()
    parser.add_argument("dict1", type=os.path.isfile)
    parser.add_argument("dict2", type=os.path.isfile)

    return parser.parse_args(args)
