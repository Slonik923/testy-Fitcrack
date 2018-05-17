#!/usr/bin/python3
import sys
import unittest
import test_assimilator
import test_api
import test_generator
import test_runner

if __name__ == '__main__':
    # run tests
    sys.stdout = open('test_generator_output.txt', 'w')
    unittest.main(test_generator, exit=False, verbosity=2)
    print()
    sys.stdout = open('test_assimilator_output.txt', 'w')
    unittest.main(test_assimilator, exit=False, verbosity=2)
    print()
    sys.stdout = open('test_runner_output.txt', 'w')
    unittest.main(test_runner, exit=False, verbosity=2)
    print()
    sys.stdout = open('test_api_output.txt', 'w')
    unittest.main(test_api, exit=False, verbosity=2)


