import unittest
import test_assimilator
import test_api
import test_generator
import test_runner

if __name__ == '__main__':
    # starts all daemons if not started
    # start_daemons()

    # run tests
    print()
    unittest.main(test_generator, exit=False, verbosity=2)
    print()
    unittest.main(test_api, exit=False, verbosity=2)
    print()
    unittest.main(test_assimilator, exit=False, verbosity=2)
    print()
    unittest.main(test_runner, exit=False, verbosity=2)


