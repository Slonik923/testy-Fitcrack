Automatizované testy pre systém Fitcrack
=============

- Inštalácia balíkov potrebných na spustenie testov:

        pip3 -r requirements.txt


- # Testy sú určené pre BOINC server, na ktorom je nainštalovaný funkčný systém Fitcrack.


- Testovanie modulu Runner:

        python3 -m unittest test_runner
    alebo:
        python3 -m unittest test_runner.TestRunner
    alebo:
        python 3 test_runner.py


- Testovanie modulu Asimilator:

        python3 -m unittest test_assimilator
    alebo:
        python3 -m unittest test_assimilator.TestAssimilator
    alebo:
        python 3 test_assimilator.py


- Testovanie modulu Generator:

        python3 -m unittest test_generator
    alebo:
        python3 -m unittest test_generator.TestGenerator
    alebo:
        python 3 test_generator.py


- Testovanie API:

        python3 -m unittest test_py
    alebo:
        python3 test_api.py
