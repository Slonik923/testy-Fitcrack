Automatizované testy pre systém Fitcrack
=============

- Inštalácia balíkov potrebných na spustenie testov:

        pip3 -r requirements.txt


# Testy sú určené pre BOINC server, na ktorom je nainštalovaný funkčný systém Fitcrack.
Detaily práce sú popísané v **[bakalárskej práci](./bakalar/xchrip00_bp.pdf)**.
Pred samotným testovaním je potrebné nastaviť hodnoty v konfiguračnom súbore `config.py`


- ## Testovanie modulu Runner:
    Pred spustením testov je potrebné:
    1. pridať do zložky s testami binárny súbor modulu a runner a špecifikovať jeho názov súbore `config.py`
    2. Premenovať súbor `hashcat_mock.py` na názov, ktorý očakáva Runner (`hashcat64.bin` v tejto
    verzii)
    3. Pridať do zložky s testami odkaz na zdrojové kódy API.

    ### Testy je možné spúšťať:

        python3 -m unittest test_runner

    alebo:

        python3 -m unittest test_runner.TestRunner

    alebo:

        python 3 test_runner.py


- ## Testovanie modulu Asimilator:

    Testy modulu Asimilator potrebujú iba pripojenie k databáze a nakonfigurovaný systém Fitcrack.
    Pripojenie k databáze sa nastavuje v konfiguračnom súbore `config.py`

    ### Testy je možné spúšťať naledovne:

        python3 -m unittest test_assimilator

    alebo:

        python3 -m unittest test_assimilator.TestAssimilator

    alebo:

        python 3 test_assimilator.py


- Testovanie modulu Generator:

    Testy modulu Generator potrebujú iba pripojenie k databáze a nakonfigurovaný systém Fitcrack.
    Pripojenie k databáze sa nastavuje v konfiguračnom súbore `config.py`

    ### Testy je možné spúšťať naledovne:

            python3 -m unittest test_generator

    alebo:

            python3 -m unittest test_generator.TestGenerator

    alebo:

            python 3 test_generator.py


- Testovanie API:

        python3 -m unittest test_py

    alebo:

        python3 test_api.py


Pri spúšťaní testov pomocou modulu unittest `python3 -m unittest` je možné špecifikovať konkrétny
testovací prípad, napríklad:

    python3 -m unittest test_runner.TestRunner.test_benchmark_ok



[Odkaz na GitHub](https://github.com/Slonik923/testy-Fitcrack)