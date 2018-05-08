import json
import unittest

import requests

import config
from api_response_models import charset_model
from database.service import is_host_active, session, get_user, get_host_by_boinc_host_id, \
    get_hosts_count, add_host, get_bench_all_package, get_test_package, get_all_boinc_hosts, \
    get_all_charsets
from setup import HostStatus, get_server_info, kill_all_modules_except
from src.database.models import *


def db_item_from_boinc_host(boinc_host):
    active = False
    if is_host_active(boinc_host.id):
        active = True
        host = get_host_by_boinc_host_id(boinc_host.id)
    else:
        host = None

    user = get_user(boinc_host.userid)
    result = {
        'os_name': boinc_host.os_name,
        "active": active,
        'id': boinc_host.id,
        'p_model': boinc_host.p_model,
        "user": {
            "name": user.name
        },
        "fc_host": {
            'package_id': None if host is None else host.package_id,
            "id": None if host is None else host.id,
            "boinc_host_id": None if host is None else host.boinc_host_id,
            'power': None if host is None else host.power,
            'status_text': None if host is None else HostStatus(host.status).name,
            'time': None if host is None else host.time.strftime("%Y-%m-%dT%H:%M:%S"),
            'status': None if host is None else host.status,
        },
        'domain_name': boinc_host.domain_name
    }

    return result


def json_from_charset(charset):
    item = {
        "time": charset.time,
        "id": charset.id,
        "name": charset.name
    }

    return item


class TestAPIHashcat(unittest.TestCase):
    def test_hc_attack_modes(self):
        file = open(config.in_files["API"]["attack_modes"])
        exp_attack_modes = json.loads(file.read())
        file.close()

        api_r = requests.get(config.API['base'] + "/hashcat/attackModes")

        self.assertEqual(200, api_r.status_code)
        self.assertEqual(exp_attack_modes, api_r.json())

    def test_hc_hash_types(self):
        file = open(config.in_files["API"]["hash_types"])
        exp_hash_types = json.loads(file.read())
        file.close()

        api_r = requests.get(config.API['base'] + "/hashcat/hashTypes")
        self.assertEqual(200, api_r.status_code, "status code")
        self.assertEqual(exp_hash_types, api_r.json())


class TestAPIHosts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        count = get_hosts_count()
        to_add = 120 - count
        test_package = get_test_package()
        bench_package = get_bench_all_package()
        add_host(test_package.id, count=int(to_add/2))
        add_host(bench_package.id, count=int(to_add/2))

    def verify_hosts(self, api_r, page=1, status="", order_by="", per_page=25, name=""):
        if per_page == 0:
            per_page = 25
        if page == 0:
            page = 1

        json = api_r.json()
        self.assertEqual(json["per_page"], per_page)
        self.assertEqual(json["page"], page)
        api_items = json["items"]
        self.assertTrue(len(api_items) <= per_page, "Hosts count")

        db_items = []

        hosts = session.query(Host).offset(per_page * (page - 1)).limit(per_page).all()
        if len(hosts) == 0:
            self.assertEqual(404, api_r.status_code, "status code")
        else:
            self.assertEqual(200, api_r.status_code, "status code")

        # TODO: order_by
        for boinc_host in hosts:
            appended = False
            host = get_host_by_boinc_host_id(boinc_host.id)
            user = get_user(boinc_host.id)
            if name != "":
                if user is not None and name == user.name:
                    db_items.append(db_item_from_boinc_host(boinc_host))
                    appended = True

            if status != "":
                if host is not None and status == HostStatus(host.status).name:
                    db_items.append(db_item_from_boinc_host(boinc_host))
                    appended = True

            if not appended:
                db_items.append(db_item_from_boinc_host(boinc_host))

        db_items.reverse()
        print("db items:")
        for item in db_items:
            print(item)

        print("api items:")
        for item in api_items:
            print(item)

        self.assertEqual(len(db_items), len(api_items), "Hosts count")
        self.assertEqual(json["total"], len(api_items), "total count should be same as length of item list")
        self.assertTrue(api_items == db_items)
        # for item in api_items:
        #    with self.subTest(item=item):
        #        self.assertTrue(item in db_items, "")

    @staticmethod
    def exercise_hosts(page, status="", order_by="", per_page=25, name=""):
        url = config.API["base"] + "/hosts/?page=" + str(page)

        if status != "":
            url += "&status=" + status

        if order_by != "":
            url += "&order_by=" + order_by

        if per_page != 0:
            url += "&per_page=" + str(per_page)

        if name != "":
            url += "&name=" + str(name.replace(" ", "%20"))

        print("url:", url)
        api_r = requests.get(url)

        return api_r
        # TODO: wtf is descending?

    @unittest.skip("just for testing tests")
    def test_subtest(self):
        for page in [1, 2]:
            with self.subTest(page=page):
                api_r = self.exercise_hosts(page)
                self.verify_hosts(api_r, page)

    @unittest.skip("No way this will works")
    def test_hosts_all_params(self):
        for page in [1, 2]:
            for status in ["", "active", "inactive"]:
                # for order_by in ["", "domain_name", "os_model", "p_model", "time", "status"]:
                for per_page in [0, 10, 25, 50, 100]:
                    for name in ["", "BENCH_ALL", "Testing Package"]:
                        with self.subTest(page=page, status=status, per_page=per_page, name=name):
                            api_r = self.exercise_hosts(page, status, per_page=per_page, name=name)
                            self.verify_hosts(api_r, page, status, per_page=per_page, name=name)

    def test_hosts_page(self):
        for page in [1, 2]:
            with self.subTest(page=page):
                api_r = self.exercise_hosts(page)
                self.verify_hosts(api_r, page)

    def test_hosts_per_page(self):
        for per_page in [0, 10, 25, 100]:
            with self.subTest(per_page=per_page):
                api_r = self.exercise_hosts(page=1, per_page=per_page)
                self.verify_hosts(api_r, page=1, per_page=per_page)

    # TODO: kombinacie page a per_page

    def test_hosts_status(self):
        for status in ["", "active", "inactive"]:
            with self.subTest(status=status):
                api_r = self.exercise_hosts(page=1, status=status)
                self.verify_hosts(api_r, page=1, status=status)

    def test_hosts_name(self):
        for name in ["", "BENCH_ALL", "Testing Package"]:
            with self.subTest(name=name):
                api_r = self.exercise_hosts(page=1, name=name)
                self.verify_hosts(api_r, page=1, name=name)

    @unittest.skip("TODO:")
    def test_hosts_order_by(self):
        for order_by in ["", "domain_name", "os_model", "p_model", "time", "status"]:
            with self.subTest(order_by=order_by):
                api_r = self.exercise_hosts(page=1, order_by=order_by)
                self.verify_hosts(api_r, page=1, order_by=order_by)

        # TODO: co je X-fields v API?

    def test_host_info(self):
        hosts = get_all_boinc_hosts()
        active_hosts = 0
        for host in hosts:
            if is_host_active(host.id):
                active_hosts += 1
        inactive_hosts = len(hosts) - active_hosts

        expected_json = {
            "totalHosts": len(hosts),
            "activeHosts": active_hosts,
            "inactiveHosts": inactive_hosts
        }

        api_r = requests.get(config.API['base'] + "/hosts/info")
        self.assertEqual(200, api_r.status_code, "status code")
        self.assertEqual(expected_json, api_r.json())

    def test_hosts(self):
        hosts = get_all_boinc_hosts()
        for host in hosts:
            with self.subTest(host_id=host.id):
                expected_json = db_item_from_boinc_host(host)

                api_r = requests.get(config.API["base"] + "/hosts/" + str(host.id))

                self.assertEqual(200, api_r.status_code, "status code")
                self.assertEqual(expected_json, api_r.json())


class TestAPIServerInfo(unittest.TestCase):
    def test_server_info(self):
        api_r = requests.get(config.API['base'] + "/serverInfo/info")
        self.assertEqual(200, api_r.status_code, "status code")

        info = get_server_info()

        self.assertEqual(info, api_r.json())

    # @unittest.skip("for now")
    def test_server_info_control(self):
        # TODO: better controls tests
        kill_all_modules_except()

        api_r = requests.get(config.API['base'] + "/serverInfo/control?operation=start")
        self.assertEqual(200, api_r.status_code, "status code")
        info = get_server_info()
        for subsystems in info["subsystems"]:
            for name in iter(subsystems):
                self.assertTrue(subsystems[name])

        api_r = requests.get(config.API['base'] + "/serverInfo/control?operation=restart")
        self.assertEqual(200, api_r.status_code, "status code")
        info = get_server_info()
        for subsystems in info["subsystems"]:
            for name in iter(subsystems):
                self.assertTrue(subsystems[name])

        api_r = requests.get(config.API['base'] + "/serverInfo/control?operation=stop")
        self.assertEqual(200, api_r.status_code, "status code")
        info = get_server_info()
        for subsystems in info["subsystems"]:
            for name in iter(subsystems):
                self.assertFalse(subsystems[name])

        api_r = requests.get(config.API['base'] + "/serverInfo/control?operation=restart")
        self.assertEqual(200, api_r.status_code, "status code")
        info = get_server_info()
        for subsystems in info["subsystems"]:
            for name in iter(subsystems):
                self.assertTrue(subsystems[name])


class TestAPICharsets(unittest.TestCase):
    def test_charsets(self):
        charsets = get_all_charsets()
        db_items = []
        for charset in charsets:
            db_items.append(json_from_charset(charset))

        db_items.reverse()

        api_r = requests.get(config.API["base"] + "/charset")
        self.assertEqual(200, api_r.status_code, "status code")
        self.assertEqual(db_items, api_r.json()["items"])

    def test_charset(self):
        charsets = get_all_charsets()
        for charset in charsets:
            with self.subTest(charset_id=charset.id):
                api_r = requests.get(config.API["base"] + "/charset/" + charset.id)
                self.assertEqual(200, api_r.status_code, "status code")
                self.assertEqual(api_r.json(), charset_model(charset))

    def test_update_charset(self):
        # TODO:
        pass

    def test_download_charset(self):
        # TODO:
        pass

    def test_post_charset(self):
        # TODO:
        pass


class TestAPIRules(unittest.TestCase):
    def test_rules(self):
        # TODO:
        pass

    def test_rule(self):
        # TODO:
        pass

    def test_post_rule(self):
        # TODO:
        pass

    def test_upload_rule(self):
        # TODO:
        pass

    def test_download_rule(self):
        # TODO:
        pass


class TestAPIMasks(unittest.TestCase):
    def test_masks(self):
        # TODO:
        pass

    def test_mask(self):
        # TODO:
        pass

    def test_post_mask(self):
        # TODO:
        pass

    def test_upload_mask(self):
        # TODO:
        pass

    def test_download_mask(self):
        # TODO:
        pass


class TestAPIDictionary(unittest.TestCase):
    def test_dictionaries(self):
        # TODO:
        pass

    def test_dictionary(self):
        # TODO:
        pass

    def test_post_dictionary(self):
        # TODO:
        pass


class TestAPIUsers(unittest.TestCase):
    def test_users(self):
        # TODO
        pass


class TestAPIJobs(unittest.TestCase):
    def test_jobs(self):
        # TODO
        pass
