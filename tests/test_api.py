#!/usr/bin/python3
import json
import os
import sys
import unittest

import requests
from sqlalchemy import func

import config
from api_response_models import charset_model, rule_model, dict_model, package_model, \
    db_item_from_boinc_host, db_item_from_package, json_from_collection_item, job_model, \
    json_from_status
from database.service import is_host_active, session, get_hosts_count, add_host, \
    get_bench_all_package, get_test_package, get_all_boinc_hosts, \
    get_all_charsets, ensure_test_package, add_charset, get_test_charset, get_all_rules, \
    get_test_rule, add_rule, get_all_dictionaries, get_test_dict, add_test_dict, get_all_packages, \
    get_package, set_attr, \
    delete_package, ensure_user, add_boinc_host, assign_host_to_package, get_active_boinc_hosts, \
    get_jobs, add_job, get_rule_by_name, delete_record, get_charset_by_name, get_dict_by_name
from fc_test_library import get_server_info, kill_all_modules_except, PackageStatus
from src.database.models import Host, FcHostActivity, FcPackage, FcHost


class TestAPIHashcat(unittest.TestCase):
    def test_hc_attack_modes(self):
        file = open(config.in_files["API"]["attack_modes"])
        exp_attack_modes = json.loads(file.read())
        file.close()

        api_r = requests.get(config.API['base'] + "/hashcat/attackModes")

        self.assertEqual(requests.codes.ok, api_r.status_code)
        self.assertEqual(exp_attack_modes, api_r.json())

    def test_hc_hash_types(self):
        file = open(config.in_files["API"]["hash_types"])
        exp_hash_types = json.loads(file.read())
        file.close()

        api_r = requests.get(config.API['base'] + "/hashcat/hashTypes")
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)
        self.assertEqual(exp_hash_types, api_r.json())


wasSuccessful = True


class TestAPIHosts(unittest.TestCase):
    name_list = ["", "test", "green rabbit"]
    page_list = [1, 2]
    status_list = ["", "active", "inactive"]
    order_list = ["", "domain_name", "os_name", "p_model", "time", "status"]
    desc_list = [None, False, True]
    per_page_list = [0, 10, 25, 50, 100]

    @classmethod
    def setUpClass(cls):
        cls.maxDiff = None
        count = get_hosts_count()
        to_add = 120 - count
        test_package = ensure_test_package()
        bench_package = get_bench_all_package()
        add_host(test_package.id, count=int(to_add / 2))
        add_host(bench_package.id, count=int(to_add / 2))

    @unittest.skipUnless(False, "Every other test case in class passed")
    def test_x_hosts_all_params(self):
        for page in self.page_list:
            for status in self.status_list:
                for order_by in self.order_list:
                    for desc in self.desc_list:
                        for per_page in self.per_page_list:
                            for name in self.name_list:
                                with self.subTest(page=page, status=status, per_page=per_page,
                                                  name=name, order_by=order_by, descending=desc):
                                    api_r = self.exercise_hosts(page, status, per_page=per_page,
                                                                name=name, order_by=order_by,
                                                                descending=desc)
                                    self.verify_hosts(api_r, page, status, per_page=per_page,
                                                      name=name, order_by=order_by, descending=desc)

    def test_hosts_page(self):
        for page in self.page_list:
            with self.subTest(page=page):
                api_r = self.exercise_hosts(page)
                self.verify_hosts(api_r, page)

    def test_hosts_per_page(self):
        for per_page in self.per_page_list:
            with self.subTest(per_page=per_page):
                api_r = self.exercise_hosts(page=1, per_page=per_page)
                self.verify_hosts(api_r, page=1, per_page=per_page)

    def test_hosts_status(self):
        for status in self.status_list:
            with self.subTest(status=status):
                api_r = self.exercise_hosts(page=1, status=status)
                self.verify_hosts(api_r, page=1, status=status)

    def test_hosts_name(self):
        for name in self.name_list:
            with self.subTest(name=name):
                api_r = self.exercise_hosts(page=1, name=name)
                self.verify_hosts(api_r, page=1, name=name)

    def test_hosts_order_by(self):
        for order_by in self.order_list:
            with self.subTest(order_by=order_by):
                api_r = self.exercise_hosts(page=1, order_by=order_by)
                self.verify_hosts(api_r, page=1, order_by=order_by)

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
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)
        self.assertEqual(expected_json, api_r.json())

    def test_hosts(self):
        hosts = get_all_boinc_hosts()
        for host in hosts:
            with self.subTest(host_id=host.id):
                expected_json = db_item_from_boinc_host(host)

                api_r = requests.get(config.API["base"] + "/hosts/" + str(host.id))

                self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)
                self.assertEqual(expected_json, api_r.json())

    def verify_hosts(self, api_r, page=1, status="", order_by="", per_page=25, name="",
                     descending=None):
        if per_page == 0:
            per_page = 25
        if page == 0:
            page = 1

        db_items = []

        q = session.query(Host)
        if name != "":
            q = q.filter(Host.domain_name.like("%" + name + "%"))
        if status == "active":
            q = q.filter(Host.id.in_(session.query(FcHostActivity.boinc_host_id)))
        elif status == "inactive":
            q = q.filter(~Host.id.in_(session.query(FcHostActivity.boinc_host_id)))
        if order_by != "":
            try:
                order_by = getattr(Host, order_by)
            except AttributeError:
                self.assertEqual(400, api_r.status_code, api_r.text)
                return

            if descending:
                order_by.desc()

            q = q.order_by(order_by)
        else:
            q = q.order_by(Host.id.desc())

        if q.count() < (page - 1) * per_page:
            self.assertEqual(404, api_r.status_code, api_r.text)
            return

        hosts = q.offset(per_page * (page - 1)).limit(per_page).all()
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)

        for host in hosts:
            db_items.append(db_item_from_boinc_host(host))

        api_json = api_r.json()
        self.assertEqual(api_json["per_page"], per_page)
        self.assertEqual(api_json["page"], page)
        api_items = api_json["items"]
        self.assertTrue(len(api_items) <= per_page, "Hosts count")

        self.assertEqual(api_json["total"], len(api_items), "total count should be same as length "
                                                            "of item list")
        self.assertEqual(db_items, api_items, "db items:\n" +
                         str([i for i in db_items]) + "\napi items:" + str([i for i in api_items]))

    @staticmethod
    def exercise_hosts(page, status="", order_by="", per_page=25, name="", descending=None):
        params = {
            "page": page,
        }

        if status != "":
            params["status"] = status

        if order_by != "":
            params["order_by"] = order_by

        if per_page != 0:
            params["per_page"] = per_page

        if name != "":
            params["name"] = name

        if descending is not None:
            params["descending"] = descending

        api_r = requests.get(config.API["base"] + "/hosts/", params=params)

        return api_r


class TestAPIServerInfo(unittest.TestCase):
    def test_server_info(self):
        api_r = requests.get(config.API['base'] + "/serverInfo/info")
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)

        info = get_server_info()

        self.assertEqual(info, api_r.json())

    @unittest.skip("for now")
    def test_server_info_control(self):
        # TODO: better controls tests
        kill_all_modules_except()

        api_r = requests.get(config.API['base'] + "/serverInfo/control?operation=start")
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)
        info = get_server_info()
        for subsystems in info["subsystems"]:
            for name in iter(subsystems):
                self.assertTrue(subsystems[name])

        api_r = requests.get(config.API['base'] + "/serverInfo/control?operation=restart")
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)
        info = get_server_info()
        for subsystems in info["subsystems"]:
            for name in iter(subsystems):
                self.assertTrue(subsystems[name])

        api_r = requests.get(config.API['base'] + "/serverInfo/control?operation=stop")
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)
        info = get_server_info()
        for subsystems in info["subsystems"]:
            for name in iter(subsystems):
                self.assertFalse(subsystems[name])

        api_r = requests.get(config.API['base'] + "/serverInfo/control?operation=restart")
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)
        info = get_server_info()
        for subsystems in info["subsystems"]:
            for name in iter(subsystems):
                self.assertTrue(subsystems[name])


class TestAPICharsets(unittest.TestCase):
    def setUp(self):
        charset = get_test_charset()
        if charset is None:
            path = config.charsets["path"] + "test_charset"
            with open(path, "w") as f:
                f.write("?l?l?l?l")
            add_charset(name="test_charset", path=path)

        else:
            with open(charset.path, "r+") as f:
                ch = f.read()
                if ch != "?l?l?l?l":
                    f.seek(0)
                    f.truncate()
                    f.write("?l?l?l?l")

    def test_charsets(self):
        charsets = get_all_charsets()
        db_items = []
        for charset in charsets:
            db_items.append(json_from_collection_item(charset))

        db_items = sorted(db_items, key=lambda item: item["id"])

        api_r = requests.get(config.API["base"] + "/charset")
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)

        api_items = api_r.json()["items"]

        self.assertEqual(db_items, api_items, "db items:\n" +
                         str([i for i in db_items]) + "\napi items:" + str([i for i in api_items]))

    def test_charset(self):
        charsets = get_all_charsets()
        for charset in charsets:
            with self.subTest(charset_id=charset.id):
                api_r = requests.get(config.API["base"] + "/charset/" + str(charset.id))
                self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)
                self.assertEqual(api_r.json(), charset_model(charset))

    def test_update_charset(self):
        charset = get_test_charset()
        json_charset = charset_model(charset)
        old_data = json_charset["data"]
        new_data = old_data + "?l?l"
        json_charset["data"] = new_data

        api_r = requests.post(config.API["base"] + "/charset/" + str(json_charset["id"]) +
                              "/update", {"newCharset": new_data})
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)
        self.assertEqual(True, api_r.json()["status"])

    def test_download_charset(self):
        test_charset = get_test_charset()
        json_charset = charset_model(test_charset)
        api_r = requests.get(config.API["base"] + "/charset/" + str(test_charset.id) + "download")
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)
        self.assertEqual(json_charset, api_r.json())

    def test_post_charset(self):
        name = "new_charset.hcchr"
        path = config.charsets["path"] + name
        charset = get_charset_by_name(name)

        if charset is not None:
            delete_record(charset)

        if os.path.isfile(path):
            os.remove(path)

        with open(name, "w") as f:
            f.write("?a?a?a")

        f = open(name, "rb")
        api_r = requests.post(config.API["base"] + "/charset", files={"file": f})
        f.close()
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)
        self.assertTrue(api_r.json()["status"])


class TestAPIRules(unittest.TestCase):
    url = config.API["base"] + "/rule/"

    def setUp(self):
        rule = get_test_rule()
        if rule is None:
            path = config.rules["path"] + "test_rule"
            with open(path, "w") as f:
                f.write("l")
            add_rule(name="test_rule", path=path)

        else:
            with open(rule.path, "r+") as f:
                ch = f.read()
                if ch != "l":
                    f.seek(0)
                    f.truncate()
                    f.write("l")

    def test_rules(self):
        rules = get_all_rules()
        db_items = []
        for rule in rules:
            db_items.append(json_from_collection_item(rule))

        db_items = sorted(db_items, key=lambda item: item["id"])

        api_r = requests.get(config.API["base"] + "/rule")
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)

        api_items = api_r.json()["items"]

        self.assertEqual(db_items, api_items, "db items:\n" +
                         str([i for i in db_items]) + "\napi items:" + str([i for i in api_items]))

    def test_rule(self):
        rules = get_all_rules()
        for rule in rules:
            with self.subTest(rule_id=rule.id):
                model = rule_model(rule)
                api_r = requests.get(config.API["base"] + "/rule/" + str(rule.id))
                self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)
                self.assertEqual(model, api_r.json(), "model:" + str(model) +
                                 "\napi:" + str(api_r.json()))

    def test_post_rule(self):
        name = "new_rule.rule"
        rule = get_rule_by_name(name)
        if rule is not None:
            delete_record(rule)

        path = config.rules["path"] + name
        if os.path.isfile(path):
            os.remove(path)

        with open(name, "w") as f:
            f.write("c")

        f = open(name, "rb")
        api_r = requests.post(self.url, files={"file": f})
        f.close()
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)
        self.assertTrue(api_r.json()["status"])

    def test_update_rule(self):
        rule = get_test_rule()
        json_rule = rule_model(rule)
        new_data = "c"
        json_rule["data"] = new_data

        api_r = requests.post(config.API["base"] + "/rule/" + str(json_rule["id"]) +
                              "/update", {"newRule": new_data})
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)
        self.assertEqual(True, api_r.json()["status"])

    def test_download_rule(self):
        test_rule = get_test_rule()
        json_rule = rule_model(test_rule)
        api_r = requests.get(config.API["base"] + "/rule/" + str(test_rule.id) + "download")
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)
        self.assertEqual(json_rule, api_r.json())


class TestAPIDictionary(unittest.TestCase):
    url = config.API["base"] + "/dictionary/"

    def setUp(self):
        d = get_test_dict()
        if d is None:
            add_test_dict()

    def test_dictionaries(self):
        dictionaries = get_all_dictionaries()
        db_items = []
        for dictionary in dictionaries:
            db_items.append(json_from_collection_item(dictionary))

        db_items = sorted(db_items, key=lambda item: item["id"])

        api_r = requests.get(self.url)
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)

        api_items = api_r.json()["items"]

        self.assertEqual(db_items, api_items, "db items:\n" +
                         str([i for i in db_items]) + "\napi items:" + str([i for i in api_items]))

    def test_dictionary(self):
        test_dict = get_test_dict()
        expected_json = dict_model(test_dict)

        api_r = requests.get(self.url + str(test_dict.id))
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)
        self.assertEqual(expected_json, api_r.json())

    def test_post_dictionary(self):
        name = "new_dict"
        d = get_dict_by_name(name)
        if d is not None:
            delete_record(d)

        path = config.dictionaries["path"] + name
        if os.path.isfile(path):
            os.remove(path)

        with open(name, "w") as f:
            f.write("c")

        f = open(name, "rb")
        api_r = requests.post(self.url, files={"file": f})
        f.close()
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)
        self.assertTrue(api_r.json()["status"])


class TestAPIPackage(unittest.TestCase):
    url = config.API["base"] + "/jobs/"

    maxDiff = None

    package_status_list = [s.name for s in PackageStatus]
    # package_status_list.append("yellow")
    host_status_list = ["", "active", "inactive", "something"]
    order_list = ["", "name", "time", "progress", "attack_mode", "status", "weight_of_sun"]
    attack_mode_list = ["", "dict", "brute", "biggest"]
    name_list = ["", "Test", "blue_bear"]
    page_list = [1, 2]
    per_page_list = [10, 25, 50, 100]
    desc_list = [None, False, True]

    def setUp(self):
        ensure_test_package()

    def tearDown(self):
        package = get_test_package()
        if package is not None:
            delete_package(package.id)

    @classmethod
    def tearDownClass(cls):
        hosts = session.query(Host)
        for host in hosts:
            session.delete(host)

        session.commit()

    def test_package(self):
        packages = get_all_packages()
        for p in packages:
            with self.subTest(package_id=p.id):
                expected_json = package_model(p)

                api_r = requests.get(self.url + str(p.id))

                self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)
                self.assertEqual(expected_json, api_r.json(), "expected:" + str(expected_json) +
                                 "\napi:" + str(api_r.json()))

    def test_packages_page(self):
        for page in self.page_list:
            with self.subTest(page=page):
                api_r = self.exercise_packages(page)
                self.verify_packages(api_r, page=page)

    def test_packages_per_page(self):
        for per_page in self.per_page_list:
            with self.subTest(per_page=per_page):
                api_r = self.exercise_packages(page=1, per_page=per_page)
                self.verify_packages(api_r, page=1, per_page=per_page)

    def test_packages_name(self):
        for name in self.name_list:
            with self.subTest(name=name):
                api_r = self.exercise_packages(page=1, name=name)
                self.verify_packages(api_r, page=1, name=name)

    def test_packages_attack_mode(self):
        for attack_mode in self.attack_mode_list:
            with self.subTest(attack_mode=attack_mode):
                api_r = self.exercise_packages(page=1, attack_mode=attack_mode)
                self.verify_packages(api_r, page=1, attack_mode=attack_mode)

    def test_packages_order_by(self):
        for order_by in self.order_list:
            for desc in self.desc_list:
                with self.subTest(order_by=order_by, descending=desc):
                    api_r = self.exercise_packages(page=1, order_by=order_by, descending=desc)
                    self.verify_packages(api_r, page=1, order_by=order_by, descending=desc)

    def test_packages_status(self):
        for status in self.package_status_list:
                with self.subTest(status=status):
                    api_r = self.exercise_packages(page=1, status=status)
                    self.verify_packages(api_r, page=1, status=status)

    def test_add_package(self):
        package = FcPackage(name="test_add", seconds_per_job=3600, hash_type=0,
                            hash=config.runner["test_hash"], status=0, indexes_verified=0,
                            hc_keyspace=0, cracking_time=0)

        json_package = package_model(package)
        json_package["time_start"] = ""
        json_package["time_end"] = ""
        json_package["seconds_per_job"] = int(json_package["seconds_per_job"])
        json_package["comment"] = "test comment"

        api_r = requests.post(self.url, json=json_package)
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)

    def test_package_info(self):
        statuses = session.query(FcPackage.status, func.count(FcPackage.id)). \
            group_by(FcPackage.status).all()
        expected = []
        for status in statuses:
            expected.append(json_from_status(status))

        api_r = requests.get(self.url + "info")
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)
        self.assertEqual(expected, api_r.json())

    def test_verify_hash_ok(self):
        h = config.runner["test_hash"]
        params = {
            "hash": h,
            "hashtype": 0
        }
        api_r = requests.get(self.url + "verifyHash", params=params)
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)
        self.assertEqual(h, api_r.json()["hash"])
        self.assertTrue(api_r.json()["result"])

    def test_verify_hash_error(self):
        h = "randomString57318648432134"
        params = {
            "hash": h,
            "hashtype": 49000
        }
        api_r = requests.get(self.url + "verifyHash", params=params)
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)
        self.assertEqual(h, api_r.json()["hash"])
        self.assertFalse(api_r.json()["result"])

    def test_delete_package_ok(self):
        test_package = ensure_test_package()
        test_package_id = test_package.id

        api_r = requests.delete(self.url + str(test_package_id))
        self.assertEqual(204, api_r.status_code, api_r.text)
        session.expire(test_package)
        package = get_package(test_package_id)
        self.assertIsNone(package)

    def test_delete_package_error(self):
        package_id = ensure_test_package().id
        old_count = len(get_all_packages())

        package_id += 1
        package = get_package(package_id)
        while package is not None:
            package_id += 1
            package = get_package(package_id)

        api_r = requests.delete(self.url + str(package_id))
        self.assertEqual(404, api_r.status_code, api_r.text)
        count = len(get_all_packages())
        self.assertEqual(old_count, count)

    def test_package_start(self):
        package = ensure_test_package()
        set_attr(package, "status", 0)
        api_r = requests.get(self.url + str(package.id) + "/action", params={"operation": "start"})
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)
        session.expire(package)
        self.assertEqual(10, package.status)

    def test_package_stop(self):
        package = ensure_test_package()
        set_attr(package, "status", 10)
        api_r = requests.get(self.url + str(package.id) + "/action", params={"operation": "stop"})
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)
        session.expire(package)
        self.assertEqual(0, package.status)

    def test_package_restart(self):
        package = ensure_test_package()
        set_attr(package, "status", 0)
        params = {
            "operation": "restart"
        }

        api_r = requests.get(self.url + str(package.id) + "/action", params=params)
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)
        session.expire(package)
        self.assertEqual(10, package.status)

    def test_package_hosts_zero(self):
        package_id = get_test_package().id
        api_r = self.exercise_package_hosts(package_id)
        self.verify_package_hosts(api_r, package_id)

    def test_package_hosts_page(self):
        package_id = get_test_package().id
        # 3 pages(per page default is 25):
        #           -> 1 full,
        #           -> 1 half full
        #           -> 1 empty
        for i in range(0, 27):
            add_host(package_id)
        host = add_host(package_id)
        assign_host_to_package(host.boinc_host_id, package_id)
        for page in self.page_list:
            with self.subTest(page=page):
                api_r = self.exercise_package_hosts(package_id, page=page)
                self.verify_package_hosts(api_r, package_id, page=page)

    def test_package_hosts_per_page(self):
        package_id = get_test_package().id
        # for per page: 10  -> 3 pages
        #               25  -> 2 pages
        #               50  -> 1 page
        #               100 -> 1 page
        for i in range(0, 27):
            add_host(package_id)
        for per_page in self.per_page_list:
            with self.subTest(per_page=per_page):
                api_r = self.exercise_package_hosts(package_id, per_page=per_page)
                self.verify_package_hosts(api_r, package_id, per_page=per_page)

    def test_package_hosts_name(self):
        package_id = get_test_package().id
        # one host
        add_host(package_id)
        # one with changed boinc host
        host = add_host(package_id)
        user = ensure_user()
        boinc_host = add_boinc_host(user.id)
        set_attr(boinc_host, "domain_name", "Test")
        set_attr(host, "boinc_host_id", boinc_host.id)
        for name in self.name_list:
            with self.subTest(name=name):
                api_r = self.exercise_package_hosts(package_id, name=name)
                self.verify_package_hosts(api_r, package_id, name=name)

    def test_package_hosts_status(self):
        package_id = get_test_package().id
        # one inactive host
        add_host(package_id)
        # one active host
        host = add_host(package_id)
        assign_host_to_package(host.boinc_host_id, package_id)
        for status in self.host_status_list:
            with self.subTest(status=status):
                api_r = self.exercise_package_hosts(package_id, status=status)
                self.verify_package_hosts(api_r, package_id, status=status)

    def test_package_hosts_order_by(self):
        package_id = get_test_package().id
        # default host
        add_host(package_id)
        # host with new boinc_host
        host = add_host(package_id)
        user = ensure_user()
        boinc_host = add_boinc_host(user.id)
        set_attr(host, "boinc_host_id", boinc_host.id)
        for order_by in self.order_list:
            for desc in self.desc_list:
                with self.subTest(order_by=order_by, descending=desc):
                    api_r = self.exercise_package_hosts(package_id, page=1, order_by=order_by,
                                                        descending=desc)
                    self.verify_package_hosts(api_r, package_id, page=1, order_by=order_by,
                                              descending=desc)

    def test_package_add_hosts(self):
        package = ensure_test_package()
        user = ensure_user()
        b_host1 = add_boinc_host(user.id)
        b_host2 = add_boinc_host(user.id)

        assign_host_to_package(b_host1.id, package.id)
        assign_host_to_package(b_host2.id, package.id)

        b_host1 = add_boinc_host(user.id)
        b_host2 = add_boinc_host(user.id)

        new_hosts_ids = [b_host1.id, b_host2.id]
        params = {"newHost_ids": new_hosts_ids}

        api_r = requests.post(self.url + str(package.id) + "/host", json=params)
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)
        self.assertEqual(True, api_r.json()["status"])

        session.expire_all()
        hosts = get_active_boinc_hosts(package.id)
        hosts_ids = [h.id for h in hosts]
        self.assertEqual(new_hosts_ids, hosts_ids)

    def test_package_jobs(self):
        package = get_test_package()
        for i in range(0, 2):
            add_job(package.id)

        for page in self.page_list:
            for per_page in self.per_page_list:
                with self.subTest(page=page, per_page=per_page):
                    api_r = self.exercise_package_jobs(package.id, page=page, per_page=per_page)
                    self.verify_package_jobs(api_r, package.id, page=page, per_page=per_page)

    def exercise_packages(self, page, per_page=25, status="", order_by="", name="",
                          attack_mode="", descending=None):
        params = {
            "page": page,
        }

        if status != "":
            params["status"] = status

        if order_by != "":
            params["order_by"] = order_by,

        if per_page != 0:
            params["per_page"] = per_page

        if name != "":
            params["name"] = name

        if attack_mode != "":
            params["attack_mode"] = attack_mode

        if descending is not None:
            params["descending"] = descending

        api_r = requests.get(self.url, params=params)

        return api_r

    def verify_packages(self, api_r, page=1, per_page=25, status="", order_by="", name="",
                        attack_mode="", descending=None):
        if per_page == 0:
            per_page = 25
        if page == 0:
            page = 1

        db_items = []

        q = session.query(FcPackage)
        if name != "":
            q = q.filter(FcPackage.name.like("%" + name + "%"))
        if status != "":
            q = q.filter(FcPackage.status == PackageStatus[status].value)
        if attack_mode != "":
            q = q.filter(FcPackage.attack == attack_mode)
        if order_by != "":
            try:
                order_by = getattr(FcPackage, order_by)
            except AttributeError:
                self.assertEqual(400, api_r.status_code, api_r.text)
                return

            if descending:
                order_by = order_by.desc()

            q = q.order_by(order_by)
        else:
            q = q.order_by(FcPackage.id.desc())

        if q.count() < (page - 1) * per_page:
            self.assertEqual(404, api_r.status_code, api_r.text)
            return

        packages = q.offset(per_page * (page - 1)).limit(per_page).all()
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)

        for p in packages:
            db_items.append(db_item_from_package(p))

        api_json = api_r.json()
        self.assertEqual(api_json["per_page"], per_page)
        self.assertEqual(api_json["page"], page)
        api_items = api_json["items"]
        self.assertTrue(len(api_items) <= per_page, "Hosts count")

        print("db items:")
        for item in db_items:
            print(item)

        print("api items:")
        for item in api_items:
            print(item)

        self.assertEqual(api_json["total"], len(api_items), "total count should be same as length "
                                                            "of item list")
        self.assertEqual(db_items, api_items, "db items:\n" +
                         str([i for i in db_items]) + "\napi items:" + str([i for i in api_items]))

    def exercise_package_jobs(self, package_id, page=1, per_page=25):
        params = {}
        if page != 0:
            params["page"] = page
        if per_page != 0:
            params["per_page"] = per_page

        api_r = requests.get(self.url + str(package_id) + "/job", params)

        return api_r

    def verify_package_jobs(self, api_r, package_id, page=1, per_page=25):
        if page == 0:
            page = 1
        if per_page == 0:
            per_page = 25

        jobs = get_jobs(package_id)
        db_items = [job_model(job) for job in jobs]

        if len(db_items) < per_page * (page - 1):
            self.assertEqual(404, api_r.status_code, api_r.text)
            return
        else:
            self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)

        api_json = api_r.json()
        self.assertEqual(page, api_json["page"])
        self.assertEqual(per_page, api_json["per_page"])
        self.assertEqual(len(db_items), api_json["total"])
        self.assertEqual(int((len(db_items) - 1) / per_page) + 1, api_json["pages"])

        api_items = api_r.json()["items"]
        self.assertEqual(db_items, api_items, "db items:\n" +
                         str([i for i in db_items]) + "\napi items:" + str([i for i in api_items]))

    def exercise_package_hosts(self, package_id, page=1, per_page=25, name="", status="",
                               order_by="", descending=None):
        params = {}
        if page != 0:
            params["page"] = page

        if per_page != 0:
            params["per_page"] = per_page

        if name != "":
            params["name"] = name

        if status != "":
            params["status"] = status

        if order_by != "":
            params["order_by"] = order_by

        if descending is not None:
            params["descending"] = descending

        api_r = requests.get(self.url + str(package_id) + "/host", params=params)
        return api_r

    def verify_package_hosts(self, api_r, package_id, page=1, per_page=25, name="", status="",
                             order_by="", descending=None):
        if per_page == 0:
            per_page = 25
        if page == 0:
            page = 1

        db_items = []

        q = session.query(Host).filter(Host.id.in_(session.query(FcHost.boinc_host_id).filter(
            FcHost.package_id == package_id)))
        if name != "":
            q = q.filter(Host.domain_name.like("%" + name + "%"))
        if status == "active":
            q = q.filter(Host.id.in_(session.query(FcHostActivity.boinc_host_id)))
        elif status == "inactive":
            q = q.filter(~Host.id.in_(session.query(FcHostActivity.boinc_host_id)))
        if order_by != "":
            try:
                order_by = getattr(Host, order_by)
            except AttributeError:
                self.assertEqual(400, api_r.status_code, api_r.text)
                return

            if descending:
                order_by.desc()

            q = q.order_by(order_by)
        else:
            q = q.order_by(Host.id.desc())

        if q.count() < (page - 1) * per_page:
            self.assertEqual(404, api_r.status_code, api_r.text)
            return

        hosts = q.offset(per_page * (page - 1)).limit(per_page).all()
        self.assertEqual(requests.codes.ok, api_r.status_code, api_r.text)

        for host in hosts:
            db_items.append(db_item_from_boinc_host(host))

        api_json = api_r.json()
        self.assertEqual(api_json["per_page"], per_page)
        self.assertEqual(api_json["page"], page)
        api_items = api_json["items"]

        self.assertLessEqual(len(api_items), per_page, "Hosts count")

        self.assertEqual(api_json["total"], len(api_items), "total count should be same as length "
                                                            "of item list")
        self.assertEqual(db_items, api_items, "db items:\n" +
                         str([i for i in db_items]) + "\napi items:" + str([i for i in api_items]))


# runs all tests in this file if file is run as normal python script
if __name__ == '__main__':
    sys.stdout = open('API_tests_output.txt', 'w')
    unittest.main(verbosity=3)
