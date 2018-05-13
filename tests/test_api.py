import datetime
import json
import sys
import unittest

import requests
from sqlalchemy import func

import config
from api_response_models import charset_model, rule_model, mask_model, dict_model, package_model
from database.service import is_host_active, session, get_user, get_host_by_boinc_host_id, \
    get_hosts_count, add_host, get_bench_all_package, get_test_package, get_all_boinc_hosts, \
    get_all_charsets, ensure_test_package, add_charset, get_test_charset, get_all_rules, \
    get_test_rule, add_rule, get_test_mask, get_all_dictionaries, ensure_example_dict, \
    get_test_dict, add_test_dict, get_all_packages, get_package, set_attr, get_hosts, \
    delete_package, ensure_user, add_boinc_host, assign_host_to_package, get_active_boinc_hosts
from fc_test_library import HostStatus, get_server_info, kill_all_modules_except, PackageStatus
from src.database.models import Host, FcCharset, FcDictionary, FcHostActivity, FcPackage


def db_item_from_boinc_host(boinc_host):
    active = is_host_active(boinc_host.id)
    host = get_host_by_boinc_host_id(boinc_host.id)
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


def db_item_from_package(package):
    result = {
        "cracking_time": float(package.cracking_time),
        "comment": package.comment,
        "time": package.time.strftime("%Y-%m-%dT%H:%M:%S"),
        "time_end": None if package.time_end is None else package.time_end.strftime(
            "%Y-%m-%d %H:%M:%S"),
        "result": package.result,
        "id": package.id,
        "time_start": None if package.time_start is None else package.time_start.strftime(
            "%Y-%m-%d %H:%M:%S"),
        "hash_type": str(package.hash_type),
        "attack": package.attack,
        "status_type": "info",
        "hash": package.hash,
        "priority": None,
        "password": package.password,
        "progress": 100 if package.indexes_verified == package.hc_keyspace else
        package.indexes_verified / package.hc_keyspace * 100,
        "status_text": PackageStatus(package.status).name,
        "attack_mode": str(package.attack_mode),
        "name": package.name,
        "status": str(package.status),
    }

    return result


def json_from_collection_item(item):
    json_item = {
        "time": item.time.strftime("%Y-%m-%dT%H:%M:%S"),
        "id": item.id,
        "name": item.name
    }

    if isinstance(item, FcDictionary):
        json_item["keyspace"] = item.keyspace

    return json_item


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
    name_list = ["", "test", "zeleny_zajo"]
    page_list = [1, 2]
    status_list = ["", "active", "inactive"]
    order_list = ["", "domain_name", "os_name", "p_model", "time", "status"]
    desc_list = [None, False, True]
    per_page_list = [0, 10, 25, 50, 100]

    @classmethod
    def setUpClass(cls):
        count = get_hosts_count()
        to_add = 120 - count
        test_package = ensure_test_package()
        bench_package = get_bench_all_package()
        add_host(test_package.id, count=int(to_add / 2))
        add_host(bench_package.id, count=int(to_add / 2))

    @unittest.skip("just for testing tests")
    def test_subtest(self):
        for page in self.page_list:
            with self.subTest(page=page):
                api_r = self.exercise_hosts(page)
                self.verify_hosts(api_r, page)

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

    # TODO: kombinacie page a per_page

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

    def verify_hosts(self, api_r, page=1, status="", order_by="", per_page=25, name="",
                     descending=None):
        if per_page == 0:
            per_page = 25
        if page == 0:
            page = 1

        db_items = []

        q = session.query(Host)
        if name != "":
            print("name:", name)
            q = q.filter(Host.domain_name.like("%" + name + "%"))
        if status == "active":
            q = q.filter(Host.id.in_(session.query(FcHostActivity.boinc_host_id)))
        elif status == "inactive":
            q = q.filter(~Host.id.in_(session.query(FcHostActivity.boinc_host_id)))
        if order_by != "":
            try:
                order_by = getattr(Host, order_by)
            except AttributeError:
                self.assertEqual(400, api_r.status_code, "status code")
                return

            if descending:
                order_by.desc()

            q = q.order_by(order_by)
        else:
            q = q.order_by(Host.id.desc())

        if q.count() < (page - 1) * per_page:
            self.assertEqual(404, api_r.status_code, "status code")
            return

        hosts = q.offset(per_page * (page - 1)).limit(per_page).all()
        self.assertEqual(200, api_r.status_code, "status code")

        for host in hosts:
            db_items.append(db_item_from_boinc_host(host))

        json = api_r.json()
        self.assertEqual(json["per_page"], per_page)
        self.assertEqual(json["page"], page)
        api_items = json["items"]
        self.assertTrue(len(api_items) <= per_page, "Hosts count")

        print("db items:")
        for item in db_items:
            print(item)

        print("api items:")
        for item in api_items:
            print(item)

        self.assertEqual(len(db_items), len(api_items), "Hosts count")
        self.assertEqual(json["total"], len(api_items), "total count should be same as length of "
                                                        "item list")
        self.assertEqual(api_items, db_items)

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
        # TODO: wtf is descending?


class TestAPIServerInfo(unittest.TestCase):
    def test_server_info(self):
        api_r = requests.get(config.API['base'] + "/serverInfo/info")
        self.assertEqual(200, api_r.status_code, "status code")

        info = get_server_info()

        self.assertEqual(info, api_r.json())

    @unittest.skip("for now")
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
        self.assertEqual(200, api_r.status_code, "status code")

        print("db items:")
        for i in db_items:
            print(i)

        api_items = api_r.json()["items"]
        print("api items:")
        for i in api_items:
            print(i)

        self.assertEqual(db_items, api_items)

    def test_charset(self):
        charsets = get_all_charsets()
        for charset in charsets:
            with self.subTest(charset_id=charset.id):
                api_r = requests.get(config.API["base"] + "/charset/" + str(charset.id))
                self.assertEqual(200, api_r.status_code, "status code")
                self.assertEqual(api_r.json(), charset_model(charset))

    def test_update_charset(self):
        charset = get_test_charset()
        json_charset = charset_model(charset)
        old_data = json_charset["data"]
        new_data = old_data + "?l?l"
        json_charset["data"] = new_data

        api_r = requests.post(config.API["base"] + "/charset/" + str(json_charset["id"]) +
                              "/update", {"newCharset": new_data})
        self.assertEqual(200, api_r.status_code, "status code")
        self.assertEqual(True, api_r.json()["status"])

    def test_download_charset(self):
        test_charset = get_test_charset()
        json_charset = charset_model(test_charset)
        api_r = requests.get(config.API["base"] + "/charset/" + str(test_charset.id) + "download")
        self.assertEqual(200, api_r.status_code, "status code")
        self.assertEqual(json_charset, api_r.json())

    @unittest.skip("How to upload file?")
    def test_post_charset(self):
        # TODO:
        path = config.charsets["path"] + "charset.hcchr"
        with open(path, "w") as f:
            f.write("?a?a?a")

        file = {"file": open(path, "r")}
        api_r = requests.post(config.API["base"] + "/charset", files=file)
        self.assertEqual(200, api_r.status_code, api_r.text)
        print(api_r.json())


class TestAPIRules(unittest.TestCase):
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
        self.assertEqual(200, api_r.status_code, "status code")

        print("db items:")
        for i in db_items:
            print(i)

        api_items = api_r.json()["items"]
        print("api items:")
        for i in api_items:
            print(i)

        self.assertEqual(db_items, api_items)

    def test_rule(self):
        rules = get_all_rules()
        for rule in rules:
            with self.subTest(rule_id=rule.id):
                api_r = requests.get(config.API["base"] + "/rule/" + str(rule.id))
                self.assertEqual(200, api_r.status_code, "status code")
                self.assertEqual(api_r.json(), rule_model(rule))

    @unittest.skip("How to upload file?")
    def test_post_rule(self):
        # TODO:
        pass

    def test_update_rule(self):
        rule = get_test_rule()
        json_rule = rule_model(rule)
        new_data = "c"
        json_rule["data"] = new_data

        api_r = requests.post(config.API["base"] + "/rule/" + str(json_rule["id"]) +
                              "/update", {"newRule": new_data})
        self.assertEqual(200, api_r.status_code, "status code")
        self.assertEqual(True, api_r.json()["status"])

    def test_download_rule(self):
        test_rule = get_test_rule()
        json_rule = rule_model(test_rule)
        api_r = requests.get(config.API["base"] + "/rule/" + str(test_rule.id) + "download")
        self.assertEqual(200, api_r.status_code, "status code")
        self.assertEqual(json_rule, api_r.json())


class TestAPIDictionary(unittest.TestCase):
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

        api_r = requests.get(config.API["base"] + "/dictionary")
        self.assertEqual(200, api_r.status_code, "status code")

        print("db items:")
        for i in db_items:
            print(i)

        api_items = api_r.json()["items"]
        print("api items:")
        for i in api_items:
            print(i)

        self.assertEqual(db_items, api_items)

    def test_dictionary(self):
        test_dict = get_test_dict()
        expected_json = dict_model(test_dict)

        api_r = requests.get(config.API["base"] + "/dictionary/" + str(test_dict.id))
        self.assertEqual(200, api_r.status_code, "status code")
        print("db:", expected_json)
        print("api:", api_r.json())
        self.assertEqual(expected_json, api_r.json())

    @unittest.skip("How to upload file?")
    def test_post_dictionary(self):
        # TODO:
        pass


class TestAPIJobs(unittest.TestCase):
    url = config.API["base"] + "/jobs/"

    status_list = [s.name for s in PackageStatus].append("yellow")
    order_list = ["", "name", "time", "progress", "attack_mode", "status", "weight_of_sun"]
    attack_mode_list = ["", "dict", "brute", "biggest"]
    name_list = ["", "Test", "blue_bear"]
    page_list = [1, 2]
    per_page_list = [10, 25, 50, 100]
    desc_list = [None, False, True]

    # TODO: neplatne hodnoty
    # TODO: saturovat db

    def setUp(self):
        ensure_test_package()

    def tearDown(self):
        package = get_test_package()
        if package is not None:
            delete_package(package.id)

    def test_packages(self):
        packages = get_all_packages()
        self.maxDiff = None
        for p in packages:
            with self.subTest(package_id=p.id):
                expected_json = package_model(p)

                api_r = requests.get(self.url + str(p.id))

                print("expected:", expected_json)
                print("api:", api_r.json())
                self.assertEqual(200, api_r.status_code, "status code")
                self.assertEqual(expected_json, api_r.json())

    def test_package_page(self):
        for page in self.page_list:
            with self.subTest(page=page):
                api_r = self.exercise_packages(page)
                self.verify_packages(api_r, page=page)

    def test_package_per_page(self):
        for per_page in self.per_page_list:
            with self.subTest(per_page=per_page):
                api_r = self.exercise_packages(page=1, per_page=per_page)
                self.verify_packages(api_r, page=1, per_page=per_page)

    def test_package_name(self):
        for name in self.name_list:
            with self.subTest(name=name):
                api_r = self.exercise_packages(page=1, name=name)
                self.verify_packages(api_r, page=1, name=name)

    def test_package_attack_mode(self):
        for attack_mode in self.attack_mode_list:
            with self.subTest(attack_mode=attack_mode):
                api_r = self.exercise_packages(page=1, attack_mode=attack_mode)
                self.verify_packages(api_r, page=1, attack_mode=attack_mode)

    def test_package_order_by(self):
        for order_by in self.order_list:
            for desc in self.desc_list:
                with self.subTest(order_by=order_by, descending=desc):
                    api_r = self.exercise_packages(page=1, order_by=order_by, descending=desc)
                    self.verify_packages(api_r, page=1, order_by=order_by, descending=desc)

    def test_add_package(self):
        package = FcPackage(name="test_add", seconds_per_job=3600, hash_type=0,
                            hash=config.runner["test_hash"], status=0, indexes_verified=0,
                            hc_keyspace=0, cracking_time=0)

        json_package = package_model(package)
        json_package["time_start"] = ""
        json_package["time_end"] = ""
        json_package["seconds_per_job"] = int(json_package["seconds_per_job"])
        json_package["comment"] = "test comment"
        print(json_package)

        api_r = requests.post(self.url, json=json_package)
        print(api_r.content)
        self.assertEqual(200, api_r.status_code, "status code")

    def test_package_info(self):
        statuses = session.query(FcPackage.status, func.count(FcPackage.id)). \
            group_by(FcPackage.status).all()
        expected = []
        for status in statuses:
            expected.append(self.json_from_status(status))

        api_r = requests.get(self.url + "info")
        self.assertEqual(200, api_r.status_code, "status code")
        self.assertEqual(expected, api_r.json())

    def test_verify_hash_ok(self):
        h = config.runner["test_hash"]
        params = {
            "hash": h,
            "hashtype": 0
        }
        api_r = requests.get(self.url + "verifyHash", params=params)
        self.assertEqual(200, api_r.status_code, "status code")
        self.assertEqual(h, api_r.json()["hash"])
        self.assertTrue(api_r.json()["result"])

    def test_verify_hash_error(self):
        h = "randomString57318648432134"
        params = {
            "hash": h,
            "hashtype": 49000
        }
        api_r = requests.get(self.url + "verifyHash", params=params)
        self.assertEqual(200, api_r.status_code, "status code")
        self.assertEqual(h, api_r.json()["hash"])
        self.assertFalse(api_r.json()["result"])

    def test_delete_package_ok(self):
        test_package_id = ensure_test_package().id

        api_r = requests.delete(self.url + str(test_package_id))
        self.assertEqual(204, api_r.status_code, "status code")
        package = get_package(test_package_id)
        self.assertIsNone(package)

    def test_delete_package_error(self):
        id = ensure_test_package().id
        old_count = len(get_all_packages())

        id += 1
        package = get_package(id)
        while package is not None:
            id += 1
            package = get_package(id)

        api_r = requests.delete(self.url + str(id))
        self.assertEqual(404, api_r.status_code, "status code")
        count = len(get_all_packages())
        self.assertEqual(old_count, count)

    def test_package_start(self):
        package = ensure_test_package()
        set_attr(package, "status", 0)
        api_r = requests.get(self.url + str(package.id) + "/action", params={"operation": "start"})
        self.assertEqual(200, api_r.status_code, "status code")
        session.expire(package)
        self.assertEqual(10, package.status)

    def test_package_stop(self):
        package = ensure_test_package()
        set_attr(package, "status", 10)
        api_r = requests.get(self.url + str(package.id) + "/action", params={"operation": "stop"})
        self.assertEqual(200, api_r.status_code, "status code")
        session.expire(package)
        self.assertEqual(0, package.status)

    def test_package_restart(self):
        package = ensure_test_package()
        set_attr(package, "status", 0)
        api_r = requests.get(self.url + str(package.id) + "/action", params={"operation":
                                                                                 "restart"})
        self.assertEqual(200, api_r.status_code, "status code")
        session.expire(package)
        self.assertEqual(10, package.status)

    def test_package_hosts(self):
        # TODO:
        pass

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
        self.assertEqual(200, api_r.status_code, "status code")
        self.assertEqual(True, api_r.json()["status"])

        session.expire_all()
        hosts = get_active_boinc_hosts(package.id)
        hosts_ids = [h.id for h in hosts]
        self.assertEqual(new_hosts_ids, hosts_ids)

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
            q = q.filter(FcPackage.status == PackageStatus(status).value)
        if attack_mode != "":
            q = q.filter(FcPackage.attack == attack_mode)
        if order_by != "":
            try:
                order_by = getattr(FcPackage, order_by)
            except AttributeError:
                self.assertEqual(400, api_r.status_code, "status code")
                return

            if descending:
                order_by = order_by.desc()

            q = q.order_by(order_by)
        else:
            q = q.order_by(FcPackage.id.desc())

        if q.count() < (page - 1) * per_page:
            self.assertEqual(404, api_r.status_code, "status code")
            return

        packages = q.offset(per_page * (page - 1)).limit(per_page).all()
        self.assertEqual(200, api_r.status_code, "status code")

        for p in packages:
            db_items.append(db_item_from_package(p))

        json = api_r.json()
        self.assertEqual(json["per_page"], per_page)
        self.assertEqual(json["page"], page)
        api_items = json["items"]
        self.assertTrue(len(api_items) <= per_page, "Hosts count")

        print("db items:")
        for item in db_items:
            print(item)

        print("api items:")
        for item in api_items:
            print(item)

        self.assertEqual(len(db_items), len(api_items), "Packages count")
        self.assertEqual(json["total"], len(api_items), "total count should be same as length of "
                                                        "item list")
        self.assertEqual(api_items, db_items)

    @staticmethod
    def json_from_status(status):

        return {
            'status': PackageStatus(status[0]).name,
            'count': status[1]
        }
