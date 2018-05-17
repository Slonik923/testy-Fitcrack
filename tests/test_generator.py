#!/usr/bin/python3
import os
import sys
from time import sleep
from xml.etree import ElementTree as ET

from config import *
from database.service import *
from fc_test_library import *


class TestGenerator(unittest.TestCase):
    """
    Class for generator tests
    """
    tested_module = "sample_work_generator"
    appid = 0

    @classmethod
    def setUpClass(cls):
        cls.delete_all()

        cls.appid = get_app_version().appid

        ensure_example_dict()

    def setUp(self):
        make_run_only(self.tested_module)

    def tearDown(self):
        self.delete_all()

    @classmethod
    def tearDownClass(cls):
        start_daemons()

    def test_del_fin_host(self):
        """
        Generator should deletes all host with finished package
        """
        package_id = add_package().id
        host = add_host(package_id)
        host_id = host.id

        set_package_status(package_id, PackageStatus.finished)

        self.assertTrue(is_running(self.tested_module),
                        str(self.tested_module) + " not running anymore")
        host_count = session.query(FcHost).filter(FcHost.package_id == host_id).count()
        self.assertEqual(host_count, 0, "Hosts with finished package should be deleted")

    def test_del_exh_host(self):
        """
        Generator should deletes all host with exhausted package
        """
        package_id = add_package().id
        host = add_host(package_id)
        host_id = host.id

        set_package_status(package_id, PackageStatus.exhausted)

        self.assertTrue(is_running(self.tested_module),
                        str(self.tested_module) + "not running anymore")

        host_count = session.query(FcHost).filter(FcHost.package_id == host_id).count()
        self.assertEqual(host_count, 0, "Hosts with exhausted package should be deleted")

    def test_passed_time(self):
        """
        Package with end time < time now and nothing to crack should be set to status finishing
        """

        time = datetime.datetime.now() - datetime.timedelta(minutes=1)
        time = time.strftime("%Y-%m-%d %H:%M:%S")
        package = add_package(time_end=time, status=PackageStatus.running)
        add_job(package.id, 0, hc_keyspace=42)

        self.wait_for_generator_db(expected_val=PackageStatus.finishing.value, obj=package,
                                   attr="status")
        self.assertEqual(PackageStatus.finishing.value, package.status)
        self.assertTrue(is_running(self.tested_module),
                        str(self.tested_module) + "not running anymore")

    def test_package_set_start_time(self):
        """
        Generator should set start time to running package if it was not set yet
        """
        package = add_package(time_start=None, status=PackageStatus.running)

        self.wait_for_generator_sleep()

        self.assertGreater(package.time_start.timestamp(), 0,
                           "Package should have the time set")

    def test_make_benchmark(self):
        """
        Tests generator ability to create benchmark job
        """
        package = add_package(status=PackageStatus.running)

        assign_host_to_package(boinc_host.id, package.id)

        self.wait_for_generator_sleep()

        host = session.query(FcHost).filter(FcHost.boinc_host_id == boinc_host.id). \
            filter(FcHost.status == HostStatus.benchmark.value).order_by(FcHost.time.desc()).first()

        self.assertIsNotNone(host)

        job = session.query(FcJob).filter(FcJob.host_id == host.id).one()

        wu = session.query(WorkUnit).filter(WorkUnit.id == job.workunit_id).one_or_none()

        self.assertIsNotNone(wu)
        self.assertEqual(job.package_id, package.id)
        self.assertEqual(job.workunit_id, wu.id)
        self.assertEqual(job.host_id, host.id)
        self.assertEqual(job.boinc_host_id, boinc_host.id)
        self.assertTrue(is_running(self.tested_module),
                        str(self.tested_module) + "not running anymore")

        xml_doc = wu.xml_doc
        path = self.find_file_from_xml(xml_doc)
        self.assertNotEqual(path, "", "Couldn't found config file")
        f = open(path)
        self.assertIsNotNone(f, "Couldn't open config file")
        file = f.read()
        f.close()
        self.assertNotEqual(0, len(file), "Config file is empty")
        try:
            output = FitcrackTLVConfig.from_string(file)
        except ValueError as err:
            self.fail(err)

        self.verify_tlv_benchmark(output)

    def test_add_host_to_package(self):
        """
        Generator should change package id of host, when host is assigned to package
        """
        package = add_package(status=PackageStatus.running)

        assign_host_to_package(boinc_host.id, package.id)

        self.wait_for_generator_sleep()

        host = get_host(package.id)
        self.assertIsNotNone(host)
        self.assertEqual(host.package_id, package.id)

    def test_enough_jobs(self):
        """
        Every Host should have planned max 2 jobs
        """
        package = add_package(status=PackageStatus.running)

        add_host(package_id=package.id, status=HostStatus.normal)
        num_jobs = 2
        add_job(package.id, 0, count=num_jobs, hc_keyspace=2)

        assign_host_to_package(boinc_host.id, package.id)

        self.wait_for_generator_sleep()

        jobs = get_jobs(package.id)
        self.assertEqual(num_jobs, len(jobs))
        self.assertTrue(is_running(self.tested_module),
                        str(self.tested_module) + "not running anymore")

    def test_make_job_dict(self):
        """
        Verifies if generator plans new job for dictionary attack
        """
        c = FitcrackTLVConfig.create(attack_mode=AttackModes.dictionary, hash_type=0,
                                     name="test make job dict")
        package = add_package(status=PackageStatus.running, attack_mode=AttackModes.dictionary,
                              dict1=config.in_files["example_dict"]["name"], config_str=str(c))
        add_host(package.id, status=HostStatus.normal, power=1500000000)

        assign_host_to_package(boinc_host.id, package.id)

        self.wait_for_generator_sleep()

        jobs = get_jobs(package.id)
        self.assertIsNotNone(jobs)
        self.assertEqual(1, len(jobs))
        job = None
        for j in jobs:
            if j.workunit_id != 0:
                job = j

        self.assertIsNotNone(job)
        self.assertTrue(is_running(self.tested_module),
                        str(self.tested_module) + "not running anymore")

        output = self.verify_workunit(job.workunit_id)
        self.verify_tlv_normal(output, attack_mode=AttackModes.dictionary, hash_type=0)

    def test_make_job_comb(self):
        """
        Verifies if generator plans new job for combination attack
        """
        d = config.in_files["example_dict"]["name"]
        c = FitcrackTLVConfig.create(attack_mode=AttackModes.combination, hash_type=0,
                                     name="test make job combination")
        package = add_package(status=PackageStatus.running, attack_mode=AttackModes.combination,
                              config_str=str(c), dict1=d, dict2=d)
        add_host(package.id, power=15000000000, status=HostStatus.normal)

        assign_host_to_package(boinc_host.id, package.id)

        self.wait_for_generator_sleep()
        set_package_status(package.id, PackageStatus.finished)

        jobs = get_jobs(package.id)
        self.assertEqual(1, len(jobs))
        job = None
        for j in jobs:
            if j.workunit_id != 0:
                job = j

        self.assertIsNotNone(job)
        self.assertTrue(is_running(self.tested_module),
                        str(self.tested_module) + "not running anymore")

        output = self.verify_workunit(job.workunit_id)

        self.verify_tlv_normal(output, attack_mode=AttackModes.combination, hash_type=0)

    def test_make_job_mask(self):
        """
        Verifies if generator plans new job for combination attack
        """
        package = add_package(status=PackageStatus.running, attack_mode=AttackModes.mask)
        add_mask(package.id, mask="?l?l?l?l?l?l?l?d?d?d", keyspace=8031810176000,
                 hc_keyspace=456976000)
        add_host(package.id, status=HostStatus.normal, power=1500000000)

        assign_host_to_package(boinc_host.id, package.id)

        self.wait_for_generator_sleep()

        jobs = get_jobs(package.id)
        self.assertEqual(len(jobs), 1)
        job = None
        for j in jobs:
            if j.workunit_id != 0:
                job = j

        self.assertIsNotNone(job)
        self.assertTrue(is_running(self.tested_module),
                        str(self.tested_module) + "not running anymore")

        output = self.verify_workunit(job.workunit_id)
        self.verify_tlv_normal(output, attack_mode=AttackModes.mask, hash_type=0)

    def test_make_job_error(self):
        """
        Verifies, that generator will be working normally after getting not expected attack mode
        """
        package = add_package(status=PackageStatus.running, attack_mode=42)
        add_host(package.id, status=HostStatus.normal, power=1500000000)
        add_job(package.id, 0)

        assign_host_to_package(boinc_host.id, package.id)

        self.wait_for_generator_sleep()

        self.assertEqual(package.status, PackageStatus.malformed.value)
        self.assertTrue(is_running(self.tested_module),
                        str(self.tested_module) + "not running anymore")

    def test_set_job_fin(self):
        """
        Generator should set package to finishing, when end time > now time
        """
        c = FitcrackTLVConfig.create(attack_mode=AttackModes.dictionary, hash_type=0,
                                     name="test make job dict")
        package = add_package(status=PackageStatus.running, attack_mode=AttackModes.dictionary,
                              dict1=config.in_files["example_dict"]["name"], config_str=str(c))
        add_host(package.id, status=HostStatus.normal, power=42)
        add_job(package.id, hc_keyspace=0)

        assign_host_to_package(boinc_host.id, package.id)

        self.wait_for_generator_db(obj=package, attr="status",
                                   expected_val=PackageStatus.finishing.value)

        self.assertTrue(is_running(self.tested_module),
                        str(self.tested_module) + "not running anymore")
        set_package_status(package.id, PackageStatus.finished)

    def test_retry_job_dict(self):
        """
        Generator should duplicate retry job
        """
        c = FitcrackTLVConfig.create(attack_mode=AttackModes.dictionary, hash_type=0,
                                     name="test make job dict")
        package = add_package(status=PackageStatus.finishing, attack_mode=AttackModes.dictionary,
                              dict1=config.in_files["example_dict"]["name"], config_str=str(c))
        add_host(package.id, status=HostStatus.normal, power=2)
        job = add_job(package.id, 0, retry=1, hc_keyspace=42)

        assign_host_to_package(boinc_host.id, package.id)

        self.wait_for_generator_sleep()

        new_job = self.find_duplicated_job(job)

        self.verify_duplicated_jobs(job, new_job)

    def test_retry_job_comb(self):
        """
        Generator should duplicate retry job
        """
        d = config.in_files["example_dict"]["name"]
        c = FitcrackTLVConfig.create(attack_mode=AttackModes.combination, hash_type=0,
                                     name="test make job combination")
        package = add_package(status=PackageStatus.finishing, attack_mode=AttackModes.combination,
                              config_str=str(c), dict1=d, dict2=d)
        add_host(package.id, power=2, status=HostStatus.normal)
        job = add_job(package.id, 0, retry=1, hc_keyspace=42)

        assign_host_to_package(boinc_host.id, package.id)

        self.wait_for_generator_sleep()

        new_job = self.find_duplicated_job(job)

        self.verify_duplicated_jobs(job, new_job)

    def test_retry_job_mask(self):
        """
        Generator should duplicate retry job
        """
        package = add_package(status=PackageStatus.finishing, attack_mode=AttackModes.mask)
        mask = add_mask(package.id, mask="?l?l?l?l?l?l?l?d?d?d", keyspace=8031810176000,
                        hc_keyspace=456976000)
        add_host(package.id, status=HostStatus.normal, power=20000)
        job = add_job(package.id, 0, retry=1, hc_keyspace=42000, mask_id=mask.id)

        assign_host_to_package(boinc_host.id, package.id)

        self.wait_for_generator_sleep()

        new_job = self.find_duplicated_job(job)

        self.verify_duplicated_jobs(job, new_job)

    def test_package_fin_no_new_job(self):
        """
        When all keyspace was searched package status should be set to finishing
        """
        package = add_package(status=PackageStatus.finishing, attack_mode=AttackModes.dictionary)
        add_host(package.id, status=HostStatus.normal, power=0)

        assign_host_to_package(boinc_host.id, package.id)

        self.wait_for_generator_sleep()

        jobs = get_jobs(package.id)
        self.assertEqual(0, len(jobs), "Job was generated")

    def test_set_package_timeout(self):
        """
        Finishing package with end time in past and no running jobs should be set to timeout
        """
        time = datetime.datetime.now() - datetime.timedelta(minutes=1)
        time = time.strftime("%Y-%m-%d %H:%M:%S")
        package = add_package(time_end=time, status=PackageStatus.finishing)

        self.wait_for_generator_db(obj=package, attr="status",
                                   expected_val=PackageStatus.timeout.value)

    def test_set_package_exhausted(self):
        """
        When current index of cracking password > hc_keyspace and password was not found package
        status should be exhausted
        """
        package = add_package(status=PackageStatus.finishing, hc_keyspace=42, current_idex=43)

        self.wait_for_generator_db(obj=package, attr="status",
                                   expected_val=PackageStatus.exhausted.value)

    def test_set_package_ready(self):
        """
        When all jobs are done, package is paused/ready
        """
        package = add_package(status=PackageStatus.finishing)

        self.wait_for_generator_db(obj=package, attr="status",
                                   expected_val=PackageStatus.ready.value)

    def wait_for_generator_sleep(self, wait=3):
        sleep(wait)
        self.assertTrue(is_running(self.tested_module), "Module not running")

    def wait_for_generator_log(self, mod_time, timeout=10):
        dif = 0.5
        while os.path.getmtime(logs_path + self.tested_module + ".log") == mod_time:
            self.assertNotEqual(timeout, 0, "Timeout")
            sleep(dif)
            timeout -= dif
        self.assertTrue(is_running(self.tested_module), "Module not running")

    def wait_for_generator_db(self, expected_val, obj, attr, timeout=10):
        self.assertIsNotNone(obj)
        dif = 0.5
        while getattr(obj, attr) != expected_val:
            self.assertNotEqual(timeout, 0, str(obj) + "." + attr + " is " +
                                str(getattr(obj, attr)) + " not " + str(expected_val))
            sleep(dif)
            timeout -= dif
            session.expire(obj)

        self.assertTrue(is_running(self.tested_module), "Module not running")

    @staticmethod
    def find_file_from_xml(file):
        file = file.decode("utf-8")

        # root element needs to be added
        new_file = file.replace("\n", "\n\t")
        new_file = "<root>\n\t" + new_file
        new_file = new_file + "\n</root>"

        file_refs = []
        root = ET.fromstring(new_file)
        file_infos = root.findall("file_info")
        # finds all names al urls from xml_doc
        for info in file_infos:
            name = info.find("name")
            url = info.find("url")
            ref = {"name": name.text, "url": url.text}
            file_refs.append(ref)

        # each file have additional info
        # we need open_name value
        wu = root.find("workunit")
        file_infos = wu.findall("file_ref")
        for info in file_infos:
            name = info.find("file_name")
            open_name = info.find("open_name")
            for ref in file_refs:
                if ref["name"] == name.text:
                    ref["open_name"] = open_name.text
                    break

        # print("file references:", file_refs)

        # in xml_doc could be references to multiple files
        for ref in file_refs:
            if ref["open_name"] == "config":
                # ip address needs to be changed for project home directory
                pattern = re.compile("^http://((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
                                     "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/test_fitcrack/")
                m = re.match(pattern, ref["url"])
                if m:
                    return config.project["home"] + ref["url"][m.end():]
                else:
                    return ""

    @staticmethod
    def delete_all():
        graphs = session.query(FcPackageGraph)
        for graph in graphs:
            session.delete(graph)

        hosts = session.query(FcHost)
        for host in hosts:
            session.delete(host)

        activities = session.query(FcHostActivity)
        for activity in activities:
            session.delete(activity)

        jobs = session.query(FcJob)
        for job in jobs:
            session.delete(job)

        packages = session.query(FcPackage).filter(FcPackage.id != 1)
        for package in packages:
            session.delete(package)

        session.commit()

    def verify_tlv_benchmark(self, output, hash_type=0):
        self.assertIsNotNone(output, "TLV is None")
        self.assertEqual(output.mode, "b", "Mode should be benchmark")
        self.assertIsNotNone(output.hash_type)  # can be None?
        self.assertEqual(output.hash_type, hash_type, "Hash type")

    def verify_tlv_normal(self, output, attack_mode, hash_type, start_index=None,
                          hc_keyspace=None):
        if not isinstance(attack_mode, AttackModes):
            raise ValueError("attack_mode need to be instance of AttackModes Enum")
        attack_mode_name = AttackModesShort(attack_mode.value).name
        attack_mode_value = attack_mode.value

        self.assertIsNotNone(output, "TLV is None")
        self.assertEqual(output.mode, "n", "Mode should be normal")
        self.assertEqual(output.attack, attack_mode_name, "Attack")
        self.assertEqual(output.attack_mode, attack_mode_value, "Attack mode")
        self.assertEqual(output.hash_type, hash_type, "Hash type")
        if start_index is not None:
            self.assertEqual(output.start_index, start_index, "Start index")
        if hc_keyspace is not None:
            self.assertEqual(output.hc_keyspace, hc_keyspace, "Keyspace")

    def verify_workunit(self, wu_id):
        wu = get_workunit(wu_id)
        xml_doc = wu.xml_doc
        path = self.find_file_from_xml(xml_doc)
        self.assertNotEqual(path, "", "Couldn't found config file")
        f = open(path)
        self.assertIsNotNone(f, "Couldn't open config file")
        file = f.read()
        f.close()
        self.assertNotEqual(0, len(file), "Config file is empty")
        try:
            output = FitcrackTLVConfig.from_string(file)
        except ValueError as err:
            self.fail(err)

        return output

    def find_duplicated_job(self, job):
        jobs = get_jobs(job.package_id)
        self.assertIsNotNone(jobs, "Retry job should stay in db")
        self.assertEqual(2, len(jobs), "Generator should duplicate job")

        new_job = None
        for j in jobs:
            if j != job:
                new_job = j
                break

        return new_job

    def verify_duplicated_jobs(self, job, new_job):
        self.assertIsNotNone(new_job)
        self.assertEqual(new_job.retry, 0)
        self.assertEqual(new_job.finished, 0)
        self.assertEqual(new_job.duplicate, job.id)
        self.assertEqual(new_job.duplicated, 1)

        self.assertEqual(job.package_id, new_job.package_id)
        self.assertEqual(job.host_id, new_job.host_id)
        self.assertEqual(job.boinc_host_id, new_job.boinc_host_id)
        self.assertEqual(job.start_index, new_job.start_index)
        self.assertEqual(job.start_index_2, new_job.start_index_2)
        self.assertEqual(job.hc_keyspace, new_job.hc_keyspace)
        self.assertEqual(job.mask_id, new_job.mask_id)
        self.assertEqual(job.cracking_time, new_job.cracking_time)

        self.assertEqual(job.finished, 1)


if __name__ == '__main__':
    sys.stdout = open('test_generator_output.txt', 'w')
    unittest.main()
