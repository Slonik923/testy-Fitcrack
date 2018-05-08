import os
import subprocess
import unittest
from shutil import copy
from time import sleep
from xml.etree import ElementTree as Et

from database.service import *
from setup import is_running, make_run_only, start_daemons, RunnerOutput
from src.database.models import FcPackage, FcJob, FcHost, FcHashcache


class TestAssimilator(unittest.TestCase):
    """
    Class for testing assimilator
    """
    package_id = 0
    tested_module = "sample_assimilator"
    wu_id = 0
    appid = 0
    canonical_res = None

    @classmethod
    def setUpClass(cls):
        cls.delete_all()
        delete_all_packages_except_bench_all()

        cls.package_id = add_package().id
        print("adding package:", cls.package_id)

        cls.appid = get_app_version().appid

    @classmethod
    def tearDownClass(cls):
        # change back to default value
        set_delete_finished_jobs_setting(0)

        delete_all_packages_except_bench_all()

        # start all daemons after all tests are done
        start_daemons()

    def setUp(self):
        self.wu_id = add_workunit().id
        self.canonical_res = add_result(self.wu_id)
        make_run_only(self.tested_module)

        set_delete_finished_jobs_setting(0)

        if not is_package(self.package_id):
            print("SETUP ADDING FUCKEN PACKAGE!!!!")
            self.package_id = add_package().id

    def tearDown(self):
        pass
        self.delete_all()

    def test_bench_all_exists(self):
        """
        Tests if there is package for benchmarking new hosts
        """
        benchmark = get_bench_all_package()
        self.assertIsNotNone(benchmark, "Package BENCH_ALL does not exists")

    def test_bench_no_file(self):
        """
        Tests workunit with no runner output file
        """
        self.run_assimilate_handler()

    def test_bench_ok_mask(self):
        """
        Tests assimilation of successful benchmark
        """
        for delete_finished in [0, 1]:
            with self.subTest(delete_finished=delete_finished):
                set_delete_finished_jobs_setting(delete_finished)

                file_path = config.in_files["assimilator"]["bench_ok"]
                old_package = self.run_assimilate_handler(file_path)

                self.verify_assimilate_output(file_path, old_package)

    def test_bench_ok(self):
        """
        Tests assimilation of successful benchmark of mask attack
        keyspace is computed differently in mask attack
        """
        for delete_finished in [0, 1]:
            with self.subTest(delete_finished=delete_finished):
                set_delete_finished_jobs_setting(delete_finished)

                delete_package(self.package_id)

                self.package_id = add_package(token=test_package_token,
                                              attack="dict", attack_mode=0,
                                              keyspace=2437, hc_keyspace=2437,
                                              dict1="facebook-phished.txt",
                                              config_path=config.in_files["runner"][
                                                  "config_dict"]).id

                file_path = config.in_files["assimilator"]["bench_ok"]
                old_package = self.run_assimilate_handler(file_path)

                self.verify_assimilate_output(file_path, old_package)

    def test_bench_err(self):
        """
        Tests assimilation of benchmark task with error result
        """
        for delete_finished in [0, 1]:
            with self.subTest(delete_finished=delete_finished):
                set_delete_finished_jobs_setting(delete_finished)

                file_path = config.in_files["assimilator"]["bench_error"]
                old_package = self.run_assimilate_handler(file_path)

                self.verify_assimilate_output(file_path, old_package)

    def test_normal_found(self):
        """
        Tests assimilation of normal task, where password was found
        """
        for delete_finished in [0, 1]:
            with self.subTest(delete_finished=delete_finished):
                set_delete_finished_jobs_setting(delete_finished)

                file_path = config.in_files["assimilator"]["normal_found"]
                old_package = self.run_assimilate_handler(file_path)

                self.verify_assimilate_output(file_path, old_package)

    def test_normal_not_found(self):
        """
        Tests assimilation of normal task, where password was not found
        """
        for delete_finished in [0, 1]:
            with self.subTest(delete_finished=delete_finished):
                set_delete_finished_jobs_setting(delete_finished)

                file_path = config.in_files["assimilator"]["normal_not_found"]
                old_package = self.run_assimilate_handler(file_path)

                self.verify_assimilate_output(file_path, old_package)

    def test_normal_error(self):
        """
        Tests assimilation of normal task with error result
        """
        file_path = config.in_files["assimilator"]["normal_hc_error"]
        old_package = self.run_assimilate_handler(file_path)

        self.verify_assimilate_output(file_path, old_package)

    @classmethod
    def delete_all(cls):
        """
        deletes all lines from workunit and result tables
        """
        wus = session.query(WorkUnit)
        for wu in wus:
            session.delete(wu)

        results = session.query(Result)
        for result in results:
            session.delete(result)

        jobs = session.query(FcJob)
        for job in jobs:
            session.delete(job)

        hosts = session.query(FcHost)
        for host in hosts:
            session.delete(host)

        graphs = session.query(FcPackageGraph)
        for graph in graphs:
            session.delete(graph)

        caches = session.query(FcHashcache)
        for cache in caches:
            session.delete(cache)

        session.commit()

    @staticmethod
    def xml_doc_in(filename):
        """
        Create a xml file from template and modify it to contains path to
        filename in boinc directory hierarchy
        :param filename:
        :return: binary string of newly created file
        """
        tree = Et.parse(config.template["app_out"])
        root = tree.getroot()

        file_info = root.find("file_info")
        name_el = file_info.find("name")
        for child in name_el:
            name_el.remove(child)
        name_el.text = filename

        url_el = file_info.find("url")
        for child in url_el:
            url_el.remove(child)
        url_el.text = "http://" + config.server_ip + "/fitcrack_cgi/file_upload_handler"

        result = root.find("result")
        file_ref = result.find("file_ref")
        file_name_el = file_ref.find("file_name")
        for child in file_name_el:
            file_name_el.remove(child)
        file_name_el.text = filename

        tree.write("/home/boincadm/tests/in/result-xml_doc_in_test")
        f = open("/home/boincadm/tests/in/result-xml_doc_in_test", "br")
        result = f.read()
        f.close()

        return result

    @staticmethod
    def move_file_to_boinc_dir(file_path):
        """
        Move file to boinc directory hierarchy
        :param file_path:
        :return: filename without path
        """
        filename = os.path.basename(file_path)
        # boinc utility to determining right directory in boinc directory hierarchy
        process = subprocess.Popen(["/home/boincadm/boinc-src/tools/dir_hier_path", filename],
                                   cwd=config.project["home"], stdout=subprocess.PIPE)

        path, err = process.communicate()
        path = path.decode("ascii")
        path = path.strip()
        # we need upload directory, not download
        path = path.replace("download", "upload")

        dir_path = os.path.dirname(path)
        try:
            os.stat(dir_path)
        except FileNotFoundError:
            os.mkdir(dir_path)

        copy(file_path, path)

        return filename

    def verify_bench_ok(self, output, old_package):
        """
        Verifies that all attributes from output file are correctly inserted to the database
        output contains information from runner after successful benchmark
        :param output: Runner output object
        :param old_package: package before assimilator changed it
        :return:
        """
        package_id = old_package.id

        fc_host = session.query(FcHost).filter(FcHost.boinc_host_id == boinc_host.id). \
            filter(FcHost.package_id == package_id).first()

        self.assertIsNotNone(fc_host, "host not found in fc_host table")

        hash_type = old_package.hash_type
        benchmark = get_benchmark(boinc_host.id, hash_type)

        self.assertIsNotNone(benchmark, "benchmark not found")

        self.assertAlmostEqual(output.power, benchmark.power, "benchmark power")

        # mask attack keyspace returned from hashcat needs to be processed
        if old_package.attack_mode == 3:
            keyspace = int(old_package.keyspace)
            hc_keyspace = int(old_package.hc_keyspace)
            factor = int(keyspace / hc_keyspace)
            host_power = int(output.power / (factor * 3))
        else:
            host_power = output.power

        self.assertEqual(host_power, fc_host.power, "fc_host power")

        package = get_package(package_id)

        self.assertAlmostEqual(old_package.cracking_time + output.cracking_time,
                               package.cracking_time, "package cracking time")

        setting = get_settings()
        job = session.query(FcJob).filter(FcJob.package_id == package_id). \
            filter(FcJob.host_id == fc_host.id).filter(FcJob.boinc_host_id == boinc_host.id). \
            filter(FcJob.workunit_id == self.wu_id).first()
        if setting.delete_finished_jobs:
            self.assertIsNone(job, "job should be deleted")
        else:
            self.assertIsNotNone(job, "job shouldn't be deleted")
            self.assertAlmostEqual(output.cracking_time, job.cracking_time, "job cracking time")

    def verify_bench_error(self):
        """
        Verifies that all attributes from output file are correctly inserted to the database
        output contains information from runner after benchmark error occurred
        :return:
        """

        host = get_host(self.package_id)
        self.assertIsNotNone(host, "host not found in fc_host table")

        self.assertGreaterEqual(host.power, 1, "planning new benchmark")

    def verify_normal_found(self, output, old_package):
        """
        Verifies that all attributes from output file are correctly inserted to the database
        output contains information from runner after successful normal task in which password
        was found
        :param output: Runner Output object
        :param old_package: package before changes from assimilator
        :return:
        """
        package = get_package(self.package_id)
        self.assertIsNotNone(package, "Package should be in db")
        self.assertEqual(package.status, 1, "Package should be finished")
        self.assertEqual(package.result, output.password, "Package result")
        self.assertAlmostEqual(old_package.cracking_time + output.cracking_time,
                               package.cracking_time,
                               "package cracking time")

        fc_host = ensure_host(self.package_id)

        job = session.query(FcJob).filter(FcJob.package_id == self.package_id).filter(
            FcJob.host_id == fc_host.id). \
            filter(FcJob.boinc_host_id == boinc_host.id).filter(
            FcJob.workunit_id == self.wu_id).one_or_none()
        setting = get_settings()
        if setting.delete_finished_jobs:
            self.assertIsNone(job, "Job should be deleted")
        else:
            self.assertAlmostEqual(output.cracking_time, job.cracking_time, "job cracking time")

            jobs = session.query(FcJob).filter(FcJob.package_id == self.package_id)
            self.assertIsNotNone(jobs, "Job should stay in db")
            for job in jobs:
                self.assertEqual(job.finished, 1, "Job should be finished")

        caches = session.query(FcHashcache).filter(FcHashcache.hash_type == package.hash_type). \
            filter(FcHashcache.hash == package.hash)
        self.assertIsNotNone(caches, "Hash should be in cache")

    def verify_normal_not_found(self, output, old_package):
        """
        Verifies that all attributes from output file are correctly inserted to the database
        output contains information from runner after successful normal task in which password
        was not found
        :param output: Runner Output object
        :param old_package: package before changes from assimilator
        :return:
        """
        settings = get_settings()
        package = get_package(self.package_id)
        ensure_host(self.package_id)

        self.assertAlmostEqual(old_package.cracking_time + output.cracking_time,
                               package.cracking_time,
                               "package cracking time")

        job = session.query(FcJob).filter(FcJob.workunit_id == self.wu_id).one_or_none()
        if settings.delete_finished_jobs:
            self.assertIsNone(job, "Job should be deleted")
            self.assertGreaterEqual(package.indexes_verified, old_package.indexes_verified)
        else:
            self.assertAlmostEqual(output.cracking_time, job.cracking_time, places=2,
                                   msg="job cracking time")
            self.assertEqual(package.indexes_verified,
                             old_package.indexes_verified + job.hc_keyspace)

        # TODO: host cracking time

    def verify_normal_error(self):
        """
        Verifies that all attributes from output file are correctly inserted to the database
        output contains information from runner after normal task with error
        :return:
        """
        host = ensure_host(self.package_id)
        jobs = session.query(FcJob).filter(FcJob.package_id == self.package_id).filter(
            FcJob.host_id == host.id)
        for job in jobs:
            self.assertEqual(job.retry, 1, "job retry")

        self.assertEqual(host.power, 0)
        self.assertEqual(host.status, 0, "host should have status benchmark(0)")

    def verify_assimilate_output(self, filename, old_package):
        """
        Creates Runner Output file from filename and calls one of verification methods
        depending on runner output file
        :param filename: file name of runner output
        :param old_package: package before changes from assimilator
        :return:
        """
        with open(filename, "r") as f:
            file = f.read()
        runner_output = RunnerOutput(file)

        # benchmark
        if runner_output.mode == "b":
            if runner_output.status_code == 0:
                self.verify_bench_ok(runner_output, old_package)
            else:
                self.verify_bench_error()
        # normal mode
        elif runner_output.mode == "n":
            if runner_output.status_code == 0:
                self.verify_normal_found(runner_output, old_package)
            elif runner_output.status_code == 1:
                self.verify_normal_not_found(runner_output, old_package)
            else:
                self.verify_normal_error()
        # benchmark all
        elif runner_output.mode == "a":
            pass
            # TODO: test_bench_all

    def run_assimilate_handler(self, file_path=""):
        """
        Setups job, workunit, that assimilate_handler will be called
        Moves file to boinc directory hierarchy and creates xml file for workunit with filename
        :param file_path: uploads runner output
        :return: old package
        """
        if file_path != "":
            filename = self.move_file_to_boinc_dir(file_path)
            doc_in = self.xml_doc_in(filename)
        else:
            doc_in = None

        job_id = add_job(self.package_id, self.wu_id).id

        old_package = get_package(self.package_id)
        print("handler:", self.package_id)
        # TODO:
        self.assertIsNotNone(old_package, "nebuď kokot a daj to")
        session.expunge(old_package)

        set_wu_ready(self.wu_id, self.canonical_res.id, doc_in)

        settings = get_settings()
        timeout = 10
        dif = 0.5

        if settings.delete_finished_jobs:
            job = session.query(FcJob).filter(FcJob.id == job_id).one_or_none()
            while job is not None:
                self.assertNotEqual(timeout, 0, "Timeout")
                sleep(dif)
                timeout -= dif
                session.expire_all()
                job = session.query(FcJob).filter(FcJob.id == job_id).one_or_none()
        else:
            wu = get_workunit(self.wu_id)
            # waits till assimilate handler exits
            while wu.assimilate_state != 2:
                self.assertNotEqual(timeout, 0, "Timeout")
                sleep(dif)
                timeout -= dif
                session.expire(wu)

        self.assertTrue(is_running(self.tested_module),
                        str(self.tested_module) + "not running anymore")

        return old_package
        # TODO: use ORM for old package


# runs all tests in this file if file is run as normal python script
if __name__ == '__main__':
    unittest.main()
