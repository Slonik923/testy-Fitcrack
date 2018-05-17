from database.models import WorkUnit
from database.service import session, get_mask, get_all_package_masks, get_charset, get_dict, \
    is_host_active, get_host_by_boinc_host_id, get_user, get_active_boinc_hosts, get_boinc_host
from fc_test_library import PackageStatus, HostStatus
from src.database.models import FcPackage, FcDictionary, FcJob


def charset_model(charset):
    with open(charset.path, 'rb') as file:
        content = file.read()

    can_decode = True
    try:
        content = content.decode()
    except UnicodeDecodeError:
        can_decode = False
        content = str(content)

    return {
        "id": charset.id,
        "name": charset.name,
        "time": charset.time.strftime("%Y-%m-%dT%H:%M:%S"),
        "data": content,
        "canDecode": can_decode
    }


def rule_model(rule):
    with open(rule.path, 'r') as file:
        content = file.read()

    return {
        "id": rule.id,
        "name": rule.name,
        "time": rule.time.strftime("%Y-%m-%dT%H:%M:%S"),
        "data": content,
    }


def dict_model(d):
    with open(d.path, 'r') as file:
        content = file.read()

    return {
        "status": True,
        "dict": {
            "id": d.id,
            "time": d.time.strftime("%Y-%m-%dT%H:%M:%S"),
            "keyspace": d.keyspace,
            "name": d.name,
        },
        "data": content,
    }


def mask_model(mask):
    with open(mask.path, 'r') as file:
        content = file.read()

    return {
        "id": mask.id,
        "name": mask.name,
        "time": mask.time.strftime("%Y-%m-%dT%H:%M:%S"),
        "data": content,
    }


def json_from_mask(mask):
    return {
        "package_id": None if mask is None else mask.id,
        "progress": mask.current_index / mask.hc_keyspace * 100,
        "current_index": mask.current_index,
        "mask": mask.mask,
        "id": mask.id,
        "keyspace": mask.keyspace,
        "hc_keyspace": mask.hc_keyspace
    }


def json_from_charset_id(charset_id):
    charset = get_charset(charset_id)

    return {
        "id": None if charset is None else charset.id,
        "time": None if charset is None else charset.time.strftime("%Y-%m-%d %H:%M:%S"),
        "name": None if charset is None else charset.name,
    }


def json_from_dict(dict_id):
    d = get_dict(dict_id)

    return {
        "id": None if d is None else d.id,
        "keyspace": None if d is None else d.keyspace,
        "name": None if d is None else d.name,
        "time": None if d is None else d.time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def package_model(package):
    hosts = get_active_boinc_hosts(package.id)
    json_hosts = [db_item_from_boinc_host(h) for h in hosts]
    return {
        "current_index": str(package.current_index),
        "markov": {
            "id": None,
            "name": None,
            "time": None,
        },
        "status_type": package.status_type,
        "replicate_factor": str(package.replicate_factor),
        "progress":  float(package.progress),
        "charSet1": json_from_charset_id(package.charset1),
        "charSet2": json_from_charset_id(package.charset2),
        "charSet3": json_from_charset_id(package.charset3),
        "charSet4": json_from_charset_id(package.charset4),
        "time_end": None if package.time_end is None else package.time_end.strftime("%Y-%m-%d %H:%M:%S"),
        "priority": None,
        "indexes_verified": str(package.indexes_verified),
        "hc_keyspace": str(package.hc_keyspace),
        "keyspace": str(package.keyspace),
        "comment": package.comment,
        "workunits": package.workunits,
        "time_start": None if package.time_start is None else package.time_start.strftime(
            "%Y-%m-%d %H:%M:%S"),
        "password": package.password,
        "hash": package.hash,
        "cracking_time_str": package.cracking_time_str,
        "id": package.id,
        "hash_type_name": package.hash_type_name,
        # TODO:
        "hosts": json_hosts,
        "time": None if package.time is None else package.time.strftime("%Y-%m-%dT%H:%M:%S"),
        "seconds_per_job": str(package.seconds_per_job),
        "dict1": package.dict1,
        "dict2": package.dict2,
        "rule_left": package.rule_left,
        "rule_right": package.rule_right,
        "masks": package.masks,
        "current_index_2": str(package.current_index_2),
        "attack": package.attack,
        "attack_mode": str(package.attack_mode),
        "hashes": package.hashes,
        "hash_type": str(package.hash_type),
        "name": package.name,
        "status": str(package.status),
        "rulesFile": {
            "id": None,
            "name": None,
            "time": None,
        },
        "status_text": PackageStatus(package.status).name,
        "cracking_time": float(package.cracking_time),
        "dictionary1": json_from_dict(package.dict1),
        "dictionary2": json_from_dict(package.dict2),
    }


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
        "progress": 100.0 if package.indexes_verified == package.hc_keyspace else
        package.indexes_verified / package.hc_keyspace * 100,
        "status_text": PackageStatus(package.status).name,
        "attack_mode": str(package.attack_mode),
        "name": package.name,
        "status": str(package.status),
        "deleted": package.deleted,
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


def job_model(job):
    host = get_boinc_host(job.boinc_host_id)
    json_host = db_item_from_boinc_host(host)

    return {
        "cracking_time": float(job.cracking_time),
        "id": str(job.id),
        "mask_id": job.mask_id,
        "host_id": job.host_id,
        "time": job.time.strftime("%Y-%m-%dT%H:%M:%S"),
        "boinc_host_id": job.boinc_host_id,
        "start_index_2": job.start_index_2,
        "finished": bool(job.finished),
        "retry": bool(job.retry),
        "host": json_host,
        "package_id": job.package_id,
        "hc_keyspace": job.hc_keyspace,
        "workunit_id": job.workunit_id,
        "duplicate": bool(job.duplicate),
        "duplicated": bool(job.duplicated),
        "cracking_time_str": job.cracking_time_str,
        "start_index": job.start_index
    }


def json_from_status(status):
    return {
        'status': PackageStatus(status[0]).name,
        'count': status[1]
    }
