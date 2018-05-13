from database.models import WorkUnit
from database.service import session, get_mask, get_all_package_masks, get_charset, get_dict
from fc_test_library import PackageStatus
from src.database.models import FcPackage


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
        "hosts": package.hosts,
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
