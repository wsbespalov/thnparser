import os
import sys
import json
import peewee
import logging
import zipfile
import bz2
import gzip
import urllib.request as req
from settings import SETTINGS
from io import BytesIO
from datetime import datetime
from model_thn import THN

logging.basicConfig(format='%(name)s >> [%(asctime)s] :: %(message)s', level=logging.DEBUG)
logger = logging.getLogger(__file__)
logger.setLevel(logging.INFO)

debug = bool(SETTINGS.get("debug", True))

enable_extra_logging = SETTINGS.get("enable_extra_logging", False)
enable_results_logging = SETTINGS.get("enable_results_logging", False)
enable_exception_logging = SETTINGS.get("enable_exception_logging", True)

drop_thn_table_before = SETTINGS.get("drop_thn_table_before", False)
undefined = SETTINGS.get("undefined", "undefined")

POSTGRES = SETTINGS.get("postgres", {})

pg_default_database = POSTGRES.get("database", "updater_db")
pg_default_user = POSTGRES.get("user", "admin")
pg_default_password = POSTGRES.get("password", "123")
pg_default_host = POSTGRES.get("host", "localhost")
pg_default_port = POSTGRES.get("port", "5432")

pg_drop_before = bool(POSTGRES.get("drop_pg_before", True))

pg_database = os.environ.get("PG_DATABASE", pg_default_database)
pg_user = os.environ.get("PG_USER", pg_default_user)
pg_password = os.environ.get("PG_PASS", pg_default_password)
pg_host = os.environ.get("PG_HOST", pg_default_host)
pg_port = os.environ.get("PG_PORT", pg_default_port)

database = peewee.PostgresqlDatabase(
    database=pg_database,
    user=pg_user,
    password=pg_password,
    host=pg_host,
    port=pg_port
)

source_file = "https://vulners.com/api/v3/archive/collection/?type=thn"

def get_feed_data(getfile, unpack=True):
    try:
        response = req.urlopen(getfile)
    except:
        msg = "[!] Could not fetch file %s"%getfile
        sys.exit(msg)
    data = None
    data = response.read()
    if unpack:
        if 'gzip' in response.info().get('Content-Type'):
            data = gzip.GzipFile(fileobj = BytesIO(data))
        elif 'bzip2' in response.info().get('Content-Type'):
            data = BytesIO(bz2.decompress(data))
        elif 'zip' in response.info().get('Content-Type'):
            fzip = zipfile.ZipFile(BytesIO(data), 'r')
            if len(fzip.namelist())>0:
                data=BytesIO(fzip.read(fzip.namelist()[0]))
        elif 'application/octet-stream' in response.info().get('Content-Type'):
            if data[:4] == b'PK\x03\x04': # Zip
                fzip = zipfile.ZipFile(BytesIO(data), 'r')
                if len(fzip.namelist())>0:
                    data=BytesIO(fzip.read(fzip.namelist()[0]))
    return (data, response)

def LOGINFO_IF_ENABLED(message="\n"):
    if enable_extra_logging:
        logger.info(message)

def LOGWARN_IF_ENABLED(message="\n"):
    if enable_extra_logging:
        logger.warning(message)

def LOGERR_IF_ENABLED(message="\n"):
    if enable_exception_logging:
        logger.error(message)

def LOGVAR_IF_ENABLED(message="\n"):
    if enable_results_logging:
        logger.info(message)

def set_default(obj):
    if isinstance(obj, set):
        return list(obj)
    raise TypeError

def connect_database():
    try:
        peewee.logger.disabled = True
        if database.is_closed():
            database.connect()
        else:
            pass
        LOGVAR_IF_ENABLED("[+] Connect Postgress database")
        return True
    except peewee.OperationalError as peewee_operational_error:
        LOGERR_IF_ENABLED("[e] Connect Postgres database error: {}".format(peewee_operational_error))
    return False


def disconnect_database():
    try:
        if database.is_closed():
            pass
        else:
            database.close()
        LOGVAR_IF_ENABLED("[+] Disconnect Postgress database")
        peewee.logger.disabled = False
        return True
    except peewee.OperationalError as peewee_operational_error:
        LOGERR_IF_ENABLED("[e] Disconnect Postgres database error: {}".format(peewee_operational_error))
    peewee.logger.disabled = False
    return False


def drop_thn_table():
    connect_database()
    if THN.table_exists():
        THN.drop_table()
    disconnect_database()


def create_thn_table():
    connect_database()
    if not THN.table_exists():
        THN.create_table()
    disconnect_database()


def count_d2sec_table():
    connect_database()
    count = THN.select().count()
    if count:
        disconnect_database()
        return count
    return 0

def check_if_thn_item_in_postgres(item_in_json):
    connect_database()
    sid = -1
    if "thn_id" in item_in_json:
        thn_id = item_in_json["thn_id"]
        thns = list(
            THN.select().where(
                (THN.thn_id == thn_id)
            )
        )
    disconnect_database()
    if len(thns) == 0:
        return False, sid
    return False, thns[0].to_json["thn_id"]

def create_thn_item_in_postgres():
    pass


def create_thn_item_in_postgres():
    pass


def update_thn_item_in_postgres():
    pass


def create_or_update_thn_item_in_postgres(item_in_json):
    exists, sid = check_if_thn_item_in_postgres(item_in_json)
    if exists and sid != -1:
        result = update_thn_item_in_postgres(item_in_json, sid)
        return result, sid
    elif not exists and sid == -1:
        sid = create_thn_item_in_postgres(item_in_json)
        return "created", sid

def update_thn_vulners():
    data_raw, response = get_feed_data(source_file)
    data_in_json = json.loads(str(data_raw.read(), "utf-8"))
    if isinstance(data_in_json, list):
        if len(data_in_json) > 0:
            created = []
            modified = []
            skipped = []
            for item_in_json in data_in_json:
                thn = {}
                thn["index"] = item_in_json.get("_index", "thn")
                thn["thn_id"] = item_in_json.het("_id", undefined)
                thn["score"] = item_in_json.get("_score", None)
                if thn["score"] is None:
                    thn["score"] = undefined
                thn["sort"] = item_in_json.get("sort", [])

                source = item_in_json.get("_source", {})
                thn["lastseen"] = source.get("lastseen", datetime.utcnow())
                thn["object_type"] = source.get("_object_type", undefined)
                thn["object_types"] = source.get("_object_type", [])
                thn["references"] = source.get("references", [])
                thn["description"] = source.get("description", "")
                thn["published"] = source.get("published", datetime.utcnow())
                thn["reporter"] = source.get("reporter", undefined)
                thn["type"] = source.get("type", undefined)
                thn["title"] = source.get("title", undefined)

                enchantments = source.get("enchantments", {})
                score = enchantments.get("score", {})
                thn["enchantments_score_vector"] = score.get("vector", "NONE")
                thn["enchantments_score_value"] = str(score.get("value", "0.0"))
                thn["bulletin_family"] = source.get("bulletinFamily", undefined)
                thn["cvelist"] = source.get("cvelist", [])
                thn["object_type"] = source.get("_object_type", undefined)
                thn["modified"] = source.get("modified", datetime.utcnow())
                thn["href"] = source.get("href", undefined)
                cvss = source.get("cvss", {})
                thn["cvss_score"] = str(cvss.get("score", "0.0"))
                thn["cvss_vector"] = cvss.get("vector", "NONE")

                result, sid = create_or_update_thn_item_in_postgres(thn)

                if result == "created":
                    created.append(thn)
                elif result == "modified":
                    modified.append(thn)
                else:
                    skipped.append(thn)

            LOGINFO_IF_ENABLED("[+] Create {} vulnerabilities".format(len(created)))
            LOGINFO_IF_ENABLED("[+] Modify {} vulnerabilities".format(len(modified)))
            LOGINFO_IF_ENABLED("[+] Skip   {} vulnerabilities".format(len(skipped)))

        else:
            LOGERR_IF_ENABLED("[e] Get empty data set from MS source")

    else:
        LOGERR_IF_ENABLED("[e] Get not JSON data from THN source")

def run():
    if drop_thn_table_before:
        drop_thn_table()

    create_thn_table()

    update_thn_vulners()


def main():
    run()


if __name__ == "__main__":
    main()