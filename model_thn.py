import os
import peewee
from datetime import datetime

from playhouse.postgres_ext import ArrayField
from settings import SETTINGS

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

class THN(peewee.Model):
    class Meta:
        database = database
        ordering = ("thn_id", )
        table_name = "vulnerabilities_thn"

    id = peewee.PrimaryKeyField(null=False)
    index = peewee.TextField(default="")
    thn_id = peewee.TextField(default="")
    score = peewee.TextField(default="")
    sort = peewee.TextField(default="")
    lastseen = peewee.TextField(default="")
    object_type = peewee.TextField(default="")
    object_types = ArrayField(peewee.TextField, default=[])
    description = peewee.TextField(default="")
    published = peewee.TextField(default="")
    reporter = peewee.TextField(default="")
    type = peewee.TextField(default="")
    title = peewee.TextField(default="")
    enchantments_score_vector = peewee.TextField(default="")
    enchantments_score_value = peewee.TextField(default="")
    bulletin_family = peewee.TextField(default="")
    cvelist = ArrayField(peewee.TextField, default=[])
    modified = peewee.TextField(default="")
    href = peewee.TextField(default="")
    cvss_score = peewee.TextField(default="")
    cvss_vector = peewee.TextField(default="")

    def __unicode__(self):
        return "thn"

    def __str__(self):
        return str(self.thn_id)

    @property
    def to_json(self):
        return dict(
            id=self.id,
            index=self.index,
            thn_id=self.thn_id,
            score=self.score,
            lastseen=self.lastseen,
            object_type=self.object_type,
            object_types=self.object_types,
            description=self.description,
            published=self.published,
            reporter=self.reporter,
            type=self.type,
            title=self.title,
            enchantments_score_vector=self.enchantments_score_vector,
            enchantments_score_value=self.enchantments_score_value,
            bulletin_family=self.bulletin_family,
            cvelist=self.cvelist,
            modified=self.modified,
            href=self.href,
            cvss_score=self.cvss_score,
            cvss_vector=self.cvss_vector
        )