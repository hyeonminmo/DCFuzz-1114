import peewee as pw

db = pw.DatabaseProxy()

class BaseModel(pw.Model):
    class Meta:
        database = db

# 퍼저별 seed 테이블
class AFLGoSeed(BaseModel):
    name = pw.TextField(unique=True)   # id:000123,...
    prox_score = pw.IntegerField(null=True)
    bitmap_size = pw.IntegerField(null=True)
    dom_covered = pw.IntegerField(null=True)


class WindRangerSeed(BaseModel):
    name = pw.TextField(unique=True)
    prox_score = pw.IntegerField(null=True)
    bitmap_size = pw.IntegerField(null=True)
    dom_covered = pw.IntegerField(null=True)


class DAFLSeed(BaseModel):
    name = pw.TextField(unique=True)
    prox_score = pw.IntegerField(null=True)
    bitmap_size = pw.IntegerField(null=True)
    dom_covered = pw.IntegerField(null=True)


def init_db(database: pw.Database):
    db.initialize(database)
    database.connect(reuse_if_open=True)
    database.create_tables([AFLGoSeed, WindRangerSeed, DAFLSeed])
