import datetime
import secrets
import uuid

import jwt
import peewee

import Settings

db = peewee.SqliteDatabase('Database.db')  # база даных для пользователей, хранится на ЖД
db.connect()
ramDb = peewee.SqliteDatabase(':memory:')  # база данных в оперативке, удаляется с перезапуском приложения.
ramDb.connect()

from werkzeug.security import check_password_hash, generate_password_hash


class BaseModel(peewee.Model):
    class Meta:
        database = db


class RamModel(peewee.Model):
    class Meta:
        database = ramDb


class User(BaseModel):
    id = peewee.IntegerField(unique=True, primary_key=True)
    public_id = peewee.CharField(unique=True)
    contact = peewee.CharField()
    name = peewee.CharField(unique=True)
    password = peewee.CharField()
    admin = peewee.BooleanField(default=False)


def AddUser(name, password, contact, admin=False):
    new_user = User.create(name=name, contact=contact, password=generate_password_hash(password, method='sha256'),
                           public_id=str(uuid.uuid4()), admin=admin)
    new_user.save()


def GetUsersArr():
    result = []
    users = User.select()
    for user in users:
        user_dict = {}
        user_dict['public_id'] = user.public_id
        user_dict['contact'] = user.contact
        user_dict['name'] = user.name
        user_dict['admin'] = user.admin
        result.append(user_dict)
    return result


def VerifyCredentials(username, password):
    user = User.select().where(User.name == username).first()
    if not user:
        return False
    if check_password_hash(user.password, password):
        token = jwt.encode({'public_id': user.public_id,
                            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=Settings.token_exp)},
                           Settings.secret_key)
        return token


class Product(BaseModel):
    id = peewee.CharField(unique=True, primary_key=True)
    width = peewee.IntegerField(null=False)
    height = peewee.IntegerField(null=False)
    length = peewee.IntegerField(null=False)
    weight = peewee.IntegerField(null=False)
    name = peewee.CharField(null=False)


class Cells(BaseModel):
    id = peewee.IntegerField(unique=True, primary_key=True)
    width = peewee.IntegerField(null=False)
    height = peewee.IntegerField(null=False)
    length = peewee.IntegerField(null=False)
    floor = peewee.IntegerField(null=False)
    occupied = peewee.BooleanField(default=False)
    product_id = peewee.CharField(default='')
    arrayAddress = peewee.CharField(
        default='{}')  # обычно тут будет JSON, не использую JSONField, т.к не везде работает.
    string_address = peewee.CharField(null=False)


class RegCodes(BaseModel):
    code = peewee.CharField()


def AddRegCodes(count=1):
    generated = []
    for i in range(count):
        rndtoken = secrets.token_urlsafe()
        code = RegCodes.create(code=rndtoken)
        code.save()
        generated.append(rndtoken)
    return generated


def GetCells():
    return Cells.select().dicts()


db.create_tables([User, RegCodes])
db.create_tables([Cells, Product])
Cells.delete().execute()
Product.delete().execute()
if __name__ == '__main__':
    GetCells()
