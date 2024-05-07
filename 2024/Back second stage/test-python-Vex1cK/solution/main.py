from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel
import os
import psycopg2
import logging
from urllib.parse import urlparse
import re
import hashlib
import datetime
import jwt
import uuid


class UserReg(BaseModel):
    login: str
    email: str
    password: str
    countryCode: str
    isPublic: bool
    phone: str = ""
    image: str = ""


class UserAuth(BaseModel):
    login: str
    password: str


class UserChange(BaseModel):
    isPublic: bool = None
    countryCode: str = None
    phone: str = None
    image: str = None


class ChangePass(BaseModel):
    oldPassword: str
    newPassword: str


class FriendLogin(BaseModel):
    login: str


class PostCreate(BaseModel):
    content: str
    tags: list[str]


app = FastAPI()
answer = "Noneee"
req = "Nonee"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
OK = 'ok'
JWT_HEADER = {
    "alg": "HS256",
    "typ": "JWT"
}
LOCAL = False
SECRET_KEY = (os.getenv("RANDOM_SECRET") if not LOCAL else "abcdefg12345")
VALID = {
    'login': "YellowMe",
    "password": "12345ABGFcjfd",
    "email": "bimbimbambam@ya.ru",
    "isPublic": True,
    "countryCode": "RU"
}


def get_connection():
    try:
        if LOCAL:
            connection = None
            dt = {
                'user': "postgres",
                # нет, это не мой пароль, не верьте, 100% скам, вы его введёте и у вас взорвётся комп (не важно что он только на моем пк подойдёт)
                'password': "e9r9hmmwGbU53id8pIhJ",
                'host': "127.0.0.1",
                'port': 5432,
            }
            connection = psycopg2.connect(
                user=dt['user'],
                password=dt["password"],
                host=dt["host"],
                port=dt['port'],
            )
        else:
            connection = None
            url = urlparse(os.getenv("POSTGRES_CONN"))
            dt = {
                'user': url.username,
                'password': url.password,
                'host': url.hostname,
                'port': url.port,
                'database': url.path[1:]
            }
            connection = psycopg2.connect(
                user=dt['user'],
                password=dt["password"],
                host=dt["host"],
                port=dt['port'],
                dbname=dt['database']
            )
    except Exception as ex:
        if connection:
            connection.close()
        return False, ex

    return True, connection


def is_table_in_db(connection, table):
    status = OK
    with connection.cursor() as cursor:
        check_table_query = F"SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = '{table}');"
        cursor.execute(check_table_query)
        table_exists = cursor.fetchone()[0]

    if not table_exists:
        status = False

    return bool(status)


def create_users_table(connection):
    with connection.cursor() as cursor:
        cursor.execute(
            """CREATE TABLE users(
            id serial PRIMARY KEY,
            login varchar(30) NOT NULL,
            email varchar(50) NOT NULL,
            password text NOT NULL,
            countryCode varchar(2) NOT NULL,
            isPublic boolean NOT NULL,
            phone varchar(20),
            image text
            );"""
        )
    connection.commit()
    return True


def create_tokens_table(connection):
    with connection.cursor() as cursor:
        cursor.execute(
            """CREATE TABLE tokens(
            login varchar(30) NOT NULL,
            token text NOT NULL
            );"""
        )
    connection.commit()
    return True


def create_friends_table(connection):
    with connection.cursor() as cursor:
        cursor.execute(
            """CREATE TABLE friends(
            login varchar(30) NOT NULL,
            friend varchar(30) NOT NULL,
            addedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );"""
        )
    connection.commit()
    return True


def create_posts_table(connection):
    with connection.cursor() as cursor:
        cursor.execute(
            """CREATE TABLE posts(
            id text NOT NULL,
            content text NOT NULL,
            author varchar(30) NOT NULL,
            tags TEXT[] NOT NULL,
            createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            likesCount INTEGER NOT NULL,
            dislikesCount INTEGER NOT NULL
            );"""
        )
    connection.commit()
    return True


def create_reactions_table(connection):
    with connection.cursor() as cursor:
        cursor.execute(
            """CREATE TABLE reactions(
            postId text NOT NULL,
            login varchar(30) NOT NULL,
            reation INTEGER NOT NULL
            );"""
        )
    connection.commit()
    return True


def add_user_into_table(connection, data: dict):
    if "phone" not in data.keys():
        data['phone'] = None
    if "image" not in data.keys():
        data['image'] = None

    with connection.cursor() as cursor:
        cursor.execute(
            f"""INSERT INTO users (login, email, password, countryCode, isPublic, phone, image) VALUES
            ('{data['login']}', '{data['email']}', '{data['password']}',
              '{data['countryCode']}', '{data['isPublic']}', '{data['phone']}', '{data['image']}');"""
        )
    connection.commit()

    return True


def find_el_in_table(connection, table, col, el):
    exist = is_table_in_db(connection, table)
    if not exist:
        if table == 'tokens':
            create_tokens_table(connection)
        elif table == 'users':
            create_users_table(connection)
        elif table == 'friends':
            create_friends_table(connection)
        elif table == "posts":
            create_posts_table(connection)
        elif table == "reactions":
            create_reactions_table(connection)
    with connection.cursor() as cursor:
        cursor.execute(
            f"SELECT * FROM {table} WHERE {col} = '{el}';"
        )
        data = cursor.fetchone()
    return data


def del_el_in_table(connection, table, col, el):
    with connection.cursor() as cursor:
        cursor.execute(
            f"DELETE FROM {table} WHERE {col} = '{el}';"
        )
        connection.commit()
    return True


def find_country_by_alpha2(alpha2):
    status = OK
    try:
        connection = None
        _, connection = get_connection()
        data = find_el_in_table(connection, "countries", "alpha2", alpha2)
        if data:
            data = {
                "name": data[1],
                "alpha2": data[2],
                "alpha3": data[3],
                "region": data[4]
            }
        else:
            status = 404

    except Exception as _ex:
        return JSONResponse(status_code=500,
                            content={'reason': f"ERROR Error while working with PostgreSQL: {_ex}"})
    finally:
        if connection:
            connection.close()
            # logging.info("INFO connection closed")
    if status == OK:
        return data
    else:
        return JSONResponse(status_code=status, content={"reason": "The country with the specified code was not found!"})


def checkUserData(user: dict):
    alph = "abcdefghijklmnopqrstuvwxyz"
    if not re.fullmatch("[a-zA-Z0-9-]+", user['login']) or len(user['login']) > 30:
        return False, "Incorrect login"
    if len(user['email']) < 1 or len(user['email']) > 50:
        return False, "Incorrect email"
    if not any([f"{i}" in user['password'] for i in range(10)]) or \
            len(user['password']) > 100 or len(user['password']) < 6 or \
            not any([sym in user['password'] for sym in alph]) or \
            not any([sym.upper() in user['password'] for sym in alph]):
        return False, "Incorrect password"
    if not re.fullmatch("[a-zA-Z]{2}", user['countryCode']) or len(user['countryCode']) > 2:
        return False, "Incorrect countryCode"
    if type(user['isPublic']) != bool:
        return False, "Incorrect isPublic"

    try:
        find_country_by_alpha2(user['countryCode'])
    except Exception as _ex:
        return False, str(_ex)

    if user['phone']:
        if not re.fullmatch("\+[\d]+", user['phone']) or len(user['phone']) > 20:
            return False, "Incorrect phone"
    if user['image']:
        if len(user['image']) > 200 or len(user['image']) < 1:
            return False, "Incorrect image"

    return True, ""


def check_limit_and_offset(limit, offset):
    try:
        int(limit)
    except ValueError:
        return False, "Incorrect limit"
    try:
        int(offset)
    except ValueError:
        return False, "Incorrect offset"
    limit = int(limit)
    offset = int(offset)
    if limit < 0 or limit > 50:
        return False, "Incorrect limit"
    if offset < 0:
        return False, "Incorrect offset"
    return True, ""


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def get_profile(userdata):
    profile = {}
    profile['login'] = userdata[1]
    profile['email'] = userdata[2]
    profile['isPublic'] = userdata[5]
    profile['countryCode'] = userdata[4]
    if userdata[6]:
        profile['phone'] = userdata[6]
    if userdata[7]:
        profile['image'] = userdata[7]
    return profile


def get_cur_time(patt="%Y%m%d%H%M%S%f"):
    return datetime.datetime.now().strftime(patt)[:-3]


def get_rand_id():
    return f"{get_cur_time()}-{uuid.uuid4()}"


def get_rfc339(time):
    return datetime.datetime.strptime(str(time), "%Y-%m-%d %H:%M:%S.%f").isoformat()


def get_current_user(token: str = Depends(oauth2_scheme)):
    decoded_token = None
    status = OK
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return "The token has expired", None
    except jwt.InvalidTokenError:
        return "Invalid token", None

    try:
        connection = None
        _, connection = get_connection()

        data = find_el_in_table(connection, "tokens", "token", token)
        if not data:
            status = "there is no such token"
    except Exception as ex:
        return str(ex), None
    finally:
        if connection:
            connection.close()

    if status != OK:
        return status, None

    return status, decoded_token


def get_post_from_post_found(post_found):
    post = {}
    keys = ['id', 'content', 'author', 'tags',
            'createdAt', 'likesCount', 'dislikesCount']
    for i in range(len(keys)):
        post[keys[i]] = post_found[i]
    return post


def get_post_by_postID(postId, login):
    post = {}
    try:
        connection = None
        _, connection = get_connection()

        post_found = find_el_in_table(connection, 'posts', 'id', postId)
        if post_found:
            author = post_found[2]
            if author != login:
                author_profile = find_el_in_table(
                    connection, "users", "login", author)
                if not author_profile[5]:
                    find_el_in_table(connection, "friends",
                                     'login', 'justRandomLoginOk')
                    with connection.cursor() as cursor:
                        cursor.execute(
                            f"""SELECT * FROM friends
                            WHERE (login, friend) = ('{author}', '{login}');"""
                        )
                        friend = cursor.fetchone()
                    if not friend:
                        status = 404
                        mess = "you cannot access this post"

            if status == OK:
                post = get_post_from_post_found(post_found)
        else:
            status = 404
            mess = "There is no post with this id"

    except Exception as ex:
        return {"status": 500, "reason": str(ex)}
    finally:
        if connection:
            connection.close()
    
    if status != OK:
        return {'status': status, "reason": mess}
    
    return {'status': OK, "content": post}


@app.exception_handler(RequestValidationError)
def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        content={"reason": "Invalid data"},
        status_code=400,
    )


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/api/ping", status_code=200)
def ping_ping():
    return "ping-ping"


@app.get("/api/countries", status_code=200)
def simple_countries(region=[]):
    if region:
        if region not in ["Europe", "Africa", "Americas", "Oceania", "Asia"]:
            return JSONResponse(status_code=400, content={"reason": "Некорректный регион: " + str(region)})
    try:
        connection = None
        _, connection = get_connection()
        logging.info("Connected")

        with connection.cursor() as cursor:
            if region:
                reglist = ([region] if type(region) == str else region)
                reglist = list(map(lambda x: "'" + x + "'", reglist))
                req = f"SELECT * FROM countries WHERE region IN ({', '.join(reglist)});"
                # эта штука делает из ["eu", "ru"] => "('eu', 'ru')"
            else:
                req = "SELECT * FROM countries"

            cursor.execute(req)

            data = cursor.fetchall()
            data = list(map(lambda x: {
                "name": x[1],
                "alpha2": x[2],
                "alpha3": x[3],
                "region": x[4]
            }, data))

    except Exception as ex:
        # logging.error(f"Error while working with PostgreSQL: {_ex}")
        # data = [
        #     {
        #         "name": str(_ex),
        #         "alpha2": 'DZ',
        #         "alpha3": 'DZA',
        #         "region": 'Africa',
        #     }
        # ]
        return JSONResponse(status_code=500,
                            content={'reason': str(ex)})
    finally:
        if connection:
            connection.close()
    return data


@app.get("/api/countries/{alpha2}", status_code=200)
def not_simple_countries(alpha2):
    return find_country_by_alpha2(alpha2)


@app.post("/api/auth/register", status_code=201)
def register(user: UserReg):
    user = user.model_dump()
    status = OK

    ok, reason = checkUserData(user)
    if not ok:
        print(reason)
        errmess = "Incorrect registration data: " + reason
        return JSONResponse(status_code=400, content={'reason': errmess})

    user['password'] = hash_password(user["password"])

    try:
        connection = None
        _, connection = get_connection()
        exist = is_table_in_db(connection, "users")
        if not exist:
            create_users_table(connection)

        check_login = find_el_in_table(
            connection, "users", "login", user['login'])
        check_email = find_el_in_table(
            connection, "users", "email", user['email'])
        check_phone = False
        if user['phone']:
            check_phone = find_el_in_table(
                connection, "users", "phone", user['phone'])

        if check_login:
            status = 409
            errmess = "a user with this login already exists"
        if check_email:
            status = 409
            errmess = "a user with this email already exists"
        if check_phone:
            status = 409
            errmess = "a user with this phone already exists"

        if status == OK:
            add_user_into_table(connection, user)
    except Exception as ex:
        return JSONResponse(status_code=500,
                            content={'reason': str(ex)})
    finally:
        if connection:
            connection.close()

    if status != OK:
        return JSONResponse(status_code=status, content={"reason": errmess})

    profile = {"profile": {
        "login": user['login'],
        "email": user['email'],
        "countryCode": user['countryCode'],
        "isPublic": user['isPublic'],
    }}
    if user['phone']:
        profile["profile"]['phone'] = user['phone']
    if user['image']:
        profile["profile"]['image'] = user['image']
    return profile


@app.post("/api/auth/sign-in", status_code=200)
def auth_user(user: UserAuth):
    user = user.model_dump()
    status = OK
    errmess = ""
    token = None

    try:
        connection = None
        _, connection = get_connection()
        userdata = find_el_in_table(
            connection, "users", "login", user['login'])
        if userdata:

            if hash_password(user['password']) == userdata[3]:
                exist = is_table_in_db(connection, "tokens")
                if not exist:
                    create_tokens_table(connection)

                # last_data = find_el_in_table(
                #     connection, "tokens", "login", user['login'])
                # if last_data:
                #     try:
                #         jwt.decode(last_data[1], SECRET_KEY,
                #                    algorithms=["HS256"])
                #         # если ошибки нет, значит токен еще не истёк, его и вернём:

                #         if connection:
                #             connection.close()
                #         return {"token": last_data[1]}

                #     except jwt.ExpiredSignatureError:
                #         # токен истёк
                #         del_el_in_table(connection, "tokens",
                #                         "login", user['login'])
                # сказали 2 раза создавать токен на одного и того же пользователя..

                payload = {
                    "sub": user["login"],
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=6)
                }

                # Создание токена
                token = jwt.encode(payload, SECRET_KEY,
                                   algorithm="HS256", headers=JWT_HEADER)

                with connection.cursor() as cursor:
                    cursor.execute(
                        f"INSERT INTO tokens (login, token) VALUES ('{user['login']}', '{token}');"
                    )
                    connection.commit()

            else:
                status = 401
                errmess = "Wrong password"
        else:
            status = 401
            errmess = "there is no user with this login"
    except Exception as ex:
        return JSONResponse(status_code=500,
                            content={'reason': str(ex)})
    finally:
        if connection:
            connection.close()

    if status != OK:
        return JSONResponse(status_code=status, content={"reason": errmess})

    return {"token": token}


@app.get("/api/me/profile", status_code=200)
def get_me(status_token: tuple[str, any] = Depends(get_current_user)):
    if status_token[0] != OK:
        return JSONResponse(status_code=401, content={'reason': status_token[0]})
    profile = {}

    try:
        connection = None
        _, connection = get_connection()
        userdata = find_el_in_table(
            connection, "users", "login", status_token[1]['sub'])
        profile = get_profile(userdata)
    except Exception as ex:
        return JSONResponse(status_code=500, content={'reason': str(ex)})
    finally:
        if connection:
            connection.close()

    return profile


@app.patch("/api/me/profile", status_code=200)
def change_me(data: UserChange, status_token: tuple[str, any] = Depends(get_current_user)):
    if status_token[0] != OK:
        return JSONResponse(status_code=401, content={'reason': status_token[0]})
    data = data.model_dump()
    data['login'] = VALID['login']
    data['email'] = VALID['email']
    data['password'] = VALID['password']
    if not data['isPublic']:
        data['isPublic'] = VALID['isPublic']
    if not data['countryCode']:
        data['countryCode'] = VALID['countryCode']
    ok, reason = checkUserData(data)
    if not ok:
        return JSONResponse(status_code=400, content={'reason': reason})

    profile = {}
    status = OK

    try:
        connection = None
        _, connection = get_connection()
        if data['phone']:
            userdata = find_el_in_table(
                connection, "users", "phone", data['phone'])
            if userdata:
                status = 409
                reason = "a user with such a phone number already exists"

        if status == OK:
            # чтобы создать таблицу если та еще не существует
            find_el_in_table(connection, "users", "login", "create_table")
            login = status_token[1]['sub']
            with connection.cursor() as cursor:
                fields = ",\n".join([f"{key} = '{data[key]}'" for key in
                                     ['isPublic', "countryCode", 'phone', 'image'] if key in data])
                req = f"""UPDATE users
                        SET
                            {fields}
                        WHERE
                            login = '{login}';"""
                cursor.execute(req)
                connection.commit()

            userdata = find_el_in_table(connection, "users", "login", login)
            profile = get_profile(userdata)
    except Exception as ex:
        return JSONResponse(status_code=500, content={"reason": str(ex)})
    finally:
        if connection:
            connection.close()

    if status != OK:
        return JSONResponse(status_code=status, content={'reason': reason})

    return profile


@app.get("/api/profiles/{login}", status_code=200)
def get_profile_by_login(login, status_token: tuple[str, any] = Depends(get_current_user)):
    if status_token[0] != OK:
        return JSONResponse(status_code=401, content={'reason': status_token[0]})
    status = OK
    reason = ""
    profile = {}

    try:
        connection = None
        _, connection = get_connection()

        mylogin = status_token[1]['sub']
        userdata = find_el_in_table(connection, "users", "login", login)
        if userdata:
            if mylogin == login or userdata[5]:
                profile = get_profile(userdata)
            else:
                status = 403
                reason = "It is not possible to get a user profile"
        else:
            status = 403
            reason = "There is no user with this login"
    except Exception as ex:
        return JSONResponse(status_code=500, content={'reason': str(ex)})
    finally:
        if connection:
            connection.close()

    if status != OK:
        return JSONResponse(status_code=status, content={'reason': reason})

    return profile


@app.post("/api/me/updatePassword", status_code=200)
def change_password(passwords: ChangePass, status_token: tuple[str, any] = Depends(get_current_user)):
    if status_token[0] != OK:
        return JSONResponse(status_code=401,
                            content={'reason': status_token[0]})

    passwords = passwords.model_dump()

    new_pass = passwords['newPassword']
    alph = "abcdefghijklmnopqrstuvwxyz"
    if not any([f"{i}" in new_pass for i in range(10)]) or \
            len(new_pass) > 100 or len(new_pass) < 6 or \
            not any([sym in new_pass for sym in alph]) or \
            not any([sym.upper() in new_pass for sym in alph]):
        return JSONResponse(status_code=400, content={'reason': "Incorrect new password"})

    login = status_token[1]['sub']
    status = OK
    errmess = ''

    try:
        connection = None
        _, connection = get_connection()
        userdata = find_el_in_table(connection, "users", "login", login)
        if userdata:
            if userdata[3] == hash_password(passwords['oldPassword']):
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"""UPDATE users
                        SET password = '{hash_password(new_pass)}'
                        WHERE login = '{login}';
                        """
                    )
                    connection.commit()

                del_el_in_table(connection, "tokens", "login", login)
            else:
                status = 403
                errmess = "Invalid old password"
        # такого случая не возникает т.к. токен точно содержит существующий логин (если уж он прошел проверку)
        else:
            status = 404
            errmess = "User not found"
    except Exception as ex:
        return JSONResponse(status_code=500, content={'reason': str(ex)})
    finally:
        if connection:
            connection.close()

    if status != OK:
        return JSONResponse(status_code=status,
                            content={'reason': errmess})

    return {"status": OK}


@app.post("/api/friends/add", status_code=200)
def add_friend(friend_login: FriendLogin, status_token: tuple[str, any] = Depends(get_current_user)):
    if status_token[0] != OK:
        return JSONResponse(status_code=401,
                            content={'reason': status_token[0]})

    friend_login = friend_login.model_dump()['login']
    if not re.fullmatch("[a-zA-Z0-9-]+", friend_login) or len(friend_login) > 30:
        return JSONResponse(status_code=400, content={"reason": "Incorrect friend login"})

    status = OK
    errmess = ""
    my_login = status_token[1]['sub']

    try:
        connection = None
        _, connection = get_connection()

        userdata = find_el_in_table(connection, "users", "login", friend_login)
        if userdata:
            if my_login != friend_login:
                # это для создания таблицы если она не существует
                find_el_in_table(connection, "friends", "login", my_login)
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"""SELECT *
                            FROM friends
                            WHERE (login, friend) IN (('{my_login}', '{friend_login}'));"""
                    )
                    friend_data = cursor.fetchone()
                if not friend_data:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            f"""INSERT INTO friends (login, friend, addedAt) VALUES
                            ('{my_login}', '{friend_login}', '{datetime.datetime.now()}');"""
                        )
                    connection.commit()
        else:
            status = 404
            errmess = 'The user with this login was not found'
    except Exception as ex:
        return JSONResponse(status_code=500, content={'reason': str(ex)})
    finally:
        if connection:
            connection.close()

    if status != OK:
        return JSONResponse(status_code=status,
                            content={'reason': errmess})

    return {"status": OK}


@app.post("/api/friends/remove", status_code=200)
def remove_friend(friend_login: FriendLogin, status_token: tuple[str, any] = Depends(get_current_user)):
    if status_token[0] != OK:
        return JSONResponse(status_code=401,
                            content={'reason': status_token[0]})

    friend_login = friend_login.model_dump()['login']
    if not re.fullmatch("[a-zA-Z0-9-]+", friend_login) or len(friend_login) > 30:
        return JSONResponse(status_code=400, content={"reason": "Incorrect friend login"})

    status = OK
    errmess = ""
    my_login = status_token[1]['sub']

    try:
        connection = None
        _, connection = get_connection()

        if my_login != friend_login:
            # это для создания таблицы если она не существует
            find_el_in_table(connection, "friends", "login", my_login)
            with connection.cursor() as cursor:
                cursor.execute(
                    f"""SELECT *
                        FROM friends
                        WHERE (login, friend) IN (('{my_login}', '{friend_login}'));"""
                )
                friend_data = cursor.fetchone()
            if friend_data:
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"""DELETE FROM friends WHERE 
                        (login, friend) = ('{my_login}', '{friend_login}');"""
                    )
                connection.commit()
    except Exception as ex:
        return JSONResponse(status_code=500, content={'reason': str(ex)})
    finally:
        if connection:
            connection.close()

    if status != OK:
        return JSONResponse(status_code=status,
                            content={'reason': errmess})

    return {"status": OK}


@app.get("/api/friends", status_code=200)
def get_friends(paginationLimit=5, paginationOffset=0, status_token: tuple[str, any] = Depends(get_current_user)):
    if status_token[0] != OK:
        return JSONResponse(status_code=401,
                            content={'reason': status_token[0]})

    ok, mess = check_limit_and_offset(paginationLimit, paginationOffset)
    if not ok:
        return JSONResponse(status_code=400,
                            content={'reason': mess})

    data = None

    try:
        connection = None
        _, connection = get_connection()

        with connection.cursor() as cursor:
            cursor.execute(
                f"""SELECT * FROM friends
                    WHERE login = '{status_token[1]['sub']}'
                    ORDER BY addedat DESC
                    LIMIT {paginationLimit}
                    OFFSET {paginationOffset};"""
            )
            data = cursor.fetchall()

        data = list(map(lambda x: {"login": x[1],
                                   "addedAt": get_rfc339(x[2])}, data))

    except Exception as ex:
        return JSONResponse(status_code=500, content={'reason': str(ex)})
    finally:
        if connection:
            connection.close()

    return data


@app.post("/api/posts/new", status_code=200)
def create_post(data: PostCreate, status_token: tuple[str, any] = Depends(get_current_user)):
    if status_token[0] != OK:
        return JSONResponse(status_code=401,
                            content={'reason': status_token[0]})

    status = OK
    errmess = ''
    data = data.model_dump()
    if len(data['content']) > 1000:
        status = 400
        errmess = "The text length is too long"
    elif any([len(tag) > 20 for tag in data['tags']]):
        status = 400
        errmess = "The length of one of the tags is too long"
    if status != OK:
        return JSONResponse(status_code=status,
                            content={'reason': errmess})

    login = status_token[1]['sub']
    post = {}
    post['id'] = get_rand_id()
    post['content'] = data['content']
    post['tags'] = data['tags']
    post['author'] = login
    post['createdAt'] = datetime.datetime.now()
    post['likesCount'] = 0
    post['dislikesCount'] = 0

    try:
        connection = None
        _, connection = get_connection()

        find_el_in_table(connection, 'posts', 'author',
                         "thatIsJustRandomLogin")  # для создания таблицы

        with connection.cursor() as cursor:
            req = f"""INSERT INTO posts (id, content, author, tags, createdAt, likesCount, dislikesCount) VALUES
            ('{post['id']}', '{post['content']}', '{post['author']}',""" + \
                f""" ARRAY{post['tags']}, '{post['createdAt']}', {post['likesCount']}, {post['dislikesCount']});"""
            cursor.execute(req)
            connection.commit()

    except Exception as ex:
        return JSONResponse(status_code=500, content={'reason': str(ex)})
    finally:
        if connection:
            connection.close()

    return post
    

@app.get('/api/posts/{postId}', status_code=200)
def get_post(postId, status_token: tuple[str, any] = Depends(get_current_user)):
    if status_token[0] != OK:
        return JSONResponse(status_code=401,
                            content={'reason': status_token[0]})

    status = OK
    mess = ""
    if type(postId) != str:
        status = 400
        mess = "Invalid postId"
    else:
        if len(postId) > 100:
            status = 400
            mess = "Invalid postId"

    if status != OK:
        return JSONResponse(status_code=status,
                            content={'reason': mess})

    login = status_token[1]['sub']

    res = get_post_by_postID(postId, login)

    status = res['status']

    if status != OK:
        return JSONResponse(status_code=status,
                            content={'reason': res['reason']})

    return res['content']


@app.get('/api/posts/feed/my', status_code=200)
def feed_my_post(paginationLimit=5, paginationOffset=0, status_token: tuple[str, any] = Depends(get_current_user)):
    if status_token[0] != OK:
        return JSONResponse(status_code=401,
                            content={'reason': status_token[0]})

    ok, mess = check_limit_and_offset(paginationLimit, paginationOffset)
    if not ok:
        return JSONResponse(status_code=400,
                            content={'reason': mess})

    posts = []

    try:
        connection = None
        _, connection = get_connection()

        with connection.cursor() as cursor:
            cursor.execute(
                f"""SELECT * FROM posts
                    WHERE author = '{status_token[1]['sub']}'
                    ORDER BY addedat DESC
                    LIMIT {paginationLimit}
                    OFFSET {paginationOffset};"""
            )
            posts = cursor.fetchall()

        posts = list(map(lambda x: get_post_from_post_found(x), posts))

    except Exception as ex:
        return JSONResponse(status_code=500, content={'reason': str(ex)})
    finally:
        if connection:
            connection.close()

    return posts


@app.get('/api/posts/feed/{login}', status_code=200)
def feed_post(login, paginationLimit=5, paginationOffset=0, status_token: tuple[str, any] = Depends(get_current_user)):
    if status_token[0] != OK:
        return JSONResponse(status_code=401,
                            content={'reason': status_token[0]})

    ok, mess = check_limit_and_offset(paginationLimit, paginationOffset)
    if not ok:
        return JSONResponse(status_code=400,
                            content={'reason': mess})

    if not re.fullmatch("[a-zA-Z0-9-]+", login) or len(login) > 30:
        return JSONResponse(status_code=400,
                            content={'reason': "Incorrect login"})

    posts = []
    status = OK
    errmess = ''
    my_login = status_token[1]['sub']

    try:
        connection = None
        _, connection = get_connection()

        if my_login != login:
            user_found = find_el_in_table(connection, "users" "login", login)
            if user_found:
                if not user_found[5]:
                    find_el_in_table(connection, "friends",
                                     'login', 'justRandomLoginOk')
                    with connection.cursor() as cursor:
                        cursor.execute(
                            f"""SELECT * FROM friends
                            WHERE (login, friend) = ('{login}', '{my_login}');"""
                        )
                        friend = cursor.fetchone()
                    if not friend:
                        status = 404
                        mess = "you cannot access this post"
            else:
                status = 404
                errmess = 'User not found'

        if status == OK:
            with connection.cursor() as cursor:
                cursor.execute(
                    f"""SELECT * FROM posts
                        WHERE author = '{login}'
                        ORDER BY addedat DESC
                        LIMIT {paginationLimit}
                        OFFSET {paginationOffset};"""
                )
                posts = cursor.fetchall()

            posts = list(map(lambda x: get_post_from_post_found(x), posts))

    except Exception as ex:
        return JSONResponse(status_code=500, content={'reason': str(ex)})
    finally:
        if connection:
            connection.close()

    if status != OK:
        return JSONResponse(status_code=status,
                            content={'reason': errmess})

    return posts


@app.post("/api/posts/{postId}/like", status_code=200)
def like_post(postId, status_token: tuple[str, any] = Depends(get_current_user)):
    if status_token[0] != OK:
        return JSONResponse(status_code=401,
                            content={'reason': status_token[0]})
    
    status = OK
    mess = ""
    if type(postId) != str:
        status = 400
        mess = "Invalid postId"
    else:
        if len(postId) > 100:
            status = 400
            mess = "Invalid postId"

    if status != OK:
        return JSONResponse(status_code=status,
                            content={'reason': mess})
    
    login = status_token[1]['sub']
    res = get_post_by_postID(postId, login)

    if res['status'] != OK:
        return JSONResponse(status_code=res['status'],
                            content={'reason': res['reason']})
    
    need_to_plus = {
        "like": 0,
        "dislike": 0
    }
    post = {}
    
    try:
        connection = None
        _, connection = get_connection()

        find_el_in_table(connection, "reactions", "login", 'justsomelogintocreateatable')
        with connection.cursor() as cursor:
            cursor.execute(
                f"""SELECT * FROM reactions
                    WHERE (postId, login) = ('{postId}', '{login}');"""
            )
            last_reaction = cursor.fetchone()
        
        if not last_reaction:
            need_to_plus['like'] = 1
        else:
            reaction = int(last_reaction[2])  # 1 -> был лайк | -1 -> был дизлайк
            if reaction == -1:
                need_to_plus["dislike"] = -1
                need_to_plus['like'] = 1
            if reaction == 0: # ну вдруг...
                need_to_plus['like'] = 1
        
        if need_to_plus['like'] != 0 or need_to_plus['dislike'] != 0:
            post = {"like": res['content'][5], "dislike": res['content'][6]}
            post['like'] += need_to_plus['like']
            post['dislike'] += need_to_plus['dislike']

        else:
            post = res['content']

    except Exception as ex:
        return JSONResponse(status_code=500, content={'reason': str(ex)})
    finally:
        if connection:
            connection.close()
    
    return post