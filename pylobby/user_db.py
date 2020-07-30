import sqlite3
from typing import Sequence, Union


# Yes this looks inefficient - but it's clever and never out of date.
# If the DB caching is too bad we can optimize later...
class UserObj:
    db: "UserDB"
    id: int
    # Note: id not considered a field.
    fields: Sequence[str] = (
        "name",
        "password",
        "email",
        "country",
        "lastip",
        "lasttime",
        "session",
    )

    def __init__(self, db: "UserDB", uid: int):
        self.__dict__["db"] = db
        self.__dict__["id"] = uid

    def __getattr__(self, key: str) -> Union[str, int]:
        if key not in UserObj.fields:
            raise AttributeError()
        self.db.cursor.execute(
            "SELECT {} FROM users WHERE id = ?".format(key), (self.id,)
        )
        return self.db.cursor.fetchone()[0]

    def __setattr__(self, key: str, value: Union[str, int]) -> None:
        self.db.cursor.execute(
            "UPDATE users SET {} = ? WHERE id = ?".format(key), (value, self.id)
        )


class UserDB:
    def __init__(self, path: str):
        self.connection = sqlite3.connect(path, isolation_level=None)
        self.cursor = self.connection.cursor()

        self.cursor.execute(
            "create table if not exists users ("
            "  id INTEGER PRIMARY KEY,"
            "  name TEXT NOT NULL,"
            "  password TEXT NOT NULL,"
            "  email TEXT NOT NULL,"
            "  country TEXT NOT NULL,"
            "  lastip TEXT NOT NULL, "
            "  lasttime INTEGER NULL DEFAULT '0',"
            "  session INTEGER NULL DEFAULT '0');"
        )

    def __contains__(self, uname: str) -> bool:
        self.cursor.execute(
            "SELECT EXISTS(SELECT name FROM users WHERE name=? LIMIT 1);", (uname,)
        )
        return self.cursor.fetchone()[0]

    def __getitem__(self, id_or_name: Union[int, str]):
        if isinstance(id_or_name, int):
            return UserObj(self, id_or_name)
        try:
            self.cursor.execute(
                "SELECT id FROM users WHERE name=? LIMIT 1;", (id_or_name,)
            )
            uid = self.cursor.fetchone()[0]
            return UserObj(self, uid)
        except:
            raise KeyError()

    def create(self, name: str, password: str, email: str, country: str, lastip: str):
        self.cursor.execute(
            "INSERT INTO users (name, password, email, country, lastip) VALUES (?, ?, ?, ?, ?);",
            (name, password, email, country, lastip),
        )
        return UserObj(self, self.cursor.lastrowid)
