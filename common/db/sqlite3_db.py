# -*- coding:utf-8 -*-
import sqlite3, re
class sqlite3_db(object):
    def __init__(self, dbname):
        self.__dbname = dbname
        self.__cursor = None
        self.__connector = None
        self._create_sqlite3_connector()

    @property
    def dbname(self):
        return self.__dbname

    @dbname.setter
    def dbname(self, value):
        self.__dbname = value

    @property
    def cursor(self):
        return self.__cursor

    @cursor.setter
    def cursor(self, value):
        self.__cursor = value

    @property
    def connector(self):
        return self.__connector

    @connector.setter
    def connector(self, value):
        self.__connector = value

    def del_obj(self):
        try:
            self.connector.close() if self.connector else None
            self.cursor.close() if self.cursor else None
        except:
            pass

    def _create_sqlite3_connector(self):
        dbname = self.dbname
        self.connector = None
        if not dbname:
            return self.connector
        try:
            self.connector = sqlite3.connect(database=dbname, check_same_thread=False)
            self.connector.text_factory = str
            self.cursor = self.connector.cursor()
            self.cursor.execute("SELECT * FROM sqlite_master")
        except (sqlite3.DatabaseError, sqlite3.OperationalError), msg:
            warnMsg = "unable to connect using SQLite 3 library, trying with SQLite 2"
            try:
                try:
                    import sqlite
                except ImportError:
                    errMsg = "sql requires 'python-sqlite' third-party library "
                    errMsg += "in order to directly connect to the database '%s'" % dbname
                    raise Exception(errMsg)

            except (sqlite3.DatabaseError, sqlite3.OperationalError), msg:

                raise Exception(msg[0])

            self.cursor.close() if self.cursor else None
            self.connector.close() if self.connector else None
            self.cursor = None
            self.connector = None

    def create_table(self,sql):
        if sql is not None and sql != '':
            self.cursor.execute(sql)

    def query(self, sql):
        result = None
        try:
            result = self.cursor.execute(sql)
        except (sqlite3.DatabaseError, sqlite3.OperationalError), msg:
            errMsg = "exec sql query error,msg:%s" % msg
            raise Exception(errMsg)
        return result

    def queryall(self, sql):
        result = None
        try:
            result = self.cursor.execute(sql).fetchall()
        except (sqlite3.DatabaseError, sqlite3.OperationalError), msg:
            errMsg = "exec sql query error,msg:%s" % msg
            raise Exception(errMsg)
        return result

    def queryrow(self, sql):
        result = None
        try:
            result = self.cursor.execute(sql).fetchone()
        except (sqlite3.DatabaseError, sqlite3.OperationalError), msg:
            errMsg = "exec sql query error,msg:%s" % msg
            raise Exception(errMsg)
        return result

    def querymany(self, sql, maxnum=0):

        result = None
        try:
            result = self.cursor.execute(sql).fetchmany(maxnum)
        except (sqlite3.DatabaseError, sqlite3.OperationalError), msg:
            errMsg = "exec sql query error,msg:%s" % msg
            raise Exception(errMsg)
        return result

    def filter_sql(self, value):
        value = str(value)
        value = re.escape(value)
        return value

    def select(self, sql, limit=None, offset=None, where=None):
        result = None
        if not sql:
            raise Exception("Query was empty")
        else:
            if where:
                sql = "{0} WHERE {1}".format(sql, where)
            if limit:
                sql = "{0} LIMIT {1}".format(sql, limit)

            if offset:
                sql = "{0},{1}".format(sql, offset)
            try:
                result = self.query(sql)
            except (sqlite3.DatabaseError, sqlite3.OperationalError), msg:
                errMsg = "exec sql query error,msg:%s,sql:%s" % (msg, sql)
                raise Exception(errMsg)
        return result

    def count(self, table):
        sql = 'SELECT count(*) FROM {0}'.format(table)
        rows_affected = 0
        try:
            rows_affected = self.query_row(sql)
        except (sqlite3.DatabaseError, sqlite3.OperationalError), msg:
            errMsg = "Database error\n------\n\nSQL: {0}\n\nError Message: {1}".format(sql, msg)
            raise Exception(errMsg)
        return rows_affected

    def update(self, table, data, where=''):
        if not where:
            errMsg = "DB Update no where string"
            raise Exception(errMsg)

        update_string = []
        if data and isinstance(data, dict):
            for key, val in data.items():
                update_string.append('`' + key + "` = '" + self.filter_sql(val) + "'")
        else:
            errMsg = "data is not dict type"
            raise Exception(errMsg)

        sql = 'UPDATE `{0}` SET {1} WHERE {2}'.format(table, ', '.join(update_string), where)
        rows_affected = None
        try:
            rows_affected = self.query(sql)
            self.connector.commit()
        except (sqlite3.DatabaseError, sqlite3.OperationalError), msg:
            errMsg = "Database error\n------\n\nSQL: {0}\n\nError Message: {1}".format(sql, msg)
            raise Exception(errMsg)

        return rows_affected

    def delete(self, table, where=''):
        rows_affected = None
        if not where:
            errMsg = "DB Delete no where string"
            raise Exception(errMsg)

        sql = 'DELETE FROM `{0}` WHERE {1}'.format(table, where)

        try:
            rows_affected = self.query(sql)
            self.connector.commit()
        except (sqlite3.DatabaseError, sqlite3.OperationalError), msg:
            errMsg = "Database error\n------\n\nSQL: {0}\n\nError Message: {1}".format(sql, msg)
            raise Exception(errMsg)

        return rows_affected

    def insert(self, table, data,filter=True):
        insert_data = {}
        if data and isinstance(data, dict):
            for key, val in data.items():
                val = val if isinstance(val,int) else val.replace('"',"'") if val else ""
                insert_data.update({key: '"{0}"'.format(self.filter_sql(val) if filter else val)})
        else:
            errMsg = "data is not dict type"
            raise Exception(errMsg)

        sql = 'INSERT INTO `{0}` ({1}) VALUES ({2})'.format(table, ','.join(insert_data.keys()),
                                                        ','.join(insert_data.values()))
        rows_affected = None
        try:
            rows_affected = self.query(sql)
            self.connector.commit()
        except (sqlite3.DatabaseError, sqlite3.OperationalError), msg:
            errMsg = "Database error\n------\n\nSQL: {0}\n\nError Message: {1}".format(sql, msg)
            raise Exception(errMsg)

        return rows_affected

    def query_row(self, sql, where=None):
        result = None
        if not sql:
            raise Exception("Query was empty")
        else:
            if where:
                sql = "{0} WHERE {1}".format(sql, where)
            try:
                result = self.queryrow(sql)
            except (sqlite3.DatabaseError, sqlite3.OperationalError), msg:
                errMsg = "exec sql query error,msg:%s,sql:%s" % (msg, sql)
                raise Exception(errMsg)
        return result

    def query_many(self, sql, maxnum=0, limit=None, offset=None, where=None, group_by=None):
        result = None
        if not sql:
            raise Exception("Query was empty")
        else:
            if where:
                sql = "{0} WHERE {1}".format(sql, where)
            if group_by:
                sql = "{0} GROUP BY {1}".format(sql, self.filter_sql(group_by))
            if limit:
                sql = "{0} LIMIT {1}".format(sql, limit)
            if offset:
                sql = "{0},{1}".format(sql, offset)

            try:
                result = self.querymany(sql, maxnum)
            except (sqlite3.DatabaseError, sqlite3.OperationalError), msg:
                errMsg = "exec sql query error,msg:%s,sql:%s" % (msg, sql)
                raise Exception(errMsg)
        return result

    def query_all(self, sql, limit=None, offset=None, where=None, group_by=None):
        result = None
        if not sql:
            raise Exception("Query was empty")
        else:
            if where:
                sql = "{0} WHERE {1}".format(sql, where)
            if group_by:
                sql = "{0} GROUP BY {1}".format(sql, self.filter_sql(group_by))
            if limit:
                sql = "{0} LIMIT {1}".format(sql, limit)
            if offset:
                sql = "{0},{1}".format(sql, offset)

            try:
                result = self.queryall(sql)
            except (sqlite3.DatabaseError, sqlite3.OperationalError), msg:
                errMsg = "exec sql query error,msg:%s,sql:%s" % (msg, sql)
                raise Exception(errMsg)
        return result


