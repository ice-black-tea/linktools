#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : mysql.py
@time    : 2020/03/23
@site    :
@software: PyCharm

              ,----------------,              ,---------,
         ,-----------------------,          ,"        ,"|
       ,"                      ,"|        ,"        ,"  |
      +-----------------------+  |      ,"        ,"    |
      |  .-----------------.  |  |     +---------+      |
      |  |                 |  |  |     | -==----'|      |
      |  | $ sudo rm -rf / |  |  |     |         |      |
      |  |                 |  |  |/----|`---=    |      |
      |  |                 |  |  |   ,/|==== ooo |      ;
      |  |                 |  |  |  // |(((( [33]|    ,"
      |  `-----------------'  |," .;'| |((((     |  ,"
      +-----------------------+  ;;  | |         |,"
         /_)______________(_/  //'   | +---------+
    ___________________________/___  `,
   /  oooooooooooooooo  .o.  oooo /,   \,"-----------
  / ==ooooooooooooooo==.o.  ooo= //   ,`\--{)B     ,"
 /_==__==========__==_ooo__ooo=_/'   /___________,"
"""
from linktools.database import table, field
from linktools.database.struct import Table


# noinspection SqlDialectInspection,SqlNoDataSourceInspection
class MysqlUtils:

    @staticmethod
    def make_select_sql(model, is_allow_none=False, is_allow_default=False, where=None, order=None, limit=None, args=()):
        table = Table.from_model(model)
        field_values = MysqlUtils._pick_field_values(model, is_allow_none, is_allow_default)
        # noinspection PyTypeChecker
        sql = "SELECT {} FROM {} WHERE 1=1{}{}{}{}".format(
            ",".join([f.name for f in table.fields]),
            table.name,
            "" if len(field_values) == 0 else (" AND " + " AND ".join([f.equals_value for f in field_values])),
            "" if where is None else " AND {}".format(where),
            "" if order is None else " ORDER BY {}".format(order),
            "" if limit is None else " LIMIT {}".format(limit)
        )
        _args = [f.bind_value for f in filter(lambda f: f.is_bind_value, field_values)]
        if args is not None:
            _args.extend(args)
        return sql, _args

    @staticmethod
    def set_value_by_tuple(model, values):
        fields = Table.from_model(model).fields
        for i in range(len(fields)):
            fields[i].set(model, values[i])

    @staticmethod
    def _pick_field_values(model, is_allow_none, is_allow_default):

        class FieldValue:

            def __init__(self, field, value):
                self.field = field
                self.bind_value = value

            @property
            def value(self):
                return "%s" if self.is_bind_value else str(self.bind_value)

            @property
            def equals_value(self):
                return self.name + "=" + self.value

            def __getattr__(self, item):
                return getattr(self.field, item)

        field_values = []
        for field in Table.from_model(model).fields:
            value = field.get(model)
            if is_allow_default and field.default_value is not None:
                field_values.append(FieldValue(field, field.default_value))
            elif is_allow_none or value is not None:
                field_values.append(FieldValue(field, value))

        return field_values

    @staticmethod
    def make_insert_sql(model, is_allow_none=False, is_allow_default=False):
        field_values = MysqlUtils._pick_field_values(model, is_allow_none, is_allow_default)
        sql = "INSERT INTO {} ({}) VALUES ({})".format(
            Table.from_model(model).name,
            ",".join([f.name for f in field_values]),
            ",".join([f.value for f in field_values])
        )
        args = [f.bind_value for f in filter(lambda f: f.is_bind_value, field_values)]
        return sql, args

    @staticmethod
    def make_insert_or_update_sql(model, is_allow_none=False, is_allow_default=False):
        field_values = MysqlUtils._pick_field_values(model, is_allow_none, is_allow_default)
        sql = "INSERT INTO {} ({}) VALUES ({}) ON DUPLICATE KEY UPDATE {}".format(
            Table.from_model(model).name,
            ",".join([f.name for f in field_values]),
            ",".join([f.value for f in field_values]),
            ",".join([f.equals_value for f in filter(lambda f: not f.is_private_key, field_values)])
        )
        args = [f.bind_value for f in filter(lambda f: f.is_bind_value, field_values)]
        args.extend([f.bind_value for f in filter(lambda f: f.is_bind_value and not f.is_private_key, field_values)])
        return sql, args


mysql_utils = MysqlUtils


if __name__ == '__main__':

    @table("table_name")
    class test:

        @field("aaaa")
        def field1(self):
            return None

        @field(is_bind_value=False)
        def field2(self):
            return "1"

        @field
        def field3(self):
            pass

    t = test()

    print(mysql_utils.make_select_sql(t))
    print(mysql_utils.make_insert_sql(t))
    print(mysql_utils.make_insert_sql(t, is_allow_none=True))
    print(mysql_utils.make_insert_or_update_sql(t))

    t.field1 = "111"
    t.field2 = None

    print(mysql_utils.make_select_sql(t))
    print(mysql_utils.make_insert_sql(t))
    print(mysql_utils.make_insert_sql(t, is_allow_none=True))
    print(mysql_utils.make_insert_or_update_sql(t))
