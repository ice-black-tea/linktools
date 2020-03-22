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


class DBField:

    def __init__(self, name, related_name=None, private_key=False, default=None, is_bind=True):
        self.name = name
        self.related_name = related_name if related_name is not None else name
        self.private_key = private_key
        self.default = default
        self.is_bind = is_bind


class DBTable:

    def __init__(self, name, fields):
        self.name = name
        self.fields = fields


# noinspection SqlNoDataSourceInspection,SqlDialectInspection,PyStringFormat
class DBModel:

    def __init__(self, table):
        self.table = table
        for field in table.fields:
            setattr(self, field.related_name, None)

    def make_select_sql(self, is_allow_none=False, where=None, order=None, limit=None, args=()):
        field_values = self._pick_field_values(is_allow_none, False)
        # noinspection PyTypeChecker
        sql = "SELECT {} FROM {} WHERE 1=1{}{}{}{}".format(
            ",".join([f.name for f in self.table.fields]),
            self.table.name,
            "" if len(field_values) == 0 else (" AND " + " AND ".join([f.equals_value for f in field_values])),
            "" if where is None and len(where) != 0 else " AND {}".format(where),
            "" if order is None and len(order) != 0 else " ORDER BY {}".format(order),
            "" if limit is None and len(limit) != 0 else " LIMIT {}".format(limit)
        )
        _args = [f.bind_value for f in filter(lambda f: f.is_bind, field_values)]
        if args is not None:
            _args.extend(args)
        return sql, _args

    def set_value_by_tuple(self, values):
        # noinspection PyTypeChecker
        for i in range(len(self.table.fields)):
            setattr(self, self.table.fields[i].related_name, values[i])

    def _pick_field_values(self, is_allow_none, is_allow_default):

        class FieldValue:

            def __init__(self, field, value, is_bind):
                self.field = field
                self.bind_value = value
                self.is_bind = is_bind

            @property
            def value(self):
                return "%s" if self.is_bind else self.bind_value

            @property
            def equals_value(self):
                return self.field.name + "=" + self.value

        fields = []
        values = self.__dict__
        for field in self.table.fields:
            if field.related_name in values:
                value = values[field.related_name]
                if is_allow_none is True or value is not None:
                    fields.append(FieldValue(field, value, True))
                    continue
            if is_allow_default is True and field.default is not None:
                fields.append(FieldValue(field, field.default, field.is_bind))
                continue
        return fields

    def make_insert_sql(self, is_allow_none=False):
        field_values = self._pick_field_values(is_allow_none, True)
        sql = "INSERT INTO {} ({}) VALUES ({})".format(
            self.table.name,
            ",".join([f.field.name for f in field_values]),
            ",".join([f.value for f in field_values])
        )
        args = [f.bind_value for f in filter(lambda f: f.is_bind, field_values)]
        return sql, args

    def make_insert_or_update_sql(self, is_allow_none=False):
        field_values = self._pick_field_values(is_allow_none, True)
        sql = "INSERT INTO {} ({}) VALUES ({}) ON DUPLICATE KEY UPDATE {}".format(
            self.table.name,
            ",".join([f.field.name for f in field_values]),
            ",".join([f.value for f in field_values]),
            ",".join([f.equals_value for f in filter(lambda f: not f.field.private_key, field_values)])
        )
        args = [f.bind_value for f in filter(lambda f: f.is_bind, field_values)]
        args.extend([f.bind_value for f in filter(lambda f: f.is_bind and not f.field.private_key, field_values)])
        return sql, args
