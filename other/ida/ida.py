import re

SIZE_OF_POINT = 8 if BADADDR == 0xFFFFFFFFFFFFFFFFL else 4
FF_POINT = FF_DWORD if SIZE_OF_POINT == 4 else FF_QWORD
GET_POINT = get_wide_dword if SIZE_OF_POINT == 4 else get_qword

def __fix_struc_member_name(member_name):
    if member_name != None and member_name != "":
        member_name = re.sub(r"((?<=\)):[\s\S]*$)|(`virtual thunk to')|( )", "", member_name)
        member_name = member_name.replace(",", "::::")
        member_name = member_name.replace("<", "[")
        member_name = member_name.replace(">", "]")
        member_name = member_name.replace("=", "[equal]")
        member_name = member_name.replace("&", "[ref]")
        member_name = member_name.replace("*", "[ptr]")
        member_name = member_name.replace("~", "[destructor]")
    return member_name

def __is_bad_struc_id(struc_id):
    return struc_id == -1 or struc_id == BADADDR

def __get_or_add_struc(struc_name):
    struc_id = get_struc_id(struc_name)
    if __is_bad_struc_id(struc_id):
        struc_id = add_struc(-1, struc_name, 0)
    return struc_id

def __set_member_type(struc_id, member_type, member_offset):
    tinfo = idaapi.tinfo_t()
    struc = ida_struct.get_struc(struc_id)
    if not struc:
        return False
    member = ida_struct.get_member(struc, member_offset)
    if not member:
        return False
    idaapi.parse_decl2(idaapi.cvar.idati, '%s;' % member_type, tinfo, idaapi.PT_TYP)
    idaapi.set_member_tinfo2(struc, member, 0, tinfo, idaapi.SET_MEMTI_COMPATIBLE)
    return True

def __del_struc_member(struc_id):
    while del_struc_member(struc_id, get_struc_size(struc_id) - 1):
        pass
    return True

def __add_struc_member(struc_id, member_name, member_offset, \
                       flag=FF_POINT, typeid=0, nbytes=SIZE_OF_POINT):
    if __is_bad_struc_id(struc_id) \
        or member_name is None \
        or member_name == "" \
        or member_offset < 0:
        return False
    del_struc_member(struc_id, member_offset)

    i = 0
    member_name = name = __fix_struc_member_name(member_name)
    while get_member_offset(struc_id, member_name) != -1:
        member_name = "%s_%d" % (name, i)
        i = i + 1

    ret = add_struc_member(struc_id, member_name, member_offset, flag, typeid, nbytes)
    if ret < 0:
        print("error: add struct member %s failed (%d)" % (name, ret))
        return False
    return True

def add_vtbl_struc(vtbl_struc_name, vtbl_start, vtbl_end):
    vtbl_struc_id = __get_or_add_struc(vtbl_struc_name)
    if __is_bad_struc_id(vtbl_struc_id):
        print("error: add vtbl struct %s failed" % vtbl_struc_name)
        return False

    __del_struc_member(vtbl_struc_id)
    for addr in range(vtbl_start, vtbl_end, SIZE_OF_POINT):
        result = False
        ea = GET_POINT(addr)
        off = addr - vtbl_start
        if result == False:
            result = __add_struc_member(vtbl_struc_id, get_func_off_str(ea), off)
        if result == False:
            result = __add_struc_member(vtbl_struc_id, get_func_name(ea), off)
        if result == False:
            result = __add_struc_member(vtbl_struc_id, "field_%x" % off, off)
        if result == True:
            set_member_cmt(vtbl_struc_id, off,
                "addr: %xh\nname: %s" % (ea, get_func_name(ea)), 0)

    print("add vtbl struct %s finish" % vtbl_struc_name)
    return True

def add_vtbl_member(struc_name, vtbl_start, vtbl_end, vtbl_offset=0):
    struc_id = __get_or_add_struc(struc_name)
    if __is_bad_struc_id(struc_id):
        print("error: add struct %s failed" % vtbl_struc_name)
        return False

    vtbl_struc_name = "vtbl_%s_%d" % (struc_name, vtbl_offset)
    vtbl_struc_member = "vtbl_%d" % vtbl_offset
    if not add_vtbl_struc(vtbl_struc_name, vtbl_start, vtbl_end):
        return False
    if not __add_struc_member(struc_id, vtbl_struc_member, vtbl_offset):
        return False
    if not __set_member_type(struc_id, "%s *" % vtbl_struc_name, vtbl_offset):
        return False

    print("add vtbl member %s.%s finish" % (struc_name, vtbl_struc_member))
    return True

def set_user_reg(reg_name, reg_value, addr_start, addr_end):
    for addr in range(addr_start, addr_end):
        SetRegEx(addr, reg_name, reg_value, SR_user)
