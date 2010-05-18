# wisecracks.py
#
# by Gregory Newman
# gregory.e.newman@gmail.com

import sqlite3

def open_comments_db():
    sqlite_db_path = GetIdbPath() + ".comments.db"
    sqlite_connection = sqlite3.connect(sqlite_db_path)
    try:
        sqlite_connection.execute('''create table comments (address int, comment text, is_repeatable int, timestamp datetime)''')
        sqlite_connection.execute('''create table locals (address int, member_offset int, member_name text, timestamp datetime)''')
        sqlite_connection.commit()
        break
    except sqlite3.OperationalError:
        print "table exists"
    return sqlite_connection


def save_function_info():
    cdb_conn = open_comments_db()
    
    function_ea = GetFunctionAttr(GetEventEa(), FUNCATTR_START)
    
    function_comments = gather_function_comments(function_ea)
    function_frame_members = gather_frame_members(function_ea)

    for comment in function_comments:
        query = 'select comment from comments where address=%d AND is_repeatable=%d order by timestamp desc limit 1' % (comment['address'],comment['is_repeatable'])
        last_comment_text = cdb_conn.execute(query).fetchone()
        if last_comment_text != None:
            last_comment_text = last_comment_text[0].encode('ascii')
        if comment['comment_text'] != last_comment_text:
            query = 'insert into comments values (%d,"%s",%d,datetime("now"))' % (comment['address'], comment['comment_text'], comment['is_repeatable'])
            cdb_conn.execute(query)

    for member in function_frame_members:
        query = 'select member_name from locals where member_offset=%d and address=%d order by timestamp desc limit 1' % (member['member_offset'],function_ea)
        last_member_name = cdb_conn.execute(query).fetchone()
        if last_member_name != None:
            last_member_name = last_member_name[0].encode('ascii')
        if member['member_name'] != last_member_name:
            query = 'insert into locals values (%d,%d,"%s",datetime("now"))' % (function_ea,member['member_offset'],member['member_name'])
            cdb_conn.execute(query)

    try:
        cdb_conn.commit()
    except sqlite3.OperationalError:
        print "error committing"
        cdb_conn.close()

    cdb_conn.close()

def restore_function_info():
    cdb_conn = open_comments_db()

    function_ea = GetFunctionAttr(GetEventEa(), FUNCATTR_START)
    function_frame = GetFrame(function_ea)
    member_offsets = get_member_offsets(function_ea)

    for offset in member_offsets:
        query = 'select member_name from locals where address=%d AND member_offset=%d order by timestamp desc limit 1' % (function_ea, offset)
        member_name = cdb_conn.execute(query).fetchone()
        if member_name != None:
            member_name = member_name[0].encode('ascii')
            SetMemberName(function_frame, offset, member_name)

    function_end = GetFunctionAttr(function_ea, FUNCATTR_END)
    function_iterator = function_ea

    while function_iterator != BADADDR:
        query = 'select comment from comments where address=%d and is_repeatable=0 order by timestamp desc limit 1' % (function_iterator)
        comment_text = cdb_conn.execute(query).fetchone()
        if comment_text != None:
            comment_text = comment_text[0].encode('ascii')
            MakeComm(function_iterator, comment_text)

        query = 'select comment from comments where address=%d and is_repeatable=1 order by timestamp desc limit 1' % (function_iterator)
        comment_text = cdb_conn.execute(query).fetchone()
        if comment_text != None:
            comment_text = comment_text[0].encode('ascii')
            MakeRptCmt(function_iterator, comment_text)

        function_iterator = NextHead(function_iterator, function_end)


    

    return

def get_member_offsets(ea):
    offsets_list = []
    function_frame = GetFrame(ea)
    first_member = GetFirstMember(function_frame)
    last_member = GetLastMember(function_frame)
    member_iterator = first_member

    while member_iterator <= last_member:
        offsets_list.append(member_iterator)
        member_iterator += GetMemberSize(function_frame,member_iterator)

    return offsets_list

def gather_function_comments(ea):
    comments_list = []
    function_start = GetFunctionAttr(ea, FUNCATTR_START)
    function_end = GetFunctionAttr(ea, FUNCATTR_END)
    function_iterator = function_start

    while function_iterator != BADADDR:
        if GetCommentEx(function_iterator, False):
            comments_list.append({"address":function_iterator, "comment_text":GetCommentEx(function_iterator, False), "is_repeatable":False})
        if GetCommentEx(function_iterator, True):
            comments_list.append({"address":function_iterator, "comment_text":GetCommentEx(function_iterator, True), "is_repeatable":True})
 
        function_iterator = NextHead(function_iterator, function_end)

    return comments_list

def gather_frame_members(ea):
    members_list = []
    offsets_list = get_member_offsets(ea)
    for offset in offsets_list:
        members_list.append({"member_offset":offset, "member_name":GetMemberName(function_frame,offset)})

    return members_list
