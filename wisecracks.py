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


def test_func():
    cdb_conn = open_comments_db()

    for a in cdb_conn.execute('select * from comments where address=13264785 order by timestamp desc limit 1'):
        print a

    cdb_conn.close()
    return

def save_function_info():
    cdb_conn = open_comments_db()
    
    function_ea = GetEventEa()
    function_ea = GetFunctionAttr(function_ea, FUNCATTR_START)
    
    function_comments = gather_function_comments(function_ea)
    function_frame_members = gather_frame_members(function_ea)

    for comment in function_comments:
        query = 'select comment from comments where address=%d AND is_repeatable=%d order by timestamp desc limit 1' % (comment['address'],comment['is_repeatable'])
        last_comment_text = cdb_conn.execute(query).fetchone()
        if last_comment_text != None:
            print last_comment_text
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



def gather_function_comments(ea):
    comments_list = []
#   current_ea = GetEventEa()
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
    function_frame = GetFrame(ea)
    first_member = GetFirstMember(function_frame)
    last_member = GetLastMember(function_frame)
    member_iterator = first_member
    while member_iterator <= last_member:
        print "Name: " + GetMemberName(function_frame, member_iterator)
        members_list.append({"member_offset":member_iterator, "member_name":GetMemberName(function_frame,member_iterator)})
        member_iterator = member_iterator+GetMemberSize(function_frame,member_iterator)

    return members_list


def save_function_comments():
    cdb_conn = open_comments_db()
    current_ea = GetEventEa()
    function_start = GetFunctionAttr(current_ea, FUNCATTR_START)
    function_end = GetFunctionAttr(current_ea, FUNCATTR_END)
    function_iterator = function_start

    while function_iterator != BADADDR:
        if GetCommentEx(function_iterator,False):
            comment_string = GetCommentEx(function_iterator,False)
            print "Saving %X - %s" % (function_iterator,comment_string)
            cdb_conn.execute('insert into comments values (%d,"%s")' % (function_iterator,comment_string))
        function_iterator = NextHead(function_iterator, function_end)

    cdb_conn.commit()
    cdb_conn.close()

def restore_function_comments():
    cdb_conn = open_comments_db()
    current_ea = GetEventEa()
    function_start = GetFunctionAttr(current_ea, FUNCATTR_START)
    function_end = GetFunctionAttr(current_ea, FUNCATTR_END)
    function_iterator = function_start

    comments = cdb_conn.execute('select * from comments where (address >= %d AND address <= %d)' % (function_start,function_end))
    for comment in comments:
        MakeComm(comment[0],comment[1].encode('ascii'))

    cdb_conn.close()
    return



#save_function_comments()

#restore_function_comments()                       
