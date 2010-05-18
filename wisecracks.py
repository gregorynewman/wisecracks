import sqlite3

def open_comments_db():
    sqlite_db_path = GetIdbPath() + ".comments.db"
    sqlite_connection = sqlite3.connect(sqlite_db_path)
    try:
        sqlite_connection.execute('''create table comments (address int, comment text)''')
        sqlite_connection.commit()
        break
    except sqlite3.OperationalError:
        print "table exists"
    return sqlite_connection



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

restore_function_comments()
