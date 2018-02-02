#!/usr/bin/env python
#
#  Name: r2_hash_func_decoder.py
#  Description: A script that will decode hashed functions names. This is a
#  common technique used in injection based shellcode.
#

import argparse
import os
import sys

try:
    import pefile
    import r2pipe
    import sqlite3
except ImportError as err:
    print("Error while importing module: %s" % str(err))
    sys.exit(0)


CALLING_CONVENTIONS = {
    'doublepulsar': [
        ('movabs', 'call')  # movabs xxx; call yyy
    ],
    'metasploit': [
        ('push', 'call'),  # push xxx; call xxx - 32bit
        ('mov', 'call')    # mov xxx; call xxx - 64bit
    ]
}
TECHNIQUES = [
    'doublepulsar',
    'metasploit'
]


# ------------------------------------------------------------------------------
#  Database
# ------------------------------------------------------------------------------

def create_db(db_path):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    sql_command = """
    SELECT COUNT(*)
    FROM sqlite_master
    WHERE type='table' AND name='techniques'
    """
    c.execute(sql_command)
    if c.fetchone()[0] == 1:
        c.close()
        return

    sql_command = """
    CREATE TABLE techniques (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        technique TEXT UNIQUE
    );
    """
    c.execute(sql_command)

    for technique in TECHNIQUES:
        sql_command = "INSERT OR REPLACE INTO techniques VALUES (NULL, ?)"
        c.execute(sql_command, (technique, ))

    sql_command = """
    CREATE TABLE hashes (
        technique_id INTEGER,
        hash INTEGER,
        func_name TEXT,
        lib_name TEXT,
        PRIMARY KEY (technique_id, hash),
        FOREIGN KEY(technique_id) REFERENCES techniques(id)
    );
    """
    c.execute(sql_command)
    conn.commit()
    conn.close()


# ------------------------------------------------------------------------------
#  Hash Routines
# ------------------------------------------------------------------------------


def ror13(x):
    return 0xFFFFFFFF & ((x >> 13) | (x << 32 - 13))


# DoublePulsar
def doublepulsar(f_name, d_name):
    x = 0
    z = 0
    while True:
        y = x
        y = (y << 7) & 0xFFFFFFFF
        y = (y - x) & 0xFFFFFFFF
        x = y
        if z == len(f_name):
            return x
        x = x + f_name[z]
        z = z + 1


# Metasploit
def metasploit(f_name, d_name):
    # In the PEB d_name is wide so adjust accordingly
    d_hash = 0
    for i in d_name:
        d_hash = ror13(d_hash)
        x = i
        if x >= 0x61:
            x -= 32
        d_hash += x
        d_hash = ror13(d_hash)
    d_hash = ror13(d_hash)
    d_hash = ror13(d_hash)

    f_hash = 0
    for i in f_name:
        f_hash = ror13(f_hash)
        f_hash += i
    f_hash = ror13(f_hash)

    f_hash += d_hash

    if f_hash > 0xFFFFFFFF:
        f_hash -= 0xFFFFFFFF + 1

    return f_hash


# ------------------------------------------------------------------------------
#  General
# ------------------------------------------------------------------------------

def analyse(connection, technique):
    print('Analysing:')
    r2 = r2pipe.open()

    funcs = r2.cmdj("aflj")
    if not funcs:
        print("No functions defined!")
        return

    sql_command = """
        SELECT lib_name, func_name
        FROM hashes JOIN techniques
        ON hashes.technique_id == techniques.id
        WHERE technique=? AND hash=?
    """

    c = connection.cursor()

    for f in funcs:
        print("Function: %s 0x%x %u" % (f['name'], f['offset'], f['realsz']))
        asm = r2.cmdj("pDj %u @ %s" % (f['realsz'], f['offset']))
        for i in range(0, len(asm) - 1):
            op = asm[i]
            next_op = asm[i + 1]
            if op['size'] == 0 or next_op['size'] == 0:
                break
            for cc in CALLING_CONVENTIONS[technique]:
                if 'opcode' in next_op and next_op['opcode'].startswith(cc[1]):
                    args = op['opcode'].split(" ")
                    if args[0] == cc[0]:
                        try:
                            h = int(args[-1], 16) & 0xFFFFFFFF
                        except:
                            continue
                        c.execute(sql_command, (technique, h,))
                        result = c.fetchone()
                        if result:
                            print("|_ 0x%.08x\t\t%s\t\t%s!%s" %
                                  (op['offset'], op['opcode'], result[0], result[1]))
                            r2.cmd("CCu %s!%s @ %u" %
                                   (result[0], result[1], op['offset']))
                            break

        print("")


def parse_file(connection, path):
    c = connection.cursor()

    if path.endswith(".dll") or path.endswith(".exe"):
        print("Processing %s..." % (path))
        abs_path = os.path.abspath(path)
        f = pefile.PE(abs_path)
        for sym in f.DIRECTORY_ENTRY_EXPORT.symbols:
            if sym.name is not None:
                for technique in TECHNIQUES:
                    sql_command = "SELECT id FROM techniques WHERE technique=?"
                    c.execute(sql_command, (technique,))
                    technique_id = c.fetchone()[0]
                    dll_name = bytes(os.path.basename(path), 'ascii')
                    h = eval(technique)(sym.name, dll_name)
                    sql_command = "INSERT OR REPLACE INTO hashes VALUES (?, ?, ?, ?)"
                    c.execute(sql_command, (technique_id, int(h), str(sym.name, 'ascii'), str(dll_name, 'ascii')))

    connection.commit()


def generate(connection, paths):
    print('Generating Hashes:')
    for path in paths:
        path = os.path.abspath(path)
        if os.path.isdir(path):
            for file in os.listdir(path):
                parse_file(connection, os.path.join(path, file))
        else:
            parse_file(connection, path)


def search(connection, hash):
    val = int(hash, 16)
    print('Searching for 0x%X...' % (val))

    c = connection.cursor()
    sql_command = """
        SELECT technique, lib_name, func_name
        FROM hashes JOIN techniques
        ON hashes.technique_id == techniques.id
        WHERE hash=?
    """
    c.execute(sql_command, (val,))
    results = c.fetchall()
    if not results:
        print('No matches!')
        return
    for result in results:
        print('- %s: %s!%s()' % result)


def main():
    parser = argparse.ArgumentParser(description='Decode function hashes to their corresponding function names.')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-a', '--analyse', metavar='TECHNIQUE', type=str, help='Auto analyse functions using specified technique.')
    group.add_argument('-g', '--generate', nargs='+', metavar='PATH', help='Generates the hashes required for decoding from DLLs and EXEs, specify directory or file.')
    group.add_argument('-l', '--list', help='List Supported hashing techniques.', action='store_true')
    group.add_argument('-s', '--search', metavar='HASH', type=str, help='Lookup hash in the database.')
    args = parser.parse_args()

    script_dir = os.path.dirname(__file__)
    db_path = os.path.join(script_dir, 'r2_hash_func_decoder.db')
    create_db(db_path)

    conn = sqlite3.connect(db_path)

    if args.analyse:
        analyse(conn, args.analyse)
    if args.generate:
        generate(conn, args.generate)
    if args.list:
        print('Suported Hashing Techniques:')
        for f in TECHNIQUES:
            print('- %s' % f)
    if args.search:
        search(conn, args.search)

    conn.close()


if __name__ == "__main__":
    main()
