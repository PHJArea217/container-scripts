#!/usr/bin/python3

import os, sys, time, stat

OLDFILE = sys.argv[1]
NEWFILE = sys.argv[2]
TMPFILE = sys.argv[3]

while True:
    try:
        os.link(OLDFILE, TMPFILE)
        stat_r = os.lstat(TMPFILE)
        if stat.S_ISSOCK(stat_r.st_mode):
            os.rename(TMPFILE, NEWFILE)
    except:
        try:
            os.unlink(TMPFILE)
        except:
            pass
    
    try:
        time.sleep(5)
    except:
        pass
