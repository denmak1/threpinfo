# threpinfo.py
# used for getting detailed breakdowns of score, piv, etc per stage for:
# th06, th07, th08


import sys
import multiprocessing
import struct
from detect_rpy_game import getRpyGame


working_vals = []


# dump raw files
DUMP = 0


# DEBUG levels:
# 1 - initializations
# 2 - initializations loops
# 3 - 1st level uncompress loop
# 4 - unused
# 5 - 2nd level uncompress loops
# 6 - 3rd level uncompress loops
DEBUG = 0


# returns substring of string of length n starting from begin
# easier to read than the python way of getting a substring
def substr(a, begin, n):
    return a[begin : (begin + n)]


# dump uncompressed data to file
# open file in hex editor to find values of interest
def dumpUncompressedToFile(fdata):
    o_file = open("uncompressed_repdata.rpy", "w")
    o_file.write(fdata);
    o_file.close()
    print "dumped uncompressed to file"


# dump decrypted
def dumpDecryptedToFile(fdata):
    o_file = open("decrypted_repdata.rpy", "w")
    o_file.write(fdata);
    o_file.close()
    print "dumped decrypted to file"


# fname   - filename
# mask_s  - beginning of mask bits
# cryp_s  - beginning of encryption bits
# var_s   - var bytes (????)
# comp_s  - ?????
# score_s - score entry point
# score_n - scores (1 per stage: 0 1 2 3 4 5 6 7 8)
def uncompressRep(fname, mask_s, cryp_s, var_s, comp_s, score_s, score_n):
    BASE = 0x80

    # read file in binary format
    with open(fname, 'rb') as repfile:
        fdata = repfile.read()
    # print fdata

    # begin decrypt, all data up to encryption bytes
    fdata_u = fdata[0 : (0 + cryp_s)]
    # print "fdata_u =", fdata_u

    # masking byte used for encryption in replay
    iterator = fdata[mask_s : (mask_s + 1)]
    mask_b = ord(iterator)      # okay

    if(DEBUG > 0): print "mask =", mask_b
    # print "file len =", len(fdata)
    
    # decrypt the fdata binary string into fdata_u using mask
    i = cryp_s
    while(i < len(fdata)):
        temp = ord(fdata[i : (i+1)])
        # print "temp =", temp

        fdata_u += chr((temp - mask_b) & 0xFF)  # mask + append
        mask_b = (mask_b + 7) & 0xFF            # update mask
        i += 1

    if(DUMP == 1):
        dumpDecryptedToFile(fdata_u)

    # case for th06, no uncompression needed
    if(substr(fdata, 0x00, 4).upper() == "T6RP" or \
       substr(fdata, 0x00, 4).upper() == "T10R"):
        return fdata_u

    # print fdata_u

    # change variables, clear 2nd binary str
    fdata_1 = fdata_u           # file data decrypted
    fdata_2 = '';               # file data uncompressed
    
    # uncompress
    v = {}              # might need rework
    v[0x04] = 0
    v[0x1C] = 0
    v[0x30] = 0
    v[0x0C] = 0
    v[0x24] = 0
    v[0x10] = 0
    v[0x2C] = 0
    v[0x28] = 0
    v[0x34] = 1
    v[0x11] = 0x80      # [0x80], 0x60, 0x90, 0xAA
    v[0x20] = 0
    v[0x4B] = []        # trace

    if(DEBUG > 0): print "registers =", v

    # size
    min_i = 0
    stage = 0
    while(stage < score_n):
        adder = 0;

        for i in range(4):
            base = score_s + stage * 4 + 3 - i
            tmpord = ord(fdata_1[base : base + 1])
            adder = adder * 0x0100 + tmpord

            if(DEBUG > 1): print "stage =", stage, "adder =", adder

        if(adder > min_i):
            min_i = adder

        stage += 1

    min_i = min_i + 0x28
    if(DEBUG > 0): print "min_i =", min_i

    # initial register for 0x20
    for i in range(4):
        temp = ord(substr(fdata_1, var_s - i, 1))
        v[0x20] = v[0x20] * 0x100 + temp

        # print "v[0x20] =", v[0x20]
    
    v[0x3C] = v[0x20]
    if(DEBUG > 0): print "reg 0x3C =", v[0x3C]

    # initial registers for 0x4B array, all value of 0
    v[0x4B] = [0] * 0x2000
    # print "reg 0x4B =", v[0x4B]

    # based on input
    base = comp_s
    i = base
    fdata_2 = substr(fdata_1, 0, base)

    if(DEBUG > 0): print "len = ", len(fdata_2);

    # loop level 1
    while(len(fdata_2) < min_i):
        case_break = 0

        # loop level 2: inner while loop 1
        while(len(fdata_2) < min_i):
            first_loop = 1

            # begin do loop
            while True:
                if(v[0x11] == 0x80):
                    v[0x04] = ord(substr(fdata_1, i, 1))

                    if(DEBUG > 4): print "[loop 1] v[0x04] =", v[0x04]

                    if(i - base < v[0x20]):
                        i += 1
                    else:
                        v[0x04] = 0

                    v[0x28] = v[0x28] + v[0x04]

                if(first_loop == 1):
                    v[0x1C] = v[0x04] & v[0x11]
                    v[0x11] = v[0x11] >> 1

                    if(v[0x11] == 0):
                        v[0x11] = 0x80          # 0x60, 0x90?????
                    if(v[0x1C] == 0):
                        case_break = 1
                        break

                    v[0x30] = 0x80
                    v[0x1C] = 0
                    first_loop = 0

                else:
                    if((v[0x11] & v[0x04]) != 0):
                        v[0x1C] = v[0x1C] | v[0x30]

                    v[0x30] = v[0x30] >> 1
                    v[0x11] = v[0x11] >> 1

                    if(v[0x11] == 0):
                        v[0x11] = 0x80

                # termination case
                if(not(v[0x30] != 0)):
                    break
            # end of do loop

            if(case_break == 1):
                break
 
            fdata_2 += chr(v[0x1C])
            v[0x4B][v[0x34]] = chr(v[0x1C] & 0xFF)
            v[0x34] = (v[0x34] + 1) & 0x1FFF    # clear

            if(DEBUG > 2): print "[loop 1] end v[0x34] =", v[0x34]
        # end of inner while loop 1

        # print "len = ", len(fdata_2), "min =", min_i
        if(len(fdata_2) > min_i):
            break

        v[0x30] = 0x1000
        v[0x1C] = 0

        # inner while loop 2
        while(v[0x30] != 0):
            if(v[0x11] == 0x80):
                v[0x04] = ord(substr(fdata_1, i, 1))

                if(DEBUG > 4): print "[loop 2] v[0x04] =", v[0x04]

                if(i - base < v[0x20]):
                    i += 1
                else:
                    v[0x04] = 0

                v[0x28] = v[0x28] + v[0x04]
                if(DEBUG > 4): print "[loop 2] v[0x28] =", v[0x28]
        
            # at this point v[0x11] == 0x80, x[0x04] updated
            if(v[0x11] & v[0x04] != 0):
                v[0x1C] = v[0x1C] | v[0x30]

            v[0x30] = v[0x30] >> 1
            v[0x11] = v[0x11] >> 1

            if(DEBUG > 2): print "[loop 2] v[0x30] =", v[0x30], "v[0x11] =", v[0x11]

            if(v[0x11] == 0):
                v[0x11] = 0x80          # reset
        # end of inner while loop 2
                
        v[0x0C] = v[0x1C]
        if(v[0x0C] == 0):
            break;

        v[0x30] = 8
        v[0x1C] = 0

        if(DEBUG > 4): print "while loop 3 preentry..."
        
        # inner while loop 3
        while(v[0x30] != 0):
            if(v[0x11] == 0x80):
                v[0x04] = ord(substr(fdata_1, i, 1));
                
                if(i - base < v[0x20]):
                    i += 1
                else:
                    v[0x04] = 0

                v[0x28] += v[0x04]
                if(DEBUG > 4): print "[loop 3] v[0x28] =", v[0x28]

            # at this point v[0x11] == 0x80, x[0x04] updated
            if(v[0x11] & v[0x04] != 0):
                v[0x1C] = v[0x1C] | v[0x30]

            v[0x30] = v[0x30] >> 1      # /2
            v[0x11] = v[0x11] >> 1      # /2

            if(v[0x11] == 0):
                v[0x11] = 0x80          # reset
        # end of inner while loop 3

        v[0x24] = v[0x1C] + 2
        v[0x10] = 0

        # inner while loop 4
        # specific to building the uncompressd binary string here with the values in the
        # registers v[]
        while(v[0x10] <= v[0x24] and len(fdata_2) < min_i and v[0x0C] < min_i):
            v[0x2C] = v[0x4B][(v[0x0C] + v[0x10]) & 0x1FFF]
            if(DEBUG > 5): print "[loop 4] v[0x2C] = ", v[0x2C]

            fdata_2 += v[0x2C]
            v[0x4B][v[0x34]] = chr(ord(v[0x2C]) & 0xFF)
            v[0x34] = (v[0x34] + 1) & 0x1FFF

            if(DEBUG > 5): print "[loop 4] v[0x34] =", v[0x34]

            v[0x10] += 1
        # end of inner while loop 4

    # print v

    # print "len final = ", len(fdata_2);

    if(DUMP == 1):
        dumpUncompressedToFile(fdata_2)

    return fdata_2
# END uncompressRep


# for th08, returns a dictionary of stuff related to each stage
# returns: { stage: [score, piv, graze, time, items, lives, bombs] }, final
# input: rep_b - uncompressed replay file as binary string
def th08RepInfo(rep_b):    
    results = {}        # will hold final dictionary
    final = ""

    # replay file is split up into 8 blocks, one for each stage
    # score, piv, items, etc data stored with same offsets at beginning of each block
    real_stage = 0
    first_loop = 1
    for i in range(8):
        score   = 0
        piv     = 0
        graze   = 0
        time    = 0
        add_off = 0
        items   = 0
        lives   = 0
        bombs   = 0
        
        # initial offset from the beginning of the file to each stage block with values
        # iterated by byte, this finds the first (lowest) address of stage i, which we will
        # read from to get our values
        # also accounts for little endian
        for j in range(4):
            # stage offsets at 0x20 for IN
            index = 0x20 + i * 4 + 3 - j
            add_off = add_off * 0x0100 + ord(substr(rep_b, index, 1))

            # no longer need special case for items

        # print "stage", i, "go to address:", add_str

        # continue parse if our file has info
        if(add_off > 0):

            score_str = ""
            piv_str   = ""
            graze_str = ""
            bombs_str = ""
            lives_str = ""
            items_str = ""

            # iterate over each byte, find specific offset for the data we want and
            # starting from the stage block add_off. shift and accumualte values
            for k in range(4):
                score_offset = add_off + 0x03 - k
                score = score * 0x0100 + ord(substr(rep_b, score_offset, 1))
                score_str += substr(rep_b, score_offset, 1).encode('hex')

                piv_offset = add_off + 0x17 - k
                piv = piv * 0x0100 + ord(substr(rep_b, piv_offset, 1)) 
                piv_str += substr(rep_b, piv_offset, 1).encode('hex')
                
                graze_offset = add_off + 0x0B - k
                graze = graze * 0x0100 + ord(substr(rep_b, graze_offset, 1))
                graze_str += substr(rep_b, graze_offset, 1).encode('hex')

                bombs_offset = add_off + 0x21 - k
                bombs = bombs * 0x0100 + ord(substr(rep_b, bombs_offset, 1))
                bombs_str += substr(rep_b, bombs_offset, 1).encode('hex')

                lives_offset = add_off + 0x20 - k
                lives = lives * 0x0100 + ord(substr(rep_b, lives_offset, 1))
                lives_str += substr(rep_b, lives_offset, 1).encode('hex')

                items_offset = add_off + 0x07 - k
                items = items * 0x0100 + ord(substr(rep_b, items_offset, 1))
                items_str = substr(rep_b, items_offset, 1).encode('hex')

                # time_offset = add_off + 0x0000 - k
                # time = time * 0x0100 + ord(substr(rep_b, time_offset, 1))

                """
                # brute force to find time
                tt = 0x00
                while(tt < 0x1F):
                    time_offset = add_off + tt - k
                    time = time * 0x0100 + ord(substr(rep_b, time_offset, 1))
                    print "tt =", tt, "time =", time
                    tt += 0x01
                # nothing...
                """

            # clear out unnessary bits for certain values to avoid rubbish info
            score = score & 0xFFFFFFFF      # 4 bytes long, unecessary
            piv   = piv   & 0xFFFFFFFF      # 4 bytes long, unecessary
            graze = graze & 0xFFFFFFFF      # 4 bytes long, unecessary
            lives = lives & 0x000000FF      # 1 byte long
            bombs = bombs & 0x000000FF      # 1 byte long
            items = items & 0x0000FFFF      # 2 bytes long
            # time = time / 0x07D0

            # print items
            # print score_str, piv_str, graze_str, bombs_str, lives_str
        
        score *= 10

        # only consider when all values are not 0
        if(not(score == 0 and piv == 0 and graze == 0 and \
           items == 0 and lives == 0 and bombs == 0)):

            results[real_stage] = [score]

            # adjust due to stage differences so that all info is end-of-stage info
            if(first_loop == 0):
                results[real_stage-1].extend([piv, graze, items, lives, bombs])

            real_stage += 1
            first_loop = 0
        
        if(i == 7 and score > 0): final = "6B"
        else:                     final = "6A"

        # print i, score, piv, graze, items, lives, bombs

    return results, final
# END th08RepInfo


# for th07, returns a dictionary of stuff related to each stage
# returns: { stage: [score, cherry, chmax, cplus, graze, items, lives, bombs] }
# input: rep_b - uncompressed replay file as binary string
def th07RepInfo(rep_b):
    results = {}        # will hold final dictionary

    real_stage = 0
    first_loop = 1
    for i in range(7):
        score   = 0
        chrry   = 0
        chmax   = 0
        cplus   = 0
        graze   = 0
        items   = 0
        lives   = 0
        bombs   = 0
       
        add_off = 0
        add_str = ""

        # initial offset from the beginning of the file to each stage block with values
        # iterated by byte, this finds the first (lowest) address of stage i, which we will
        # read from to get our values
        # also accounts for little endian
        for j in range(4):
            # stage offsets found at 0x1C for PCB
            index = 0x1C + i * 4 + 3 - j
            # print substr(rep_b, index, 4).encode('hex')

            add_off = add_off * 0x0100 + ord(substr(rep_b, index, 1))
            add_str += substr(rep_b, index, 1).encode('hex')

        # print "stage", i, "go to address:", add_str

        # continue parse if our file has info
        if(add_off > 0):
            score_str = ""
            chrry_str = ""
            chmax_str = ""
            cplus_str = ""
            graze_str = ""
            bombs_str = ""
            lives_str = ""
            items_str = ""

            # iterate over each byte, find specific offset for the data we want and
            # starting from the stage block add_off. shift and accumualte values
            for k in range(4):
                score_offset = add_off + 0x03 - k
                score = score * 0x0100 + ord(substr(rep_b, score_offset, 1))
                score_str += substr(rep_b, score_offset, 1).encode('hex')

                chrry_offset = add_off + 0x0B - k
                chrry = chrry * 0x0100 + ord(substr(rep_b, chrry_offset, 1)) 
                chrry_str += substr(rep_b, chrry_offset, 1).encode('hex')
                
                chmax_offset = add_off + 0x0F - k
                chmax = chmax * 0x0100 + ord(substr(rep_b, chmax_offset, 1)) 
                chmax_str += substr(rep_b, chmax_offset, 1).encode('hex')

                cplus_offset = add_off + 0x13 - k
                cplus = cplus * 0x0100 + ord(substr(rep_b, cplus_offset, 1)) 
                cplus_str += substr(rep_b, cplus_offset, 1).encode('hex')

                graze_offset = add_off + 0x17 - k
                graze = graze * 0x0100 + ord(substr(rep_b, graze_offset, 1))
                graze_str += substr(rep_b, graze_offset, 1).encode('hex')

                bombs_offset = add_off + 0x27 - k
                bombs = bombs * 0x0100 + ord(substr(rep_b, bombs_offset, 1))
                bombs_str += substr(rep_b, bombs_offset, 1).encode('hex')

                lives_offset = add_off + 0x26 - k
                lives = lives * 0x0100 + ord(substr(rep_b, lives_offset, 1))
                lives_str += substr(rep_b, lives_offset, 1).encode('hex')

                items_offset = add_off + 0x07 - k
                items = items * 0x0100 + ord(substr(rep_b, items_offset, 1))
                items_str = substr(rep_b, items_offset, 1).encode('hex')

            # clear out unnessary bits for certain values to avoid rubbish info
            score = score & 0xFFFFFFFF      # 4 bytes long, unecessary
            chrry = chrry & 0xFFFFFFFF      # 4 bytes long, unecessary
            chmax = chmax & 0xFFFFFFFF      # 4 bytes long
            cplus = cplus & 0xFFFFFFFF      # possible
            graze = graze & 0xFFFFFFFF      # 4 bytes long, unecessary
            lives = lives & 0x000000FF      # 1 byte long
            bombs = bombs & 0x000000FF      # 1 byte long
            items = items & 0x0000FFFF      # 2 bytes long

            # print score
            # print score_str, piv_str, graze_str, bombs_str, lives_str
        
        score *= 10
        
        # only consider when all values are not 0
        if(not(score == 0 and chrry == 0 and chmax == 0 and \
           cplus == 0 and graze == 0 and lives == 0 and \
           bombs == 0 and items == 0)):

            results[real_stage] = [score]

            # adjust due to stage differences so that all info is end-of-stage info
            if(first_loop == 0 and real_stage  < 6):
                results[real_stage-1].extend([chrry, chmax, cplus, graze, items, lives, bombs])

            real_stage += 1
            first_loop = 0
        
        # print i, score, chrry, chmax, cplus, graze, items, lives, bombs

    return results
# END th07RepInfo


# for th06, returns a dictionary of stuff related to each stage
# returns: { stage: [score, lives, bombs] }
# input: rep_b - uncompressed replay file as binary string
def th06RepInfo(rep_b):
    results = {}        # will hold final dictionary

    real_stage = 0
    for i in range(6):
        score   = 0
        lives   = 0
        bombs   = 0
       
        add_off = 0
        add_str = ""

        for j in range(4):
            # stage offsets found at 0x34 for EoSD
            index = 0x34 + i * 4 + 3 - j
            add_off = add_off * 0x0100 + ord(substr(rep_b, index, 1))
            add_str += substr(rep_b, index, 1).encode('hex')

        # print "stage", i, "go to address:", add_str

        # continue parse if our file has info
        if(add_off > 0):
            score_str = ""
            bombs_str = ""
            lives_str = ""

            for k in range(4):
                score_offset = add_off + 0x03 - k
                score = score * 0x0100 + ord(substr(rep_b, score_offset, 1))
                score_str += substr(rep_b, score_offset, 1).encode('hex')

                lives_offset = add_off + 0x0C - k
                lives = lives * 0x0100 + ord(substr(rep_b, lives_offset, 1))
                lives_str += substr(rep_b, lives_offset, 1).encode('hex')

                bombs_offset = add_off + 0x0D - k
                bombs = bombs * 0x0100 + ord(substr(rep_b, bombs_offset, 1))
                bombs_str += substr(rep_b, bombs_offset, 1).encode('hex')


            # clear out unnessary bits for certain values to avoid rubbish info
            score = score & 0xFFFFFFFF      # 4 bytes long, unecessary
            lives = lives & 0x000000FF      # 1 byte long
            bombs = bombs & 0x000000FF      # 1 byte long
        
        
        # only consider when all values are not 0
        if(not(score == 0 and lives == 0 and bombs == 0)):
            results[real_stage] = [score, lives, bombs]
            real_stage += 1

        # print i, score, lives, bombs

    return results
# END th06RepInfo


# for full runs only, returns detailed info for th08 and a flag as a string, where
# "6A" =  final A and "6B" = final B
def getTh08DetailedInfo(fname):
    fdat = uncompressRep(fname, 0x15, 0x18, 0x18, 0x68, 0x20, 9)
    return th08RepInfo(fdat)
# END getTh08DetailedInfo


# basic info for th08, should work for non full runs as well
# as dictionary: {score, date, name, shot, difficulty, slowdown%, ratio, version}
def getTh08BasicInfo(fname):
    fdat = uncompressRep(fname, 0x15, 0x18, 0x18, 0x68, 0x20, 9)
    
    charmap = {
        0:  "Border Team",
        1:  "Magic Team",
        2:  "Scarlet Team",
        3:  "Ghost Team",
        4:  "Reimu",
        5:  "Yukari",
        6:  "Marisa",
        7:  "Alice",
        8:  "Sakuya",
        9:  "Remilia",
        10: "Youmu",
        11: "Yuyuko"
    }

    difficultymap = {
        0: "easy",
        1: "normal",
        2: "hard",
        3: "lunatic",
        4: "extra"
    }

    score = 0
    for i in range(4):
		score = score * 0x0100 + ord(substr(fdat, 0xB0 + 3 - i, 1))
    score *= 10

    date       = substr(fdat, 0x6C, 5)          # no time + day
    player     = substr(fdat, 0x72, 8)
    character  = charmap[ord(substr(fdat, 0x6A, 1))]
    difficulty = difficultymap[ord(substr(fdat, 0x6B, 1))]
    slowdown   = struct.unpack('f', substr(fdat, 0x118, 4))[0]
    version    = substr(fdat, 0x012C, 5)        # returns 'debug' in eng replays
    # can't find others

    # read from bottom of the file for the other info
    with open(fname, 'rb') as rfile:
        rawfile = rfile.read()
        rfile.seek(0)

        if(rawfile[-1] == "00".decode('hex')):
            rawfile = rfile.readlines()[-11:-1]
        else:
            rawfile = rfile.readlines()[-10:]

    date = rawfile[0].split("\t")[1].strip()
    stage = rawfile[4].split("\t")[1].strip()
    miss = rawfile[5].split("\t")[1].strip()
    bomb = rawfile[6].split("\t")[1].strip()
    ratio = rawfile[8].split("\t")[1].strip()
    version = rawfile[-1].split("\t")[1].strip()

    return {
        "score":      score,
        "date":       date,
        "player":     player,
        "shot":       character,
        "difficulty": difficulty,
        "stage":      stage,
        "miss":       miss,
        "bombs":      bomb,
        "slow":       slowdown,
        "ratio":      ratio,
        "ver":        version
    }
# END getTh08BasicInfo


# for full runs only, returns detailed info for th07
def getTh07DetailedInfo(fname):
    fdat = uncompressRep(fname, 0x0D, 0x10, 0x17, 0x54, 0x20, 9)
    return th07RepInfo(fdat)
# END getTh07DetailedInfo


# basic info for th07, should work for non full runs as well
# as dictionary: {score, date, name, shot, difficulty, slowdown%, version}
def getTh07BasicInfo(fname):
    fdat = uncompressRep(fname, 0x0D, 0x10, 0x17, 0x54, 0x20, 9)
    
    charmap = {
        0: "ReimuA",
        1: "ReimuB",
        2: "MarisaA",
        3: "MarisaB",
        4: "SakuyaA",
        5: "SakuyaB"
    }

    difficultymap = {
        0: "easy",
        1: "normal",
        2: "hard",
        3: "lunatic",
        4: "extra",
        5: "phantasm"
    }

    score = 0
    for i in range(4):
		score = score * 0x0100 + ord(substr(fdat, 0x6C + 3 - i, 1))
    score *= 10

    date       = substr(fdat, 0x58, 5)
    player     = substr(fdat, 0x5E, 8)
    character  = charmap[ord(substr(fdat, 0x56, 1))]
    difficulty = difficultymap[ord(substr(fdat, 0x57, 1))]
    slowdown   = struct.unpack('f', substr(fdat, 0xCC, 4))[0]
    version    = substr(fdat, 0xE0, 5)

    return {
        "score":      score,
        "date":       date,
        "player":     player,
        "shot":       character,
        "difficulty": difficulty,
        "slow":       slowdown,
        "ver":        version
    }
# END getTh07BasicInfo


# full runs only, th06
def getTh06DetailedInfo(fname):
    fdat = uncompressRep(fname, 0x0E, 0x0F, 0x0F, 0x16, 0x20, 9)
    return th06RepInfo(fdat)
# getTh06DetailedInfo


# basic info for th06, should work for non full runs as well
# as dictionary: {score, date, name, shot, difficulty, slowdown%, version}
def getTh06BasicInfo(fname):
    fdat = uncompressRep(fname, 0x0E, 0x0F, 0x0F, 0x16, 0x20, 9)
    
    charmap = {
        0: "ReimuA",
        1: "ReimuB",
        2: "MarisaA",
        3: "MarisaB"
    }

    difficultymap = {
        0: "easy",
        1: "normal",
        2: "hard",
        3: "lunatic",
        4: "extra"
    }

    score = 0
    for i in range(4):
		score = score * 0x0100 + ord(substr(fdat, 0x24 + 3 - i, 1))

    date       = substr(fdat, 0x10, 8)
    player     = substr(fdat, 0x19, 8)
    character  = charmap[ord(substr(fdat, 0x06, 1))]
    difficulty = difficultymap[ord(substr(fdat, 0x07, 1))]
    slowdown   = struct.unpack('f', substr(fdat, 0x2C, 4))[0]
    version    = ""     # can't find version string

    return {
        "score":      score,
        "date":       date,
        "player":     player,
        "shot":       character,
        "difficulty": difficulty,
        "slow":       slowdown,
        "ver":        version
    }
# END getTh06BasicInfo


def uncompTest((i, j, k, l)):
    fname = "./replays/th10_udse03.rpy"

    try:
        fdat = uncompressRep(fname, i, j, k, l, 0x20, 9)
        if(len(fdat) >= 70000):
            print i, j, k, l, " possible"
            # return (i, j, k, l)
        else:
            pass
    except TypeError:
            pass


# main entry point for replay file parsing
def main():
    fname = sys.argv[1]
    game = getRpyGame(fname)

    result = {}

    if(game == "in" or game == "th08"):
        result, final = getTh08DetailedInfo(fname)
        print getTh08BasicInfo(fname)

    elif(game == "pcb" or game == "th07"):
        result = getTh07DetailedInfo(fname)
        print getTh07BasicInfo(fname)

    elif(game == "eosd" or game == "th06"):
        result = getTh06DetailedInfo(fname)
        print getTh06BasicInfo(fname)

    else:
        print "game not supported"

    """
    elif(game == "th10" or game =="mof"):
        fdat = uncompressRep(fname, 0x0E, 0x0F, 0x19, 0x1E, 0x20, 9)
        print "done"

        
        pool = multiprocessing.Pool(processes = 8)
        combos = []
        
        for i in xrange(0x05, 0x1F):
            for j in xrange(i, 0x1F):
                for k in xrange(j, 0x1F):
                    for l in xrange(k, 0xFF):
                        combos.append((i, j, k, l))

        print "made tuples"

        results = pool.map(uncompTest, combos)
        
        # print results

    """

    for stage in result:
        print "stage:", stage, result[stage]


main()
