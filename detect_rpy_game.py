# detect_rpy_game.py
# returns the game name of the replay


import sys


# maps the ids in the replay files to their acronym
name_map = {
    "T6RP": "eosd",
    "T7RP": "pcb",
    "T8RP": "in",
    "T9RP": "pofv",
    "T95R": "stb",
    "T10R": "mof",
    "T11R": "sa",
    "T12R": "ufo",
    "T125": "ds",
    "128R": "gfw",
    "T13R": "td",
    "T14R": "ddc",
    "T143": "isc",
    "T15R": "lolk"
}


# input - file name or path
# returns - string representing the game this replay is for
#         - "err" is error encountered (bad file)
def getRpyGame(fname):
    game_name = ""
    
    try:
        rfile = open(fname, 'rb')
        game_name = rfile.read(4).upper()   # first 4 bytes
        rfile.close()
    except:
        rfile.close()
        return "err"

    # th13 and th14 have T13R as the id in the .rpy file
    if(game_name == "T13R"):
        rfile = open(fname, 'rb')
        repdata = rfile.read()
        rfile.close()

        # it's 2hu 13
        if("938C95FB905F97EC955F".decode('hex') in repdata):
            game_name = "T13R"
        # it's 2hu 14
        else:
            game_name = "T14R"

    if(game_name not in name_map):
        return "err"
    else:
        return name_map[game_name]
# END getRpyGame


def main():
    fname = sys.argv[1]
    print getRpyGame(fname)

main()
