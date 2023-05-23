from types import SimpleNamespace as Namespace
from impacket.smbconnection import SMBConnection
from time import sleep
import traceback
import sys
import json

def SMBProbe(netCommand) -> int:
    exit_code = 1

    for _ in range(0,3):  
        try:
            conn = SMBConnection(netCommand._nextTarget, netCommand._nextTarget, sess_port=445)
            conn.login("paul.mdz", "paul.mdz123@")
        except:
            if("STATUS_LOGON_FAILURE" in traceback.format_exc()):
                exit_code =  0
                break
            elif("Connection refused" in traceback.format_exc()):
                exit_code =  1
                sleep(10)
  
    return exit_code

if __name__ == "__main__":
    exit_code = 1
    netCommand = json.loads(sys.argv[1][1:], object_hook=lambda d: Namespace(**d))
    sleep(10)
    
    if(sys.argv[2] == "smb"):
        exit_code = SMBProbe(netCommand)

    print(exit_code)