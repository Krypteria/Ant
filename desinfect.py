from types import SimpleNamespace as Namespace
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.smbconnection import SMBConnection
import winrm
import sys
import json
import auth

def getAvailaibleExecutablePath(conn, share) -> str:
    remoteFirstOptionFilePath = "windows\system32\spool\drivers\color\Photo.gmmp"

    if(pathExist(conn, share, remoteFirstOptionFilePath)):
        return "windows\system32\spool\drivers\color"
    else:
        return "users\public\documents"

def pathExist(conn, share, remoteFilePath) -> bool:
    try:
        tid = conn.connectTree(share)
        fid = conn.openFile(tid, remoteFilePath)
        conn.closeFile(tid, fid)
        conn.disconnectTree(tid)
        return True
    except:
        return False
    
def deleteExecutable(netCommand,conn) -> None:
    share = "C$"
    remotePath = getAvailaibleExecutablePath(conn, share)
    remoteFilePath = "{remotePath}\{command}.exe".format(remotePath = remotePath, command=netCommand._command)
    
    conn.deleteFile(share, remoteFilePath)
    conn.logoff()

def desinfectDefenderException(remote_auth, netCommand, conn) -> None:
    share = "C$"
    remotePath = getAvailaibleExecutablePath(share, conn)

    base = "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths" 
    value = "C:\{remotePath}".format(remotePath = remotePath)
    
    if(netCommand._protocol == "winrm"):
        protocol = winrm.Protocol(endpoint='http://{host}:5985/wsman'.format(host=remote_auth.getHost()),transport='ntlm',username=r'{domain}\{user}'.format(domain=remote_auth.getDomain(),user=remote_auth.getUsername()),password=remote_auth.getPassword(),server_cert_validation='ignore')
        shellID = protocol.open_shell()

        protocol.run_command(shellID,'cmd /Q /c reg delete "{base}" /v "{value}" /f'.format(base=base, value=value))
        protocol.run_command(shellID,'cmd /Q /c gpupdate /force')
        protocol.close_shell(shellID)
    elif(netCommand._protocol == "wmi"):
        dcom,classObject = wmiConnectionObjects(remote_auth)

        classObject.Create('cmd.exe /Q /c reg delete "{base}" /v "{value}" /f'.format(base=base, value=value), 'c:\\', None)
        classObject.Create('cmd.exe /Q /c gpupdate /force', 'c:\\', None)

        dcom.disconnect()

def winrmCleanup(remote_auth,shellID,commandID, netCommand) -> None:
    protocol = winrm.Protocol(endpoint='http://{host}:5985/wsman'.format(host=remote_auth.getHost()),transport='ntlm',username=r'{domain}\{user}'.format(domain=remote_auth.getDomain(),user=remote_auth.getUsername()),password=remote_auth.getPassword(),server_cert_validation='ignore')
    try:
        if(netCommand._command == "netsh"):
            netshShellID = protocol.open_shell()
            protocol.run_command(netshShellID, 'netsh interface portproxy delete v4tov4 listenaddress={srcaddr} listenport={srcport}'.format(srcaddr=netCommand._srcaddr, srcport=netCommand._srcport))  
            protocol.close_shell(netshShellID)
        else:
            protocol.cleanup_command(shellID, commandID)
    
        protocol.close_shell(shellID)     
    except:
        protocol.close_shell(shellID)

def wmiConnectionObjects(remote_auth) -> tuple:
    password, lmhash, nthash = remote_auth.retrieveAuthMethodCreds()

    dcom = DCOMConnection(remote_auth.getHost(), remote_auth.getUsername(), password, remote_auth.getDomain(), lmhash, nthash)
    iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
    iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
    iWbemServices = iWbemLevel1Login.NTLMLogin('//{machine}/root/cimv2'.format(machine=remote_auth.getHost()), NULL, NULL)

    classObject,_ = iWbemServices.GetObject('Win32_Process')

    return dcom, classObject

def wmiCleanup(remote_auth, _ ,commandID, netCommand) -> bool:
    dcom,classObject = wmiConnectionObjects(remote_auth)

    if(netCommand._command == "netsh"):
        classObject.Create('cmd.exe /Q /c netsh interface portproxy delete v4tov4 listenaddress={srcaddr} listenport={srcport}'.format(srcaddr=netCommand._srcaddr, srcport=netCommand._srcport), 'c:\\', None)
    else:
        classObject.Create('cmd.exe /Q /c wmic process where processid={pid} delete'.format(pid=commandID), 'c:\\', None)

    dcom.disconnect()

if __name__ == "__main__":
    netCommand = json.loads(sys.argv[1][1:], object_hook=lambda d: Namespace(**d))
    remote_auth = auth.getAuth(netCommand._srcaddr)
    desinfect_phase = sys.argv[2]

    if(desinfect_phase == "process"):
        try:
            if(netCommand._protocol == "winrm"):
                winrmCleanup(remote_auth,netCommand._shellID,netCommand._commandID, netCommand)
            elif(netCommand._protocol == "wmi"):
                wmiCleanup(remote_auth, netCommand._shellID,netCommand._commandID, netCommand)
        except:
            pass
    elif(desinfect_phase == "executable"):
        password, lmhash, nthash = remote_auth.retrieveAuthMethodCreds()
    
        conn = SMBConnection(netCommand._srcaddr, netCommand._srcaddr, sess_port=445)
        conn.login(remote_auth.getUsername(), password, remote_auth.getDomain(), lmhash, nthash)

        deleteExecutable(netCommand, conn)
        desinfectDefenderException(remote_auth, netCommand, conn)