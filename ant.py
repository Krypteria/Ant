from json import JSONEncoder
import os
import subprocess
import traceback
import readline
import json
import re

topologyFile = "topology.conf"
authFile = "auth.conf"
executablesFolder = "executables"
supportedModes = ["tunnel","portforwarding","all"]
supportedBinaries = ["chisel","socat","goproxy","netsh"]
supportedCommands = ["probe", "desinfect", "deploy", "exit", "help", "redeploy", "update"]
supportedProtocols = ["winrm","wmi"]
supportedProbeProtocols = ["smb","all"]

class netCommandObject:
    def portforwardingCommand(self, protocol, mode, command, dstaddr, dstport, srcaddr, srcport) -> None:
        self._protocol = protocol
        self._mode = mode
        self._command = command
        self._srcaddr = srcaddr
        self._srcport = srcport
        self._dstaddr = dstaddr
        self._dstport = dstport
        self._deployed = False
        self._shellID = None
        self._commandID = None

    def chiselCommand (self, protocol, mode, command, dstaddr, dstport, srcaddr, nextTarget, sessionID, probeProtocol) -> None:
        self._protocol = protocol
        self._mode = mode
        self._command = command
        self._dstaddr = dstaddr
        self._dstport = dstport
        self._srcaddr = srcaddr
        self._nextTarget = nextTarget
        self._sessionID = sessionID
        self._probeProtocol = probeProtocol
        self._deployed = False
        self._shellID = None
        self._commandID = None
    
    def getProtocol(self) -> str:
        return self._protocol
    
    def getSrcAddr(self) -> str:
        return self._srcaddr
    
    def getSrcPort(self) -> str:
        return self._srcport

    def getDstAddr(self) -> str:
        return self._dstaddr
    
    def getDstPort(self) -> str:
        return self._dstport

    def getCommand(self) -> str:
        return self._command
    
    def getProbeProtocol(self) -> str:
        return self._probeProtocol
    
    def setDeployed(self, deployed) -> None:
        self._deployed = deployed

    def deployed(self) -> bool:
        return self._deployed

    def setCommandIDs(self, hostIdentifiers) -> None:
        if(hostIdentifiers != None):
            self._shellID = hostIdentifiers[0]
            self._commandID = hostIdentifiers[1]

    def getCommandIDs(self) -> tuple:
        if(self._shellID == None or self._commandID == None):
            return None
        else:
            return (self._shellID, self._commandID)

class netCommandObjectEncoder(JSONEncoder):
    def default(self, o):
        return o.__dict__

def validAddress(address) -> bool:
    regex = "^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return bool(re.match(regex, address))

def validPort(port):
    return port > 1 and port < 65535

def probe(netCommands, command_split) -> None:
    print("")
    if(command_split[1] == "all"):
        probeAll(netCommands)
    else: 
        probeHost(netCommands, command_split[2], command_split[1])

def probeAll(netCommands) -> None:
    probe = False
    for address, _ in netCommands.items():
        if(netCommands[address][supportedModes[0]].deployed()):
            probe = True
            break
        
    if(probe): 
        for address, _ in netCommands.items():
            if(netCommands[address][supportedModes[0]].deployed()):
                correctDeployment = probeHost(netCommands, address, None)
                if(not correctDeployment):
                    break   
    else:
        print("\t[!] - No infrastructure deployed\n")     

def probeHostPetition(netCommand, protocol) -> bool:
    netCommandTransfer = json.dumps(netCommand, cls=netCommandObjectEncoder, indent=None, separators=(',', ':')).encode("utf-8")
    probe = subprocess.run("exec proxychains -q python probes.py {data} {protocol}".format(data=netCommandTransfer, protocol=protocol),capture_output=True,shell=True, text=True)

    if(probe == None):
        return False
    else:
        return probe.stdout.strip() == "0"

def probeHost(netCommands, address, protocol=None) -> bool:
    correctDeployment = True

    print("\t[*] - Probing tunnel at {host}".format(host=address))
    if(supportedModes[0] in netCommands[address] and netCommands[address][supportedModes[0]].deployed()):
        netCommand = netCommands[address][supportedModes[0]]
        if(protocol != None):
            correctDeployment = probeHostPetition(netCommand, protocol)
        else:
            correctDeployment = probeHostPetition(netCommand, netCommand.getProbeProtocol())

        if(correctDeployment):
            print("\t\t[*] - Tunnel: {srcaddr} -> {dstaddr}:{dstport} OK\n".format(srcaddr=netCommand.getSrcAddr(),dstaddr=netCommand.getDstAddr(),dstport=netCommand.getDstPort()))
        else:
            print("\t\t[*] - Tunnel: {srcaddr} -> {dstaddr}:{dstport} FAIL\n".format(srcaddr=netCommand.getSrcAddr(),dstaddr=netCommand.getDstAddr(),dstport=netCommand.getDstPort()))      
    elif((supportedModes[0] not in netCommands[address] or (supportedModes[0] in netCommands[address] and not netCommands[address][supportedModes[0]].deployed()))):
        print("\t\t[!] - Probe failed for host {srcaddr}\n".format(srcaddr=address))
        correctDeployment = False

    return correctDeployment

def desinfect(netCommands, command_split) -> dict:
    if(command_split[1]== "all"):
        netCommands = desinfectAll(netCommands, False)
    else:
        if(len(command_split) == 3):
            netCommands = desinfectHost(netCommands,command_split[1],command_split[2])
        else:
            netCommands = desinfectHost(netCommands,"all",command_split[1])
    
    print("")
    return netCommands

def desinfectAll(netCommands, exit) -> dict:
    desinfect = False
    for address, mode in reversed(netCommands.items()):
        for netCommand in mode.values():
            if(netCommand.deployed()):
                netCommands = desinfectHost(netCommands, "all", address, None)
                desinfect = True
                break

    if(not desinfect and not exit):
            print("\t[!] - No infrastructure deployed\n")     
    
    return netCommands

def desinfectHostPetition(netCommand) -> None:
    print("\t\t\t[*] - Desinfecting process")
    netCommandTransfer = json.dumps(netCommand, cls=netCommandObjectEncoder, indent=None, separators=(',', ':')).encode("utf-8")
    subprocess.run("exec proxychains -q python desinfect.py {data} process".format(data=netCommandTransfer), shell=True, text=True)

    if(netCommand.getCommand() != "netsh"):
        print("\t\t\t[*] - Desinfecting executable")
        subprocess.run("exec proxychains -q python desinfect.py {data} executable".format(data=netCommandTransfer), shell=True, text=True)

def desinfectHost(netCommands, command, address, netCommand=None) -> dict:
    if(command == supportedModes[0] or command == supportedModes[1]):
        netCommandDesinfect = netCommands[address][command]
        if(netCommand != None):
            netCommandDesinfect = netCommand

        if(netCommandDesinfect.getCommandIDs() != None):
            print("\n\t[*] - Desinfecting {address} host".format(address=address))
            print("\t\t[*] - Desinfecting {command} in {address} host".format(command=command, address=address))
            desinfectHostPetition(netCommandDesinfect)
            netCommandDesinfect.setDeployed(False)
            netCommandDesinfect.setCommandIDs(None)
            netCommands[address][command] = netCommandDesinfect
            if(netCommand == None):
                print("\t\t[*] - Host {address} desinfected".format(address=address))
        elif(netCommandDesinfect.getCommandIDs() == None and netCommand == None):
            print("\t[*] - Host {address} not infected".format(address=address))
    elif(command == supportedModes[2]):
        infected = False
        for commandHost in netCommands[address]:
            netCommandDesinfect = netCommands[address][commandHost]
            if(netCommandDesinfect.getCommandIDs() != None):
                netCommands = desinfectHost(netCommands, commandHost, address, netCommandDesinfect)
                infected = True
        if(infected):
            print("\t\t\t[*] - Host {address} desinfected".format(address=address))
        else:
            print("\t\t[*] - Host {address} not infected".format(address=address))
        
    return netCommands

def deploy(netCommands, command_split) -> dict:
    print("")
    if(command_split[1] == "all"):
        netCommands = deployAll(netCommands)
    else:
        netCommand, _ = deployHost(netCommands,command_split[1], command_split[2])
        if(netCommand != None):
            netCommands[command_split[2]][command_split[1]] = netCommand
    
    return netCommands

def deployAll(netCommands) -> dict:
    deploy = True
    if(netCommands != {}):
        for address, mode in netCommands.items():
            for netCommand in mode.values():
                if(netCommand.deployed()):
                    print("\t[!] - Part of the infrastructure is deployed, desinfect everything before re-deploying\n")
                    deploy = False
                    break

        if(deploy):
            for address, mode in netCommands.items():
                for command,netCommand in mode.items(): 
                    netCommand, correctDeployment = deployHost(netCommands, command, netCommand.getSrcAddr())
                    netCommands[address][command] = netCommand
                    if(not correctDeployment):
                        break 
                if(not correctDeployment):
                    print("\t[!] - Command deploy all canceled due and error deploying last host\n")
                    break 
    else:
        print("\t[!] - Nothing to deploy, check topology.conf\n")
    return netCommands

def deployHostPetition(netCommand) -> tuple:
    netCommandTransfer = json.dumps(netCommand, cls=netCommandObjectEncoder, indent=None, separators=(',', ':')).encode("utf-8")   
    pivot = subprocess.run("exec proxychains -q python connections.py {data}".format(data=netCommandTransfer),capture_output=True,shell=True, text=True)
    
    if(pivot.returncode == 1):
        print("\n"+pivot.stderr)
        print("\n\t[!] - An error ocurred during the {command} deploy on {address} host".format(command = netCommand.getCommand(), address = netCommand.getSrcAddr()))
        return None
    else:
        pivot_output = pivot.stdout.strip().split(",")
        shellID,commandID = pivot_output[0],pivot_output[1]
        return (shellID,commandID)

def deployHost(netCommands, command, address) -> tuple:
    correctDeployment = True
    
    netCommand = netCommands[address][command]
    if(command == supportedModes[0]):
        if(netCommand.deployed()):
            print("\t[*] - Tunnel already deployed\n")
        else:
            print("\t[*] - Deploying tunnel at {address}".format(address=address))
    elif(command == supportedModes[1]):
        print("\t[*] - Deploying port forwarding at {address}".format(address=address))

    if(not netCommand.deployed()):
        hostIdentifiers = deployHostPetition(netCommand)
        if(hostIdentifiers != None):
            netCommands[address][command].setCommandIDs(hostIdentifiers)
            netCommands[address][command].setDeployed(True)
            if(command == supportedModes[0]):
                correctDeployment = probeHost(netCommands,address)
            else:
                print("\t[*] - Port Forwarding: {srcaddr}:{srcport} -> {dstaddr}:{dstport} OK\n".format(srcaddr=netCommand.getSrcAddr(),srcport = netCommand.getSrcPort(), dstaddr=netCommand.getDstAddr(),dstport=netCommand.getDstPort()))
            if(not correctDeployment):
                netCommands = desinfectHost(netCommands, command, address)
        else:
            correctDeployment = False
    
    return netCommands[address][command],correctDeployment

def redeploy(netCommands, command_split) -> dict:
    if(command_split[1]== "all"):
        netCommands = desinfectAll(netCommands, False)
        print("")
        netCommands = deployAll(netCommands)
    else:
        if(len(command_split) == 3):
            if(command_split[2] in netCommands and command_split[1] in netCommands[command_split[2]]):
                netCommands = desinfectHost(netCommands,command_split[1],command_split[2])
                print("")
                netCommand, _ = deployHost(netCommands,command_split[1], command_split[2])
            else:
                print("\t[!] - Provided mode not defined for {addr} on topology.conf\n".format(addr = command_split[2]))
        else:
            netCommands = desinfectHost(netCommands,"all",command_split[1])
            print("")
            netCommand, _ = deployHost(netCommands,command_split[1], command_split[2])
            if(netCommand != None):
                netCommands[command_split[2]][command_split[1]] = netCommand

    return netCommands

def validCommand(command, command_split, netCommands):
    valid = True
    if((command == supportedCommands[1] or command == supportedCommands[0]) and (len(command_split) < 2 or len(command_split) > 3)):
        print("\t[!] - Provided command not supported, type 'help' for more information\n")
        valid = False
    elif(command == supportedCommands[0] and command_split[1] not in supportedProbeProtocols):
        print("\t[!] - Provided command not supported, type 'help' for more information\n")
        valid = False
    elif(command == supportedCommands[1] and len(command_split) == 3 and command_split[1] not in supportedModes):
        print("\t[!] - Provided command not supported, type 'help' for more information\n")
        valid = False 
    elif((command == supportedCommands[5] or command == supportedCommands[2]) and (len(command_split) < 2 or len(command_split) > 3)):
        print("\t[!] - Provided command not supported, type 'help' for more information\n")
        valid = False
    elif((command == supportedCommands[5] or command == supportedCommands[2]) and command_split[1] not in supportedModes):
        print("\t[!] - Provided command not supported, type 'help' for more information\n")
        valid = False 
    elif((command == supportedCommands[6] or command == supportedCommands[3]) and len(command_split) != 1):
        print("\t[!] - Provided command not supported, type 'help' for more information\n")
        valid = False

    if(valid):
        if(command == supportedCommands[1] and len(command_split) == 2 and command_split[1] != "all" and not validAddress(command_split[1])):
            print("\t[!] - Provided address not valid\n")
            valid = False
        elif(command == supportedCommands[1] and len(command_split) == 2 and command_split[1] != "all" and command_split[1] not in netCommands):
            print("\t[!] - Provided address not defined on topology.conf\n")
            valid = False
        elif((command == supportedCommands[5] or command == supportedCommands[2] or command == supportedCommands[1] or command == supportedCommands[0]) and len(command_split) == 3 and not validAddress(command_split[2])):
            print("\t[!] - Provided address not valid\n")
            valid = False
        elif((command == supportedCommands[5] or command == supportedCommands[2] or command == supportedCommands[1] or command == supportedCommands[0]) and len(command_split) == 3 and command_split[2] not in netCommands):
            print("\t[!] - Provided address not defined on topology.conf\n")
            valid = False

    return valid

def helpDialog(supportedCommands,command_split):
    if(len(command_split) > 1 and command_split[1] != ""):
        if(command_split[1] == supportedCommands[2]):
            print("\n\t{0: <30} deploy the desired topology.".format(supportedCommands[2] + " all"))
            print("\t{0: <30} deploy a tunnel in the desired host.".format(supportedCommands[2] + " tunnel <IP>"))
            print("\t{0: <30} deploy a port forwarding the desired host.\n".format(supportedCommands[2] + " portforwarding <IP>"))
        if(command_split[1] == supportedCommands[0]):
            print("\n\t{0: <30} probes the status of the entire topology.".format(supportedCommands[0] + " all"))
            print("\t{0: <30} probes the status of a given host using smb protocol.\n".format(supportedCommands[0] + " smb <IP>"))
        if(command_split[1] == supportedCommands[1]):
            print("\n\t{0: <30} desinfects the desired host.".format(supportedCommands[1] + " <IP>"))
            print("\t{0: <30} desinfects the tunnel on the desired host.".format(supportedCommands[1] + " tunnel <IP>"))
            print("\t{0: <30} desinfects the port forwarding on the desired host.".format(supportedCommands[1] + " portforwarding <IP>"))
            print("\t{0: <30} desinfects all the infected machines.\n".format(supportedCommands[1] + " all"))
        if(command_split[1] == supportedCommands[5]):
            print("\n\t{0: <30} redeploys all the topology.".format(supportedCommands[5] + " all"))
            print("\t{0: <30} redeploys a tunnel on the desired host.".format(supportedCommands[5] + " tunnel <IP>"))
            print("\t{0: <30} redeploys a port forwarding on the desired host.\n".format(supportedCommands[5] + " portforwarding <IP>"))
    else:
        print("\n\t{: <9} [+] \t {: <20}".format(supportedCommands[2], "deploys the desired topology."))
        print("\t{: <9} [+] \t {: <20}".format(supportedCommands[1], "desinfects the desired topology."))
        print("\t{: <9} [+] \t {: <20}".format(supportedCommands[5], "redeploys the desired topology."))
        print("\t{: <9} [+] \t {: <20}".format(supportedCommands[0], "probes the status of the topology."))
        print("\t{: <9}  \t {: <20}".format(supportedCommands[6], "reads the topology.conf file and updates the topology"))
        print("\t{: <9}  \t {: <20}".format(supportedCommands[3], "desinfects all the machines and exits Ant."))
        print("\t{: <9}  \t {: <20}".format(supportedCommands[4], "shows this help message.\n"))
        print("\n\tFor command details: help <COMMAND>\n")

def interactiveMode(netCommands):
    print("  ___  __  __ ______  ")
    print(" // \\\ ||\ || | || |  ")
    print(" ||=|| ||\\\||   ||    ")
    print(" || || || \||   ||  \n")
    
    print("Interactive mode - type 'help' for more information\n")

    historialFile = ".ant_history"

    try:
        readline.read_history_file(historialFile)
        readline.set_history_length(1000)
    except FileNotFoundError:
        pass

    command = ""
    
    try:
        while command != "exit":
            command_raw = input(">> ")
            command_split = command_raw.split(" ")
            command_split = [entry.lower() for entry in command_split]
            command = command_split[0]

            if(command in supportedCommands and validCommand(command, command_split, netCommands)):
                if command_raw.strip() == "\x1b[A":
                    historialLen = readline.get_current_history_length()
                    if historialLen > 1:
                        prev_command = readline.get_history_item(historialLen - 2)
                        command_raw = prev_command
                else:
                    readline.add_history(command_raw)
                    if(command == supportedCommands[0]):
                        probe(netCommands, command_split)
                    elif(command == supportedCommands[1]):
                        netCommands = desinfect(netCommands, command_split)
                    elif(command == supportedCommands[2]):
                        netCommands = deploy(netCommands, command_split)
                    elif(command == supportedCommands[3]):
                        readline.clear_history()
                        desinfectAll(netCommands, True)
                    elif(command == supportedCommands[4]):
                        helpDialog(supportedCommands, command_split)
                    elif(command == supportedCommands[5]):
                        netCommands = redeploy(netCommands, command_split)
                    elif(command == supportedCommands[6]):
                        netCommands = readTopology()
                        print("\n [*] - topology updated\n")
    except EOFError:
        print("\n\t[*] - Signal received, forcing exit")
        desinfectAll(netCommands, True)
    except KeyboardInterrupt:
        print("\n\t[*] - Signal received, forcing exit")
        desinfectAll(netCommands, True)
    except:
        print(traceback.print_exc())
        desinfectAll(netCommands, True)
        print("\n\t[!] - If you see this message something strange happens, contact with the owner of the project. Thanks :) - [!]")

def readTopology() -> list:
    topology = {}
    topology_raw = open(topologyFile).read().splitlines()
    for host_command_raw in topology_raw:
        if("#" not in host_command_raw and host_command_raw != ""):
            host_command = host_command_raw.split(",")
            host_command = [entry.lower() for entry in host_command]
            netCommand = netCommandObject()
            if(len(host_command) == 9):
                netCommand.chiselCommand(host_command[0],host_command[1],host_command[2],host_command[3],host_command[4],host_command[5],host_command[6],host_command[7],host_command[8])
            elif(len(host_command) == 7):
                netCommand.portforwardingCommand(host_command[0],host_command[1],host_command[2],host_command[3],host_command[4],host_command[5],host_command[6])
            
            if(host_command[5] not in topology):
                topology[host_command[5]] = {}
            
            topology[host_command[5]][host_command[1]] = netCommand

    return topology

def validTopologyFile() -> bool:
    i, valid = 1, True
    topology_raw = open(topologyFile).read().splitlines()
    
    for host_command_raw in topology_raw:
        if("#" not in host_command_raw and host_command_raw != ""):
            host_command = host_command_raw.split(",")
            host_command = [entry.lower() for entry in host_command]

            if(len(host_command) != 7 and len(host_command) != 9):
                print("[!] - Length error at line {index} in topology file".format(index=i))
                valid = False
                break

            if(host_command[0] not in supportedProtocols):
                print("[!] - Protocol not supported at line {index} in topology file".format(index=i))
                valid = False
                break
            if(host_command[1] not in supportedModes):
                print("[!] - Mode not supported at line {index} in topology file".format(index=i))
                valid = False
                break
            if(host_command[2] not in supportedBinaries):
                print("[!] - Command not supported at line {index} in topology file".format(index=i))
                valid = False
                break

            if(len(host_command) == 9):
                if(not validAddress(host_command[3]) or not validAddress(host_command[5]) or not validAddress(host_command[6])):
                    print("[!] - Invalid IP address at line {index} in topology file".format(index=i))
                    valid = False
                    break
                elif(not validPort(int(host_command[4]))):
                    print("[!] - Invalid port at line {index} in topology file".format(index=i))
                    valid = False
                    break
                elif(host_command[8] not in supportedProbeProtocols):
                    print("[!] - Invalid probe protocol at line {index} in topology file".format(index=i))
                    valid = False
                    break
            elif(len(host_command) == 7):
                if(not validAddress(host_command[3]) or not validAddress(host_command[5])):
                    print("[!] - Invalid IP address at line {index} in topology file".format(index=i))
                    valid = False
                    break
                elif(not validPort(int(host_command[4])) or not validPort(int(host_command[6]))):
                    print("[!] - Invalid port at line {index} in topology file".format(index=i))
                    valid = False
                    break
            i+=1

    return valid

def makeFiles() -> bool:
    firstTime = False
    if(not os.path.isdir(executablesFolder)):
        print("\n\t[*] - \"executables\" folder created")
        os.makedirs(executablesFolder)
        firstTime = True
    
    if(not os.path.isfile(topologyFile)):
        print("\t[*] - \"topology.conf\" created")
        topology = open(topologyFile, "w")
        topology.write("# [*]---------------------------------------------------------------------------------------[*]\n# tunnel\n# protocol,mode,command,dst_addr,dst_port,src_addr,src_port,target,chisel_id,probe_protocol\n\n# port forwarding\n# protocol,mode,command,dst_addr,dst_port,src_addr,src_port\n# [*]---------------------------------------------------------------------------------------[*]\n\n# Topology here")
        topology.close()
        firstTime = True

    if(not os.path.isfile(authFile)):
        print("\t[*] - \"auth.conf\" created")
        auth = open(authFile, "w")
        auth.write("# [*]---------------------------------------------------------------------------------------[*]\n# dst_addr,domain,username,password/ntlm hash\n# [*]---------------------------------------------------------------------------------------[*]\n\n# Auth here")
        auth.close()    
        firstTime = True

    return firstTime   

def ant() -> None:
    if(not makeFiles()):
        if(validTopologyFile()):
            netCommands = readTopology()
            interactiveMode(netCommands)
    else:
        print("\n\tNow you can configure and launch Ant normally :) Happy hacking!")

if __name__ == "__main__":
    ant()