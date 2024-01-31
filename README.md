Ant is a post-exploitation tool that allows to automate the deployment of tunnels and port forwarding over a topology previously defined in a configuration file. To achieve this remotely, Ant can perform all actions over the WMI and WinRM protocols in addition to the SMB protocol for certain parts of the deployment phase.

Ant has 4 main commands, deploy, desinfect, redeploy and probe.
```
>> help

        deploy    [+]    deploys the desired topology.
        desinfect [+]    desinfects the desired topology.
        redeploy  [+]    redeploys the desired topology.
        probe     [+]    probes the status of the topology.
        update           reads the topology.conf file and updates the topology
        exit             desinfects all the machines and exits Ant.
        help             shows this help message.


        For command details: help <COMMAND>
```

## Ant preview

![post](https://github.com/Krypteria/Ant/assets/55555187/af152fb7-7326-4bde-a9d3-9781529d496e)

## Ant capabilities

### Deploy
  
```
>> help deploy

        deploy all                     deploy the desired topology.
        deploy tunnel <IP>             deploy a tunnel in the desired host.
        deploy portforwarding <IP>     deploy a port forwarding the desired host.
```
#### Supported protocols and binaries

Ant allows the user to perform actions using the WMI protocol or the WinRM protocol. There are two types of deployment, tunnel deployment or portforwarding deployment. The type of deployment depends on the data of the **topology.conf** configuration file.

The topology.conf file has the following structure:
```
# tunnel
protocol,mode,command,dst_addr,dst_port,src_addr,target,chisel_id,probe_protocol

# port forwarding
protocol,mode,command,dst_addr,dst_port,src_addr,src_port
```
- protocol: wmi,winrm
- mode: tunnel, portforwarding
- command: chisel,netsh,goproxy,socat
- target: IP of a machine reachable only if the tunnel is deployed correctly.
- probe_protocol: protocol to be used to do a reachability test (currently SMB only)

Ant also has two extra functionalities regarding the topology.conf configuration file.
- Automatically validates that the contents of the topology.conf file are correct and indicates the errors it finds if it is not correct.
- topology.conf file supports comments. Lines starting with # will be ignored.

To understand how to use the topology.conf file, let's assume we have the following topology belonging to an internal network on which we want to operate:

![image](https://user-images.githubusercontent.com/55555187/232250429-0f685d68-655e-4b16-984e-5d8d6a6058ef.png)

In order to have connectivity to all machines from the attacking machine, the following configuration file could be used:
```
wmi,tunnel,chisel,172.16.1.10,8081,172.16.1.23,172.16.1.5,1111,smb
wmi,portforwarding,netsh,172.16.1.10,8081,172.16.1.23,3000
winrm,tunnel,chisel,172.16.1.23,3000,172.16.1.5,172.16.2.6,2222,smb
wmi,portforwarding,goproxy,172.16.1.23,3000,172.16.1.5,3000
winrm,tunnel,chisel,172.16.1.5,3000,172.16.2.6,172.16.2.10,3333,smb
```

With this configuration file, Ant would perform the following actions:

1. Creates a tunnel using chisel from IP 172.16.1.23 to IP 172.16.1.10:8081 assigning session ID 1111
2. Creates a port forwarding using netsh from IP 172.16.1.1.23:3000 to IP 172.16.1.1.10:8081
3. Creates a tunnel using chisel from IP 172.16.1.1.5 to IP 172.16.1.1.23:3000 assigning ID 2222
4. Creates a port forwarding using goproxy from IP 172.16.1.1.5:3000 to IP 172.16.1.1.23:3000
5. Creates a tunnel using chisel from IP 172.16.2.6 to IP 172.16.1.5:3000 assigning ID 3333

After executing the above actions we would have the following topology:

![image](https://user-images.githubusercontent.com/55555187/232250262-4bc5495a-c60d-4096-a9cb-c4ae80ad1007.png)

For this to work, one must have Administrator privileges on the machines on which the binaries are deployed because certain actions in the deployment and disinfection stages require such privileges. The credentials are provided through a configuration file named **auth.conf** which has the following format:

```
dst_addr,domain,username,password/ntlm hash
```

For the above topology, an example of auth.conf file would be as follows:
```
172.16.1.23,epicorp.local,mySuperDA,domainadmin123
172.16.1.5,epicorp.local,mySuperDA,domainadmin123
172.16.2.6,supercorp.local,JeffADM:70016778cc0524c799ac25b439bd61e0
```

Having explained the requirements for implementing actions with Ant, it is important to understand the inner workings of Ant in order to assess its opsec degree (it's not much but it's honest work) an when to use it.

#### How the deployment phase works

Ant performs the deployment phase in a variable number of stages, depending on whether we are deploying a tunnel or a port forwarding. It is important to note that all binaries to be deployed must be in the **/executables** directory created when Ant is started.

Tunnel 

1. An exception in the anti-malware solution for the *C:\windows\system32\drivers\spool\color or C:\users\public\documents* (if the first one doesn't exist, Ant uses the second one) folder is deployed remotely using WMI/WinRM (Currently only Windows Defender is covered)
2. Through an SMB connection the binary is uploaded to the *C:\windows\system32\drivers\spool\color* folder 
3. Once the binary has been deployed, it is verified that the binary has been uploaded correctly by accessing it via SMB.
4. Using WMI / WinRM, the command associated with that binary is executed using the parameters of the topology.conf and auth.conf files.

Port forwarding

1. An exception in the anti-malware solution for the  *C:\windows\system32\drivers\spool\color or C:\users\public\documents* (if the first one doesn't exist, Ant uses the second one) folder is deployed remotely using WMI/WinRM (Currently only Windows Defender is covered)
2. Through an SMB connection the binary is uploaded to the *C:\windows\system32\drivers\spool\color* folder (in the netsh case, this step is not performed)
3. Using WMI / WinRM, the command associated with that binary is executed using the parameters of the topology.conf and auth.conf files

#### How the AV exception is created

In general, Windows Defender exceptions are stored in the registry key *HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions
\Paths*. This registry is blocked against terminal writes by the wdfilter.sys (kernel-mode driver) process giving an UnauthorizedAccessException error unless it is done from the GUI or using the Add-MpPreference cmdlet in Powershell.

Because modification of the registry by any of these methods is highly controlled, it is not viable if a more stealthy approach is desired.

A less known alternative is the registry key *HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths* which is used to define exclusions at group policy level. This registry key is not protected by the wdfilter.sys process and can be modified using reg.exe.

In general, the keys \Exclusion and \Paths are not defined, so it is necessary to first check if they are present or need to be created. To do this, Ant uses different ways to obtain this information. In the case of **WMI**, the [stdregprov](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/regprov/stdregprov) class is used to query the registry and obtain direct output. In the case of **WinRM** it makes use of the endpoint :5985/wsman to spawn a cmd.exe process that interacts with the registry using reg.exe.

Once the presence of these registry keys have been checked and they have been created if necessary, Ant creates a new exclusion for the file *C:\windows\system32\drivers\spool\color or C:\users\public\documents* (if the first one doesn't exist, Ant uses the second one) using reg.exe. Once the exclusion has been added, it is necessary to update the machine's group policies for this change to take effect, which requires Administrator permissions. The default Windows gpupdate command is used to perform this update.

It is important to note that this technique only works on domain-joined machines that can make use of group policies. For non-domain joined machines you would have to create an empty local group policy and then update the group policy or reboot the machine. These options are not implemented.

### Probe
  
```
>> help probe

        probe all                      probes the status of the entire topology.
        probe smb <IP>                 probes the status of a given host using smb protocol.
```
The probe stage can happen in two different situations.
1. The user requests it by providing an IP with a tunnel deployed on it.
2. Once the deployment is finished, it is automatically launched against the target IP provided in the topology.conf file.

The probe works as follows, a login is performed against the SMB service from the IP provided using a fake username and password (this could generate IOCs so in the future it will be considered to allow the user to enter the username and password to be used). Depending on the response from the server it can be determined whether we have visibility with the machine or not.

If the response obtained contains the string *STATUS_LOGON_FAILURE* it means that we have visibility with the machine but the credentials are not valid. On the other hand, if we obtain a response containing the string *Connection refused* then we do not have visibility with the machine.

### Desinfection

```
>> help desinfect

        desinfect <IP>                 desinfects the desired host.
        desinfect tunnel <IP>          desinfects the tunnel on the desired host.
        desinfect portforwarding <IP>  desinfects the port forwarding on the desired host.
        desinfect all                  desinfects all the infected machines.
```

The sanitisation phase, like the deployment phase, uses the WMI and WinRM protocols to perform actions and involves a variable number of steps depending on whether a port forwarding or a tunnel is desinfected.

The first step is common to both scenarios. The process of the binary is killed using **wmic** from a cmd spawned either with WMI or WinRM. Once the process has been killed, the binary (if there is a binary deployed, in the case of netsh this step is not performed) is deleted using the previously spawned cmd. When there is no trace of the file, the Windows Defender exception is removed using the same techniques described in the deployment section. 

One detail that is important to keep in mind is that when you run the "desinfect all" command, it starts desinfecting in reverse order to the order of infection. That is, the last tunnel / port forwarding deployed will be the first to be disinfected in order to avoid leaving infected and unreachable network segments.

### Redeploy

```
>> help redeploy

        redeploy all                   redeploys all the topology.
        redeploy tunnel <IP>           redeploys a tunnel on the desired host.
        redeploy portforwarding <IP>   redeploys a port forwarding on the desired host.

```

I don't have much to say about this feature, if you need to redeploy a tunnel or portforwarding on an already infected host, this option allows you to perform the desinfection and deployment phase without having to type both commands.


### Other relevant features

- Ant has a **command history system** implemented to allow quick retyping of previous commands in the interactive session :)
- The **topology.conf file can be loaded dynamically**. If you want to add a new line and launch it with Ant, you don't need to re-launch the script, just run the **update** command and the desired topology will be the one currently in the topology.conf file. It is also worth mentioning that the auth.conf file is always dynamically loaded for new deployments so you can always add new credentials. 

*Caution, if you remove a line that defines a tunnel or port forwarding from the topology.conf file and it was deployed, Ant will no longer take it into account so it will not be possible to desinfect it. Be careful what you change in the configuration file.*

## Dependencies and installation

Python >= 3.8 is required.

It is recommended to use conda's virtual environments when installing Ant. An enviroment for Ant can be created as follows:
```
conda create -n ant python=3.9
```
Once the environment has been created, it must be activated in the following way
```
conda activate ant
```

With the environment activated, the requirements are installed using pip.
```
pip install -r requirements.txt
```

## Disclaimer

Ant is a project made for fun and has a lot of things that could be improved to be considered fully opsec. Still, I think it can be useful to automate these tasks in controlled environments and especially in environments like HackTheBox or similar where machines are rebooted every day and it can be tedious to do the whole process manually.

As always, use this project in controlled environments or with express permission. 

