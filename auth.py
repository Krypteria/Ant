authFile = "auth.conf"

class authentication:
    def __init__(self,host,domain,username,password) -> None:
        self._host = host
        self._domain = domain
        self._username = username
        if(":" in password and len(password) < 64):
            self._password = "00000000000000000000000000000000" + password
        else:
            self._password = password

    def getHost(self) -> str:
        return self._host
    
    def getDomain(self) -> str:
        return self._domain
    
    def getUsername(self) -> str:
        return self._username
    
    def getPassword(self) -> str:
        return self._password
    
    def retrieveAuthMethodCreds(self):
        password, lmhash, nthash="","",""
        
        if(":" in self.getPassword()):
            ntlm = self.getPassword().split(":")
            lmhash, nthash = ntlm[0], ntlm[1]
        else:
            password = self.getPassword()
        
        return password,lmhash,nthash
    
def getAuth(address) -> authentication:
    auth_raw = open(authFile).read().splitlines()
    for line_raw in auth_raw:
        if("#" not in line_raw):
            auth = line_raw.split(",")
            if(auth[0] == address):
                break
    return authentication(auth[0],auth[1],auth[2],auth[3])