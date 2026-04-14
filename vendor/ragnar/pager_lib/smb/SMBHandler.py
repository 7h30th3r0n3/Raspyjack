import os, sys, socket, urllib.request, urllib.error, urllib.parse, mimetypes, email, tempfile
from urllib.parse import (unwrap, unquote, splittype, splithost, quote,
     splitport, splittag, splitattr, splituser, splitpasswd, splitvalue)
from urllib.response import addinfourl
from urllib.request import ftpwrapper
from nmb.NetBIOS import NetBIOS
from smb.SMBConnection import SMBConnection

from io import BytesIO

USE_NTLM = True
MACHINE_NAME = None

class SMBHandler(urllib.request.BaseHandler):

    def smb_open(self, req):
        global USE_NTLM, MACHINE_NAME

        if not req.host:
            raise urllib.error.URLError('SMB error: no host given')
        host, port = splitport(req.host)
        if port is None:
            port = 139
        else:
            port = int(port)

        # username/password handling

        user, host = splituser(host)
        
        if user:
            user, passwd = splitpasswd(user)
        else:
            passwd = None
        
        host = unquote(host)
        user = user or ''

        domain = ''
        if ';' in user:
            domain, user = user.split(';', 1)

        passwd = passwd or ''
        myname = MACHINE_NAME or self.generateClientMachineName()

        server_name,host = host.split(',') if ',' in host else [None,host]

        if server_name is None:
            n = NetBIOS()

            names = n.queryIPForName(host)
            if names:
                server_name = names[0]
            else:
                raise urllib.error.URLError('SMB error: Hostname does not reply back with its machine name')

        path, attrs = splitattr(req.selector)
        if path.startswith('/'):
            path = path[1:]
        dirs = path.split('/')
        dirs = list(map(unquote, dirs))
        service, path = dirs[0], '/'.join(dirs[1:])

        try:
            conn = SMBConnection(user, passwd, myname, server_name, domain=domain, use_ntlm_v2 = USE_NTLM)
            conn.connect(host, port)

            headers = email.message.Message()
            if req.data:
                filelen = conn.storeFile(service, path, req.data)

                headers.add_header('Content-length', '0')
                fp = BytesIO(b"")
            else:
                fp = self.createTempFile()
                file_attrs, retrlen = conn.retrieveFile(service, path, fp)
                fp.seek(0)

                mtype = mimetypes.guess_type(req.get_full_url())[0]
                if mtype:
                    headers.add_header('Content-type', mtype)
                if retrlen is not None and retrlen >= 0:
                    headers.add_header('Content-length', '%d' % retrlen)

            return addinfourl(fp, headers, req.get_full_url())
        except Exception as ex:
            raise urllib.error.URLError('smb error: %s' % ex).with_traceback(sys.exc_info()[2])

    def createTempFile(self):
        return tempfile.TemporaryFile()

    def generateClientMachineName(self):
        hostname = socket.gethostname()
        if hostname:
            return hostname.split('.')[0]
        return 'SMB%d' % os.getpid()
