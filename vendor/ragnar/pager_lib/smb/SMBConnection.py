
import os, logging, select, socket, types, typing, struct, errno

from tqdm import tqdm
from .smb_constants import *
from .smb_structs import *
from .base import SMB, NotConnectedError, NotReadyError, SMBTimeout


class SMBConnection(SMB):

    log = logging.getLogger('SMB.SMBConnection')

    #: SMB messages will never be signed regardless of remote server's configurations; access errors will occur if the remote server requires signing.
    SIGN_NEVER = 0
    #: SMB messages will be signed when remote server supports signing but not requires signing.
    SIGN_WHEN_SUPPORTED = 1
    #: SMB messages will only be signed when remote server requires signing.
    SIGN_WHEN_REQUIRED = 2

    def __init__(self, username, password, my_name, remote_name, domain = '', use_ntlm_v2 = True, sign_options = SIGN_WHEN_REQUIRED, is_direct_tcp = False):
        """
        Create a new SMBConnection instance.

        *username* and *password* are the user credentials required to authenticate the underlying SMB connection with the remote server.
        *password* can be a string or a callable returning a string.
        File operations can only be proceeded after the connection has been authenticated successfully.

        Note that you need to call *connect* method to actually establish the SMB connection to the remote server and perform authentication.

        The default TCP port for most SMB/CIFS servers using NetBIOS over TCP/IP is 139.
        Some newer server installations might also support Direct hosting of SMB over TCP/IP; for these servers, the default TCP port is 445.

        :param string my_name: The local NetBIOS machine name that will identify where this connection is originating from.
                               You can freely choose a name as long as it contains a maximum of 15 alphanumeric characters and does not contain spaces and any of ``\\/:*?";|+``
        :param string remote_name: The NetBIOS machine name of the remote server.
                                   On windows, you can find out the machine name by right-clicking on the "My Computer" and selecting "Properties".
                                   This parameter must be the same as what has been configured on the remote server, or else the connection will be rejected.
        :param string domain: The network domain. On windows, it is known as the workgroup. Usually, it is safe to leave this parameter as an empty string.
        :param boolean use_ntlm_v2: Indicates whether pysmb should be NTLMv1 or NTLMv2 authentication algorithm for authentication.
                                    The choice of NTLMv1 and NTLMv2 is configured on the remote server, and there is no mechanism to auto-detect which algorithm has been configured.
                                    Hence, we can only "guess" or try both algorithms.
                                    On Sambda, Windows Vista and Windows 7, NTLMv2 is enabled by default. On Windows XP, we can use NTLMv1 before NTLMv2.
        :param int sign_options: Determines whether SMB messages will be signed. Default is *SIGN_WHEN_REQUIRED*.
                                 If *SIGN_WHEN_REQUIRED* (value=2), SMB messages will only be signed when remote server requires signing.
                                 If *SIGN_WHEN_SUPPORTED* (value=1), SMB messages will be signed when remote server supports signing but not requires signing.
                                 If *SIGN_NEVER* (value=0), SMB messages will never be signed regardless of remote server's configurations; access errors will occur if the remote server requires signing.
        :param boolean is_direct_tcp: Controls whether the NetBIOS over TCP/IP (is_direct_tcp=False) or the newer Direct hosting of SMB over TCP/IP (is_direct_tcp=True) will be used for the communication.
                                      The default parameter is False which will use NetBIOS over TCP/IP for wider compatibility (TCP port: 139).
        """
        SMB.__init__(self, username, password, my_name, remote_name, domain, use_ntlm_v2, sign_options, is_direct_tcp)
        self.sock = None
        self.auth_result = None
        self.is_busy = False
        self.is_direct_tcp = is_direct_tcp

    #
    # SMB (and its superclass) Methods
    #

    def onAuthOK(self):
        self.auth_result = True

    def onAuthFailed(self):
        self.auth_result = False

    def write(self, data):
        assert self.sock
        data_len = len(data)
        total_sent = 0
        while total_sent < data_len:
            sent = self.sock.send(data[total_sent:])
            if sent == 0:
                raise NotConnectedError('Server disconnected')
            total_sent = total_sent + sent

    #
    # Support for "with" context
    #
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    #
    # Misc Properties
    #

    @property
    def isUsingSMB2(self):
        """A convenient property to return True if the underlying SMB connection is using SMB2 protocol."""
        return self.is_using_smb2


    #
    # Public Methods
    #

    def connect(self, ip, port = 139, sock_family = None, timeout = 60):
        """
        Establish the SMB connection to the remote SMB/CIFS server.

        You must call this method before attempting any of the file operations with the remote server.
        This method will block until the SMB connection has attempted at least one authentication.

        :param port: Defaults to 139. If you are using direct TCP mode (is_direct_tcp=true when creating this SMBConnection instance), use 445.
        :param sock_family: In Python 3.x, use *None* as we can infer the socket family from the provided *ip*. In Python 2.x, it must be either *socket.AF_INET* or *socket.AF_INET6*.
        :return: A boolean value indicating the result of the authentication atttempt: True if authentication is successful; False, if otherwise.
        """
        if self.sock:
            self.sock.close()

        self.auth_result = None
        if sock_family:
            self.sock = socket.socket(sock_family)
            self.sock.settimeout(timeout)
            self.sock.connect(( ip, port ))
        else:
            self.sock = socket.create_connection(( ip, port ), timeout = timeout)

        self.is_busy = True
        try:
            if not self.is_direct_tcp:
                self.requestNMBSession()
            else:
                self.onNMBSessionOK()
            while self.auth_result is None:
                self._pollForNetBIOSPacket(timeout)
        finally:
            self.is_busy = False

        return self.auth_result

    def close(self):
        """
        Terminate the SMB connection (if it has been started) and release any sources held by the underlying socket.
        """
        if self.sock:
            self.sock.close()
            self.sock = None

    def listShares(self, timeout = 30):
        """
        Retrieve a list of shared resources on remote server.

        :return: A list of :doc:`smb.base.SharedDevice<smb_SharedDevice>` instances describing the shared resource
        """
        if not self.sock:
            raise NotConnectedError('Not connected to server')

        results = [ ]

        def cb(entries):
            self.is_busy = False
            results.extend(entries)

        def eb(failure):
            self.is_busy = False
            raise failure

        self.is_busy = True
        try:
            self._listShares(cb, eb, timeout)
            while self.is_busy:
                self._pollForNetBIOSPacket(timeout)
        finally:
            self.is_busy = False

        return results

    def listPath(self, service_name, path,
                 search = SMB_FILE_ATTRIBUTE_READONLY | SMB_FILE_ATTRIBUTE_HIDDEN | SMB_FILE_ATTRIBUTE_SYSTEM | SMB_FILE_ATTRIBUTE_DIRECTORY | SMB_FILE_ATTRIBUTE_ARCHIVE | SMB_FILE_ATTRIBUTE_INCL_NORMAL,
                 pattern = '*', timeout = 30):
        """
        Retrieve a directory listing of files/folders at *path*

        For simplicity, pysmb defines a "normal" file as a file entry that is not read-only, not hidden, not system, not archive and not a directory.
        It ignores other attributes like compression, indexed, sparse, temporary and encryption.

        Note that the default search parameter will query for all read-only (SMB_FILE_ATTRIBUTE_READONLY), hidden (SMB_FILE_ATTRIBUTE_HIDDEN),
        system (SMB_FILE_ATTRIBUTE_SYSTEM), archive (SMB_FILE_ATTRIBUTE_ARCHIVE), normal (SMB_FILE_ATTRIBUTE_INCL_NORMAL) files
        and directories (SMB_FILE_ATTRIBUTE_DIRECTORY).
        If you do not need to include "normal" files in the result, define your own search parameter without the SMB_FILE_ATTRIBUTE_INCL_NORMAL constant.
        SMB_FILE_ATTRIBUTE_NORMAL should be used by itself and not be used with other bit constants.

        :param string/unicode service_name: the name of the shared folder for the *path*
        :param string/unicode path: path relative to the *service_name* where we are interested to learn about its files/sub-folders.
        :param integer search: integer value made up from a bitwise-OR of *SMB_FILE_ATTRIBUTE_xxx* bits (see smb_constants.py).
        :param string/unicode pattern: the filter to apply to the results before returning to the client.
        :return: A list of :doc:`smb.base.SharedFile<smb_SharedFile>` instances.
        """
        if not self.sock:
            raise NotConnectedError('Not connected to server')

        results = [ ]

        def cb(entries):
            self.is_busy = False
            results.extend(entries)

        def eb(failure):
            self.is_busy = False
            raise failure

        self.is_busy = True
        try:
            self._listPath(service_name, path, cb, eb, search = search, pattern = pattern, timeout = timeout)
            while self.is_busy:
                self._pollForNetBIOSPacket(timeout)
        finally:
            self.is_busy = False

        return results

    def listSnapshots(self, service_name, path, timeout = 30):
        """
        Retrieve a list of available snapshots (shadow copies) for *path*.

        Note that snapshot features are only supported on Windows Vista Business, Enterprise and Ultimate, and on all Windows 7 editions.

        :param string/unicode service_name: the name of the shared folder for the *path*
        :param string/unicode path: path relative to the *service_name* where we are interested in the list of available snapshots
        :return: A list of python *datetime.DateTime* instances in GMT/UTC time zone
        """
        if not self.sock:
            raise NotConnectedError('Not connected to server')

        results = [ ]

        def cb(entries):
            self.is_busy = False
            results.extend(entries)

        def eb(failure):
            self.is_busy = False
            raise failure

        self.is_busy = True
        try:
            self._listSnapshots(service_name, path, cb, eb, timeout = timeout)
            while self.is_busy:
                self._pollForNetBIOSPacket(timeout)
        finally:
            self.is_busy = False

        return results

    def getAttributes(self, service_name, path, timeout = 30):
        """
        Retrieve information about the file at *path* on the *service_name*.

        :param string/unicode service_name: the name of the shared folder for the *path*
        :param string/unicode path: Path of the file on the remote server. If the file cannot be opened for reading, an :doc:`OperationFailure<smb_exceptions>` will be raised.
        :return: A :doc:`smb.base.SharedFile<smb_SharedFile>` instance containing the attributes of the file.
        """
        if not self.sock:
            raise NotConnectedError('Not connected to server')

        results = [ ]

        def cb(info):
            self.is_busy = False
            results.append(info)

        def eb(failure):
            self.is_busy = False
            raise failure

        self.is_busy = True
        try:
            self._getAttributes(service_name, path, cb, eb, timeout)
            while self.is_busy:
                self._pollForNetBIOSPacket(timeout)
        finally:
            self.is_busy = False

        return results[0]

    def getSecurity(self, service_name, path, timeout = 30):
        """
        Retrieve the security descriptor of the file at *path* on the *service_name*.

        :param string/unicode service_name: the name of the shared folder for the *path*
        :param string/unicode path: Path of the file on the remote server. If the file cannot be opened for reading, an :doc:`OperationFailure<smb_exceptions>` will be raised.
        :return: A :class:`smb.security_descriptors.SecurityDescriptor` instance containing the security information of the file.
        """
        if not self.sock:
            raise NotConnectedError('Not connected to server')

        results = [ ]

        def cb(info):
            self.is_busy = False
            results.append(info)

        def eb(failure):
            self.is_busy = False
            raise failure

        self.is_busy = True
        try:
            self._getSecurity(service_name, path, cb, eb, timeout)
            while self.is_busy:
                self._pollForNetBIOSPacket(timeout)
        finally:
            self.is_busy = False

        return results[0]

    def retrieveFile(self, service_name, path, file_obj, timeout = 30, show_progress = False, tqdm_kwargs = {}):
        """
        Retrieve the contents of the file at *path* on the *service_name* and write these contents to the provided *file_obj*.

        Use *retrieveFileFromOffset()* method if you wish to specify the offset to read from the remote *path* and/or the number of bytes to write to the *file_obj*.

        :param string/unicode service_name: the name of the shared folder for the *path*
        :param string/unicode path: Path of the file on the remote server. If the file cannot be opened for reading, an :doc:`OperationFailure<smb_exceptions>` will be raised.
        :param file_obj: A file-like object that has a *write* method. Data will be written continuously to *file_obj* until EOF is received from the remote service. In Python3, this file-like object must have a *write* method which accepts a bytes parameter.
        :param bool show_progress: If True, a progress bar will be shown to reflect the current file operation progress.
        :return: A 2-element tuple of ( file attributes of the file on server, number of bytes written to *file_obj* ).
                 The file attributes is an integer value made up from a bitwise-OR of *SMB_FILE_ATTRIBUTE_xxx* bits (see smb_constants.py)
        """
        return self.retrieveFileFromOffset(service_name, path, file_obj, 0, -1, timeout, show_progress = show_progress, tqdm_kwargs = tqdm_kwargs)

    def retrieveFileFromOffset(self, service_name, path, file_obj, offset = 0, max_length = -1, timeout = 30, show_progress = False, tqdm_kwargs = {}):
        """
        Retrieve the contents of the file at *path* on the *service_name* and write these contents to the provided *file_obj*.

        :param string/unicode service_name: the name of the shared folder for the *path*
        :param string/unicode path: Path of the file on the remote server. If the file cannot be opened for reading, an :doc:`OperationFailure<smb_exceptions>` will be raised.
        :param file_obj: A file-like object that has a *write* method. Data will be written continuously to *file_obj* up to *max_length* number of bytes. In Python3, this file-like object must have a *write* method which accepts a bytes parameter.
        :param integer/long offset: the offset in the remote *path* where the first byte will be read and written to *file_obj*. Must be either zero or a positive integer/long value.
        :param integer/long max_length: maximum number of bytes to read from the remote *path* and write to the *file_obj*. Specify a negative value to read from *offset* to the EOF.
                                        If zero, the method returns immediately after the file is opened successfully for reading.
        :param bool show_progress: If True, a progress bar will be shown to reflect the current file operation progress.
        :return: A 2-element tuple of ( file attributes of the file on server, number of bytes written to *file_obj* ).
                 The file attributes is an integer value made up from a bitwise-OR of *SMB_FILE_ATTRIBUTE_xxx* bits (see smb_constants.py)
        """
        if not self.sock:
            raise NotConnectedError('Not connected to server')

        results = [ ]

        def cb(r):
            self.is_busy = False
            results.append(r[1:])

        def eb(failure):
            self.is_busy = False
            raise failure

        self.is_busy = True
        
        try:
            self._retrieveFileFromOffset(service_name, path, file_obj, cb, eb, offset, max_length, timeout = timeout, show_progress=show_progress, tqdm_kwargs=tqdm_kwargs)
            while self.is_busy:
                self._pollForNetBIOSPacket(timeout)
        finally:
            self.is_busy = False

        return results[0]

    def storeFile(self, service_name, path, file_obj, timeout = 30, show_progress = False, tqdm_kwargs = {}):
        """
        Store the contents of the *file_obj* at *path* on the *service_name*.
        If the file already exists on the remote server, it will be truncated and overwritten.

        :param string/unicode service_name: the name of the shared folder for the *path*
        :param string/unicode path: Path of the file on the remote server. If the file at *path* does not exist, it will be created. Otherwise, it will be overwritten.
                                    If the *path* refers to a folder or the file cannot be opened for writing, an :doc:`OperationFailure<smb_exceptions>` will be raised.
        :param file_obj: A file-like object that has a *read* method. Data will read continuously from *file_obj* until EOF. In Python3, this file-like object must have a *read* method which returns a bytes parameter.
        :param bool show_progress: If True, a progress bar will be shown to reflect the current file operation progress.
        :return: Number of bytes uploaded
        """
        return self.storeFileFromOffset(service_name, path, file_obj, 0, True, timeout, show_progress = show_progress, tqdm_kwargs = tqdm_kwargs)

    def storeFileFromOffset(self, service_name, path, file_obj, offset = 0, truncate = False, timeout = 30, show_progress = False, tqdm_kwargs = {}):
        """
        Store the contents of the *file_obj* at *path* on the *service_name*.

        :param string/unicode service_name: the name of the shared folder for the *path*
        :param string/unicode path: Path of the file on the remote server. If the file at *path* does not exist, it will be created.
                                    If the *path* refers to a folder or the file cannot be opened for writing, an :doc:`OperationFailure<smb_exceptions>` will be raised.
        :param file_obj: A file-like object that has a *read* method. Data will read continuously from *file_obj* until EOF.
        :param offset: Long integer value which specifies the offset in the remote server to start writing. First byte of the file is 0.
        :param truncate: Boolean value. If True and the file exists on the remote server, it will be truncated first before writing. Default is False.
        :param bool show_progress: If True, a progress bar will be shown to reflect the current file operation progress.
        :return: the file position where the next byte will be written.
        """
        if not self.sock:
            raise NotConnectedError('Not connected to server')

        results = [ ]

        def cb(r):
            self.is_busy = False
            results.append(r[1])

        def eb(failure):
            self.is_busy = False
            raise failure

        self.is_busy = True
        try:
            self._storeFileFromOffset(service_name, path, file_obj, cb, eb, offset, truncate = truncate, timeout = timeout, show_progress=show_progress, tqdm_kwargs=tqdm_kwargs)
            while self.is_busy:
                self._pollForNetBIOSPacket(timeout)
        finally:
            self.is_busy = False

        return results[0]

    def deleteFiles(self, service_name, path_file_pattern, delete_matching_folders = False, timeout = 30):
        """
        Delete one or more regular files. It supports the use of wildcards in file names, allowing for deletion of multiple files in a single request.

        If delete_matching_folders is True, immediate sub-folders that match the path_file_pattern will be deleted recursively.

        :param string/unicode service_name: Contains the name of the shared folder.
        :param string/unicode path_file_pattern: The pathname of the file(s) to be deleted, relative to the service_name.
                                                 Wildcards may be used in th filename component of the path.
                                                 If your path/filename contains non-English characters, you must pass in an unicode string.
        :return: None
        """
        if not self.sock:
            raise NotConnectedError('Not connected to server')

        def cb(r):
            self.is_busy = False

        def eb(failure):
            self.is_busy = False
            raise failure

        self.is_busy = True
        try:
            self._deleteFiles(service_name, path_file_pattern, delete_matching_folders, cb, eb, timeout = timeout)
            while self.is_busy:
                self._pollForNetBIOSPacket(timeout)
        finally:
            self.is_busy = False

    def resetFileAttributes(self, service_name, path_file_pattern, file_attributes = ATTR_NORMAL, timeout = 30):
        """
        Reset file attributes of one or more regular files or folders.
        It supports the use of wildcards in file names, allowing for unlocking of multiple files/folders in a single request.
        This function is very helpful when deleting files/folders that are read-only.
        By default, it sets the ATTR_NORMAL flag, therefore clearing all other flags.
        (See https://msdn.microsoft.com/en-us/library/cc232110.aspx for further information)

        Note: this function is currently only implemented for SMB2!

        :param string/unicode service_name: Contains the name of the shared folder.
        :param string/unicode path_file_pattern: The pathname of the file(s) to be deleted, relative to the service_name.
                                                 Wildcards may be used in the filename component of the path.
                                                 If your path/filename contains non-English characters, you must pass in an unicode string.
        :param int file_attributes: The desired file attributes to set. Defaults to `ATTR_NORMAL`.
        :return: None
        """
        if not self.sock:
            raise NotConnectedError('Not connected to server')

        def cb(r):
            self.is_busy = False

        def eb(failure):
            self.is_busy = False
            raise failure

        self.is_busy = True
        try:
            self._resetFileAttributes(service_name, path_file_pattern, cb, eb, file_attributes, timeout)
            while self.is_busy:
                self._pollForNetBIOSPacket(timeout)
        finally:
            self.is_busy = False

    def createDirectory(self, service_name, path, timeout = 30):
        """
        Creates a new directory *path* on the *service_name*.

        :param string/unicode service_name: Contains the name of the shared folder.
        :param string/unicode path: The path of the new folder (relative to) the shared folder.
                                    If the path contains non-English characters, an unicode string must be used to pass in the path.
        :return: None
        """
        if not self.sock:
            raise NotConnectedError('Not connected to server')

        def cb(r):
            self.is_busy = False

        def eb(failure):
            self.is_busy = False
            raise failure

        self.is_busy = True
        try:
            self._createDirectory(service_name, path, cb, eb, timeout = timeout)
            while self.is_busy:
                self._pollForNetBIOSPacket(timeout)
        finally:
            self.is_busy = False

    def deleteDirectory(self, service_name, path, timeout = 30):
        """
        Delete the empty folder at *path* on *service_name*

        :param string/unicode service_name: Contains the name of the shared folder.
        :param string/unicode path: The path of the to-be-deleted folder (relative to) the shared folder.
                                    If the path contains non-English characters, an unicode string must be used to pass in the path.
        :return: None
        """
        if not self.sock:
            raise NotConnectedError('Not connected to server')

        def cb(r):
            self.is_busy = False

        def eb(failure):
            self.is_busy = False
            raise failure

        self.is_busy = True
        try:
            self._deleteDirectory(service_name, path, cb, eb, timeout = timeout)
            while self.is_busy:
                self._pollForNetBIOSPacket(timeout)
        finally:
            self.is_busy = False

    def rename(self, service_name, old_path, new_path, timeout = 30):
        """
        Rename a file or folder at *old_path* to *new_path* shared at *service_name*. Note that this method cannot be used to rename file/folder across different shared folders

        *old_path* and *new_path* are string/unicode referring to the old and new path of the renamed resources (relative to) the shared folder.
        If the path contains non-English characters, an unicode string must be used to pass in the path.

        :param string/unicode service_name: Contains the name of the shared folder.
        :return: None
        """
        if not self.sock:
            raise NotConnectedError('Not connected to server')

        def cb(r):
            self.is_busy = False

        def eb(failure):
            self.is_busy = False
            raise failure

        self.is_busy = True
        try:
            self._rename(service_name, old_path, new_path, cb, eb)
            while self.is_busy:
                self._pollForNetBIOSPacket(timeout)
        finally:
            self.is_busy = False

    def echo(self, data, timeout = 10):
        """
        Send an echo command containing *data* to the remote SMB/CIFS server. The remote SMB/CIFS will reply with the same *data*.

        :param bytes data: Data to send to the remote server. Must be a bytes object.
        :return: The *data* parameter
        """
        if not self.sock:
            raise NotConnectedError('Not connected to server')

        results = [ ]

        def cb(r):
            self.is_busy = False
            results.append(r)

        def eb(failure):
            self.is_busy = False
            raise failure

        self.is_busy = True
        try:
            self._echo(data, cb, eb)
            while self.is_busy:
                self._pollForNetBIOSPacket(timeout)
        finally:
            self.is_busy = False

        return results[0]

    #
    # Protected Methods
    #

    def _poll_for_data(self, expiry_time, read_len, data, timeout, poller):
        while read_len > 0:
            try:
                if expiry_time < time.time():
                    raise SMBTimeout

                if poller:
                    ready = poller.poll(timeout * 1000)
                else:
                    ready, _, _ = select.select([self.sock.fileno()], [], [], timeout)
                if not ready:
                    raise SMBTimeout

                d = self.sock.recv(read_len)
                if len(d) == 0:
                    raise NotConnectedError
                data += d
                read_len -= len(d)
            except select.error as ex:
                if getattr(ex, "errno", None) not in (errno.EINTR, errno.EAGAIN):
                    raise ex
        return data, read_len

    def _pollForNetBIOSPacket(self, timeout):
        if os.name == "posix":
            poller = select.poll()
            poller.register(self.sock, select.POLLIN)
        else:
            poller = None
        expiry_time = time.time() + timeout
        read_len = 4
        data = b""

        data, read_len = self._poll_for_data(
            expiry_time=expiry_time,
            read_len=read_len,
            data=data,
            timeout=timeout,
            poller=poller,
        )

        type, flags, length = struct.unpack(">BBH", data)
        if flags & 0x01:
            length = length | 0x10000

        data, read_len = self._poll_for_data(
            expiry_time=expiry_time,
            read_len=length,
            data=data,
            timeout=timeout,
            poller=poller,
        )

        self.feedData(data)
