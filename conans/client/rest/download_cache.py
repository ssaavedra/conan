from requests.auth import HTTPBasicAuth
from conans.client.rest.file_uploader import FileUploader
from conans.client.rest import response_to_str
from conans.client.rest.file_downloader import FileDownloader
import os
import shutil
from threading import Lock

from six.moves.urllib_parse import urlsplit, urlunsplit

from conans.client.tools.files import check_md5, check_sha1, check_sha256
from conans.errors import AuthenticationException, ConanException, ForbiddenException
from conans.util.files import mkdir
from conans.util.locks import SimpleLock
from conans.util.sha import sha256 as sha256_sum


class CachedFileDownloader(object):
    _thread_locks = {}  # Needs to be shared among all instances

    def __init__(self, cache_folder, file_downloader, user_download=False):
        self._cache_folder = cache_folder
        self._file_downloader = file_downloader
        self._user_download = user_download

    @staticmethod
    def _check_checksum(cache_path, md5, sha1, sha256):
        if md5:
            check_md5(cache_path, md5)
        if sha1:
            check_sha1(cache_path, sha1)
        if sha256:
            check_sha256(cache_path, sha256)

    def download(self, url, file_path=None, auth=None, retry=None, retry_wait=None, overwrite=False,
                 headers=None, md5=None, sha1=None, sha256=None):
        """ compatible interface of FileDownloader + checksum
        """
        checksum = sha256 or sha1 or md5
        # If it is a user download, it must contain a checksum
        assert (not self._user_download) or (self._user_download and checksum)
        h = self._get_hash(url, checksum)
        lock = os.path.join(self._cache_folder, "locks", h)
        cached_path = os.path.join(self._cache_folder, h)
        with SimpleLock(lock):
            # Once the process has access, make sure multithread is locked too
            # as SimpleLock doesn't work multithread
            thread_lock = self._thread_locks.setdefault(lock, Lock())
            thread_lock.acquire()
            try:
                if not os.path.exists(cached_path):
                    try:
                        self._file_downloader.download(url, cached_path, auth, retry, retry_wait,
                                                       overwrite, headers)
                        self._check_checksum(cached_path, md5, sha1, sha256)
                    except Exception:
                        if os.path.exists(cached_path):
                            os.remove(cached_path)
                        raise
                else:
                    # specific check for corrupted cached files, will raise, but do nothing more
                    # user can report it or "rm -rf cache_folder/path/to/file"
                    try:
                        self._check_checksum(cached_path, md5, sha1, sha256)
                    except ConanException as e:
                        raise ConanException("%s\nCached downloaded file corrupted: %s"
                                             % (str(e), cached_path))

                if file_path is not None:
                    file_path = os.path.abspath(file_path)
                    mkdir(os.path.dirname(file_path))
                    shutil.copy2(cached_path, file_path)
                else:
                    with open(cached_path, 'rb') as handle:
                        tmp = handle.read()
                    return tmp
            finally:
                thread_lock.release()

    def _get_hash(self, url, checksum=None):
        """ For Api V2, the cached downloads always have recipe and package REVISIONS in the URL,
        making them immutable, and perfect for cached downloads of artifacts. For V2 checksum
        will always be None.
        For ApiV1, the checksum is obtained from the server via "get_snapshot()" methods, but
        the URL in the apiV1 contains the signature=xxx for signed urls, but that can change,
        so better strip it from the URL before the hash
        """
        urltokens = urlsplit(url)
        # append empty query and fragment before unsplit
        if not self._user_download:  # removes ?signature=xxx
            url = urlunsplit(urltokens[0:3]+("", ""))
        if checksum is not None:
            url += checksum
        h = sha256_sum(url.encode())
        return h


class NetCachedFileDownloader(FileDownloader, FileUploader):
    """
    Caches a file download in an intermediary repository.

    That is, this class's .download(url) method will .upload() to an alternate
    location if config.net_cache and config.net_cache_url.format(url) does not
    return a 200 OK from a HEAD method.
    """

    def __init__(self, requester, output, verify, config):
        super(NetCachedFileDownloader, self).__init__(requester, output, verify, config)

    def download(self, url, file_path=None, auth=None, retry=None, retry_wait=None, overwrite=False,
                 headers=None, netcache_auth=None):
        if self._config.net_cache:
            # TODO: Make a netcache_url that fits the constraints of Artifactory/Conan Server
            netcache_url = self._config.net_cache_url.format(url)
            netcache_auth = None
            if self._config.net_cache_username and self._config.net_cache_password:
                netcache_auth = HTTPBasicAuth(self._config.net_cache_username, self._config.net_cache_password)

            if self.is_file_in_netcache(self, netcache_url, netcache_auth, retry, retry_wait, headers):
                return self.download_from_netcache(netcache_url, file_path, netcache_auth, retry, retry_wait, overwrite, headers)
            else:
                self.download_upstream(url, file_path, auth, retry, retry_wait, overwrite, headers)
                return self.save_onto_netcache(netcache_url, file_path, netcache_auth, retry, retry_wait, overwrite, headers)
        else:
            return super(NetCachedFileDownloader, self).download(url, file_path, auth, retry, retry_wait, overwrite)

    def is_file_in_netcache(self, url, auth, retry, retry_wait, headers):
        self._call_with_retry(self._output, retry, retry_wait, self._is_file_in_netcache, url, auth, headers)

    def _is_file_in_netcache(self, url, auth, headers):
        try:
            response = self._requester.head(url, stream=False, verify=self._verify_ssl, auth=auth,
                                        headers=headers)
        except Exception as exc:
            raise ConanException("Error checking file in netcache %s: '%s'" % (url, exc))

        if response.ok:
            return True
        else:
            if response.status_code == 404:
                return False
            elif response.status_code == 403:
                if auth is None or (hasattr(auth, "token") and auth.token is None):
                    # TODO: This is a bit weird, why this conversion? Need to investigate (this came from conans.client.rest.file_downloader)
                    raise AuthenticationException(response_to_str(response))
                raise ForbiddenException(response_to_str(response))
            elif response.status_code == 401:
                raise AuthenticationException()
            raise ConanException("Error %d checking for file in netcache %s" % (response.status_code, url))

    def download_from_netcache(self, url, file_path, netcache_auth, retry, retry_wait, overwrite, headers):
        return super(NetCachedFileDownloader, self).download(url, file_path, netcache_auth, retry, retry_wait, overwrite, headers)

    def download_upstream(self, url, file_path, auth, retry, retry_wait, overwrite, headers):
        return super(NetCachedFileDownloader, self).download(url, file_path, auth, retry, retry_wait, overwrite, headers)

    def save_onto_netcache(self, url, file_path, netcache_auth, retry, retry_wait, overwrite, headers):
        super(NetCachedFileDownloader, self).upload(
            url, file_path, netcache_auth, dedup=False, retry=retry, retry_wait=retry_wait, headers=headers, display_name=None
        )
