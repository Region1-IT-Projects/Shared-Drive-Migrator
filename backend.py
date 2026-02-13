from __future__ import annotations

import logging
import time
from ssl import SSLError

import googleapiclient.discovery as g_discover
import googleapiclient.errors as g_api_errors
from google.auth.exceptions import RefreshError
from google.auth.transport.requests import Request
from google.oauth2 import service_account

logger = logging.getLogger(__name__)
MAX_BACKOFF = 30

class MigratorError(Exception):
    pass

class RateLimitError(MigratorError):
    pass

class UnknownAPIError(MigratorError):
    def __init__(self, deets):
        super().__init__(f"Unknown API Error: {deets}")
        self.deets = deets

class GoogleIncompetenceError(MigratorError):
    pass

class PermissionError(MigratorError):
    pass

class AbusiveContentError(PermissionError):
    pass

class MissingAdminSDKError(MigratorError):
    def __init__(self, helptext):
        super().__init__(helptext)

class APIWrapper:
    def __init__(self):
        self.total_requests = 0
        self.requests_since_error = 0
        self.total_errors = 0
        self.cur_backoff = 0.01

    def __str__(self):
        return f"Requests: {self.total_requests} ({self.requests_since_error} since last error), Errors:{self.total_errors}, Backoff: {self.cur_backoff:.2f}s"

    def __call__(self, method, retries = 0, retryable_errors = (RateLimitError, GoogleIncompetenceError)):
        try:
            return self.run(method)
        except retryable_errors as e:
            if retries < 5:
                backoff_time = self.calc_backoff()
                logger.info(f"Backing off for {backoff_time:.2f} seconds before retrying...")
                time.sleep(backoff_time)
                return self.__call__(method, retries + 1)
            else:
                logger.error(f"Max retries exceeded for method {method}, giving up.")
                raise e

    def run(self, method):
        self.total_requests += 1
        self.requests_since_error += 1
        try:
            return method.execute()
        except g_api_errors.HttpError as e:
            self.total_errors += 1
            self.requests_since_error = 0
            if e.resp.status in [403, 429]:
                error_reason = e.error_details[0]['reason']
                logger.debug(f"API Error {e.resp.status} - {error_reason}")
                if error_reason in ['rateLimitExceeded', 'userRateLimitExceeded', 'quotaExceeded']:
                    logger.info("Rate limit exceeded!")
                    raise RateLimitError() from e
                if error_reason in ['accessNotConfigured']:
                    logger.error("Admin SDK API not enabled for this service account!")
                    raise MissingAdminSDKError(e.error_details[0]['message']) from e
            elif e.resp.status in [500, 502, 503, 504]:
                logger.error("google messed up: ",e)
                raise GoogleIncompetenceError() from e
            elif e.resp.status in [400, 401]:
                if e.reason == 'abusiveContentRestriction':
                    logger.warning("Google flagged request as abusive content")
                    raise AbusiveContentError() from e
                raise PermissionError() from e
            logger.error(f"Unknown API Error {e.resp.status} - {e.error_details}")
            raise UnknownAPIError(e) from e
        except SSLError as e:
            logger.error(f"SSL Error: {e}")
            self.total_errors += 1
            self.requests_since_error = 0
            raise GoogleIncompetenceError() from e

    def calc_backoff(self) -> float:
        if self.requests_since_error > 10:
            self.cur_backoff /=2
        elif self.requests_since_error == 0:
            self.cur_backoff *= 2
        if self.cur_backoff > MAX_BACKOFF:
            self.cur_backoff = MAX_BACKOFF
        return self.cur_backoff

class File:
    def __init__(self, infodict: dict):
        self.id = infodict['id']
        self.name = infodict['name']
        self.mime_type = infodict['mimeType']
        self.trashed = infodict.get('trashed', False)
        self.permissions = infodict.get('permissions', [])
        self.parents = infodict.get('parents', [])

class SharedDrive:
    def __init__(self, infodict: dict):
        self.id = infodict['id']
        self.name = infodict['name']
        self.hidden = infodict.get('hidden', False)
        self.restrictions = infodict.get('restrictions', {})
        self.migrated: bool = "migrated" in self.name.lower()
        self.files: list[File] = []
        self.failed_files: list[File] = []
    def __str__(self):
        return str(self.name)

class User:
    def __init__(self, name, address, service_account, photo_url, api_wrapper: APIWrapper):
        self.user_name = name
        self.address = address
        self.drive_service = g_discover.build("drive", "v3", credentials=service_account.with_subject(address))
        self.photo = photo_url
        self.wrapper: APIWrapper = api_wrapper
        self.drives: list[SharedDrive] = []
    def __str__(self):
        return f"User(name={self.user_name}, address={self.address})"

    def _check_permissions(self, object_id, page_token=None) -> str:
        resp = self.wrapper(
            self.drive_service.permissions()
            .list(fileId=object_id, pageToken=page_token, supportsAllDrives=True, fields="nextPageToken, permissions(id, role, emailAddress)"),
            retries=5)
        permissions: list = resp.get('permissions', [])
        if 'nextPageToken' in resp:
            permissions += self._check_permissions(object_id, page_token=resp['nextPageToken'])
        for perm in permissions:
            if perm['emailAddress'] == self.address:
                return perm['role']

    def get_drives(self) -> list[SharedDrive]:
        api_resp: dict = self.wrapper(self.drive_service.drives().list(fields="drives(id, name, hidden, restrictions)"))
        for d in api_resp.get('drives', []):
            if self._check_permissions(d['id']) in ['owner', 'organizer']:
                try:
                    drive = SharedDrive(d)
                    self.drives.append(drive)
                except KeyError as e:
                    logger.warning(f"Drive {d['id']} is missing expected fields, skipping: {e}")
                    continue
        return self.drives


class SingleMigrator:
    def __init__(self, src_user: User, dst_user: User):
        if not isinstance(src_user, User) or not isinstance(dst_user, User):
            raise ValueError("Invalid source or destination user! Both must be valid User objects.")
        self.src_user = src_user
        self.dst_user = dst_user

    def start_migration(self, drives: list[SharedDrive], migrate_personal_drive: bool):
        pass #TODO

class Org:
    def __init__(self, keyfile_dict, wrapper: APIWrapper):
        self.worker = service_account.Credentials.from_service_account_info(keyfile_dict,
        scopes=["https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/admin.directory.user.readonly"])
        self.user_service = None
        self.users = []
        self.wrapper = wrapper


    def set_admin(self, address: str):
        # validate address is valid email address
        if '@' not in address:
            logger.error(f"Invalid admin email address: {address}")
            raise ValueError("Invalid email address!")
        if address.split('.')[-1] not in ['com', 'net', 'org', 'edu']:
            logger.error(f"Invalid admin email address: {address}")
            raise ValueError("Invalid email address!")
        creds = self.worker.with_subject(address)
        try:
            creds.refresh(Request())
            logger.debug(f"Successfully refreshed credentials for {address}")
        except RefreshError as e:
            logger.error(f"Failed to refresh credentials for {address}: {e}")
            raise ValueError("Invalid admin credentials! Check that the email is correct and that the service account has domain-wide delegation enabled.") from e
        logger.info(f"Admin set to {address}")
        # build user service with admin credentials
        self.user_service = g_discover.build("admin", "directory_v1", credentials=creds)

    def fetch_users(self, page_token=None) -> list[dict]:
        logger.debug(f"Listing all users {'[recursive call]' if page_token else ''}")
        if not self.user_service:
            logger.error("Attempted to search for user without user service instance!")
            raise ValueError("User service not configured!")

        query_ret = self.wrapper(self.user_service.users().list(customer='my_customer', pageToken=page_token))

        # filter out just the full name of each user and return as list
        users: list = []
        for user in query_ret.get('users', []):
            try:
                users.append(user["name"]["fullName"])
            except KeyError:
                logger.warning(f"User {user['primaryEmail']} is missing a full name, skipping")

        if 'nextPageToken' in query_ret:
            return users + self.fetch_users(page_token=query_ret["nextPageToken"])
        return users

    def find_user(self, name) -> User:

        query_ret = self.wrapper(self.user_service.users().list(customer='my_customer', query=f'name:"{name}"'))

        if 'users' not in query_ret or len(query_ret['users']) == 0:
            logger.warning(f"No users found matching name: {name}")
            return None
        if len(query_ret['users']) > 1:
            logger.warning(f"Multiple users found matching name: {name}, using first result")
        user_info = query_ret['users'][0]
        return User(name, user_info['primaryEmail'], self.worker, user_info.get('thumbnailPhotoUrl'), self.wrapper)

    def find_user_by_email(self, email) -> User:

        query_ret = self.wrapper(self.user_service.users().list(customer='my_customer', query=f'email:"{email}"'))

        if 'users' not in query_ret or len(query_ret['users']) == 0:
            logger.warning(f"No users found matching email: {email}")
            return None
        user_info = query_ret['users'][0]
        return User(user_info["name"]["fullName"], email, self.worker, user_info.get('thumbnailPhotoUrl'), self.wrapper)
