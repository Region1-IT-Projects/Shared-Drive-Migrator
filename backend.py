from __future__ import annotations
import googleapiclient.discovery as g_discover
import googleapiclient.errors as g_api_errors
from google.oauth2 import service_account
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
import time
from ssl import SSLError

import logging
logger = logging.getLogger(__name__)
MAX_BACKOFF = 30

class MigratorError(Exception):
    pass

class RateLimit(MigratorError):
    pass

class UnknownAPIErr(MigratorError):
    def __init__(self, deets):
        super().__init__(f"Unknown API Error: {deets}")
        self.deets = deets

class GoogleIncompetence(MigratorError):
    pass

class PermissionError(MigratorError):
    pass

class AbusiveContentError(PermissionError):
    pass

class MissingAdminSDK(MigratorError):
    def __init__(self, helptext):
        super().__init__(helptext)

class API_wrapper:
    def __init__(self):
        self.total_requests = 0
        self.requests_since_error = 0
        self.total_errors = 0
        self.cur_backoff = 0.01

    def __call__(self, method):
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
                    raise RateLimit()
                if error_reason in ['accessNotConfigured']:
                    logger.error("Admin SDK API not enabled for this service account!")
                    raise MissingAdminSDK(e.error_details[0]['message']) 
            elif e.resp.status in [500, 502, 503, 504]:
                logger.error("google messed up: ",e)
                raise GoogleIncompetence()
            elif e.resp.status in [400, 401]:
                if e.reason == 'abusiveContentRestriction':
                    logger.warning("Google flagged request as abusive content")
                    raise AbusiveContentError()
                raise PermissionError()
            logger.error(f"Unknown API Error {e.resp.status} - {e.error_details}")
            raise UnknownAPIErr(e)
        except SSLError as e:
            logger.error(f"SSL Error: {e}")
            self.total_errors += 1
            self.requests_since_error = 0
            raise GoogleIncompetence()

    def calc_backoff(self):
        if self.requests_since_error > 10:
            self.cur_backoff /=2
        elif self.requests_since_error == 0:
            self.cur_backoff *= 2
        if self.cur_backoff > MAX_BACKOFF:
            self.cur_backoff = MAX_BACKOFF
        return self.cur_backoff

class User:
    def __init__(self, name, address, service_account, photo_url=None):
        self.user_name = name
        self.address = address
        self.drive_service = g_discover.build("drive", "v3", credentials=service_account.with_subject(address))
        self.wrapper = API_wrapper()
        self.photo = photo_url

class SingleMigrator:
    def __init__(self, src_user: User, dst_user: User):
        self.src_user = src_user
        self.dst_user = dst_user
        pass #TODO implement actual migration logic here, this is just a placeholder for now

class Org: 
    def __init__(self, keyfile_dict):
        self.worker = service_account.Credentials.from_service_account_info(keyfile_dict, 
        scopes=["https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/admin.directory.user.readonly"])
        self.user_service = None
        self.wrapper = API_wrapper()
        self.users = []


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
            raise ValueError("Invalid admin credentials! Check that the email is correct and that the service account has domain-wide delegation enabled.")
        logger.info(f"Admin set to {address}")
        # build user service with admin credentials
        self.user_service = g_discover.build("admin", "directory_v1", credentials=creds)

    def fetch_users(self, pageToken=None) -> list[dict]:
        logger.debug(f"Listing all users {'[recursive call]' if pageToken else ''}")
        if not self.user_service:
            logger.error("Attempted to search for user without user service instance!")
            raise ValueError("User service not configured!")

        query_ret = self.wrapper(self.user_service.users().list(customer='my_customer', pageToken=pageToken))

        # filter out just the full name of each user and return as list
        users: list = []
        for user in query_ret.get('users', []):
            try:
                users.append(user["name"]["fullName"])
            except KeyError:
                logger.warning(f"User {user['primaryEmail']} is missing a full name, skipping")

        if 'nextPageToken' in query_ret:
            return users + self.fetch_users(pageToken=query_ret["nextPageToken"])
        return users
        
    def find_user(self, name) -> User:

        query_ret = self.wrapper(self.user_service.users().list(customer='my_customer', query=f'name:"{name}"'))

        if 'users' not in query_ret or len(query_ret['users']) == 0:
            logger.warning(f"No users found matching name: {name}")
            return None
        if len(query_ret['users']) > 1:
            logger.warning(f"Multiple users found matching name: {name}, using first result")
        user_info = query_ret['users'][0]
        return User(name, user_info['primaryEmail'], self.worker, user_info.get('thumbnailPhotoUrl'))

    def find_user_by_email(self, email) -> User:

        query_ret = self.wrapper(self.user_service.users().list(customer='my_customer', query=f'email:"{email}"'))

        if 'users' not in query_ret or len(query_ret['users']) == 0:
            logger.warning(f"No users found matching email: {email}")
            return None
        user_info = query_ret['users'][0]
        return User(user_info["name"]["fullName"], email, self.worker, user_info.get('thumbnailPhotoUrl'))