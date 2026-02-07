import googleapiclient.discovery as g_discover
import googleapiclient.errors as g_api_errors
from google.oauth2 import service_account
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
                error_reason = e.error_details[0] if e.error_details else None
                if error_reason in ['rateLimitExceeded', 'userRateLimitExceeded', 'quotaExceeded']:
                    logger.info("Rate limit exceeded!")
                    raise RateLimit()
                if error_reason in ['accessNotConfigured']:
                    logger.error("Admin SDK API not enabled for this service account!")
                    raise MissingAdminSDK(e.error_details['message']) 
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



class Org: 
    def __init__(self, keyfile_dict):
        self.service_account = service_account.Credentials.from_service_account_info(keyfile_dict, 
        scopes=["https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/admin.directory.user.readonly"])
        self.user_service = g_discover.build("admin", "directory_v1", credentials=self.service_account)
        self.drive_service = g_discover.build("drive", "v3", credentials=self.service_account)
        self.wrapper = API_wrapper()
        self.domain = None

    def set_domain(self, domain):
        valid_tlds = ['com', 'org', 'net', 'edu']
        if not any(domain.endswith('.' + tld) for tld in valid_tlds):
            raise ValueError("Invalid domain! Must end with a valid TLD.")
        self.domain = domain
        logger.debug(f"ORG Set domain to {domain}")

    def search_user(self, fuzzy_name: str, pageToken = None) -> list[str]:
        logger.debug(f"Searching for user with query {fuzzy_name} in domain {self.domain}, {"[recursive call]" if pageToken else ""}")
        if not self.domain:
            logger.error("Attempted to search for user without setting domain!")
            raise ValueError("Domain not set!")
        try:
            query_ret = self.wrapper(self.user_service.users().list(query=fuzzy_name, domain=self.domain, pageToken=pageToken))
        except MigratorError as e:
            logger.debug(f"Failed to look up user {fuzzy_name} due to {e}")
            return []
        try:
            users: list = query_ret['users']
        except KeyError:
                return []
        if 'nextPageToken' in query_ret.keys():
            return users + self.search_user(fuzzy_name, pageToken=query_ret["nextPageToken"])
        logger.debug(f"User search complete with {len(users)} results")
        return users
        
