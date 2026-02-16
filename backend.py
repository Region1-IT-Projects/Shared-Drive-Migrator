from __future__ import annotations

import io
import logging
import time
import uuid
from ssl import SSLError
from collections import deque

import googleapiclient.discovery as g_discover
import googleapiclient.errors as g_api_errors
from google.auth.exceptions import RefreshError
from google.auth.transport.requests import Request
from google.oauth2 import service_account
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
import pdb

logger = logging.getLogger(__name__)
# mute google api stuff
for logger_name in ['googleapiclient.discovery_cache', 'googleapiclient.discovery', 'googleapiclient.http',
                    'google_auth_httplib2', 'google.auth.transport.requests', 'urllib3.connectionpool', 'python_multipart.multipart']:
    logging.getLogger(logger_name).setLevel(logging.WARNING)
MAX_BACKOFF = 30
mime_map = {
    'application/vnd.google-apps.document': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.google-apps.spreadsheet': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.google-apps.presentation': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'application/vnd.google-apps.drawing': 'image/jpeg',
    'application/vnd.google-apps.jam' : 'application/pdf'
}

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

class GooglePermissionError(MigratorError):
    pass

class AbusiveContentErrorGoogle(GooglePermissionError):
    pass

class MissingAdminSDKError(MigratorError):
    def __init__(self, helptext):
        super().__init__(helptext)

class ObjectNotFoundError(MigratorError):
    pass

class TimeEstimator:
    def __init__(self):
        self.time_buffer = deque(maxlen=10)
        self.time_buffer.append(0) # don't divide by zero
        self.last_ts = time.time()
    def reset_base_time(self):
        self.last_ts = time.time()
    def bip(self):
        newtime = time.time()
        self.time_buffer.append(newtime-self.last_ts)
        self.last_ts = newtime
    def get_sliding_average(self):
        ret = 0.0
        for v in self.time_buffer:
            ret += v
        return ret / len(self.time_buffer)
    def extrapolate(self, ops_remaining: int):
        return round(self.get_sliding_average() * ops_remaining)

class APIWrapper:
    def __init__(self):
        self.total_requests = 0
        self.requests_since_error = 0
        self.total_errors = 0
        self.cur_backoff = 0.01
        self.time_buffer = deque(maxlen=5)
        self.time_buffer.append(0)

    def __str__(self):
        t_avg = 0
        for t in self.time_buffer:
            t_avg += t
        t_avg /= len(self.time_buffer)
        return f"Requests: {self.total_requests} ({self.requests_since_error} since last error), Errors: {self.total_errors}, Backoff: {self.cur_backoff:.2f}s, Average API Response Time: {t_avg:.2f}s"

    def __call__(self, method, retries = 1, retryable_errors = (RateLimitError, GoogleIncompetenceError), **kwargs):
        try:
            return self.run(method, **kwargs)
        except retryable_errors as e:
            if retries < 5:
                backoff_time = self.calc_backoff()
                logger.info(f"Backing off for {backoff_time:.2f} seconds before retrying...")
                time.sleep(backoff_time)
                return self.__call__(method, retries + 1, retryable_errors=retryable_errors, **kwargs)
            else:
                logger.error(f"Max retries exceeded for method {method}, giving up.")
                raise e

    def run(self, method, **kwargs):
        self.total_requests += 1
        self.requests_since_error += 1
        start_time = time.time()
        try:
            ret = method(**kwargs).execute()
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
                logger.error(f"google messed up: {e.resp.status} error - {e.error_details}")
                raise GoogleIncompetenceError() from e
            elif e.resp.status in [400, 401]:
                if e.reason == 'abusiveContentRestriction':
                    logger.warning("Google flagged request as abusive content")
                    raise AbusiveContentErrorGoogle() from e
                raise GooglePermissionError() from e
            elif e.resp.status == 404:
                logger.warning(f"Object not found: {e.error_details}")
                raise ObjectNotFoundError() from e
            logger.error(f"Unknown API Error {e.resp.status} - {e.error_details}")
            raise UnknownAPIError(e) from e
        except SSLError as e:
            logger.error(f"SSL Error: {e}")
            self.total_errors += 1
            self.requests_since_error = 0
            raise GoogleIncompetenceError() from e
        self.time_buffer.append(time.time() - start_time)
        return ret

    def calc_backoff(self) -> float:
        if self.requests_since_error > 10:
            self.cur_backoff /=2
        elif self.requests_since_error == 0:
            self.cur_backoff *= 2
        if self.cur_backoff > MAX_BACKOFF:
            self.cur_backoff = MAX_BACKOFF
        return self.cur_backoff

uncopyable_mime_types = ['application/vnd.google-apps.shortcut', 'application/vnd.google-apps.script', 'application/vnd.google-apps.form', 'application/vnd.google-apps.map', 'application/vnd.google-apps.site']

class File:
    def __init__(self, infodict: dict):
        self.id = infodict['id']
        self.name = infodict['name']
        self.mime_type = infodict['mimeType']
        self.is_folder = self.mime_type == 'application/vnd.google-apps.folder'
        self.is_invalid = self.mime_type in uncopyable_mime_types
        self.trashed = infodict.get('trashed', False)
        self.migrated = infodict.get('properties', {}).get('migrator_new_id', None) is not None
        self.permissions = infodict.get('permissions', [])
        parentlist = infodict.get('parents', [])
        self.parent_id = parentlist[0] if len(parentlist) == 1 else None
        self.children: list[File] = []

class Drive:
    """
    Generic drive class for both shared drives and personal drives
    """
    def __init__(self, id: str):
        self.id = id
        self.name = "Personal Drive"
        self.num_files = 0
        self.num_migrated_files = 0
        self.status_message = "Not started"
        self.root: list[File] = []
        self.all_files: dict[str, File] = {}
        self.failed_files: list[File] = []
        self.initialized = False
        self.time_estimator = TimeEstimator()

    def __str__(self):
        return str(self.name)

    def gen_status_dict(self) -> dict:
        return {
            'name': self.name,
            'num_files': self.num_files,
            'num_migrated_files': self.num_migrated_files,
            'status_message': self.status_message,
            'failed_files': [f.name for f in self.failed_files],
            'time_remaining': self.time_estimator.extrapolate(self.num_files-self.num_migrated_files)
        }

    def build_filetree(self, files: list[dict], skip_migrated = False): #TODO switch to true when done testing, add option in UI
        for f in files:
            newf = File(f)
            if newf.trashed or newf.is_invalid:
                logger.debug(f"Skipping file {newf.name} (id: {newf.id}) in drive {self.name} because it is {'trashed' if newf.trashed else 'invalid MIME type'}")
                continue
            if skip_migrated and newf.migrated:
                logger.debug(f"Skipping file {newf.name} (id: {newf.id}) in drive {self.name} because it has already been migrated")
                continue
            self.all_files[f['id']] = newf
        self.num_files = len(self.all_files)
        for f in self.all_files.values():
            if f.parent_id and f.parent_id in self.all_files:
                self.all_files[f.parent_id].children.append(f)
            else:
                self.root.append(f)
        self.initialized = True

class SharedDrive(Drive):
    def __init__(self, infodict: dict):
            super().__init__(infodict['id'])
            self.name = infodict['name']
            self.hidden = infodict.get('hidden', False)
            self.restrictions = infodict.get('restrictions', {})
            self.migrated: bool = "migrated" in self.name.lower()

            # successor system allows resubility of already migrated drives in case of migration failure or partial migration
            self.possible_successors: list[SharedDrive] = []
            self.successor: SharedDrive | None = None

    def add_potential_successor(self, drive: SharedDrive):
        self.possible_successors.append(drive)

    def set_successor(self, drive: SharedDrive):
        self.successor = drive


class User:
    def __init__(self, name, address, service_account, photo_url, api_wrapper: APIWrapper):
        self.user_name = name
        self.address = address
        self.drive_service = g_discover.build("drive", "v3", credentials=service_account.with_subject(address))
        self.photo = photo_url
        self.wrapper: APIWrapper = api_wrapper
        self.personal_drive = Drive(
            self.wrapper(self.drive_service.files().get, fileId='root', fields='id', retries=2)['id']
        )
        self.drives: list[SharedDrive] = []
        self.outstanding_shares: dict[str, str] = {} # permission id -> object id for shares that have been made but not yet removed
    def __str__(self):
        return f"User(name={self.user_name}, address={self.address})"

    def _check_permissions(self, object_id, page_token=None) -> str | None:
        resp = self.wrapper(
            self.drive_service.permissions().list, supportsAllDrives=True,
            fileId=object_id, pageToken=page_token, fields="nextPageToken, permissions(id, role, emailAddress)",
            retries=5)
        permissions: list = resp.get('permissions', [])
        if 'nextPageToken' in resp:
            permissions += self._check_permissions(object_id, page_token=resp['nextPageToken'])
        for perm in permissions:
            if perm['emailAddress'] == self.address:
                return perm['role']
        return None

    def get_drives(self, include_hidden = False) -> list[SharedDrive]:
        api_resp: dict = self.wrapper(self.drive_service.drives().list, fields="drives(id, name, hidden, restrictions)")
        for d in api_resp.get('drives', []):
            if self._check_permissions(d['id']) in ['owner', 'organizer']:
                try:
                    drive = SharedDrive(d)
                    if drive.hidden and not include_hidden:
                        continue
                    self.drives.append(drive)
                except KeyError as e:
                    logger.warning(f"Drive {d['id']} is missing expected fields, skipping: {e}")
                    continue
        return self.drives

    def share_object(self, object_id, email, role='writer') -> str:
        new_perm = {
            'type': 'user',
            'role': role,
            'emailAddress': email
        }
        resp = self.wrapper(self.drive_service.permissions().create, supportsAllDrives=True, fileId=object_id, body=new_perm)
        id = resp.get('id', None)
        if not id:
            logger.error(f"Failed to share object {object_id} with {email}")
            raise UnknownAPIError(f"Failed to share object {object_id} with {email}. Got response: {resp}")
        logger.debug(f"Shared object {object_id} with {email} [permission id: {id}]")
        self.outstanding_shares[id] = object_id
        return id

    def remove_share(self, object_id, permission_id):
        if permission_id not in self.outstanding_shares:
            logger.warning(f"Attempting to remove permission {permission_id} which is not in outstanding shares for user {self.address}")
        self.wrapper(self.drive_service.permissions().delete, supportsAllDrives=True, fileId=object_id, permissionId=permission_id)
        logger.debug(f"Removed share {permission_id} from object {object_id}")
        self.outstanding_shares.pop(permission_id, None)

    def remove_all_shares(self):
        for perm_id, obj_id in list(self.outstanding_shares.items()):
            try:
                self.remove_share(obj_id, perm_id)
            except Exception as e:
                logger.error(f"Failed to remove share {perm_id} from object {obj_id}: {e}")
            self.outstanding_shares.pop(perm_id, None)

    def create_drive(self, predecessor_drive: SharedDrive) -> SharedDrive:
        body = {
            'name': predecessor_drive.name,
            'restrictions': predecessor_drive.restrictions,
            'hidden': predecessor_drive.hidden,
            'themeId': 'abacus'
        }
        resp = self.wrapper(self.drive_service.drives().create, body=body, requestId=uuid.uuid4().hex, fields="id, name, hidden, restrictions")
        new_drive = SharedDrive(resp)
        self.drives.append(new_drive)
        return new_drive

    def _fetch_files(self, token: str | None = None, **kwargs) -> list[dict]:
        query_ret: dict = self.wrapper(self.drive_service.files().list,
                                      pageToken=token, retries=5,
                                      fields="nextPageToken, files(id, name, kind, mimeType, parents, owners, trashed, properties)",
                                      **kwargs)
        if query_ret is None:
            return []
        try:
            file_list: list = query_ret['files']
        except KeyError:
            if "error" in query_ret:
                logger.warning("Got error in API response: {}".format(query_ret['error']))
                raise UnknownAPIError(query_ret.get("error")) from None
            file_list = [query_ret]
        if 'nextPageToken' in query_ret:
            file_list += self._fetch_files(query_ret['nextPageToken'], **kwargs)
        return file_list

    def index_shared_drive_files(self, drive: SharedDrive):
        file_list = self._fetch_files(driveId=drive.id, corpora="drive", q="trashed=false", supportsAllDrives=True, includeItemsFromAllDrives=True)
        drive.build_filetree(file_list)

    def index_personal_drive_files(self):
        file_list = self._fetch_files(corpora="user", q="trashed=false")
        self.personal_drive.build_filetree(file_list)

class SingleMigrator:
    def __init__(self, src_user: User, dst_user: User):
        if not isinstance(src_user, User) or not isinstance(dst_user, User):
            raise ValueError("Invalid source or destination user! Both must be valid User objects.")
        self.src_user = src_user
        self.dst_user = dst_user
        self.to_migrate: list[SharedDrive] = []
        self.migrate_personal_drive = False
        self.download_file_size_limit_mb = 0 #default to not allowing any downloads
        self.download_location = None
        self.initialized = False #also serve as abort flag
        self.index_progress = 0

    def abort(self):
        self.initialized = False
        logger.info("Abort flag set, migration will stop after current file is finished.")

    def _migrate_shared_drive(self, drive: SharedDrive):
        # share old drive with new user
        permission_id = self.src_user.share_object(drive.id, self.dst_user.address, role='organizer')
        logger.debug(f"Shared drive {drive.name} with {self.dst_user.address} with permission id {permission_id}")
        # create new drive in destination account
        if drive.successor:
            logger.info(f"Drive {drive} has successor {drive.successor}, skipping creation and using successor drive for migration")
            new_drive = drive.successor
        else:
            new_drive = self.dst_user.create_drive(drive)
            drive.set_successor(new_drive)
            logger.debug(f"Created new drive {new_drive.name} in destination account for migrating drive {drive.name}")
        assert isinstance(new_drive, SharedDrive)
        drive.status_message = "In progress"
        drive.time_estimator.reset_base_time()
        id_map = {}

        def move_folder(folder: File, parent_id=None):
            if not self.initialized:
                return
            drive.num_migrated_files += 1
            # create folder in new drive with same name and properties as old folder
            new_file = {
                'name': folder.name,
                'mimeType': folder.mime_type,
                'parents': [parent_id] if parent_id else [],
                'properties': {
                    'migrator_source_id': folder.id
                }
            }
            resp = self.dst_user.wrapper(self.dst_user.drive_service.files().create, supportsAllDrives=True, body=new_file, fields="id")
            new_id = resp.get('id', None)
            if not new_id:
                logger.error(f"Failed to create folder {folder.name} in drive {new_drive.name}")
                raise UnknownAPIError(f"Failed to create folder {folder.name} in drive {new_drive.name}. Got response: {resp}")
            id_map[folder.id] = new_id
            # mark old folder as migrated by adding property with new folder id
            try:
                self.src_user.wrapper(self.src_user.drive_service.files().update, supportsAllDrives=True, fileId=folder.id, body={'properties': {'migrator_new_id': new_id}}, fields="id")
            except MigratorError as e:
                logger.error(f"Failed to mark folder {folder.name} as migrated in source drive: {e}")
                # not a critical error, continue with migration
            for child in folder.children:
                if child.is_folder:
                    move_folder(child, parent_id=new_id)
                else:
                    move_file(child, parent_id=new_id)
            logger.debug(f"Finished moving folder {folder.name} in drive {new_drive.name}")
            drive.time_estimator.bip()
        def move_file(file: File, parent_id=None):
            if not self.initialized:
                return
            logger.debug(f"Moving file {file.name} in drive {new_drive.name}...")
            drive.num_migrated_files += 1
            # old drive has been shared to new user, use new user to copy file to new drive, preserving as much metadata and properties as possible
            new_metadata = {
                'name': file.name,
                'mimeType': file.mime_type,
                'parents': [parent_id] if parent_id else [],
                'properties': {
                    'migrator_source_id': file.id
                }
            }
            try:
                resp = self.dst_user.wrapper(self.dst_user.drive_service.files().copy, supportsAllDrives=True, fileId=file.id, body=new_metadata, fields="id", retries=5)
                new_id = resp.get('id', None)
                if not new_id:
                    logger.error(f"Failed to copy file {file.name} to drive {new_drive.name}")
                    drive.failed_files.append(file)
                id_map[file.id] = new_id
            except MigratorError as e:
                logger.error(f"Failed to copy file {file.name} to drive {new_drive.name}: {e}")
                drive.failed_files.append(file)
                return
            # mark old file as migrated by adding property with new file id
            try:
                self.src_user.wrapper(self.src_user.drive_service.files().update, supportsAllDrives=True, fileId=file.id, body={'properties': {'migrator_new_id': new_id}})
            except MigratorError as e:
                logger.error(f"Failed to mark file {file.name} as migrated in source drive: {e}")
                # not a critical error, continue with migration
            drive.time_estimator.bip()

        logger.debug("Dropping into file move loop")
        for f in drive.root:
            if f.is_folder:
                move_folder(f, parent_id=new_drive.id)
            else:
                move_file(f, parent_id=new_drive.id)
        # remove share from old drive
        logger.debug(f"Removing share from source drive {drive.name}...")
        try:
            self.src_user.remove_share(drive.id, permission_id)
        except MigratorError as e:
            logger.error(f"Failed to remove share from source drive {drive.name}: {e}")
            # not a critical error, continue with migration
        drive.status_message = "Completed"
        if not drive.migrated:
            try:
                self.src_user.wrapper(self.src_user.drive_service.drives().update, driveId=drive.id, body={'name': drive.name + " - Migrated"}, retries=5)
            except MigratorError as e:
                logger.error(f"Failed to rename source drive {drive.name}: {e}")
            drive.migrated = True

    def _migrate_personal_drive(self):
        # create new "Migrated" folder in root of new drive to hold migrated personal drive files
        # mark personal drive as in-progress for UI polling
        if not self.initialized:
            return

        pd = self.src_user.personal_drive
        pd.status_message = "In progress"

        try:
            resp = self.dst_user.wrapper(self.dst_user.drive_service.files().create,
                body={
                    'name': 'Migrated Personal Drive',
                    'mimeType': 'application/vnd.google-apps.folder',
                    'properties': {
                        'migrator_personal_drive': 'true'
                    }
                }, fields="id", retries=5)
            new_root_id = resp.get('id', None)
            if not new_root_id:
                if pd:
                    pd.status_message = "Failed: could not create root folder"
                raise UnknownAPIError(f"Failed to create root folder for personal drive migration in destination account. Got response: {resp}")
        except MigratorError as e:
            logger.error(f"Failed to create root folder for personal drive migration in destination account: {e}")
            if pd:
                pd.status_message = f"Failed: {e}"
            raise e
        path_map = {self.src_user.personal_drive.id: new_root_id}
        # build folder structure in new drive by creating folders with same name and properties as old folders
        def move_folder(folder: File, parent_id):
            new_file = {
                'name': folder.name,
                'mimeType': folder.mime_type,
                'parents': [parent_id],
                'properties': {
                    'migrator_source_id': folder.id
                }
            }
            try:
                resp = self.dst_user.wrapper(self.dst_user.drive_service.files().create, body=new_file, fields="id", retries=5)
                new_id = resp.get('id', None)
                if not new_id:
                    logger.error(f"Failed to create folder {folder.name} in personal drive migration")
                    raise UnknownAPIError(f"Failed to create folder {folder.name} in personal drive migration. Got response: {resp}")
                path_map[folder.id] = new_id
            except MigratorError as e:
                logger.error(f"Failed to create folder {folder.name} in personal drive migration: {e}")
                raise e
            for child in folder.children:
                if child.is_folder:
                    move_folder(child, parent_id=new_id)
            self.src_user.personal_drive.num_migrated_files += 1
        for f in self.src_user.personal_drive.root:
            if f.is_folder:
                move_folder(f, parent_id=new_root_id)
        logger.info("Finished creating folder structure for personal drive migration, now copying files...")

        def strategy_a(to_move: File) -> str | None:
            # share file in personal drive with new user, then have new user copy them to new drive
            self.src_user.share_object(to_move.id, self.dst_user.address, role='writer')
            new_parent = path_map.get(to_move.parent_id, new_root_id)
            try:
                new_id = self.dst_user.wrapper(self.dst_user.drive_service.files().copy, fileId=to_move.id, body={
                    'name': to_move.name,
                    'mimeType': to_move.mime_type,
                    'parents': [new_parent],
                    'properties': {
                        'migrator_source_id': to_move.id
                    }
                }, fields="id", retries=5)
            except MigratorError as e:
                logger.warning(f"Failed to copy file {to_move.name} in personal drive migration with strategy A: {e}")
                return None
            return new_id.get('id', None)

        def strategy_b(to_move: File) -> str | None:
            # google takout style approach: download all files and folders in personal drive, then reupload them to new drive with new user credentials
            if self.download_file_size_limit_mb > 0:
                # check file size before downloading
                try:
                    metadata = self.src_user.wrapper(self.src_user.drive_service.files().get, fileId=to_move.id, fields="size")
                    size = int(metadata.get('size', 0))
                except MigratorError as e:
                    logger.warning(f"Failed to get size for file {to_move.name} in personal drive migration: {e}")
                    return None
                if size > self.download_file_size_limit_mb * 1024 * 1024:
                            logger.warning(f"Skipping file {to_move.name} in personal drive migration because it exceeds the download size limit")
                            return None
            else:
                logger.debug("file downloading disabled")
                return None
            # download file content
            if to_move.mime_type in mime_map:
                request = self.src_user.drive_service.files().export_media(fileId=to_move.id, mimeType=mime_map[to_move.mime_type])
            else:
                request = self.src_user.drive_service.files().get_media(fileId=to_move.id)
            try:
                fh = io.BytesIO()
                downloader = MediaIoBaseDownload(fh, request)
                done = False
                while not done:
                    status, done = downloader.next_chunk()
                logger.debug(f"Downloaded file {to_move.name} in personal drive migration, now uploading...")
            except Exception as e:
                logger.warning(f"Failed to download file {to_move.name} in personal drive migration: {e}")
                return None
            fh.seek(0)
            new_parent = path_map.get(to_move.parent_id, new_root_id)
            try:
                uploader = MediaIoBaseUpload(fh, mimetype=mime_map.get(to_move.mime_type, 'application/octet-stream'), resumable=True)
                id = self.dst_user.wrapper(self.dst_user.drive_service.files().create, body={
                    'name': to_move.name,
                    'mimeType': to_move.mime_type,
                    'parents': [new_parent],
                    'properties': {
                        'migrator_source_id': to_move.id
                    }}, media_body=uploader, fields="id", retries=1)
            except MigratorError as e:
                logger.warning(f"Failed to upload file {to_move.name} in personal drive migration with strategy B: {e}")
                return None
            return id

        pd.time_estimator.reset_base_time()

        for f in self.src_user.personal_drive.all_files.values():
            if not self.initialized:
                logger.debug("got kill signal, bailing out of migration")
                return
            if not isinstance(f, File):
                logger.warning(f"Encountered non-File object in personal drive files: {f}, skipping")
                continue
            if f.is_folder:
                continue
            if not (new_id := strategy_a(f)):
                logger.info(f"Strategy A failed for file {f.name} in personal drive, trying strategy B...")
                if not (new_id := strategy_b(f)):
                    logger.error(f"Failed to migrate file {f.name} in personal drive with both strategies, skipping")
                    self.src_user.personal_drive.failed_files.append(f)
                    continue
            self.src_user.personal_drive.num_migrated_files += 1
            # mark old file as migrated by adding property with new file id
            try:
                self.src_user.wrapper(self.src_user.drive_service.files().update, fileId=f.id, body={'properties': {'migrator_new_id': new_id}})
            except MigratorError as e:
                logger.error(f"Failed to mark file {f.name} as migrated in source drive with strategy A: {e}")
                # not a critical error, continue with migration
            pd.time_estimator.bip()
        # mark personal drive migration as completed for UI
        pd.status_message = "Completed"
        logger.debug("Clean exit of personal drive migrator")

    def perform_migration(self) -> bool:
        is_ok = True
        logger.debug(f"Starting migration of {len(self.to_migrate)} drives")
        for d in self.to_migrate:
            if not self.initialized:
                logger.info("Migration aborted, stopping migration loop.")
                return False
            logger.info(f"Starting migration of drive {d}...")
            try:
                self._migrate_shared_drive(d)
            except Exception as e:
                logger.error(f"Migration of drive {d} failed with error: {e}")
                d.status_message = f"Critical Error: {e}"
                is_ok = False
            logger.info(f"Finished migration of drive {d}. {len(d.failed_files)} files failed to migrate.")
        if self.migrate_personal_drive:
            logger.info("Starting migration of personal drive...")
            self._migrate_personal_drive()
            logger.info("Finished migration of personal drive.")
        return is_ok and self.initialized # if abort, we arent ok

    def set_migration_options(self, download_file_size_limit_mb: int, download_location: str): #TODO options setter in UI
        self.download_file_size_limit_mb = download_file_size_limit_mb
        self.download_location = download_location

    def init_migration(self, drives: list[SharedDrive], migrate_personal_drive: bool):
        # Initialize migration object but don't actually start migration yet
        self.to_migrate = drives
        self.migrate_personal_drive = migrate_personal_drive
        self.initialized = True

    def poll_progress(self) -> list[dict]:
        # return list of dicts with progress info for each drive being migrated
        progress = [d.gen_status_dict() for d in self.to_migrate]
        if self.migrate_personal_drive:
            progress.append(self.src_user.personal_drive.gen_status_dict())
        return progress

    def prepare_shared_migration(self):
        # index files in all drives to be migrated
        for i, drive in enumerate(self.to_migrate):
            logger.info(f"Indexing files in drive {drive}...")
            self.index_progress = round(i+1 / len(self.to_migrate) * 100, 1)
            self.src_user.index_shared_drive_files(drive)
            logger.info(f"Found {drive.num_files} files in drive {drive}")
        logger.info("Finished indexing files for migration")

    def prepare_personal_migration(self):
        if self.migrate_personal_drive:
            logger.info("Indexing files in personal drive...")
            self.src_user.index_personal_drive_files()
            logger.info(f"Found {self.src_user.personal_drive.num_files} files in personal drive")

    def generate_drive_list(self):
        # generate list of drives, identify duplicate names across source and destination accounts and mark for user confirmation
        src_drives = self.src_user.get_drives()
        dst_drives = self.dst_user.get_drives()
        for d in src_drives:
            for dd in dst_drives:
                if d.name == dd.name:
                    d.add_potential_successor(dd)
        return src_drives


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

        query_ret = self.wrapper(self.user_service.users().list, customer='my_customer', pageToken=page_token)

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

        query_ret = self.wrapper(self.user_service.users().list, customer='my_customer', query=f'name:"{name}"')

        if 'users' not in query_ret or len(query_ret['users']) == 0:
            logger.warning(f"No users found matching name: {name}")
            return None
        if len(query_ret['users']) > 1:
            logger.warning(f"Multiple users found matching name: {name}, using first result")
        user_info = query_ret['users'][0]
        return User(name, user_info['primaryEmail'], self.worker, user_info.get('thumbnailPhotoUrl'), self.wrapper)

    def find_user_by_email(self, email) -> User:

        query_ret = self.wrapper(self.user_service.users().list, customer='my_customer', query=f'email:"{email}"')

        if 'users' not in query_ret or len(query_ret['users']) == 0:
            logger.warning(f"No users found matching email: {email}")
            return None
        user_info = query_ret['users'][0]
        return User(user_info["name"]["fullName"], email, self.worker, user_info.get('thumbnailPhotoUrl'), self.wrapper)
