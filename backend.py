from __future__ import annotations

import asyncio
import concurrent.futures
import io
import logging
import time
import uuid
import threading # Added
from collections import deque
from ssl import SSLError

import httplib2 # Added: Required for thread-local transport
import googleapiclient.discovery as g_discover
import googleapiclient.errors as g_api_errors
from google.auth.exceptions import RefreshError
from google.auth.transport.requests import Request
from google.oauth2 import service_account
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
import google_auth_httplib2
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

# --- Thread Safety Fix ---
class ThreadLocalHttp:
    def __init__(self, credentials):
        self.credentials = credentials
        self._local = threading.local()

    def request(self, *args, **kwargs):
        if not hasattr(self._local, 'http'):
            # Create a clean httplib2 instance
            base_http = httplib2.Http()
            # Wrap it with credentials so it handles Auth headers automatically
            self._local.http = google_auth_httplib2.AuthorizedHttp(
                self.credentials, http=base_http
            )
        return self._local.http.request(*args, **kwargs)
# -------------------------

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

class ProgrammerIncompetenceError(MigratorError):
    def __init__(self, deets):
        super().__init__(f"Programmer Incompetence Error: {deets}")
        self.deets = deets
        logger.error(f"BUG: Programmer Incompetence Error - {deets}")

class GooglePermissionError(MigratorError):
    pass

class GoogleAbusiveContentError(GooglePermissionError):
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
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=20)

    def __str__(self):
        t_avg = 0
        for t in self.time_buffer:
            t_avg += t
        t_avg /= len(self.time_buffer)
        return f"Requests: {self.total_requests} ({self.requests_since_error} since last error), Errors: {self.total_errors}, Backoff: {self.cur_backoff:.2f}s, Average API Response Time: {t_avg:.2f}s"

    async def __call__(self, method, retries=0, retryable_errors=(RateLimitError, GoogleIncompetenceError), **kwargs):
        try:
            return await self.run(method, **kwargs)
        except retryable_errors as e:
            logger.debug(f"Caught retryable error: {e}. Attempt {retries}/5.")
            if retries < 5:
                backoff_time = self.calc_backoff()
                logger.info(f"Backing off for {backoff_time:.2f} seconds before retrying...")
                await asyncio.sleep(backoff_time)
                return await self.__call__(method, retries + 1, retryable_errors=retryable_errors, **kwargs)
            else:
                logger.error(f"Max retries exceeded for method {method}, giving up.")
                raise e

    async def run(self, method, **kwargs):
        self.total_requests += 1
        self.requests_since_error += 1
        start_time = time.time()
        loop = asyncio.get_running_loop()
        try:
            def _blocking_request():
                return method(**kwargs).execute()
            ret = await loop.run_in_executor(self.executor, _blocking_request)

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
                    raise GoogleAbusiveContentError() from e
                elif e.reason == 'invalidParameter': #rant: WHY IS THIS A 400 ERROR AND NOT A 403 ERROR????
                    logger.error(f"Invalid parameter error: {e.error_details}")
                    raise ProgrammerIncompetenceError(f"Invalid parameter error: {e.error_details}") from e
                logger.error(f"Permission error: {e.resp.status} - {e.error_details}")
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
            self.cur_backoff /= 2
        elif self.requests_since_error == 0:
            self.cur_backoff *= 2
        if self.cur_backoff > MAX_BACKOFF:
            self.cur_backoff = MAX_BACKOFF
        return self.cur_backoff

    def shutdown(self):
        self.executor.shutdown(wait=True)

uncopyable_mime_types = ['application/vnd.google-apps.shortcut', 'application/vnd.google-apps.script',
                         'application/vnd.google-apps.form', 'application/vnd.google-apps.map',
                         'application/vnd.google-apps.site']

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
        # MODIFIED: Use ThreadLocalHttp to ensure thread safety
        self.drive_service = g_discover.build("drive", "v3", http=ThreadLocalHttp(service_account.with_subject(address)))
        self.photo = photo_url
        self.wrapper: APIWrapper = api_wrapper
        self.personal_drive = Drive(self.drive_service.files().get(fileId='root', fields='id').execute()['id'])
        self.drives: list[SharedDrive] = []
        self.outstanding_shares: dict[str, str] = {} # permission id -> object id for shares that have been made but not yet removed
    def __str__(self):
        return f"User(name={self.user_name}, address={self.address})"

    async def _check_permissions(self, object_id) -> str | None:
        page_token = None
        permissions = []
        while True:
            resp = await self.wrapper(
                self.drive_service.permissions().list, supportsAllDrives=True,
                fileId=object_id, pageToken=page_token, fields="nextPageToken, permissions(id, role, emailAddress)")
            page_token = resp.get('nextPageToken', None)
            permissions.extend(resp.get('permissions', []))
            if not page_token:
                break
        for perm in permissions:
            if perm.get('emailAddress') == self.address:
                return perm.get('role', None)
        return None

    async def get_drives(self, include_hidden = False) -> list[SharedDrive]:
        api_resp: dict = await self.wrapper(self.drive_service.drives().list, fields="drives(id, name, hidden, restrictions)")
        for d in api_resp.get('drives', []):
            if await self._check_permissions(d['id']) in ['owner', 'organizer']:
                try:
                    drive = SharedDrive(d)
                    if drive.hidden and not include_hidden:
                        continue
                    self.drives.append(drive)
                except KeyError as e:
                    logger.warning(f"Drive {d['id']} is missing expected fields, skipping: {e}")
                    continue
        return self.drives

    async def share_object(self, object_id, email, role='writer') -> str:
        new_perm = {
            'type': 'user',
            'role': role,
            'emailAddress': email
        }
        logger.debug(f"Sharing object {object_id} from {self.address} to {email} as {role}...")
        resp = await self.wrapper(self.drive_service.permissions().create, supportsAllDrives=True, fileId=object_id, sendNotificationEmail=False, body=new_perm, fields="id")
        logger.debug(f"Share response for object {object_id} with {email}: {resp}")
        perm_id = resp.get('id', None)
        if not perm_id:
            logger.error(f"Failed to share object {object_id} with {email}")
            raise UnknownAPIError(f"Failed to share object {object_id} with {email}. Got response: {resp}")
        logger.debug(f"Shared object {object_id} with {email} [permission id: {perm_id}]")
        self.outstanding_shares[perm_id] = object_id
        return perm_id

    async def remove_share(self, object_id, permission_id):
        if permission_id not in self.outstanding_shares:
            logger.warning(f"Attempting to remove permission {permission_id} which is not in outstanding shares for user {self.address}")
        try:
            await self.wrapper(self.drive_service.permissions().delete, supportsAllDrives=True, fileId=object_id, permissionId=permission_id)
            logger.debug(f"Removed share {permission_id} from object {object_id}")
            self.outstanding_shares.pop(permission_id, None)
        except MigratorError as e:
            logger.warning(f"Failed to remove share {permission_id} from object {object_id}: {e}")

    async def remove_all_shares(self):
        tasks = []
        for perm_id, obj_id in list(self.outstanding_shares.items()):
            tasks.append(self.remove_share(obj_id, perm_id))
        await asyncio.gather(*tasks, return_exceptions=False)

    async def create_drive(self, predecessor_drive: SharedDrive) -> SharedDrive:
        body = {
            'name': predecessor_drive.name,
            'restrictions': predecessor_drive.restrictions,
            'hidden': predecessor_drive.hidden,
            'themeId': 'abacus'
        }
        resp = await self.wrapper(self.drive_service.drives().create, body=body, requestId=uuid.uuid4().hex, fields="id, name, hidden, restrictions")
        new_drive = SharedDrive(resp)
        self.drives.append(new_drive)
        return new_drive

    async def _fetch_files(self, **kwargs) -> list[dict]:
        """Async version of file listing."""
        next_token = None
        files = []
        while True:
            query_ret: dict = await self.wrapper(
                self.drive_service.files().list,
                pageToken=next_token,
                fields="nextPageToken, files(id, name, kind, mimeType, parents, owners, trashed, properties)",
                **kwargs
            )
            if query_ret is None:
                logger.warning(f"Received empty response when fetching files with kwargs {kwargs}")
                break
            next_token = query_ret.get('nextPageToken')
            files.extend(query_ret.get('files', []))
            if not next_token:
                break

        return files

    async def index_shared_drive_files(self, drive: SharedDrive, semaphore: asyncio.Semaphore):
        """Indexes a single shared drive."""
        async with semaphore:
            file_list = await self._fetch_files(
                driveId=drive.id,
                corpora="drive",
                q="trashed=false",
                supportsAllDrives=True,
                includeItemsFromAllDrives=True
            )
            drive.build_filetree(file_list)

    async def index_personal_drive_files(self):
        """Indexes the personal drive."""
        file_list = await self._fetch_files(corpora="user", q="trashed=false")
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
        self.initialized = False
        self.is_active = False #also serve as abort flag
        self.semaphore = asyncio.Semaphore(10)
        self.transfer_semaphore = asyncio.Semaphore(3) # for offline heavy transfers
        self.wrapper = src_user.wrapper # src_user and dst_user wrapper should be the same object

    def abort(self):
        self.is_active = False
        logger.info("Abort flag set, migration will stop after current file is finished.")

    async def _online_copy_file(self, file: File, parent_id: str | None, src_drive: Drive, mark_failures: bool = True):
        """Worker to asynchronously copy single file"""
        if not self.initialized or not self.is_active:
            return
        new_metadata = {
            'name': file.name,
            'mimeType': file.mime_type,
            'parents': [parent_id] if parent_id else [],
            'properties': {
                'migrator_source_id': file.id
            }
        }
        async with self.semaphore:
            try:
                resp = await self.wrapper(self.dst_user.drive_service.files().copy, supportsAllDrives=True,
                                          fileId=file.id, body=new_metadata, fields="id")
                new_id = resp.get('id', None)
                if not new_id:
                    logger.error(f"Failed to copy file {file.name}")
                    if mark_failures:
                     src_drive.failed_files.append(file)
            except MigratorError as e:
                logger.error(f"Failed to copy file {file.name} from drive {src_drive.name}: {e}")
                if mark_failures:
                     src_drive.failed_files.append(file)
            try:
                await self.wrapper(
                    self.src_user.drive_service.files().update,
                    supportsAllDrives=True,
                    fileId=file.id,
                    body={'properties': {'migrator_new_id': new_id}}
                )
            except MigratorError as e:
                logger.warning(f"Failed to mark file {file.name} as migrated from drive {src_drive.name}: {e}")
            src_drive.time_estimator.bip()

    async def _offline_copy_file(self, file: File, parent_id: str) -> str | None:
        """Refactored Async Strategy B: Download and Re-upload.
        Note: Currently only works for personal drive!"""
        async with self.transfer_semaphore:  # Limit heavy transfers
            loop = asyncio.get_running_loop()

            if self.download_file_size_limit_mb > 0:
                try:
                    metadata = await self.wrapper(
                        self.src_user.drive_service.files().get,
                        fileId=file.id,
                        fields="size"
                    )
                    size = int(metadata.get('size', 0))
                    if size > self.download_file_size_limit_mb * 1024 * 1024:
                        logger.warning(f"Skipping {file.name}: Exceeds size limit.")
                        return None
                except MigratorError as e:
                    logger.error(f"Failed to download file {file.name}: {e}")
                    return None

            def _blocking_transfer():
                fh = io.BytesIO()
                if file.mime_type in mime_map:
                    request = self.src_user.drive_service.files().export_media(
                        fileId=file.id,
                        mimeType=mime_map[file.mime_type]
                    )
                else:
                    request = self.src_user.drive_service.files().get_media(fileId=file.id)
                downloader = MediaIoBaseDownload(fh, request)
                done = False
                while not done:
                    status, done = downloader.next_chunk()
                fh.seek(0)
                # Setup Uploader
                upload_mime = mime_map.get(file.mime_type, 'application/octet-stream')
                uploader = MediaIoBaseUpload(fh, mimetype=upload_mime, resumable=True)

                id_resp = self.dst_user.drive_service.files().create(
                    body={
                        'name': file.name,
                        'mimeType': file.mime_type,
                        'parents': [parent_id],
                        'properties': {'migrator_source_id': file.id}
                    },
                    media_body=uploader,
                    fields="id"
                ).execute()
                self.src_user.personal_drive.time_estimator.bip()
                return id_resp.get('id')
            return await loop.run_in_executor(None, _blocking_transfer)


    async def _migrate_folder_recursive(self, folder: File, parent_id: str | None, src_drive: Drive):
        """Recursively creates folders and schedules file copies."""
        if not self.initialized or not self.is_active:
            return
        new_folder_body = {
            'name': folder.name,
            'mimeType': folder.mime_type,
            'parents': [parent_id] if parent_id else [],
            'properties': {'migrator_source_id': folder.id}
        }
        async with self.semaphore:
            resp = await self.wrapper(
                self.dst_user.drive_service.files().create,
                supportsAllDrives=True,
                body=new_folder_body,
                fields="id"
            )
            src_drive.time_estimator.bip()

        new_id = resp.get('id')
        src_drive.num_migrated_files += 1
        tasks = []
        for child in folder.children:
            if child.is_folder:
                tasks.append(self._migrate_folder_recursive(child, new_id, src_drive))
            else:
                tasks.append(self._online_copy_file(child, new_id, src_drive))

        await asyncio.gather(*tasks, return_exceptions=False)

    async def _migrate_shared_drive(self, drive: SharedDrive):
        logger.debug(f"Starting migration of drive. {drive.name} has {drive.num_files} files to migrate.")
        # share old drive with new user
        async with self.semaphore:
            permission_id = await self.src_user.share_object(drive.id, self.dst_user.address, role='organizer')
        logger.debug(f"Shared drive {drive.name} with {self.dst_user.address} with permission id {permission_id}")
        # create new drive in destination account
        if drive.successor:
            logger.info(f"Drive {drive} has successor {drive.successor}, skipping creation and using successor drive for migration")
            new_drive = drive.successor
        else:
            async with self.semaphore:
                new_drive = await self.dst_user.create_drive(drive)
            drive.set_successor(new_drive)
            logger.debug(f"Created new drive {new_drive.name} in destination account for migrating drive {drive.name}")
        if not isinstance(new_drive, SharedDrive):
            logger.error(f"Expected SharedDrive object but got {type(new_drive)}")
            return
        drive.status_message = "In progress"
        drive.time_estimator.reset_base_time()

        tasks = []
        for f in drive.root:
            if f.is_folder:
                tasks.append(self._migrate_folder_recursive(f, new_drive.id, drive))
            else:
                tasks.append(self._online_copy_file(f, new_drive.id, drive))

        await asyncio.gather(*tasks, return_exceptions=False)
        drive.status_message = "Completed"
        logger.debug(f"Removing share from source drive {drive.name}...")
        try:
            await self.src_user.remove_share(drive.id, permission_id)
        except MigratorError as e:
            logger.error(f"Failed to remove share from source drive {drive.name}: {e}")
            # not a critical error, continue with migration
        drive.status_message = "Completed"
        if not drive.migrated:
            try:
                await self.src_user.wrapper(self.src_user.drive_service.drives().update, driveId=drive.id, body={'name': drive.name + " - Migrated"})
            except MigratorError as e:
                logger.error(f"Failed to rename source drive {drive.name}: {e}")
            drive.migrated = True

    async def _migrate_personal_drive(self):
        if not self.initialized or not self.is_active:
            return

        self.src_user.personal_drive.status_message = "In progress"
        # create base folder in target drive
        try:
            resp = await self.dst_user.wrapper(self.dst_user.drive_service.files().create,
                body={
                    'name': 'Migrated Personal Drive',
                    'mimeType': 'application/vnd.google-apps.folder',
                    'properties': {
                        'migrator_personal_drive': 'true'
                    }
                }, fields="id")
            new_root_id = resp.get('id', None)
            if not new_root_id:
                self.src_user.personal_drive.status_message = "Failed: could not create root folder"
                raise UnknownAPIError(f"Failed to create root folder for personal drive migration in destination account. Got response: {resp}")
        except MigratorError as e:
            logger.error(f"Failed to create root folder for personal drive migration in destination account: {e}")
            self.src_user.personal_drive.status_message = f"Failed: {e}"
            raise e
        path_map = {self.src_user.personal_drive.id: new_root_id}

        # build folder structure in new drive by creating folders with same name and properties as old folders
        # recursive to ensure file structure is preserved
        async def move_folder(folder: File, parent_id):
            new_folder_metadata = {
                'name': folder.name,
                'mimeType': folder.mime_type,
                'parents': [parent_id],
                'properties': {
                    'migrator_source_id': folder.id
                }
            }
            try:
                resp = await self.dst_user.wrapper(self.dst_user.drive_service.files().create, body=new_folder_metadata,
                                                   fields="id")
                new_id = resp.get('id', None)
                if not new_id:
                    logger.error(f"Failed to create folder {folder.name} in personal drive migration")
                    raise UnknownAPIError(f"Failed to create folder {folder.name} in personal drive migration. Got response: {resp}")
                path_map[folder.id] = new_id
            except MigratorError as e:
                logger.error(f"Failed to create folder {folder.name} in personal drive migration: {e}")
                raise e
            self.src_user.personal_drive.time_estimator.bip()
            for child in folder.children:
                if child.is_folder:
                    await move_folder(child, parent_id=new_id)
            self.src_user.personal_drive.num_migrated_files += 1
        for f in self.src_user.personal_drive.root:
            if f.is_folder:
                await move_folder(f, parent_id=new_root_id)
        async def copy_file(file: File, parent_id):
            try:
                await self._online_copy_file(file, parent_id, self.src_user.personal_drive, False)
                self.src_user.personal_drive.num_migrated_files += 1
                return
            except MigratorError:
                logger.warning(f"Personal drive: failed online migration of {file.name}, attempting offline method")
            try:
                await self._offline_copy_file(file, parent_id)
                self.src_user.personal_drive.num_migrated_files += 1
            except MigratorError:
                logging.error(f"Both methods of copying file {file.name} failed!")
                self.src_user.personal_drive.failed_files.append(file.name)

        logger.info("Finished creating folder structure for personal drive migration, now copying files...")
        file_copy_tasks = [copy_file(f, path_map[f.parent_id]) for f in self.src_user.personal_drive.all_files.values()]
        await asyncio.gather(*file_copy_tasks, return_exceptions=False)

    async def perform_migration(self) -> bool:
        """The main entry point called by the UI."""
        self.initialized = True
        self.is_active = True
        drive_tasks = [self._migrate_shared_drive(d) for d in self.to_migrate]
        if self.migrate_personal_drive:
            drive_tasks.append(self._migrate_personal_drive())
        logger.debug(f"Starting migration with {len(drive_tasks)} concurrent drive migrations...")
        try:
            await asyncio.gather(*drive_tasks, return_exceptions=False)
        except Exception as e:
            logger.error(f"Migration failed with exception: {e}")
            pdb.post_mortem(e)
        return self.initialized

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

    async def prepare_migration(self):
        """Index all  drives concurrently."""
        tasks = [self.src_user.index_shared_drive_files(drive, self.semaphore) for drive in self.to_migrate]
        async def index_personal_drive_wrapper():
            with self.semaphore:
                await self.src_user.index_personal_drive_files()
        if self.migrate_personal_drive:
            tasks.append(index_personal_drive_wrapper())
        logger.info(f"Starting concurrent indexing of {len(tasks)} drives...")
        try:
            await asyncio.gather(*tasks, return_exceptions=False)
        except Exception as e:
            pdb.post_mortem(e)
        logger.info("Finished indexing all drives.")

    async def generate_drive_list(self):
        # generate list of drives, identify duplicate names across source and destination accounts and mark for user confirmation
        src_drives, dst_drives = await asyncio.gather(self.src_user.get_drives(), self.dst_user.get_drives(), return_exceptions=False)
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
        # MODIFIED: Use ThreadLocalHttp to ensure thread safety
        self.user_service = g_discover.build("admin", "directory_v1", http=ThreadLocalHttp(creds))

    async def fetch_users(self, page_token=None) -> list[dict]:
        logger.debug(f"Listing all users {'[recursive call]' if page_token else ''}")
        if not self.user_service:
            logger.error("Attempted to search for user without user service instance!")
            raise ValueError("User service not configured!")

        query_ret = await self.wrapper(self.user_service.users().list, customer='my_customer', pageToken=page_token)

        # filter out just the full name of each user and return as list
        users: list = []
        for user in query_ret.get('users', []):
            try:
                users.append(user["name"]["fullName"])
            except KeyError:
                logger.warning(f"User {user['primaryEmail']} is missing a full name, skipping")

        if 'nextPageToken' in query_ret:
            return users + await self.fetch_users(page_token=query_ret["nextPageToken"])
        return users

    async def find_user(self, name) -> User | None:

        query_ret = await self.wrapper(self.user_service.users().list, customer='my_customer', query=f'name:"{name}"')

        if 'users' not in query_ret or len(query_ret['users']) == 0:
            logger.warning(f"No users found matching name: {name}")
            return None
        if len(query_ret['users']) > 1:
            logger.warning(f"Multiple users found matching name: {name}, using first result")
        user_info = query_ret['users'][0]
        return User(name, user_info['primaryEmail'], self.worker, user_info.get('thumbnailPhotoUrl'), self.wrapper)

    async def find_user_by_email(self, email) -> User | None:

        query_ret = await self.wrapper(self.user_service.users().list, customer='my_customer', query=f'email:"{email}"')

        if 'users' not in query_ret or len(query_ret['users']) == 0:
            logger.warning(f"No users found matching email: {email}")
            return None
        user_info = query_ret['users'][0]
        return User(user_info["name"]["fullName"], email, self.worker, user_info.get('thumbnailPhotoUrl'), self.wrapper)