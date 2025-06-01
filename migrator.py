import csv
import ssl
import time
import uuid
from json import JSONDecodeError
from threading import Thread
from typing import TextIO
import googleapiclient.discovery as g_discover
import googleapiclient.errors as g_api_errors
from google.oauth2 import service_account
from google.auth.exceptions import RefreshError
import logging
import random
import hashlib

logger = logging.getLogger(__name__)

def g_api_wrapper(api_request, recursion_level=0):
    """Wrapper around Google API requests to handle common errors"""
    try:
        return api_request.execute()
    except g_api_errors.HttpError as e:
        logger.debug(f"Got an HTTP error: {e}")
        if e.resp.status in [403, 429]:
            error_reason = e.error_details[0] if e.error_details else None
            if error_reason in ['rateLimitExceeded', 'userRateLimitExceeded', 'quotaExceeded']:
                if recursion_level < 10:
                    # Wait and retry
                    delay = 2 ** recursion_level + random.uniform(0, 1)  # Exponential backoff with jitter
                    logger.warning("Rate limit exceeded, retrying after a {} seconds delay...".format(round(delay, 2)))
                    time.sleep(delay)
                    return g_api_wrapper(api_request, recursion_level + 1)
                else:
                    logger.error(f"Rate limit exceeded for {api_request}. Giving up after {recursion_level} retries.")
                    return None
        elif e.resp.status in [400, 401]:
            logger.error("Bad request or unauthorized access. This is a bug, please report it!! Bailing out. Error: {}".format(e))
        elif e.resp.status in [500, 502, 503, 504]:
            logger.warning("Google API server error. This is likely a temporary issue. Retrying...")
            if recursion_level < 10:
                delay = 2 ** recursion_level + random.uniform(0, 1)  # Exponential backoff with jitter
                time.sleep(delay)
                return g_api_wrapper(api_request, recursion_level + 1)
            else:
                logger.error(f"Google API server error for {api_request}. Giving up after {recursion_level} retries.")
                logger.info("Please try again later or check the Google Workspace status page for ongoing issues.")
                return None
        else:
            logger.error(f"Unhandled HTTP error for request {api_request}: {e}")
            return None
        return None
    except JSONDecodeError as e:
        logging.error("Failed to decode JSON response from Google API: {}".format(e))
        logging.info("Likley a temporary issue, retrying immediately...")
        if recursion_level < 10:
            return g_api_wrapper(api_request, recursion_level + 1)
        else:
            logging.error("Giving up after {} retries.".format(recursion_level))
        return None
    except ssl.SSLError as e:
        logger.warning(f"SSL error for request {api_request}: {e}")
        # do exponential backoff
        if recursion_level < 10:
            delay = 2 ** recursion_level + random.uniform(0, 1)
            logger.info(f"Retrying after {delay} seconds...")
            time.sleep(delay)
            return g_api_wrapper(api_request, recursion_level + 1)
        else:
            logger.error(f"Giving up after {recursion_level} retries due to SSL error.")
            logger.info("Please check your network connection or Google Workspace status page for ongoing issues. This is not an issue with the migrator itself.")
            return None

class GFile:
    moved = False
    trashed = False
    moved_to = ""
    def __init__(self, indict):
        self.id = indict["id"]
        self.name = indict["name"]
        self.kind = indict["kind"]
        self.mimeType = indict["mimeType"]
        try:
            self.parent = indict["parents"][0]
        except KeyError:
            self.parent = None
        try:
            self.is_mine: bool = indict["owners"][0]['me']
        except KeyError:
            self.is_mine = False
        self.trashed: bool = indict["trashed"]
        self.moved = bool(indict.get("properties", {}).get("migrated_to"))
        if self.moved:
            self.moved_to = indict["properties"]["migrated_to"]
    def __repr__(self):
        return f"<File: {self.id}>"


class GDrive:
    migrator_thread: Thread | None = None
    def __init__(self, indict: dict):
        self.file_count = 0
        self.files: list[GFile] = []
        self.id: str = indict["id"]
        self.name: str = indict["name"]
        self.hidden: bool = bool(indict["hidden"])
        self.restrictions = indict["restrictions"]
        self.migrated: bool = bool(self.name.count("Migrated"))

    def set_files(self, file_list: list[dict]):
        out = set()
        for i in file_list:
            # convert to GFile object
            out.add(GFile(i))
        self.files = list(out)
        self.file_count = len(self.files)

    def __repr__(self):
        return f"<Drive: {self.name}>"


class Org:
    def __init__(self, addr, creds: service_account.Credentials):
        self.address = addr
        self.delegated_creds = creds.with_subject(addr)
        self.API = g_discover.build('drive', 'v3', credentials=self.delegated_creds)
        self.known_drives = {}
        self.personal_files: list[GFile] = []

    def new_team_drive(self, predecessor: GDrive) -> str:
        params = {"name": predecessor.name, "restrictions": predecessor.restrictions, "themeId": "abacus"}
        ret = g_api_wrapper(self.API.drives().create(requestId=uuid.uuid1().hex, body=params))
        return ret['id']

    def add_access(self, file_id: str, email: str, role: str = "writer"):
        return g_api_wrapper(
            self.API.permissions().create(fileId=file_id, body={"emailAddress": email, "role": role, "type": "user"},
                                         supportsAllDrives=True, sendNotificationEmail=False)
        )['id']

    def remove_access(self, file_id: str, access_id: str):
        g_api_wrapper(self.API.permissions().delete(fileId=file_id, permissionId=access_id, supportsAllDrives=True))

    def get_drives(self):
        tmp = g_api_wrapper(
            self.API.drives().list(fields="drives(id, name, hidden, restrictions)")
        )['drives']
        out = []
        for i in tmp:
            drive = GDrive(i)
            out.append(drive)
            self.known_drives[drive.id] = drive
        return out

    def __fetch_files(self, token: str | None = None, **kwargs) -> list[dict]:
        query_ret: dict = g_api_wrapper(
                self.API.files().list(pageToken=token,
                                      fields="nextPageToken, files(id, name, kind, mimeType, parents, owners, trashed, properties)",
                                      **kwargs))
        if query_ret is None:
            return []
        try:
            file_list: list = query_ret['files']
        except KeyError:
            if "error" in query_ret.keys():
                logger.warning("Got error in API response: {}".format(query_ret['error']))
                return []
            file_list = [query_ret]
        if 'nextPageToken' in query_ret.keys():
            file_list += self.__fetch_files(query_ret['nextPageToken'], **kwargs)
        return file_list

    def populate_drive_files(self, drive: GDrive):
        file_list = self.__fetch_files(driveId=drive.id, supportsAllDrives=True, includeItemsFromAllDrives=True, corpora="drive")
        drive.set_files(file_list)

    def get_personal_files(self):

        file_list = self.__fetch_files(corpora="user", supportsAllDrives=False, includeItemsFromAllDrives=False)

        for i in file_list:
            f = GFile(i)
            if f.is_mine and not f.trashed and f.mimeType != 'application/vnd.google-apps.shortcut':
                self.personal_files.append(f)
        return self.personal_files

    def mark_drive_moved(self, drive: GDrive):
        if drive.name.count("Migrated") == 0: # don't add migrated more than once
            g_api_wrapper(self.API.drives().update(driveId=drive.id, body={"name": drive.name + " - Migrated"}))

    def mark_file_moved(self, file_id: str, dest_id: str):
        g_api_wrapper(self.API.files().update(fileId=file_id, supportsAllDrives=True, body={"properties": {"migrated_to": dest_id}}))

    def unmark_file_moved(self, file_id: str):
        g_api_wrapper(self.API.files().update(fileId=file_id, supportsAllDrives=True, body={"properties": {"migrated_to": None}}))


def check_email_validity(email: str) -> bool:
    parts = email.split("@")
    if len(parts) != 2:
        return False
    return True

class User:
    src: Org
    dst: Org
    drives: list[GDrive]
    def __init__(self, from_org: Org, to_org: Org):
        self.src = from_org
        self.dst = to_org
        self.drives = []
    def permission_lookup(self, file_id: str, org=None, token=None) -> list[dict]:
        if org is None:
            org = self.src
        response = g_api_wrapper(
            org.API.permissions().list(fileId=file_id, supportsAllDrives=True, pageToken=token,
                                       fields="nextPageToken, permissions(id, role, emailAddress)")
        )
        permission_list = response['permissions']
        if 'nextPageToken' in response.keys():
            permission_list += self.permission_lookup(file_id, org, response['nextPageToken'])
        return permission_list

    def get_owned_team_drives(self) -> list[GDrive]:
        all_drives = self.src.get_drives()
        for drive in all_drives:
            # make sure we have organizer permission
            for perm in self.permission_lookup(drive.id):
                if perm['emailAddress'] == self.src.address:
                    if perm['role'] == 'organizer':
                        self.drives.append(drive)
        return self.drives

    def prepare_team_drive_for_migrate(self, drive: GDrive) -> str | None:
        self.src.populate_drive_files(drive)
        if drive.migrated:
            for file in drive.files:
                if file.moved:
                    # return ID of drive to which we have already migrated
                    return file.moved_to
        return None

    def migrate_drive(self, source_drive: GDrive, skip_migrated: bool, target_id: str | None = None) -> bool:
        logger.info("Starting migration")
        if not source_drive.file_count:
            logger.warning("No files found in drive {}. Has it been initialized?".format(source_drive.name))
            return False
        # if we are not copying to an existing drive, make a new one
        if target_id is None:
            target_id = self.dst.new_team_drive(source_drive)
        # temporarily add source user account to dest drive as an organizer
        temp_access = self.dst.add_access(target_id, self.src.address)
        known_paths = set()
        known_paths.add(source_drive.id)
        # mappings of filepath IDs from old to new drive
        path_map = {source_drive.id: target_id}
        # double loop, effectively BFS to add file parents before file
        while source_drive.files:
            for index, file in enumerate(source_drive.files):
                if file.trashed or (file.moved and skip_migrated):
                    source_drive.files.pop(index)
                    continue
                if file.parent in known_paths:
                    file_metadata = {
                        "name": file.name,
                        "mimeType": file.mimeType,
                        "parents": [path_map[file.parent]]
                    }
                    if file.mimeType == 'application/vnd.google-apps.shortcut':
                        # skip shortcuts, they are not copied
                        source_drive.files.pop(index)
                        continue
                    if file.mimeType == 'application/vnd.google-apps.folder':
                        # 'file' is actually a folder and cannot be copied, make a folder with same name instead
                        new_id = g_api_wrapper(
                            self.dst.API.files().create(body=file_metadata, supportsAllDrives=True, fields='id')
                        )['id']

                        known_paths.add(file.id)
                        path_map.update({file.id: new_id})
                    else:
                        g_api_wrapper(
                            self.src.API.files().copy(fileId=file.id, body=file_metadata, supportsAllDrives=True)
                        )
                    # pop instead of remove to reduce time complexity
                    self.src.mark_file_moved(file.id, target_id)
                    source_drive.files.pop(index)
        source_drive.migrated = True
        # remove source account's access to dest drive
        self.dst.remove_access(target_id, temp_access)
        # mark drive as migrated
        self.src.mark_drive_moved(source_drive)
        return True

    # share all files in personal drive to target user, return dict of file IDs to access IDs
    def share_personal_files(self, skip_migrated: bool) -> dict[str, str]:
        file_share_lookup = {}
        if len(self.src.personal_files) == 0:
            self.src.get_personal_files()
        if len(self.src.personal_files) == 0:
            logger.warning("No personal files found in {}!".format(self.src.address))
            return file_share_lookup
        # share every file in personal drive to target user
        for file in self.src.personal_files:
            if file.trashed or (file.moved and skip_migrated):
                continue
            access_id = self.src.add_access(file.id, self.dst.address)
            file_share_lookup[file.id] = access_id
        return file_share_lookup

    def migrate_personal_files(self, skip_migrated: bool = False):
        files_and_shares = self.share_personal_files(skip_migrated)
        if len(files_and_shares) == 0:
            logger.warning("No personal files to migrate for {}!".format(self.src.address))
            return
        # get base path of source and target users' drives
        try:
            src_root = g_api_wrapper(self.src.API.files().get(fileId="root", fields="id"))['id']
            dst_root = g_api_wrapper(self.dst.API.files().get(fileId="root", fields="id"))['id']
        except ValueError:
            logger.error("Cannot get root folder ID for account {}. Is it initialized?".format(self.src.address))
            return
        # create folder in target drive to store copied files
        folder_metadata = {
            "name": "Migrated Personal Files",
            "mimeType": "application/vnd.google-apps.folder",
            "parents": [dst_root]
        }
        dst_folder_id = g_api_wrapper(self.dst.API.files().create(body=folder_metadata))['id']
        migrated_files = set()
        known_paths = {src_root: dst_folder_id}
        # make a copy of the shared files in target user's drive
        while len(migrated_files) < len(files_and_shares):
            for file_id in files_and_shares:
                if file_id in migrated_files:
                    continue
                # get file metadata
                file_metadata = g_api_wrapper(self.src.API.files().get(fileId=file_id, fields="id, name, mimeType, parents"))

                new_metadata = {
                    "name": file_metadata['name'],
                    "mimeType": file_metadata['mimeType'],
                }
                # check if parent is in known_paths
                try:
                    new_metadata['parents'] = [known_paths[file_metadata['parents'][0]]]
                except KeyError:
                    # parent is not known, pass
                    continue
                # check if file is a folder
                if file_metadata['mimeType'] == 'application/vnd.google-apps.folder':
                    new_folder_id = g_api_wrapper(self.dst.API.files().create(body=new_metadata))['id']
                    known_paths[file_metadata['id']] = new_folder_id
                else:
                    # copy file to target drive
                    g_api_wrapper(self.dst.API.files().copy(fileId=file_id, body=new_metadata))
                migrated_files.add(file_id)
                # add a labeled to file indicating it has been copied
                self.src.mark_file_moved(file_id, new_metadata['parents'][0])
        logger.info("Copied {} files to target drive.".format(len(migrated_files)))
        # un-share all files in personal drive
        for file_id in files_and_shares:
            self.src.remove_access(file_id, files_and_shares[file_id])


class Migrator:
    src_creds = None
    src_creds_hash = None
    dst_creds = None
    SCOPE_LIST = ["https://www.googleapis.com/auth/drive",
                  "https://www.googleapis.com/auth/admin.directory.user.readonly"]

    def __int__(self):
        pass

    # return: string if error, list of string pairs (src, dst) if success
    def ingest_csv(self, data: TextIO) -> str | dict[str, str]:
        accounts = {}
        reader = csv.reader(data)
        for index, row in enumerate(reader):
            if len(row) != 2:
                return "Row {} invalid: {}cols != 2".format(index, len(row))
            temp_row = []
            for addr_idx, addr in enumerate(row):
                if check_email_validity(addr):
                    temp_row.append(addr.strip().casefold())
                else:
                    if index == 0:
                        # assume this is a header row
                        continue
                    return "{} is not a valid email address!".format(addr)
            if len(temp_row) == 2:
                accounts[temp_row[0]] = temp_row[1]
        return accounts

    def set_src_creds(self, credpath: str) -> bool:
        try:
            # first, create hash of the credentials file to check if src and dst credentials are the same
            with open(credpath, 'rb') as f:
                self.src_creds_hash = hashlib.sha256(f.read()).hexdigest()
            self.src_creds = service_account.Credentials.from_service_account_file(credpath, scopes=self.SCOPE_LIST)
            return True
        except FileNotFoundError:
            logger.error("Credentials file not found.")
            return False
        except ValueError as e:
            logger.error("Invalid credentials file: {}".format(e))
            return False

    def set_dst_creds(self, credpath: str) -> bool:
        """Set destination credentials from a service account file"""
        # make sure src and dest credentials are not the same
        if self.src_creds_hash is None:
            logger.warning("Tried to set destination credentials without source credentials being set!")
            return False
        try:
            with open(credpath, 'rb') as f:
                dst_creds_hash = hashlib.sha256(f.read()).hexdigest()
            if dst_creds_hash == self.src_creds_hash:
                logger.warning("Source and destination credentials are the same! This is not allowed.")
                return False
            self.dst_creds = service_account.Credentials.from_service_account_file(credpath, scopes=self.SCOPE_LIST)
            return True
        except FileNotFoundError:
            return False

    def create_user(self, source_addr: str, dest_addr: str) -> User | None:
        try:
            src_acc = Org(source_addr, self.src_creds)
            src_acc.get_drives()
            dst_acc = Org(dest_addr, self.dst_creds)
            dst_acc.get_drives()
        except RefreshError as e:
            logger.error("Failed to create user: invalid credentials for source or destination account: {}".format(e))
            return None
        u = User(src_acc, dst_acc)
        return u

class BulkMigration:
    def __init__(self, csv_path:str, mig: Migrator):
        self.do_shared = False
        self.do_personal = False
        self.skip_moved = False
        self.migrator = mig
        self.running = False
        # Read CSV file
        with open(csv_path, 'r') as csv_file:
            self.accounts = self.migrator.ingest_csv(csv_file)
        self.workers = {}

    def is_running(self):
        return self.running

    def start_migration(self, skip_moved: bool, do_personal: bool, do_shared: bool):
        """Spawn threads for each user migration"""
        # set up control flags
        self.skip_moved = skip_moved
        self.do_personal = do_personal
        self.do_shared = do_shared
        self.running = True
        for src, dst in self.accounts.items():
            worker = Thread(target=self.migrate_user, args=(src,dst))
            worker.start()
            self.workers[src] = worker
        logger.info(f"Started migration for {len(self.workers)} users.")

    def migrate_user(self, src: str, dst: str):
        logger.info("Starting migration for mapping {} -> {}".format(src, dst))
        """Migrate a single user"""
        user = self.migrator.create_user(src, dst)
        if user is None:
            logger.error(f"Failed to create user for {src} -> {dst}! Aborting...")
            return
        if self.do_personal:
            if not self.running:
                return
            user.migrate_personal_files(self.skip_moved)
            logger.info("Finished migrating personal files for {}".format(user.src.address))
            if not self.running:
                return
        if self.do_shared:
            drives = user.get_owned_team_drives()
            for idx, drive in enumerate(drives):
                if not self.running:
                    return
                target_id = user.prepare_team_drive_for_migrate(drive)
                if target_id is None:
                    logger.warning(f"Drive {drive.name} already migrated or not initialized.")
                    continue
                user.migrate_drive(drive, self.skip_moved, target_id)
                logger.info(f"Finished migrating drive {drive.name} for {user.src.address} ({idx}/{len(drives)})")
        logger.info(f"Migration for {user.src.address} completed.")

    def stop(self):
        self.running = False

    def get_progress(self):
        """Get the progress of all worker threads"""
        statuses = {}
        for worker in self.workers:
            if self.workers[worker].is_alive():
                statuses[worker] = "In Progress"
            else:
                statuses[worker] = "Completed"
        return statuses
