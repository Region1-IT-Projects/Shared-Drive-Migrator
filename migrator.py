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
        self.restrictions: dict[str] = indict["restrictions"]
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
        ret = self.API.drives().create(requestId=uuid.uuid1().hex, body=params).execute()
        return ret['id']

    def add_access(self, file_id: str, email: str, role: str = "writer"):
        return self.API.permissions().create(fileId=file_id, body={"emailAddress": email, "role": role, "type": "user"},
                                             supportsAllDrives=True).execute()['id']

    def remove_access(self, file_id: str, access_id: str):
        self.API.permissions().delete(fileId=file_id, permissionId=access_id, supportsAllDrives=True).execute()

    def get_drives(self):
        tmp = self.API.drives().list(fields="drives(id, name, hidden, restrictions)").execute()['drives']
        out = []
        for i in tmp:
            drive = GDrive(i)
            out.append(drive)
            self.known_drives[drive.id] = drive
        return out

    def __fetch_files(self, token: str | None = None, **kwargs) -> list[dict]:
        query_ret: dict = self.API.files().list(pageToken=token,
                                                fields="nextPageToken, files(id, name, kind, mimeType, parents, owners, trashed, properties)",
                                                **kwargs).execute()
        try:
            file_list: list = query_ret['files']
        except KeyError:
            if "error" in query_ret.keys():
                print("ERR: {}".format(query_ret['error']))
                return []
            file_list = [query_ret]
        if 'nextPageToken' in query_ret.keys():
            file_list += self.__fetch_files(query_ret['nextPageToken'], **kwargs)
        return file_list

    def populate_drive_files(self, drive: GDrive, num_retries = 0):
        if num_retries > 3:
            print("ERR: Too many retries for fetching drive {}'s files!".format(drive.name))
            return
        try:
            file_list = self.__fetch_files(driveId=drive.id, supportsAllDrives=True, includeItemsFromAllDrives=True, corpora="drive")
        except ssl.SSLError as e:
            print("SSL Error :", e)
            # wait a bit and retry
            time.sleep(1)
            return self.populate_drive_files(drive, num_retries + 1)
        drive.set_files(file_list)

    def get_personal_files(self, num_retries = 0):
        if num_retries > 3:
            print("ERR: Too many retries for fetching personal files!")
            return
        try:
            file_list = self.__fetch_files(corpora="user", supportsAllDrives=False, includeItemsFromAllDrives=False)
        except ssl.SSLError as e:
            print("SSL Error :", e)
            # wait a bit and retry
            time.sleep(1)
            return self.get_personal_files(num_retries + 1)
        for i in file_list:
            f = GFile(i)
            if f.is_mine and not f.trashed and f.mimeType != 'application/vnd.google-apps.shortcut':
                self.personal_files.append(f)
        return self.personal_files

    def mark_drive_moved(self, drive: GDrive):
        if drive.name.count("Migrated") == 0: # don't add migrated more than once
            self.API.drives().update(driveId=drive.id, body={"name": drive.name + " - Migrated"}).execute()

    def mark_file_moved(self, file_id: str, dest_id: str):
        self.API.files().update(fileId=file_id, supportsAllDrives=True, body={"properties": {"migrated_to": dest_id}}).execute()

    def unmark_file_moved(self, file_id: str):
        self.API.files().update(fileId=file_id, supportsAllDrives=True, body={"properties": {"migrated_to": None}}).execute()


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
        response = org.API.permissions().list(fileId=file_id, supportsAllDrives=True, pageToken=token,
                                              fields="nextPageToken, permissions(id, role, emailAddress)").execute()
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

    def migrate_drive(self, source_drive: GDrive, skip_migrated: bool, target_id: str | None = None) -> bool:
        print("Starting migration")
        if not source_drive.file_count:
            print("No files found in drive {}. Has it been initialized?".format(source_drive.name))
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
                        new_id = self.dst.API.files().create(body=file_metadata, supportsAllDrives=True,
                                                            fields='id').execute()['id']

                        known_paths.add(file.id)
                        path_map.update({file.id: new_id})
                    else:
                        try:
                            self.src.API.files().copy(fileId=file.id, body=file_metadata,
                                                      supportsAllDrives=True).execute()
                        except (g_api_errors.HttpError, TimeoutError) as e:
                            print("ERR: Cannot copy file {}: {}".format(file.name, e))
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
            print("No personal files found in {}!".format(self.src.address))
            return file_share_lookup
        # share every file in personal drive to target user
        for file in self.src.personal_files:
            if file.trashed or (file.moved and skip_migrated):
                continue
            try:
                access_id = self.src.add_access(file.id, self.dst.address)
                file_share_lookup[file.id] = access_id
            except g_api_errors.HttpError as e:
                print("Warning: Cannot share file {}: {}".format(file.name, e))
        return file_share_lookup

    # Strategy:
    # src: recurse through all files in personal drive, sharing to dest user, return list of file (and folder) IDs
    # dst: replicate folder structure (and collate loose if requested), keep dict of mappings old->new
    # dst: make a copy of shared files, placing into corresponding folder structure
    # src: un-share all shared files, mark as xfered
    def migrate_personal_files(self, skip_migrated: bool = False):
        files_and_shares = self.share_personal_files(skip_migrated)
        if len(files_and_shares) == 0:
            print("No files to migrate!")
            return
        # get base path of source and target users' drives
        try:
            src_root = self.src.API.files().get(fileId="root", fields="id").execute()['id']
            dst_root = self.dst.API.files().get(fileId="root", fields="id").execute()['id']
        except ValueError:
            print("ERR: Cannot get root folder ID!")
            return
        # create folder in target drive to store copied files
        folder_metadata = {
            "name": "Migrated Personal Files",
            "mimeType": "application/vnd.google-apps.folder",
            "parents": [dst_root]
        }
        dst_folder_id = self.dst.API.files().create(body=folder_metadata).execute()['id']
        migrated_files = set()
        known_paths = {src_root: dst_folder_id}
        # make a copy of the shared files in target user's drive
        while len(migrated_files) < len(files_and_shares):
            for file_id in files_and_shares:
                if file_id in migrated_files:
                    continue
                # get file metadata
                try:
                    file_metadata = self.src.API.files().get(fileId=file_id, fields="id, name, mimeType, parents").execute()
                except g_api_errors.HttpError as e:
                    print("ERR: Cannot get file {}: {}".format(file_id, e))
                    continue
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
                    new_folder_id = self.dst.API.files().create(body=new_metadata).execute()['id']
                    known_paths[file_metadata['id']] = new_folder_id
                else:
                    # copy file to target drive
                    self.dst.API.files().copy(fileId=file_id, body=new_metadata).execute()
                migrated_files.add(file_id)
                # add a labeled to file indicating it has been copied
                self.src.mark_file_moved(file_id, new_metadata['parents'][0])
        print("Copied {} files to target drive.".format(len(migrated_files)))
        # un-share all files in personal drive
        for file_id in files_and_shares:
            try:
                self.src.remove_access(file_id, files_and_shares[file_id])
            except g_api_errors.HttpError as e:
                print("ERR: Cannot un-share file {}: {}".format(file_id, e))

class Migrator:
    src_creds = None
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
            self.src_creds = service_account.Credentials.from_service_account_file(credpath, scopes=self.SCOPE_LIST)
            return True
        except FileNotFoundError:
            print("Credentials file not found.")
            return False
        except ValueError as e:
            print("Invalid credentials file! Error: {}".format(e))
            return False

    def set_dst_creds(self, credpath: str) -> bool:
        try:
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
        except RefreshError:
            print("Invalid credentials for source or destination account.")
            return None
        u = User(src_acc, dst_acc)
        return u

class BulkMigration:
    def __init__(self, csv_path:str, mig: Migrator, skip_moved: bool, do_personal: bool, do_shared: bool):
        self.migrator = mig
        self.skip_moved = skip_moved
        self.do_personal = do_personal
        self.do_shared = do_shared
        # Read CSV file
        with open(csv_path, 'r') as csv_file:
            self.accounts = self.migrator.ingest_csv(csv_file)
        self.workers = {}

    def start_migration(self):
        """Spawn threads for each user migration"""
        for src, dst in self.accounts.items():
            user = self.migrator.create_user(src, dst)
            if user is None:
                print(f"Failed to create user for {src} -> {dst}")
                continue
            worker = Thread(target=self.migrate_user, args=(user,))
            worker.start()
            self.workers[user.src.address] = worker
        print(f"Started migration for {len(self.workers)} users.")

    def migrate_user(self, user: User):
        print("Starting migration for mapping {} -> {}".format(user.src.address, user.dst.address))
        """Migrate a single user"""
        if self.do_personal:
            user.migrate_personal_files(self.skip_moved)
            print("Finished migrating personal files for {}".format(user.src.address))
        if self.do_shared:
            drives = user.get_owned_team_drives()
            for idx, drive in enumerate(drives):
                target_id = user.prepare_team_drive_for_migrate(drive)
                if target_id is None:
                    print(f"Drive {drive.name} already migrated or not initialized.")
                    continue
                user.migrate_drive(drive, self.skip_moved, target_id)
                print(f"Finished migrating drive {drive.name} for {user.src.address} ({idx}/{len(drives)})")
        print(f"Migration for {user.src.address} completed.")

    def get_progress(self):
        """Get the progress of all worker threads"""
        statuses = {}
        for worker in self.workers:
            if self.workers[worker].is_alive():
                statuses[worker] = "In Progress"
            else:
                statuses[worker] = "Completed"
        return statuses
