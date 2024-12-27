import csv
import uuid
from threading import Thread
from typing import TextIO
import googleapiclient.discovery as g_discover
import googleapiclient.errors as g_api_errors
from google.oauth2 import service_account

class GFile:
    moved = False
    trashed = False
    moved_to = ""
    def __init__(self, indict):
        self.id = indict["id"]
        self.name = indict["name"]
        self.kind = indict["kind"]
        self.mimeType = indict["mimeType"]
        self.parent = indict["parents"][0]
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

    def __get_all_drive_files(self, drive_id: str, token: str | None = None) -> list[dict]:
        query_ret: dict = self.API.files().list(driveId=drive_id, supportsAllDrives=True, corpora="drive",
                                                includeItemsFromAllDrives=False, pageToken=token,
                                                fields="nextPageToken, files(id, name, kind, mimeType, parents, trashed, properties)").execute()
        file_list: list = query_ret['files']
        if 'nextPageToken' in query_ret.keys():
            file_list += self.__get_all_drive_files(drive_id, query_ret['nextPageToken'])
        return file_list

    def populate_drive_files(self, drive: GDrive):
        file_list = self.__get_all_drive_files(drive.id)
        drive.set_files(file_list)

    def mark_drive_moved(self, drive: GDrive):
        if drive.name.count("Migrated") == 0: # don't add migrated more than once
            self.API.drives().update(driveId=drive.id, body={"name": drive.name + " - Migrated"}).execute()

    def mark_file_moved(self, file_id: str, dest_id: str):
        print("FILE NOT MARKED due to [debug]")
        #self.API.files().update(fileId=file_id, supportsAllDrives=True, body={"properties": {"migrated_to": dest_id}}).execute()

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

    def migrate_drive(self, source_drive: GDrive, target_id: str | None = None) -> bool:
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
                if file.trashed or file.moved:
                    source_drive.files.pop(index)
                    # todo: remove me!
                    print("skipping file {}".format(file.name))
                    continue
                if file.parent in known_paths:
                    file_metadata = {
                        "name": file.name,
                        "mimeType": file.mimeType,
                        "parents": [path_map[file.parent]]
                    }
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

class Migrator:
    users: list[User] = []
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
                    return "{} is not a valid email address!".format(addr)
            if len(temp_row) == 2:
                accounts[temp_row[0]] = temp_row[1]
        return accounts

    def set_src_creds(self, credpath: str) -> bool:
        try:
            self.src_creds = service_account.Credentials.from_service_account_file(credpath, scopes=self.SCOPE_LIST)
            return True
        except FileNotFoundError:
            return False

    def set_dst_creds(self, credpath: str) -> bool:
        try:
            self.dst_creds = service_account.Credentials.from_service_account_file(credpath, scopes=self.SCOPE_LIST)
            return True
        except FileNotFoundError:
            return False

    def create_user(self, source_addr: str, dest_addr: str) -> User:
        src_acc = Org(source_addr, self.src_creds)
        dst_acc = Org(dest_addr, self.dst_creds)
        u = User(src_acc, dst_acc)
        self.users.append(u)
        return u