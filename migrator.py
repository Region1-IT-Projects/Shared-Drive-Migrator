import uuid
from typing import TextIO

import googleapiclient.discovery as gdiscover
import googleapiclient.errors as gapi_errors
from google.auth import exceptions
from google.oauth2 import service_account
import csv

class GFile:
    def __init__(self, indict):
        self.id = indict["id"]
        self.name = indict["name"]
        self.kind = indict["kind"]
        self.mimeType = indict["mimeType"]
        self.parent = indict["parents"][0]
        self.trashed = bool(indict["trashed"])

    def __repr__(self):
        return f"<File: {self.id}>"


class Org:
    def __init__(self, addr, creds: service_account.Credentials):
        self.address = addr
        self.delegated_creds = creds.with_subject(addr)
        self.API = gdiscover.build('drive', 'v3', credentials=self.delegated_creds)
        self.known_drives = {}

    def new_team_drive(self, name: str) -> str:
        params = {"name": name, "themeId": "abacus"}
        ret = self.API.drives().create(requestId=uuid.uuid1().hex, body=params).execute()
        return ret['id']

    def add_access(self, file_id: str, email: str, role: str = "writer"):
        return self.API.permissions().create(fileId=file_id, body={"emailAddress": email, "role": role, "type": "user"}, supportsAllDrives=True).execute()['id']

    def remove_access(self, file_id: str, access_id: str):
        self.API.permissions().delete(fileId=file_id, permissionId=access_id, supportsAllDrives=True).execute()

    def get_drives(self):
        tmp = self.API.drives().list().execute()['drives']
        out = []
        for i in tmp:
            drive = GDrive(i)
            drive.set_files(self.get_all_drive_files(drive.id))
            out.append(drive)
            self.known_drives[drive.id] = drive
        return out

    def get_all_drive_files(self, drive_id: str, token: str | None = None) -> list[dict]:
        query_ret: dict = self.API.files().list(driveId=drive_id, supportsAllDrives=True, corpora="drive",
                                                    includeItemsFromAllDrives=True, pageToken=token,
                                                    fields="nextPageToken, files(id, name, kind, mimeType, parents)").execute()
        file_list: list = query_ret['files']
        if 'nextPageToken' in query_ret.keys():
            file_list += self.get_all_drive_files(drive_id, query_ret['nextPageToken'])
        return file_list

def check_email_validity(email: str, domain: str) -> bool:
    parts = email.split("@")
    if len(parts) != 2:
        return False
    if parts[1] != domain:
        return False
    return True

class Migrator:
    src_creds = None
    dst_creds = None
    domains = ["",""]
    SCOPE_LIST = ["https://www.googleapis.com/auth/drive",
                  "https://www.googleapis.com/auth/admin.directory.user.readonly"]
    def __init__(self):
        self.finished_drives = set()

    # return: string if error, list of string pairs (src, dst) if success
    def ingest_csv(self, data: TextIO) -> str | dict[str, str]:
        accounts = {}
        reader = csv.reader(data)
        for index, row in enumerate(reader):
            if len(row) != 2:
                return "Row {} invalid: {}cols != 2".format(index, len(row))
            temp_row = []
            for addr_idx, addr in enumerate(row):
                if check_email_validity(addr, self.domains[addr_idx]):
                    temp_row.append(addr.strip().casefold())
                else:
                    return "{} is not a valid email address!".format(addr)
            if len(temp_row) == 2:
                accounts[temp_row[0]] = temp_row[1]
        return accounts

    def set_src_creds(self, credpath: str) -> bool:
        try:
            self.src_creds = service_account.Credentials.from_service_account_file(credpath, scopes=self.SCOPE_LIST)
            self.domains[0] = self.src_creds.service_account_email.split("@")[1]
            return True
        except FileNotFoundError:
            return False

    def set_dst_creds(self, credpath: str) -> bool:
        try:
            self.dst_creds = service_account.Credentials.from_service_account_file(credpath, scopes=self.SCOPE_LIST)
            self.domains[1] = self.dst_creds.service_account_email.split("@")[1]
            return True
        except FileNotFoundError:
            return False

class User:
    def __init__(self, from_org: Org, to_org: Org):
        self.src = from_org
        self.dst = to_org

    def permission_lookup(self, file_id: str, org=None, token=None) -> list[dict]:
        if org is None:
            org = self.src
        response = org.API.permissions().list(fileId=file_id, supportsAllDrives=True, pageToken=token,
                                              fields="nextPageToken, permissions(id, role, emailAddress)").execute()
        permission_list = response['permissions']
        if 'nextPageToken' in response.keys():
            permission_list += self.permission_lookup(file_id, org, response['nextPageToken'])
        return permission_list

    def get_owned_team_drives(self) -> list:
        all_drives = self.src.get_drives()
        owned_drives = []
        for drive in all_drives:
            # make sure we have organizer permission
            for perm in self.permission_lookup(drive.id):
                if perm['emailAddress'] == self.src.address:
                    if perm['role'] == 'organizer':
                        owned_drives.append(drive)
        return owned_drives

    def migrate_drive(self, drive_id: str):
        target_id = self.dst.new_team_drive(drive_id)
        # temporarily add source user account to dest drive as an organizer
        temp_access = self.dst.add_access(target_id, self.src.address)
        source_drive: GDrive = self.src.known_drives[drive_id]
        known_paths = set()
        known_paths.add(drive_id)
        # mappings of filepath IDs from old to new drive
        path_map = {drive_id: target_id}
        # double loop, effectively BFS to add file parents before file
        while source_drive.files:
            for index, file in enumerate(source_drive.files):
                if file.trashed:
                    source_drive.files.pop(index)
                    continue
                if file.parent in known_paths:
                    file_metadata = {
                        "name": file.name,
                        "mimeType": file.mimeType,
                        "parents": [path_map[file.parent]]
                    }
                    if file.mimeType == 'application/vnd.google-apps.folder':
                        # 'file' is actually a folder and cannot be copied, make a folder with same name instead
                        newID = user.dst.API.files().create(body=file_metadata, supportsAllDrives=True,
                                                            fields='id').execute()['id']

                        known_paths.add(file.id)
                        path_map.update({file.id: newID})
                    else:
                        try:
                            user.src.API.files().copy(fileId=file.id, body=file_metadata,
                                                      supportsAllDrives=True).execute()
                        except gapi_errors.HttpError as e:
                            print("ERR: Cannot copy file {}: {}".format(file.name, e))
                    # pop instead of remove to reduce time complexity
                    source_drive.files.pop(index)
        source_drive.migrated = True
        self.dst.remove_access(target_id, temp_access)
        # todo: rename old drive

class GDrive:
    def __init__(self, indict: dict):
        self.file_count = 0
        self.files: list[GFile] = []
        self.id: str = indict["id"]
        self.name: str = indict["name"]
        self.hidden: bool = bool(indict["hidden"])
        self.restrictions: dict[str] = indict["restrictions"]
        self.themeId = indict["themeId"]
        self.migrated: bool = False

    def set_files(self, file_list: list[dict]):
        out = set()
        for i in file_list:
            # convert to GFile object
            out.add(GFile(i))
        self.files = list(out)
        self.file_count = len(self.files)