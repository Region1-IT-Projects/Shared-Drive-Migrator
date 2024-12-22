import uuid
import googleapiclient.discovery as gdiscover
import googleapiclient.errors as gapi_errors
from google.auth import exceptions
from google.oauth2 import service_account
import sys
import csv
import os
import time

# Global vars
VERSION = "β 1"
src_creds = None
dst_creds = None
SCOPE_LIST = ["https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/admin.directory.user.readonly"]
INTERACTIVE = False
USER_CSV = ""
AUTO_ACCEPT = False
VERBOSE = False
TERMWIDTH = os.get_terminal_size().columns
finished_drives = set()


class File:
    def __init__(self, indict):
        self.id = indict["id"]
        self.name = indict["name"]
        self.kind = indict["kind"]
        self.mimeType = indict["mimeType"]
        self.parent = indict["parents"][0]

    def __repr__(self):
        return f"<File: {self.id}>"


class Org:
    def __init__(self, addr, creds: service_account.Credentials):
        self.address = addr
        self.delegated_creds = creds.with_subject(addr)
        self.API = gdiscover.build('drive', 'v3', credentials=self.delegated_creds)


class User:
    def __init__(self, src: Org, dst: Org):
        self.src = src
        self.dst = dst

    def migrate_teamdrive(self) -> int:
        moved_files = 0
        for dr in self.team_drives:
            # create drive in destination org
            targ_id = new_shared_drive(target=self.dst, name=dr['name'])
            # temporarily add old user account to new drive as an organizer
            temp_access = self.dst.API.permissions().create(fileId=targ_id,
                                                            body=add_user_body(user.src.address, "organizer"),
                                                            supportsAllDrives=True).execute()
            file_pile = file_list_convert(
                user.get_all_drive_files(dr['id']))  # returns files AND Directories in a jumble

            moved_files += len(file_pile)
            known_paths = set()
            known_paths.add(dr['id'])
            path_map = {dr['id']: targ_id}
            # variables to detect a deadlock
            same_count = 0
            last_length = len(file_pile)
            # loop through file_pile until it is empty
            while file_pile:
                for index, file in enumerate(file_pile):
                    if file.parent in known_paths:
                        file_metadata = {
                            "name": file.name,
                            "mimeType": file.mimeType,
                            "parents": [path_map[file.parent]]
                        }
                        if file.mimeType == 'application/vnd.google-apps.folder':
                            # 'file' is actually a folder and cannot be copied, make a folder with same name instead
                            if VERBOSE:
                                print("{} is a folder, making a new one.".format(file.name))
                            newID = user.dst.API.files().create(body=file_metadata, supportsAllDrives=True,
                                                                fields='id').execute()['id']
                            if VERBOSE:
                                print("new folder ID is {}".format(newID))
                            known_paths.add(file.id)
                            path_map.update({file.id: newID})
                        else:
                            if VERBOSE:
                                print("Copying file from {} to {}.".format(file.parent, file_metadata['parents'][0]))
                            try:
                                user.src.API.files().copy(fileId=file.id, body=file_metadata,
                                                          supportsAllDrives=True).execute()
                            except gapi_errors.HttpError as e:
                                print("ERR: Cannot copy file {}: {}".format(file.name, e))
                        # pop instead of remove to reduce time complexity
                        file_pile.pop(index)
                        if VERBOSE:
                            print("moved file {}".format(file.name))
                if len(file_pile) == last_length:
                    same_count += 1
                else:
                    same_count = 0
                if same_count > 2:
                    print("ERROR: deadlock detected! No new files have been moved for 3 iterations!")
                    if AUTO_ACCEPT or input("print debug info before exiting? (y/N): ").casefold() == 'y':
                        print("Attempted moving files from drive ID {} to drive ID {}\n".format(dr['id'], targ_id))
                        print("---Moved files:---")
                        print(known_paths)
                        print("\n---Pending files:---")
                        print(file_pile)
                    print("shutting down due to error.")
                    exit(1)
            finished_drives.add(dr['id'])
            # update source drive to mark as migrated
            drive_update_body = {"name": dr['name'] + " - Migrated"}
            user.src.API.drives().update(driveId=dr['id'], body=drive_update_body).execute()
            user.dst.API.permissions().delete(fileId=targ_id, permissionId=temp_access['id'],
                                              supportsAllDrives=True).execute()
            print("Finished migrating drive in {} seconds.".format(round(time.time() - drivestart, 1)))
        return moved_files

    def migrate_all_teamdrives(self) -> int:
        counter = 0
        return counter


# Generates the body for a permissions create request
def add_user_body(email: str, role: str = "writer"):
    return {
        "emailAddress": email,
        "role": role,
        "type": "user"
    }


def run_automatic(accountPairs: list[list[str]]):
    file_count = 0
    for pair in accountPairs:
        src_acc = Org(pair[0], src_creds)
        dst_acc = Org(pair[1], dst_creds)
        user = User(src_acc, dst_acc)
        file_count += migrate_user(user)
    print("Migrated {} files from {} team drives from {} users.".format(file_count, len(finished_drives),
                                                                        len(accountPairs)))
    exit(0)