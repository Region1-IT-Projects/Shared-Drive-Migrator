import uuid
import googleapiclient.discovery as gdiscover
import googleapiclient.errors as gapiErrors
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
INTERACTIVE = True
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
        self.team_drives = self.get_team_drives()

    def get_all_drive_files(self, driveID: str, token: str | None = None) -> list[dict]:
        query_ret: dict = self.src.API.files().list(driveId=driveID, supportsAllDrives=True, corpora="drive",
                                                    includeItemsFromAllDrives=True, pageToken=token,
                                                    fields="nextPageToken, files(id, name, kind, mimeType, parents)").execute()
        file_list: list = query_ret['files']
        if 'nextPageToken' in query_ret.keys():
            file_list += self.get_all_drive_files(driveID, query_ret['nextPageToken'])
        return file_list

    def permission_lookup(self, file_id: str, org=None, token=None) -> list[dict]:
        if org is None:
            org = self.src
        response = org.API.permissions().list(fileId=file_id, supportsAllDrives=True, pageToken=token,
                                              fields="nextPageToken, permissions(id, role, emailAddress)").execute()
        permission_list = response['permissions']
        if 'nextPageToken' in response.keys():
            permission_list += self.permission_lookup(file_id, org, response['nextPageToken'])
        return permission_list

    def get_team_drives(self) -> list:
        all_drives = self.src.API.drives().list().execute()['drives']
        owned_drives = []
        for drive in all_drives:
            # run checks to make sure drive hasn't already been moved, in order of time complexity
            if drive['id'] in finished_drives:
                continue
            if "Migrated" in drive['name']:
                continue
            # make sure we have organizer permission
            for perm in self.permission_lookup(drive['id']):
                if perm['emailAddress'] == self.src.address:
                    if perm['role'] == 'organizer':
                        owned_drives.append(drive)
        return owned_drives


# Generates the body for a permissions create request
def add_user_body(email: str, role: str = "writer"):
    return {
        "emailAddress": email,
        "role": role,
        "type": "user"
    }


def new_drive(target: Org, name: str) -> str:
    params = {"name": name, "themeId": "abacus"}
    ret = target.API.drives().create(requestId=uuid.uuid1().hex, body=params).execute()
    return ret['id']


# de-duplicate file list
def file_list_convert(pile: list[dict]) -> list[File]:
    out = set()
    for i in pile:
        out.add(File(i))
    return list(out)


def migrate_user(user: User) -> int:
    moved_files = 0
    for dr in user.team_drives:
        drivestart = time.time()
        print("Found team drive {}".format(dr['name']))
        if not AUTO_ACCEPT:
            if input("Move drive? (Y/n): ").casefold() == "n":
                print("Skipping...")
                continue
        # create drive in destination org
        targ_id = new_drive(target=user.dst, name=dr['name'])
        if VERBOSE:
            print("created drive in target organization with ID ", targ_id)
        # temporarily add old user account to new drive as an organizer
        temp_access = user.dst.API.permissions().create(fileId=targ_id,
                                                        body=add_user_body(user.src.address, "organizer"),
                                                        supportsAllDrives=True).execute()
        file_pile = file_list_convert(user.get_all_drive_files(dr['id']))  # returns files AND Directories in a jumble
        if VERBOSE:
            print("Discovered {} files and directories".format(len(file_pile)))
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
                        except gapiErrors.HttpError as e:
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


def print_help():
    print("""
Team Drive workspace-to-workspace Migrator help

Usage:
    python migrator.py source_credentials.json destination_credentials.json [options]

Options:
    -i, --INTERACTIVE: Interactive mode (default)
    -a, --automatic <csv_file>: Automatic mode with CSV file
    -y, --yes: Assume Yes for all confirmations

Example:
    python migrator.py source_credentials.json destination_credentials.json -a users.csv

Note:
    - source_credentials.json and destination_credentials.json must be JSON files containing Google OAuth2 credentials.
    - users.csv should be a CSV file containing the following columns:
        - source_email
        - destination_email
    """)
    exit(1)


def parse_key(keypath: str) -> service_account.Credentials:
    try:
        return service_account.Credentials.from_service_account_file(keypath, scopes=SCOPE_LIST)
    except FileNotFoundError:
        print("Keyfile '{}' not found in {}. Ensure file exists and is spelled correctly.".format(keypath, os.getcwd()))
        exit(1)


def handle_csv_err(reason: str):
    print("Error: failed to parse CSV file '{}':".format(USER_CSV), reason)
    exit(2)


def ingest_csv(path: str) -> list[list[str]]:
    account_list = []
    with open(path, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) != 2:
                handle_csv_err("Expected 2 rows, found {}.".format(len(row)))
                temp_row = []
            for index, c in enumerate(row):
                if '@' not in c:
                    if VERBOSE and index == 0:
                        print("warning: {} not a valid email address!".format(c))
                else:
                    temp_row.append(c.strip().casefold())
            account_list.append(temp_row)

    if VERBOSE:
        print("Ingested {} account pair(s).".format(len(account_list)))
    return account_list


def run_interactive():
    src = Org(input("Source email address: ".casefold()), src_creds)
    dst = Org(input("Destination email address: ".casefold()), dst_creds)
    try:
        user = User(src, dst)
    except exceptions.RefreshError:
        print("Authentication failed! Check email addresses and try again.")
        exit(1)

    migrate_user(user)
    if input("Migrate another user? (y/N): ".casefold()) == 'y':
        run_interactive()


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


# Don't try to execute if we're being used as a library
if __name__ == "__main__":
    print("Team Drive workspace-to-workspace Migrator version {}".format(VERSION).center(TERMWIDTH, '='))
    # Parse CLI arguments
    if len(sys.argv) < 3:
        print("Incorrect invocation: too few arguments!")
        print_help()
    src_creds = parse_key(sys.argv[1])
    dst_creds = parse_key(sys.argv[2])
    arg_idx = 3
    while arg_idx < len(sys.argv):
        match sys.argv[arg_idx]:
            case '-i' | '--INTERACTIVE':
                print("INTERACTIVE mode selected")
                INTERACTIVE = True
            case '-a' | '--automatic':
                print("automatic (csv) mode selected")
                INTERACTIVE = False
                arg_idx += 1  # skip parsing of next argument by this loop
                USER_CSV = sys.argv[arg_idx]
            case '-y' | '--yes':
                print("script will assume Yes for ALL confirmations")
                AUTO_ACCEPT = True
            case '-v' | '--verbose':
                print("Verbose mode selected")
                VERBOSE = True
            case _:
                print("\n unknown argument {}! Bailing out.\n".format(sys.argv[arg_idx]))
                print_help()
        arg_idx += 1
    start_time = time.time()
    if INTERACTIVE:
        print("Running in interactive mode.")
        run_interactive()

    run_automatic(ingest_csv(USER_CSV))
    print("Finished in {} seconds.".format(round(time.time() - start_time, 1)))
