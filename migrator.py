import uuid

import googleapiclient.discovery as gdiscover
import logging
import googleapiclient.schema
from google.oauth2 import service_account
import time
import sys
import csv
import os

# Global vars
VERSION = "α-indev"
src_creds = None
dst_creds = None
SCOPE_LIST = ["https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/admin.directory.user.readonly"]
INTERACTIVE = True
USER_CSV = ""
AUTO_ACCEPT = False
VERBOSE = True

finished_drives = set()


class Dir:
    def __init__(self, dir_id: str, name: str, parent):
        self.id = dir_id
        self.name = name
        self.parent = parent
        self.contents = []

    def add_child_dir(self, dir_id):
        self.contents.append(Dir(dir_id, self))

    def add_child_file(self, file):
        self.contents.append(file)


class File:
    def __init__(self, file_id: str, name: str, parent: Dir):
        self.id = file_id
        self.name = name
        self.parent = parent


class Org:
    def __init__(self, addr, creds: service_account.Credentials):
        self.address = addr
        self.delegated_creds = creds.with_subject(addr)
        self.API = gdiscover.build('drive', 'v3', credentials=self.delegated_creds)


class User:
    def __init__(self, src: Org, dst: Org):
        self.src = src
        self.dst = dst
        self.team_drives: list = self.src.API.drives().list().execute()['drives']

    def get_all_drive_files(self, driveID: str, token: str | None = None) -> list[dict]:
        query_ret: dict = self.src.API.files().list(driveId=driveID, supportsAllDrives=True, corpora="drive",
                                                    includeItemsFromAllDrives=True, pageToken=token,
                                                    fields="nextPageToken, files(id, name, kind, mimeType, parents)").execute()
        file_list: list = query_ret['files']
        if 'nextPageToken' in query_ret.keys():
            file_list += self.get_all_drive_files(driveID, query_ret['nextPageToken'])
        return file_list


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


def migrate_user(user: User):
    for dr in user.team_drives:
        # TODO: only do this part if user is owner of drive
        if dr['id'] in finished_drives:
            print("Skipping drive '{}' as it has already been migrated".format(dr['name']))
            continue
        # create drive in destination org
        targ_id = new_drive(target=user.dst, name=dr['name'])
        # temporarily add old user account to new drive as an organizer
        user.dst.API.permissions().create(fileId=targ_id, body=add_user_body(user.src.address, "organizer"),
                                          supportsAllDrives=True).execute()
        file_pile = user.get_all_drive_files(dr['id'])  # returns files AND Directories in a jumble
        known_paths = set()
        known_paths.add(dr['id'])
        path_map = {dr['id']: targ_id}
        # variables to detect a deadlock
        same_count = 0
        last_length = len(file_pile)
        # loop through file_pile until it is empty
        while file_pile:
            for index, file in enumerate(file_pile):
                if file['parents']['id'] in known_paths:
                    # copy file over
                    newID = user.src.API.files().copy(fileId=file['id'],
                                                      parents=[path_map[file['parents']['id']]]).execute()
                    # TODO: Handle file-specific permissions?
                    known_paths.add(file['id'])
                    path_map.update({file['id']: newID})
                    # pop instead of remove to reduce time complexity
                    file_pile.pop(index)
                    if VERBOSE:
                        print("moved file {}.".format(file['name']))
            if len(file_pile) == last_length:
                same_count += 1
            else:
                same_count = 0
            if same_count > 2:
                print("ERROR: deadlock detected! No new files have been moved for 3 iterations!")
                if input("print debug info before exiting? (y/N): ").casefold() == 'y':
                    print("Attempted moving files from drive ID {} to drive ID {}\n".format(dr['id'], targ_id))
                    print("---Moved files:---")
                    print(known_paths)
                    print("\n---Pending files:---")
                    print(file_pile)
                print("shutting down due to error.")
                exit(1)
        finished_drives.add(dr['id'])


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
    - source_credentials.json and destination_credentials.json should be valid JSON files containing Google OAuth2 credentials.
    - users.csv should be a CSV file containing the following columns:
        - source_email
        - destination_email
    """)


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
            for c in row:
                if '@' not in c:
                    print("warning: {} not a valid email address!".format(c))
            account_list.append(row)
    print("Ingested {} account pairs.".format(len(account_list)))
    return account_list


def run_interactive():
    print("Not implemented!")
    exit(69)


def run_automatic(accountPairs: list[list[str]]):
    file_count = 0
    for pair in accountPairs:
        src_acc = Org(pair[0], src_creds)
        dst_acc = Org(pair[1], dst_creds)
        user = User(src_acc, dst_acc)
        file_count += migrate_user(user)
    print("Migrated migrated {} files from {} team drives from {} users.".format(file_count, len(finished_drives),
                                                                                 len(accountPairs)))
    exit(0)


# Don't try to execute if we're being used as a library
if __name__ == "__main__":
    print("\nTeam Drive workspace-to-workspace Migrator version", VERSION)
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
            case _:
                print("\n unknown argument {}! Bailing out.\n".format(sys.argv[arg_idx]))
                print_help()
    if INTERACTIVE:
        run_interactive()

    run_automatic(ingest_csv(USER_CSV))
