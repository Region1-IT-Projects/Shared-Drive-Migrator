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


def build_dirs(dr, folders: list) -> Dir:
    root = Dir(dr['id'], dr['root'], None)
    return root


def migrate_user(user: User):
    for dr in user.team_drives:
        if dr['id'] in finished_drives:
            print("Skipping drive '{}' as it has already been migrated".format(dr['name']))
            continue
        finished_drives.add(dr['id'])

        file_pile = user.get_all_drive_files(dr['id'])  # returns files AND Directories in a jumble
        # build directory structure
        folders = []
        for i in file_pile:
            if i['mimeType'] == 'application/vnd.google-apps.folder':
                folders.append(i)
        drive_root = build_dirs(dr, folders)

    pass


def print_help():
    print("Shared drive migrator script usage:")
    print("./migrator.py [SRC CRED.json] [DST CRED.json] <Options>")
    print("-----Required Arguments-----")
    print("[SRC CRED.json]\t\t credentials for source organization service account")
    print("[DST CRED.json]\t\t credentials for destination organization service account")
    print("----------Options----------")
    print("-i, --INTERACTIVE\t\t run in INTERACTIVE mode (for a few users at a time) (default)")
    print("-a, --automatic [accounts].csv\t process accounts from a CSV (in bulk)")
    print("-y, --yes\t\t\t automatically accept all confirmations / warnings")
    exit(2)


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
