import googleapiclient.discovery as gdiscover
import logging
import googleapiclient.schema
from google.oauth2 import service_account
import time
import sys
import os

# Global vars
VERSION = "α-indev"
src_creds = None
dst_creds = None
SCOPE_LIST = ["https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/admin.directory.user.readonly"]
INTERACTIVE = True
USER_CSV = ""
AUTO_ACCEPT = False


class Org:
    def __init__(self, addr, creds: service_account.Credentials):
        self.delegated_creds = creds.with_subject(addr)
        self.API = gdiscover.build('drive', 'v3', credentials=self.delegated_creds)


class User:
    def __init__(self, addr: str, src_creds: service_account.Credentials, dst_creds: service_account.Credentials,
                 src_domain: str, dst_domain: str):
        self.address = addr
        self.src = Org(self.address + src_domain, src_creds)
        self.dst = Org(self.address + dst_domain, dst_creds)
        self.team_drives: list = self.src.API.drives().list().execute()['drives']

    def get_all_drive_files(self, driveID: str, token: str | None = None) -> list[dict]:
        query_ret: dict = self.src.API.files().list(driveId=driveID, supportsAllDrives=True, corpora="drive",
                                                    includeItemsFromAllDrives=True, pageToken=token,
                                                    fields="nextPageToken, files(id, name, mimeType)").execute()
        file_list: list = query_ret['files']
        if 'nextPageToken' in query_ret.keys():
            file_list += self.get_all_drive_files(driveID, query_ret['nextPageToken'])
        return file_list


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


def ingest_csv():
    # TODO: check sanity of csv and return TBD data structure (probably list of lists n*2)
    pass


def run_interactive():
    exit(0)


def run_automatic(users: list[list[str]]):
    exit(0)


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
