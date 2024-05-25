import googleapiclient.discovery as gdiscover
import logging
import googleapiclient.schema
from google.oauth2 import service_account
import time


class Org:
    def __init__(self, addr, creds: service_account.Credentials):
        self.delegated_creds = creds.with_subject(addr)
        self.API = gdiscover.build('drive', 'v3', credentials=self.delegated_creds)


class User:
    def __init__(self, addr: str, src_creds: service_account.Credentials, dst_creds: service_account.Credentials, src_domain: str, dst_domain: str):
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


def main(src_token: str, dst_token: str, src_domain: str, dst_domain: str):
    SCOPE_LIST = ["https://www.googleapis.com/auth/drive",
                  "https://www.googleapis.com/auth/admin.directory.user.readonly"]
    src_creds: service_account.Credentials = service_account.Credentials.from_service_account_file(src_token,
                                                                                                   scopes=SCOPE_LIST)
    dst_creds: service_account.Credentials = service_account.Credentials.from_service_account_file(dst_token,
                                                                                                   scopes=SCOPE_LIST)
    test_u = User("jellington", src_creds, dst_creds, src_domain, dst_domain)


main("hvrhs-worker.json", "", "hvrhs.org", "region1schools.org")
