import googleapiclient.discovery as gdiscover
import logging
import googleapiclient.schema
from google.oauth2 import service_account
import time


def get_all_drive_files(driveID: str, token: str | None = None) -> list[dict]:
    query_ret: dict = drive.files().list(driveId=driveID, supportsAllDrives=True, corpora="drive", includeItemsFromAllDrives=True, pageToken=token, fields="nextPageToken, files(id, name, mimeType)").execute()
    file_list: list = query_ret['files']
    if 'nextPageToken' in query_ret.keys():
        file_list += get_all_drive_files(driveID, query_ret['nextPageToken'])
    return file_list


ACCOUNT_FILE_SRC = 'hvrhs-worker.json'
SCOPE_LIST = ["https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/admin.directory.user.readonly"]
credentials = service_account.Credentials.from_service_account_file(ACCOUNT_FILE_SRC, scopes=SCOPE_LIST)
u = 'jellington@hvrhs.org'
delegated_credentials = credentials.with_subject(u)
drive = gdiscover.build('drive', 'v3', credentials=delegated_credentials)
driveList: list = drive.drives().list().execute()['drives']
print("{} has {} team drives.".format(u, len(driveList)))
print("Collecting files, this might take a while...")
t_ref = time.time()
fileList: list = get_all_drive_files(driveList[0]['id'])
print("Collected {} file handles in {}s.".format(len(fileList), round(time.time() - t_ref, 2)))
