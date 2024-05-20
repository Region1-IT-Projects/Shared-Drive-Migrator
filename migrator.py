import googleapiclient.discovery as gdiscover
import logging
import googleapiclient.schema
from google.oauth2 import service_account
logging.basicConfig(filename='/tmp/migrator.log', encoding='utf-8', level=logging.DEBUG)
ACCOUNT_FILE_SRC = 'hvrhs-worker.json'
SCOPE_LIST = ["https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/admin.directory.user.readonly"]
credentials = service_account.Credentials.from_service_account_file(ACCOUNT_FILE_SRC, scopes=SCOPE_LIST)
u = 'jellington@hvrhs.org'
delegated_credentials = credentials.with_subject(u)
drive = gdiscover.build('drive', 'v3', credentials=delegated_credentials)

driveList: list = drive.drives().list().execute()['drives']
logging.info("{} has {} team drives.".format(u, len(driveList)))
