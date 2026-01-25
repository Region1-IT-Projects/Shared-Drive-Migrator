from nicegui import ui
import uuid
import logging
from enum import Enum
#session imports
import googleapiclient.discovery as g_discover
import googleapiclient.errors as g_api_errors
from google.oauth2 import service_account
from google.auth.exceptions import RefreshError

logging.basicConfig(level=logging.DEBUG)

@ui.page("/")
def main_view():
    session = Session()
    session.router()

class Stage(Enum):
        AUTH_SETUP = 0
        MODE_SELECT = 1
        SINGLE_SETUP= 2
        SINGLE_PROGRESS = 3
        BATCH_SETUP = 4
        BATCH_PROGRESS = 5

class Session:

    def __init__(self):
        self.id: str = uuid.uuid4().hex()
        self.stage = Stage.AUTH_SETUP
        self.src_org = None
        self.dst_org = None

    @ui.refreshable
    def router(self):
        match self.stage:
            case Stage.AUTH_SETUP:
                # TODO
                pass

    def ingest_keyfile(self, file: ui.upload.FileUpload, is_src: bool):
        try:
            tmp = service_account.Credentials.from_service_account_info(file.json())
        except ValueError as e:
            logging.error(f"Could not parse keyfile {file.name}")
            ui.notify(f"Could not parse keyfile E: {e}!", type="error")
            return
        if is_src:
            self.src_org = tmp
        else:
            self.dst_org = tmp


if __name__ == "__main__":
    logging.info("Hello from shared-drive-migrator!")
    ui.run()
