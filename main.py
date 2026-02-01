from nicegui import ui, events
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
        SINGLE_SETUP = 2
        SINGLE_PROGRESS = 3
        BATCH_SETUP = 4
        BATCH_PROGRESS = 5

class Session:

    def __init__(self):
        self.id: str = uuid.uuid4().hex
        self.stage = Stage.AUTH_SETUP
        self.src_org = None
        self.dst_org = None

    @ui.refreshable
    def router(self):
        with ui.column().classes('w-full items-center pb-8'):
            ui.label(f'Stage: {self.stage.name.replace("_", " ").title()}').classes('text-grey text-sm uppercase tracking-widest')
        
        match self.stage:
            case Stage.AUTH_SETUP:
                self.render_auth_setup()

    def __render_auth_inner(self, is_src: bool):
        current_file = self.src_org if is_src else self.dst_org
        label = "Source" if is_src else "Destination"
        card_classes = 'w-64 p-4 transition-all '
        card_classes += 'border-2 border-green-500 bg-green-50' if current_file else 'border border-gray-200'

        with ui.card().classes(card_classes).style('min-height: 180px'):
            with ui.column().classes('w-full items-center justify-center h-full'):
                if current_file:
                    # SUCCESS STATE
                    ui.icon('check_circle', color='positive').classes('text-5xl')
                    ui.label(f"{label} Loaded").classes('text-bold text-green-700')
                    ui.button('Change', on_click=lambda: self.clear_file(is_src)).props('flat dense')
                else:
                    # UPLOAD STATE
                    ui.label(f"{label} Keyfile").classes('text-lg font-medium')
                    ui.upload(
                        label='Select JSON keyfile',
                        auto_upload=True,
                        on_upload=lambda e: self.ingest_keyfile(e, is_src)
                    ).props('flat bordered').props('accept=.json').classes('w-full')


    def render_auth_setup(self):
        with ui.column().classes('w-full items-center gap-6'):
            ui.label("Upload Credentials").classes('text-h4 font-light')
            
            with ui.row().classes('gap-8 items-stretch'):
                self.__render_auth_inner(True)
                self.__render_auth_inner(False)
            ui.button(text="Continue", on_click= lambda: self.go_to(Stage.MODE_SELECT)).set_enabled(self.__is_auth_configured())


    async def ingest_keyfile(self, e: events.UploadEventArguments, is_src: bool):
        file = await e.file.json()
        logging.debug(f"Got file. Type {type(file)}, {file}")
        try:
            tmp = service_account.Credentials.from_service_account_info(file)
        except ValueError as e:
            logging.error(f"Could not parse keyfile {e.file.name}")
            ui.notify(f"Could not parse keyfile E: {e}!", type="error")
            return
        if is_src:
            self.src_org = tmp
            logging.debug(f"Set source credentials successfully ({type(tmp)})")
        else:
            self.dst_org = tmp
            logging.debug("Set dest credentials successfully")
        self.router.refresh()
        

    def __is_auth_configured(self) -> bool:
        return self.dst_org is not None and self.src_org is not None

    def go_to(self, stage: Stage):
        """Handle state changes, checking preconditions are met"""
        match Stage:
            case Stage.AUTH_SETUP:
                self.stage = Stage.AUTH_SETUP
            case Stage.MODE_SELECT:
                if self.__is_auth_configured():
                    # TODO: make this notify more errory
                    ui.notify("You must configure both source and destination keys before proceeding!")
                else:
                    self.stage = Stage.MODE_SELECT

    def clear_file(self, is_src: bool):
        if is_src:
            self.src_org = None
        else:
            self.dst_org = None
        self.router.refresh()



if __name__ in {"__main__", "__mp_main__"}:
    ui.run()
