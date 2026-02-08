from nicegui import app, ui, events, run
import uuid
import logging
from enum import Enum
from backend import Org, SingleMigrator, MissingAdminSDK, MigratorError
VERSION = "3.0.0-dev"

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logging.getLogger("nicegui").setLevel(logging.WARNING)

@ui.page("/", title="Drive Migration Wizard")
async def main_view():
    session = Session()
    session.render_header()
    await session.router()
    session.footer_shell()

class Stage(Enum):
        AUTH_SETUP = 0
        MODE_SELECT = 1
        SINGLE_SETUP_ACCT = 2
        SINGLE_SETUP_DRIVES = 3
        SINGLE_PROGRESS = 4
        BATCH_SETUP = 5
        BATCH_PROGRESS = 6

class Session:

    def __init__(self):
        self.id: str = uuid.uuid4().hex
        self.dark = ui.dark_mode(True) 
        self.stage = Stage.AUTH_SETUP
        self.src_org = None
        self.src_domain_admin = ""
        self.dst_org = None
        self.dst_domain_admin = ""
        self.migrator_obj = None

    @ui.refreshable
    async def router(self):
        match self.stage:
            case Stage.AUTH_SETUP:
                self.render_auth_setup()
            case Stage.MODE_SELECT:
                self.render_mode_select()
            case Stage.SINGLE_SETUP_ACCT:
                await self.render_single_setup()

    def go_to(self, stage: Stage):
        """Handle state changes, checking preconditions are met"""
        match Stage:
            case Stage.MODE_SELECT:
                if not self.__is_auth_configured():
                    # TODO: make this notify more errory
                    ui.notify("You must configure both source and destination keys before proceeding!")
                else:
                    self.stage = Stage.MODE_SELECT
            case _:
                self.stage = stage
        logging.debug(f"App stage is now {self.stage.name}")
        self.router.refresh()
        self.render_footer.refresh() #TODO move to api limiter func

    def render_header(self):
        # 'elevated' adds a shadow, 'bordered' adds a bottom line
        with ui.header(elevated=True).classes('p-4 items-center justify-between'):
            with ui.row().classes('items-center gap-3'):
                ui.icon('auto_awesome', color='white').classes('text-2xl')
                ui.label('Drive Migration Wizard').classes('text-xl font-bold')
            
            with ui.row().classes('items-center gap-4'):
                ui.badge(VERSION)
                ui.switch(text="Dark Mode").bind_value(self.dark).props('color=amber').classes('text-white')

    def footer_shell(self):
        with ui.footer().classes('border-t p-2 px-8'):
            self.render_footer()

    @ui.refreshable
    def render_footer(self):
        with ui.row().classes('w-full items-center justify-between'):
            # TODO: api rate limit details
            ui.label('Filler API info').classes('text-xs')
            ui.label(f'Stage: {self.stage.name.replace("_", " ").title()}').classes('text-xz tracking-widest')

# ----- Main Renderers -------

    def render_auth_setup(self):
        with ui.column().classes('w-full items-center gap-6'):
            ui.label("Authentication Setup").classes('text-h4 font-light')
            
            with ui.row().classes('gap-8 items-stretch'):
                self.__render_auth_inner(True)
                self.__render_auth_inner(False)
            ui.button(text="Continue", on_click= lambda :self.go_to(Stage.MODE_SELECT)).set_enabled(self.__is_auth_configured())

    def render_mode_select(self):
        # Center everything in a column
        with ui.column().classes('w-full items-center gap-8 p-8'):
            
            # Heading Section
            with ui.column().classes('items-center'):
                ui.label("Migration Mode").classes('text-h4 font-light')
                ui.label("Choose migration workflow for this session").classes('text-grey')

            with ui.row().classes('w-full justify-center items-stretch gap-8'):
                
                # --- SINGLE MODE CARD ---
                with ui.card().classes('w-80 p-6 shadow-lg border-t-4 border-blue-500 transition-transform'):
                    with ui.column().classes('items-center text-center h-full'):
                        ui.icon('person', size='64px', color='blue-500')
                        ui.label("Single User").classes('text-xl font-bold mt-2')
                        
                        ui.label("Migrate a single user at a time. Allows for fine-grained control over specific shared drives.") \
                            .classes('text-sm text-grey-600 dark:text-grey-400 mt-4 h-24')
                        
                        ui.space() # Pushes the button to the bottom
                        
                        ui.button("Select Single", on_click=lambda: self.go_to(Stage.SINGLE_SETUP_ACCT)) \
                            .props('elevated color=blue-500').classes('w-full mt-4')

                # --- MULTI MODE CARD ---
                with ui.card().classes('w-80 p-6 shadow-lg border-t-4 border-orange-500 transition-transform'):
                    with ui.column().classes('items-center text-center h-full'):
                        ui.icon('groups', size='64px', color='orange-500')
                        ui.label("Bulk Migration").classes('text-xl font-bold mt-2')
                        
                        ui.label("Migrate multiple users at a time in a 'batch'. All owned shared drives will be migrated.") \
                            .classes('text-sm text-grey-600 dark:text-grey-400 mt-4 h-24')
                        
                        ui.space() # Pushes the button to the bottom
                        
                        ui.button("Select Bulk", on_click=lambda: self.go_to(Stage.BATCH_SETUP)) \
                            .props('elevated color=orange-500').classes('w-full mt-4')


    async def render_single_setup(self):

        def render_account_card(title: str, email: str):
            with ui.card().classes('w-80 p-4'):
                ui.label(title).classes('text-sm text-grey-600 dark:text-grey-400')
                ui.label(email).classes('text-lg font-medium')

        async def finalize_user_selection(e: events.ValueChangeEventArguments):
            selected_user = e.value
            logging.debug(f"User selected: {selected_user}")
            user_lookup_spinner = ui.spinner(size='md').classes('ml-2')
            try:
                source_account = await run.io_bound(self.src_org.find_user, selected_user)
                dest_account = await run.io_bound(self.dst_org.find_user, selected_user)
            except MigratorError as e:
                logging.error(f"Error finding user: {e}")
                ui.notify("Error finding user! Check logs for details.", type='negative')
                return
            if source_account is None:
                ui.notify(f"User {selected_user} not found in source domain!", type='negative')
                return
            if dest_account is None:
                ui.notify(f"User {selected_user} not found in destination domain!", type='negative')
                return
            user_lookup_spinner.remove() # remove spinner once lookup complete
            self.migrator_obj = SingleMigrator(source_account, dest_account)
            # unhide account row and populate with details
            account_row.clear()
            with account_row:
                render_account_card("Source Account", source_account.address)
                ui.icon('arrow_forward', size='32px')
                render_account_card("Destination Account", source_account.address)
            account_row.classes('') # unhide row
        container = ui.column().classes('w-full items-center gap-8 p-8')
        with container:
            ui.label("Initializing User Directory...").classes('text-grey')
            ui.spinner(size='lg')
            user_list = []
            try:
                user_list = await run.io_bound(self.src_org.fetch_users)
            except MissingAdminSDK as e:
                ## popup modal
                with ui.dialog() as dialog, ui.card().classes('w-96 p-4'):
                    ui.label("Admin SDK API Not Enabled").classes('text-h5')
                    ui.label(str(e)).classes('text-sm text-grey-600 dark:text-grey-400')
                    ui.button("Close", on_click=dialog.close).props('flat color=blue-500').classes('mt-4')
            except Exception as e:
                logging.error(f"Failed to fetch user list! Error: {e}")
                ui.notify("Failed to fetch user list! Check logs for details.", type='negative')
            container.clear()
            ui.label("User Setup").classes('text-h4 font-light')
            ui.label("Search for a user...").classes('text-grey')
            
            user_selector = ui.select(
                label="Select User", 
                options=sorted(user_list), 
                with_input=True, 
                on_change=finalize_user_selection
            ).props('clearable use-input fill-input hide-selected').classes('w-96')

            account_row = ui.row().classes('w-full items-center gap-6 justify-center')
            account_row.classes('hidden') # hide until user selected
            ui.button(text="Continue", on_click= lambda :self.go_to(Stage.SINGLE_SETUP_DRIVES)).set_enabled(lambda: account_row.classes() != 'hidden')



# ----- Auth Specific Helpers ------

    async def ingest_keyfile(self, e: events.UploadEventArguments, is_src: bool):
        file = await e.file.json()
        try:
            tmp = Org(file)
        except ValueError as e:
            ui.notify("Invalid keyfile. Please try again.")
            logging.warning(f"Ingest keyfile failed! {e}")
            return
        if is_src:
            self.src_org = tmp
            try:
                self.src_org.set_admin(self.src_domain_admin)
            except ValueError as e:
                ui.notify("Invalid domain! Check domain format and try again.", type='negative')
                logging.warning(f"Set source domain failed! Error: {e}")
                self.src_org = None
                self.src_domain_admin = ""
        else:
            self.dst_org = tmp
            try:
                self.dst_org.set_admin(self.dst_domain_admin)
            except ValueError as e:
                ui.notify("Invalid domain! Check domain format and try again.", type='negative')
                logging.warning(f"Set destination domain failed! Error: {e}")
                self.dst_org = None
                self.dst_domain_admin = ""

        self.router.refresh()
        
    def __render_auth_inner(self, is_src: bool):
        current_file = self.src_org if is_src else self.dst_org
        card_classes = 'w-96 p-4 transition-all '
        card_classes += 'border-2 border-green-500 bg-green-50 dark:border-green-700 dark:bg-green-900/30' if current_file else 'border border-gray-200 dark:border-gray-700'

        def set_temp_domain_admin(changedval):
            domain = changedval.value.strip()
            if is_src:
                self.src_domain_admin = domain
            else:
                self.dst_domain_admin = domain
            # check each is unique
            if self.src_domain_admin == self.dst_domain_admin and self.src_domain_admin != "":
                ui.notify("Source and Destination domains must be different!", type='negative')

        with ui.card().classes(card_classes).style('min-height: 180px'):
            with ui.column().classes('w-full items-center justify-center h-full'):
                if current_file:
                    # SUCCESS STATE
                    ui.icon('check_circle', color='positive').classes('text-5xl')
                    ui.label(f"{self.src_domain_admin if is_src else self.dst_domain_admin} ready").classes('text-bold text-green-700')
                    ui.button('Change', on_click=lambda: self.__clear_auth_file(is_src)).props('flat dense')
                else:
                    # UPLOAD STATE
                    ui.label(f"{"Source" if is_src else "Destination"} Organization").classes('text-lg font-medium')
                    domain_input = ui.input(label='Admin Account', placeholder='itdept@example.org', on_change=set_temp_domain_admin, value=(self.src_domain_admin if is_src else self.dst_domain_admin)).classes('w-full').props('debounce=100')
                    ui.upload(
                        label='Select JSON keyfile',
                        auto_upload=True,
                        on_upload=lambda e: self.ingest_keyfile(e, is_src)
                    ).props('flat bordered').props('accept=.json').classes('w-full').bind_enabled_from(domain_input, 'value', backward= lambda v: len(v) > 5 and v.count('.'))


    def __is_auth_configured(self) -> bool:
        return self.dst_org is not None and self.dst_domain_admin is not None and self.src_org is not None and self.src_domain_admin is not None

    def __clear_auth_file(self, is_src: bool):
        if is_src:
            self.src_org = None
        else:
            self.dst_org = None
        self.router.refresh()



if __name__ in {"__main__", "__mp_main__"}:
    ui.run(storage_secret="supersecret")
