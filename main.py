import asyncio
import logging
import os
import uuid
from enum import Enum

from dotenv import load_dotenv
from nicegui import events, run, ui

from backend import (
    APIWrapper,
    MigratorError,
    MissingAdminSDKError,
    Org,
    SharedDrive,
    SingleMigrator,
    User,
)

load_dotenv()

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
        SINGLE_FINISHED = 5
        BATCH_SETUP = 6
        BATCH_PROGRESS = 7

class Session:

    def __init__(self):
        self.id: str = uuid.uuid4().hex
        self.dark = ui.dark_mode(True)
        self.stage = Stage.AUTH_SETUP
        self.src_org = None
        self.src_domain_admin = os.getenv("SRC_ADMIN_EMAIL", "")
        self.dst_org = None
        self.dst_domain_admin = os.getenv("DST_ADMIN_EMAIL", "")
        self.migrator_obj = None
        self.api_wrapper = APIWrapper()
        ui.timer(1, self.render_footer.refresh)

    @ui.refreshable
    async def router(self):
        match self.stage:
            case Stage.AUTH_SETUP:
                self.render_auth_setup()
            case Stage.MODE_SELECT:
                self.render_mode_select()
            case Stage.SINGLE_SETUP_ACCT:
                await self.render_single_setup()
            case Stage.SINGLE_SETUP_DRIVES:
                await self.render_single_drive_select()
            case Stage.SINGLE_PROGRESS:
                await self.render_single_progress()
            case _:
                ui.label("This stage is not implemented yet!").classes('text-red-500')

    def go_to(self, stage: Stage):
        """Handle state changes, checking preconditions are met"""
        match Stage:
            case Stage.AUTH_SETUP:
                self.__clear_auth_file(True)
                self.__clear_auth_file(False)
                self.stage = Stage.AUTH_SETUP
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
            ui.label(str(self.api_wrapper)).classes('text-xs')
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
                with ui.card().classes('w-80 p-6 shadow-lg border-t-4 border-blue-500 transition-transform'), ui.column().classes('items-center text-center h-full'):
                    ui.icon('person', size='64px', color='blue-500')
                    ui.label("Single User").classes('text-xl font-bold mt-2')

                    ui.label("Migrate a single user at a time. Allows for fine-grained control over specific shared drives.") \
                        .classes('text-sm text-grey-600 dark:text-grey-400 mt-4 h-24')

                    ui.space() # Pushes the button to the bottom

                    ui.button("Select Single", on_click=lambda: self.go_to(Stage.SINGLE_SETUP_ACCT)) \
                        .props('elevated color=blue-500').classes('w-full mt-4')

                # --- MULTI MODE CARD ---
                with ui.card().classes('w-80 p-6 shadow-lg border-t-4 border-orange-500 transition-transform'), ui.column().classes('items-center text-center h-full'):
                    ui.icon('groups', size='64px', color='orange-500')
                    ui.label("Bulk Migration").classes('text-xl font-bold mt-2')

                    ui.label("Migrate multiple users at a time in a 'batch'. All owned shared drives will be migrated.") \
                        .classes('text-sm text-grey-600 dark:text-grey-400 mt-4 h-24')

                    ui.space() # Pushes the button to the bottom

                    ui.button("Select Bulk", on_click=lambda: self.go_to(Stage.BATCH_SETUP)) \
                        .props('elevated color=orange-500').classes('w-full mt-4')

    def show_admin_sdk_error(self, e: MissingAdminSDKError):
        with ui.dialog() as dialog, ui.card().style('width: 60vw; max-width: 800px; min-width: 300px;').classes('p-4'):
            ui.label("Admin SDK API Not Enabled").classes('text-h5')
            ui.label("The Google Admin SDK API must be enabled in your Google Cloud Console. Visit: ").classes('text-sm text-grey-600 dark:text-grey-400')
            # find link in error message
            for word in e.args[0].split():
                if word.startswith("http"):
                    ui.link(word, word, new_tab=True).classes('text-blue-500')
                    break
            ui.label("After enabling the Admin SDK API for the service account, reset and try again. Note that the change can take up to 15 minutes to take effect in Google's systems.").classes('text-sm text-grey-600 dark:text-grey-400 mt-2')
            ui.button("Reset", on_click=lambda: dialog.close() or self.go_to(Stage.MODE_SELECT)).props('elevated color=red-500').classes('w-full mt-4')
            dialog.open()

    async def render_single_setup(self):
        state = {'src': None, 'dst': None}

        def update_continue_btn():
            if isinstance(state['src'], User) and isinstance(state['dst'], User):
                self.migrator_obj = SingleMigrator(state['src'], state['dst'])
            continue_btn.set_enabled(True)

        @ui.refreshable
        def render_account_card(title: str, key: str):
            with ui.card().classes('w-80 p-4').style('min-height: 180px;'):
                ui.label(title).classes('text-sm text-grey-600 dark:text-grey-400')
                acct = state[key]
                if isinstance(acct, User):
                    update_continue_btn()
                    # SUCCESS STATE: Show the address
                    with ui.column().classes('grow w-full items-center justify-center gap-3'):
                        # User Avatar with rounded-full for a circle and object-cover to prevent stretching
                        if acct.photo:
                            ui.image(acct.photo).classes('w-20 h-20 rounded-full shadow-sm border border-grey-200 object-cover')
                        else:
                            # Fallback if the user has no photo set in the Admin SDK
                            ui.icon('account_circle', size='5rem').classes('text-grey-300')
                        # User Details
                        with ui.column().classes('items-center gap-0'):
                            ui.label(acct.address).classes('text-md font-semibold text-center break-all')
                else:
                    # MANUAL STATE: Lookup failed
                    email_input = ui.input(label="Account Email", placeholder="user@example.com").classes('w-full')

                    def handle_manual_set():
                        if email_input.value:
                            # Create the User object manually
                            if key == 'src':
                                new_user = self.src_org.find_user_by_email(email_input.value.strip())
                            else:
                                new_user = self.dst_org.find_user_by_email(email_input.value.strip())
                            if new_user is None:
                                ui.notify("No user found with that email! Check the address and try again.", type='negative')
                                return
                            state[key] = new_user # Update the state dict
                            # Refresh this card with the new User object

                            render_account_card.refresh()

                    ui.button("Set Address", on_click=handle_manual_set).props('flat')

        async def finalize_user_selection(e: events.ValueChangeEventArguments):
            selected_user = e.value
            logging.debug(f"User selected: {selected_user}")
            with account_row:
                ui.spinner(size='md').classes('ml-2')
                try:
                    state['src'] = await run.io_bound(self.src_org.find_user, selected_user)
                    state['dst'] = await run.io_bound(self.dst_org.find_user, selected_user)
                except MissingAdminSDKError as e:
                    self.show_admin_sdk_error(e)
                    return
                except MigratorError as e:
                    logging.error(f"Error finding user: {e}")
                    ui.notify("Error finding user! Check logs for details.", type='negative')
                    return

                account_row.clear()

                render_account_card("Source Account", 'src')
                ui.icon('arrow_forward', size='32px')
                render_account_card("Destination Account", 'dst')

        container = ui.column().classes('w-full items-center gap-8 p-8')
        with container:
            ui.label("Initializing User Directory...").classes('text-grey')
            ui.spinner(size='lg')
            user_list = []
            try:
                user_list = await run.io_bound(self.src_org.fetch_users)
            except MissingAdminSDKError as e:
                self.show_admin_sdk_error(e)
                return
            except Exception as e:
                logging.error(f"Failed to fetch user list! Error: {e}")
                ui.notify("Failed to fetch user list! Check logs for details.", type='negative')
            container.clear()
            logging.debug(f"User list fetched with {len(user_list)} users")
            ui.label("User Setup").classes('text-h4 font-light')
            ui.label("Search for a user...").classes('text-grey')

            ui.select(
                label="Select User",
                options=sorted(user_list),
                with_input=True,
                on_change=finalize_user_selection
            ).props('clearable use-input fill-input hide-selected').classes('w-96')

            account_row = ui.row().classes('w-full items-center gap-6 justify-center')
            continue_btn = ui.button("Continue", on_click=lambda: self.go_to(Stage.SINGLE_SETUP_DRIVES)).props('elevated')
            continue_btn.set_enabled(False)

    async def render_single_drive_select(self):
        container = ui.column().classes('w-full items-center gap-8 p-8')
        with container:
            ui.label("Loading drives...").classes('text-grey')
            ui.spinner(size='lg')
        try:
            drive_list: list[SharedDrive] = await run.io_bound(self.migrator_obj.src_user.get_drives)
        except Exception as e:
            logging.error(f"Failed to fetch drive list: {e}")
            ui.notify("Failed to fetch drives. Check logs for details.", type='negative')
            container.clear()
            return

        container.clear()
        ui.label("Select Drives to Migrate").classes('text-h4 font-light')
        ui.label("Choose which shared drives to migrate for this user. Toggle drives to exclude them.").classes('text-grey')
        switches: dict = {}
        successors_selects: dict = {}
        migrate_personal_switch = None
        with ui.card().classes('w-full p-4').style('max-height: 50vh; overflow:auto'):
            with ui.row().classes('w-full items-center justify-between'):
                with ui.column().classes('items-start'):
                    ui.label("Personal Google Drive").classes('text-md font-medium text-orange-500')
                migrate_personal_switch = ui.switch(value=True).props('color=orange')
            if not drive_list:
                ui.label("No shared drives found for this user.").classes('text-grey')
            else:
                for drive in drive_list:
                    if not isinstance(drive, SharedDrive):
                        logging.error(f"Expected SharedDrive instance, got {type(drive)}. Skipping.")
                        continue
                    if drive.migrated:
                        logging.info(f"Drive {drive} already migrated, skipping.")
                        continue
                    drive_name = str(drive)
                    drive_id = drive.id

                    with ui.row().classes('w-full items-center justify-between'):
                        with ui.column().classes('items-start'):
                            ui.label(drive_name).classes('text-md font-medium')
                            ui.label(str(drive_id)).classes('text-xs text-grey-500')
                            # If this drive has possible successors, show a dropdown to pick one
                            if drive.possible_successors:
                                options = [("Create a new drive", None)] + [ (f"{s.name} ({s.id})", s) for s in drive.possible_successors ]
                                successors_selects[drive_id] = ui.select(label='Migrate Into', options=options, value=None).classes('w-64').props('clearable')
                        switches[drive_id] = ui.switch(value=True)

        # Buttons row
        with ui.row().classes('w-full items-center justify-end gap-4'):
            def handle_continue():
                selected = []
                for idx, drive in enumerate(drive_list):
                    drive_id = getattr(drive, 'id', None) or f"drive-{idx}"
                    sw = switches.get(drive_id)
                    if sw and sw.value:
                        selected.append(drive)
                # Apply any selected successors: if a successor was chosen, set it on the drive
                for d in selected:
                    did = d.id
                    sel = successors_selects.get(did)
                    if sel is not None and sel.value is not None:
                        try:
                            d.set_successor(sel.value)
                        except Exception as e:
                            logging.error(f"Failed to set successor for drive {did}: {e}")

                personal = migrate_personal_switch.value if migrate_personal_switch is not None else True
                self.migrator_obj.init_migration(selected, personal)
                logging.debug(f"Selected drives: {[getattr(d, 'id', str(d)) for d in selected]}")
                self.go_to(Stage.SINGLE_PROGRESS)

            ui.button("Continue", on_click=handle_continue).props('elevated')

    async def render_single_progress(self):
        container = ui.column().classes('w-full items-center gap-6 p-8')
        with container:
            ui.label("Initializing Migration").classes('text-h4 font-light')
            ui.linear_progress(value=None).classes('w-64 h-2')
            ui.label("Indexing personal drive... This may take a while.").classes('text-grey italic')
            idx_task = asyncio.create_task(run.io_bound(self.migrator_obj.prepare_personal_migration))
            while not idx_task.done():
                await asyncio.sleep(0.5)
            await idx_task
            container.clear()
        with container:
            ui.label("Initializing Migration").classes('text-h4 font-light')
            # Progress bar for indexing
            idx_progress_bar = ui.linear_progress(value=0, show_value=False).classes('w-64 h-2')
            ui.label("Indexing shared drives... This may take a while.").classes('text-grey italic')
            idx_task = asyncio.create_task(run.io_bound(self.migrator_obj.prepare_shared_migration))
            while not idx_task.done():
                val = getattr(self.migrator_obj, 'index_progress', 0) / 100.0
                idx_progress_bar.set_value(val)
                await asyncio.sleep(0.2)
            await idx_task
            container.clear()

        # Failed Files Dialog Setup
        with ui.dialog() as error_dialog, ui.card().classes('w-[500px]'):
            ui.label('Failed Files').classes('text-lg font-bold')
            with ui.scroll_area().classes('h-64 border p-2 w-full'):
                error_list_container = ui.column().classes('gap-1')
            ui.button('Close', on_click=error_dialog.close).classes('self-end')

        def show_errors(files):
            error_list_container.clear()
            with error_list_container:
                for f in files:
                    ui.label(str(f)).classes('text-xs text-red-700 font-mono')
            error_dialog.open()
        migration_task = asyncio.create_task(run.io_bound(self.migrator_obj.perform_migration))

        async def cancel_migration():
            self.migrator_obj.abort()
            migration_task.cancel()
            ui.notify('Migration Cancelled', type='warning')
            # Clean up UI or redirect
            prog_timer.deactivate()
            container.clear()
            with container:
                ui.label("Migration Stopped").classes('text-h4 text-red')
                ui.button("Start Over", on_click=lambda: self.go_to(Stage.MODE_SELECT)).props('elevated color=red-500').classes('mt-4')

        @ui.refreshable
        def render_progress():
            try:
                drives = self.migrator_obj.poll_progress() or []
            except Exception as e:
                ui.label(f"Connection Error: {e}").classes('text-red')
                return

            with ui.column().classes('w-full max-w-4xl gap-4'):
                for d in drives:
                    name = d.get('name', 'Unknown')
                    total = d.get('num_files', 0)
                    migrated = d.get('num_migrated_files', 0)
                    status = d.get('status_message', '')
                    failed = d.get('failed_files', [])
                    pct = (migrated / total) if total > 0 else (1.0 if status.lower().startswith('comp') else 0.0)
                    with ui.card().classes('w-full p-6 shadow-sm'), ui.row().classes('w-full items-center justify-between no-wrap'):
                        # Drive Info
                        with ui.column().classes('flex-grow'):
                            ui.label(name).classes('text-lg font-medium')
                            ui.label(status).classes('text-xs text-grey-500')
                            if failed:
                                ui.button(f'View {len(failed)} Failures',
                                        on_click=lambda f=failed: show_errors(f),
                                        icon='report_problem').props('flat color=red size=sm')

                        # Progress Stats
                        with ui.column().classes('items-end w-48'):
                            ui.label(f"{migrated:,} / {total:,}").classes('text-sm font-mono')
                            ui.linear_progress(value=pct, show_value=False).classes('w-full h-1.5')
                            ui.label(f"{pct:.0%}").classes('text-xs text-primary font-bold')

        with container:
            with ui.row().classes('w-full justify-between items-center mb-4'):
                ui.label("Active Migration").classes('text-h4 font-light')
                ui.button("Cancel Migration", on_click=cancel_migration, icon='stop').props('outline color=red')
            render_progress()

        def _tick():
            render_progress.refresh()
            if migration_task.done():
                prog_timer.deactivate()
                ui.notify("Migration Task Finished")

        prog_timer = ui.timer(2.0, _tick)

    async def render_single_finished(self):
        # TODO bring in summary stats from migrator object to show here
        container = ui.column().classes('w-full items-center gap-6 p-8')
        with container:
            ui.label("Migration Complete").classes('text-h4 font-light text-green-600')
            ui.icon('check_circle', size='64px', color='green-500')
            ui.label("All selected drives have been migrated successfully!").classes('text-green-700')
            ui.button("Start New Migration", on_click=lambda: self.go_to(Stage.MODE_SELECT)).props('elevated color=green-500').classes('mt-4')

# ----- Auth Specific Helpers ------

    async def ingest_keyfile(self, e: events.UploadEventArguments, is_src: bool):
        file = await e.file.json()
        try:
            tmp = Org(file, self.api_wrapper)
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

        with ui.card().classes(card_classes).style('min-height: 180px'), ui.column().classes('w-full items-center justify-center h-full'):
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
    ui.run(storage_secret="supersecret", reload=False, native=False, favicon="favicon.ico")
