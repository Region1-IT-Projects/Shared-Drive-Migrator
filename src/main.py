import asyncio
import logging
import multiprocessing
import os
import tempfile
import uuid
from datetime import timedelta
from enum import Enum
from io import BytesIO

import pandas as pd
import requests
from dotenv import load_dotenv
from nicegui import app, events, ui

from backend import (
    Migrator,
    MigratorError,
    MissingAdminSDKError,
    Org,
    SharedDrive,
    User,
    get_api_stats,
)
from icon import get_icon_base64

load_dotenv()

VERSION = "3.0.2"
log_path = ""  # overridden by logger


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
        self.migrator = Migrator(max_concurrent=20)
        ui.timer(1, self.render_footer.refresh)
        self.user_settings = {
            "allow_downloads": False,
            "max_size": 500,
            "skip_migrated": True,
        }
        logging.debug(f"Created new session {self.id}")

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
            case Stage.SINGLE_FINISHED:
                await self.render_single_finished()
            case Stage.BATCH_SETUP:
                await self.render_multi_setup()
            case Stage.BATCH_PROGRESS:
                await self.render_multi_progress()
            case _:
                ui.label("This stage is not implemented yet!").classes("text-red-500")

    def go_to(self, stage: Stage):
        """Handle state changes, checking preconditions are met"""
        match stage:
            case Stage.AUTH_SETUP:
                self.__clear_auth_file(True)
                self.__clear_auth_file(False)
                self.stage = Stage.AUTH_SETUP
            case Stage.MODE_SELECT:
                if not self.__is_auth_configured():
                    ui.notify(
                        "You must configure both source and destination keys before proceeding!",
                        type="negative",
                        timeout=None,
                        close_button=True,
                    )
                else:
                    self.stage = Stage.MODE_SELECT
            case Stage.SINGLE_SETUP_ACCT:  # TODO: this reset for multi-account
                if isinstance(self.migrator, Migrator):
                    self.migrator.targets.clear()
                self.stage = Stage.SINGLE_SETUP_ACCT
            case _:
                self.stage = stage
        logging.debug(f"App stage is now {self.stage.name}")
        self.router.refresh()
        self.render_footer.refresh()

    def confirm_shutdown(self):
        def do_shutdown():
            ui.notify("Program Terminated")
            app.shutdown()
        with ui.dialog() as dialog, ui.card():
            ui.label("Are you sure you want to quit?")
            with ui.row().classes("items-center"):
                ui.button("Yes", on_click=do_shutdown)
                ui.button("No", on_click=dialog.close)
        dialog.open()

    def render_header(self):
        # 'elevated' adds a shadow, 'bordered' adds a bottom line
        with ui.header(elevated=True).classes("p-4 items-center justify-between"):
            with ui.row().classes("items-center gap-3"):
                ui.icon("auto_awesome", color="white").classes("text-2xl")
                ui.label("Drive Migration Wizard").classes("text-xl font-bold")

            with ui.row().classes("items-center gap-4"):
                ui.button(
                    icon="code",
                    on_click=lambda: ui.run_javascript(
                        'window.open("https://github.com/repos/Region1-IT-Projects/Shared-Drive-Migrator", "_blank")'
                    ),
                ).props("flat color=white").tooltip("Open GitHub Repo")
                ui.button(
                    icon="power_settings_new",
                    on_click=self.confirm_shutdown,
                ).props("flat color=white").tooltip("Terminate Program")
                ui.button(icon="settings", on_click=self.render_options_dialog).props(
                    "flat color=white"
                ).tooltip("Settings")

    def footer_shell(self):
        with ui.footer().classes("border-t p-2 px-8"):
            self.render_footer()

    @ui.refreshable
    def render_footer(self):
        with ui.row().classes("w-full items-center justify-between"):
            ui.label(get_api_stats()).classes("text-xs")
            ui.label(f"Logfile: {log_path}").classes("text-xs text-gray-100")
            ui.label(f"Stage: {self.stage.name.replace('_', ' ').title()}").classes(
                "text-xs"
            )

    def render_options_dialog(self):
        with ui.dialog() as self.settings_dialog, ui.card().style("min-width: 350px"):
            ui.label("Application Options").classes("text-h6 mb-2")
            with ui.column().classes("w-full gap-4"):
                ui.switch(text="Dark Mode").bind_value(self.dark)

                with ui.row().classes("items-center w-full justify-between"):
                    download_switch = ui.switch("Allow Downloads").bind_value(
                        self.user_settings, "allow_downloads"
                    )
                    # Info Icon with Tooltip
                    with ui.icon("info", size="sm").classes(
                        "text-gray-400 cursor-help"
                    ):
                        ui.tooltip(
                            "Enables personal-drive fallback exports via download & upload to this local machine."
                        )
                ui.number(label="Max download size (MB)", format="%d").bind_value(
                    self.user_settings, "max_size"
                ).bind_visibility_from(download_switch, "value").classes("w-full ml-4")
                with ui.row().classes("items-center w-full justify-between"):
                    ui.switch("Skip already-migrated files").bind_value(
                        self.user_settings, "skip_migrated"
                    )
                    with ui.icon("info", size="sm").classes(
                        "text-gray-400 cursor-help"
                    ):
                        ui.tooltip(
                            "This wizard invisibly marks every file it migrates. Enabling this option will skip any files that have already been migrated in previous sessions."
                        )
            with ui.card_actions().classes("justify-end w-full"):
                ui.button("Close", on_click=self.settings_dialog.close).props("flat")
        self.settings_dialog.open()

    # ----- Main Renderers -------

    def render_auth_setup(self):
        with ui.column().classes("w-full items-center gap-6"):
            ui.label("Authentication Setup").classes("text-h4 font-light")

            with ui.row().classes("gap-8 items-stretch"):
                self.__render_auth_inner(True)
                self.__render_auth_inner(False)
            ui.button(
                text="Continue", on_click=lambda: self.go_to(Stage.MODE_SELECT)
            ).set_enabled(self.__is_auth_configured())

    def render_mode_select(self):
        # Center everything in a column
        with ui.column().classes("w-full items-center gap-8 p-8"):
            # Heading Section
            with ui.column().classes("items-center"):
                ui.label("Migration Mode").classes("text-h4 font-light")
                ui.label("Choose migration workflow for this session").classes(
                    "text-grey"
                )

            with ui.row().classes("w-full justify-center items-stretch gap-8"):
                # --- SINGLE MODE CARD ---
                with (
                    ui.card().classes(
                        "w-80 p-6 shadow-lg border-t-4 border-blue-500 transition-transform"
                    ),
                    ui.column().classes("items-center text-center h-full"),
                ):
                    ui.icon("person", size="64px", color="blue-500")
                    ui.label("Single User").classes("text-xl font-bold mt-2")

                    ui.label(
                        "Migrate a single user at a time. Allows for fine-grained control over specific shared drives."
                    ).classes("text-sm text-grey-600 dark:text-grey-400 mt-4 h-24")

                    ui.space()  # Pushes the button to the bottom

                    ui.button(
                        "Select Single",
                        on_click=lambda: self.go_to(Stage.SINGLE_SETUP_ACCT),
                    ).props("elevated color=blue-500").classes("w-full mt-4")

                # --- MULTI MODE CARD ---
                with (
                    ui.card().classes(
                        "w-80 p-6 shadow-lg border-t-4 border-orange-500 transition-transform"
                    ),
                    ui.column().classes("items-center text-center h-full"),
                ):
                    ui.icon("groups", size="64px", color="orange-500")
                    ui.label("Bulk Migration").classes("text-xl font-bold mt-2")

                    ui.label(
                        "Migrate multiple users at a time in a 'batch'. All owned shared drives will be migrated."
                    ).classes("text-sm text-grey-600 dark:text-grey-400 mt-4 h-24")

                    ui.space()  # Pushes the button to the bottom
                    ui.button(
                        "Select Bulk", on_click=lambda: self.go_to(Stage.BATCH_SETUP)
                    ).props("elevated color=orange-500").classes("w-full mt-4")

    def show_admin_sdk_error(self, e: MissingAdminSDKError):
        with (
            ui.dialog() as dialog,
            ui.card()
            .style("width: 60vw; max-width: 800px; min-width: 300px;")
            .classes("p-4"),
        ):
            ui.label("Admin SDK API Not Enabled").classes("text-h5")
            ui.label(
                "The Google Admin SDK API must be enabled in your Google Cloud Console. Visit: "
            ).classes("text-sm text-grey-600 dark:text-grey-400")
            # find link in error message
            for word in e.args[0].split():
                if word.startswith("http"):
                    ui.link(word, word, new_tab=True).classes("text-blue-500")
                    break
            ui.label(
                "After enabling the Admin SDK API for the service account, reset and try again. Note that the change can take up to 15 minutes to take effect in Google's systems."
            ).classes("text-sm text-grey-600 dark:text-grey-400 mt-2")
            ui.button(
                "Reset",
                on_click=lambda: dialog.close() or self.go_to(Stage.MODE_SELECT),
            ).props("elevated color=red-500").classes("w-full mt-4")
            dialog.open()

    async def render_single_setup(self):
        state = {"src": None, "dst": None}

        def update_continue_btn():
            if isinstance(state["src"], User) and isinstance(state["dst"], User):
                try:
                    self.migrator.add_target(state["src"], state["dst"])
                    continue_btn.set_enabled(True)
                except (ValueError, TypeError) as e:
                    ui.notify(e, type="negative", timeout=None, close_button=True)

        @ui.refreshable
        def render_account_card(title: str, key: str):
            with ui.card().classes("w-80 p-4").style("min-height: 180px;") as card:
                ui.label(title).classes("text-sm text-grey-600 dark:text-grey-400")
                acct = state[key]
                if isinstance(acct, User):
                    # SUCCESS STATE: Show the address
                    with ui.column().classes(
                        "grow w-full items-center justify-center gap-3"
                    ):
                        # User Avatar with rounded-full for a circle and object-cover to prevent stretching
                        if acct.photo:
                            ui.image(acct.photo).classes(
                                "w-20 h-20 rounded-full shadow-sm border border-grey-200 object-cover"
                            )
                        else:
                            # Fallback if the user has no photo set in the Admin SDK
                            ui.icon("account_circle", size="5rem").classes(
                                "text-grey-300"
                            )
                        # User Details
                        with ui.column().classes("items-center gap-0"):
                            ui.label(acct.address).classes(
                                "text-md font-semibold text-center break-all"
                            )
                else:
                    # MANUAL STATE: Lookup failed
                    email_input = ui.input(
                        label="Account Email", placeholder="user@example.com"
                    ).classes("w-full")

                    async def handle_manual_set():
                        card.clear()
                        with ui.column().classes(
                            "grow w-full items-center justify-center gap-3"
                        ):
                            ui.spinner(size="lg")
                        if email_input.value:
                            # Create the User object manually
                            if key == "src":
                                new_user = await self.src_org.find_user_by_email(
                                    email_input.value.strip()
                                )
                            else:
                                new_user = await self.dst_org.find_user_by_email(
                                    email_input.value.strip()
                                )
                            if not new_user:
                                ui.notify(
                                    "No user found with that email! Check the address and try again.",
                                    type="negative",
                                    timeout=None,
                                    close_button=True,
                                )
                            else:
                                state[key] = new_user  # Update the state dict
                            # Refresh this card with the new User object
                            card.clear()
                            await render_account_card.refresh()
                            update_continue_btn()

                    ui.button("Set Address", on_click=handle_manual_set).props("flat")

        async def finalize_user_selection(e: events.ValueChangeEventArguments):
            selected_user = e.value
            logging.debug(f"User selected: {selected_user}")
            with account_row:
                ui.spinner(size="md").classes("ml-2")
                try:
                    state["src"] = await self.src_org.find_user(selected_user)
                    state["dst"] = await self.dst_org.find_user(selected_user)
                except MissingAdminSDKError as e:
                    self.show_admin_sdk_error(e)
                    return
                except MigratorError as e:
                    logging.error(f"Error finding user: {e}")
                    ui.notify(
                        "Error finding user! Check logs for details.",
                        type="negative",
                        timeout=None,
                        close_button=True,
                    )
                    return

                account_row.clear()

                render_account_card("Source Account", "src")
                ui.icon("arrow_forward", size="32px")
                render_account_card("Destination Account", "dst")
                update_continue_btn()

        container = ui.column().classes("w-full items-center gap-8 p-8")
        with container:
            ui.label("Initializing User Directory...").classes("text-grey")
            ui.spinner(size="lg")
            user_list = []
            try:
                assert isinstance(self.src_org, Org)
                user_list = await self.src_org.get_users()
            except MissingAdminSDKError as e:
                self.show_admin_sdk_error(e)
                return
            except Exception as e:
                logging.error(f"Failed to fetch user list! Error: {e}")
                ui.notify(
                    "Failed to fetch user list! Check logs for details.",
                    type="negative",
                    timeout=None,
                    close_button=True,
                )
            container.clear()
            logging.debug(f"User list fetched with {len(user_list)} users")
            ui.label("User Setup").classes("text-h4 font-light")
            ui.label("Search for a user...").classes("text-grey")

            ui.select(
                label="Select User",
                options=sorted(user_list),
                with_input=True,
                on_change=finalize_user_selection,
            ).props("clearable use-input fill-input hide-selected").classes("w-96")

            account_row = ui.row().classes("w-full items-center gap-6 justify-center")
            continue_btn = ui.button(
                "Continue", on_click=lambda: self.go_to(Stage.SINGLE_SETUP_DRIVES)
            ).props("elevated")
            continue_btn.set_enabled(False)

    async def render_single_drive_select(self):
        target_person = self.migrator.targets[0]
        container = ui.column().classes("w-full items-center gap-8 p-8")
        with container:
            ui.label("Loading drives...").classes("text-grey")
            ui.spinner(size="lg")
            try:
                drive_list: list[
                    SharedDrive
                ] = await target_person.generate_drive_list()
            except Exception as e:
                logging.error(f"Failed to fetch drive list: {e}")
                ui.notify(
                    "Failed to fetch drives. Check logs for details.",
                    type="negative",
                    timeout=None,
                    close_button=True,
                )
                container.clear()
                return

            container.clear()
            ui.label("Select Drives to Migrate").classes("text-h4 font-light")
            ui.label(
                "Choose which shared drives to migrate for this user. Toggle drives to exclude them."
            ).classes("text-grey")
            switches: dict = {}
            successors_selects: dict = {}
            migrate_personal_switch = None
            with (
                ui.card().classes("w-full p-4").style("max-height: 50vh; overflow:auto")
            ):
                with ui.row().classes("w-full items-center justify-between"):
                    with ui.column().classes("items-start"):
                        ui.label("Personal Google Drive").classes(
                            "text-md font-medium text-orange-500"
                        )
                    migrate_personal_switch = ui.switch(value=True).props(
                        "color=orange"
                    )
                if not drive_list:
                    ui.label("No shared drives found for this user.").classes(
                        "text-grey"
                    )
                else:
                    for drive in drive_list:
                        if not isinstance(drive, SharedDrive):
                            logging.error(
                                f"Expected SharedDrive instance, got {type(drive)}. Skipping."
                            )
                            continue
                        if drive.migrated and self.user_settings.get(
                            "skip_migrated", True
                        ):
                            logging.info(f"Drive {drive} already migrated, skipping.")
                            continue
                        drive_name = str(drive)
                        drive_id = drive.id

                        with ui.row().classes("w-full items-center justify-between"):
                            with ui.column().classes("items-start"):
                                ui.label(drive_name).classes("text-md font-medium")
                                ui.label(str(drive_id)).classes("text-xs text-grey-500")
                                # If this drive has possible successors, show a dropdown to pick one
                                if drive.possible_successors:
                                    options = [("Create a new drive", None)] + [
                                        (f"{s.name} ({s.id})", s)
                                        for s in drive.possible_successors
                                    ]
                                    successors_selects[drive_id] = (
                                        ui.select(
                                            label="Migrate Into",
                                            options=options,
                                            value=None,
                                        )
                                        .classes("w-64")
                                        .props("clearable")
                                    )
                            switches[drive_id] = ui.switch(value=True)

            # Buttons row
            with ui.row().classes("w-full items-center justify-end gap-4"):

                def handle_continue():
                    selected = []
                    for idx, drive in enumerate(drive_list):
                        drive_id = getattr(drive, "id", None) or f"drive-{idx}"
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
                                logging.error(
                                    f"Failed to set successor for drive {did}: {e}"
                                )

                    personal = (
                        migrate_personal_switch.value
                        if migrate_personal_switch is not None
                        else True
                    )
                    target_person.set_drives(selected)
                    self.migrator.init_migration(personal, self.user_settings)
                    logging.debug(
                        f"Selected drives: {[getattr(d, 'id', str(d)) for d in selected]}"
                    )
                    self.go_to(Stage.SINGLE_PROGRESS)

                ui.button(
                    "Back", on_click=lambda: self.go_to(Stage.SINGLE_SETUP_ACCT)
                ).props("outline color=blue-500")
                ui.button("Continue", on_click=handle_continue).props("elevated")

    def _update_bindable_state(self, state: dict, raw_data: dict) -> dict:
        """
        Computes derived values (percentages, text labels, booleans) and updates
        the reactive state dictionary so the UI bindings update automatically.
        """
        for user, user_data in raw_data.items():
            if user not in state:
                state[user] = {
                    "drives": {},
                    "is_indexing": True,
                    "is_complete": False,
                    "is_idle": False,
                    "time_text": "",
                }

            user_state = state[user]
            for drive, drive_data in user_data.items():
                if drive not in user_state["drives"]:
                    user_state["drives"][drive] = {
                        "name": "Unknown",
                        "status_message": "",
                        "failed_files": [],
                        "has_failures": False,
                        "failure_text": "",
                        "is_indexing": True,
                        "is_complete": False,
                        "is_progressing": False,
                        "progress_text": "0 / 0",
                        "pct": 0.0,
                        "time_text": "",
                        "time_s": 0,
                        "has_time": False,
                    }

                d_state = user_state["drives"][drive]
                d_state["name"] = drive_data.get("name", "Unknown")
                d_state["status_message"] = status = drive_data.get(
                    "status_message", ""
                )
                d_state["failed_files"] = failed = drive_data.get("failed_files", [])

                # Progress Computations
                total = drive_data.get("num_files", 0)
                mig = drive_data.get("num_migrated_files", 0)
                d_state["pct"] = (mig / total) if total > 0 else 0.0
                d_state["progress_text"] = f"{mig:,} / {total:,}"

                time_s = round(drive_data.get("time_remaining", 0))
                d_state["time_s"] = time_s
                d_state["time_text"] = (
                    f"About {str(timedelta(seconds=time_s))} Remaining"
                    if time_s > 1
                    else ""
                )
                d_state["has_time"] = time_s > 1

                # Status Booleans for Visibility Bindings
                d_state["is_indexing"] = "indexing" in status.lower()
                d_state["is_complete"] = "complete" in status.lower()
                d_state["is_progressing"] = (
                    not d_state["is_indexing"] and not d_state["is_complete"]
                )
                d_state["has_failures"] = bool(failed)
                d_state["failure_text"] = f"View {len(failed)} Failures"

            # User-level computed fields (for multi-progress summaries)
            statuses = [
                ds.get("status_message", "") for ds in user_state["drives"].values()
            ]
            user_state["is_indexing"] = any("indexing" in s.lower() for s in statuses)
            user_state["is_working"] = (
                any("in progress" in s.lower() for s in statuses)
                and not user_state["is_indexing"]
            )
            user_state["is_complete"] = all(
                "complete" in s.lower() for s in statuses
            ) and bool(statuses)
            user_state["is_idle"] = (
                not user_state["is_indexing"]
                and not user_state["is_working"]
                and not user_state["is_complete"]
            )
            time_s = round(
                max([ds.get("time_s", 0) for ds in user_state["drives"].values()])
            )
            user_state["time_text"] = (
                f"About {str(timedelta(seconds=time_s))} Remaining"
                if time_s > 1
                else "Estimating time remaining..."
            )
        return state

    def _render_individual_progress(
        self, user_drives_state: dict, error_callback: callable
    ):
        for drive_name, d_state in user_drives_state.items():
            if drive_name == "personal" and not self.migrator.migrate_personal_drive:
                continue

            with (
                ui.card().classes("w-full p-6 shadow-sm"),
                ui.row().classes("w-full items-center justify-between no-wrap"),
            ):
                with ui.column().classes("flex-grow"):
                    ui.label().classes("text-lg font-medium").bind_text_from(
                        d_state, "name"
                    )
                    ui.label().classes("text-xs text-grey-500").bind_text_from(
                        d_state, "status_message"
                    )
                    ui.button(
                        icon="report_problem",
                        # Using default arg `d=d_state` prevents late-binding issues in loops
                        on_click=lambda d=d_state: error_callback(
                            d.get("failed_files", [])
                        ),
                    ).props("flat color=red size=sm").bind_text_from(
                        d_state, "failure_text"
                    ).bind_visibility_from(d_state, "has_failures")

                ui.spinner(size="md", type="gears").classes(
                    "ml-2"
                ).bind_visibility_from(d_state, "is_indexing")

                ui.icon("check_circle", color="green").classes(
                    "text-2xl ml-2"
                ).bind_visibility_from(d_state, "is_complete")

                # Progress Stats
                with (
                    ui.column()
                    .classes("items-end w-48")
                    .bind_visibility_from(d_state, "is_progressing")
                ):
                    ui.label().classes("text-sm font-mono").bind_text_from(
                        d_state, "progress_text"
                    )
                    ui.linear_progress(show_value=False).classes(
                        "w-full h-1.5"
                    ).bind_value_from(d_state, "pct")
                    ui.label().classes("text-xs text-grey-500").bind_text_from(
                        d_state, "time_text"
                    ).bind_visibility_from(d_state, "has_time")

    async def render_single_progress(self):
        container = ui.column().classes("w-full items-center gap-6 p-8")

        # Failed Files Dialog Setup
        with ui.dialog() as error_dialog, ui.card().classes("w-[500px]"):
            ui.label("Failed Files").classes("text-lg font-bold")
            with ui.scroll_area().classes("h-64 border p-2 w-full"):
                error_list_container = ui.column().classes("gap-1")
            ui.button("Close", on_click=error_dialog.close).classes("self-end")

        def show_errors(files):
            error_list_container.clear()
            with error_list_container:
                for f in files:
                    ui.label(str(f)).classes("text-xs text-red-700 font-mono")
            error_dialog.open()

        async def cancel_migration():
            self.migrator.abort()
            ui.notify("Migration Cancelled", type="warning")
            prog_timer.deactivate()

        ui.notify("Initializing migration stats...", type="info")

        raw_data = {}
        for _ in range(15):
            raw_data = self.migrator.poll_progress()
            if raw_data:
                break
            await asyncio.sleep(1.0)

        # Create the initial bindable state dict
        state = self._update_bindable_state({}, raw_data)
        src_name = self.migrator.targets[0].src_user.user_name
        user_state = state.get(src_name, {"drives": {}})

        with container:
            ui.label("Active Migration").classes("text-h4 font-light")
            with ui.column().classes("w-full max-w-4xl gap-4"):
                self._render_individual_progress(
                    user_drives_state=user_state["drives"], error_callback=show_errors
                )

            with ui.row().classes("w-full justify-center"):
                ui.button(
                    "Start Over",
                    on_click=lambda: self.go_to(Stage.SINGLE_SETUP_ACCT),
                    icon="replay",
                ).props("outline color=blue")
                ui.button(
                    "Cancel Migration", on_click=cancel_migration, icon="stop"
                ).props("outline color=red")

        def _tick():
            # Update the underlying dict; bindings auto-update the UI without flickering
            current_data = self.migrator.poll_progress()
            if current_data:
                self._update_bindable_state(state, current_data)

        prog_timer = ui.timer(1.0, _tick)
        res = await self.migrator.perform_migration()
        prog_timer.deactivate()
        _tick()  # Ensure UI reflects 100% completion

        logging.debug(f"Migration completed with result: {res}")
        with container:
            ui.label("Migration Complete!").classes("text-h4 text-green-600")

    async def render_multi_progress(self):
        container = ui.column().classes("w-full items-center gap-6 p-8")

        # Reusable Failed Files Dialog Setup
        with ui.dialog() as error_dialog, ui.card().classes("w-[500px]"):
            ui.label("Failed Files").classes("text-lg font-bold")
            with ui.scroll_area().classes("h-64 border p-2 w-full"):
                error_list_container = ui.column().classes("gap-1")
            ui.button("Close", on_click=error_dialog.close).classes("self-end")

        def show_errors(files):
            error_list_container.clear()
            with error_list_container:
                for f in files:
                    ui.label(str(f)).classes("text-xs text-red-700 font-mono")
            error_dialog.open()

        async def cancel_migration():
            self.migrator.abort()
            ui.notify("Migration Cancelled", type="warning")
            prog_timer.deactivate()

        # Poll for initial payload to establish state definitions
        raw_data = {}
        for _ in range(15):
            raw_data = self.migrator.poll_progress()
            if raw_data:
                break
            await asyncio.sleep(1.0)

        state = self._update_bindable_state({}, raw_data)

        with container:
            ui.label("Active Migration").classes("text-h4 font-light")

            with ui.column().classes("w-full max-w-4xl gap-4"):
                for person in self.migrator.targets:
                    src_name = person.src_user.user_name
                    user_state = state.get(src_name)
                    if not user_state:
                        continue

                    with (
                        ui.card().classes("w-full p-4 shadow-sm"),
                        ui.row().classes("w-full items-center justify-between no-wrap"),
                    ):
                        with ui.column().classes("flex-grow"):
                            ui.label(src_name).classes("text-lg font-medium")
                            ui.label(f"Drives: {len(user_state['drives'])}").classes(
                                "text-xs text-grey-500"
                            )

                        def _make_open_dialog(
                            u_state=user_state, display_name_local=src_name
                        ):
                            async def _open():
                                with (
                                    ui.dialog().classes("max-w-3xl") as dlg,
                                    ui.card().classes("p-4 w-full"),
                                ):
                                    ui.label(
                                        f"Drives for {display_name_local}"
                                    ).classes("text-h6")
                                    with ui.column().classes("w-full gap-3 mt-2"):
                                        self._render_individual_progress(
                                            user_drives_state=u_state["drives"],
                                            error_callback=show_errors,
                                        )
                                    ui.button("Close", on_click=dlg.close).classes(
                                        "self-end mt-4"
                                    )
                                dlg.open()

                            return _open

                        # Data-bound status icons mapped to the user aggregate state
                        # gear state for indexing, normal spinner for working
                        with ui.column().classes("items-center"):
                            ui.spinner(size="md", type="gears").classes(
                                "ml-2"
                            ).bind_visibility_from(user_state, "is_indexing")
                            ui.spinner(size="md").classes("ml-2").bind_visibility_from(
                                user_state, "is_working"
                            )
                            # ui.label().classes("text-xs text-grey-500").bind_text_from(
                            #     user_state, "time_text").bind_visibility_from(user_state, "is_working") # Disabled until I can fix time extimation
                            ui.icon("check_circle", color="green").classes(
                                "text-2xl ml-2"
                            ).bind_visibility_from(user_state, "is_complete")
                            ui.icon("hourglass_empty").classes(
                                "text-2xl ml-2"
                            ).bind_visibility_from(user_state, "is_idle")
                        ui.button("View Drives", on_click=_make_open_dialog()).props(
                            "flat"
                        )

            with ui.row().classes("w-full justify-center"):
                ui.button(
                    "Start Over",
                    on_click=lambda: self.go_to(Stage.BATCH_SETUP),
                    icon="replay",
                ).props("outline color=blue")
                ui.button(
                    "Cancel Migration", on_click=cancel_migration, icon="stop"
                ).props("outline color=red")

        def _tick():
            current_data = self.migrator.poll_progress()
            if current_data:
                self._update_bindable_state(state, current_data)

        prog_timer = ui.timer(1.0, _tick)
        res = await self.migrator.perform_migration()
        prog_timer.deactivate()
        _tick()

        logging.debug(f"Batch migration completed with result: {res}")
        with container:
            ui.label("Batch Migration Complete!").classes("text-h4 text-green-600")

    async def render_multi_setup(self):
        user_data: list[dict] = []
        is_working = False
        options = {"personal": True, "shared": True}

        async def ingest_csv(evt: events.UploadEventArguments):
            nonlocal is_working, user_data
            is_working = True
            ui_container.refresh()
            file = await evt.file.read()
            raw = BytesIO(file)
            match evt.file.content_type:
                case (
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                ):
                    user_dataframe = pd.read_excel(raw)
                case "text/csv":
                    user_dataframe = pd.read_csv(raw)
                case "application/json":
                    user_dataframe = pd.read_json(raw)
                case _:
                    logging.warning(f"Got unknown file type {evt.file.content_type}")
            logging.debug(f"Ingested DF\n{user_dataframe}")
            rows, cols = user_dataframe.shape
            if cols != 2:
                logging.warning(
                    f"Expected exacly 2 columns, got {cols}. Rejecting file"
                )
                ui.notify("Expected exacly 2 columns, got {cols}.", type="warning")
                self.go_to(Stage.BATCH_SETUP)
                return
            user_dataframe.columns = ["src", "dst"]  # override names for consistency
            user_dataframe = user_dataframe.map(
                lambda x: x.strip() if isinstance(x, str) else x
            )
            dat = user_dataframe.to_dict(orient="records")
            lookup_tasks = []
            for entry in dat:
                entry["src_user"] = asyncio.create_task(
                    self.src_org.find_user_by_email(entry["src"])
                )
                lookup_tasks.append(entry["src_user"])
                entry["dst_user"] = asyncio.create_task(
                    self.dst_org.find_user_by_email(entry["dst"])
                )
                lookup_tasks.append(entry["dst_user"])
            await asyncio.gather(*lookup_tasks, return_exceptions=True)
            for entry in dat:
                src = entry.pop("src_user").result()
                dst = entry.pop("dst_user").result()
                if isinstance(src, User) and isinstance(dst, User):
                    self.migrator.add_target(src, dst)
                    entry["status"] = "OK"
                else:
                    entry["status"] = "Error"
                    logging.error(f"Failure to init {entry}, got results {src}, {dst}")

            is_working = False
            user_data = dat
            ui_container.refresh()

        @ui.refreshable
        async def ui_container():
            container = ui.card(align_items="center").classes("w-full")
            container.clear()
            with container:
                if is_working:
                    ui.spinner(size="lg")
                elif len(user_data):
                    with ui.card().classes("w-full p-6 shadow-sm"):
                        ui.aggrid(
                            {
                                "columnDefs": [
                                    {"headerName": "Source User", "field": "src"},
                                    {"headerName": "Destination User", "field": "dst"},
                                    {
                                        "headerName": "Status",
                                        "field": "status",
                                        "cellClassRules": {
                                            "bg-red-800": 'x == "Error"',
                                            "bg-green-800": 'x == "OK"',
                                        },
                                    },
                                ],
                                "rowData": user_data,
                            }
                        )
                else:
                    ui.upload(
                        label="Accounts File",
                        auto_upload=True,
                        on_upload=ingest_csv,
                    ).props('flat bordered accept=".csv,.xlsx,.json"')
                    ui.label(
                        "Upload a file listing source and destination accounts. Acceptable formats are: Excel, CSV, and json."
                    ).classes("text-xs text-grey-500")

        async def handle_continue():
            nonlocal is_working, options, user_data
            is_working = True
            ui_container.refresh()
            if options.get("shared"):
                tasks = []
                for person in self.migrator.targets:
                    tasks.append(asyncio.create_task(person.generate_drive_list(True)))
                await asyncio.gather(*tasks)
            self.migrator.init_migration(options.get("personal"), self.user_settings)
            self.go_to(Stage.BATCH_PROGRESS)

        with ui.column().classes("w-full items-center gap-6 p-8"):
            ui.label("User Setup").classes("text-h4 font-light")
            await ui_container()
            with ui.card(align_items="center"):
                with ui.row().classes("w-full items-center justify-center gap-4"):
                    ui.switch("Personal Drives").bind_value(options, "personal")
                    ui.switch("Team Drives").bind_value(options, "shared")
                with ui.row().classes("w-full items-center justify-center gap-4"):
                    ui.button(
                        "Back", on_click=lambda: self.go_to(Stage.MODE_SELECT)
                    ).props("outline color=blue-500")
                    ui.button("Continue", on_click=handle_continue).props("elevated")

    # ----- Auth Specific Helpers ------

    async def ingest_keyfile(self, e: events.UploadEventArguments, is_src: bool):
        file = await e.file.json()
        try:
            tmp = Org(file)
        except ValueError as err:
            ui.notify(
                "Invalid keyfile. Please try again.",
                type="negative",
                timeout=None,
                close_button=True,
            )
            logging.warning(f"Ingest keyfile failed! {err}")
            return
        except KeyError as err:
            ui.notify(
                "Keyfile is malformed!",
                type="negative",
                timeout=None,
                close_button=True,
            )
            logging.warning(f"Rejected keyfile due to {err}")
        if is_src:
            self.src_org = tmp
            try:
                self.src_org.set_admin(self.src_domain_admin)
            except ValueError as err:
                ui.notify(
                    "Domain setup failed! Did you use the correct keyfile?",
                    type="negative",
                    timeout=None,
                    close_button=True,
                )
                logging.warning(f"Set source domain failed! Error: {err}")
                self.src_org = None
                self.src_domain_admin = ""
        else:
            self.dst_org = tmp
            try:
                self.dst_org.set_admin(self.dst_domain_admin)
            except ValueError as err:
                ui.notify(
                    "Invalid domain! Check domain format and try again.",
                    type="negative",
                    timeout=None,
                    close_button=True,
                )
                logging.warning(f"Set destination domain failed! Error: {err}")
                self.dst_org = None
                self.dst_domain_admin = ""

        await self.router.refresh()

    def __render_auth_inner(self, is_src: bool):
        current_file = self.src_org if is_src else self.dst_org
        card_classes = "w-96 p-4 transition-all "
        card_classes += (
            "border-2 border-green-500 bg-green-50 dark:border-green-700 dark:bg-green-900/30"
            if current_file
            else "border border-gray-200 dark:border-gray-700"
        )

        def set_temp_domain_admin(changedval):
            domain = changedval.value.strip()
            if is_src:
                self.src_domain_admin = domain
            else:
                self.dst_domain_admin = domain
            # check each is unique
            if (
                self.src_domain_admin == self.dst_domain_admin
                and self.src_domain_admin != ""
            ):
                ui.notify(
                    "Source and Destination domains must be different!",
                    type="negative",
                    timeout=None,
                    close_button=True,
                )

        with (
            ui.card().classes(card_classes).style("min-height: 180px"),
            ui.column().classes("w-full items-center justify-center h-full"),
        ):
            if current_file:
                # SUCCESS STATE
                ui.icon("check_circle", color="positive").classes("text-5xl")
                ui.label(
                    f"{self.src_domain_admin if is_src else self.dst_domain_admin} ready"
                ).classes("text-bold text-green-700")
                ui.button(
                    "Change", on_click=lambda: self.__clear_auth_file(is_src)
                ).props("flat dense")
            else:
                # UPLOAD STATE
                ui.label(
                    f"{'Source' if is_src else 'Destination'} Organization"
                ).classes("text-lg font-medium")
                domain_input = (
                    ui.input(
                        label="Admin Account",
                        placeholder="itdept@example.org",
                        on_change=set_temp_domain_admin,
                        value=(
                            self.src_domain_admin if is_src else self.dst_domain_admin
                        ),
                    )
                    .classes("w-full")
                    .props("debounce=100")
                )
                ui.upload(
                    label="Select JSON keyfile",
                    auto_upload=True,
                    on_upload=lambda e: self.ingest_keyfile(e, is_src),
                ).props("flat bordered").props("accept=.json").classes(
                    "w-full"
                ).bind_enabled_from(
                    domain_input,
                    "value",
                    backward=lambda v: len(v) > 5 and v.count("."),
                )

    def __is_auth_configured(self) -> bool:
        if not isinstance(self.src_org, Org) or not isinstance(self.dst_org, Org):
            return False
        if self.dst_org.id == self.src_org.id:
            logging.warning(
                f"JSON Keyfiles are identical! {self.dst_org.id}, {self.src_org.id}"
            )
            ui.notify(
                "Same key was uploaded twice. Are you sure you meant to do that?",
                type="warning",
            )
            # theoretically same gcloud account could control both domains, don't error
        return self.dst_domain_admin is not None and self.src_domain_admin is not None

    def __clear_auth_file(self, is_src: bool):
        if is_src:
            self.src_org = None
        else:
            self.dst_org = None
        self.router.refresh()


with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".log") as tmp:
    log_path = tmp.name

    # 2. Configure logging to use the temp file path
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        filename=log_path,
        filemode="w",
        force=True,
    )
logging.getLogger("nicegui").setLevel(logging.WARNING)


def check_github_new_version() -> bool:
    try:
        res = requests.get(
            "https://api.github.com/repos/Region1-IT-Projects/Shared-Drive-Migrator/releases/latest"
        )
    except requests.exceptions.HTTPError:
        logging.warning("Failed to check for new version on GitHub.")
        return False
    if res.status_code == 200:
        latest_version = res.json().get("tag_name", "")
        if latest_version and latest_version > VERSION:
            return True
    return False


@ui.page("/", title="Drive Migration Wizard")
async def main_view():
    await ui.context.client.connected()
    session = Session()
    session.render_header()
    await session.router()
    session.footer_shell()
    if check_github_new_version():
        ui.notify(
            "A new version of the Drive Migration Wizard is available! Check the GitHub releases page for details.",
            type="info",
            timeout=10000,
            close_button=True,
        )


if __name__ in {"__main__", "__mp_main__"}:
    # don't fork bomb in pyinstaller version
    multiprocessing.freeze_support()
    try:
        ui.run(
            storage_secret="supersecret",
            reload=False,
            native=False,
            favicon=get_icon_base64(),
            host="127.0.0.1",
        )
    except KeyboardInterrupt:
        logging.info("Goodbye")
        app.shutdown()
    except Exception as e:
        logging.error(f"Process failed: {e}")
        # keep the script window open on a crash for diagnosis
        # (mostly for pyinstaller - packaged variants)
        while True:
            pass
