# Google Drive Workspace-to-Workspace Migration Wizard

![Project Logo](images/icon-small.png)

An easy-to-use python script that automatically copies drives from one Google Workspace domain to another via the Google Drive API.

## Features

- Copies users' personal drives and shared ('team') drives
- Guided single-user transfer or automated batch mode 
- Resumable transfers
- Browser-based UI
- Robust error handling and reporting 

## Important Caveats

This software only migrates **owned** drives and files. Therefore, only drives of which the source user is an *Organizer* and files of which the user is an *Owner* will be copied.

The migration process also *does not* preserve permissions. Upon migration, only the Owner / Organizer will have access to the copied assets and must re-share them with any who need access in the new organization. This is a security measure, to make the users consider who needs access to what and reduce unneeded access. 
<!-- Also bc thats a lot more work lmao -->


## Running

This software is designed to be run locally on a user's computer. It could theoretically be deployed as a webserver but do so at your own risk.

Upon launching this script, it will open its UI in your default browser. This project is tested on Chromium 145 but should work on just about anything that can run JavaScript.

### From Source

Users can run this project directly if they have Python 3.11+ installed.

This project is managed with `uv`. Assuming you have it installed, simply clone this repository and run:
```bash
uv run src/main.py
```
It will take care of installing dependencies and you'll be up and running.

*Or, you could install the deps listed in `pyproject.toml` manually like a caveman*

### Pre-built Binaries

For ease of use, this program is also distributed as precompiled binaries for x86-64 Linux and Windows targets. These binaries can be found in the GitHub [Releases](https://github.com/Region1-IT-Projects/Shared-Drive-Migrator/releases). These are generated automatically with pyinstaller via GitHub CI.

## Usage

### Prerequisites

This program relies on Google Cloud Platform service accounts that have domain-wide delegation for the following permissions:
- https://www.googleapis.com/auth/drive
- https://www.googleapis.com/auth/admin.directory.user.readonly

Refer to Google's [documentation](https://developers.google.com/identity/protocols/oauth2/service-account#creatinganaccount) for instructions.

Each domain involved in a migration requires its own service account, configured as specified above.

Service accounts are accessed with a keyfile. You have the service accounts' JSON keyfiles downloaded to your computer to use this program.

> [!CAUTION]
> Service accounts are very powerful and by their nature do not have 2FA. Anyone who has access to an account's keyfile can impersonate any user in the domain and take actions in Google Drive as them. Keep tight control over these keyfiles and disable the service accounts when not in use!

### General Usage

An important element of the UI is the API information in the lower left corner of the page. This lists the number of requests the program has made to Google, the number of errors, backoff time, and average response time. This metric serves as an easy way to tell if something has gone wrong. If the UI does not seem to be doing anything (just sitting at a spinner), watch the request count. If it is increasing, things are still going well. Additionally, the backoff time indicates how long the migrator will wait before trying another request. To avoid issues with API rate limits, the migrator will automatically slow itself down when it starts getting Error responses from Google.

Another element to note is the settings button in the upper right. This allows you to toggle dark mode as well as enable the fallback migration mode and set behavior for already-migrated files. See [Feature Descriptions](#feature-descriptions) for details.

### Authentication Setup

When you launch the wizard, you will be prompted to configure access to your source and destination organizations (domains). This consists of:
- The email address of a domain administrator
- The JSON Keyfile for the domain's service account

The email of a domain administrator is required for the program to be able to look up users in the directory. This does not have to be the super-admin or the address of the person performing the migration. No actions will be taken with this account other than listing users.

Once this is configured, click continue to proceed to mode selection.

### Single User Mode

Single-user mode allows you to search for a user by name. The program will attempt to find their account in both organizations. If it fails (such as if the user is named "Mike" in one organization and "Michael" in the other), it will prompt you to set the address manually.

After doing so, you may select which of the user's drives to migrate.

The program will display each of the selected drives along with their status. Each drive must first be indexed before it can be migrated. Once indexing finishes, the migrator will show the drive's progress and estimated time to completion.

Should any files fail to migrate, a red button labeled "View n Failures" will appear on the drive's list entry. Clicking this will show a list of the files that failed so that manual action can be taken.

### Bulk Migration Mode

Bulk mode allows for migrating many users at once. It is configured by uploading a file listing the email addresses of the source and destination accounts involved in the migration. This file may be an Excel spreadsheet, CSV, or json and must be of the following format:

| Source User | Destination User |
| ----------- | ---------------- |
| jdoe@example.org | doe.jane@example.com |
| rdebank@example.org | debank.robin@example.com |

Should an entry in this file not be valid, it will be marked as "Error" in the UI and migration will proceed with all other users.

This mode does not allow for individual drive selection, but the user may choose to disable migration of all personal drives or all shared drives.

Once migration is started, the wizard will display a list of the selected users with an icon, which will be one of the following:
- Spinning gears: one or more drives owned by the user is indexing
- Circular spinner: all drives are indexed, one or more drives is being copied
- Green Checkmark: all drives have been migrated

To the right of the spinner is a button to view the detailed progress of the user's drives. This is the same interface as is shown for single user mode. 

## Feature Descriptions

### Fallback Migration Mode

In testing, it has been observed that some files refuse to migrate the standard way as described [below](#principle-of-operation). The migrator supports a fallback mode where it will download the problematic file to the local machine and upload it into the new organization.

This behavior is disabled by default but can be enabled in the options menu. When enabled, the user may set the maximum size of a file to be downloaded (default 500MB). These files are not saved to disk and only exist in RAM. Increasing this limit may cause memory exhaustion.

When enabled, this fallback mode only engages when a file fails to be migrated via the normal method. 

> [!NOTE]
> Google files (docs, sheets, slides, etc...) cannot be downloaded in their native format. As such, they are converted to the Microsoft Office equivalent during the migration. This may break formatting.

### Migrated Object Handling

When the migrator finishes migrating a shared drive, it will append ` - Migrated` to the drive's name to indicate the fact it has migrated to the user. On top of this, the migrator invisibly add a *property* to every file and folder it copies, indicating that it has been copied and the ID of the new version. 

By default, the migrator will skip any file, folder, or drive that has been marked as migrated. This allows the migrator to resume where it left off if it dies in the middle of a migration. 

Sometimes, this behavior is undesirable. Switching "Skip already-migrated files" off in the settings dialog will make the migrator copy everything, regardless if it has already been marked as migrated.

## Principle of Operation

This program operates on a relatively simple process:
1. Create a new shared drive (or personal folder) in the destination domain
2. Share every file in the old domain to the destination user account
3. As the destination user, make a copy of every shared file and place it in the new folder
4. Mark every copied file, folder, and drive as migrated
5. Unshare all of the previously shared files
6. Profit

Rather than requiring each user to sign in to this wizard, we use service accounts with [domain-wide delegation](https://support.google.com/a/answer/162106?hl=en) to impersonate each user and perform the migration on their behalf.