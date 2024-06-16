# Team Drive Workspace-to-Workspace Migrator

This program automatically migrates files between Google Workspace team drives from one organization to another.

## Setup

Before this script can be used, both Google Workspaces must be configured to grant it full access to the organizations' drives. Follow the instructions listed in https://developers.google.com/identity/protocols/oauth2/service-account. Ensure that the Google Drive API is enabled for your project.

When prompted for the scopes for the API client in the Google Admin interface, enter `https://www.googleapis.com/auth/admin.directory.user.readonly` and `https://www.googleapis.com/auth/drive`.
The interface will instruct you to enter the scopes comma-separated. This is not correct and will not work. Once you enter the first scope, another input field will appear for you to enter the other scope.

## Usage

```
python migrator.py source_credentials.json destination_credentials.json [options]
```

**Arguments:**

* `source_credentials.json`: Path to the JSON file containing the OAuth2 credentials for the source organization.
* `destination_credentials.json`: Path to the JSON file containing the OAuth2 credentials for the destination organization.
* `[options]`: (Optional) Command-line options to customize the migration process.

**Options:**

* `-i`, `--INTERACTIVE`: Interactive mode where the user enters the source and destination email addresses.
* `-a`, `--automatic <csv_file>`: Automatic mode where user information is read from a CSV file.
* `-y`, `--yes`: Assumes Yes for all confirmations.
* `-v`, `--verbose`: print more information.

**Example:**

```
python migrator.py source_credentials.json destination_credentials.json -a users.csv -v
```
### Automatic Mode
To bulk-migrate shared drives owned by multiple users:
1. Create a CSV file with the following format:

```
source_email,destination_email
user1@example.com,user1@newexample.com
user2@example.com,user2@newexample.com
```
2. Specify the CSV file path as an argument:

```
python migrator.py source_credentials.json destination_credentials.json -a users.csv
```

## Requirements

* Python 3.11 +
* Google OAuth2 client library for Python
* CSV library

## Features

* Migrates files between two Google Workspace organizations.
* Supports both interactive and automatic mode.
* Detects and handles deadlocks during file migration.
* Provides progress information during the migration process.

## Dependency Installation

```
pip install --upgrade google-api-python-client oauth2client
```

## Notes

* The program requires OAuth2 credentials for both the source and destination organizations.
* The migration process is slow. Each call to the Google API can take up to 30 seconds, and migration of a single drive can take several hours.
* If the program appears to hang, this is probably due to an API call taking a long time. Only kill the program if it doesn't respond in over a minute.


## Security Implications
You must always ensure strict controls on the `credentials.json` files as these are the keys to full read/write access to all drives in 
your domain and pose a massive threat if compromised. As soon as you are finished with migration,
disable this program's API access in **both** domains' Google Admin pages, and disable the service accounts in
the Google Cloud console. 

Let me re-iterate, the service accounts for this program have 'super-admin' privileges for Google Drive and can impersonate
any user in your domain. Treat them with care.