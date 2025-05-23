# Team Drive Workspace-to-Workspace Migrator

This program automatically migrates files between Google Workspace team drives from one organization to another.

## Setup

Before this script can be used, both Google Workspaces must be configured to grant it full access to the organizations' drives. Follow the instructions listed in https://developers.google.com/identity/protocols/oauth2/service-account. Ensure that the Google Drive API is enabled for your project.

When prompted for the scopes for the API client in the Google Admin interface, enter `https://www.googleapis.com/auth/admin.directory.user.readonly` and `https://www.googleapis.com/auth/drive`.
The interface will instruct you to enter the scopes comma-separated. This is not correct and will not work. Once you enter the first scope, another input field will appear for you to enter the other scope.

### Python (Direct)
1. Clone the repository:
   ```bash
   git clone https://github.com/Region1-IT-Projects/Shared-Drive-Migrator
   ```
2. Change into the directory:
   ```bash
    cd Shared-Drive-Migrator
    ```
3. Install the required libraries:
4. (Optional) Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```
5. Install the required libraries:
   ```bash
   pip install -r requirements.txt
   ``` 
### onefile executable
1. Download the latest release from the [Releases page](https://github.com/Region1-IT-Projects/Shared-Drive-Migrator/releases).
2. Run it!


## Usage

### Python (Direct)
```bash
python app.py
```
### onefile executable
```bash
./SharedDriveMigrator
```
or for Windows:
```bash
SharedDriveMigrator.exe
```

This should automatically open a browser window to the locally running web server. If it doesn't, you can manually navigate to http://localhost:5000 in your browser.


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