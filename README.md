# Shared-Drive-Migrator
Migrate Shared drives from one Google Workspace to another

## Setup

Before this script can be used, both Google Workspaces must be configured to grant it full access to the organizations' drives. Follow the instructions listed in https://developers.google.com/identity/protocols/oauth2/service-account. Ensure that the Google Drive API is enabled for your project.

When prompted for the scopes for the API client in the Google Admin interface, enter `https://www.googleapis.com/auth/admin.directory.user.readonly` and `https://www.googleapis.com/auth/drive`.
The interface will instruct you to enter the scopes comma-separated. This is not correct and will not work. Once you enter the first scope, another input field will appear for you to enter the other scope.
