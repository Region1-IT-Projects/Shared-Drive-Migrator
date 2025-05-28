VERSION = "2.1.1"
import json
import logging

import requests
from flask import Flask, render_template, flash, request, redirect, url_for
from migrator import *
import tempfile
import traceback
import threading
import time
import os
import webbrowser
app = Flask(__name__)  # Flask constructor
logging.getLogger('werkzeug').addHandler(logging.NullHandler())
app.secret_key = 'supersecret'
# globals
mig = Migrator()
tempfiles = []
bulkMigration: BulkMigration | None = None
cur_user: User | None = None
do_update_warning = False

@app.route('/')
def hello():
    global do_update_warning
    if do_update_warning:
        flash("This software is not up to date! Please download the latest from <a href=https://github.com/Region1-IT-Projects/Shared-Drive-Migrator/releases/latest>github</a>.")
        do_update_warning = False
    return render_template("index.html")


@app.route('/setup/<stage>/', methods=['POST', 'GET'])
def setup(stage: str):
    if request.method == 'POST':
        # handle file upload
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tempfiles.append(tmp.name)
        request.files['file'].save(tmp.name)
        if stage == "source":
            mig.set_src_creds(tmp.name)
        else:
            mig.set_dst_creds(tmp.name)
        return "File uploaded successfully", 200

    else:
        if stage == "source":
            next_page = "/setup/destination"
        else:
            next_page = url_for("modeselect")
        return render_template("setup.html", stage=stage, nextpage=next_page)


@app.route('/modeselect/')
def modeselect():
    return render_template("modes.html")

@app.route('/migrate/bulk/', methods=['GET', 'POST'])
def migrate_bulk():
    global bulkMigration
    if mig.src_creds is None or mig.dst_creds is None:
        flash("Please setup source and destination credentials.")
        return redirect(url_for('setup', stage="source"))
    if request.method == 'POST':
        # save CSV file to temporary file
        tmp = tempfile.NamedTemporaryFile(delete=False)
        request.files['file'].save(tmp.name)
        cbdata = json.loads(request.form.get('checkboxData', '{}'))
        skip_moved = cbdata.get('skip_moved', 'false')
        migrate_personal = cbdata.get('do_personal', 'false')
        migrate_shared = cbdata.get('do_shared', 'false')
        if bulkMigration is not None:
            print("Error: Bulk migration already in progress!")
            flash("Bulk migration already in progress!")
            return "Error: Bulk migration already in progress!", 400
        try:
            bulkMigration = BulkMigration(tmp.name, mig, bool(skip_moved), bool(migrate_personal), bool(migrate_shared))
        except Exception as e:
            flash(f"Error processing CSV file: {str(e)}")
            print("Error processing CSV file:", e)
            bulkMigration = None
            return redirect(url_for('migrate_bulk'))
        bulkMigration.start_migration()
        return "OK", 200
    return render_template('migrate-bulk.html', nextpage="/migrate/bulk/progress/")

@app.route('/migrate/bulk/progress/', methods=['GET'])
def migrate_bulk_progress():
    if not isinstance(bulkMigration, BulkMigration):
        flash("No bulk migration in progress! ({})".format(bulkMigration))
        return redirect(url_for('migrate_bulk'))
    else:
        return render_template('bulk-progress.html')

@app.route('/migrate/bulk/progress/internal', methods=['GET'])
def migrate_bulk_progress_internal():
    if not isinstance(bulkMigration, BulkMigration):
        return "No bulk migration in progress", 404
    progress = bulkMigration.get_progress()
    if progress is None:
        return "No progress data available", 404
    # return progress as JSON
    return json.dumps(progress), 200, {'Content-Type': 'application/json'}


@app.route('/migrate/user/', methods=['GET', 'POST'])
def migrate_user():
    global cur_user
    if mig.src_creds is None or mig.dst_creds is None:
        flash("Please setup source and destination credentials.")
        return redirect(url_for('setup', stage="source"))
    if request.method == 'POST':
        src_user = request.form['source']
        dst_user = request.form['destination']
        cur_user = mig.create_user(src_user, dst_user)
        if cur_user is not None:
            return "OK", 200
        flash("Invalid user credentials. Please try again.")
    return render_template('migrate-user.html', next_page="/migrate/user/drives/")


@app.route('/migrate/user/drives/', methods=['GET', 'POST'])
def migrate_user_drives():
    if not isinstance(cur_user, User):
        flash("Please enter user information first.")
        return redirect(url_for('migrate_user'))
    user: User = cur_user
    if request.method == 'POST':
        if isinstance(request.json, dict):
            if request.json['personal']:
                # threading.Thread(target=user.migrate_personal_files, args=([bool(request.json['skip_moved'])])).start()
                user.migrate_personal_files(bool(request.json['skip_moved']))
                flash("Personal files migration finished, moving to team drives.")
            to_migrate = []
            for i in user.drives:
                if request.json[i.id+"-domigrate"]: 
                    to_migrate.append(i)
            for drive in to_migrate:
                if drive.migrator_thread is not None:
                    if drive.migrator_thread.is_alive():
                        flash ("A task to migrate Drive {} is already running!".format(drive.name))
                        continue
                dst = user.prepare_team_drive_for_migrate(drive)
                thread = threading.Thread(target=user.migrate_drive, args=(drive, bool(request.json['skip_moved']), dst))
                thread.start()
                drive.migrator_thread = thread
            return "OK", 200
        else:
            return "BAD REQUEST FORMAT (not JSON)", 400
    else:
        return render_template('user-drives.html', name=user.src.address.split("@")[0].title(), drives=user.get_owned_team_drives())

@app.route('/migrate/progress/<drive_id>/')
def migrate_progress(drive_id):
    if cur_user is User:
        for drive in cur_user.drives:
            if drive.id == drive_id:
                if len(drive.files) != 0 and not drive.migrator_thread.is_alive():
                    return "Migrator Thread Crashed", 500
                return "{}/{}".format((drive.file_count-len(drive.files)), drive.file_count), 200
    return "NOT FOUND", 404

@app.route('/migrate/success/')
def migrate_success():
    flash("Migration completed successfully.")
    return redirect(url_for('migrate_user'))

@app.errorhandler(500)
def handle_internal_error(e):
    trace = traceback.format_exc()
    return render_template('show-err.html', err=trace[trace.rindex("File "):]), 500


def open_browser():
    time.sleep(1)  # Give the server time to start
    print("Opening browser to http://127.0.0.1:5000/")
    webbrowser.open_new("http://127.0.0.1:5000/")

def get_latest_release_tag(repo):
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    response = requests.get(url)
    response.raise_for_status()
    return response.json()["tag_name"]


if __name__ == '__main__':
    try:
        latest_ver = get_latest_release_tag("Region1-IT-Projects/Shared-Drive-Migrator")
    except requests.exceptions.HTTPError:
        print("WARNING: unable to get latest software version!")
    else:
        if latest_ver.strip().lower() != VERSION.lower():
            print("\n\n")
            print("YOU ARE NOT RUNNING THE LATEST SOFTWARE VERSION".center(os.get_terminal_size().columns,'='))
            print("Latest version: {} | Current version: {}".format(latest_ver, VERSION).center(os.get_terminal_size().columns,' '))
            print("Download latest from https://github.com/Region1-IT-Projects/Shared-Drive-Migrator/releases/latest".center(os.get_terminal_size().columns,' '))
            print("\n\n")
            do_update_warning = True
    threading.Thread(target=open_browser).start()
    try:
        app.run(host="127.0.0.1", port=5000, debug=False)
    except KeyboardInterrupt:
        print("Server stopped by user.")
        # Clean up temporary files on exit
    for tmp in tempfiles:
        try:
            os.remove(tmp)
        except Exception as e:
            print(f"Error removing temporary file {tmp}: {e}")
    print("\nThanks for using Drive Migrator!")