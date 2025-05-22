import logging
from flask import Flask, render_template, flash, request, redirect, url_for
from migrator import *
import tempfile
import traceback
import threading
app = Flask(__name__)  # Flask constructor
# logging.getLogger('werkzeug').addHandler(logging.NullHandler())
app.secret_key = 'changeme'
# globals
mig = Migrator()

@app.route('/')
def hello():
    return render_template("index.html")


@app.route('/setup/<stage>/', methods=['POST', 'GET'])
def setup(stage: str):
    if request.method == 'POST':
        # handle file upload
        tmp = tempfile.NamedTemporaryFile(delete=False)
        request.files['file'].save(tmp.name)
        print("saved file to", tmp.name)
        if stage == "source":
            mig.set_src_creds(tmp.name)
        else:
            mig.set_dst_creds(tmp.name)
        return "File uploaded successfully", 200

    else:
        if stage == "source":
            next_page = "/setup/destination"
        else:
            next_page = "/modeselect"
        return render_template("setup.html", stage=stage, nextpage=next_page)


@app.route('/modeselect/')
def modeselect():
    return render_template("modes.html")


@app.route('/migrate/user/', methods=['GET', 'POST'])
def migrate_user():
    if mig.src_creds is None or mig.dst_creds is None:
        flash("Please setup source and destination credentials.")
        return redirect(url_for('setup', stage="source"))
    if request.method == 'POST':
        src_user = request.form['source']
        dst_user = request.form['destination']
        if mig.create_user(src_user, dst_user) is not None:
            return "OK", 200
        flash("Failed to acquire user credentials. Please try again.")
    return render_template('migrate-user.html', next_page="/migrate/user/drives/")


@app.route('/migrate/user/drives/', methods=['GET', 'POST'])
def migrate_user_drives():
    if len(mig.users) == 0:
        flash("Please enter user information first.")
        return redirect(url_for('migrate_user'))
    user = mig.users[-1]
    if request.method == 'POST':
        if isinstance(request.json, dict):
            if request.json['personal']:
                #threading.Thread(target=user.migrate_personal_files, args=()).start()
                user.migrate_personal_files()
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
                thread = threading.Thread(target=user.migrate_drive, args=(drive, dst))
                thread.start()
                drive.migrator_thread = thread
            return "OK", 200
        else:
            return "BAD REQUEST FORMAT (not JSON)", 400
    else:
        return render_template('user-drives.html', name=user.src.address.split("@")[0].title(), drives=user.get_owned_team_drives())

@app.route('/migrate/progress/<drive_id>/')
def migrate_progress(drive_id):
    for user in mig.users:
        for drive in user.drives:
            if drive.id == drive_id:
                if len(drive.files) != 0 and not drive.migrator_thread.is_alive():
                    return "Migrator Thread Crashed", 500
                return "{}/{}".format((drive.file_count-len(drive.files)), drive.file_count), 200
    return "NOT FOUND", 404

@app.route('/migrate/success/')
def migrate_success():
    flash("Migration completed successfully.")
    return redirect(url_for('modeselect'))

@app.errorhandler(500)
def handle_internal_error(e):
    trace = traceback.format_exc()
    return render_template('show-err.html', err=trace[trace.rindex("File "):]), 500


if __name__ == '__main__':
    app.run()
