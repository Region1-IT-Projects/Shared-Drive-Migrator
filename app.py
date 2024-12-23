from flask import Flask, render_template, flash, request, redirect, url_for
from migrator import *
import tempfile
import traceback

app = Flask(__name__)  # Flask constructor
app.secret_key = 'changeme'
app.debug = True
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
        flash("User creation failed. Please try again.")
    return render_template('migrate-user.html', next_page="/migrate/user/drives/")


@app.route('/migrate/user/drives/')
def migrate_user_drives():
    if len(mig.users) == 0:
        flash("Please enter user information first.")
        return redirect(url_for('migrate_user'))
    user = mig.users[-1]
    return render_template('user-drives.html', name=user.src.address.split("@")[0], drives=user.get_owned_team_drives())


@app.errorhandler(500)
def handle_internal_error(e):
    trace = traceback.format_exc()
    return render_template('show-err.html', err=trace[trace.rindex("File "):]), 500


if __name__ == '__main__':
    app.run()
