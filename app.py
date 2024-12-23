from flask import Flask, render_template, flash, request, redirect, url_for
from migrator import *
import tempfile
import traceback
app = Flask(__name__)  # Flask constructor
# globals
mig = Migrator()
@app.route('/')
def hello():
    return render_template("index.html")

@app.route('/setup/<stage>/', methods = ['POST', 'GET'])
def setup(stage: str):
    if request.method == 'POST':
        # handle file upload
        tmp = tempfile.NamedTemporaryFile(delete=False)
        request.files['file'].save(tmp.name)
        print("saved file to", tmp.name)
        if stage == "source":
            mig.set_src_creds(tmp.name)
        else :
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

@app.route('/migrate/user/', methods = ['GET','POST'])
def migrate_user():
    if request.method == 'POST':
        return redirect(url_for('modeselect'))
    else:
        return render_template('migrate-user.html')

@app.errorhandler(500)
def handle_internal_error(e):
    trace = traceback.format_exc()
    return render_template('show-err.html', err=trace[trace.rindex("File "):]), 500

if __name__ == '__main__':
    app.run()