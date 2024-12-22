from flask import Flask, render_template, flash, request, redirect, url_for
from migrator import *
import tempfile
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
        return "File uploaded successfully", 200
        
    else:
        if stage == "source":
            next_page = "/setup/destination"
        else:
            next_page = "google.com"
        return render_template("setup.html", stage=stage, nextpage=next_page)

if __name__ == '__main__':
    app.run()