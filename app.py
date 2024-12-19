from flask import Flask, render_template, flash, request, redirect, url_for

app = Flask(__name__)  # Flask constructor

@app.route('/')
def hello():
    return render_template("index.html")

@app.route('/setup/<stage>/', methods = ['POST', 'GET'])
def setup(stage: str):
    if request.method == 'POST':
        # handle file upload
        print("Got: ", request.files)
        return "File uploaded successfully", 200
        
    else:
        if stage == "source":
            next_page = "/setup/destination"
        else:
            next_page = "google.com"
        return render_template("setup.html", stage=stage, nextpage=next_page)

if __name__ == '__main__':
    app.run()