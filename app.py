import os
import rfc_classifier
import table

from flask import Flask
from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for
from flask import jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_FOLDER= '/files'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif','py'])
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/result')
def result():
    	
	urlname  = request.args['name']
	res  =  rfc_classifier.getResult(urlname)
	return jsonify(res)  # passes a list as argument
    	
@app.route('/details')
def details():
	
	urlname  = request.args['name']
	tab=table.getDetails(urlname)
	return jsonify(tab)

@app.route('/features')
def features():
    	return render_template('features.html')

@app.route('/', methods = ['GET', 'POST'])

def hello():
	
	if request.method == 'POST':
		if 'file' not in request.files:
			flash('no file part')
			return "false"
		file = request.files['file']
		if file.filename == '':
			flash('no select file')
			return 'false'
		if file and allowed_file(file.filename):
			filename = secure_filename(file.filename)
			contents = file.read()
			with open("files/URL.txt","wb") as f:
				f.write(contents)
			file.save = (os.path.join(app.config['UPLOAD_FOLDER'], filename))
			
			return render_template("index.html")
			
	
	return  render_template("index.html")

if __name__ == '__main__':
    app.run(debug=True)