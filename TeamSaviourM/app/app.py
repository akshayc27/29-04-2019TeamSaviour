from flask import Flask, render_template,url_for,request




#################
#### imports ####
#################

from flask import Flask

################
#### config ####
################



####################
#### blueprints ####
####################

from app.mods.mod_anomalies.views import anomalies_blueprint
from app.mods.mod_dynamic.views import dynamic_blueprint
from app.mods.mod_scan.views import scan_blueprint
from app.mods.mod_scan.views import file_blueprint
from app.mods.mod_config.views import config_blueprint

# register the blueprints
app.register_blueprint(anomalies_blueprint)
app.register_blueprint(dynamic_blueprint)
app.register_blueprint(scan_blueprint)
app.register_blueprint(file_blueprint)
app.register_blueprint(config_blueprint)





from flask_uploads import UploadSet,configure_uploads,ALL,DATA
from werkzeug import secure_filename

import sys
import sklearn

app = Flask(__name__)

import os
import datetime
import time

import warnings
warnings.filterwarnings('ignore')


LOCAL_IP = '127.0.0.1'
IF_CONTAMINATION = '0.01'

@app.route("/")
def Hello():
	return render_template("index.html")



if __name__ == '__main__':
	app.run(debug=True)