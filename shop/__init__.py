from flask import Flask, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_uploads import UploadSet, configure_uploads, IMAGES, patch_request_class
import os
from flask_recaptcha import ReCaptcha
from flask_msearch import Search
from flask_login import LoginManager
from datetime import timedelta
 
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
recaptcha = ReCaptcha(app=app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY']='hfouewhfoiwefoquw'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 

app.config.update(dict(
    RECAPTCHA_ENABLED = True,
    RECAPTCHA_SITE_KEY = "6LcaCiUeAAAAAE8c5Eb3ADVw-7UPybPHppPl7kpv",
    RECAPTCHA_SECRET_KEY = "6LcaCiUeAAAAAI5X0blM8ghaB4mzElzJa9hHQw5p",
    ))

app.config['UPLOADED_PHOTOS_DEST'] = os.path.join(basedir, 'static/images')
photos = UploadSet('photos', IMAGES)
configure_uploads(app, photos)
patch_request_class(app)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
search = Search()
search.init_app(app)

recaptcha = ReCaptcha()
recaptcha.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view='login'
login_manager.needs_refresh_message_category='danger'
login_manager.login_message = "Please login first"



app.config.from_pyfile('config.cfg')

from shop.products import routes
from shop.admin import routes
from shop.carts import carts
from shop.customers import routes


