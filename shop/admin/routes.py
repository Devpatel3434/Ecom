from flask import render_template,session, request,redirect,url_for,flash
from shop import app,db,bcrypt
from .forms import RegistrationForm,LoginForm
from .models import User
from shop.customers.model import Register,CustomerOrder
from shop.products.models import Addproduct,Category,Brand
from flask_admin import Admin , AdminIndexView
from flask_admin.contrib.sqla import ModelView
from flask_login import current_user, logout_user

@app.route('/admin')
def admin():
    if session.get('admin'):

    #user = User.query.all()
        products = Addproduct.query.all()
        return render_template('admin/index.html', title='Admin page',products=products)
    else:
        return redirect (url_for('adminlogin'))

@app.route('/brands')
def brands():
    brands = Brand.query.order_by(Brand.id.desc()).all()
    return render_template('admin/brand.html', title='brands',brands=brands)


@app.route('/categories')
def categories():
    categories = Category.query.order_by(Category.id.desc()).all()
    return render_template('admin/brand.html', title='categories',categories=categories)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hash_password = bcrypt.generate_password_hash(form.password.data)
        user = User(name=form.name.data,username=form.username.data, email=form.email.data,
                    password=hash_password)
        db.session.add(user)
        flash(f'welcome {form.name.data} Thanks for registering','success')
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('admin/register.html',title='Register user', form=form)


@app.route('/adminlogin', methods=['GET','POST'])
def adminlogin():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            session['email'] = form.email.data
            flash(f'welcome {form.email.data} you are logedin now','success')
            session['admin'] = True
            return redirect(url_for('admin'))
        else:
            flash(f'Wrong email and password', 'success')
            return redirect(url_for('login'))
    return render_template('admin/login.html',title='Login page',form=form)

class MyModelView(ModelView):
    def is_accessible(self):
        if session.get('admin'):
            return current_user.is_authenticated
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('adminlogin'))

class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        if session.get('admin'):
            return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('adminlogin'))

@app.route('/logout')
def admin_logout():
    session['admin'] = False
    logout_user()
    return redirect(url_for('home'))


admin = Admin(app, index_view=MyAdminIndexView())
admin.add_view(MyModelView(Register, db.session))
admin.add_view(MyModelView(User, db.session))
admin.add_view(MyModelView(CustomerOrder, db.session))