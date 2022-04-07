from flask import render_template,session, request,redirect,url_for,flash,current_app,make_response
from flask_login import login_required, current_user, logout_user, login_user
from shop import app,db,photos, search,bcrypt,login_manager
from .forms import CustomerRegisterForm, CustomerLoginFrom
from .model import Register,CustomerOrder
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import os
import json 
import pdfkit 
import stripe 
from flask_mail import *
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_admin import Admin , AdminIndexView
from flask_admin.contrib.sqla import ModelView
from random import randint
from flask_recaptcha import ReCaptcha
from flask_login.utils import login_required
from datetime import timedelta
recaptcha = ReCaptcha()
publishable_key ='pk_test_51KcAKvSEMsuOirAeOAKQbYGrQy8GD0wU8BU66AuwKCckMgWyREFiVMMnXJMfIbnOSjUuExPs7NjpERzRM3xRpEIE00kdRnaOcC'
stripe.api_key ='sk_test_51KcAKvSEMsuOirAeenljZCsaRHHKT6beUZ2BRm22y533wGMPiUBOcxsG7mIrPVmgsKZ1r0G1DTli7tG34FyPasEv00VrZkb7YG'

@app.route('/payment',methods=['POST'])
def payment():
    invoice = request.form.get('invoice')
    #invoice = request.get('invoice')
    amount = request.form.get('amount')

    customer = stripe.Customer.create(
        email=request.form['stripeEmail'],
        source=request.form['stripeToken'],
    )

    stripe.PaymentIntent.create(
    customer=customer.id,
    amount=amount,
    currency='usd',
    description='Ecom',
    )


    '''customer = stripe.Customer.create(
      email=request.form['stripeEmail'],
      source=request.form['stripeToken'],
    )
    charge = stripe.Charge.create(
      customer=customer.id,
      description='Ecom',
      amount=amount,
      currency='usd',
    )'''
    orders =  CustomerOrder.query.filter_by(customer_id = current_user.id,invoice=invoice).order_by(CustomerOrder.id.desc()).first()
    orders.status = 'Paid'
    db.session.commit()
    return redirect(url_for('thanks'))

@app.route('/thanks') 
def thanks():
    return render_template('customer/thank.html')


'''@app.route('/customer/register', methods=['GET','POST'])
def customer_register():
    form = CustomerRegisterForm()
    if form.validate_on_submit():
        hash_password = bcrypt.generate_password_hash(form.password.data)
        register = Register(name=form.name.data, username=form.username.data, email=form.email.data,password=hash_password,country=form.country.data, city=form.city.data,contact=form.contact.data, address=form.address.data, zipcode=form.zipcode.data)
        db.session.add(register)
        flash(f'Welcome {form.name.data} Thank you for registering', 'success')
        db.session.commit()
        return redirect(url_for('customerLogin'))
    return render_template('customer/register.html', form=form)'''

mail = Mail(app)
    
s = URLSafeTimedSerializer('Thisisasecret!')


@app.route('/signup')
def signup():
    return render_template('tem/signup.html')
@app.route('/signup', methods=['POST'])
def customer_register():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    user = Register.query.filter_by(email=email).first()

        #if (user==None):
            #return redirect(url_for('signup'))
    if user: # if a user is found, we want to redirect back to signup page so user can try again
        flash('Email address already exists') 
        return redirect(url_for('signup'))
    email = request.form.get('email')
    password=generate_password_hash(password, method='sha256')

     
    token = s.dumps(email,  salt='email-confirm')
    tokens = s.dumps(name)
    tokenss = s.dumps(password)

    msg = Message('Confirm Email', sender='playpubg34@gmail.com', recipients=[email])
    link = url_for('confirm_email', name=tokens, password=tokenss, token=token, _external=True)
    msg.body = 'Your link is {}'.format(link)
    mail.send(msg)
    #new_user = Register(email=email, name=name, password=generate_password_hash(password, method='sha256'))
    #db.session.add(new_user)
    #db.session.commit()
    return redirect(url_for('login'))

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
    
        email = s.loads(token, salt='email-confirm', max_age=120)
        name = s.loads(request.args.get('name'))
        #fname = request.args.get('fname')
        #lname =  s.loads(request.args.get('lname'))
        password =  s.loads(request.args.get('password'))
    except SignatureExpired:
        return '<h1>The token is expired!</h1>'
    ml = Register.query.filter_by(email=email).first()
    if ml:
        return render_template('tem/emailalreadyconfirm.html')
    else:
        #ml.confirmed = True
        new_user = Register(email=email, name=name, password=password)
        db.session.add(new_user)
        db.session.commit()
        return render_template('tem/emailverification.html')
generate_rand = 0
generated_otp = 0
@app.route('/login')
def login():
    return render_template('tem/login.html')

    
@app.route('/login', methods=['POST'])
def login_post():
    global generate_rand
    email = request.form.get('email')
    password = request.form.get('password')
    #remember = True if request.form.get('remember') else False

    user = Register.query.filter_by(email=email).first()
        
    #abc = recaptcha.verify()
        
    if (user and check_password_hash(user.password, password)) and recaptcha.verify():
        otp = randint(100000, 999999)
        generate_rand = otp
        msg = Message('Confirm OTP', sender='playpubg34@gmail.com', recipients=[email])
        msg.body = str(generate_rand) 
        mail.send(msg)

        login_user(user)
        return redirect('/verify')
        #return redirect(url_for('main.profile'))
    elif(user==None):
        return render_template('tem/login.html',message = "Email is not registered")
    elif not (user and check_password_hash(user.password, password)):
        return render_template('tem/login.html',message="Email and password don't match")
    
    return render_template('tem/login.html', message="Recheck the Field") 

@app.route('/resend', methods=['GET', 'POST'])
def resend():
    global generated_otp
    #email = request.args.get('email')
    if request.method == 'GET':
     return render_template('tem/resend.html')
    
    newotp = randint(100000, 999999)
    generated_otp=newotp 
    mails = request.form['email']
    msg = Message('Confirm OTP', sender='playpubg34@gmail.com', recipients=[mails])
    msg.body = str(newotp) #'Your link is {}'.format(link)
    mail.send(msg)
    #return redirect(url_for('confirm', email=email))
    return redirect('/verify')
        

@app.route('/verify', methods=['GET', 'POST'])
@login_required
def confirm():
    global generate_rand
    global generated_otp
    #if request.method == 'GET':
       # return '<form action="/confirm" method="POST"><input name="otp"><input type="submit"></form>'
    if request.method == 'GET':
        return render_template('tem/verify.html')
    userotp=request.form['otp']
    if generate_rand== int(userotp):
        #session['profile'] = True
        return redirect(url_for('home'))
    elif generated_otp == int(userotp):
        #session['profile'] = True
        return redirect(url_for('home'))
        #return " Email verified Success"
    #return redirect('/verify')
    else:
        return render_template('tem/verify.html', message = "Enter Correct OTP")

@app.route('/profile')
@login_required
def profile():
    return render_template('tem/profile.html', name=current_user.name)


r = URLSafeTimedSerializer('Thisisasecretkey!')
@app.route('/passreset', methods=['GET', 'POST'])
def passreset():
    if request.method == 'GET':
        return render_template('tem/pass_reset.html')
    email = request.form['email']
    user = Register.query.filter_by(email=email).first()
    if user:
        token = r.dumps(email,  salt='pass-reset')
        msg = Message('Password reset flask app', sender='playpubg34@gmail.com', recipients=[email])
        link = url_for('pass_reset',  token=token, _external=True)
        msg.body = 'Your link to change password is {}'.format(link)
        mail.send(msg)
        return redirect(url_for('login'))
    else:
        return render_template('tem/pass_reset.html', message='email not found')
@app.route('/pass_reset/<token>')
def pass_reset(token):
    try:
        smail = r.loads(token, salt='pass-reset', max_age=3600)
    except SignatureExpired:
        return '<h1>The token is expired!</h1>'
        
    ps = Register.query.filter_by(email=smail).first()
    if ps:
        email = r.dumps(smail)
        return redirect(url_for('password_reset', email=email))
    else:
        return render_template('tem/emailverification.html')

@app.route('/password_reset/<email>', methods=['GET', 'POST'])
def password_reset(email):
    if request.method == 'GET':
        return render_template('tem/password_reset.html')
    email = r.loads(email)
    print ('email is = ', email)
    user = Register.query.filter_by(email=email).first()
    if user:
        password, cnfpassword=request.form['password'], request.form['cnfpassword']
        if(password==cnfpassword):
            password=generate_password_hash(password, method='sha256')
            user.password = password
            db.session.commit()
            return render_template('tem/passupdated.html')
            
        else:
            return 'hello2'
            
    else:
        return 'hello 3'


'''
@app.route('/customer/login', methods=['GET','POST'])
def customerLogin():
    form = CustomerLoginFrom()
    if form.validate_on_submit():
        user = Register.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('You are login now!', 'success')
            next = request.args.get('next')
            return redirect(next or url_for('home'))
        flash('Incorrect email and password','danger')
        return redirect(url_for('customerLogin'))
            
    return render_template('customer/login.html', form=form)

'''
@app.route('/customer/logout')
def customer_logout():
    logout_user()
    return redirect(url_for('home'))

def updateshoppingcart():
    for key, shopping in session['Shoppingcart'].items():
        session.modified = True
        del shopping['image']
        del shopping['colors']
    return updateshoppingcart

@app.route('/getorder')
@login_required
def get_order():
    if current_user.is_authenticated:
        customer_id = current_user.id
        invoice = secrets.token_hex(5)
        updateshoppingcart
        try:
            order = CustomerOrder(invoice=invoice,customer_id=customer_id,orders=session['Shoppingcart'])
            db.session.add(order)
            db.session.commit()
            session.pop('Shoppingcart')
            flash('Your order has been sent successfully','success')
            return redirect(url_for('orders',invoice=invoice))
        except Exception as e:
            print(e)
            flash('Some thing went wrong while get order', 'danger')
            return redirect(url_for('getCart'))
        


@app.route('/orders/<invoice>')
@login_required
def orders(invoice):
    if current_user.is_authenticated:
        grandTotal = 0
        subTotal = 0
        customer_id = current_user.id
        customer = Register.query.filter_by(id=customer_id).first()
        orders = CustomerOrder.query.filter_by(customer_id=customer_id, invoice=invoice).order_by(CustomerOrder.id.desc()).first()
        for _key, product in orders.orders.items():
            discount = (product['discount']/100) * float(product['price'])
            subTotal += float(product['price']) * int(product['quantity'])
            subTotal -= discount
            tax = ("%.2f" % (.06 * float(subTotal)))
            grandTotal = ("%.2f" % (1.06 * float(subTotal)))

    else:
        return redirect(url_for('login'))
    return render_template('customer/order.html', invoice=invoice, tax=tax,subTotal=subTotal,grandTotal=grandTotal,customer=customer,orders=orders)




@app.route('/get_pdf/<invoice>', methods=['POST'])
@login_required
def get_pdf(invoice):
    if current_user.is_authenticated:
        grandTotal = 0
        subTotal = 0
        customer_id = current_user.id
        if request.method =="POST":
            customer = Register.query.filter_by(id=customer_id).first()
            orders = CustomerOrder.query.filter_by(customer_id=customer_id, invoice=invoice).order_by(CustomerOrder.id.desc()).first()
            for _key, product in orders.orders.items():
                discount = (product['discount']/100) * float(product['price'])
                subTotal += float(product['price']) * int(product['quantity'])
                subTotal -= discount
                tax = ("%.2f" % (.06 * float(subTotal)))
                grandTotal = float("%.2f" % (1.06 * subTotal))

            rendered =  render_template('customer/pdf.html', invoice=invoice, tax=tax,grandTotal=grandTotal,customer=customer,orders=orders)
            pdf = pdfkit.from_string(rendered, False)
            response = make_response(pdf)
            response.headers['content-Type'] ='application/pdf'
            response.headers['content-Disposition'] ='inline; filename='+invoice+'.pdf'
            return response
    return request(url_for('orders'))


@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=1)