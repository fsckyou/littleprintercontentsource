#!/usr/bin/env python3

import datetime
import os
from dotenv import load_dotenv
from email.policy import default
from fileinput import filename
from functools import wraps
from hashlib import md5
from math import floor
from re import U, template
from enum import unique
import requests
import traceback

from flask import (Flask, Response, abort, flash, g, redirect, render_template, request,
                   session, template_rendered, url_for)
from peewee import *

load_dotenv()

SECRET_KEY = os.getenv('LPCS_SECRET_KEY')

database = SqliteDatabase('lpcs.db', pragmas={'foreign_keys': 1})


class BaseModel(Model):
    class Meta:
        database = database

# simple utility function to create tables


def create_tables():
    with database:
        database.create_tables([User, Friendship, Printer])


class User(BaseModel):
    """User class"""
    username = CharField(unique=True)
    password = CharField()
    email = CharField()
    oAuthToken = CharField(null=True)
    join_date = DateTimeField()

    def friends(self):
        return (User
                .select()
                .distinct()
                .join(Friendship, on=((Friendship.user1 == User.id) | (Friendship.user2 == User.id)))
                .where((Friendship.user1 == self) | (Friendship.user2 == self)))

    def link_oAuth(self):
        pass

    def gravatar_url(self, size=80):
        return 'http://www.gravatar.com/avatar/%s?d=identicon&s=%d' % \
            (md5(self.email.strip().lower().encode('utf-8')).hexdigest(), size)


class Printer(BaseModel):
    """Generic Printer Interface"""
    name = CharField()
    owner = ForeignKeyField(User, backref='printers')
    key_url = CharField()
    accessibility = IntegerField(default=0, constraints=[Check(
        'accessibility >= 0 & accessibility < 3')])  # 0 = private, 1 = friends, 2 = public
    type = CharField(default="LittlePrinter", null=True)

    def print_plain_text(self, text_to_print: str, from_string: str) -> bool:
        headers = {"content-type":"text/plain"}
        params = {"from":from_string}
        try:
            r = requests.post(url=self.key_url, timeout=2, data=text_to_print.encode("UTF-8"), params=params, headers=headers)
        except requests.exceptions.RequestException:
            return False
        if r.status_code == 200:
            return True
        return False

    def set_name(self, new_name: str) -> None:
        self.name = new_name
        return

    def set_private(self) -> None:
        self.accessibility = 0
        return

    def set_public(self) -> None:
        self.accessibility = 2
        return

    def set_friends_only(self) -> None:
        self.accessibility = 1
        return
    
    def is_online(self) -> bool:
        try:
            r = requests.get(url=self.key_url,timeout=2)
        except requests.exceptions.RequestException:
            return False
        data = r.json()
        return (data['status'] == "online")


class Friendship(BaseModel):
    user1 = ForeignKeyField(User)
    user2 = ForeignKeyField(User)
    confirmed = BooleanField()

    class Meta:
        indexes = (
            # Specify a unique multi-column index on from/to-user.
            (('user1', 'user2'), True),
        )

class ContentSource:
    name: str
    url: str

class ContentPlainText(ContentSource):
    name = "Send Plain Text"
    route = "plaintext"
    
    def print_text(self, text_to_print:str , target_printer:Printer, from_user:User):
        target_printer.print_plain_text(text_to_print,from_user.username)
    
content_sources = [ContentPlainText,]

################################################################################
#                                                                              #
#                               FLASK TIME!                                    #
#                                                                              #
################################################################################


# create a flask application - this ``app`` object will be used to handle
# inbound requests, routing them to the proper 'view' functions, etc
app = Flask(__name__)
app.config.from_object(__name__)

# given a template and a SelectQuery instance, render a paginated list of
# objects from the query inside the template

def object_list(template_name, qr, var_name='object_list', **kwargs):
    kwargs.update(
        page=int(request.args.get('page', 1)),
        pages=floor(qr.count() / 20) + 1)
    kwargs[var_name] = qr.paginate(kwargs['page'])
    return render_template(template_name, **kwargs)

# retrieve a single object matching the specified query or 404 -- this uses the
# shortcut "get" method on model, which retrieves a single object or raises a
# DoesNotExist exception if no matching object exists
# https://charlesleifer.com/docs/peewee/peewee/models.html#Model.get)


def get_object_or_404(model, *expressions):
    try:
        return model.get(*expressions)
    except model.DoesNotExist:
        abort(404)

# flask provides a "session" object, which allows us to store information across
# requests (stored by default in a secure cookie).  this function allows us to
# mark a user as being logged-in by setting some values in the session data:


def auth_user(user):
    session['logged_in'] = True
    session['user_id'] = user.id
    session['username'] = user.username
    flash('You are logged in as %s' % (user.username))

# get the user from the session


def get_current_user():
    if session.get('logged_in'):
        return User.get(User.id == session['user_id'])

# view decorator which indicates that the requesting user must be authenticated
# before they can access the view.  it checks the session to see if they're
# logged in, and if not redirects them to the login view.


def login_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return inner

# Request handlers -- these two hooks are provided by flask and we will use them
# to create and tear down a database connection on each request.


@app.before_request
def before_request():
    g.db = database
    g.db.connect()


@app.after_request
def after_request(response):
    g.db.close()
    return response

# views -- these are the actual mappings of url to view function


@app.route('/favicon.ico')
def favicon():
    # just get the favicon in the static directory I guess?
    return redirect(url_for('static', filename='favicon.ico'))


@app.route('/')
def homepage():
    # depending on whether the requesting user is logged in or not, show them
    # either the public timeline or their own private timeline
    if session.get('logged_in'):
        return redirect(url_for('contentcatalog'))
    return render_template('homepage.html')


@app.route('/join/', methods=['GET', 'POST'])
def join():
    if request.method == 'POST' and request.form['username']:
        try:
            with database.atomic():
                # Attempt to create the user. If the username is taken, due to the
                # unique constraint, the database will raise an IntegrityError.
                user = User.create(
                    username=request.form['username'],
                    password=md5((request.form['password']).encode(
                        'utf-8')).hexdigest(),
                    email=request.form['email'],
                    join_date=datetime.datetime.now())

            # mark the user as being 'authenticated' by setting the session vars
            auth_user(user)
            return redirect(url_for('homepage'))

        except IntegrityError:
            traceback.print_exc()

    return render_template('join.html')


@app.route('/login/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST' and request.form['username']:
        try:
            pw_hash = md5(request.form['password'].encode('utf-8')).hexdigest()
            user = User.get(
                (User.username == request.form['username']) &
                (User.password == pw_hash))
        except User.DoesNotExist:
            flash('The password entered is incorrect')
        else:
            auth_user(user)
            return redirect(url_for('homepage'))

    return render_template('login.html')


@app.route('/logout/')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out')
    return redirect(url_for('homepage'))


@app.route('/contentcatalog/', methods=['GET','POST'])
@login_required
def contentcatalog():
    kargs= {"content_sources": content_sources}
    if request.method == 'POST' and request.form["target_printer"]:
        session["target_printer"] = request.form["target_printer"]
        return render_template('contentcatalog.html',**kargs)
    else: 
        session["target_printer"] = None
        return render_template('contentcatalog.html',**kargs)

@app.route('/plaintext/', methods=['GET','POST'])
@login_required
def plaintext():
    if request.method == 'POST':
        if(session["target_printer"]):
            target_printer: Printer = Printer.get(session.get("target_printer"))
            if target_printer.is_online():
                target_printer.print_plain_text(request.form["message"],session.get("username"))
                flash("Message sent!")
            else:
                flash("Couldn't send message. Printer is offline.")
        else:
            print("no printer yet")
    return render_template('plaintext.html')

@app.route('/yourprinters/')
@login_required
def yourprinters():
    userid = session.get('user_id')
    user = User.get_by_id(userid)
    printers = user.printers
    return object_list('printerslist.html', printers, 'printer_list', user=user)


@app.route('/addprinter/', methods=['GET', 'POST'])
def addprinter():
    if request.method == 'POST' and request.form['name']:
        if request.form['type'] == "LittlePrinter":
            printer = Printer.create(name=request.form['name'],
                                     key_url=request.form['key_url'],
                                     owner=User.get_by_id(1)
                                     )
        return redirect(url_for('yourprinters'))
    return render_template('addprinter.html')


# allow running from the command line
if __name__ == '__main__':
    create_tables()
    app.run()
