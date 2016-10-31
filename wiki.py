#!/usr/bin/env python
# wiki.py

#
#  All import statements here:
#
import webapp2
import os
import jinja2
import re
import hashlib
import random
import string
from google.appengine.ext import db
from jinja2 import Environment
import datetime


#
# Application initiation:
#
# Set up the template library.   Our templates are stored in the templates
# subdirectory
#
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
env = Environment(
    loader=jinja2.FileSystemLoader(template_dir),
    autoescape=False)


def render_str(template_name, **params):
    template = env.get_template(template_name)
    return template.render(params)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render(self, template, **kw):
        self.write(render_str(template, **kw))

    def getUsername(self):
        user_id_str = self.request.cookies.get('user_id')
        user = None
        if user_id_str:
            user_id = user_id_str.split('|')[0]
            pw_hash = user_id_str.split('|')[1]
            user = User.get_by_id(int(user_id))

        # validate the password hash
        if user and (pw_hash == user.pw_hash.split(',')[0]):
            return user.username

        return None


class WikiPageContent(db.Model):
    path = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    def renderversion(self):
        self._render_text = self.content.replace('\n', '<br/>')
        return render_str("wiki_page_version.html", wikipage=self)


#
# Users and Authentication
#
class User(db.Model):
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)


# TODO: change this to bcrypt
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = ''.join(random.choice(string.letters) for x in xrange(5))
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


class WikiSignup(Handler):
    def write_template(self, template_name, **params):
        template = env.get_template(template_name)
        self.response.out.write(template.render(params))

    def write_form(self, **params):
        self.write_template('wiki_signup.html', **params)

    def get(self):
        self.write_form()

    def valid_username(self, username):
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return USER_RE.match(username)

    def valid_email(self, email):
        USER_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
        return USER_RE.match(email)

    def valid_password(self, password):
        USER_RE = re.compile(r"^.{3,20}$")
        return USER_RE.match(password)

    def valid_password_verify(self, password, verify):
        return (password == verify)

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        if not(self.valid_username(username)):
            self.write_form(
                error_username="ERROR: That's not a valid username",
                username=username,
                email=email)
        elif not(self.valid_password(password)):
            self.write_form(
                error_password="ERROR: That wasn't a valid password",
                username=username,
                email=email)
        elif not(self.valid_password_verify(password, verify)):
            self.write_form(
                error_verify="ERROR: The passwords don't match",
                username=username,
                email=email)
        elif email and not(self.valid_email(email)):
            self.write_form(
                error_email="ERROR: That wasn't a valid email",
                username=username,
                email=email)
        else:
            # user is valid
            # check database to make sure it doesn't already exist
            users = db.GqlQuery("SELECT * FROM User")
            found = False
            for u in users:
                if u.username == username:
                    found = True
            if found:
                self.write_form(
                    error_username="ERROR: username already exists",
                    username=username,
                    email=email)
            else:
                # TODO: if everything else works, use memcached to eliminate
                #       concurrency.
                # create the user
                pw_hash_str = make_pw_hash(username, password)
                pw_hash = pw_hash_str.split(',')[0]
                user = User(
                    username=username,
                    pw_hash=pw_hash_str,
                    email=email)
                user.put()
                user_id = str(user.key().id())
                # set the cookie
                self.response.headers.add_header(
                    'Set-Cookie', 'user_id=%s|%s; Path=/wiki/' %
                    (user_id, pw_hash))
                # redirect to the welcome page
                self.redirect("/wiki/")


class WikiHandler(Handler):
    def get(self):
        self.redirect("/wiki/")


class WikiLogin(Handler):
    def write_template(self, template_name, **params):
        template = env.get_template(template_name)
        self.response.out.write(template.render(params))

    def get(self):
        self.write_template('wiki_login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        users = db.GqlQuery("SELECT * FROM User")
        user_id = None
        for u in users:
            if u.username == username:
                user_id = u.key().id()

        if not user_id:
            self.write_template(
                'wiki_login.html',
                username=username,
                error="ERROR: invalid login")
        else:
            user = User.get_by_id(int(user_id))
            pw_hash = user.pw_hash.split(',')[0]
            salt = user.pw_hash.split(',')[1]
            if user.pw_hash == make_pw_hash(username, password, salt):
                # verified, set cookie and redirect somewhere...
                self.response.headers.add_header(
                    'Set-Cookie',
                    str('user_id=%s|%s; Path=/' % (user_id, pw_hash)))
                self.redirect("/wiki/")
            else:
                self.write_template(
                    'wiki_login.html',
                    username=username,
                    error="ERROR: invalid login")


class WikiLogout(Handler):
    def get(self):
        # delete the cookie, or set the cookie to empty
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect("/wiki/")


class WikiEditPage(Handler):
    def get(self, path):
        username = self.getUsername()
        if username:
            content = ""
            page = getWikiPageByPath(path)
            if page:
                content = page.content
            self.render('wiki_edit.html',
                        username=username,
                        content=content,
                        path=path
                        )
        else:
            self.redirect("/wiki" + path)

    def post(self, path):
        content = self.request.get('content')
        page = WikiPageContent(path=path, content=str(content))
        page.put()
        self.redirect('/wiki' + path)


# returns the most recent version of the page
def getWikiPageByPath(path):
    pages = db.GqlQuery("SELECT * FROM WikiPageContent")
    most_recent_time = datetime.datetime(2000, 1, 1)
    most_recent_page = None
    for page in pages:
        if path == page.path:
            if page.created > most_recent_time:
                most_recent_time = page.created
                most_recent_page = page
    return most_recent_page


class WikiPage(Handler):
    # Go to that page if it has already been created.
    # Go to an edit page if that page doesn't yet exist, assuming the user is
    # signed in
    def get(self, path):
        username = self.getUsername()
        page = None
        version = self.request.get('v')
        if version:
            page = WikiPageContent.get_by_id(int(version))
        else:
            page = getWikiPageByPath(path)

        if page:
            self.render(
                'wiki_page.html',
                username=username,
                content=page.content,
                path=path)
        elif username:
            self.redirect("/wiki/_edit" + path)
        else:
            self.redirect("/wiki/signup")


class WikiHistory(Handler):
    def get(self, path):
        username = self.getUsername()
        # in descending order, print out each version of the page and the first
        # lines of content, with view and edit links on the right columns
        pages = db.GqlQuery("SELECT * FROM WikiPageContent "
                            "WHERE path='" + path + "' "
                            "ORDER BY created DESC ")
        if username:
            self.render(
                'wiki_history.html',
                username=username,
                path=path,
                wikipages=pages)
        else:
            self.redirect("/wiki" + path)
