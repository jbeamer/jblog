#!/usr/bin/env python
# blog.py

#
# All import statements here:
#
import webapp2
import os
import jinja2
import re
import hashlib
import random
import string
import json
import time
from google.appengine.ext import db
from google.appengine.api import memcache
from jinja2 import Environment
from wiki import \
    WikiHandler, \
    WikiSignup, \
    WikiLogin, \
    WikiLogout, \
    WikiEditPage, \
    WikiPage, \
    WikiHistory

#
# Application initiation:
#
# Set up the template library.   Our templates are stored in the templates
# subdirectory
#
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
env = Environment(
    loader=jinja2.FileSystemLoader(template_dir),
    autoescape=True)


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

            # look up user
            user = User.get_by_id(int(user_id))

        # validate the password hash
        if user and (pw_hash == user.pw_hash.split(',')[0]):
            return user.username


#
#  Users and Authentication
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


class SignupHandler(Handler):
    def write_template(self, template_name, **params):
        template = env.get_template(template_name)
        self.response.out.write(template.render(params))

    def write_form(self, **params):
        self.write_template('signup.html', **params)

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
                    'Set-Cookie', 'user_id=%s|%s; Path=/' % (user_id, pw_hash))
                # redirect to the welcome page
                self.redirect("/blog/welcome")


class WelcomeHandler(Handler):
    def write_template(self, template_name, **params):
        template = env.get_template(template_name)
        self.response.out.write(template.render(params))

    def get(self):
        username = self.getUsername()
        if username:
            # write the welcome page with the username found in the db
            self.write_template('welcome.html', username=username)
        else:
            # invalid user state -- redirect to signup form
            self.redirect("/blog/signup")


class LoginHandler(Handler):
    def write_template(self, template_name, **params):
        template = env.get_template(template_name)
        self.response.out.write(template.render(params))

    def get(self):
        self.write_template('login.html')

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
                'login.html',
                username=username,
                error="ERROR: invalid login")
        else:
            # username = self.request.get('username')
            user = User.get_by_id(int(user_id))
            pw_hash = user.pw_hash.split(',')[0]
            salt = user.pw_hash.split(',')[1]
            if user.pw_hash == make_pw_hash(username, password, salt):
                # verified, set cookie and redirect somewhere...
                self.response.headers.add_header(
                    'Set-Cookie',
                    str('user_id=%s|%s; Path=/' % (user_id, pw_hash)))
                self.redirect("/blog/welcome")
            else:
                self.write_template(
                    'login.html',
                    username=username,
                    error="ERROR: invalid login")


# logout
class LogoutHandler(Handler):
    def get(self):
        # delete the cookie, or set the cookie to empty
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect("/blog/signup")


class BlogPost(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br/>')
        return render_str("blog_post.html", blogpost=self)

    def json(self):
        return json.dumps(
            {
                "subject": self.subject,
                "content": self.content,
                "created": self.created.strftime("%c"),
                "last_modified": self.last_modified.strftime("%c")
            })


def getBlogPostById(blog_id):
    # prevent the running of multiple queries
    key = "blogpost_" + str(blog_id)
    blogpost_tuple = memcache.get(key)
    if blogpost_tuple:
        blogpost, time_queried = blogpost_tuple
    else:
        blogpost = BlogPost.get_by_id(blog_id)
        time_queried = time.time()
        memcache.set(key, (blogpost, time_queried))

    return (blogpost, time_queried)


class MainPageHandler(Handler):
    def get(self):
        self.redirect('/blog')


def topBlogPosts(update=False):
    # prevent the running of multiple queries
    key = "topblogposts"
    blogpost_tuple = memcache.get(key)
    if blogpost_tuple is None or update:
        blogposts = db.GqlQuery("SELECT * "
                                "FROM BlogPost "
                                "ORDER BY created DESC "
                                "limit 10")
        blogposts = list(blogposts)
        time_queried = time.time()
        memcache.set(key, (blogposts, time_queried))
    else:
        blogposts, time_queried = blogpost_tuple
    return (blogposts, time_queried)


class BlogHandler(Handler):
    def get(self):
        blogposts, time_queried = topBlogPosts()
        self.render('blog_front.html',
                    blogposts=blogposts,
                    username=self.getUsername(),
                    age=time.time()-time_queried)


class BlogHandlerJSON(Handler):
    def get(self):
        blogposts, time_queried = topBlogPosts()
        self.response.headers['Content-Type'] = \
            'application/json; charset=UTF-8'
        self.write("[")
        first = True
        for blogpost in blogposts:
            if first:
                first = False
            else:
                self.write(",")
            self.write(blogpost.json())
        self.write("]")


class NewPostHandler(Handler):
    def get(self):
        self.render('blog_newpost.html', username=self.getUsername())

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        error = ''

        if subject and content:
            bp = BlogPost(subject=subject, content=content)
            bp.put()
            topBlogPosts(True)

            blog_id = str(bp.key().id())
            self.redirect('/blog/' + blog_id)
        else:
            error = "ERROR: enter subject and content"
            self.render(
                'blog_newpost.html',
                subject=subject,
                content=content,
                error=error,
                username=self.getUsername())


class FlushHandler(Handler):
    def get(self):
        memcache.flush_all()
        self.redirect('/blog')


class SinglePostHandlerHTML(Handler):
    def get(self, blog_id):
        blogpost_tuple = getBlogPostById(int(blog_id))
        if blogpost_tuple:
            # TODO: cache and set timing here...
            blogpost, time_queried = blogpost_tuple
            age = time.time() - time_queried
            self.render(
                'blog_singlepost.html',
                blogpost=blogpost,
                username=self.getUsername(),
                age=age)
        else:
            self.error(404)


class SinglePostHandlerJSON(Handler):
    def get(self, blog_id):
        blogpost_tuple = getBlogPostById(int(blog_id))
        if blogpost_tuple:
            blogpost, time_queried = blogpost_tuple
            self.response.headers['Content-Type'] = \
                'application/json; charset=UTF-8'
            self.write(blogpost.json())
        else:
            self.error(404)


#
# APPLICATION DEFINITION
#
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([
                                ('/',               MainPageHandler),
                                ('/blog',           BlogHandler),
                                ('/blog/',          BlogHandler),
                                ('/blog.json',      BlogHandlerJSON),
                                ('/blog/.json',     BlogHandlerJSON),
                                ('/blog/newpost',   NewPostHandler),
                                (r'/blog/(\d+)',        SinglePostHandlerHTML),
                                (r'/blog/(\d+).json',   SinglePostHandlerJSON),
                                ('/blog/signup',    SignupHandler),
                                ('/blog/welcome',   WelcomeHandler),
                                ('/blog/login',     LoginHandler),
                                ('/blog/logout',    LogoutHandler),
                                ('/blog/flush',     FlushHandler),
                                ('/wiki',           WikiHandler),
                                ('/wiki/signup',    WikiSignup),
                                ('/wiki/login',     WikiLogin),
                                ('/wiki/logout',    WikiLogout),
                                ('/wiki/_edit'+PAGE_RE, WikiEditPage),
                                ('/wiki/_history'+PAGE_RE, WikiHistory),
                                ('/wiki'+PAGE_RE,   WikiPage)
                               ], debug=True)
