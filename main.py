#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re
import string
import random
import logging
from string import letters

import webapp2
import jinja2
import hashlib


from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BaseHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)
##########################################################

##### Create school table ######
class School(db.Model):
    name = db.StringProperty(required = True)
    des = db.TextProperty()
    
##### Create user table #####
class User(db.Model):
    name = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.EmailProperty(required = True)
    auth_sch = db.ReferenceProperty(School)
    
##### Create sign up page #####

### Validate input ###
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(name):
    q = User.all().filter("name =",name)
    result = q.get()
    if result:
        return None
    else:
        return name and USER_RE.match(name)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)
    
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return email and EMAIL_RE.match(email)

### Hashing password ###
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))
    
def make_pw_salt(name,pw,salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name+pw+salt).hexdigest()
    return "%s,%s" %(h,salt)
    
def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    return h == make_pw_salt(name,pw,salt)

### Checking email to give authorized ###
email_sch = {'@williams.edu': 'Williams College', '@amherst.edu': 'Amherst College', '@wesleyan.edu': 'Wesleyan University', '@smith.edu': 'Smith College', '@mtholyoke.edu': 'Mount Holyoke College', '@hampshire.edu': 'Hampshire College', '@lafayette.edu': 'Lafayette College', '@dickinson.edu': 'Dickinson College', '@bowdoin.edu': 'Bowdoin College', '@colgate.edu': 'Colgate University'}
#email_check = {'wth':'@williams.edu', '9':'@amherst.edu', '8':'@wesleyan.edu', '7':'@smith.edu', '6':'@mtholyoke.edu', '5':'@hampshire.edu', '4':'@lafayette.edu', '3':'@dickinson.edu', '2':'@bowdoin.edu', '1':'@colgate.edu'}

def check_email(email):
    check = False
    result = email.split('@')[1]
    result = '@' + result
    for x in email_sch:
        if result==x:
            check = True
    return check
    
def authorize_sch(email):
    auth_school = None
    if check_email(email):
        result = email.split('@')[1]
        result = '@' + result
        auth_school = email_sch[result]
    return auth_school
    
### sigup handler ###
class SignUp(BaseHandler):
    def get(self):
        self.render("signup.html")
    def post(self):
        have_error = False
        name = self.request.get('name')
        password = self.request.get('password')
        repass = self.request.get('repass')
        email = self.request.get('email')
        
        params = dict(name = name, email = email)
        
        if not valid_username(name):
            params['error_name']="That's an invalid username."
            have_error = True
        
        if not valid_password(password):
            params['error_pass']="That's an invalid password."
            have_error = True
        elif password!=repass:
            params['error_repass']="The password you entered didn't not match."
            have_error = True
            
        if not valid_email(email):
            params['error_email']="That's an invalid email."
            have_error = True    
            
        if have_error:
            self.render('signup.html', **params)
        else:
            auth_sch = None
            if authorize_sch(email):
                sch = authorize_sch(email)
                sch2 = School.all().filter("name =", sch)
                auth_sch = sch2.get()
            password = make_pw_salt(name,password)
            p = User(name= name, password = password, email = email, auth_sch=auth_sch)
            p.put()
            self.redirect('/indexschool')
                
##### Create adding-school page #####
class AddSchool(BaseHandler):
    def get(self):
        self.render("addschool.html")
        
    def post(self):
        name = self.request.get("name")
        name = name.strip()
        des = self.request.get("description")
        school = School(name=name,des=des)
        school.put()
        self.redirect('/addschool')

##### Create indexing-school page #####
class IndexSchool(BaseHandler):
    def get(self):
        q = School.all()
        schools = q.fetch(1000)
        self.render("indexschool.html",schools=schools)
        
##### Create separated page for each school #####
class SchoolHandler(BaseHandler):
    def get(self,schoolname):
        q = School.all()
        q.filter("name =", schoolname)
        result = q.get()
        self.render("school.html",school=result)
        
app = webapp2.WSGIApplication([('/addschool', AddSchool),
                               ('/indexschool', IndexSchool),
                               (r'/school/(.*)', SchoolHandler),
                               ('/signup', SignUp),
                               ],
                              debug=True)
