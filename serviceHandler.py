# =============================================================================
# SERVICEHANDLER
# Copyright (c) 2011-2012
#
# Author: Inigo Gonzalez Vazquez - @haas85
# =============================================================================

import base64
import time

import cgi


import logging

import webapp2


class ServiceHandler(webapp2.RequestHandler):
    contentAccept = {
        'PLAIN': {'content': 'text/plain', 'attach': False},
        'HTML': {'content': 'text/html', 'attach': False},
        'JSON': {'content': 'application/json', 'attach': False},
        'XML': {'content': 'application/xml', 'attach': False}
    }

    def initialize(self, request, response):
        super(ServiceHandler, self).initialize(request, response)
        '''If you want not to do something automatically take it out form here'''
        self.setResponseHeaders()
        self.getParameters()
        # print self.request
        # print self.parameters
        # print self.response
        # logging.info(self.hasCredentials)

    @property
    def checkAuth(self):
        try:
            #http basic auth
            if('Authorization' in self.request.headers):
                auth_header = self.request.headers['Authorization']
                auth_parts = auth_header.split(' ')
                '''
                    auth_parts[1] it has a string cyphered using base64 which contains userid and pass
                    in the following format userid:pass
                '''
                user_pass_parts = base64.b64decode(auth_parts[1]).split(':')
                '''
                    user_pass_parts it is a list of credentials, first position the userid and second the pass
                    now you can do whatever you want. in this case y must decypher again the data
                '''
                self._current_user = str(base64.b64decode(
                            user_pass_parts[0]))
                self._current_pass = str(base64.b64decode(
                            user_pass_parts[1]))
            #If there is not auth header checks if there are auth cookies
            elif 'Cookie' in self.request.headers:
                auth_cookie = self.request.headers['Cookie']
                auth_parts = auth_cookie.split(';')
                '''
                    This checks if there are elements in the cookies
                '''
                for obj in auth_parts:
                    if ('usr=' in obj):
                        self._current_user = str(base64.b64decode(
                            self.parse_cookie(
                                obj.split('usr=')[1])))
                    if ('pwd=' in obj):
                        self._current_pass = str(base64.b64decode(
                            self.parse_cookie(
                                obj.split('pwd=')[1])))
            else:
                return False
            if self._current_user and self._current_pass:
                '''
                    Now we check the credential to make login.
                '''
                return True
            else:
                return False
        except AttributeError:
            logging.info("No credentials")
            return False
        except Exception, e:
            logging.info("Error de credenciales")
            logging.info(e)
            return False

    def setResponseHeaders(self):
        self.response.headers['Cache-Control'] = 'no-cache, must-revalidate'
        self.response.headers['Pragma'] = 'no-cache'
        self.response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        self.response.headers['Access-Control-Allow-Origin'] = '*'
        reqType = self.request.headers['Accept'].split(',')
        if self.contentAccept['HTML']['content'] in reqType:
            self.response.headers['Content-Type'] = self.contentAccept['HTML']['content'] + '; charset=utf-8'
            return
        else:
            for obj in self.contentAccept:
                if self.contentAccept[obj]['content'] in reqType:
                    if self.contentAccept[obj]['attach']:
                        self.response.headers['Content-Disposition'] = 'Attachment'
                    self.response.headers['Content-Type'] = self.contentAccept[obj]['content'] + '; charset=utf-8'
                    return
        self.response.headers['Content-Type'] = self.contentAccept['PLAIN']['content'] + '; charset=utf-8'

    #headers must be a dict
    def setResponse(self, code, data, headers=None):
        if headers != None:
            if type(headers) == 'dict':
                for head in headers:
                    self.response.headers[head] = headers[head]
        self.response.set_status(code)
        self.response.out.write(data)

    #This method parses the parameters of the request and works with put and delete requests too.
    def getParameters(self):
        if ('Content-Type' in self.request.headers) and ('multipart/form-data' in self.request.headers['Content-Type']):
            self.parameters = {}
            form = cgi.FieldStorage()
            for arg in form:
                if str(arg) not in self.parameters:
                    self.parameters[str(arg)] = []
                self.parameters[str(arg)].append(form[str(arg)])
        elif self.request.body == "":
            self.parameters = {}
            for arg in self.request.arguments():
                self.parameters[str(arg)] = self.request.get_all(str(arg))
        else:
            self.parameters = cgi.parse_qs(self.request.body)

    #Checks if a parameter exists in the request
    def existParameter(self, param):
        if param in self.parameters:
            return True
        else:
            return False

    #Checks if a all the parameters in the list exists in the request
    def requiredParams(self, params_list):
        for param in params_list:
            if str(param) not in self.parameters:
                return False
        return True

    def parse_cookie(self, value):
        """Parses and verifies a cookie value from set_cookie"""
        if not value:
            return None
        parts = value.split("|")
        if len(parts) != 3:
            return None
        if self.cookie_signature(parts[0], parts[1]) != parts[2]:
            logging.warning("Invalid cookie signature %r", value)
            return None
        timestamp = int(parts[1])
        if timestamp < time.time() - 30 * 86400:
            logging.warning("Expired cookie %r", value)
            return None
        try:
            return base64.b64decode(parts[0]).strip()
        except:
            return None

    '''Methods for non supported requests (if the service supports it overwrite it)'''

    def get(self):
        self.setResponse(401,
            '{"code":"401", "message":"Unauthorized operation"}')

    def post(self):
        self.setResponse(401,
            '{"code":"401", "message":"Unauthorized operation"}')

    def put(self):
        self.setResponse(401,
            '{"code":"401", "message":"Unauthorized operation"}')

    def delete(self):
        self.setResponse(401,
            '{"code":"401", "message":"Unauthorized operation"}')
