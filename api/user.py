import json, jwt
from flask import Blueprint, request, jsonify, current_app, Response, redirect
from flask_restful import Api, Resource # used for REST API building
from datetime import datetime
from auth_middleware import token_required, User
from __init__ import app, db, cors, dbURI
import sqlite3


from model.users import User

user_api = Blueprint('user_api', __name__,
                   url_prefix='/api/user')

# API docs https://flask-restful.readthedocs.io/en/latest/api.html
api = Api(user_api)

class UserAPI:        
    class _CRUD(Resource):  # User API operation for Create, Read.  THe Update, Delete methods need to be implemeented
        ##@token_required
        def post(self): # Create method
            ''' Read data for json body '''
            body = request.get_json()
            
            
            ''' Avoid garbage in, error checking '''
            # validate name
            name = body.get('name')
            if name is None or len(name) < 1:
                return {'message': f'Name is missing, or is less than 2 characters'}, 400
            # validate uid
            uid = body.get('uid')
            if uid is None or len(uid) < 1:
                return {'message': f'User ID is missing, or is less than 2 characters'}, 400
            # look for password and dob
            password = body.get('password')
            dob = body.get('dob')
            zipcode = body.get('zipcode')
            ''' #1: Key code block, setup USER OBJECT '''
            uo = User(name=name,
                      uid=uid,password=password,zipcode=zipcode)
            
            ''' Additional garbage error checking '''
            # set password if provided
            if password is not None:
                uo.set_password(password)
            # convert to date type
            if dob is not None:
                try:
                    uo.dob = datetime.strptime(dob, '%Y-%m-%d').date()
                except:
                    return {'message': f'Date of birth format error {dob}, must be mm-dd-yyyy'}, 400
            
            ''' #2: Key Code block to add user to database '''
            # create user in database
            user = uo.create()
            # success returns json of user
            if user:
                return jsonify(user.read())
            # failure returns error
            return {'message': f'Processed {name}, either a format error or User ID {uid} is duplicate'}, 400
    
    class _Delete(Resource):
        ##@token_required
        def post(self):
            body = request.get_json()

            if not body:
                return {
                    "message": "Please provide user details",
                    "data": None,
                    "error": "Bad request"
                }, 400

            uid = body.get('uid')
            if uid is None:
                return {'message': f'User ID is missing'}, 400

            password = body.get('password')

            user = User.query.filter_by(_uid=uid).first()

            if user is None or not user.is_password(password):
                return {'message': f"Invalid user id or password"}, 400

        # If UID and password are correct, delete the user from the database
            db.session.delete(user)
            db.session.commit()

            return {'message': 'User deleted successfully'}, 200
          # @token_required
        def get(self): # Read Method , current_user
            users = User.query.all()    # read/extract all users from database
            json_ready = [user.read() for user in users]  # prepare output in json
            return jsonify(json_ready)  # jsonify creates Flask response object, more specific to APIs than json.dumps       
    class _Security(Resource):
        def post(self):
            try:
                body = request.get_json()
                if not body:
                    return {
                        "message": "Please provide user details",
                        "data": None,
                        "error": "Bad request"
                    }, 400
                ''' Get Data '''
                uid = body.get('uid')
                if uid is None:
                    return {'message': f'User ID is missing'}, 400
                password = body.get('password')
                
                ''' Find user '''
                user = User.query.filter_by(_uid=uid).first()
                if user is None or not user.is_password(password):
                    return {'message': f"Invalid user id or password"}, 400
                if user:
                    try:
                        token = jwt.encode(
                            {"_uid": user._uid},
                            current_app.config["SECRET_KEY"],
                            algorithm="HS256"
                        )
                        access = "true"
                        resp = Response("Authentication for %s successful" % (user._uid))
                        resp.set_cookie("jwt", token,
                                max_age=3600,
                                secure=True,
                                httponly=True,
                                path='/',
                                samesite='None'  # This is the key part for cross-site requests

                                # domain="frontend.com"
                                )
                        return resp
                    except Exception as e:
                        current_app.logger.error('Error during authentication: %s', e)
                        return {'message': 'Internal server error'}, 500
                return {
                    "message": "Error fetching auth token!",
                    "data": None,
                    "error": "Unauthorized"
                }, 404
            except Exception as e:
                return {
                        "message": "Something went wrong!",
                        "error": str(e),
                        "data": None
                }, 500
    class _display(Resource):
        @token_required
        
        def get(self,current_user): # Read Method , current_user
            users = User.query.all()    # read/extract all users from database
            json_ready = [user.read() for user in users]  # prepare output in json
            return jsonify(json_ready)  # jsonify creates Flask response object, more specific to APIs than json.dumps
        
    
            
    # building RESTapi endpoint
    api.add_resource(_CRUD, '/')
    api.add_resource(_Security, '/authenticate')
    api.add_resource(_Delete, '/delete')
    api.add_resource(_display, '/display')