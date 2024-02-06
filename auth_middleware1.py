from functools import wraps
import jwt
from flask import request, abort, jsonify
from flask import current_app
from model.users import User


def token_required1(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("jwt")
        if not token:
            return {
                "message": "Authentication Token is missing!",
                "data": None,
                "error": "Unauthorized"
            }, 401
        try:
            data=jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
            print("current_user:")
            print(User.query.filter_by(_uid=data["_uid"]).first())
            current_user=User.query.filter_by(_uid=data["_uid"]).first()
            print("current_user1:")
            print(current_user.uid)
            if current_user is None:
                return {
                "message": "Invalid Authentication token!",
                "data": None,
                "error": "Unauthorized"
            }, 401
        except Exception as e:
            return {
                "message": "Something went wrong",
                "data": None,
                "error": str(e)
            }, 500

        return f(current_user, *args, **kwargs)

    return decorated