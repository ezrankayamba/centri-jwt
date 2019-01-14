# app/home/views.py

from flask import request, jsonify
from app import db, jwt, bcrypt
from . import users
from app.models import User, RevokedTokenModel
from flask_jwt_extended import (create_access_token, create_refresh_token,
                                jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return RevokedTokenModel.is_jti_blacklisted(jti)


@users.route('/registration', methods=['POST'])
def signup():
    data = request.json
    user = User.find_by_username(data['username'])
    if not user:
        user = User(
            username=data['username'],
            password=User.hash_pwd(data['password'])
        )
    else:
        return jsonify({
            'result': -1,
            'message': 'Failed registration for user(already exist): {}'.format(data['username'])
        }), 403

    try:
        user.save_to_db(update=False)
        return jsonify({
            'result': 0,
            'message': 'Successful registration for user: {}'.format(data['username'])
        })
    except Exception as e:
        return jsonify({
            'result': -1,
            'message': 'Failed registration for user: {}'.format(data['username']),
            'error': str(e)
        }), 500


@users.route('/changepwd', methods=['POST'])
@jwt_required
def change_pwd():
    current_user = get_jwt_identity()
    data = request.json
    if not current_user:
        return jsonify({
            'result': -1,
            'message': 'User not logged in!'
        }), 403

    try:
        user = User.find_by_username(current_user['username'])
        user.password = User.hash_pwd(data['password'])
        user.save_to_db(update=True)
        return jsonify({
            'result': 0,
            'message': 'Successful change password for user: {}'.format(data['username'])
        })
    except Exception as e:
        return jsonify({
            'result': -1,
            'message': 'Failed change password for user: {}'.format(data['username']),
            'error': str(e)
        }), 500


@users.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.find_by_username(data['username'])
    if not user:
        return jsonify({
            'result': -1,
            'message': 'Invalid username or password'
        }), 403

    res = User.check_pwd(user.password, data['password'])
    if not res:
        return jsonify({
            'result': -1,
            'message': 'Invalid username or password'
        }), 403
    identity = {'username': user.username, 'id': user.id, 'role': user.role}
    access_token = create_access_token(identity=identity)
    refresh_token = create_refresh_token(identity=identity)

    return jsonify({
        'result': 0,
        'message': 'Successful login',
        'access_token': access_token,
        'refresh_token': refresh_token
    })


@users.route('/logout/access', methods=['POST'])
@jwt_required
def logout_access():
    jti = get_raw_jwt()['jti']
    try:
        revoked_token = RevokedTokenModel(jti=jti)
        revoked_token.add()
        return jsonify({
            'result': 0,
            'message': 'Successful access logout'
        })
    except:
        return jsonify({
            'result': -1,
            'message': 'Invalid request'
        }), 500


@users.route('/user', methods=['GET'])
@jwt_required
def get_user():
    try:
        current_user = get_jwt_identity()
        return jsonify(logged_in_as=current_user), 200
    except:
        return jsonify({
            'result': -1,
            'message': 'Invalid request'
        }), 500


@users.route('/logout/refresh', methods=['POST'])
@jwt_refresh_token_required
def logout_refresh():
    jti = get_raw_jwt()['jti']
    try:
        revoked_token = RevokedTokenModel(jti=jti)
        revoked_token.add()
        return jsonify({
            'result': 0,
            'message': 'Successful refresh logout'
        })
    except:
        return jsonify({
            'result': -1,
            'message': 'Invalid request'
        }), 500


@users.route('/token/refresh', methods=['POST'])
@jwt_refresh_token_required
def token_refresh():
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)
    return jsonify({
        'result': 0,
        'message': 'Successful token refresh',
        'access_token': access_token
    })
