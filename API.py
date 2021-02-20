import os

import requests
import json

from playhouse.shortcuts import model_to_dict
from flask_cors import CORS
import DB
from DB import User, VerifyCredentials, Cells, Product
from flask import Flask, request, jsonify, make_response, render_template, redirect
from functools import wraps
import Settings
import jwt
import uuid

app = Flask(__name__,template_folder=os.path.abspath('frontend'))
app.static_folder = 'frontend/static'
CORS(app)

def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):

        token = request.cookies.get('auth', default='', type=str)
        if not token:
            # return jsonify({'data': 'The auth token is missing.'}), 401
            return redirect('/'), 302
        try:
            tokenDecoded = jwt.decode(token, Settings.secret_key, algorithms='HS256')
        except jwt.exceptions.ExpiredSignatureError:
            # return jsonify({'data': 'The auth token has expired.'}), 401
            return redirect('/'),302
        except:
            # return jsonify({'data': "The auth token is invalid"}), 401
            return redirect('/'), 302
        current_user = User.select().where(User.public_id == tokenDecoded['public_id']).first()
        return func(current_user, *args, **kwargs)

    return decorated

@app.route('/', methods=['GET'])
def index():
    return render_template('login.html')
@app.route('/api/addUser', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'data': "You don't have permission for this action."})
    data = request.get_json()
    try:
        password = data['password']
        name = data['username']
        contact = data['contact']
        isadmin = data['admin']
        DB.AddUser(name, password, contact, (isadmin in ['true', 'True', '1', 'Yes']))
    except Exception as e:
        return jsonify({'data': str(e)}), 400
    return jsonify({'data': 'The user has been successfully registered!'}), 200


@app.route('/api/users', methods=['GET'])
@token_required
def get_all_users(current_user):
    #if not current_user.admin:
    #    return jsonify({'data': "You don't have permission for this action."})
    return jsonify(DB.GetUsersArr())


@app.route('/api/user/<public_id>', methods=['GET'])
@token_required
def get_single_user(current_user, public_id):
    if not current_user.admin or current_user.public_id != public_id:
        return jsonify({'data': "You don't have permission for this action."})
    user = DB.User.select().where(DB.User.public_id == public_id).first()
    if not user:
        return jsonify({'data': 'No user found.'}), 404
    user_dict = {}
    user_dict['public_id'] = user.public_id
    user_dict['contact'] = user.contact
    user_dict['name'] = user.name
    user_dict['admin'] = user.admin
    return jsonify(user_dict)


@app.route('/api/currentuser', methods=['GET'])
@token_required
def get_cur_usr(current_user):
    user_dict = {}
    user_dict['public_id'] = current_user.public_id
    user_dict['contact'] = current_user.contact
    user_dict['name'] = current_user.name
    user_dict['admin'] = current_user.admin
    return jsonify(user_dict)


@app.route('/api/user/<public_id>/delete', methods=['GET', 'POST'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'data': "You don't have permission for this action."})
    query = User.select().where(User.public_id == public_id).first()
    if not query:
        return jsonify({'data': 'No user found.'}), 404
    try:
        query.delete_instance()
    except Exception as e:
        return jsonify({'data': str(e)}), 401
    return jsonify({'data': 'The user has been successfully deleted!'}), 200


@app.route('/api/user/<public_id>/promote', methods=['GET', 'POST'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'data': "You don't have permission for this action."})
    query = User.select().where(User.public_id == public_id).first()
    if not query:
        return jsonify({'data': 'No user found.'}), 404
    try:
        query.admin = True
        query.save()
    except Exception as e:
        return jsonify({'data': str(e)}), 401
    return jsonify({'data': 'The user has been successfully promoted!'}), 200


@app.route('/api/user/<public_id>/downgrade', methods=['GET', 'POST'])
@token_required
def downgrade_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'data': "You don't have permission for this action."})
    query = User.select().where(User.public_id == public_id).first()
    if not query:
        return jsonify({'data': 'No user found.'}), 404
    try:
        query.admin = False
        query.save()
    except Exception as e:
        return jsonify({'data': str(e)}), 401
    return jsonify({'data': 'The user has been successfully downgraded!'}), 200


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    try:
        password = data['password']
        username = data['username']
    except Exception as e:
        return jsonify({'data': str(e)}), 400
    token = VerifyCredentials(username, password)
    if token:

        response = make_response()
        response.set_cookie("auth", token)
        response.set_data(token)
        response.location = request.url_root
        return response
    else:
        return jsonify({'data': 'Invalid username or password.'}),401


@app.route('/api/signup', methods=['POST', 'GET'])
def signup_with_token():
    args = request.args
    try:
        password = args.get(key='password')
        name = args.get(key='name')
        contact = args.get(key='contact')
        DB.AddUser(name, password, contact)
    except Exception as e:
        return jsonify({'data': str(e)}), 400
    return jsonify({'data': 'The user has been successfully registered!'}), 200


@app.route('/api/addRegToken')
@token_required
def add_new_tokens(current_user):
    if not current_user.admin:
        return jsonify({'data': "You don't have permission for this action."})
    args = request.args
    amount = args.get(key='count', default=1, type=int)
    codes = DB.AddRegCodes(amount)
    return '\n'.join([str(elem) for elem in codes])


@app.route('/api/addProducts', methods=['POST'])
@token_required
def add_products(current_user):  # TODO осуществить удаление товара
    data = request.get_json()
    if not data:
        return jsonify({'error':'Empty input.'})
    data.sort(key = lambda x: x['weight'],reverse = True)
    result = {'successful':[],'failed':[]}
    for product in data:
        id = str(uuid.uuid4())
        width = int(product['width'])
        height = int(product['height'])
        length = int(product['length'])
        weight = int(product['weight'])
        name = product['name']
        query = Cells.select().where((Cells.occupied==False) &
                                     (Cells.height>=height)&
                                     (
                                             ((Cells.length>=length) & (Cells.width>=width))|
                                             ((Cells.length>=width)& (Cells.width>=length)))
                                     ).order_by(Cells.floor).first()
        if (query):
            if requests.post(Settings.api_link, json=[
                {'uuid': id, 'destination': json.loads(query.arrayAddress)}]).status_code == 200:
                    cell = query
                    print(cell.floor)
                    Product.create(id=id,width = width, height = height, length = length,weight = weight,name=name).save()
                    cell.occupied = True
                    cell.product_id = id
                    cell.save()
                    result['successful'].append({'id':id,'name':name,'stringAddress':cell.string_address})
            else:
                result['failed'].append({'id': id, 'name': name})
        else:
            result['failed'].append({'id': id, 'name': name})

    return jsonify(result)
@app.route('/api/getProducts', methods=['GET'])
@token_required
def get_products(current_user):


    query = Cells.select().where((Cells.occupied==True))
    if (query.exists()):
        result = []
        for i in query:
            elem = model_to_dict(i)
            elem['product'] = model_to_dict(Product.select().where(Product.id == i.product_id).first())
            result.append(elem)
        return jsonify(result)
    else:
        return {'error':'the storage is empty'}
@app.route('/api/deleteProducts', methods=['POST',"DELETE"])
@token_required
def delete_products(current_user):
    data = request.get_json()
    if not data:
        return jsonify({'status':'error empty input'}),400
    query = Cells.select().where((Cells.occupied==True)&(Cells.product_id.in_(data)))

    if (query.exists()):

        for i in query:
            i.occupied=False
            i.save()
            x = requests.get(Settings.api_link+'/position',params = {'destination':[json.loads(i.arrayAddress)]})
        Product.delete().where((Product.id.in_(data))).execute()
        return {'status':'success'}
    else:
        return {'status':'error no such ids'},400

@app.route('/<name>')
def sendHtml(name):
    try:
        return render_template(name)
    except:
        return render_template('404.html'),404
def loadCells():
    data = requests.get(Settings.api_link + '/scheme').json()
    length = data['size']['size_x']
    height = data['size']['size_y']
    merged = data['merged']
    for number in range(1, height):
        for letter in ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I'][:length]:
            if not any(letter + str(number) in sublist for sublist in merged):
                Cells.create(floor=height - number + 1, width=1000, height=1000, length=1000,
                             string_address=letter + str(number),
                             arrayAddress=json.dumps([letter + str(number)])).save()
    for cell in merged:

        cell_length = 1000
        if len(cell) == 4:
            cell_height = 2000
            cell_width = 2000
        else:
            cell_height = 1000
            cell_width = 2000
        first_letter = cell[0][0]
        first_number = int(cell[0][1])
        last_letter = cell[-1][0]
        last_number = int(cell[-1][1])
        Cells.create(floor=height - last_number + 1, width=cell_width, length=cell_length, height=cell_height,
                     string_address=f'{first_letter}-{last_letter}{first_number}-{last_number}',
                     arrayAddress=json.dumps(cell)).save()


if __name__ == '__main__':
    loadCells()
    app.run(host='0.0.0.0', port=80)
