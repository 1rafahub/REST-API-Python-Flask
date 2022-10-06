from flask_restful import Resource, reqparse
from sqlalchemy import Identity
from blacklist import BLACKLIST
from models.usuario import UserlModel
from flask_jwt_extended import create_access_token, get_jwt, jwt_required
from werkzeug.security import safe_str_cmp
from blacklist import BLACKLIST

# import hmac

# str_to_bytes = lambda s: s.encode("utf-8") if isinstance(s, str) else s 
# safe_str_cmp = lambda a, b: hmac.compare_digest(str_to_bytes(a), str_to_bytes(b))

atributos = reqparse.RequestParser()
atributos.add_argument('login', type=str,  help="The field 'login' cannot be left blank")
atributos.add_argument('senha', type=str,  help="The field 'senha' cannot be left blank")


class User(Resource):
 #/usuario/{user_id}
    def get(self, user_id):
        user = UserlModel.find_user(user_id)
        if user:
            return user.json() 
        
        return {'message': 'User not found.'}, 404

    @jwt_required()
    def delete(self, user_id):
        user = UserlModel.find_user(user_id)
        if user:
            try:
                user.delete_user()
            
            except:
                return {'message': 'An error ocurred trying to delete user.'}, 500
            return {'message' : 'User deleted!'}
        
        return {'message' : 'Hotel not found.'}, 404


class UserRegister(Resource):
    #/cadastro
    def post(self):

        dados = atributos.parse_args()

        if UserlModel.find_by_login(dados['login']):
            return {'message' : "The login '{}' already exists.".format(dados['login'])}

        user = UserlModel(**dados)
        user.save_user()
        return {'message' : 'User created successfully!'}, 201

class UserLogin(Resource):

    @classmethod
    def post(cls):
        dados = atributos.parse_args()

        user = UserlModel.find_by_login(dados['login'])

        if user and safe_str_cmp(user.senha, dados['senha']):
            token_acess = create_access_token(identity=user.user_id)
            return {'access_token' : token_acess}, 200

        return{'message'  : 'The user name or password is incorrect'}, 401

class UserLogout(Resource):

    @jwt_required()
    def post(self):
        jwt_id = get_jwt()['jti']
        BLACKLIST.add(jwt_id)
        return {'message' : 'Logged out successgully'}, 200