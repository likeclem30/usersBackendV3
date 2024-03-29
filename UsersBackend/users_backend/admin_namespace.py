import http.client
from flask_restplus import Namespace, Resource, fields
from datetime import datetime
from users_backend.models import UserModel, bcrypt
from users_backend.db import db
from sqlalchemy.exc import IntegrityError

admin_namespace = Namespace('admin', description='Admin operations')


model = {
    'id': fields.Integer(),
    'username': fields.String(),
    # DO NOT RETURN THE PASSWORD!!!
    'creation': fields.DateTime(),
}
user_model = admin_namespace.model('User', model)


user_parser = admin_namespace.parser()
user_parser.add_argument('username', type=str, required=True,
                         help='Username')
user_parser.add_argument('password', type=str, required=True,
                         help='Password')


@admin_namespace.route('/users/')
class UserCreate(Resource):

    @admin_namespace.expect(user_parser)
    @admin_namespace.marshal_with(user_model, code=http.client.CREATED)
    def post(self):
        '''
        Create a new user
        '''
        args = user_parser.parse_args()
        # password = args['password']

        """# Hash and Salt Password
        password_hash = bcrypt.generate_password_hash(password)\
            .decode('UTF-8')"""

        new_user = UserModel(username=args['username'],
                             password=args['password'],
                             creation=datetime.utcnow())
        db.session.add(new_user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            result = {'result': 'Username already exists, try another one'}
            return result, http.client.UNPROCESSABLE_ENTITY

        result = admin_namespace.marshal(new_user, user_model)

        return result, http.client.CREATED
