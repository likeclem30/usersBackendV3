import http.client
from datetime import datetime, timedelta
from flask_restplus import Namespace, Resource
from users_backend import config
from users_backend.models import UserModel, bcrypt
from users_backend.token_validation import validate_token_header
from users_backend.token_validation import generate_token_header
from users_backend.db import db
from sqlalchemy import func
from flask import abort

api_namespace = Namespace('api', description='API operations')


def authentication_header_parser(value):
    username = validate_token_header(value, config.PUBLIC_KEY)
    if username is None:
        abort(401)
    return username


# Input and output formats for Users

authentication_parser = api_namespace.parser()
authentication_parser.add_argument('Authorization', location='headers',
                                   type=str,
                                   help='Bearer Access Token')

login_parser = api_namespace.parser()
login_parser.add_argument('username', type=str, required=True,
                          help='username')
login_parser.add_argument('password', type=str, required=True,
                          help='password')


@api_namespace.route('/login/')
class UserLogin(Resource):

    @api_namespace.doc('login')
    @api_namespace.expect(login_parser)
    def post(self):
        '''
        Login and return a valid Authorization header
        '''
        args = login_parser.parse_args()

        # Search for the user
        user = (UserModel
                .query
                .filter(UserModel.username == args['username'])
                .first())
        if not user:
            return '', http.client.UNAUTHORIZED

        # Check the password
        # REMEMBER, THIS IS NOT SAFE. DO NOT STORE PASSWORDS IN PLAIN
        auth_user = bcrypt.check_password_hash(user.password, args['password'])

        if not auth_user:
            return '', http.client.UNAUTHORIZED

        # Generate the header
        header = generate_token_header(user.username, config.PRIVATE_KEY)
        return {'Authorized': header}, http.client.OK


change_pw_parser = api_namespace.parser()
change_pw_parser.add_argument('username', type=str, required=True,
                              help='username')
change_pw_parser.add_argument('new_password', type=str, required=True,
                              help='new password')


@api_namespace.route('/update/')
class ChangePw(Resource):
    @api_namespace.doc('change password')
    @api_namespace.expect(change_pw_parser)
    def post(self):
        """
        Change a user password
        """

        args = change_pw_parser.parse_args()

        # Get user
        user = (UserModel
                .query
                .filter(UserModel.username == args['username'])
                .one())
        user.password = bcrypt.generate_password_hash(
                            args['new_password']
        ).decode('UTF-8')
        db.session.add(user)
        db.session.commit()

        return http.client.OK


dateQuery_parser = authentication_parser.copy()
dateQuery_parser.add_argument('startdate', type=str, required=True,
                              help="The start date format '%d/%m/%Y'")
dateQuery_parser.add_argument('enddate', type=str, required=True,
                              help="The end date format '%d/%m/%Y'")


@api_namespace.route('/datequery/')
class UsersDateQuery(Resource):

    @api_namespace.doc('query count in db')
    @api_namespace.expect(dateQuery_parser)
    def get(self):
        '''
        Help find  the daily signup within a range of dates
        '''
        args = dateQuery_parser.parse_args()
        authentication_header_parser(args['Authorization'])

        start_date_str = args['startdate']
        end_date_str = args['enddate']

        start_date = datetime.strptime(start_date_str, "%d/%m/%Y").date()

        end_date = datetime.strptime(end_date_str, "%d/%m/%Y").date()

        result = {}

        if start_date > end_date:
            return '', http.client.BAD_REQUEST

        while start_date <= end_date:

            user = (
                db.session
                .query(func.count(UserModel.id))
                .filter(func.date(UserModel.creation) == start_date)
                .all()
            )
            date = start_date.strftime("%d/%m/%Y")
            result[date] = user[0][0]

            start_date = start_date + timedelta(days=1)

        return result


@api_namespace.route('/sumquery/')
class UsersSummaryQuery(Resource):

    @api_namespace.doc('query count in db')
    @api_namespace.expect(authentication_parser)
    def get(self):
        '''
        Help find the sum of records in database
        '''
        args = authentication_parser.parse_args()
        authentication_header_parser(args['Authorization'])
        user = (
                UserModel
                .query
                .count()
            )

        return user
