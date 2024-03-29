'''
Test the User operations
'''
from unittest.mock import ANY
import http.client
from freezegun import freeze_time

from faker import Faker
fake = Faker()


@freeze_time('2019-05-07 13:47:34')
def test_create_user(client):
    new_user = {
        'username': fake.name(),
        'password': fake.password(length=15, special_chars=True),
    }
    response = client.post('/admin/users/', data=new_user)
    result = response.json

    assert http.client.CREATED == response.status_code

    expected = {
        'id': ANY,
        'username': new_user['username'],
        'creation': '2019-05-07T13:47:34',
    }
    assert result == expected


def test_login(client):
    USERNAME = fake.name()
    PASSWORD = fake.password(length=15, special_chars=True)
    new_user = {
        'username': USERNAME,
        'password': PASSWORD,
    }
    response = client.post('/admin/users/', data=new_user)
    assert http.client.CREATED == response.status_code

    response = client.post('/api/login/', data=new_user)
    result = response.json
    assert http.client.OK == response.status_code

    expected = {
        'Authorized': ANY,
    }
    assert result == expected


def test_wrong_password(client):
    USERNAME = fake.name()
    PASSWORD = fake.password(length=15, special_chars=True)
    new_user = {
        'username': USERNAME,
        'password': PASSWORD,
    }
    response = client.post('/admin/users/', data=new_user)
    assert http.client.CREATED == response.status_code

    fake_user = {
        'username': new_user['username'],
        'password': fake.password(length=15, special_chars=True),
    }
    response = client.post('/api/login/', data=fake_user)
    assert http.client.UNAUTHORIZED == response.status_code


def test_change_password(client):
    USERNAME = fake.name()
    PASSWORD = fake.password(length=15, special_chars=True)
    new_user = {
        'username': USERNAME,
        'password': PASSWORD,
    }
    response = client.post('/admin/users/', data=new_user)
    assert http.client.CREATED == response.status_code

    response = client.post('/api/login/', data=new_user)
    result = response.json
    assert http.client.OK == response.status_code

    expected = {
        'Authorized': ANY,
    }
    assert result == expected

    new_pw = {
        'username': USERNAME,
        'new_password': fake.password(length=15, special_chars=True),
    }
    response = client.post('/api/update/', data=new_pw)
    assert http.client.OK == response.status_code


def test_changed_password_login(client):
    USERNAME = fake.name()
    PASSWORD = fake.password(length=15, special_chars=True)
    new_user = {
        'username': USERNAME,
        'password': PASSWORD,
    }
    response = client.post('/admin/users/', data=new_user)
    assert http.client.CREATED == response.status_code

    response = client.post('/api/login/', data=new_user)
    result = response.json
    assert http.client.OK == response.status_code

    expected = {
        'Authorized': ANY,
    }
    assert result == expected

    new_pw = {
        'username': USERNAME,
        'new_password': fake.password(length=15, special_chars=True),
    }
    response = client.post('/api/update/', data=new_pw)
    assert http.client.OK == response.status_code

    user = {
        'username': USERNAME,
        'password': new_pw['new_password'],
    }
    response = client.post('/api/login/', data=user)
    result = response.json
    assert http.client.OK == response.status_code

    expected = {
        'Authorized': ANY,
    }
    assert result == expected
