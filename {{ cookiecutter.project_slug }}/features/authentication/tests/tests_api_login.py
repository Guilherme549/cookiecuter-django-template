from django.contrib.auth import get_user_model
from django.urls import reverse
from core.tests import APITestCase
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework_simplejwt.utils import datetime_from_epoch

User = get_user_model()


class LoginAPITestCase(APITestCase):
    url = reverse("token_obtain")
    refresh_url = reverse("token_refresh")

    def setUp(self):
        self.password = "any-password-here"
        self.user = User.create_faker({"password": self.password})

    def test_wrong_email(self):
        data = {"email": "anywrong@email.com.br", "password": "any-password"}

        response = self.client.post(self.url, data)
        response_data = response.json()

        self.assertEqual(response.status_code, 401)
        self.assertIsNotNone(response_data.get("detail"))

    def test_empty_email(self):
        data = {"email": "", "password": "any-password"}

        response = self.client.post(self.url, data)
        response_data = response.json()

        self.assertEqual(response.status_code, 400)
        self.assertIsNotNone(response_data.get("email"))
        self.assertTrue(len(response_data.get("email")) == 1)

    def test_wrong_password(self):
        data = {
            "email": self.user.email,
            "password": "wrong-password",
        }
        response = self.client.post(self.url, data)
        response_data = response.json()

        self.assertEqual(response.status_code, 401)
        self.assertIsNotNone(response_data.get("detail"))

    def test_empty_password(self):
        data = {"email": self.user.email, "password": ""}

        response = self.client.post(self.url, data)
        response_data = response.json()

        self.assertEqual(response.status_code, 400)
        self.assertIsNotNone(response_data.get("password"))
        self.assertTrue(len(response_data.get("password")) == 1)

    def test_correct_credentials(self):
        data = {
            "email": self.user.email,
            "password": self.password,
        }
        response = self.client.post(self.url, data)
        response_data = response.json()

        self.assertEqual(response.status_code, 200)

        refresh = response_data.get("refresh")
        access = response_data.get("access")

        refresh_token = RefreshToken(refresh)
        refresh_exp = datetime_from_epoch(refresh_token.payload.get("exp"))
        refresh_iat = datetime_from_epoch(refresh_token.payload.get("iat"))
        access_token = AccessToken(access)
        access_exp = datetime_from_epoch(access_token.payload.get("exp"))
        access_iat = datetime_from_epoch(access_token.payload.get("iat"))

        self.assertEqual(refresh_token.payload.get("user_id"), self.user.id)
        self.assertEqual(access_token.payload.get("user_id"), self.user.id)
        self.assertEqual((access_exp - access_iat).total_seconds(), 300)
        self.assertEqual((refresh_exp - refresh_iat).total_seconds(), 86400)

        user = response_data.get("user")

        self.assertIsNotNone(refresh)
        self.assertIsNotNone(access)
        self.assertIsNotNone(user)

        email = user.get("email")
        name = user.get("name")
        id = user.get("id")

        self.assertEqual(id, self.user.id)
        self.assertEqual(name, self.user.name)
        self.assertEqual(email, self.user.email)

    def test_refresh_token_valid(self):
        token = str(RefreshToken.for_user(self.user))
        data = {
            "refresh": token,
        }
        response = self.client.post(self.refresh_url, data)
        response_data = response.json()

        self.assertEqual(response.status_code, 200)
        access = response_data.get("access")
        access_token = AccessToken(access)
        access_exp = datetime_from_epoch(access_token.payload.get("exp"))
        access_iat = datetime_from_epoch(access_token.payload.get("iat"))
        self.assertEqual(access_token.payload.get("user_id"), self.user.id)
        self.assertEqual((access_exp - access_iat).total_seconds(), 300)
