from django.urls import reverse
from django.contrib.auth.hashers import check_password
from core.tests import APITestCase
from features.user.models import User


class ChangePasswordAPITestCase(APITestCase):
    def setUp(self):
        self.url = reverse("change-password")
        self.password = "my-new-password"
        self.user = User.create_faker(
            {"password": self.password, "update_password": True}
        )

    def test_change_password_unauthenticated(self):
        data = {
            "password1": self.password,
            "password2": self.password,
        }
        response = self.client.put(self.url, data)
        self.assertResponseNotAuthenticated(response)

        user = User.objects.get(pk=self.user.pk)
        self.assertTrue(user.update_password)

    def test_change_password(self):
        password = "any-here-que"
        data = {
            "password1": password,
            "password2": password,
        }
        self.authenticate(self.user)
        response = self.client.put(self.url, data)

        self.assertEqual(response.status_code, 200)
        user = User.objects.get(pk=self.user.pk)
        self.assertTrue(check_password(password, user.password))
        self.assertFalse(check_password(self.password, user.password))
        self.assertFalse(user.update_password)

    def test_change_password_unconfirmed(self):
        password = "any-here-que"
        data = {
            "password1": password,
            "password2": "password",
        }
        self.authenticate(self.user)
        response = self.client.put(self.url, data)
        self.assertResponseValidationError(
            response, "password2", "As duas senhas não conferem."
        )

        user = User.objects.get(pk=self.user.pk)
        self.assertTrue(user.update_password)
