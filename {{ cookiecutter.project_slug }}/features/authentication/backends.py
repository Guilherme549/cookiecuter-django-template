from django.contrib.auth.backends import ModelBackend as BaseModelBackend
from django.contrib.auth import get_user_model

UserModel = get_user_model()


class ModelBackend(BaseModelBackend):
    """
    This is implemented to replace the original without any change because if
    the original was setted in configurations, the django raises an error when the
    field on the UserModel.USERNAME_FIELD is not setted as unique. Our custom UserModel
    has an Constraint, but the changes order gots some error. In the future is possible that
    work-around is not not needed.

    The error is raised here:
    https://github.com/django/django/blob/main/django/contrib/auth/checks.py#L62

    An workaround is create an custom class without any new implementation and change the
    settings.
    """

    pass
