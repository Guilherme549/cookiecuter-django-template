from django.contrib import auth
from django.db import models
from django.db.models import Q
from django.utils import timezone
from django.contrib.auth.hashers import make_password
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from core.faker import fake


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        """
        Create and save a user with the given email and password.
        """
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.password = make_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email=None, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email=None, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self._create_user(email, password, **extra_fields)

    def with_perm(
        self, perm, is_active=True, include_superusers=True, backend=None, obj=None
    ):
        if backend is None:
            backends = auth._get_backends(return_tuples=True)
            if len(backends) == 1:
                backend, _ = backends[0]
            else:
                raise ValueError(
                    "You have multiple authentication backends configured and "
                    "therefore must provide the `backend` argument."
                )
        elif not isinstance(backend, str):
            raise TypeError(
                "backend must be a dotted import path string (got %r)." % backend
            )
        else:
            backend = auth.load_backend(backend)
        if hasattr(backend, "with_perm"):
            return backend.with_perm(
                perm,
                is_active=is_active,
                include_superusers=include_superusers,
                obj=obj,
            )
        return self.none()


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField("E-mail", unique=True, blank=True)
    name = models.CharField("Nome", max_length=160)
    is_staff = models.BooleanField(
        "Membro da Equipe?",
        default=False,
        help_text="Indica que usuário consegue acessar este site de administração.",
    )
    date_joined = models.DateTimeField("Data de registro", default=timezone.now)

    objects = UserManager()

    EMAIL_FIELD = "email"
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    @staticmethod
    def create_faker(data=None):
        data = data or {}

        if "password" in data:
            password = data.pop("password")
        else:
            password = None  

        data = {"email": fake.unique.email(), "name": fake.name(), **data}

        user = User.objects.create(**data)

        need_save = False

        if password:
            user.password = make_password(password)
            need_save = True

        if need_save:
            user.save()

        return user

    class Meta:
        verbose_name = "Usuário"
        verbose_name_plural = "Usuários"
        

class UserForgotPasswordToken(models.Model):
    usuario = models.ForeignKey("user.User", on_delete=models.CASCADE)
    token = models.CharField("Token", max_length=36)
    created_at = models.DateTimeField("Data de criação", auto_now_add=True)
    
    def save(self, *args, **kwargs):
        self.send_email()

        return super().save(*args, **kwargs)
    
    def send_email(self):
        email = ForgotPasswordEmail(
            context={
                "username": self.usuario.nome_razao_social,
                "token": self.token
            }
        )
        
        email.send(to_emails=[self.usuario.email])
    
    def is_valid(self):
        limit = self.created_at + timedelta(minutes=10)
        
        return limit > now()
