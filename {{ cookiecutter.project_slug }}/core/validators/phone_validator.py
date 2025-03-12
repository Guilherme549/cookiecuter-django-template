from django.core.validators import RegexValidator


class PhoneValidator(RegexValidator):
    regex = "^\\(\\d{2}\\) \\d{5}-\\d{4}$"
    message = "O valor não é um número de celular válido"


validate_phone = PhoneValidator()
