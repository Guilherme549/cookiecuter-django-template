from django.core.validators import RegexValidator


class PostalCodeValidator(RegexValidator):
    regex = "^\\d{5}-\\d{3}$"
    message = "O valor não é um CEP válido"


validate_postal_code = PostalCodeValidator()
