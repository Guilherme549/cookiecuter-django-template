import re
from django.utils.deconstruct import deconstructible
from django.core.exceptions import ValidationError


@deconstructible
class CPFValidator:
    def __init__(self):
        pass

    def dv_maker(self, v):
        if v >= 2:
            return 11 - v
        return 0

    def __call__(self, cpf: str):
        if not re.match("^\\d{3}\\.\\d{3}\\.\\d{3}\\-\\d{2}$", cpf):
            raise ValidationError("Precisa estar no formato 999.999.999-99")

        cpf = cpf.replace(".", "").replace("-", "")

        orig_dv = cpf[-2:]
        new_1dv = sum([i * int(cpf[idx]) for idx, i in enumerate(range(10, 1, -1))])
        new_1dv = self.dv_maker(new_1dv % 11)
        cpf = cpf[:-2] + str(new_1dv) + cpf[-1]
        new_2dv = sum([i * int(cpf[idx]) for idx, i in enumerate(range(11, 1, -1))])
        new_2dv = self.dv_maker(new_2dv % 11)
        cpf = cpf[:-1] + str(new_2dv)
        if cpf[-2:] != orig_dv:
            raise ValidationError("O valor não é um CPF válido")
        if cpf.count(cpf[0]) == 11:
            raise ValidationError("O valor não é um CPF válido")


validate_cpf = CPFValidator()
