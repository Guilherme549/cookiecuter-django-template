# Parameterized Filters

A classe `ParameterizedFilterBackend` disponível em `core.filters.parameterized` foi construída como uma alternativa ao `django-filters` de modo que seja possível customizar, com facilidade, os nomes a serem utilizados nos filtros, reduzindo, desse modo, a complexidade na filtragem.

## Exemplo de uso

Em um `ModelViewSet` declare o `filter_backends` contendo o `ParameterizedFilterBackend`. Os parâmetros, por sua vez, são declarados no atributo `filter_params_query`, conforme o exemplo abaixo:

```python
from rest_framework.viewsets import ModelViewSet
from core.filters import ParameterizedFilterBackend

class UsersViewSet(ModelViewSet):
    serializer_class = UserSerializer
    filter_backends = [ParameterizedFilterBackend]
    filter_params_query = {
        'name': 'name__icontains',
        "street": "address__street__icontains",
        "state": "address__uf",
    }
    queryset = User.objects.all()
```

Assim, ao fazer uma requisição de listagem, enviar o parâmetro `?name=XPTO` teremos a filtragem no model, da forma: `User.objects.filter(name__icontains="XPTO")`. Do mesmo modo, se fizermos `?street=XPTO`, teremos: `User.objects.filter(address__street__icontains="XPTO")`.


## Benefícios

- Simplicidade, perto do `django-filters`.
- Documentação Swagger gerada automáticamente com o `drf-spectacular`.
