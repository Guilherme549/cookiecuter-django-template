# drf_rw_serializers

A biblioteca traz customizações dos `ViewSet's` para facilitar a separação de `serializers` para leitura e escrita.

## Exemplo de uso

```python
from drf_rw_serializers import mixins
from drf_rw_serializers.viewsets import GenericViewSet
from .models import UserSubscription
from .serializers import (
    UserSubscriptionWriteSerializer,
    UserSubscriptionReadSerializer,
)

@extend_schema(tags=['subscriptions'])
class UserSubscriptionViewSet(mixins.CreateModelMixin, GenericViewSet):
    write_serializer_class = UserSubscriptionWriteSerializer
    read_serializer_class = UserSubscriptionReadSerializer
    queryset = UserSubscription.objects.all()
```
