from django.db import models
from rest_framework.filters import BaseFilterBackend
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter
from drf_spectacular.plumbing import build_basic_type, build_parameter_type
from .utils import get_field_parts

class ParameterizedFilterBackend(BaseFilterBackend):
    def get_params(self, view, request):
        queries = getattr(view, "filter_params_query", {})
        return list(queries.keys())

    def get_params_filter_query(self, view, request):
        return getattr(view, "filter_params_query", {})

    def get_search_params_names(self, view, request):
        params = {}
        raw_params = self.get_params(view, request)
        for param in raw_params:
            param_name = getattr(view, "%s_param" % param, None)
            if not param_name:
                param_name = param

            params[param] = param_name

        return params

    def get_param_value(self, request, param_name):
        value = request.query_params.get(param_name, "")
        value = value.replace("\x00", "")
        value = value.replace(",", " ")
        return value

    def get_search_params_values(self, names: dict, request):
        values = {}
        for name in names.keys():
            values[name] = self.get_param_value(request, names[name])
        return values

    def filter_queryset(self, request, queryset, view):
        names = self.get_search_params_names(view, request)
        query_names = self.get_params_filter_query(view, request)
        values = self.get_search_params_values(names, request)

        queryset_dict = {}
        for item in names.keys():
            if not values[item]:
                continue
            queryset_dict[query_names[item]] = values[item]

        if len(queryset_dict.keys()) == 0:
            return queryset

        return queryset.filter(**queryset_dict)

    def get_schema_operation_parameters(self, view):
        raw_params = self.get_params(view, None)
        query_names = self.get_params_filter_query(view, None)
        queryset = view.get_queryset()
        model = queryset.model

        unambiguous_mapping = {
            models.CharField: OpenApiTypes.STR,
            models.SlugField: OpenApiTypes.STR,
            models.URLField: OpenApiTypes.STR,
            models.EmailField: OpenApiTypes.STR,
            models.IPAddressField: OpenApiTypes.STR,
            models.GenericIPAddressField: OpenApiTypes.STR,
            models.FilePathField: OpenApiTypes.STR,
            models.FileField: OpenApiTypes.STR,
            models.ImageField: OpenApiTypes.STR,
            models.TextField: OpenApiTypes.STR,
            models.BooleanField: OpenApiTypes.BOOL,
            models.DateField: OpenApiTypes.DATE,
            models.DateTimeField: OpenApiTypes.DATETIME,
            models.TimeField: OpenApiTypes.TIME,
            models.UUIDField: OpenApiTypes.UUID,
            models.DurationField: OpenApiTypes.DURATION,
            models.IntegerField: OpenApiTypes.INT,
            models.BigIntegerField: OpenApiTypes.INT,
            models.SmallIntegerField: OpenApiTypes.INT,
            models.PositiveBigIntegerField: OpenApiTypes.INT,
            models.PositiveIntegerField: OpenApiTypes.INT,
            models.PositiveSmallIntegerField: OpenApiTypes.INT,
            models.FloatField: OpenApiTypes.FLOAT,
            models.DecimalField: OpenApiTypes.DECIMAL,
        }

        params = []
        for param in raw_params:
            field = query_names[param]
            if not field:
                continue
            
            field_parts, lookup = get_field_parts(model, field)
            if not field_parts:
                continue

            last_field = field_parts[-1]
            lookup_name = lookup.lookup_name if lookup is not None else ""
            
            if not last_field.__class__ in unambiguous_mapping:
                continue

            description = "Filtrar por "
            for i in range(0, len(field_parts)):
                part = field_parts[-1 - i]
                description += part.verbose_name
                if i + 1 < len(field_parts):
                    description += " no objeto relacionado: "
            
            if lookup_name:
                description += f" (com o lookup: {lookup_name})"

            open_api_type = unambiguous_mapping[last_field.__class__]
            schema = build_basic_type(open_api_type)
            enum = None
            if last_field.choices and not lookup:
                enum = [value for value, _ in last_field.choices]

            print(enum)

            params += [
                build_parameter_type(
                    name=param,
                    required=False,
                    location=OpenApiParameter.QUERY,
                    description=description,
                    schema=schema,
                    enum=enum,
                )
            ]

        return params

__all__ = ["ParameterizedFilterBackend"]
