from django.db.models.constants import LOOKUP_SEP
from django.core.exceptions import FieldDoesNotExist
from django.db.models.fields.related import ForeignObjectRel, RelatedField

def get_field_parts(model, field_name):
    """
    Get the field parts that represent the traversable relationships from the
    base ``model`` to the final field, described by ``field_name``.

    ex::

        >>> parts = get_field_parts(Book, 'author__first_name')
        >>> [p.verbose_name for p in parts]
        ['author', 'first name']

    """
    parts = field_name.split(LOOKUP_SEP)
    opts = model._meta
    fields = []
    lookup = None

    # walk relationships
    for name in parts:
        try:
            field = opts.get_field(name)
        except FieldDoesNotExist:
            if not fields:
                return None, None
            last_field = fields[-1]
            lookup = last_field._get_lookup(name)
            if not lookup:
                return None, None
            continue

        fields.append(field)
        try:
            if isinstance(field, RelatedField):
                opts = field.remote_field.model._meta
            elif isinstance(field, ForeignObjectRel):
                opts = field.related_model._meta
        except AttributeError:
            # Lazy relationships are not resolved until registry is populated.
            raise RuntimeError(
                "Unable to resolve relationship `%s` for `%s`. Django is most "
                "likely not initialized, and its apps registry not populated. "
                "Ensure Django has finished setup before loading `FilterSet`s."
                % (field_name, model._meta.label)
            )

    return fields, lookup

