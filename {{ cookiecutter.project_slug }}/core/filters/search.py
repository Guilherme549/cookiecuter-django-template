from rest_framework import filters


class SearchFilter(filters.SearchFilter):
    """
    Customize the django rest_framework SearchFilter to search by
    field__icontain="My large term" instread of field__icontains="My" AND
    field__icontains="large" AND field__icontains="term".
    """

    def get_search_terms(self, request):
        """
        Search terms are set by a ?search=... query parameter,
        and may be comma and/or whitespace delimited.
        """
        params = request.query_params.get(self.search_param, '')
        params = params.replace('\x00', '')  # strip null characters
        params = params.replace(',', ' ')
        return [params]
