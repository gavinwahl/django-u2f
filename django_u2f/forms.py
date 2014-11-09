import django
from django import forms
from django.core.exceptions import ValidationError, NON_FIELD_ERRORS


class KeyResponseForm(forms.Form):
    response = forms.CharField()

    if django.get_version() < (1, 7):
        def add_error(self, field, error):
            """
            Update the content of `self._errors`.

            The `field` argument is the name of the field to which the errors
            should be added. If its value is None the errors will be treated as
            NON_FIELD_ERRORS.

            The `error` argument can be a single error, a list of errors, or a
            dictionary that maps field names to lists of errors. What we define as
            an "error" can be either a simple string or an instance of
            ValidationError with its message attribute set and what we define as
            list or dictionary can be an actual `list` or `dict` or an instance
            of ValidationError with its `error_list` or `error_dict` attribute set.

            If `error` is a dictionary, the `field` argument *must* be None and
            errors will be added to the fields that correspond to the keys of the
            dictionary.
            """
            if not isinstance(error, ValidationError):
                # Normalize to ValidationError and let its constructor
                # do the hard work of making sense of the input.
                error = ValidationError(error)

            if hasattr(error, 'error_dict'):
                if field is not None:
                    raise TypeError(
                        "The argument `field` must be `None` when the `error` "
                        "argument contains errors for multiple fields."
                    )
                else:
                    error = error.error_dict
            else:
                error = {field or NON_FIELD_ERRORS: error.error_list}

            for field, error_list in error.items():
                if field not in self.errors:
                    if field != NON_FIELD_ERRORS and field not in self.fields:
                        raise ValueError(
                            "'%s' has no field named '%s'." % (self.__class__.__name__, field))
                    self._errors[field] = self.error_class()
                self._errors[field].extend(error_list)
                if field in self.cleaned_data:
                    del self.cleaned_data[field]
