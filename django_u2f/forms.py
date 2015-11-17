from django import forms


class KeyResponseForm(forms.Form):
    response = forms.CharField()
