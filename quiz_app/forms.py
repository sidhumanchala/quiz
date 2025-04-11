from django import forms


class QuizSettingsForm(forms.Form):
    topic = forms.CharField(
        label="Quiz Topic",
        widget=forms.TextInput(attrs={
            'placeholder': 'Enter any quiz topic'
        })
    )

    num_questions = forms.IntegerField(
        label="Number of Questions",
        min_value=2,
        max_value=20,
        widget=forms.NumberInput(attrs={
            'placeholder': 'Between 2 and 20'
        })
    )

    timer = forms.IntegerField(
        label="Timer (in minutes)",
        min_value=1,
        max_value=60,
        widget=forms.NumberInput(attrs={
            'placeholder': '1 to 60 minutes'
        })
    )

    difficulty = forms.ChoiceField(choices=[
        ('easy', 'Easy'),
        ('medium', 'Medium'),
        ('hard', 'Hard')
    ])
    negative_marking = forms.BooleanField(required=False, label="Enable negative marking")