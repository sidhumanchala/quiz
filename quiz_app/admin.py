from django.contrib import admin
from .models import Register

# Register your models here.
@admin.register(Register)
class RegisterAdmin(admin.ModelAdmin):
    list_display = ('full_name', 'email','created_at')
    search_fields = ('full_name', 'email','created_at')
    list_filter = ('full_name','created_at')  # Filter options
