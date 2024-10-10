from django.contrib import admin
from .models import Note

# Register your models here.
@admin.register(Note)
class NoteAdmin(admin.ModelAdmin):
    list_display=['title','category','text','user']
    #the above line is a list that show title, category and other things above.
    list_filter=['title','category','user']
    