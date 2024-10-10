from django.urls import path
from . import views

urlpatterns = [
    #path('',views.HelloNotesView.as_view(),name='hello_notes'),
    path('a/',views.NoteCreateListView.as_view(),name='notes'),
    path('get-note/<int:id>/',views.GetNote.as_view(),name='note_detail'),
    path('create-note/',views.PostNote.as_view()),
    path('update-note/<int:id>/',views.UpdateNote.as_view()),
    path('delete-note/<int:id>/',views.DeleteNote.as_view()),
    path('get-notes/',views.GetAllNotes.as_view(),name='note_detail'),
]