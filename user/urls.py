from django.urls import path
from . import views
from .views import UpdateUserByIdView

urlpatterns = [
    path('',views.HelloUserView.as_view(),name='hello_notes'),
    path('get-user/<int:user_id>/',views.GetUserByIdView.as_view(),name='note_detail'),
    path('update-user/<int:user_id>/', UpdateUserByIdView.as_view(), name='update_user_by_id'),
]