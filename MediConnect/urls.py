from django.urls import path
from .views import *
urlpatterns = [
    # views
    path('',patient_index,name='patient_index'),
    path('signup/',signup_view,name='signup'),
    path('login/',login_view,name='login'),
    path('logout/',logout_view,name='logout'),
    path('appointment/',appointment_view,name='appointment'),
    path('my-appointments/',my_appointments,name='my_appointments'),
    path('my-messages/',my_messages,name='my_messages'),
    path('my-records/',my_records,name='my_records'),
    path('my-cases/',my_cases,name='my_cases'),
    path('submit-case/',submit_case,name='submit_case'),
    path('profile/',profile,name='profile'),
]