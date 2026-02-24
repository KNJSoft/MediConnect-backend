from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView
from .api_views.api_user import *
from .api_views.api_Device import *
from .api_views.api_IP import *
from .api_views.api_KnowledgeBase import *
from .api_views.api_PandemicSignal import *
from .api_views.api_Case import *
from .api_views.api_DoctorProfile import *
urlpatterns = [
    # user
    path('user/login',UserLogin.as_view(),name='user_login'),
    path('user/patient',UserPatientCreate.as_view(),name='user_patient'),
    path('user/doctor',UserDoctorCreate.as_view(),name='user_doctor'),
    path('user/admin',UserAdminCreate.as_view(),name='user_admin'),
    path('user/superadmin',UserSuperAdminCreate.as_view(),name='user_superadmin'),
    path('user/list',UserList.as_view(),name='user_list'),
    path('user/update/<int:id>',UserUpdate.as_view(),name='user_update'),
    path('user/delete/<int:id>',UserDelete.as_view(),name='user_delete'),
    path('user/detail/<int:id>',UserDetail.as_view(),name='user_detail'),
    path('user/detail/email/<str:email>',UserDetailByEmail.as_view(),name='user_detail_by_email'),

    # device
    path('device/create',DeviceCreate.as_view(),name='device_create'),
    path('device/detail/<int:id>',DeviceDetail.as_view(),name='device_detail'),
    path('device/update/<int:id>',DeviceUpdate.as_view(),name='device_update'),
    path('device/delete/<int:id>',DeviceDelete.as_view(),name='device_delete'),
    path('device/list',DeviceList.as_view(),name='device_list'),
    
    # ip
    path('ip/create',IPCreate.as_view(),name='ip_create'),
    path('ip/detail/<int:id>',IPDetail.as_view(),name='ip_detail'),
    path('ip/update/<int:id>',IPUpdate.as_view(),name='ip_update'),
    path('ip/delete/<int:id>',IPDelete.as_view(),name='ip_delete'),
    path('ip/list',IPList.as_view(),name='ip_list'),
    
    # knowledge base
    path('knowledge-base/create',KnowledgeBaseCreate.as_view(),name='knowledge_base_create'),
    path('knowledge-base/detail/<int:id>',KnowledgeBaseDetail.as_view(),name='knowledge_base_detail'),
    path('knowledge-base/update/<int:id>',KnowledgeBaseUpdate.as_view(),name='knowledge_base_update'),
    path('knowledge-base/delete/<int:id>',KnowledgeBaseDelete.as_view(),name='knowledge_base_delete'),
    path('knowledge-base/list',KnowledgeBaseList.as_view(),name='knowledge_base_list'),

    # PandemicSignal
    path('pandemic-signal/create',PandemicSignalCreate.as_view(),name='pandemic_signal_create'),
    path('pandemic-signal/detail/<int:id>',PandemicSignalDetail.as_view(),name='pandemic_signal_detail'),
    path('pandemic-signal/update/<int:id>',PandemicSignalUpdate.as_view(),name='pandemic_signal_update'),
    path('pandemic-signal/delete/<int:id>',PandemicSignalDelete.as_view(),name='pandemic_signal_delete'),
    path('pandemic-signal/list',PandemicSignalList.as_view(),name='pandemic_signal_list'),

    # Case
    path('case/create',CaseCreate.as_view(),name='case_create'),
    path('case/detail/<int:id>',CaseDetail.as_view(),name='case_detail'),
    path('case/update/<int:id>',CaseUpdate.as_view(),name='case_update'),
    path('case/delete/<int:id>',CaseDelete.as_view(),name='case_delete'),
    path('case/list',CaseList.as_view(),name='case_list'),

    # doctor
    path('doctor/create',DoctorProfileCreate.as_view(),name='doctor_profile_create'),
    path('doctor/detail/<int:id>',DoctorProfileDetail.as_view(),name='doctor_profile_detail'),
    path('doctor/update/<int:id>',DoctorProfileUpdate.as_view(),name='doctor_profile_update'),
    path('doctor/delete/<int:id>',DoctorProfileDelete.as_view(),name='doctor_profile_delete'),
    path('doctor/list',DoctorProfileList.as_view(),name='doctor_profile_list'),
]