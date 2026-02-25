from django.contrib import admin
from .models import *
# from rest_framework_simplejwt.models import TokenUser

# Register your models here.
admin.site.register(User)
admin.site.register(Device)
admin.site.register(IP)
admin.site.register(KnowledgeBase)
admin.site.register(PandemicSignal)
admin.site.register(Case)
admin.site.register(DoctorProfile)
admin.site.register(Appointment)
admin.site.register(MedicalRecord)
admin.site.register(Message)
admin.site.register(DashboardInfo)

# user tokens
# admin.site.register(OutstandingToken)
# admin.site.register(TokenUser)

ets="MediConnect AI"
admin.site.site_header=ets
admin.site.site_title=ets
admin.site.index_title=ets

