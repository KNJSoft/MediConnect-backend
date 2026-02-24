from rest_framework import generics

from MediConnect.permissions import IsAdmin
from ..models import Case
from ..serializers.Case_serializer import CaseSerializer
from ..permissions import *

# create case

class CaseCreate(generics.CreateAPIView):
    queryset = Case.objects.all()
    serializer_class = CaseSerializer
    permission_classes = [IsDoctorOrSuperAdmin]
    
    def perform_create(self, serializer):
        serializer.save(role=User.UserRole.DOCTOR)

    def get_queryset(self):
        return Case.objects.filter(role=User.UserRole.DOCTOR)

# get case

class CaseDetail(generics.RetrieveAPIView):
    queryset = Case.objects.all()
    serializer_class = CaseSerializer
    permission_classes = [IsDoctorOrAdminOrSuperAdmin,IsPatient]
    lookup_field = 'id'

# update case

class CaseUpdate(generics.UpdateAPIView):
    queryset = Case.objects.all()
    serializer_class = CaseSerializer
    permission_classes = [IsDoctorOrAdminOrSuperAdmin,IsPatient]
    lookup_field = 'id'

# delete case

class CaseDelete(generics.DestroyAPIView):
    queryset = Case.objects.all()
    serializer_class = CaseSerializer
    permission_classes = [IsDoctorOrAdminOrSuperAdmin,IsPatient]
    lookup_field = 'id'

# list all case

class CaseList(generics.ListAPIView):
    permission_classes = [IsAll]
    queryset = Case.objects.all()
    serializer_class = CaseSerializer

