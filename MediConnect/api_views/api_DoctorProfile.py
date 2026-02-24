from rest_framework import generics

from MediConnect.permissions import IsAdminOrSuperAdmin, IsDoctorOrAdminOrSuperAdmin
from ..models import DoctorProfile
from ..serializers.DoctorProfile_serializer import DoctorProfileSerializer
from ..permissions import *

# create doctor profile
class DoctorProfileCreate(generics.CreateAPIView):
    queryset = DoctorProfile.objects.all()
    serializer_class = DoctorProfileSerializer
    permission_classes = [IsAdminOrSuperAdmin]
    
    def perform_create(self, serializer):
        serializer.save()

    def get_queryset(self):
        return DoctorProfile.objects.all()

# get doctor profile

class DoctorProfileDetail(generics.RetrieveAPIView):
    queryset = DoctorProfile.objects.all()
    serializer_class = DoctorProfileSerializer
    permission_classes = [IsAdminOrSuperAdmin]
    lookup_field = 'id'
    
# update doctor profile

class DoctorProfileUpdate(generics.UpdateAPIView):
    queryset = DoctorProfile.objects.all()
    serializer_class = DoctorProfileSerializer
    permission_classes = [IsDoctorOrAdminOrSuperAdmin]
    lookup_field = 'id'
    
# delete doctor profile

class DoctorProfileDelete(generics.DestroyAPIView):
    queryset = DoctorProfile.objects.all()
    serializer_class = DoctorProfileSerializer
    permission_classes = [IsAdminOrSuperAdmin]
    lookup_field = 'id'


# list all doctor profile
class DoctorProfileList(generics.ListAPIView):
    permission_classes = [IsAll]
    queryset = DoctorProfile.objects.all()
    serializer_class = DoctorProfileSerializer
