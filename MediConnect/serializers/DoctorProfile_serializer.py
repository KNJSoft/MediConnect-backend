from rest_framework import serializers
from ..models import DoctorProfile

class DoctorProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = DoctorProfile
        fields = '__all__'
        read_only_fields = ['id']
