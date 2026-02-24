from rest_framework import serializers
from ..models import PandemicSignal

class PandemicSignalSerializer(serializers.ModelSerializer):
    class Meta:
        model = PandemicSignal
        fields = '__all__'
        read_only_fields = ['id','last_detected']