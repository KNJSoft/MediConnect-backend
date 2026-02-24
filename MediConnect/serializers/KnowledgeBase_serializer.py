from rest_framework import serializers
from ..models import KnowledgeBase

class KnowledgeBaseSerializer(serializers.ModelSerializer):
    class Meta:
        model = KnowledgeBase
        fields = '__all__'
        read_only_fields = ['id','frequency']
