from rest_framework import generics
from ..permissions import IsAll, IsAdminOrSuperAdmin
from ..models import KnowledgeBase
from ..serializers.KnowledgeBase_serializer import KnowledgeBaseSerializer

class KnowledgeBaseCreate(generics.CreateAPIView):
    queryset = KnowledgeBase.objects.all()
    serializer_class = KnowledgeBaseSerializer
    permission_classes = [IsAll]
    
    def perform_create(self, serializer):
        serializer.save()


class KnowledgeBaseDetail(generics.RetrieveAPIView):
    queryset = KnowledgeBase.objects.all()
    serializer_class = KnowledgeBaseSerializer
    permission_classes = [IsAll]
    lookup_field = 'id'
    

class KnowledgeBaseUpdate(generics.UpdateAPIView):
    queryset = KnowledgeBase.objects.all()
    serializer_class = KnowledgeBaseSerializer
    permission_classes = [IsAll]
    lookup_field = 'id'


class KnowledgeBaseDelete(generics.DestroyAPIView):
    queryset = KnowledgeBase.objects.all()
    serializer_class = KnowledgeBaseSerializer
    permission_classes = [IsAdminOrSuperAdmin]
    lookup_field = 'id'
    

# list all knowledge base
class KnowledgeBaseList(generics.ListAPIView):
    permission_classes = [IsAll]
    queryset = KnowledgeBase.objects.all()
    serializer_class = KnowledgeBaseSerializer
    