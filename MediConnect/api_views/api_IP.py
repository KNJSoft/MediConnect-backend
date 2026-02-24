from rest_framework import generics
from ..permissions import IsAll, IsAdminOrSuperAdmin
from ..models import IP
from ..serializers.IP_serializer import IPSerializer


class IPCreate(generics.CreateAPIView):
    queryset = IP.objects.all()
    serializer_class = IPSerializer
    permission_classes = [IsAll]
    
    def perform_create(self, serializer):
        serializer.save()
    
    
class IPDetail(generics.RetrieveAPIView):
    queryset = IP.objects.all()
    serializer_class = IPSerializer
    permission_classes = [IsAll]
    lookup_field = 'id'
    

class IPUpdate(generics.UpdateAPIView):
    queryset = IP.objects.all()
    serializer_class = IPSerializer
    permission_classes = [IsAll]
    lookup_field = 'id'
    
    
class IPDelete(generics.DestroyAPIView):
    queryset = IP.objects.all()
    serializer_class = IPSerializer
    permission_classes = [IsAdminOrSuperAdmin]
    lookup_field = 'id'
    

# list all ip
class IPList(generics.ListAPIView):
    permission_classes = [IsAll]
    queryset = IP.objects.all()
    serializer_class = IPSerializer
