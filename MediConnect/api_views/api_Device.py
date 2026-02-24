from rest_framework import generics
from ..permissions import IsAll, IsAdminOrSuperAdmin
from ..models import Device
from ..serializers.Device_serializer import DeviceSerializer


class DeviceCreate(generics.CreateAPIView):
    queryset = Device.objects.all()
    serializer_class = DeviceSerializer
    permission_classes = [IsAll]
    
    def perform_create(self, serializer):
        serializer.save()
    
    
class DeviceDetail(generics.RetrieveAPIView):
    queryset = Device.objects.all()
    serializer_class = DeviceSerializer
    permission_classes = [IsAll]
    lookup_field = 'id'
    

class DeviceUpdate(generics.UpdateAPIView):
    queryset = Device.objects.all()
    serializer_class = DeviceSerializer
    permission_classes = [IsAll]
    lookup_field = 'id'
    

class DeviceDelete(generics.DestroyAPIView):
    queryset = Device.objects.all()
    serializer_class = DeviceSerializer
    permission_classes = [IsAdminOrSuperAdmin]
    lookup_field = 'id'

# list all device
class DeviceList(generics.ListAPIView):
    permission_classes = [IsAll]
    queryset = Device.objects.all()
    serializer_class = DeviceSerializer
