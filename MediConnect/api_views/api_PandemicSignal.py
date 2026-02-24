from rest_framework import generics
from ..permissions import IsAll, IsAdminOrSuperAdmin
from ..models import PandemicSignal
from ..serializers.PandemicSignal_serializer import PandemicSignalSerializer


class PandemicSignalCreate(generics.CreateAPIView):
    queryset = PandemicSignal.objects.all()
    serializer_class = PandemicSignalSerializer
    permission_classes = [IsAll]
    
    def perform_create(self, serializer):
        serializer.save()


class PandemicSignalDetail(generics.RetrieveAPIView):
    queryset = PandemicSignal.objects.all()
    serializer_class = PandemicSignalSerializer
    permission_classes = [IsAll]
    lookup_field = 'id'
    


class PandemicSignalUpdate(generics.UpdateAPIView):
    queryset = PandemicSignal.objects.all()
    serializer_class = PandemicSignalSerializer
    permission_classes = [IsAll]
    lookup_field = 'id'


class PandemicSignalDelete(generics.DestroyAPIView):
    queryset = PandemicSignal.objects.all()
    serializer_class = PandemicSignalSerializer
    permission_classes = [IsAdminOrSuperAdmin]
    lookup_field = 'id'


# list all pandemic signal
class PandemicSignalList(generics.ListAPIView):
    permission_classes = [IsAll]
    queryset = PandemicSignal.objects.all()
    serializer_class = PandemicSignalSerializer
