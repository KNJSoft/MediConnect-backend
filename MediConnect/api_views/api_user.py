from rest_framework import generics
from ..models import User,UserRole
from ..serializers.user_serializer import UserSerializer,MyTokenObtainPairSerializer
from ..permissions import *
from rest_framework_simplejwt.views import TokenObtainPairView
# create user patient

class UserPatientCreate(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    
    def perform_create(self, serializer):
        serializer.save(role=UserRole.PATIENT)

    def get_queryset(self):
        return User.objects.filter(role=UserRole.PATIENT)

# create user doctor

class UserDoctorCreate(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    
    def perform_create(self, serializer):
        serializer.save(role=UserRole.DOCTOR)

    def get_queryset(self):
        return User.objects.filter(role=UserRole.DOCTOR)

# create user admin

class UserAdminCreate(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    
    def perform_create(self, serializer):
        serializer.save(role=UserRole.ADMIN)

    def get_queryset(self):
        return User.objects.filter(role=UserRole.ADMIN)

# create user super admin

class UserSuperAdminCreate(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    
    def perform_create(self, serializer):
        serializer.save(role=UserRole.SUPER_ADMIN)

    def get_queryset(self):
        return User.objects.filter(role=UserRole.SUPER_ADMIN)
    
# list all users

class UserList(generics.ListAPIView):
    permission_classes = [IsDoctorOrAdminOrSuperAdmin]
    queryset = User.objects.all()
    serializer_class = UserSerializer
    
# update user

class UserUpdate(generics.UpdateAPIView):
    permission_classes = [IsAll]
    queryset = User.objects.all()
    serializer_class = UserSerializer
    lookup_field = 'id'

# delete user

class UserDelete(generics.DestroyAPIView):
    permission_classes = [IsSuperAdmin]
    queryset = User.objects.all()
    serializer_class = UserSerializer
    lookup_field = 'id'

# get user by id

class UserDetail(generics.RetrieveAPIView):
    permission_classes = [IsAll]
    queryset = User.objects.all()
    serializer_class = UserSerializer
    lookup_field = 'id'

# get user by email

class UserDetailByEmail(generics.RetrieveAPIView):
    permission_classes = [IsAll]
    queryset = User.objects.all()
    serializer_class = UserSerializer
    lookup_field = 'email'

    
# login user

class UserLogin(TokenObtainPairView):
    permission_classes = []
    queryset = User.objects.all()
    serializer_class = MyTokenObtainPairSerializer
    