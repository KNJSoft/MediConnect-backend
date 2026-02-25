from django.shortcuts import render
from .models import DashboardInfo, Appointment, MedicalRecord, Message,User
from django.utils import timezone
from django.contrib.auth import login, authenticate
from django.shortcuts import redirect
from django.contrib import messages
from django.contrib.auth.forms import UserCreationForm
from django import forms

# Create your views here.

class UserRegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True)
    first_name = forms.CharField(max_length=150, required=True)
    last_name = forms.CharField(max_length=150, required=True)
    role = forms.ChoiceField(choices=[('PATIENT', 'Patient'), ('DOCTOR', 'Doctor')], required=True)

    class Meta:
        model = User
        fields = ('email', 'first_name', 'last_name', 'role', 'password1', 'password2')

    def save(self, commit=True):
        user = super().save(commit=False)
        user.username = self.cleaned_data['email']
        if commit:
            user.save()
        return user

def signup_view(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, 'Inscription réussie!')
            return redirect('patient_index')
    else:
        form = UserRegistrationForm()
    return render(request, 'MediConnect/signup.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(request, username=email, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, 'Connexion réussie!')
            return redirect('patient_index')
        else:
            messages.error(request, 'Email ou mot de passe incorrect.')
    return render(request, 'MediConnect/login.html')

def patient_index(request):
    """
    Vue pour la page d'accueil des patients.
    """
    today = timezone.now().date()
    dashboard_infos = DashboardInfo.objects.filter(is_active=True).order_by('-created_at')
    upcoming_appointments = Appointment.objects.filter(status='SCHEDULED', date__gte=today).order_by('date', 'time')[:5]
    recent_records = MedicalRecord.objects.all().order_by('-date')[:3]
    recent_messages = Message.objects.all().order_by('-created_at')[:5]
    
    context = {
        'dashboard_infos': dashboard_infos,
        'upcoming_appointments': upcoming_appointments,
        'recent_records': recent_records,
        'recent_messages': recent_messages,
    }
    return render(request, 'MediConnect/index.html', context)
