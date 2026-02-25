from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from .models import DashboardInfo, Appointment, MedicalRecord, Message,User,UserRole,Case,PandemicSignal
from django.utils import timezone
from django.contrib.auth import login, authenticate, logout
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
        email = request.POST.get('email')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        password1 = request.POST.get('password1')
        # password2 = request.POST.get('password2')  # Commented out as per template
        
        # Basic validation
        if not all([email, first_name, last_name, password1]):
            messages.error(request, 'Tous les champs sont requis.')
            return render(request, 'MediConnect/signup.html')
        
        if User.objects.filter(email=email).exists():
            messages.error(request, 'Un utilisateur avec cet email existe déjà.')
            return render(request, 'MediConnect/signup.html')
        
        # Create user
        user = User.objects.create_user(
            username=email,
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=password1,
            role=UserRole.PATIENT  # Default to patient
        )
        login(request, user)
        messages.success(request, 'Inscription réussie!')
        return redirect('patient_index')
    
    return render(request, 'MediConnect/signup.html')

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

def logout_view(request):
    logout(request)
    messages.success(request, 'Déconnexion réussie!')
    return redirect('login')
# @login_required(login_url="login")
def patient_index(request):
    """
    Vue pour la page d'accueil des patients.
    """
    today = timezone.now().date()
    dashboard_infos = DashboardInfo.objects.filter(is_active=True).order_by('-created_at')
    upcoming_appointments = Appointment.objects.filter(status='SCHEDULED',patient=request.user, date__gte=today).order_by('date', 'time')[:5]
    recent_records = MedicalRecord.objects.all().filter(patient=request.user).order_by('-date')[:3]
    recent_messages = Message.objects.all().filter(sender=request.user,receiver=request.user).order_by('-created_at')[:5]
    # PandemicSignals
    pandemic_signals = PandemicSignal.objects.all().order_by('-last_detected')[:5]
    # Statistiques de santé
    # Rendez-vous cette année
    appointments_this_year = Appointment.objects.filter(patient=request.user, date__year=today.year).count()
    # Taux d'assiduité
    attendance_rate = appointments_this_year / Appointment.objects.filter(patient=request.user).count() * 100
    # Médecins consultés
    doctors = Appointment.objects.filter(patient=request.user).values('doctor').distinct()
    # Examens en attente
    pending_exams = MedicalRecord.objects.filter(patient=request.user).count()
    
    context = {
        'dashboard_infos': dashboard_infos,
        'upcoming_appointments': upcoming_appointments,
        'recent_records': recent_records,
        'recent_messages': recent_messages,
        'pandemic_signals': pandemic_signals,
        'appointments_this_year': appointments_this_year,
        'attendance_rate': attendance_rate,
        'doctors': doctors,
        'pending_exams': pending_exams,
    }
    return render(request, 'MediConnect/index.html', context)

# Prendre un rendez-vous
def appointment_view(request):
    if request.method == 'POST':
        date = request.POST.get('date')
        time = request.POST.get('time')
        patient = request.user
        doctor = request.POST.get('doctor')
        status = 'SCHEDULED'
        appointment = Appointment.objects.create(date=date, time=time, patient=patient, doctor=doctor, status=status)
        messages.success(request, 'Rendez-vous pris avec succès!')
        return redirect('patient_index')
    return render(request, 'MediConnect/appointment.html')


# Mes Rendez-vous
@login_required(login_url="login")
def my_appointments(request):
    appointments = Appointment.objects.filter(patient=request.user)
    return render(request, 'MediConnect/my_appointments.html', {'appointments': appointments})


# Mes Messages
def my_messages(request):
    messages = Message.objects.filter(sender=request.user,receiver=request.user)
    return render(request, 'MediConnect/my_messages.html', {'messages': messages})

# Mes Dossiers
def my_records(request):
    records = MedicalRecord.objects.filter(patient=request.user)
    return render(request, 'MediConnect/my_records.html', {'records': records})


# Cases
@login_required(login_url="login")
def my_cases(request):
    cases = Case.objects.filter(patient=request.user)
    return render(request, 'MediConnect/my_cases.html', {'cases': cases})
# submit case
@login_required(login_url="login")
def submit_case(request):
    if request.method == 'POST':
        case = Case.objects.create(
            patient=request.user,
            doctor=request.POST.get('doctor'),
            symptoms_description=request.POST.get('symptoms_description'),
            ai_clarification=request.POST.get('ai_clarification'),
            suggested_medication=request.POST.get('suggested_medication'),
            status="PENDING",
            # is_emergency=request.POST.get('is_emergency')
        )
        messages.success(request, 'Cas soumis avec succès!')
        return redirect('my_cases')
    return render(request, 'MediConnect/submit_case.html')


# Profile
@login_required(login_url="login")
def profile(request):
    user = request.user
    return render(request, 'MediConnect/profile.html', {'user': user})
