from rest_framework import serializers
from ..models import User
from django.conf import settings

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    class Meta:
        model = User
        fields = '__all__'
        read_only_fields = ['id','created_at','updated_at','is_active','is_staff','is_verified','verification_code','verification_code_created_at','last_login','date_joined']
    def create(self, validated_data):
        instance = User(**validated_data)
        instance.set_password(validated_data['password'])
        # username = null, generate by email
        if not validated_data['username']:
            instance.username = validated_data['email']
        instance.save()
        # self.send_confirmation_email(instance, "🎉 Bienvenue sur MediConnect", "message", "Inscription")
        return instance


    def send_confirmation_email(self, instance, subject, message_content, type_evenement):
        """
        Envoie un e-mail de confirmation à l'utilisateur.

        Args:
            instance: L'instance du participant.
            subject: Le sujet de l'e-mail.
            message_content: Le corps principal du message.
            type_evenement: Le typreturne d'événement ("Inscription" ou "Présence") pour personnaliser légèrement le message.
        """
        destinataire = instance.email
        nom = instance.first_name

        # Construction du contenu HTML de l'e-mail
        contenu_html = f"""
                Bonjour {nom},<br><br>
                {message_content}<br><br>
                
                Cordialement,<br>
                L’équipe du MediConnect<br>
                📧 Contact@mediconnect.com<br>
                🌐 https://mediconnect.com<br>
                🔗 LinkedIn
                """

        # Utilisation de la configuration Django pour l'envoi d'e-mails
        email = EmailMessage(
            subject,
            contenu_html,
            settings.EMAIL_HOST_USER,
            [destinataire],
        )
        email.content_subtype = "html"

        try:
            email.send()
        except Exception as e:
            print(f"Erreur lors de l'envoi de l'e-mail à {destinataire}: {e}")

        return instance

# serializer for login user
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        
        # Add custom claims
        # role, email, first_name, last_name, phone_number, address
        token['id'] = user.id
        token['email'] = user.email
        # token['first_name'] = user.first_name
        # token['last_name'] = user.last_name
        # token['phone_number'] = user.phone_number
        # token['address'] = user.address
        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        refresh = self.get_token(self.user)
        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)
        # Add custom claims
        # role, email, first_name, last_name, phone_number, address
        data['user'] = UserSerializer(self.user).data
        
        # data['id'] = self.user.id
        # data['role'] = self.user.role
        # data['email'] = self.user.email
        # data['first_name'] = self.user.first_name
        # data['last_name'] = self.user.last_name
        # data['phone_number'] = self.user.phone_number
        # data['address'] = self.user.address
        return data
        


