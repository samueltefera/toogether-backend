from rest_framework import status
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
from django.core.exceptions import ObjectDoesNotExist
from api import models, serializers
from django.contrib.auth.hashers import make_password
from datetime import date, timedelta
from django.utils import timezone
from django.contrib.gis.geos import GEOSGeometry
from decimal import *
from django.core.mail import send_mail
import uuid

from api.utils.emails import send_report_email

import random
import json
import requests
from django.conf import settings

# Documentation imports
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample, OpenApiResponse

# simple json token
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken

# ----------------------- LOGIN --------------------------------


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        serializer = serializers.ProfileSerializer(self.user).data
        for key, value in serializer.items():
            data[key] = value

        return data


class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer
    permission_classes = [AllowAny]


# ----------------------- PROFILES VIEWS --------------------------------


@extend_schema(
    request=OpenApiExample(
        name="Recovery Code Request",
        value={"email": "user@example.com"},
        request_only=True
    ),
    responses={
        200: OpenApiResponse(
            description="Code sent successfully",
            examples=[
                OpenApiExample(
                    "Success Response",
                    value={"detail": "We sent you an email with you recovery password code"},
                    status_codes=["200"],
                )
            ]
        ),
        400: OpenApiResponse(
            description="Email not found",
            examples=[
                OpenApiExample(
                    "Error Response",
                    value={"detail": "There is no account associated with the email entered"},
                    status_codes=["400"],
                )
            ]
        )
    },
    description="Send a recovery code to the user's email for password reset",
    summary="Send recovery code"
)
@api_view(["POST"])
@permission_classes([AllowAny])
def recovery_code(request):
    data = request.data
    email = data["email"]

    try:
        current_profile = models.Profile.objects.get(email=email)
    except ObjectDoesNotExist:
        return Response(
            {"detail": "There is no account associated with the email entered"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # way to check in a one to one if there is already a relation
    try:
        old_code = current_profile.verification_code
    except ObjectDoesNotExist:
        old_code = None

    if old_code:
        old_code.delete()

    code_generator = "".join(str(random.randrange(10)) for i in range(6))
    verification_code = models.VerificationCode.objects.create(
        profile=current_profile, email=email, code=code_generator
    )
    verification_code.save()

    send_mail(
        "Reset your password",
        f"Here is your recovery password code {verification_code.code}. Please don't share it with anyone",
        "toogethersite@gmail.com",
        [email],
        fail_silently=False,
    )

    return Response(
        {"detail": "We sent you an email with you recovery password code"},
        status=status.HTTP_200_OK,
    )


@extend_schema(
    request=OpenApiExample(
        name="Validate Code Request",
        value={
            "email": "user@example.com",
            "code": "123456"
        },
        request_only=True
    ),
    responses={
        200: OpenApiResponse(
            description="Code validation successful",
            examples=[
                OpenApiExample(
                    "Success Response",
                    value={
                        "detail": "Recovery code success",
                        "AccessToken": "token_value"
                    },
                    status_codes=["200"],
                )
            ]
        ),
        400: OpenApiResponse(
            description="Invalid or expired code",
            examples=[
                OpenApiExample(
                    "Error Response",
                    value={"detail": "Code does not exists"},
                    status_codes=["400"],
                )
            ]
        )
    },
    description="Validate recovery code to reset password",
    summary="Validate recovery code"
)
@api_view(["POST"])
@permission_classes([AllowAny])
def validate_code(request):
    data = request.data
    code = data["code"]
    email = data["email"]

    try:
        verification_code = models.VerificationCode.objects.get(code=code)
    except ObjectDoesNotExist:
        return Response(
            {"detail": "Code does not exists"}, status=status.HTTP_400_BAD_REQUEST
        )

    try:
        current_profile = models.Profile.objects.get(email=email)
        current_code = current_profile.verification_code
    except ObjectDoesNotExist:
        return Response(
            {"detail": "Something went wrong"}, status=status.HTTP_400_BAD_REQUEST
        )

    code_is_valid = timezone.now() <= verification_code.expiration

    # check that the code belongs to the user
    if verification_code == current_code and code_is_valid:
        serializer = serializers.ProfileSerializer(current_profile, many=False)
        return Response(
            {
                "detail": "Recovery code success",
                "AccessToken": serializer.data["token"],
            },
            status=status.HTTP_200_OK,
        )

    return Response({"detail": "Expirated code"}, status=status.HTTP_400_BAD_REQUEST)


class ProfileViewSet(ModelViewSet):
    queryset = models.Profile.objects.all()
    serializer_class = serializers.ProfileSerializer
    permission_classes = [IsAuthenticated]

    # admin actions for this model view set
    def get_permissions(self):
        ALLOW_ANY = ["create"]
        if self.action in ALLOW_ANY:
            return [AllowAny()]
        return [permission() for permission in self.permission_classes]

    def list(self, request):
        return Response(
            {"detail": "Not authorized"}, status=status.HTTP_401_UNAUTHORIZED
        )

    # * Register
    def create(self, request):
        data = request.data
        
        # Check if required fields are present
        if 'password' not in data or 'repeated_password' not in data or 'email' not in data:
            return Response(
                {"detail": "Email, password and repeated_password are required"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            
        password = data["password"]
        repeated_password = data["repeated_password"]

        if password != repeated_password:
            message = {"detail": "Your password does not match"}
            return Response(message, status=status.HTTP_400_BAD_REQUEST)

        try:
            # create a new user data model
            user = models.Profile.objects.create(
                email=data["email"], password=make_password(data["password"])
            )
            serializer = serializers.ProfileSerializer(user, many=False)
            return Response(serializer.data)
        except:
            message = {"detail": "User with this email already exist"}
            return Response(message, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        try:
            profile = models.Profile.objects.get(pk=pk)
        except ObjectDoesNotExist:
            return Response(
                {"detail": "Profile does not exist"}, status=status.HTTP_400_BAD_REQUEST
            )

        # only the current user and an admin can execute this function
        if profile.id != request.user.id and not request.user.is_superuser:
            return Response(
                {
                    "detail": "Not autherized",
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        serializer = serializers.ProfileSerializer(profile, many=False)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def update(self, request, pk=None):
        fields_serializer = serializers.UpdateProfileSerializer(data=request.data)
        fields_serializer.is_valid(raise_exception=True)

        try:
            profile = models.Profile.objects.get(pk=pk)
        except ObjectDoesNotExist:
            return Response(
                {"Error": "Profile does not exist"}, status=status.HTTP_400_BAD_REQUEST
            )

        # only the current user and an admin can execute this function
        if profile.id != request.user.id and not request.user.is_superuser:
            return Response(
                {
                    "detail": "Not autherized",
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if "gender" in request.data:
            profile.gender = fields_serializer.validated_data["gender"]
        if "show_me" in request.data:
            profile.show_me = fields_serializer.validated_data["show_me"]
        if "nationality" in request.data:
            profile.nationality = fields_serializer.validated_data["nationality"]
        if "city" in request.data:
            profile.city = fields_serializer.validated_data["city"]
        if "instagram" in request.data:
            profile.instagram = fields_serializer.validated_data["instagram"]
        if "university" in request.data:
            profile.university = fields_serializer.validated_data["university"]
        if "description" in request.data:
            profile.description = fields_serializer.validated_data["description"]

        profile.save()
        profile_serializer = serializers.ProfileSerializer(profile, many=False)
        return Response(profile_serializer.data)

    def destroy(self, request, pk=None):
        try:
            profile = models.Profile.objects.get(pk=pk)
        except ObjectDoesNotExist:
            return Response(
                {"Error": "Profile does not exist"}, status=status.HTTP_400_BAD_REQUEST
            )

        # only the current user and an admin can execute this function
        if profile.id != request.user.id and not request.user.is_superuser:
            return Response(
                {
                    "detail": "Not autherized",
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )
        profile.delete()
        return Response(
            {"detail": "User deleted successfully"}, status=status.HTTP_200_OK
        )

    @extend_schema(
        request=serializers.CreateProfileSerializer,
        responses={
            200: serializers.ProfileSerializer,
            400: OpenApiResponse(
                description="Invalid profile data or age under 18",
                examples=[
                    OpenApiExample(
                        "Age Error Response",
                        value={"detail": "You must be over 18 years old to use this app"},
                        status_codes=["400"],
                    )
                ]
            )
        },
        description="Create or update user profile with name, birthdate, university, description, gender, and show_me preferences",
        summary="Create user profile"
    )
    @action(detail=False, methods=["post"], url_path=r"actions/create-profile")
    def create_profile(self, request):
        profile = request.user

        def age(birthdate):
            today = date.today()
            age = (
                today.year
                - birthdate.year
                - ((today.month, today.day) < (birthdate.month, birthdate.day))
            )
            return age

        fields_serializer = serializers.CreateProfileSerializer(data=request.data)
        fields_serializer.is_valid(raise_exception=True)

        profile.name = fields_serializer.validated_data["name"]
        profile.birthdate = fields_serializer.validated_data["birthdate"]
        profile.university = fields_serializer.validated_data["university"]
        profile.description = fields_serializer.validated_data["description"]
        profile.gender = fields_serializer.validated_data["gender"]
        profile.show_me = fields_serializer.validated_data["show_me"]

        if age(profile.birthdate) < 18:
            return Response(
                {"detail": "You must be over 18 years old to use this app"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        else:
            profile.age = age(profile.birthdate)
            profile.has_account = True

        profile.save()
        profile_serializer = serializers.ProfileSerializer(profile)
        return Response(profile_serializer.data)

    @extend_schema(
        request=serializers.UpdateLocation,
        responses={
            200: serializers.ProfileSerializer,
            400: OpenApiResponse(
                description="Invalid location data",
                examples=[
                    OpenApiExample(
                        "Error Response",
                        value={"detail": "Invalid location data"},
                        status_codes=["400"],
                    )
                ]
            )
        },
        description="Update the user's location with latitude and longitude coordinates",
        summary="Update user location"
    )
    @action(detail=False, methods=["post"], url_path=r"actions/location")
    def update_location(self, request):
        profile = request.user

        # receives lat and lon
        fields_serializer = serializers.UpdateLocation(data=request.data)
        fields_serializer.is_valid(raise_exception=True)

        lat = fields_serializer.validated_data["lat"]
        lon = fields_serializer.validated_data["lon"]

        # update the location point using the new lat and lon
        point = {"type": "Point", "coordinates": [lat, lon]}

        profile.location = GEOSGeometry(json.dumps(point), srid=4326)
        profile.save()
        serializer = serializers.ProfileSerializer(profile, many=False)
        return Response(serializer.data)

    @extend_schema(
        responses={
            200: serializers.SwipeProfileSerializer,
            400: OpenApiResponse(
                description="Profile not found",
                examples=[
                    OpenApiExample(
                        "Error Response",
                        value={"Error": "Profile does not exist"},
                        status_codes=["400"],
                    )
                ]
            )
        },
        description="Block a user profile by ID",
        summary="Block profile"
    )
    @action(detail=True, methods=["post"], url_path=r"actions/block-profile")
    def block_profile(self, request, pk=None):
        current_profile = request.user

        try:
            blocked_profile = models.Profile.objects.get(pk=pk)
        except ObjectDoesNotExist:
            return Response(
                {"Error": "Profile does not exist"}, status=status.HTTP_400_BAD_REQUEST
            )

        # block profile
        current_profile.block_profile(blocked_profile)

        serializer = serializers.SwipeProfileSerializer(blocked_profile, many=False)
        return Response(serializer.data)

    @extend_schema(
        responses={
            200: serializers.SwipeProfileSerializer,
            400: OpenApiResponse(
                description="Profile not found",
                examples=[
                    OpenApiExample(
                        "Error Response",
                        value={"Error": "Profile does not exist"},
                        status_codes=["400"],
                    )
                ]
            )
        },
        description="Unblock a previously blocked user profile by ID",
        summary="Unblock profile"
    )
    @action(detail=True, methods=["post"], url_path=r"actions/disblock-profile")
    def disblock_profile(self, request, pk=None):
        profile = request.user
        try:
            blocked_profile = models.Profile.objects.get(pk=pk)
        except ObjectDoesNotExist:
            return Response({"Error": "Profile does not exist"})
        profile.blocked_profiles.remove(blocked_profile)
        serializer = serializers.SwipeProfileSerializer(blocked_profile, many=False)
        return Response(serializer.data)

    @extend_schema(
        responses={
            200: OpenApiResponse(
                description="List of blocked profiles",
                examples=[
                    OpenApiExample(
                        "Success Response",
                        value={
                            "count": 2,
                            "results": [
                                {"id": "profile_id1", "name": "User 1", "email": "user1@example.com"},
                                {"id": "profile_id2", "name": "User 2", "email": "user2@example.com"}
                            ]
                        },
                        status_codes=["200"],
                    )
                ]
            )
        },
        description="Get a list of all profiles blocked by the current user",
        summary="Get blocked profiles"
    )
    @action(detail=False, methods=["get"], url_path=r"actions/get-blocked-profiles")
    def get_blocked_profiles(self, request):
        current_profile = request.user
        blocked_profiles = current_profile.blocked_profiles.all()
        serializer = serializers.SwipeProfileSerializer(blocked_profiles, many=True)
        return Response({"count": blocked_profiles.count(), "results": serializer.data})

    @extend_schema(
        request=OpenApiExample(
            name="Reset Password Request",
            value={
                "password": "new_password",
                "repeated_password": "new_password"
            },
            request_only=True
        ),
        responses={
            200: OpenApiResponse(
                description="Password reset successful",
                examples=[
                    OpenApiExample(
                        "Success Response",
                        value={"detail": "You password has been reseted"},
                        status_codes=["200"],
                    )
                ]
            ),
            400: OpenApiResponse(
                description="Passwords don't match",
                examples=[
                    OpenApiExample(
                        "Error Response",
                        value={"detail": "Your passwords does not match"},
                        status_codes=["400"],
                    )
                ]
            )
        },
        description="Reset user password with a new password",
        summary="Reset password"
    )
    @action(detail=False, methods=["post"], url_path=r"actions/reset-password")
    def reset_password(self, request):
        current_profile = request.user
        data = request.data
        password = data["password"]
        repeated_password = data["repeated_password"]

        if password == repeated_password:
            current_profile.password = make_password(password)
            current_profile.save()
            return Response(
                {"detail": "You password has been reseted"}, status=status.HTTP_200_OK
            )

        return Response(
            {"detail": "Your passwords does not match"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    @extend_schema(
        responses={
            200: OpenApiResponse(
                description="Report sent successfully",
                examples=[
                    OpenApiExample(
                        "Success Response",
                        value={"detail": "Report sent successfully"},
                        status_codes=["200"],
                    )
                ]
            ),
            400: OpenApiResponse(
                description="Profile not found",
                examples=[
                    OpenApiExample(
                        "Error Response",
                        value={"Error": "Profile does not exist"},
                        status_codes=["400"],
                    )
                ]
            )
        },
        description="Report a user profile and automatically block them",
        summary="Report profile"
    )
    @action(detail=True, methods=["post"], url_path=r"actions/report-profile")
    def report_profile(self, request, pk=None):
        current_profile = request.user

        # get reported profile by id
        try:
            reported_profile = models.Profile.objects.get(pk=pk)
        except ObjectDoesNotExist:
            return Response(
                {"Error": "Profile does not exist"}, status=status.HTTP_400_BAD_REQUEST
            )

        # send report by email to admins
        send_report_email(reported_profile=reported_profile)

        # then block the reported profile
        current_profile.block_profile(reported_profile)

        return Response(
            {"detail": "Report sent successfully"}, status=status.HTTP_200_OK
        )


# ----------------------- PHOTOS VIEWS --------------------------------
class PhotoViewSet(ModelViewSet):
    serializer_class = serializers.PhotoSerializer
    permission_classes = [IsAuthenticated]

    def list(self, request):
        profile = request.user
        queryset = models.Photo.objects.filter(profile=profile.id).order_by(
            "created_at"
        )
        serializer = serializers.PhotoSerializer(queryset, many=True)
        return Response(serializer.data)

    def retrieve(self, request, pk):
        photo = models.Photo.objects.get(pk=pk)
        serializer = serializers.PhotoSerializer(photo, many=False)
        return Response(serializer.data)

    def create(self, request):
        profile = request.user
        profile_photos = models.Photo.objects.filter(profile=profile.id)

        fields_serializer = serializers.PhotoSerializer(data=request.data)
        fields_serializer.is_valid(raise_exception=True)

        if len(profile_photos) >= 5:
            return Response(
                {"detail": "Profile cannot have more than 5 images"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        photo = models.Photo.objects.create(
            profile=profile, image=fields_serializer._validated_data["image"]
        )
        serializer = serializers.PhotoSerializer(photo, many=False)
        return Response(serializer.data)

    def update(self, request, pk=None, *args, **kwargs):
        photo = models.Photo.objects.get(pk=pk)
        fields_serializer = serializers.PhotoSerializer(data=request.data, partial=True)
        fields_serializer.is_valid(raise_exception=True)
        photo.image = fields_serializer.validated_data["image"]

        photo.save()
        serializer = serializers.PhotoSerializer(photo, many=False)
        return Response(serializer.data)

    def destroy(self, request, pk):
        photo = models.Photo.objects.get(pk=pk)
        photo.delete()
        return Response({"detail": "Photo deleted"}, status=status.HTTP_200_OK)

@extend_schema(
    request=serializers.PhoneVerificationRequestSerializer,
    responses={
        200: OpenApiResponse(
            description="Verification code sent successfully",
            examples=[
                OpenApiExample(
                    "Success Response",
                    value={"detail": "Verification code sent successfully"},
                    status_codes=["200"],
                )
            ]
        ),
        400: OpenApiResponse(
            description="Failed to send verification code",
            examples=[
                OpenApiExample(
                    "Error Response",
                    value={"detail": "Failed to send verification code"},
                    status_codes=["400"],
                )
            ]
        )
    },
    description="Send a verification code to the provided phone number",
    summary="Send phone verification code"
)
@api_view(["POST"])
@permission_classes([AllowAny])
def send_phone_verification(request):
    """
    Send a verification code to the provided phone number.
    
    Example request:
    {
        "phone": "912345678"
    }
    
    Example response:
    {
        "detail": "Verification code sent successfully"
    }
    """
    serializer = serializers.PhoneVerificationRequestSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    phone = serializer.validated_data["phone"]

    # Format phone number to include country code if not present
    if not phone.startswith("+"):
        phone = f"+251{phone}"

    # Call Afromessage API to send verification code
    headers = {
        "Authorization": f"Bearer {settings.AFROMESSAGE_API_KEY}",
        "Content-type": "application/json"
    }
    
    params = {
        "from": "",
        "sender": "",
        "to": phone,
        "ps": "Your verification code is",
        "sb": "1",
        "sa": "1",
        "ttl": "0",
        "len": "4",
        "t": "0"
    }

    response = requests.get(
        "https://api.afromessage.com/api/challenge",
        headers=headers,
        params=params
    )

    if response.status_code != 200:
        return Response(
            {"detail": "Failed to send verification code"},
            status=status.HTTP_400_BAD_REQUEST
        )

    data = response.json()
    if data["acknowledge"] != "success":
        return Response(
            {"detail": "Failed to send verification code"},
            status=status.HTTP_400_BAD_REQUEST
        )

    return Response(
        {"detail": "Verification code sent successfully"},
        status=status.HTTP_200_OK
    )

@extend_schema(
    request=serializers.PhoneVerificationSerializer,
    responses={
        200: OpenApiResponse(
            description="Phone verification successful",
            examples=[
                OpenApiExample(
                    "Success Response",
                    value={
                        "refresh": "refresh_token_here",
                        "access": "access_token_here",
                        "id": "user_id",
                        "phone": "+251912345678",
                        "name": "User Name",
                        "email": "user@example.com",
                        "is_phone_verified": True
                    },
                    status_codes=["200"],
                )
            ]
        ),
        400: OpenApiResponse(
            description="Verification failed",
            examples=[
                OpenApiExample(
                    "Error Response",
                    value={"detail": "Invalid verification code"},
                    status_codes=["400"],
                )
            ]
        )
    },
    description="Verify the code sent to the phone number and log in or register the user",
    summary="Verify phone and login/register"
)
@api_view(["POST"])
@permission_classes([AllowAny])
def verify_phone_code(request):
    """
    Verify the code sent to the phone number and log in or register the user.
    
    Example request:
    {
        "phone": "912345678",
        "code": "1234"
    }
    
    Example response:
    {
        "refresh": "refresh_token_here",
        "access": "access_token_here",
        "id": "user_id",
        "email": "user_email",
        "name": "user_name",
        ... other user fields ...
    }
    """
    serializer = serializers.PhoneVerificationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    phone = serializer.validated_data["phone"]
    code = serializer.validated_data["code"]

    # Format phone number to include country code if not present
    if not phone.startswith("+"):
        phone = f"+251{phone}"

    # Call Afromessage API to verify code
    headers = {
        "Authorization": f"Bearer {settings.AFROMESSAGE_API_KEY}",
        "Content-type": "application/json"
    }
    
    params = {
        "to": phone,
        "code": code
    }

    response = requests.get(
        "https://api.afromessage.com/api/verify",
        headers=headers,
        params=params
    )

    if response.status_code != 200:
        return Response(
            {"detail": "Failed to verify code"},
            status=status.HTTP_400_BAD_REQUEST
        )

    data = response.json()
    if data["acknowledge"] != "success":
        return Response(
            {"detail": "Invalid verification code"},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Check if user exists with this phone number
    try:
        user = models.Profile.objects.get(phone=phone)
        # User exists, update phone verification status if needed
        if not user.is_phone_verified:
            user.is_phone_verified = True
            user.save()
    except models.Profile.DoesNotExist:
        # Create a new user with phone number
        user = models.Profile.objects.create(
            phone=phone,
            is_phone_verified=True,
            password=make_password(str(uuid.uuid4()))  # Generate random password
        )

    # Generate token directly using RefreshToken
    refresh = RefreshToken.for_user(user)
    
    # Create response with user data and tokens
    response_data = serializers.ProfileSerializer(user, many=False).data
    response_data['refresh'] = str(refresh)
    response_data['access'] = str(refresh.access_token)
    
    return Response(response_data, status=status.HTTP_200_OK)
