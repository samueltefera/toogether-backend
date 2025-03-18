from rest_framework import serializers

class PhoneVerificationSerializer(serializers.Serializer):
    phone = serializers.CharField(
        required=True,
        help_text="Phone number with or without country code",
        example="912345678"
    )
    code = serializers.CharField(
        required=True,
        help_text="4-digit verification code sent to the phone number",
        example="1234"
    )

class PhoneVerificationRequestSerializer(serializers.Serializer):
    phone = serializers.CharField(
        required=True,
        help_text="Phone number with or without country code",
        example="912345678"
    ) 