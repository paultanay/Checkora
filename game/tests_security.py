"""
Security tests for the Checkora project.
Focuses on verifying Host Header protection and other core security settings.
"""

from django.test import TestCase, Client, override_settings
from django.core import mail
from django.contrib.auth.models import User
from django.urls import reverse
from django.conf import settings

class SecurityHostHeaderTest(TestCase):
    """
    Validates that the application is protected against Host Header Poisoning.
    Host Header Poisoning can occur when absolute URLs (like password reset links)
    are generated using an unvalidated HTTP Host header.
    """

    def setUp(self):
        """Set up a test user for auth-related security flows."""
        self.user = User.objects.create_user(
            username='security_test_user',
            email='security@example.com',
            password='password123'
        )
        self.client = Client()

    def test_settings_does_not_contain_wildcard(self):
        """
        Ensures that ALLOWED_HOSTS does not contain the '*' wildcard.
        A wildcard in production allows any Host header, which is insecure.
        """
        self.assertNotIn(
            '*', 
            settings.ALLOWED_HOSTS, 
            "CRITICAL: ALLOWED_HOSTS contains a wildcard. This must be a strict allowlist in production."
        )
        # Verify our primary production domains are present
        self.assertIn('checkora.vercel.app', settings.ALLOWED_HOSTS)

    @override_settings(
        DEBUG=False,
        EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend'
    )
    def test_host_header_poisoning_protection(self):
        """
        Verifies that absolute URLs in emails cannot be poisoned by a malicious Host header.
        This test uses the actual settings of the application.
        """
        malicious_host = 'attacker-domain.com'
        reset_url = reverse('password_reset')

        # We attempt to trigger a password reset while injecting a malicious Host header.
        # If ALLOWED_HOSTS is configured correctly, Django will use a safe default 
        # or raise an error if the Client enforces strict validation.
        response = self.client.post(
            reset_url, 
            {'email': self.user.email}, 
            HTTP_HOST=malicious_host
        )

        # If the request was accepted (status 302), we verify the generated link is safe.
        if response.status_code == 302:
            self.assertEqual(len(mail.outbox), 1, "Password reset email should have been sent.")
            email_body = mail.outbox[0].body
            
            # The link should NOT contain the malicious host.
            self.assertNotIn(
                f'http://{malicious_host}', 
                email_body, 
                f"VULNERABILITY: Reset link was poisoned with {malicious_host}"
            )
            
            # Instead, it should use a trusted host (Django defaults to 'testserver' in tests 
            # if the provided one is rejected or ignored by the backend).
            self.assertIn('http://testserver', email_body)
