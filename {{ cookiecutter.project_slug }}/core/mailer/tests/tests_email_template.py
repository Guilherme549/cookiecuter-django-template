from django.test import TestCase
from django.test.utils import override_settings
from unittest.mock import patch, MagicMock, call
from core.mailer.email_template import EmailTemplate, EmailTemplateNotSpecifiedException


class EmailTemplateTestCase(TestCase):
    def test_without_subject_template(self):
        with self.assertRaises(EmailTemplateNotSpecifiedException):
            mail = EmailTemplate(None, {}, "any.html", {}, ["example@example.com.br"])
            mail.send()

    @patch(
        "core.mailer.email_template.render_to_string", MagicMock(return_value="content")
    )
    def test_without_body_template(self):
        with self.assertRaises(EmailTemplateNotSpecifiedException):
            mail = EmailTemplate("any.txt", {}, "", {}, ["example@example.com.br"])
            mail.send()

    @patch("core.mailer.email_template.render_to_string")
    @patch("core.mailer.email_template.EmailMessage")
    @override_settings(DEFAULT_FROM_EMAIL="bing@example.com")
    def test_with_all_data(self, mock_email: MagicMock, mock_render: MagicMock):
        mock_content = "Rendered Content"
        mock_render.return_value = mock_content
        context = {"data": "any"}
        to_mails = ["example@example.com.br"]
        mock_email.return_value.send = MagicMock()

        mail = EmailTemplate("any.txt", context, "any.html", context, to_mails)
        mail.send()

        self.assertListEqual(
            mock_render.mock_calls,
            [call("any.txt", context=context), call("any.html", context=context)],
        )
        mock_email.assert_called_once_with(
            mock_content,
            mock_content,
            "bing@example.com",
            to_mails,
        )
        mock_email.return_value.send.assert_called_once_with(False)
