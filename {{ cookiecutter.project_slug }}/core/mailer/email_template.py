from typing import List
from django.template.loader import render_to_string
from django.conf import settings
from django.core.mail import EmailMessage


class EmailTemplateNotSpecifiedException(Exception):
    pass


class EmailTemplate:
    def __init__(
        self,
        subject_template: str,
        subject_context: dict,
        body_template: str,
        body_context: dict,
        to_emails: List[str],
    ):
        self.from_email = settings.DEFAULT_FROM_EMAIL
        self.subject_template = subject_template
        self.subject_context = subject_context
        self.body_template = body_template
        self.body_context = body_context
        self.to_emails = to_emails

    def get_subject_template(self):
        if not self.subject_template:
            raise EmailTemplateNotSpecifiedException(
                "subject template is not specified"
            )
        return self.subject_template

    def get_subject_context(self):
        return self.subject_context or {}

    def get_body_template(self):
        if not self.body_template:
            raise EmailTemplateNotSpecifiedException("body template is not specified")
        return self.body_template

    def get_body_context(self):
        return self.body_context or {}

    def render_subject(self):
        template = self.get_subject_template()
        context = self.get_subject_context()
        return render_to_string(template, context=context)

    def render_body(self):
        template = self.get_body_template()
        context = self.get_body_context()
        return render_to_string(template, context=context)

    def send(self):
        subject = self.render_subject()
        body = self.render_body()
        email = EmailMessage(subject, body, self.from_email, self.to_emails)
        email.content_subtype = "html"
        email.send(False)
