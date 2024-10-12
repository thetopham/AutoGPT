import imaplib
import poplib
import email
from email.parser import BytesParser
from email.policy import default
from typing import List

from pydantic import BaseModel, ConfigDict, Field

from backend.data.block import Block, BlockCategory, BlockOutput, BlockSchema
from backend.data.model import BlockSecret, SchemaField, SecretField


class EmailRetrieveCredentials(BaseModel):
    protocol: str = Field(
        default="imap", description="Protocol to use for retrieving emails: 'imap' or 'pop3'"
    )
    server: str = Field(
        default="imap.gmail.com", description="Email server address"
    )
    port: int = Field(default=993, description="Port number (993 for IMAP, 995 for POP3)")
    username: BlockSecret = SecretField(key="email_username")
    password: BlockSecret = SecretField(key="email_password")

    model_config = ConfigDict(title="Email Retrieval Credentials")

class ReceiveEmailBlock(Block):
    class Input(BlockSchema):
        creds: EmailRetrieveCredentials = Field(
            description="Credentials for retrieving emails",
            default=EmailRetrieveCredentials(),
        )
        folder: str = SchemaField(
            description="Email folder to fetch from (e.g., 'INBOX')",
            default="INBOX",
            placeholder="INBOX",
        )
        max_emails: int = SchemaField(
            description="Maximum number of emails to retrieve",
            default=10,
            placeholder="10",
        )

    class Output(BlockSchema):
        emails: List[dict] = SchemaField(description="List of retrieved emails")

    def __init__(self):
        super().__init__(
            id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            description="This block retrieves emails using the provided POP3 or IMAP credentials.",
            categories={BlockCategory.INPUT},
            input_schema=ReceiveEmailBlock.Input,
            output_schema=ReceiveEmailBlock.Output,
            test_input={
                "creds": {
                    "protocol": "imap",
                    "server": "imap.gmail.com",
                    "port": 993,
                    "username": "your-email@gmail.com",
                    "password": "your-email-password",
                },
                "folder": "INBOX",
                "max_emails": 5,
            },
            test_output=[("emails", [{"subject": "Test Email", "from": "sender@example.com"}])],
            test_mock={
                "retrieve_emails": lambda *args, **kwargs: [
                    {"subject": "Test Email", "from": "sender@example.com"}
                ]
            },
        )

    @staticmethod
    def retrieve_emails(
        creds: EmailRetrieveCredentials, folder: str, max_emails: int
    ) -> List[dict]:
        protocol = creds.protocol.lower()
        username = creds.username.get_secret_value()
        password = creds.password.get_secret_value()
        emails = []

        if protocol == "imap":
            with imaplib.IMAP4_SSL(creds.server, creds.port) as mail:
                mail.login(username, password)
                mail.select(folder)

                result, data = mail.search(None, "ALL")
                if result != "OK":
                    raise Exception("Failed to search emails.")

                email_ids = data[0].split()
                for email_id in email_ids[-max_emails:]:
                    res, msg_data = mail.fetch(email_id, "(RFC822)")
                    if res != "OK":
                        continue
                    msg = BytesParser(policy=default).parsebytes(msg_data[0][1])
                    emails.append({
                        "subject": msg.get("Subject"),
                        "from": msg.get("From"),
                        "date": msg.get("Date"),
                        "body": ReceiveEmailBlock.get_email_body(msg),
                    })

        elif protocol == "pop3":
            with poplib.POP3_SSL(creds.server, creds.port) as mail:
                mail.user(username)
                mail.pass_(password)

                num_messages = len(mail.list()[1])
                for i in range(max(1, num_messages - max_emails + 1), num_messages + 1):
                    resp, lines, octets = mail.retr(i)
                    msg_content = b"\r\n".join(lines)
                    msg = BytesParser(policy=default).parsebytes(msg_content)
                    emails.append({
                        "subject": msg.get("Subject"),
                        "from": msg.get("From"),
                        "date": msg.get("Date"),
                        "body": ReceiveEmailBlock.get_email_body(msg),
                    })
        else:
            raise ValueError("Unsupported protocol. Choose 'imap' or 'pop3'.")

        return emails

    @staticmethod
    def get_email_body(msg) -> str:
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    return part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")
        else:
            return msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8", errors="replace")

    def run(self, input_data: Input, **kwargs) -> BlockOutput:
        try:
            emails = self.retrieve_emails(
                input_data.creds,
                input_data.folder,
                input_data.max_emails,
            )
            yield "emails", emails
        except Exception as e:
            yield "error", str(e)
