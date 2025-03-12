from faker import Faker
from core.faker.faker_image import ImageProvider


def get_faker():
    fake = Faker("pt_BR")
    fake.add_provider(ImageProvider)

    return fake


fake = get_faker()
