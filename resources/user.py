from datetime import datetime
from asyncdb.models import Column, Model
from navigator_auth.conf import (
    AUTH_DB_SCHEMA,
    AUTH_USERS_VIEW
)


# class User(Model):
#     """Basic User notation."""

#     user_id: int = Column(required=False, primary_key=True)
#     first_name: str
#     last_name: str
#     display_name: str
#     email: str = Column(required=False, max=254)
#     alt_email: str = Column(required=False, max=254)
#     password: str = Column(required=False, max=128)
#     last_login: datetime = Column(required=False)
#     username: str = Column(required=False)
#     is_superuser: bool = Column(required=True, default=False)
#     is_active: bool = Column(required=True, default=True)
#     is_new: bool = Column(required=True, default=True)
#     is_staff: bool = Column(required=False, default=True)
#     title: str = Column(equired=False, max=90)
#     avatar: str = Column(max=512)
#     associate_id: str = Column(required=False)
#     associate_oid: str = Column(required=False)
#     department_code: str = Column(required=False)
#     position_id: str = Column(required=False)
#     group_id: list = Column(required=False)
#     groups: list = Column(required=False)
#     program_id: list = Column(required=False)
#     programs: list = Column(required=False)
#     created_at: datetime = Column(required=False)

#     class Meta:
#         driver = "pg"
#         name = AUTH_USERS_VIEW
#         schema = AUTH_DB_SCHEMA
#         description = 'View Model for getting Users.'
#         strict = True
#         frozen = False

class User(Model):
    """Basic User notation."""

    user_id: int = Column(required=False, primary_key=True)
    first_name: str
    last_name: str
    display_name: str
    email: str = Column(required=False, max=254)
    alt_email: str = Column(required=False, max=254)
    password: str = Column(required=False, max=128)
    last_login: datetime = Column(required=False)
    username: str = Column(required=False)
    is_superuser: bool = Column(required=True, default=False)
    is_active: bool = Column(required=True, default=True)
    is_new: bool = Column(required=True, default=True)
    is_staff: bool = Column(required=False, default=True)
    title: str = Column(equired=False, max=90)
    avatar: str = Column(max=512)
    associate_id: str = Column(required=False)
    associate_oid: str = Column(required=False)
    department_code: str = Column(required=False)
    position_id: str = Column(required=False)
    group_id: list = Column(required=False)
    groups: list = Column(required=False)
    job_code: str = Column(required=False)
    program_id: list = Column(required=False)
    programs: list = Column(required=False)
    start_date: datetime = Column(required=False)
    birthday: str = Column(required=False)
    worker_type: str = Column(required=False)
    created_at: datetime = Column(required=False)
    reports_to_associate_oid: str = Column(required=False)
    manager_id: str = Column(required=False)

    def birth_date(self):
        if self.birthday:
            _, month, day = self.birthday.split('-')
            # Get the current year
            current_year = datetime.now().year
            # Create a new date string with the current year
            new_date_str = f"{current_year}-{month}-{day}"
            # Convert the new date string to a datetime object
            return datetime.strptime(new_date_str, "%Y-%m-%d").date()
        return None

    def employment_duration(self):
        if not self.start_date:
            return None, None, None
        # Get today's date
        today = datetime.now().date()
        # employment:
        employment = self.start_date.date()
        # Calculate the difference
        delta = today - employment
        # Calculate total number of years
        years = today.year - employment.year
        # Adjust for cases where the current month is before the start month
        if today.month < employment.month or (
            today.month == employment.month and today.day < employment.day
        ):
            years -= 1
        # Calculate the months
        months = today.month - employment.month
        if months < 0:
            months += 12
        # Adjust months if the current day is before the start day
        if today.day < employment.day:
            months -= 1
            days = delta.days - (
                employment.replace(
                    year=today.year, month=today.month
                ) - employment
            ).days
        else:
            days = today.day - employment.day
        # returning a tuple of years, months and days.
        return years, months, days

    class Meta:
        driver = "pg"
        name = AUTH_USERS_VIEW
        schema = AUTH_DB_SCHEMA
        description = 'View Model for getting Users.'
        strict = True
        frozen = False
