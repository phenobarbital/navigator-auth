from datetime import datetime, date
import time
from datamodel import Model, Field

def now():
    return datetime.today()

def curtime():
    return time.time()

class Environment(Model):
    time: float = Field(default_factory=curtime)
    timestamp: datetime = Field(default_factory=now)
    dow: int
    day_of_week: int
    hour: int
    date: date

    def __post_init__(self):
        self.hour = self.timestamp.hour
        self.dow = self.timestamp.weekday()
        self.day_of_week = self.dow
        self.date = self.timestamp.date()
        super(Environment, self).__post_init__()
