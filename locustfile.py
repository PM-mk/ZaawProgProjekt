import random
import string

from locust import HttpUser, task, between


pool = string.ascii_letters + string.digits
MAX_NUM = 9223372036854775807


def generate_string(length=20):
    return "".join(random.choice(pool) for _ in range(length))


class QuickstartUser(HttpUser):
    wait_time = between(1, 5)

    name: str
    pwd: str

    def on_start(self):
        self.name = generate_string()
        self.pwd = generate_string()
        self.client.post("/register", json={"username": self.name, "password": self.pwd})
        self.client.post("/token", json={"username": self.name, "password": self.pwd})

    @task
    def test_prime(self):
        number = random.randrange(MAX_NUM)
        self.client.get(f"/prime/{number}")

    @task
    def test_time(self):
        self.client.get("/time", auth={"username": self.name, "password": self.pwd})

    @task
    def test_invert(self):
        with open('test_image.jpeg', 'rb') as image:
            self.client.post("/picture/invert", files={'test_image': image})
