import random
import string
from locust import HttpUser, task, between

pool = string.ascii_letters + string.digits
MAX_NUM = 9223372036854775807


def generate_string(length=20):
    return "".join(random.choice(pool) for _ in range(length))


class PerformanceTestUser(HttpUser):
    wait_time = between(1, 5)

    name: str
    pwd: str
    token: str

    def on_start(self):
        self.name = generate_string()
        self.pwd = generate_string()
        self.client.post(f"/register/?username={self.name}&password={self.pwd}", name="/register")
        while True:
            response = self.client.post("/token",
                                        headers={'Content-Type': 'application/x-www-form-urlencoded',
                                                 "accept": "application/json"},
                                        data=f"username={self.name}&password={self.pwd}")
            if response.status_code == 200:
                self.token = response.json()['access_token']
                break

    # Request tokena zloopowany ze względu na to że na zdeployowanej aplikacji
    # endpoint nie oddaje tokena w 50% przypadków, na localhost to się nie dzieje.
    # Wymuszam aby każdy user miał token przed testowaniem reszty endpointów

    @task
    def test_prime(self):
        number = random.randrange(MAX_NUM)
        self.client.get(f"/prime/{number}", name="/prime")

    @task
    def test_time(self):  # to samo co token, sukces ok. 50%
        self.client.get("/time", headers={'accept': 'text/plain', 'Authorization': f'Bearer {self.token}'})

    @task
    def test_invert(self):
        image = [('image', ('test_image.jpg', open('test_image.jpeg', 'rb'), 'image/jpeg'))]
        self.client.post("/picture/invert", files=image)
