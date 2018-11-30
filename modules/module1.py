
from module import Module


class CustomModule(Module):

    def __init__(self):
        pass

    def run(self):
        print("Se ha ejecutado el modulo1")
        self.super_function()
