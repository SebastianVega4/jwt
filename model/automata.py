class Base64URLDFA:
    ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

    def __init__(self):
        self.state = 'q0'

    def process(self, input_str: str) -> bool:
        self.state = 'q0'
        for symbol in input_str:
            if symbol in self.ALPHABET:
                continue
            else:
                self.state = 'qerr'
                break
        return self.state == 'q0' and bool(input_str)

    def reset(self):
        self.state = 'q0'

class JWTStructureDFA:
    def process(self, input_str: str) -> bool:
        parts = input_str.split('.')
        if len(parts) != 3:
            return False
        dfa = Base64URLDFA()
        return all(dfa.process(part) for part in parts)
