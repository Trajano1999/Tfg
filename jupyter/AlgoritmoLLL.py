import random

def lenstra(n, B, max_attempts):
    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a

    def pollard_rho(n):
        x, y, d = 2, 2, 1
        f = lambda x: (x ** 2 + 1) % n

        while d == 1:
            x = f(x)
            y = f(f(y))
            d = gcd(abs(x - y), n)

        return d

    for _ in range(max_attempts):
        a = random.randint(1, n - 1)
        x = random.randint(0, n - 1)
        y = random.randint(0, n - 1)
        c = y * y - (x ** 3) - a * x

        E = (a, c)
        P = (x, y)

        for i in range(2, B):
            Q = (P[0], P[1])
            for j in range(i):
                Q = add_points(Q, E, n)

            d = gcd(n, Q[1])
            if 1 < d < n:
                return d

    return None

def add_points(P, E, n):
    if P == (0, 0):
        return (0, 0)

    x1, y1 = P
    a, c = E

    s = ((3 * x1 * x1 + a) * pow(2 * y1, -1, n)) % n
    x3 = (s * s - 2 * x1) % n
    y3 = (s * (x1 - x3) - y1) % n

    return (x3, y3)

if __name__ == "__main__":
    n = 5959                # El número que deseas factorizar
    B = 20                  # Límite de la curva elíptica
    max_attempts = 1000     # Número máximo de

    factor = lenstra(n, B, max_attempts)
    if factor is not None:
        print(f"Un factor no trivial de {n} es {factor}")
    else:
        print(f"{n} es un número primo o el algoritmo no tuvo éxito.")