def create_playfair_square(phrase):
    key = phrase.replace('J', 'I').upper() + 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    key = "".join(dict.fromkeys(key))  # Remove duplicate letters
    grid = [[k for k in key[i:i + 5]] for i in range(0, 25, 5)]
    return grid


def find_location(grid, char):
    """
    Helper function to get the row and column of the given char.
    """
    char = char.upper().replace('J', 'I')  # Замена 'J' на 'I' и приведение к верхнему регистру
    for i in range(0, 5):
        for j in range(0, 5):
            if grid[i][j] == char:
                return i, j
    raise ValueError(f"Character {char} not found in Playfair square")


def playfair_encrypt(message: str, key: str) -> (str, list, list):
    playfair_square = create_playfair_square(key)
    ciphertext = ''
    steps = []

    message = "".join(filter(str.isalpha, message)).upper().replace('J', 'I')

    i = 0
    while i < len(message) - 1:
        if message[i] == message[i + 1]:
            message = message[:i + 1] + 'X' + message[i + 1:]
        i += 1

    if len(message) % 2 == 1:
        message += 'X'

    for i in range(0, len(message), 2):
        digraph = message[i:i + 2]
        row1, col1 = find_location(playfair_square, digraph[0])
        row2, col2 = find_location(playfair_square, digraph[1])
        explanation = f"Биграмма {digraph}: "

        if row1 == row2:
            sub1 = playfair_square[row1][(col1 + 1) % 5]
            sub2 = playfair_square[row2][(col2 + 1) % 5]
            explanation += f"Буквы находятся в одной строке, сдвигаем вправо: {digraph} -> {sub1}{sub2}"
        elif col1 == col2:
            sub1 = playfair_square[(row1 + 1) % 5][col1]
            sub2 = playfair_square[(row2 + 1) % 5][col2]
            explanation += f"Буквы находятся в одном столбце, сдвигаем вниз: {digraph} -> {sub1}{sub2}"
        else:
            sub1 = playfair_square[row1][col2]
            sub2 = playfair_square[row2][col1]
            explanation += f"Буквы образуют прямоугольник, меняем столбцы: {digraph} -> {sub1}{sub2}"

        steps.append(f"{explanation}")
        ciphertext += sub1 + sub2

    return ciphertext, steps, playfair_square


def playfair_decrypt(ciphertext: str, key: str) -> (str, list, list):
    playfair_square = create_playfair_square(key)
    message = ''
    steps = []

    for i in range(0, len(ciphertext), 2):
        digraph = ciphertext[i:i + 2]
        row1, col1 = find_location(playfair_square, digraph[0])
        row2, col2 = find_location(playfair_square, digraph[1])
        explanation = f"Биграмма {digraph}: "

        if row1 == row2:
            sub1 = playfair_square[row1][(col1 - 1) % 5]
            sub2 = playfair_square[row2][(col2 - 1) % 5]
            explanation += f"Буквы находятся в одной строке, сдвигаем влево: {digraph} -> {sub1}{sub2}"
        elif col1 == col2:
            sub1 = playfair_square[(row1 - 1) % 5][col1]
            sub2 = playfair_square[(row2 - 1) % 5][col2]
            explanation += f"Буквы находятся в одном столбце, сдвигаем вверх: {digraph} -> {sub1}{sub2}"
        else:
            sub1 = playfair_square[row1][col2]
            sub2 = playfair_square[row2][col1]
            explanation += f"Буквы образуют прямоугольник, меняем столбцы: {digraph} -> {sub1}{sub2}"

        steps.append(f"{explanation}")
        message += sub1 + sub2

    i = 0
    while i < len(message) - 2:
        if message[i] == message[i + 2] and message[i + 1] == 'X':
            message = message[:i + 1] + message[i + 2:]
        i += 1

    if message[-1] == 'X':
        message = message[:-1]

    return message, steps, playfair_square