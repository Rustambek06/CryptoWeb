def encrypt_text(plaintext, n):
    ans = ""
    steps = []
    for i in range(len(plaintext)):
        ch = plaintext[i]
        if ch == " ":
            ans += " "
            steps.append({'original': ch, 'shifted': ' '})
        elif ch.isdigit():
            shifted_char = chr((ord(ch) + n - 48) % 10 + 48)
            ans += shifted_char
            steps.append({'original': ch, 'shifted': shifted_char})
        elif ch.isupper():
            shifted_char = chr((ord(ch) + n - 65) % 26 + 65)
            ans += shifted_char
            steps.append({'original': ch, 'shifted': shifted_char})
        else:
            shifted_char = chr((ord(ch) + n - 97) % 26 + 97)
            ans += shifted_char
            steps.append({'original': ch, 'shifted': shifted_char})

    return ans, steps