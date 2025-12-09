import re

def check_password_strength(password):
    strength_points = 0

    # length check
    if len(password) >= 8:
        strength_points += 1

    # uppercase letter
    if re.search(r"[A-Z]", password):
        strength_points += 1

    # lowercase letter
    if re.search(r"[a-z]", password):
        strength_points += 1

    # number
    if re.search(r"[0-9]", password):
        strength_points += 1

    # special character
    if re.search(r"[@$!%*?&#]", password):
        strength_points += 1

    # Determine strength
    if strength_points <= 2:
        return "Weak"
    elif strength_points == 3 or strength_points == 4:
        return "Medium"
    else:
        return "Strong"


def main():
    print("=== Password Strength Checker ===")
    password = input("Enter your password: ")
    strength = check_password_strength(password)
    print(f"Password Strength: {strength}")


if __name__ == "__main__":
    main()
