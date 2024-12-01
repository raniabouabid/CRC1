def calculate_crc8(message, polynomial):
    # Convertir le message et le polynôme en entier
    message_bytes = bytes.fromhex(message)
    poly = int(polynomial, 16)

    # Initialiser le registre CRC à 0x00
    crc = 0x00

    # Parcourir chaque octet du message
    for byte in message_bytes:
        crc ^= byte  # XOR avec l'octet courant
        for _ in range(8):  # Parcourir chaque bit
            if crc & 0x80:  # Si le bit de poids fort est 1
                crc = (crc << 1) ^ poly
            else:
                crc <<= 1
            crc &= 0xFF  # Assurer que CRC reste sur 8 bits

    # Retourner le CRC sous forme d'entiers binaires et hexadécimaux
    crc_hex = f"{crc:02X}"  # CRC en hexadécimal
    crc_bin = f"{crc:08b}"  # CRC en binaire (8 bits)
    return crc_hex, crc_bin


def calculate_crc16(message, polynomial):
    """
    Calcule le CRC-16 pour un message donné avec un polynôme.

    Args:
        message (str): Message en hexadécimal sous forme de chaîne (ex : '0207').
        polynomial (str): Polynôme en hexadécimal sous forme de chaîne (ex : 'A001').

    Returns:
        tuple: CRC calculé en hexadécimal et en binaire.
    """
    # Convertir le message et le polynôme en entier
    message_bytes = bytes.fromhex(message)
    poly = int(polynomial, 16)

    # Initialiser le registre CRC à 0xFFFF
    crc = 0xFFFF

    # Parcourir chaque octet du message
    for byte in message_bytes:
        crc ^= byte  # XOR avec l'octet courant
        for _ in range(8):  # Parcourir chaque bit
            if crc & 0x0001:  # Si le bit de poids faible est 1
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1

    # Retourner le CRC sous forme d'entiers binaires et hexadécimaux
    crc_hex = f"{crc & 0xFFFF:04X}"  # CRC en hexadécimal
    crc_bin = f"{crc & 0xFFFF:016b}"  # CRC en binaire (16 bits)
    return crc_hex, crc_bin


if __name__ == "__main__":
    print("=== Calcul du CRC ===")

    # Choisir le type de CRC
    crc_type = input("Choisissez le type de CRC : (1) CRC-8 ou (2) CRC-16 ? Entrez 1 ou 2 : ").strip()
    if crc_type not in ["1", "2"]:
        print("Erreur : Choix non valide. Entrez 1 ou 2.")
        exit()

    # Saisir le message en hexadécimal
    message = input("Entrez le message en hexadécimal (ex : 0207) : ").strip()
    if not all(c in "0123456789ABCDEFabcdef" for c in message):
        print("Erreur : Le message doit être en hexadécimal valide.")
        exit()

    # Saisir le polynôme en hexadécimal
    if crc_type == "1":
        polynomial = input("Entrez le polynôme en hexadécimal pour CRC-8 (ex : 07) : ").strip()
    else:
        polynomial = input("Entrez le polynôme en hexadécimal pour CRC-16 (ex : A001) : ").strip()

    if not all(c in "0123456789ABCDEFabcdef" for c in polynomial):
        print("Erreur : Le polynôme doit être en hexadécimal valide.")
        exit()

    # Calculer le CRC
    if crc_type == "1":
        crc_hex, crc_bin = calculate_crc8(message, polynomial)
    else:
        crc_hex, crc_bin = calculate_crc16(message, polynomial)

    # Afficher les résultats
    print("\n=== Résultats ===")
    print(f"Message (hex)      : {message.upper()}")
    print(f"Polynôme (hex)     : {polynomial.upper()}")
    print(f"CRC calculé (hex)  : {crc_hex}")
    print(f"CRC calculé (bin)  : {crc_bin}")
