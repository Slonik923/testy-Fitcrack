def charset_model(charset):
    with open(charset.path, 'rb') as file:
        content = file.read()

    can_decode = True
    try:
        content = content.decode()
    except UnicodeDecodeError:
        can_decode = False
        content = str(content)

    return {
        "id": charset.id,
        "name": charset.name,
        "time": charset.time,
        "data": content,
        "canDecode": can_decode
    }