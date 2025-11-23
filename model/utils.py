def show_tree(jwt_string: str):
    """
    Imprime el árbol de derivación del JWT en consola.
    """
    try:
        header, payload, signature = jwt_string.split('.')
        print("JWT")
        print("├── HEADER:    ", header)
        print("├── PAYLOAD:   ", payload)
        print("└── SIGNATURE: ", signature)
    except Exception as e:
        print(f"Error al mostrar árbol de derivación: {str(e)}")
