def check_room_id(room_id):
    if not room_id.startswith("!"):
        raise ValueError("RoomIDs start with !")

    if ":" not in room_id:
        raise ValueError("RoomIDs must have a domain component, seperated by a :")


def check_user_id(user_id):
    if not user_id.startswith("@"):
        raise ValueError("UserIDs start with @")

    if ":" not in user_id:
        raise ValueError("UserIDs must have a domain component, seperated by a :")
