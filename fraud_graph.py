from collections import defaultdict


class FraudGraph:
    def __init__(self):
        self.user_to_devices = defaultdict(set)
        self.user_to_recipients = defaultdict(set)
        self.user_to_locations = defaultdict(set)

        self.device_to_users = defaultdict(set)
        self.recipient_to_users = defaultdict(set)
        self.location_to_users = defaultdict(set)

    def add_transaction(self, transaction):
        user = transaction.user_id
        device = transaction.device
        recipient = transaction.recipient
        location = transaction.location

        self.user_to_devices[user].add(device)
        self.user_to_recipients[user].add(recipient)
        self.user_to_locations[user].add(location)

        self.device_to_users[device].add(user)
        self.recipient_to_users[recipient].add(user)
        self.location_to_users[location].add(user)

    def build_from_transactions(self, transactions):
        for transaction in transactions:
            self.add_transaction(transaction)

    def get_users_by_device(self, device):
        return list(self.device_to_users.get(device, set()))

    def get_users_by_recipient(self, recipient):
        return list(self.recipient_to_users.get(recipient, set()))

    def get_users_by_location(self, location):
        return list(self.location_to_users.get(location, set()))

    def get_shared_devices(self):
        shared_devices = {}

        for device, users in self.device_to_users.items():
            if len(users) > 1:
                shared_devices[device] = list(users)

        return shared_devices

    def get_shared_recipients(self):
        shared_recipients = {}

        for recipient, users in self.recipient_to_users.items():
            if len(users) > 1:
                shared_recipients[recipient] = list(users)

        return shared_recipients

    def get_shared_locations(self):
        shared_locations = {}

        for location, users in self.location_to_users.items():
            if len(users) > 1:
                shared_locations[location] = list(users)

        return shared_locations

    def get_suspicious_devices(self, minimum_users=2):
        suspicious_devices = {}

        for device, users in self.device_to_users.items():
            if len(users) >= minimum_users:
                suspicious_devices[device] = {
                    "user_count": len(users),
                    "users": list(users)
                }

        return suspicious_devices

    def get_suspicious_recipients(self, minimum_users=2):
        suspicious_recipients = {}

        for recipient, users in self.recipient_to_users.items():
            if len(users) >= minimum_users:
                suspicious_recipients[recipient] = {
                    "user_count": len(users),
                    "users": list(users)
                }

        return suspicious_recipients

    def get_connected_users(self, user_id):
        connected_users = set()

        devices = self.user_to_devices.get(user_id, set())
        recipients = self.user_to_recipients.get(user_id, set())

        for device in devices:
            connected_users.update(
                self.device_to_users.get(device, set())
            )

        for recipient in recipients:
            connected_users.update(
                self.recipient_to_users.get(recipient, set())
            )

        connected_users.discard(user_id)

        return list(connected_users)

    def get_connection_strength(self, user_id, other_user_id):
        shared_devices = (
            self.user_to_devices.get(user_id, set())
            & self.user_to_devices.get(other_user_id, set())
        )

        shared_recipients = (
            self.user_to_recipients.get(user_id, set())
            & self.user_to_recipients.get(other_user_id, set())
        )

        shared_locations = (
            self.user_to_locations.get(user_id, set())
            & self.user_to_locations.get(other_user_id, set())
        )

        connection_count = (
            len(shared_devices)
            + len(shared_recipients)
            + len(shared_locations)
        )

        if connection_count == 0:
            strength = "NO CONNECTION"
            risk_score = 0
        elif connection_count == 1:
            strength = "WEAK CONNECTION"
            risk_score = 5
        else:
            strength = "STRONG CONNECTION"
            risk_score = 15

        return {
            "shared_devices": list(shared_devices),
            "shared_recipients": list(shared_recipients),
            "shared_locations": list(shared_locations),
            "connection_count": connection_count,
            "strength": strength,
            "risk_score": risk_score
        }

    def get_user_connections(self, user_id):
        connections = []

        connected_users = self.get_connected_users(user_id)

        for other_user in connected_users:
            connection = self.get_connection_strength(
                user_id,
                other_user
            )

            connections.append({
                "user_id": other_user,
                **connection
            })

        connections.sort(
            key=lambda item: item["risk_score"],
            reverse=True
        )

        return connections

    def get_user_graph_risk(self, user_id):
        connections = self.get_user_connections(user_id)

        if not connections:
            return {
                "user_id": user_id,
                "connected_user_count": 0,
                "strong_connections": 0,
                "weak_connections": 0,
                "graph_risk_score": 0
            }

        strong_connections = sum(
            1
            for connection in connections
            if connection["strength"] == "STRONG CONNECTION"
        )

        weak_connections = sum(
            1
            for connection in connections
            if connection["strength"] == "WEAK CONNECTION"
        )

        graph_risk_score = sum(
            connection["risk_score"]
            for connection in connections
        )

        graph_risk_score = min(graph_risk_score, 30)

        return {
            "user_id": user_id,
            "connected_user_count": len(connections),
            "strong_connections": strong_connections,
            "weak_connections": weak_connections,
            "graph_risk_score": graph_risk_score
        }

    def get_summary(self):
        return {
            "users": len(self.user_to_devices),
            "devices": len(self.device_to_users),
            "recipients": len(self.recipient_to_users),
            "locations": len(self.location_to_users)
        }