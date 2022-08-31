LEVEL_OVERRIDE = "override"
LEVEL_AUTHORITY = "authority"
LEVEL_HIGH = "high"
LEVEL_MEDIUM = "medium"
LEVEL_LOW = "low"


class KeyTrust:

    def __init__(self, key, level) -> None:
        level = level.upper()
        self.key = key
        self.levels = ["UNTRUSTED", "LOW", "MEDIUM",
                       "HIGH", "AUTHORITY", "OVERRIDE"]
        if level not in self.levels:
            raise ValueError("Invalid trust level")
        required = {"UNTRUSTED": -5, "LOW": -1, "MEDIUM": 1,
                    "HIGH": 5, "AUTHORITY": 100, "OVERRIDE": 1000000000000}
        self.level = level
        self.level_value = required[self.level]

    def __gt__(self, other):
        return self.levelValue > other.levelValue

    def __lt__(self, other):
        return self.levelValue < other.levelValue

    def __eq__(self, other):
        return self.levelValue == other.levelValue

    def __le__(self, other):
        return self.levelValue <= other.levelValue

    def __ge__(self, other):
        return self.levelValue >= other.levelValue

    def __str__(self):
        return self.level


def new(key, level=LEVEL_MEDIUM):
    """The trust level of a key.

       Creates a new TrustedKeys object.

        Args:
            level (str): The level of trust of the key.
                Possible values:
                    - "AUTHORITY": The key is verified by a highly trusted authority. (100)
                    - "TRUSTED": The key is verified by a somewhat trusted authority. (5)
                    - "MEDIUM": The key is verified by an authority, but not by a highly trusted one. (1, Default)
                    - "LOW": The key is verified by an untrusted source (-1)
                    - "UNTRUSTED": The key is verified by a source know to be untrusted. (-5)
                    - "OVERRIDE" : The user has verified the key themselves. (10000000000000)

        Raises:
            ValueError: If the level is not valid.

        Notes:
            Trust levels are maintained by the user.
            Each user keeps a record of the trust level of every public key they have seen, and this can vary from user to user.
            A key that is trusted by a user might not be trusted by another user.

            A potential downfall of this system is that a large number of untrusted users can overrule an authority.
            This, however, is not a truly major concern, and an 'override' trust level is provided to allow users to confirm a trusted key
            Use the override trust level with caution, as it will most likely overrule other trust levels.

    """
    return KeyTrust(key, level)
